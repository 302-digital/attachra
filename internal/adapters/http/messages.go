package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
)

// messageDTO is the JSON shape of a single message (api/openapi.yaml,
// schema Message). Recipients and AttachmentCount are derived from
// this message's Link/Attachment rows, not stored columns on
// store.Message itself (see store.MessageSummary's doc comment).
// Status is a pointer so a legacy/unknown message (the empty-string
// sentinel, store.MessageStatus's own doc comment) renders as JSON
// null rather than an empty string, matching the schema's `nullable:
// true`.
type messageDTO struct {
	ID              string   `json:"id"`
	QueueID         string   `json:"queue_id"`
	Sender          string   `json:"sender"`
	CreatedAt       string   `json:"created_at"`
	Recipients      []string `json:"recipients"`
	AttachmentCount int      `json:"attachment_count"`
	Status          *string  `json:"status"`
}

// messageListDTO is the paginated list envelope (schema MessageList +
// PageMeta).
type messageListDTO struct {
	Data       []messageDTO `json:"data"`
	NextCursor *string      `json:"next_cursor"`
}

// toMessageDTO maps a store.MessageSummary to its wire shape,
// formatting its timestamp as RFC3339Nano UTC and collapsing the
// empty-string legacy Status sentinel to JSON null.
func toMessageDTO(m store.MessageSummary) messageDTO {
	dto := messageDTO{
		ID:              m.ID,
		QueueID:         m.QueueID,
		Sender:          m.Sender,
		CreatedAt:       m.CreatedAt.UTC().Format(time.RFC3339Nano),
		Recipients:      m.Recipients,
		AttachmentCount: m.AttachmentCount,
	}
	if dto.Recipients == nil {
		dto.Recipients = []string{}
	}
	if m.Status != "" {
		s := string(m.Status)
		dto.Status = &s
	}
	return dto
}

// handleMessagesCollection dispatches the /api/v1/messages collection
// by method. Only GET is defined (api/openapi.yaml has no mutation on
// this resource — messages are only ever created by the milter
// pipeline, never through the API).
func (h *APIHandler) handleMessagesCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listMessages(w, r)
	default:
		h.writeMethodNotAllowed(w, "GET")
	}
}

// handleMessageItem dispatches the /api/v1/messages/{messageId} item
// by method.
func (h *APIHandler) handleMessageItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getMessage(w, r)
	default:
		h.writeMethodNotAllowed(w, "GET")
	}
}

// listMessages implements GET /api/v1/messages (admin, viewer): a
// cursor-paginated, filterable page of processed messages (US-8.1/
// T-8.1.4, SR-130-5).
func (h *APIHandler) listMessages(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	limit, ok := parseLimit(w, r, h.logger)
	if !ok {
		return
	}

	q := r.URL.Query()
	params := store.MessageListParams{
		Limit:     limit,
		Cursor:    q.Get("cursor"),
		Sender:    q.Get("sender"),
		Recipient: q.Get("recipient"),
	}

	if raw := q.Get("status"); raw != "" {
		status := store.MessageStatus(raw)
		if !status.Valid() {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid value for query parameter \"status\"")
			return
		}
		params.Status = status
	}

	from, ok := parseTimeParam(w, r, h.logger, "from")
	if !ok {
		return
	}
	params.From = from

	to, ok := parseTimeParam(w, r, h.logger, "to")
	if !ok {
		return
	}
	params.To = to

	page, err := h.metadata.ListMessages(r.Context(), params)
	if err != nil {
		if errors.Is(err, store.ErrInvalidCursor) {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid cursor")
			return
		}
		h.logger.Error("api: list messages failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	dto := messageListDTO{Data: make([]messageDTO, 0, len(page.Messages))}
	for _, m := range page.Messages {
		dto.Data = append(dto.Data, toMessageDTO(m))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		dto.NextCursor = &c
	}
	writeAPIJSON(w, h.logger, http.StatusOK, dto)
}

// getMessage implements GET /api/v1/messages/{messageId} (admin,
// viewer).
func (h *APIHandler) getMessage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	id := r.PathValue("messageId")
	m, err := h.metadata.GetMessageSummary(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
			return
		}
		h.logger.Error("api: get message failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	writeAPIJSON(w, h.logger, http.StatusOK, toMessageDTO(m))
}
