package http

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
)

// attachmentDTO is the JSON shape of a single attachment
// (api/openapi.yaml, schema Attachment). It deliberately never carries
// StorageKey — the object store key is an opaque, unguessable
// identifier that is never exposed outside the storage driver boundary
// (SR-121-3) — mirroring linkDTO's own "deliberately excludes
// token_hash" precedent for the equivalent invariant on links
// (the token-hygiene invariant). RetainUntil is a pointer so a legacy
// pre-ATR-178 row (the zero-time sentinel, store.Attachment.RetainUntil's
// own doc comment) renders as JSON null rather than the zero time.
type attachmentDTO struct {
	ID           string  `json:"id"`
	MessageID    string  `json:"message_id"`
	PartRef      string  `json:"part_ref"`
	Filename     string  `json:"filename"`
	DeclaredType string  `json:"declared_type"`
	DetectedType string  `json:"detected_type"`
	Size         int64   `json:"size"`
	RetainUntil  *string `json:"retain_until"`
	CreatedAt    string  `json:"created_at"`
}

// attachmentListDTO is the paginated list envelope (schema
// AttachmentList + PageMeta).
type attachmentListDTO struct {
	Data       []attachmentDTO `json:"data"`
	NextCursor *string         `json:"next_cursor"`
}

// toAttachmentDTO maps a store.Attachment to its wire shape, formatting
// timestamps as RFC3339Nano UTC and collapsing a zero RetainUntil to
// JSON null.
func toAttachmentDTO(a store.Attachment) attachmentDTO {
	dto := attachmentDTO{
		ID:           a.ID,
		MessageID:    a.MessageID,
		PartRef:      a.PartRef,
		Filename:     a.Filename,
		DeclaredType: a.DeclaredType,
		DetectedType: a.DetectedType,
		Size:         a.Size,
		CreatedAt:    a.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if !a.RetainUntil.IsZero() {
		s := a.RetainUntil.UTC().Format(time.RFC3339Nano)
		dto.RetainUntil = &s
	}
	return dto
}

// handleAttachmentsCollection dispatches the /api/v1/attachments
// collection by method. Only GET is defined (api/openapi.yaml has no
// mutation on this resource — attachments are only ever created by the
// milter pipeline, never through the API).
func (h *APIHandler) handleAttachmentsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listAttachments(w, r)
	default:
		h.writeMethodNotAllowed(w, "GET")
	}
}

// handleAttachmentItem dispatches the /api/v1/attachments/{attachmentId}
// item by method.
func (h *APIHandler) handleAttachmentItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getAttachment(w, r)
	default:
		h.writeMethodNotAllowed(w, "GET")
	}
}

// listAttachments implements GET /api/v1/attachments (admin, viewer):
// a cursor-paginated, filterable page of replaced attachments (US-8.1/
// T-8.1.4, SR-130-5).
func (h *APIHandler) listAttachments(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	limit, ok := parseLimit(w, r, h.logger)
	if !ok {
		return
	}

	q := r.URL.Query()
	params := store.AttachmentListParams{
		Limit:     limit,
		Cursor:    q.Get("cursor"),
		MessageID: q.Get("message_id"),
		Filename:  q.Get("filename"),
		MimeType:  q.Get("mime_type"),
	}

	minSize, ok := parseSizeParam(w, r, h.logger, "min_size")
	if !ok {
		return
	}
	params.MinSize = minSize

	maxSize, ok := parseSizeParam(w, r, h.logger, "max_size")
	if !ok {
		return
	}
	params.MaxSize = maxSize

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

	page, err := h.metadata.ListAttachments(r.Context(), params)
	if err != nil {
		if errors.Is(err, store.ErrInvalidCursor) {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid cursor")
			return
		}
		h.logger.Error("api: list attachments failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	dto := attachmentListDTO{Data: make([]attachmentDTO, 0, len(page.Attachments))}
	for _, a := range page.Attachments {
		dto.Data = append(dto.Data, toAttachmentDTO(a))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		dto.NextCursor = &c
	}
	writeAPIJSON(w, h.logger, http.StatusOK, dto)
}

// getAttachment implements GET /api/v1/attachments/{attachmentId}
// (admin, viewer). It reuses store.MetadataStore.GetAttachment
// directly (rather than a dedicated summary method, unlike messages):
// api/openapi.yaml's Attachment schema has no derived/aggregated
// field the way Message.recipients/attachment_count does, so the
// stored row already is the full wire shape (minus StorageKey).
func (h *APIHandler) getAttachment(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	id := r.PathValue("attachmentId")
	a, err := h.metadata.GetAttachment(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
			return
		}
		h.logger.Error("api: get attachment failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	writeAPIJSON(w, h.logger, http.StatusOK, toAttachmentDTO(a))
}

// parseSizeParam reads and validates a non-negative int64 query
// parameter (api/openapi.yaml `min_size`/`max_size`: integer, format
// int64, minimum 0). An absent parameter is valid and returns a nil
// bound (no constraint); a present but unparseable or negative value
// is a 400. It writes the error response itself and returns ok=false
// when it does, mirroring parseTimeParam's contract.
func parseSizeParam(w http.ResponseWriter, r *http.Request, logger *slog.Logger, name string) (*int64, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil, true
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		writeAPIError(w, logger, http.StatusBadRequest, errCodeBadRequest, "invalid value for query parameter \""+name+"\"")
		return nil, false
	}
	return &n, true
}
