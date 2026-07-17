package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/store"
)

// linkDTO is the JSON shape of a single link (api/openapi.yaml, schema
// Link). It deliberately never carries TokenHash — the object store
// key equivalent for a link's bearer credential — matching the schema's
// explicit "Deliberately excludes token_hash" note (the token-hygiene
// invariant). HoldSetBy/HoldSetAt are pointers so an unheld link
// renders them as JSON null rather than an empty string/epoch.
type linkDTO struct {
	ID           string  `json:"id"`
	MessageID    string  `json:"message_id"`
	AttachmentID string  `json:"attachment_id"`
	Recipient    string  `json:"recipient"`
	ExpiresAt    string  `json:"expires_at"`
	MaxDownloads int     `json:"max_downloads"`
	Downloads    int     `json:"downloads"`
	Status       string  `json:"status"`
	Hold         bool    `json:"hold"`
	HoldSetBy    *string `json:"hold_set_by"`
	HoldSetAt    *string `json:"hold_set_at"`
	CreatedAt    string  `json:"created_at"`
}

// linkListDTO is the paginated list envelope (schema LinkList +
// PageMeta). NextCursor is a pointer so it renders as null on the last
// page, per the PageMeta contract.
type linkListDTO struct {
	Data       []linkDTO `json:"data"`
	NextCursor *string   `json:"next_cursor"`
}

// revokeByMessageRequestDTO is the request body for POST
// /links/revoke-by-message (schema RevokeByMessageRequest).
type revokeByMessageRequestDTO struct {
	MessageID string `json:"message_id"`
}

// revokeByMessageResultDTO is the response for POST
// /links/revoke-by-message (schema RevokeByMessageResult).
type revokeByMessageResultDTO struct {
	Revoked int `json:"revoked"`
	Held    int `json:"held"`
}

// revokeBySenderRequestDTO is the request body for POST
// /links/revoke-by-sender (schema RevokeBySenderRequest).
type revokeBySenderRequestDTO struct {
	Sender string `json:"sender"`
}

// revokeBySenderResultDTO is the response for POST
// /links/revoke-by-sender (schema RevokeBySenderResult).
type revokeBySenderResultDTO struct {
	Revoked      int `json:"revoked"`
	HeldMessages int `json:"held_messages"`
}

// toLinkDTO maps a store.Link to its wire shape, formatting timestamps
// as RFC3339Nano UTC and collapsing a zero HoldSetAt/empty HoldSetBy to
// JSON null.
func toLinkDTO(l store.Link) linkDTO {
	dto := linkDTO{
		ID:           l.ID,
		MessageID:    l.MessageID,
		AttachmentID: l.AttachmentID,
		Recipient:    l.Recipient,
		ExpiresAt:    l.ExpiresAt.UTC().Format(time.RFC3339Nano),
		MaxDownloads: l.MaxDownloads,
		Downloads:    l.Downloads,
		Status:       string(l.Status),
		Hold:         l.Hold,
		CreatedAt:    l.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if l.HoldSetBy != "" {
		s := l.HoldSetBy
		dto.HoldSetBy = &s
	}
	if !l.HoldSetAt.IsZero() {
		s := l.HoldSetAt.UTC().Format(time.RFC3339Nano)
		dto.HoldSetAt = &s
	}
	return dto
}

// apiActor builds the audit.Event Actor string for an API-originated
// link mutation: a stable, unique reference (the token's own store ID)
// plus its operator-chosen name for readability, distinguishing API
// callers from "milter", "system" and the CLI's plain operator-supplied
// --actor string in the audit trail (api/openapi.yaml AuditEvent.actor:
// "API principal, \"milter\", or \"system\"").
func apiActor(p principal) string {
	return fmt.Sprintf("api:%s:%s", p.TokenID, p.Name)
}

// handleLinksCollection dispatches the /api/v1/links collection by
// method. Only GET is defined (api/openapi.yaml has no POST on this
// path — link creation happens only via the milter pipeline).
func (h *APIHandler) handleLinksCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listLinks(w, r)
	default:
		h.writeMethodNotAllowed(w, "GET")
	}
}

// handleLinkItem dispatches the /api/v1/links/{linkId} item by method.
func (h *APIHandler) handleLinkItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getLink(w, r)
	default:
		h.writeMethodNotAllowed(w, "GET")
	}
}

// handleLinkRevoke dispatches POST /api/v1/links/{linkId}/revoke.
func (h *APIHandler) handleLinkRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, "POST")
		return
	}
	h.revokeLink(w, r)
}

// handleLinkHold dispatches POST /api/v1/links/{linkId}/hold.
func (h *APIHandler) handleLinkHold(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, "POST")
		return
	}
	h.setLinkHold(w, r, true)
}

// handleLinkUnhold dispatches POST /api/v1/links/{linkId}/unhold.
func (h *APIHandler) handleLinkUnhold(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, "POST")
		return
	}
	h.setLinkHold(w, r, false)
}

// handleRevokeByMessage dispatches POST /api/v1/links/revoke-by-message.
func (h *APIHandler) handleRevokeByMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, "POST")
		return
	}
	h.revokeLinksByMessage(w, r)
}

// handleRevokeBySender dispatches POST /api/v1/links/revoke-by-sender.
func (h *APIHandler) handleRevokeBySender(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, "POST")
		return
	}
	h.revokeLinksBySender(w, r)
}

// listLinks implements GET /api/v1/links (admin, viewer): a
// cursor-paginated, filterable page of links, never a token hash
// (SR-130-5, the token-hygiene invariant).
func (h *APIHandler) listLinks(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	limit, ok := parseLimit(w, r, h.logger)
	if !ok {
		return
	}

	q := r.URL.Query()
	params := store.LinkListParams{
		Limit:     limit,
		Cursor:    q.Get("cursor"),
		MessageID: q.Get("message_id"),
		Recipient: q.Get("recipient"),
	}

	if raw := q.Get("status"); raw != "" {
		status := store.LinkStatus(raw)
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

	page, err := h.metadata.ListLinks(r.Context(), params)
	if err != nil {
		if errors.Is(err, store.ErrInvalidCursor) {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid cursor")
			return
		}
		h.logger.Error("api: list links failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	dto := linkListDTO{Data: make([]linkDTO, 0, len(page.Links))}
	for _, l := range page.Links {
		dto.Data = append(dto.Data, toLinkDTO(l))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		dto.NextCursor = &c
	}
	writeAPIJSON(w, h.logger, http.StatusOK, dto)
}

// getLink implements GET /api/v1/links/{linkId} (admin, viewer).
func (h *APIHandler) getLink(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	id := r.PathValue("linkId")
	l, err := h.metadata.GetLinkByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
			return
		}
		h.logger.Error("api: get link failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	writeAPIJSON(w, h.logger, http.StatusOK, toLinkDTO(l))
}

// revokeLink implements POST /api/v1/links/{linkId}/revoke (admin
// only, SR-130-3): mirrors link.Engine.Revoke, refusing with 409 held
// if the link is currently under legal hold (ATR-233/ATR-257). The
// mutation itself — and its audit record (US-7.1) — happens entirely
// inside Engine.Revoke; this handler only translates its outcome to
// HTTP.
func (h *APIHandler) revokeLink(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, store.RoleAdmin)
	if !ok {
		return
	}

	id := r.PathValue("linkId")
	if err := h.links.Revoke(r.Context(), apiActor(p), id); err != nil {
		switch {
		case errors.Is(err, link.ErrHeld):
			writeAPIError(w, h.logger, http.StatusConflict, errCodeHeld, "link is under legal hold")
		case errors.Is(err, link.ErrNotFound):
			writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
		default:
			h.logger.Error("api: revoke link failed", "error", err.Error())
			writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		}
		return
	}

	l, err := h.metadata.GetLinkByID(r.Context(), id)
	if err != nil {
		h.logger.Error("api: reload revoked link failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	writeAPIJSON(w, h.logger, http.StatusOK, toLinkDTO(l))
}

// setLinkHold implements both POST /api/v1/links/{linkId}/hold and
// POST /api/v1/links/{linkId}/unhold (admin only, SR-130-3), mirroring
// link.Engine.SetHold(ctx, actor, linkId, hold) (ATR-257). Both
// endpoints share this one implementation since they differ only in
// the boolean they pass through.
func (h *APIHandler) setLinkHold(w http.ResponseWriter, r *http.Request, hold bool) {
	p, ok := h.authorize(w, r, store.RoleAdmin)
	if !ok {
		return
	}

	id := r.PathValue("linkId")
	if err := h.links.SetHold(r.Context(), apiActor(p), id, hold); err != nil {
		if errors.Is(err, link.ErrNotFound) {
			writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
			return
		}
		h.logger.Error("api: set link hold failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	l, err := h.metadata.GetLinkByID(r.Context(), id)
	if err != nil {
		h.logger.Error("api: reload held link failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	writeAPIJSON(w, h.logger, http.StatusOK, toLinkDTO(l))
}

// revokeLinksByMessage implements POST /api/v1/links/revoke-by-message
// (admin only): mirrors link.Engine.RevokeMessage, cascading a revoke
// across every link of one message. A held link is skipped and
// reported via the response's held count, not treated as a hard
// failure (api/openapi.yaml: "a partial revoke is still reported as
// 200"). An unknown message_id is the one hard failure this operation
// reports, as 404 — RevokeMessage itself cannot distinguish "message
// has zero links" from "message does not exist" (ListLinksByMessage
// returns an empty slice for both), so this handler checks existence
// explicitly via GetMessage first.
func (h *APIHandler) revokeLinksByMessage(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, store.RoleAdmin)
	if !ok {
		return
	}

	var req revokeByMessageRequestDTO
	if !decodeJSONBody(w, r, h.logger, &req) {
		return
	}
	if req.MessageID == "" {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "message_id is required")
		return
	}

	if _, err := h.metadata.GetMessage(r.Context(), req.MessageID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
			return
		}
		h.logger.Error("api: get message for revoke-by-message failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	revoked, held, err := h.links.RevokeMessage(r.Context(), apiActor(p), req.MessageID)
	if err != nil && !errors.Is(err, link.ErrHeld) {
		h.logger.Error("api: revoke links by message failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	writeAPIJSON(w, h.logger, http.StatusOK, revokeByMessageResultDTO{Revoked: revoked, Held: held})
}

// revokeLinksBySender implements POST /api/v1/links/revoke-by-sender
// (admin only): mirrors link.Engine.RevokeSender, first resolving the
// sender's message IDs via store.MetadataStore.ListMessagesBySender
// (the fan-out is an API-layer concern, not Engine's own — see
// RevokeSender's doc comment). An unknown sender is not an error (zero
// messages, zero links revoked), matching the CLI's own
// runLinkRevokeBySender behavior.
func (h *APIHandler) revokeLinksBySender(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authorize(w, r, store.RoleAdmin)
	if !ok {
		return
	}

	var req revokeBySenderRequestDTO
	if !decodeJSONBody(w, r, h.logger, &req) {
		return
	}
	if req.Sender == "" {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "sender is required")
		return
	}

	messages, err := h.metadata.ListMessagesBySender(r.Context(), req.Sender)
	if err != nil {
		h.logger.Error("api: list messages by sender failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	messageIDs := make([]string, len(messages))
	for i, m := range messages {
		messageIDs[i] = m.ID
	}

	revoked, heldMessages, err := h.links.RevokeSender(r.Context(), apiActor(p), messageIDs)
	if err != nil && !errors.Is(err, link.ErrHeld) {
		h.logger.Error("api: revoke links by sender failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	writeAPIJSON(w, h.logger, http.StatusOK, revokeBySenderResultDTO{Revoked: revoked, HeldMessages: heldMessages})
}

// parseTimeParam reads and validates an RFC3339 date-time query
// parameter (api/openapi.yaml: `from`/`to` filters, format date-time).
// An absent parameter is valid and returns the zero time.Time (no
// bound); a present but unparseable value is a 400. It writes the
// error response itself and returns ok=false when it does.
func parseTimeParam(w http.ResponseWriter, r *http.Request, logger *slog.Logger, name string) (time.Time, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		writeAPIError(w, logger, http.StatusBadRequest, errCodeBadRequest, fmt.Sprintf("invalid value for query parameter %q", name))
		return time.Time{}, false
	}
	return t, true
}

// decodeJSONBody decodes r.Body as strict JSON (rejecting unknown
// fields) into dst, translating a MaxBytesReader overflow into 413 and
// any other decode failure into 400. It writes the error response
// itself and returns ok=false when it does, mirroring
// createAPIToken's body-handling in apitokens.go so every bodied
// endpoint in this package treats a malformed or oversized request
// body identically.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, logger *slog.Logger, dst any) (ok bool) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeAPIError(w, logger, http.StatusRequestEntityTooLarge, errCodePayloadTooLarge, "request body exceeds the configured size limit")
			return false
		}
		writeAPIError(w, logger, http.StatusBadRequest, errCodeBadRequest, "invalid request body")
		return false
	}
	return true
}
