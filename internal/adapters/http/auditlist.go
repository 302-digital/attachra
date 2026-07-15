package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
)

// auditEventDTO mirrors api/openapi.yaml schema AuditEvent (GET
// /audit). Actor/MessageID/Recipient/Details are all optional in the
// schema, so they are omitted (not rendered as empty-string/empty-map)
// when absent.
type auditEventDTO struct {
	ID        string         `json:"id"`
	Seq       int64          `json:"seq"`
	PrevHash  string         `json:"prev_hash"`
	Timestamp string         `json:"timestamp"`
	Type      string         `json:"type"`
	Actor     string         `json:"actor,omitempty"`
	MessageID string         `json:"message_id,omitempty"`
	Recipient string         `json:"recipient,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// auditEventListDTO is the paginated list envelope (schema
// AuditEventList + PageMeta).
type auditEventListDTO struct {
	Data       []auditEventDTO `json:"data"`
	NextCursor *string         `json:"next_cursor"`
}

// toAuditEventDTO maps an audit.Recorded to its wire shape, formatting
// its timestamp as RFC3339Nano UTC.
func toAuditEventDTO(rec audit.Recorded) auditEventDTO {
	return auditEventDTO{
		ID:        rec.ID,
		Seq:       rec.Seq,
		PrevHash:  rec.PrevHash,
		Timestamp: rec.Timestamp.UTC().Format(time.RFC3339Nano),
		Type:      string(rec.Type),
		Actor:     rec.Actor,
		MessageID: rec.MessageID,
		Recipient: rec.Recipient,
		Details:   rec.Details,
	}
}

// handleAuditCollection implements GET /api/v1/audit (admin, viewer,
// auditor — ADR-015: the audit log and its export are the only
// resources an auditor token may reach): a cursor-paginated,
// filterable page of audit events, in ascending seq order (US-8.1/
// T-8.1.6, SR-130-5's mandatory pagination and response-size limit on
// this resource).
func (h *APIHandler) handleAuditCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w, "GET")
		return
	}
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer, store.RoleAuditor); !ok {
		return
	}

	limit, ok := parseLimit(w, r, h.logger)
	if !ok {
		return
	}

	q := r.URL.Query()
	params := audit.ListParams{
		Limit:     limit,
		Cursor:    q.Get("cursor"),
		MessageID: q.Get("message_id"),
	}

	if raw := q.Get("type"); raw != "" {
		typ := audit.Type(raw)
		if !typ.Valid() {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid value for query parameter \"type\"")
			return
		}
		params.Type = typ
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

	page, err := h.auditReader.ListEvents(r.Context(), params)
	if err != nil {
		if errors.Is(err, audit.ErrInvalidCursor) {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid cursor")
			return
		}
		h.logger.Error("api: list audit events failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	dto := auditEventListDTO{Data: make([]auditEventDTO, 0, len(page.Events))}
	for _, rec := range page.Events {
		dto.Data = append(dto.Data, toAuditEventDTO(rec))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		dto.NextCursor = &c
	}
	writeAPIJSON(w, h.logger, http.StatusOK, dto)
}

// handleAuditExport implements GET /api/v1/audit/export (admin,
// viewer, auditor): streams every matching event as JSON Lines
// (audit.ExportJSONL), in ascending seq order, without buffering the
// full result set (CLAUDE.md invariant #4, SR-128-3). Unlike
// handleAuditCollection, this endpoint is deliberately not paginated —
// api/openapi.yaml's description directs a caller wanting a bounded
// export to filter by from/to/type instead.
func (h *APIHandler) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w, "GET")
		return
	}
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer, store.RoleAuditor); !ok {
		return
	}

	q := r.URL.Query()
	filter := audit.Filter{}

	if raw := q.Get("type"); raw != "" {
		typ := audit.Type(raw)
		if !typ.Valid() {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid value for query parameter \"type\"")
			return
		}
		filter.Type = typ
	}

	from, ok := parseTimeParam(w, r, h.logger, "from")
	if !ok {
		return
	}
	filter.From = from

	to, ok := parseTimeParam(w, r, h.logger, "to")
	if !ok {
		return
	}
	filter.To = to

	// Headers must be set before the first byte is streamed: once
	// ExportJSONL starts writing, the status line is committed and
	// cannot be changed to a later error response (the same streaming
	// contract internal/adapters/http's download path already follows
	// for large bodies).
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	if err := audit.ExportJSONL(r.Context(), h.auditReader, w, filter); err != nil {
		// The 200 status and any bytes already streamed cannot be taken
		// back; the failure is only observable server-side (matching
		// audit.ExportJSONL's own doc comment: a client seeing a
		// truncated stream should treat it as "discard, do not resume
		// from here").
		h.logger.Error("api: export audit events failed", "error", err.Error())
	}
}
