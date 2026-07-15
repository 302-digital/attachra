package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
)

// apiTokenDTO is the JSON shape of an API token's metadata (api/openapi.yaml,
// schema ApiToken). It deliberately never carries the token secret or its
// hash — only issuance metadata (invariant #5, SR-130-2). last_used_at is
// a pointer so it renders as JSON null (not an empty string) for a token
// that has never authenticated a request, matching the contract's
// nullable field.
type apiTokenDTO struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Role       string  `json:"role"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}

// apiTokenListDTO is the paginated list envelope (schema ApiTokenList +
// PageMeta). next_cursor is a pointer so it renders as null on the last
// page, per the PageMeta contract.
type apiTokenListDTO struct {
	Data       []apiTokenDTO `json:"data"`
	NextCursor *string       `json:"next_cursor"`
}

// apiTokenCreateRequestDTO is the create request body (schema
// ApiTokenCreateRequest).
type apiTokenCreateRequestDTO struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// apiTokenCreateResponseDTO is the create response (schema
// ApiTokenCreateResponse): the token metadata plus the one-time secret,
// the only place the raw bearer value is ever returned (invariant #5,
// SR-130-2).
type apiTokenCreateResponseDTO struct {
	apiTokenDTO
	Secret string `json:"secret"`
}

// toAPITokenDTO maps a store.APIToken to its wire shape, formatting
// timestamps as RFC3339Nano UTC and collapsing a zero LastUsedAt to a
// JSON null.
func toAPITokenDTO(t store.APIToken) apiTokenDTO {
	dto := apiTokenDTO{
		ID:        t.ID,
		Name:      t.Name,
		Role:      string(t.Role),
		CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if !t.LastUsedAt.IsZero() {
		s := t.LastUsedAt.UTC().Format(time.RFC3339Nano)
		dto.LastUsedAt = &s
	}
	return dto
}

// handleAPITokensCollection dispatches the /api/v1/api-tokens collection
// by method. Both operations are admin-only (x-required-role: [admin],
// SR-130-3): token management is never available to viewer or auditor.
func (h *APIHandler) handleAPITokensCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listAPITokens(w, r)
	case http.MethodPost:
		h.createAPIToken(w, r)
	default:
		h.writeMethodNotAllowed(w, "GET, POST")
	}
}

// handleAPITokenItem dispatches the /api/v1/api-tokens/{tokenId} item by
// method. Both operations are admin-only.
func (h *APIHandler) handleAPITokenItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getAPIToken(w, r)
	case http.MethodDelete:
		h.revokeAPIToken(w, r)
	default:
		h.writeMethodNotAllowed(w, "GET, DELETE")
	}
}

// listAPITokens implements GET /api/v1/api-tokens (admin): a cursor-paginated
// page of token metadata, never any secret (SR-130-5, invariant #5).
func (h *APIHandler) listAPITokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin); !ok {
		return
	}

	limit, ok := parseLimit(w, r, h.logger)
	if !ok {
		return
	}

	page, err := h.tokens.ListAPITokens(r.Context(), store.APITokenListParams{
		Limit:  limit,
		Cursor: r.URL.Query().Get("cursor"),
	})
	if err != nil {
		// A malformed client cursor is a 400; anything else is an
		// internal failure surfaced generically (never the store error).
		if errors.Is(err, store.ErrInvalidCursor) {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid cursor")
			return
		}
		h.logger.Error("api: list tokens failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	dto := apiTokenListDTO{Data: make([]apiTokenDTO, 0, len(page.Tokens))}
	for _, t := range page.Tokens {
		dto.Data = append(dto.Data, toAPITokenDTO(t))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		dto.NextCursor = &c
	}
	writeAPIJSON(w, h.logger, http.StatusOK, dto)
}

// createAPIToken implements POST /api/v1/api-tokens (admin): mint a new
// token, returning its secret exactly once (invariant #5, SR-130-2).
func (h *APIHandler) createAPIToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin); !ok {
		return
	}

	var req apiTokenCreateRequestDTO
	if !decodeJSONBody(w, r, h.logger, &req) {
		return
	}

	if req.Name == "" {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "name is required")
		return
	}
	role, err := store.ParseRole(req.Role)
	if err != nil {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "role must be one of admin, viewer, auditor")
		return
	}

	id, err := store.NewTokenID()
	if err != nil {
		h.logger.Error("api: generate token id failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	secret, hash, err := store.GenerateAPISecret(store.MinAPISecretBytes)
	if err != nil {
		h.logger.Error("api: generate token secret failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	if err := h.tokens.CreateAPIToken(r.Context(), store.NewAPITokenParams{
		ID:        id,
		Name:      req.Name,
		Role:      role,
		TokenHash: hash,
	}); err != nil {
		h.logger.Error("api: create token failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	// Log the issuance (never the secret): who/what created a token is
	// security-relevant operational information (SR-113-3 keeps the secret
	// out of it). It is also recorded as a durable, tamper-evident
	// TypeTokenChange audit event (ATR-296, SR-128-2), since the slog
	// line alone can be altered or dropped by whoever controls the log
	// pipeline.
	if actor, ok := principalFrom(r.Context()); ok {
		h.logger.Info("api: created token", "token_id", id, "role", string(role), "created_by", actor.TokenID)
		h.recordTokenAuditEvent(r.Context(), "create", actor.TokenID, id, req.Name, string(role))
	}

	created, err := h.tokens.GetAPIToken(r.Context(), id)
	if err != nil {
		h.logger.Error("api: reload created token failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	resp := apiTokenCreateResponseDTO{apiTokenDTO: toAPITokenDTO(created), Secret: secret}
	writeAPIJSON(w, h.logger, http.StatusCreated, resp)
}

// getAPIToken implements GET /api/v1/api-tokens/{tokenId} (admin).
func (h *APIHandler) getAPIToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin); !ok {
		return
	}

	id := r.PathValue("tokenId")
	tok, err := h.tokens.GetAPIToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
			return
		}
		h.logger.Error("api: get token failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}
	writeAPIJSON(w, h.logger, http.StatusOK, toAPITokenDTO(tok))
}

// revokeAPIToken implements DELETE /api/v1/api-tokens/{tokenId} (admin):
// revocation takes effect immediately for the next request bearing that
// token's secret (SR-130-2). Returns 204 on success.
func (h *APIHandler) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authorize(w, r, store.RoleAdmin)
	if !ok {
		return
	}

	id := r.PathValue("tokenId")
	if err := h.tokens.RevokeAPIToken(r.Context(), id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, h.logger, http.StatusNotFound, errCodeNotFound, "no resource found for the given identifier")
			return
		}
		h.logger.Error("api: revoke token failed", "error", err.Error())
		writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
		return
	}

	// Reload the revoked token's non-secret metadata (name, role) for the
	// audit event below, best-effort: a reload failure must not turn an
	// already-successful revocation into an error response (CLAUDE.md
	// invariant #3's spirit applied to this control-plane path), it just
	// means the event carries less context.
	var name, role string
	if tok, err := h.tokens.GetAPIToken(r.Context(), id); err != nil {
		h.logger.Warn("api: reload revoked token metadata failed", "token_id", id, "error", err.Error())
	} else {
		name, role = tok.Name, string(tok.Role)
	}

	h.logger.Info("api: revoked token", "token_id", id, "revoked_by", actor.TokenID)
	h.recordTokenAuditEvent(r.Context(), "revoke", actor.TokenID, id, name, role)
	w.WriteHeader(http.StatusNoContent)
}

// recordTokenAuditEvent records a TypeTokenChange event for the create
// or revoke action against the API token identified by tokenID,
// attributed to actor (ATR-296, SR-128-2). name and role may be empty
// (e.g. the post-revoke metadata reload above failed) — the event is
// still recorded with whatever non-secret context is available, since
// token_id and actor alone are enough to correlate it with the store's
// own token row. It never carries the token's secret or hash
// (invariant #5). Recording is best-effort, mirroring
// internal/core/link.Engine.recordAudit: a sink failure is logged but
// must never change the HTTP response already decided by the caller.
func (h *APIHandler) recordTokenAuditEvent(ctx context.Context, action, actor, tokenID, name, role string) {
	details := map[string]any{"action": action, "token_id": tokenID}
	if name != "" {
		details["name"] = name
	}
	if role != "" {
		details["role"] = role
	}
	if _, err := h.audit.Record(ctx, audit.Event{
		Type:    audit.TypeTokenChange,
		Actor:   actor,
		Details: details,
	}); err != nil {
		h.logger.Warn("api: failed to record token audit event", "action", action, "token_id", tokenID, "error", err.Error())
	}
}

// parseLimit reads and validates the shared `limit` query parameter
// (api/openapi.yaml parameter Limit: integer 1..200). An absent limit is
// valid (the store defaults it); a present but non-integer or
// out-of-range value is a 400, so a client cannot smuggle an unbounded or
// nonsensical page size. It writes the error response itself and returns
// ok=false when it does.
func parseLimit(w http.ResponseWriter, r *http.Request, logger *slog.Logger) (limit int, ok bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 0, true // store applies its default.
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxAPIPageLimit {
		writeAPIError(w, logger, http.StatusBadRequest, errCodeBadRequest, "invalid value for query parameter \"limit\"")
		return 0, false
	}
	return n, true
}

// maxAPIPageLimit mirrors the contract's Limit maximum (api/openapi.yaml).
const maxAPIPageLimit = 200
