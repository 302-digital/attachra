package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// API error codes (api/openapi.yaml, schema Error.code). This is the
// complete, stable set the contract enumerates; only a subset is emitted
// by the endpoints implemented so far (T-8.1.2/T-8.1.7), the rest are
// declared here so the resource handlers added by ATR-197..200 reuse the
// same constants rather than reinventing string literals.
const (
	errCodeBadRequest       = "bad_request"
	errCodeUnauthorized     = "unauthorized"
	errCodeForbidden        = "forbidden"
	errCodeNotFound         = "not_found"
	errCodeConflict         = "conflict"
	errCodeHeld             = "held"
	errCodeInvalidPolicy    = "invalid_policy"
	errCodeValidationFailed = "validation_failed"
	errCodePayloadTooLarge  = "payload_too_large"
	errCodeRateLimited      = "rate_limited"
	errCodeGone             = "gone"
	errCodeInternal         = "internal"
)

// apiError is the single JSON error envelope every non-2xx /api/v1
// response carries (api/openapi.yaml, schema Error). Its message is
// always a safe, human-readable string that never embeds internal detail
// — no stack trace, driver error text, SQL or file path (SR-130-1): the
// caller of writeAPIError chooses a fixed, curated message, and any
// diagnostic detail is logged server-side instead of returned.
type apiError struct {
	Error apiErrorBody `json:"error"`
}

type apiErrorBody struct {
	Code    string           `json:"code"`
	Message string           `json:"message"`
	Details []apiErrorDetail `json:"details,omitempty"`
}

// apiErrorDetail mirrors the contract's ValidationIssue: a structured,
// per-field issue used only by policy validate/reload (ATR-199). Its
// JSON shape (path/rule_name/message) is identical to the
// ValidateResponse schema's own issue items, so policies.go reuses this
// type there too rather than declaring a second, structurally identical
// DTO.
type apiErrorDetail struct {
	Path     string `json:"path"`
	RuleName string `json:"rule_name,omitempty"`
	Message  string `json:"message"`
}

// writeAPIError renders a single apiError as JSON with the given status.
// message must be a static, non-sensitive string (see apiError's doc
// comment); callers with diagnostic detail log it separately rather than
// passing it here.
func writeAPIError(w http.ResponseWriter, logger *slog.Logger, status int, code, message string) {
	writeAPIJSON(w, logger, status, apiError{Error: apiErrorBody{Code: code, Message: message}})
}

// writeAPIErrorWithDetails is like writeAPIError but also attaches the
// contract's optional per-field `details` array (api/openapi.yaml,
// Error.details: "Populated only by policy validate/reload failures").
// Used by POST /policies/reload's 409 response (ATR-199) to report
// structured issues alongside the human-readable message.
func writeAPIErrorWithDetails(w http.ResponseWriter, logger *slog.Logger, status int, code, message string, details []apiErrorDetail) {
	writeAPIJSON(w, logger, status, apiError{Error: apiErrorBody{Code: code, Message: message, Details: details}})
}

// writeAPIJSON serializes v as JSON with the given status and the API's
// standard headers. A marshal or write failure cannot change the
// already-committed status line, so it is only logged. The response is
// never cached (an API resource view must not be retained by an
// intermediary) and is always typed application/json.
func writeAPIJSON(w http.ResponseWriter, logger *slog.Logger, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// A value this package constructs should always marshal; if it
		// somehow does not, fall back to a fixed 500 envelope rather than
		// leaking the marshal error to the client.
		if logger != nil {
			logger.Error("api: failed to marshal response", "error", err.Error())
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"an internal error occurred"}}`))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil && logger != nil {
		logger.Warn("api: failed to write response body", "error", err.Error())
	}
}
