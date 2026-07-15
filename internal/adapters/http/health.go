package http

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// ReadinessCheck is a single named dependency probe /readyz runs
// (US-7.2/T-7.2.3, ATR-194). Name is a short, stable identifier
// ("database", "storage", "policy") returned in the JSON response body
// so an operator can tell which dependency is degraded — Check's error
// itself is only logged server-side, never included in the response
// (SR-130-1/"no leakage of sensitive details in an unauthenticated
// endpoint").
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// HealthHandler serves /healthz (liveness) and /readyz (readiness) for
// container/orchestrator probes (T-7.2.3, Docker/Kubernetes healthcheck
// and readinessProbe). Both routes are mounted without authentication
// (SR-130-1 explicitly excepts health from the deny-by-default auth
// policy that will cover the rest of the API surface, T-8.1.2) and are
// designed to be fast, side-effect-free, and to never reveal
// dependency-specific error detail to the caller.
type HealthHandler struct {
	checks  []ReadinessCheck
	timeout time.Duration
	logger  *slog.Logger
}

// defaultReadinessTimeout bounds how long a single /readyz call may
// take across all configured checks combined, so a hung dependency
// cannot make the readiness probe itself hang indefinitely (T-7.2.3
// "fast, does not add load").
const defaultReadinessTimeout = 5 * time.Second

// NewHealthHandler constructs a HealthHandler. checks is run, in
// order, on every /readyz request; logger receives the underlying
// error for any failing check (never sent to the client). A nil
// logger is replaced with a discarding one.
func NewHealthHandler(checks []ReadinessCheck, logger *slog.Logger) *HealthHandler {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &HealthHandler{checks: checks, timeout: defaultReadinessTimeout, logger: logger}
}

// Liveness implements /healthz: process is up and able to serve HTTP
// at all. It performs no dependency checks and never fails once the
// server itself is accepting connections.
func (h *HealthHandler) Liveness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readinessCheckResult is one check's outcome in the /readyz JSON
// response body: only the check's name and a boolean, never the
// underlying error text (SR-130-1).
type readinessCheckResult struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
}

// readinessResponse is the full /readyz JSON response body.
type readinessResponse struct {
	Status string                 `json:"status"` // "ok" or "unavailable"
	Checks []readinessCheckResult `json:"checks"`
}

// Readiness implements /readyz: runs every configured ReadinessCheck
// (US-7.2/T-7.2.3) and reports 200 if all pass, 503 if any fails.
// Every check runs against a single shared deadline (h.timeout) so one
// hung dependency cannot block the response beyond that bound.
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	results := make([]readinessCheckResult, 0, len(h.checks))
	allOK := true
	for _, c := range h.checks {
		err := c.Check(ctx)
		ok := err == nil
		if !ok {
			allOK = false
			h.logger.Warn("readiness check failed", "check", c.Name, "error", err.Error())
		}
		results = append(results, readinessCheckResult{Name: c.Name, OK: ok})
	}

	status := http.StatusOK
	statusText := "ok"
	if !allOK {
		status = http.StatusServiceUnavailable
		statusText = "unavailable"
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// Encoding errors here can only occur after headers are already
	// written (the body is a small, always-marshalable struct), so
	// there is nothing left to do but leave the (possibly truncated)
	// response as-is; there is no separate error channel for an
	// already-committed response.
	_ = json.NewEncoder(w).Encode(readinessResponse{Status: statusText, Checks: results})
}
