package http

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// pathParamPattern matches one {name}-style path parameter segment in
// an apiRoute.pattern (e.g. "{linkId}", "{tokenId}").
var pathParamPattern = regexp.MustCompile(`\{[^{}]+\}`)

// concretePath substitutes every {param} segment in pattern with a
// fixed placeholder, turning a route pattern into a request path a
// real HTTP client can issue. The substituted value never needs to
// resolve to a real resource: every handler this test exercises calls
// authorize() (the role check) before any store lookup, so an
// unknown/placeholder id still reaches the 403 this test asserts,
// never a 404.
func concretePath(pattern string) string {
	return pathParamPattern.ReplaceAllString(pattern, "test-placeholder")
}

// candidateMethods are every HTTP method any /api/v1 handler in this
// package currently dispatches on (GET for reads, POST for actions/
// mutations, DELETE for api-tokens revoke). Trying all three against
// every route, regardless of which verb that specific resource
// actually implements, means this test does not need to know each
// resource's accepted method set: an unsupported verb answers 405
// (still proof the auditor did not get through), and a supported one
// answers 403 (proof the role check rejected it) — either is an
// acceptable outcome; only a 2xx is not.
var candidateMethods = []string{http.MethodGet, http.MethodPost, http.MethodDelete}

// TestAuditorRoleMatrixIsRouterDerived is the ADR-015 regression guard
// for the auditor role's core guarantee: a token with RoleAuditor may
// reach GET /audit and GET /audit/export and *nothing else* anywhere
// under /api/v1.
//
// An earlier version of this guard (TestAuditorOnlyReachesAuditResources,
// internal/adapters/http/auditlist_test.go) hand-maintained its list of
// "everything else" paths to probe. That list is a fork of the real
// route table: it silently misses any route added after the list was
// written (a security review flagged /links/revoke-by-message,
// /links/revoke-by-sender, /links/{linkId}/hold and
// /links/{linkId}/unhold as already missing, plus the /policies routes
// this branch's rebase onto dev just added) — copy-pasting RoleAuditor
// into a new mutation's authorize() call would pass that hardcoded
// test forever.
//
// This version derives its negative-access list directly from
// (*APIHandler).routes(), the same declarative table newMux registers
// the live mux from (see routes' doc comment): every pattern it
// returns other than /audit and /audit/export is asserted forbidden
// to an auditor token, so a newly added resource is automatically
// covered — fail-closed by construction, not by remembering to update
// a parallel list.
func TestAuditorRoleMatrixIsRouterDerived(t *testing.T) {
	h, ts := newRoleMatrixTestServer(t)
	auditorSecret := seedRoleMatrixToken(t, h, "auditor", store.RoleAuditor)

	allowed := map[string]bool{
		apiPrefix + "audit":        true,
		apiPrefix + "audit/export": true,
	}

	routes := h.routes()
	if len(routes) < 2 {
		t.Fatalf("routes() returned %d entries, want at least the audit/audit-export pair", len(routes))
	}

	var probed, allowedCount int
	for _, rt := range routes {
		if allowed[rt.pattern] {
			allowedCount++
			continue
		}
		probed++
		path := concretePath(rt.pattern)

		for _, method := range candidateMethods {
			resp := doRoleMatrixRequest(t, ts, method, path, auditorSecret)
			status := resp.StatusCode
			_ = resp.Body.Close()

			if status == http.StatusForbidden || status == http.StatusMethodNotAllowed {
				continue // Expected: role check rejected it, or the verb isn't supported here.
			}
			t.Errorf("auditor %s %s (pattern %q): status = %d, want 403 (or 405 if this verb is not supported) — auditor must reach ONLY /audit and /audit/export (ADR-015)",
				method, path, rt.pattern, status)
		}
	}

	if allowedCount != len(allowed) {
		t.Fatalf("routes() only matched %d of the %d expected auditor-allowed patterns — %v is stale relative to routes()", allowedCount, len(allowed), allowed)
	}
	if probed == 0 {
		t.Fatal("no non-audit routes were probed; this test would pass vacuously")
	}
	t.Logf("router-derived auditor role matrix: probed %d non-audit routes x %d methods, %d audit-allowed routes excluded", probed, len(candidateMethods), allowedCount)
}

// TestAuditorRoleMatrixPositiveAccess confirms the flip side: an
// auditor token DOES get through (200, not 403) to both allowed
// resources, so the negative sweep above is not vacuously true because
// every route including /audit itself is somehow unreachable.
func TestAuditorRoleMatrixPositiveAccess(t *testing.T) {
	h, ts := newRoleMatrixTestServer(t)
	auditorSecret := seedRoleMatrixToken(t, h, "auditor", store.RoleAuditor)

	for _, path := range []string{apiPrefix + "audit", apiPrefix + "audit/export"} {
		resp := doRoleMatrixRequest(t, ts, http.MethodGet, path, auditorSecret)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("auditor GET %s: status = %d, want 200", path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// newRoleMatrixTestServer builds a minimal, real APIHandler (backed by
// a fresh sqlite store and a working link.Engine) and starts it behind
// an httptest.Server, mirroring newAPITestServer in api_test.go. It is
// duplicated here (rather than reused) because this file is a
// whitebox test (package http, so it can call the unexported routes()
// method) while api_test.go's helpers live in the external http_test
// package and are not visible from here.
func newRoleMatrixTestServer(t *testing.T) (*APIHandler, *httptest.Server) {
	t.Helper()

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "role-matrix-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	linkEngine, err := link.NewEngine(st, link.Defaults{
		TTL:          72 * time.Hour,
		MaxDownloads: 0,
		TokenBytes:   link.MinTokenBytes,
	}, st)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}

	// nil policy Store: this test never calls /policies, and a nil
	// Store is the same community-edition passthrough mode
	// cmd/attachra itself falls back to (see policies.go).
	h := NewAPIHandler(st, st, linkEngine, nil, logger, st, st, metrics.New(), APIConfig{
		AuthFailuresPerMinute: 100000,
		AuthFailuresBurst:     100000,
	})
	ts := httptest.NewServer(h.Handler())
	t.Cleanup(ts.Close)
	return h, ts
}

// seedRoleMatrixToken mints a token of the given role directly against
// h's underlying token store and returns its raw secret.
func seedRoleMatrixToken(t *testing.T, h *APIHandler, name string, role store.Role) string {
	t.Helper()

	id, err := store.NewTokenID()
	if err != nil {
		t.Fatalf("NewTokenID() error = %v", err)
	}
	secret, hash, err := store.GenerateAPISecret(store.MinAPISecretBytes)
	if err != nil {
		t.Fatalf("GenerateAPISecret() error = %v", err)
	}
	if err := h.tokens.CreateAPIToken(context.Background(), store.NewAPITokenParams{
		ID: id, Name: name, Role: role, TokenHash: hash,
	}); err != nil {
		t.Fatalf("CreateAPIToken() error = %v", err)
	}
	return secret
}

// doRoleMatrixRequest issues a bearer-authenticated request against ts,
// with a body only for methods that plausibly carry one (POST): an
// empty JSON object is a harmless, always-parseable body for every
// mutation this package defines, so a request never fails on body
// decoding before it even reaches the role check under test.
func doRoleMatrixRequest(t *testing.T, ts *httptest.Server, method, path, bearer string) *http.Response {
	t.Helper()

	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	return resp
}
