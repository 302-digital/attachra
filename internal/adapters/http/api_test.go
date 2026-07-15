package http_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// defaultTestPolicyYAML is a minimal, always-valid policy document used
// as the default active policy for tests that do not care about its
// content (role enforcement, generic wiring), and as the starting point
// for tests (policies_test.go) that overwrite it and reload.
const defaultTestPolicyYAML = `
version: 1
name: "test-policy"
rules: []
default:
  action: pass
`

// newTestPolicyStore writes content to a fresh file under t.TempDir()
// and loads it into a *policy.Store, returning both the store and the
// file path (reload tests rewrite the file at that path and call
// POST /policies/reload).
func newTestPolicyStore(t *testing.T, content string) (*policy.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	st, err := policy.NewStore(path)
	if err != nil {
		t.Fatalf("policy.NewStore(%q) error = %v, want nil", path, err)
	}
	return st, path
}

// newTestLinkEngine builds a link.Engine over st with fixed, valid
// Defaults, recording its audit events into st (sqlite.Store also
// implements audit.AuditSink), matching the pattern
// internal/core/link's own tests use.
func newTestLinkEngine(t *testing.T, st *sqlite.Store) *link.Engine {
	t.Helper()

	e, err := link.NewEngine(st, link.Defaults{
		TTL:          72 * time.Hour,
		MaxDownloads: 0,
		TokenBytes:   link.MinTokenBytes,
	}, st)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}
	return e
}

// newAPITestServer builds an APIHandler over a fresh sqlite store, mounts
// it via NewServer (nil download deps are unused by /api/v1 routes), and
// returns an httptest.Server plus the underlying token store so a test
// can seed tokens directly.
func newAPITestServer(t *testing.T) (*httptest.Server, *sqlite.Store, *metrics.Metrics) {
	t.Helper()

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "api-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New()
	linkEngine := newTestLinkEngine(t, st)
	policyStore, _ := newTestPolicyStore(t, defaultTestPolicyYAML)
	// A generous auth-failure budget keeps unrelated tests (which fire
	// several deliberately-unauthenticated probes from one client IP) from
	// tripping the anti-brute-force throttle; TestAPIAuthFailureThrottle
	// builds its own handler with a tight budget to exercise it.
	api := adapterhttp.NewAPIHandler(st, st, linkEngine, policyStore, logger, st, st, m, adapterhttp.APIConfig{
		MaxBodyBytes:          512,
		AuthFailuresPerMinute: 1000,
		AuthFailuresBurst:     1000,
	})

	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)

	return ts, st, m
}

// seedToken mints a token of the given role directly in st and returns
// its raw secret (the value a client would send as a Bearer credential).
func seedToken(t *testing.T, st *sqlite.Store, name string, role store.Role) (id, secret string) {
	t.Helper()

	id, err := store.NewTokenID()
	if err != nil {
		t.Fatalf("NewTokenID() error = %v", err)
	}
	secret, hash, err := store.GenerateAPISecret(store.MinAPISecretBytes)
	if err != nil {
		t.Fatalf("GenerateAPISecret() error = %v", err)
	}
	if err := st.CreateAPIToken(context.Background(), store.NewAPITokenParams{
		ID: id, Name: name, Role: role, TokenHash: hash,
	}); err != nil {
		t.Fatalf("CreateAPIToken() error = %v", err)
	}
	return id, secret
}

// do issues a request to the test server with an optional Bearer secret
// and body, returning the response.
func do(t *testing.T, ts *httptest.Server, method, path, bearer, body string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	return resp
}

// decodeError reads the response body as the API's Error envelope.
func decodeError(t *testing.T, resp *http.Response) (code string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	return env.Error.Code
}

func TestAPIDenyByDefault(t *testing.T) {
	ts, _, _ := newAPITestServer(t)

	// No Authorization header at all: every /api/v1 route is behind auth
	// (SR-130-1), so an unauthenticated request never reaches a handler.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/api-tokens"},
		{http.MethodPost, "/api/v1/api-tokens"},
		{http.MethodGet, "/api/v1/api-tokens/anything"},
		{http.MethodDelete, "/api/v1/api-tokens/anything"},
		{http.MethodGet, "/api/v1/unknown-resource"}, // even an unknown path is 401, not 404.
	} {
		resp := do(t, ts, tc.method, tc.path, "", "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without token: status = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
		if code := decodeError(t, resp); code != "unauthorized" {
			t.Errorf("%s %s: error code = %q, want unauthorized", tc.method, tc.path, code)
		}
	}
}

func TestAPIInvalidAndRevokedTokenRejected(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	id, secret := seedToken(t, st, "admin", store.RoleAdmin)

	// A garbage bearer is 401.
	resp := do(t, ts, http.MethodGet, "/api/v1/api-tokens", "not-a-real-token", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("garbage bearer: status = %d, want 401", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// The real token works.
	resp = do(t, ts, http.MethodGet, "/api/v1/api-tokens", secret, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid admin bearer: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Revoke it, then the same secret is immediately rejected (SR-130-2).
	if err := st.RevokeAPIToken(context.Background(), id, "2026-07-09T00:00:00Z"); err != nil {
		t.Fatalf("RevokeAPIToken() error = %v", err)
	}
	resp = do(t, ts, http.MethodGet, "/api/v1/api-tokens", secret, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked bearer: status = %d, want 401 (revocation must be immediate)", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestAPIRoleEnforcement(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	_, viewerSecret := seedToken(t, st, "viewer", store.RoleViewer)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	// api-tokens management is admin-only (x-required-role: [admin]).
	// viewer and auditor are authenticated but forbidden (403), not 401 —
	// the distinction proves the role check runs after successful auth.
	for _, tc := range []struct {
		name   string
		secret string
	}{
		{"viewer", viewerSecret},
		{"auditor", auditorSecret},
	} {
		resp := do(t, ts, http.MethodGet, "/api/v1/api-tokens", tc.secret, "")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s listing tokens: status = %d, want 403", tc.name, resp.StatusCode)
		}
		if code := decodeError(t, resp); code != "forbidden" {
			t.Errorf("%s listing tokens: error code = %q, want forbidden", tc.name, code)
		}
	}

	// admin is allowed.
	resp := do(t, ts, http.MethodGet, "/api/v1/api-tokens", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin listing tokens: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestAPITokenCRUDLifecycle(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	// Create a viewer token.
	resp := do(t, ts, http.MethodPost, "/api/v1/api-tokens", adminSecret, `{"name":"ci","role":"viewer"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: status = %d, want 201", resp.StatusCode)
	}
	var created struct {
		ID         string  `json:"id"`
		Name       string  `json:"name"`
		Role       string  `json:"role"`
		Secret     string  `json:"secret"`
		LastUsedAt *string `json:"last_used_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	_ = resp.Body.Close()

	if created.Secret == "" {
		t.Errorf("create response secret is empty, want the one-time secret")
	}
	if created.Role != "viewer" || created.Name != "ci" {
		t.Errorf("create response = %+v, want role=viewer name=ci", created)
	}
	if created.LastUsedAt != nil {
		t.Errorf("last_used_at = %v on a fresh token, want null", *created.LastUsedAt)
	}

	// The freshly created viewer secret actually authenticates.
	resp = do(t, ts, http.MethodGet, "/api/v1/api-tokens/"+created.ID, created.Secret, "")
	if resp.StatusCode != http.StatusForbidden {
		// viewer cannot read the admin-only token resource.
		t.Errorf("viewer GET token: status = %d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// admin can GET the token metadata (never a secret).
	resp = do(t, ts, http.MethodGet, "/api/v1/api-tokens/"+created.ID, adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET token: status = %d, want 200", resp.StatusCode)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(bodyBytes), "secret") {
		t.Errorf("GET token body contains a secret field, want metadata only: %s", bodyBytes)
	}

	// admin revokes it -> 204, and a re-GET still shows metadata (200).
	resp = do(t, ts, http.MethodDelete, "/api/v1/api-tokens/"+created.ID, adminSecret, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete token: status = %d, want 204", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// The revoked viewer secret no longer authenticates.
	resp = do(t, ts, http.MethodGet, "/api/v1/api-tokens", created.Secret, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked token auth: status = %d, want 401", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Revoking a non-existent token is 404.
	resp = do(t, ts, http.MethodDelete, "/api/v1/api-tokens/does-not-exist", adminSecret, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete missing token: status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestAPITokenCreateAndRevokeRecordAuditEvents verifies that both a
// successful token creation and a successful revocation through the
// REST API record a TypeTokenChange audit event carrying the acting
// admin's identity, the affected token's id/name/role, and never the
// token secret or its hash (ATR-296, SR-128-2, invariant #5).
func TestAPITokenCreateAndRevokeRecordAuditEvents(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	adminID, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	resp := do(t, ts, http.MethodPost, "/api/v1/api-tokens", adminSecret, `{"name":"ci-runner","role":"viewer"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: status = %d, want 201", resp.StatusCode)
	}
	var created struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	_ = resp.Body.Close()

	resp = do(t, ts, http.MethodDelete, "/api/v1/api-tokens/"+created.ID, adminSecret, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke token: status = %d, want 204", resp.StatusCode)
	}
	_ = resp.Body.Close()

	got := collectAPITokenAuditEvents(t, st)

	var sawCreate, sawRevoke bool
	for _, ev := range got {
		if ev.Type != audit.TypeTokenChange || ev.Details["token_id"] != created.ID {
			continue
		}
		if ev.Actor != adminID {
			t.Errorf("event Actor = %q, want %q", ev.Actor, adminID)
		}
		if ev.Details["name"] != "ci-runner" {
			t.Errorf("event Details[name] = %v, want ci-runner", ev.Details["name"])
		}
		if ev.Details["role"] != "viewer" {
			t.Errorf("event Details[role] = %v, want viewer", ev.Details["role"])
		}
		for _, secretish := range []string{created.Secret, adminSecret} {
			for _, v := range ev.Details {
				if s, ok := v.(string); ok && secretish != "" && s == secretish {
					t.Fatalf("event Details = %+v contains a raw secret, want none", ev.Details)
				}
			}
		}
		switch ev.Details["action"] {
		case "create":
			sawCreate = true
		case "revoke":
			sawRevoke = true
		}
	}
	if !sawCreate {
		t.Error("no TypeTokenChange event with Details[action]=create found")
	}
	if !sawRevoke {
		t.Error("no TypeTokenChange event with Details[action]=revoke found")
	}
}

// collectAPITokenAuditEvents drains every audit.Recorded event from st
// (used as both APITokenStore and AuditSink by newAPITestServer).
func collectAPITokenAuditEvents(t *testing.T, st *sqlite.Store) []audit.Recorded {
	t.Helper()
	var got []audit.Recorded
	if err := st.StreamEvents(context.Background(), audit.Filter{}, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	return got
}

func TestAPICreateTokenValidation(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"missing name", `{"role":"viewer"}`},
		{"bad role", `{"name":"x","role":"superuser"}`},
		{"malformed json", `{"name":`},
		{"unknown field", `{"name":"x","role":"viewer","extra":true}`},
	} {
		resp := do(t, ts, http.MethodPost, "/api/v1/api-tokens", adminSecret, tc.body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", tc.name, resp.StatusCode)
		}
		if code := decodeError(t, resp); code != "bad_request" {
			t.Errorf("%s: error code = %q, want bad_request", tc.name, code)
		}
	}
}

func TestAPIBodyLimit(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	// MaxBodyBytes is 512 in the test server; a larger body is rejected
	// with 413 before the handler can buffer it (SR-130-5).
	big := `{"name":"` + strings.Repeat("a", 2000) + `","role":"viewer"}`
	resp := do(t, ts, http.MethodPost, "/api/v1/api-tokens", adminSecret, big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status = %d, want 413", resp.StatusCode)
	}
	if code := decodeError(t, resp); code != "payload_too_large" {
		t.Errorf("oversized body: error code = %q, want payload_too_large", code)
	}
}

func TestAPIMethodNotAllowed(t *testing.T) {
	ts, st, _ := newAPITestServer(t)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	resp := do(t, ts, http.MethodPut, "/api/v1/api-tokens", adminSecret, "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT collection: status = %d, want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "GET, POST" {
		t.Errorf("Allow header = %q, want \"GET, POST\"", allow)
	}
	_ = resp.Body.Close()
}

func TestAPIAuthFailureThrottle(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "throttle-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	linkEngine := newTestLinkEngine(t, st)
	// A tight budget: 3 auth failures per IP, then 429 (anti-brute-force,
	// SR-130-5). This test never touches /policies, so a nil policy Store
	// (matching community-edition passthrough mode) is fine.
	api := adapterhttp.NewAPIHandler(st, st, linkEngine, nil, logger, st, st, metrics.New(), adapterhttp.APIConfig{
		AuthFailuresPerMinute: 3,
		AuthFailuresBurst:     3,
	})
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)

	// Fire a burst of bad-bearer requests from one client IP and confirm
	// the tail is throttled with 429 rather than an endless stream of 401s.
	var got401, got429 int
	for i := 0; i < 8; i++ {
		resp := do(t, ts, http.MethodGet, "/api/v1/api-tokens", "bad-token", "")
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			got401++
		case http.StatusTooManyRequests:
			got429++
			if ra := resp.Header.Get("Retry-After"); ra == "" {
				t.Errorf("429 response missing Retry-After header")
			}
		default:
			t.Errorf("unexpected status %d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
	if got401 == 0 || got429 == 0 {
		t.Errorf("expected a mix of 401 then 429, got %d/%d", got401, got429)
	}
}

// TestAPIAuthFailureThrottleBehindTrustedProxyUsesForwardedIP verifies
// ATR-311 for the REST API surface: with http.trusted_proxies
// configuring the reverse proxy's address as trusted, the per-IP
// auth-failure throttle (SR-130-5) keys off the real client address
// carried in X-Forwarded-For rather than the proxy's own RemoteAddr —
// otherwise every request proxied through the same nginx instance
// shares one budget, and one noisy client can lock out every other
// client's legitimate (mistyped) token attempts.
//
// This exercises api.Handler() directly against an httptest.Recorder
// (rather than a real httptest.Server) so RemoteAddr/X-Forwarded-For
// can be set explicitly per request, since a real TCP client always
// reports its actual loopback RemoteAddr.
func TestAPIAuthFailureThrottleBehindTrustedProxyUsesForwardedIP(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "throttle-proxy-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	trusted, err := adapterhttp.ParseTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies() error = %v, want nil", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	linkEngine := newTestLinkEngine(t, st)
	api := adapterhttp.NewAPIHandler(st, st, linkEngine, nil, logger, st, st, metrics.New(), adapterhttp.APIConfig{
		AuthFailuresPerMinute: 2,
		AuthFailuresBurst:     2,
		TrustedProxies:        trusted,
	})
	handler := api.Handler()

	requestAs := func(forwardedFor string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/api-tokens", nil)
		req.RemoteAddr = "127.0.0.1:44444" // The trusted proxy's own loopback peer address.
		req.Header.Set("X-Forwarded-For", forwardedFor)
		req.Header.Set("Authorization", "Bearer bad-token")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// Client A exhausts its 2-failure budget.
	if code := requestAs("203.0.113.1"); code != http.StatusUnauthorized {
		t.Fatalf("client A attempt #1 status = %d, want 401", code)
	}
	if code := requestAs("203.0.113.1"); code != http.StatusUnauthorized {
		t.Fatalf("client A attempt #2 status = %d, want 401", code)
	}
	if code := requestAs("203.0.113.1"); code != http.StatusTooManyRequests {
		t.Fatalf("client A attempt #3 status = %d, want 429 (own budget exhausted)", code)
	}

	// Client B, proxied through the same nginx instance (same
	// RemoteAddr), must have its own untouched budget.
	if code := requestAs("203.0.113.2"); code != http.StatusUnauthorized {
		t.Fatalf("client B attempt #1 status = %d, want 401 (independent budget)", code)
	}
}

func TestAPIRecoversFromHandlerPanicWithoutLeak(t *testing.T) {
	// A store whose GetAPIToken panics simulates an unexpected failure
	// deep in a handler; the recovery middleware must turn it into a
	// generic 500 with no internal detail (SR-130-1/SR-130-5).
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "panic-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	id, secret := seedToken(t, st, "admin", store.RoleAdmin)
	panicking := panicTokenStore{Store: st}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	linkEngine := newTestLinkEngine(t, st)
	// This test never touches /policies, so a nil policy Store (matching
	// community-edition passthrough mode) is fine.
	api := adapterhttp.NewAPIHandler(panicking, st, linkEngine, nil, logger, st, st, metrics.New(), adapterhttp.APIConfig{})
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)

	resp := do(t, ts, http.MethodGet, "/api/v1/api-tokens/"+id, secret, "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("panicking handler: status = %d, want 500", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "boom") || strings.Contains(string(body), "panic") {
		t.Errorf("500 body leaked internal detail: %s", body)
	}
	if !strings.Contains(string(body), `"internal"`) {
		t.Errorf("500 body = %s, want the generic internal error envelope", body)
	}
}

// panicTokenStore wraps a real store but panics on the GetAPIToken path,
// exercising the recovery middleware. Auth (LookupActiveAPIToken) is
// delegated to the real store so the request reaches the handler.
type panicTokenStore struct {
	*sqlite.Store
}

func (p panicTokenStore) GetAPIToken(_ context.Context, _ string) (store.APIToken, error) {
	panic("boom: simulated internal failure")
}
