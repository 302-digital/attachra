package http_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// validDryRunPolicyYAML is the active policy used by most /policies
// tests here: a single rule blocking ".exe" attachments, falling back
// to pass otherwise, so dry-run has a non-trivial rule to exercise.
const validDryRunPolicyYAML = `
version: 1
name: "block-exe"
rules:
  - name: "block executables"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "no executables"
default:
  action: pass
`

// newPoliciesTestServer builds an APIHandler over a fresh sqlite store
// and a real *policy.Store loaded from a temp file containing
// policyYAML, mounts it via httptest.NewServer, and returns the
// server, the token store (to seed tokens) and the policy file's path
// (so reload tests can overwrite it before calling POST
// /policies/reload). Unlike newAPITestServer's deliberately tiny
// 512-byte MaxBodyBytes default (which exists to exercise
// TestAPIBodyLimit), this uses a generous limit since POST
// /policies/validate exercises full YAML documents.
func newPoliciesTestServer(t *testing.T, policyYAML string) (ts *httptest.Server, st *sqlite.Store, policyPath string) {
	t.Helper()

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "policies-api-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	policyPath = filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	policyStore, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore(%q) error = %v, want nil", policyPath, err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	linkEngine := newTestLinkEngine(t, st)
	api := adapterhttp.NewAPIHandler(st, st, linkEngine, policyStore, logger, st, st, metrics.New(), adapterhttp.APIConfig{
		MaxBodyBytes:          1 << 16,
		AuthFailuresPerMinute: 1000,
		AuthFailuresBurst:     1000,
	})

	ts = httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)
	return ts, st, policyPath
}

// TestPoliciesRoleEnforcement covers every /policies operation's
// x-required-role set (SR-130-3, api/openapi.yaml): admin and viewer
// may call get/validate/dry-run — validate and dry-run are in viewer's
// allowed set because neither mutates the active policy (the contract's
// own rationale) — but only admin may reload; auditor is forbidden on
// every one of them (ADR-015: auditor is scoped to the audit log only).
func TestPoliciesRoleEnforcement(t *testing.T) {
	ts, st, _ := newPoliciesTestServer(t, validDryRunPolicyYAML)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)
	_, viewerSecret := seedToken(t, st, "viewer", store.RoleViewer)
	_, auditorSecret := seedToken(t, st, "auditor", store.RoleAuditor)

	dryRunBody := `{"sender":"a@example.com","recipients":["b@example.com"],"attachments":[{"filename":"x.pdf","size":10,"detected_type":"application/pdf"}]}`

	for _, tc := range []struct {
		name, method, path, secret, body string
		wantStatus                       int
	}{
		{"admin get current", http.MethodGet, "/api/v1/policies/current", adminSecret, "", http.StatusOK},
		{"viewer get current", http.MethodGet, "/api/v1/policies/current", viewerSecret, "", http.StatusOK},
		{"auditor get current", http.MethodGet, "/api/v1/policies/current", auditorSecret, "", http.StatusForbidden},

		{"admin validate", http.MethodPost, "/api/v1/policies/validate", adminSecret, defaultTestPolicyYAML, http.StatusOK},
		{"viewer validate", http.MethodPost, "/api/v1/policies/validate", viewerSecret, defaultTestPolicyYAML, http.StatusOK},
		{"auditor validate", http.MethodPost, "/api/v1/policies/validate", auditorSecret, defaultTestPolicyYAML, http.StatusForbidden},

		{"admin dry-run", http.MethodPost, "/api/v1/policies/dry-run", adminSecret, dryRunBody, http.StatusOK},
		{"viewer dry-run", http.MethodPost, "/api/v1/policies/dry-run", viewerSecret, dryRunBody, http.StatusOK},
		{"auditor dry-run", http.MethodPost, "/api/v1/policies/dry-run", auditorSecret, dryRunBody, http.StatusForbidden},

		{"viewer reload forbidden", http.MethodPost, "/api/v1/policies/reload", viewerSecret, "", http.StatusForbidden},
		{"auditor reload forbidden", http.MethodPost, "/api/v1/policies/reload", auditorSecret, "", http.StatusForbidden},
		{"admin reload ok", http.MethodPost, "/api/v1/policies/reload", adminSecret, "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, ts, tc.method, tc.path, tc.secret, tc.body)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusForbidden {
				if code := decodeError(t, resp); code != "forbidden" {
					t.Errorf("%s %s: error code = %q, want forbidden", tc.method, tc.path, code)
				}
			}
		})
	}
}

// validateResponseWire mirrors api/openapi.yaml's ValidateResponse for
// decoding test responses.
type validateResponseWire struct {
	Valid  bool `json:"valid"`
	Errors []struct {
		Path     string `json:"path"`
		RuleName string `json:"rule_name"`
		Message  string `json:"message"`
	} `json:"errors"`
	Warnings []struct {
		Path     string `json:"path"`
		RuleName string `json:"rule_name"`
		Message  string `json:"message"`
	} `json:"warnings"`
}

// invalidPolicyYAML has two independent validation errors (rule missing
// a name, and an invalid glob pattern) plus one warning (a `replace`
// action with an explicit ttl but no retention) — used to assert that
// POST /policies/validate reports every issue found, not just the
// first (§3.5).
const invalidPolicyYAML = `
version: 1
name: "bad-policy"
rules:
  - when:
      attachment:
        filename: ["[invalid"]
    then:
      action: pass
default:
  action: replace
  ttl: "30d"
`

// TestPoliciesValidateReturnsAllErrorsAndWarnings verifies POST
// /policies/validate reports the complete set of issues found in one
// response (not just the first), each naming its path and — when
// known — the offending rule, and never mutates the currently active
// policy (a subsequent GET /policies/current is unchanged).
func TestPoliciesValidateReturnsAllErrorsAndWarnings(t *testing.T) {
	ts, st, _ := newPoliciesTestServer(t, validDryRunPolicyYAML)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	resp := do(t, ts, http.MethodPost, "/api/v1/policies/validate", adminSecret, invalidPolicyYAML)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("validate: status = %d, want 200 (a validation result, not an error response)", resp.StatusCode)
	}
	var got validateResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode ValidateResponse: %v", err)
	}
	_ = resp.Body.Close()

	if got.Valid {
		t.Errorf("valid = true, want false")
	}
	if len(got.Errors) != 2 {
		t.Fatalf("errors = %d, want 2 (rule name required + invalid glob), got %+v", len(got.Errors), got.Errors)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings = %d, want 1 (ttl without retention), got %+v", len(got.Warnings), got.Warnings)
	}
	for _, e := range got.Errors {
		if e.Path == "" || e.Message == "" {
			t.Errorf("error missing path/message: %+v", e)
		}
	}

	// A well-formed but semantically valid document reports valid=true
	// and no issues.
	resp2 := do(t, ts, http.MethodPost, "/api/v1/policies/validate", adminSecret, defaultTestPolicyYAML)
	var got2 validateResponseWire
	if err := json.NewDecoder(resp2.Body).Decode(&got2); err != nil {
		t.Fatalf("decode ValidateResponse: %v", err)
	}
	_ = resp2.Body.Close()
	if !got2.Valid || len(got2.Errors) != 0 {
		t.Errorf("valid document: valid=%v errors=%v, want valid=true errors=[]", got2.Valid, got2.Errors)
	}

	// validate never applies the submitted document: the active policy
	// is still the original one this server was started with.
	assertCurrentPolicyName(t, ts, adminSecret, "block-exe")
}

// policyCurrentWire mirrors the subset of api/openapi.yaml's Policy
// schema these tests assert on.
type policyCurrentWire struct {
	Name  string `json:"name"`
	Rules []struct {
		Name string `json:"name"`
	} `json:"rules"`
}

// assertCurrentPolicyName fetches GET /policies/current and fails the
// test if its name does not match want.
func assertCurrentPolicyName(t *testing.T, ts *httptest.Server, secret, want string) {
	t.Helper()
	resp := do(t, ts, http.MethodGet, "/api/v1/policies/current", secret, "")
	defer func() { _ = resp.Body.Close() }()
	var p policyCurrentWire
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatalf("decode Policy: %v", err)
	}
	if p.Name != want {
		t.Errorf("current policy name = %q, want %q", p.Name, want)
	}
}

const reloadedPolicyYAML = `
version: 1
name: "reloaded-policy"
rules:
  - name: "block zip"
    then:
      action: block
      reason: "no zips"
default:
  action: pass
`

// TestPoliciesReloadAppliesNewPolicyAndRejectsInvalid is the central
// acceptance test for reload's contract (SR-119-1/§3.5): a valid file
// on disk is applied and reflected by a subsequent GET
// /policies/current, but a subsequently-invalid file is never applied
// — the previously active (valid) policy remains in effect and the
// operation reports 409 with the validation detail.
func TestPoliciesReloadAppliesNewPolicyAndRejectsInvalid(t *testing.T) {
	ts, st, policyPath := newPoliciesTestServer(t, validDryRunPolicyYAML)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	// Sanity: starts out on the original policy.
	assertCurrentPolicyName(t, ts, adminSecret, "block-exe")

	// Rewrite the file with a new, valid policy and reload: the new
	// policy takes effect.
	if err := os.WriteFile(policyPath, []byte(reloadedPolicyYAML), 0o600); err != nil {
		t.Fatalf("rewrite policy file: %v", err)
	}
	resp := do(t, ts, http.MethodPost, "/api/v1/policies/reload", adminSecret, "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("reload valid policy: status = %d, body = %s, want 200", resp.StatusCode, body)
	}
	var reloadResp struct {
		Policy struct {
			Name      string `json:"name"`
			Version   int    `json:"version"`
			RuleCount int    `json:"rule_count"`
		} `json:"policy"`
		Warnings []string `json:"warnings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reloadResp); err != nil {
		t.Fatalf("decode ReloadResponse: %v", err)
	}
	_ = resp.Body.Close()
	if reloadResp.Policy.Name != "reloaded-policy" || reloadResp.Policy.RuleCount != 1 {
		t.Errorf("reload response = %+v, want name=reloaded-policy rule_count=1", reloadResp.Policy)
	}
	assertCurrentPolicyName(t, ts, adminSecret, "reloaded-policy")

	// Rewrite the file with an invalid policy (no default action) and
	// reload again: the operation fails 409, and — critically — the
	// active policy is unchanged (still reloaded-policy), not nulled
	// out or replaced with the broken document.
	const invalidOnDisk = `
version: 1
name: "broken-policy"
rules: []
`
	if err := os.WriteFile(policyPath, []byte(invalidOnDisk), 0o600); err != nil {
		t.Fatalf("rewrite policy file: %v", err)
	}
	resp2 := do(t, ts, http.MethodPost, "/api/v1/policies/reload", adminSecret, "")
	if resp2.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("reload invalid policy: status = %d, body = %s, want 409", resp2.StatusCode, body)
	}
	var errEnv struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&errEnv); err != nil {
		t.Fatalf("decode Error: %v", err)
	}
	_ = resp2.Body.Close()
	if errEnv.Error.Code != "invalid_policy" {
		t.Errorf("error code = %q, want invalid_policy", errEnv.Error.Code)
	}
	if errEnv.Error.Message == "" {
		t.Errorf("error message is empty, want a description of the validation failure")
	}
	// SR-130-1 (this package's apiError doc comment: "no ... file
	// path"): the 409 message must never leak the server's absolute
	// policy file path, even though policy.DocumentError's Name field
	// (and thus its Error() string) carries it internally.
	if strings.Contains(errEnv.Error.Message, policyPath) {
		t.Errorf("error message leaks the policy file path: %q", errEnv.Error.Message)
	}

	assertCurrentPolicyName(t, ts, adminSecret, "reloaded-policy")
}

// dryRunResponseWire mirrors api/openapi.yaml's DryRunResponse.
type dryRunResponseWire struct {
	Action      string  `json:"action"`
	Reason      *string `json:"reason"`
	Attachments []struct {
		Filename string  `json:"filename"`
		Action   string  `json:"action"`
		RuleName *string `json:"rule_name"`
		Reason   *string `json:"reason"`
	} `json:"attachments"`
}

// TestPoliciesDryRunEvaluatesWithoutSideEffects verifies POST
// /policies/dry-run reports the decision the active policy would make
// (mirroring policy.Evaluate) and never creates a message, attachment
// or link row — a pure simulation.
func TestPoliciesDryRunEvaluatesWithoutSideEffects(t *testing.T) {
	ts, st, _ := newPoliciesTestServer(t, validDryRunPolicyYAML)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	body := `{
		"sender": "sender@example.com",
		"recipients": ["recipient@example.com"],
		"attachments": [
			{"filename": "invoice.pdf", "size": 1024, "detected_type": "application/pdf"},
			{"filename": "payload.exe", "size": 2048, "detected_type": "application/x-msdownload"}
		]
	}`

	resp := do(t, ts, http.MethodPost, "/api/v1/policies/dry-run", adminSecret, body)
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("dry-run: status = %d, body = %s, want 200", resp.StatusCode, respBody)
	}
	var got dryRunResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode DryRunResponse: %v", err)
	}
	_ = resp.Body.Close()

	if got.Action != "block" {
		t.Errorf("message action = %q, want block (the .exe attachment blocks the whole message)", got.Action)
	}
	if len(got.Attachments) != 2 {
		t.Fatalf("attachments = %d, want 2", len(got.Attachments))
	}
	if got.Attachments[0].Action != "pass" {
		t.Errorf("invoice.pdf decision = %q, want pass", got.Attachments[0].Action)
	}
	if got.Attachments[1].Action != "block" {
		t.Errorf("payload.exe decision = %q, want block", got.Attachments[1].Action)
	}
	if got.Attachments[1].RuleName == nil || *got.Attachments[1].RuleName != "block executables" {
		t.Errorf("payload.exe rule_name = %v, want \"block executables\"", got.Attachments[1].RuleName)
	}

	// Side-effect free: no message was created for this simulated
	// evaluation — the dry-run request describes a hypothetical
	// message, not a real one, and must never touch the metadata
	// store. ListMessagesBySender is the narrowest existing store query
	// that can observe this: if a message had been created, it would
	// show up here under the request's sender.
	messages, err := st.ListMessagesBySender(t.Context(), "sender@example.com")
	if err != nil {
		t.Fatalf("ListMessagesBySender() error = %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("messages after dry-run = %d, want 0 (dry-run must not create any message)", len(messages))
	}
}

// TestPoliciesDryRunValidation covers the request-shape checks POST
// /policies/dry-run applies before evaluating (missing sender/
// recipients/attachments, and a missing per-attachment detected_type).
func TestPoliciesDryRunValidation(t *testing.T) {
	ts, st, _ := newPoliciesTestServer(t, validDryRunPolicyYAML)
	_, adminSecret := seedToken(t, st, "admin", store.RoleAdmin)

	for _, tc := range []struct {
		name, body string
	}{
		{"missing sender", `{"recipients":["b@example.com"],"attachments":[{"filename":"x","size":1,"detected_type":"text/plain"}]}`},
		{"empty recipients", `{"sender":"a@example.com","recipients":[],"attachments":[{"filename":"x","size":1,"detected_type":"text/plain"}]}`},
		{"empty attachments", `{"sender":"a@example.com","recipients":["b@example.com"],"attachments":[]}`},
		{"missing detected_type", `{"sender":"a@example.com","recipients":["b@example.com"],"attachments":[{"filename":"x","size":1}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, ts, http.MethodPost, "/api/v1/policies/dry-run", adminSecret, tc.body)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if code := decodeError(t, resp); code != "bad_request" {
				t.Errorf("error code = %q, want bad_request", code)
			}
		})
	}
}

// TestPoliciesNoStoreConfigured verifies the three operations that
// need an active policy.Store (current/reload/dry-run) fail safely
// when this server was started without one — community-edition
// passthrough mode (empty config.Policy.Path) passes a nil Store to
// NewAPIHandler — while POST /policies/validate keeps working, since
// it only parses the submitted document and needs no active policy.
func TestPoliciesNoStoreConfigured(t *testing.T) {
	stt, err := sqlite.Open(filepath.Join(t.TempDir(), "no-policy-test.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = stt.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	linkEngine := newTestLinkEngine(t, stt)
	api := adapterhttp.NewAPIHandler(stt, stt, linkEngine, nil, logger, stt, stt, metrics.New(), adapterhttp.APIConfig{
		MaxBodyBytes:          1 << 16,
		AuthFailuresPerMinute: 1000,
		AuthFailuresBurst:     1000,
	})
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)

	_, adminSecret := seedToken(t, stt, "admin", store.RoleAdmin)

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/policies/current", ""},
		{http.MethodPost, "/api/v1/policies/reload", ""},
		{http.MethodPost, "/api/v1/policies/dry-run", `{"sender":"a@example.com","recipients":["b@example.com"],"attachments":[{"filename":"x","size":1,"detected_type":"text/plain"}]}`},
	} {
		resp := do(t, ts, tc.method, tc.path, adminSecret, tc.body)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s %s with no policy configured: status = %d, want 500", tc.method, tc.path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	// validate needs no active Store: it works regardless.
	resp := do(t, ts, http.MethodPost, "/api/v1/policies/validate", adminSecret, defaultTestPolicyYAML)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("validate with no policy configured: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
