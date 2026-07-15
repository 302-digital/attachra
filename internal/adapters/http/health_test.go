package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
)

func TestHealthHandlerLiveness(t *testing.T) {
	h := adapterhttp.NewHealthHandler(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.Liveness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Liveness() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHealthHandlerReadinessAllHealthy(t *testing.T) {
	checks := []adapterhttp.ReadinessCheck{
		{Name: "database", Check: func(context.Context) error { return nil }},
		{Name: "storage", Check: func(context.Context) error { return nil }},
	}
	h := adapterhttp.NewHealthHandler(checks, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Readiness() status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Status string `json:"status"`
		Checks []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
	if len(body.Checks) != 2 {
		t.Fatalf("checks = %+v, want 2 entries", body.Checks)
	}
	for _, c := range body.Checks {
		if !c.OK {
			t.Errorf("check %q OK = false, want true", c.Name)
		}
	}
}

func TestHealthHandlerReadinessDegraded(t *testing.T) {
	sensitiveErr := errors.New("password authentication failed for user \"attachra\"")
	checks := []adapterhttp.ReadinessCheck{
		{Name: "database", Check: func(context.Context) error { return sensitiveErr }},
		{Name: "storage", Check: func(context.Context) error { return nil }},
	}
	h := adapterhttp.NewHealthHandler(checks, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Readiness() status = %d, want %d; body = %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}

	body := rec.Body.String()
	if strings.Contains(body, "password") {
		t.Errorf("Readiness() response body leaked check error detail: %s", body)
	}

	var parsed struct {
		Status string `json:"status"`
		Checks []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	if parsed.Status != "unavailable" {
		t.Errorf("status = %q, want %q", parsed.Status, "unavailable")
	}
	foundFailing := false
	for _, c := range parsed.Checks {
		if c.Name == "database" {
			foundFailing = true
			if c.OK {
				t.Error("database check OK = true, want false")
			}
		}
	}
	if !foundFailing {
		t.Error("response did not include the failing \"database\" check")
	}
}

func TestHealthHandlerReadinessNoChecks(t *testing.T) {
	h := adapterhttp.NewHealthHandler(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Readiness() with no checks configured status = %d, want %d", rec.Code, http.StatusOK)
	}
}
