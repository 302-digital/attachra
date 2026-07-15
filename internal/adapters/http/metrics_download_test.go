package http_test

import (
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
	"github.com/302-digital/attachra/internal/core/metrics"
)

// TestDownloadRecordsSuccessMetric verifies a successful download
// increments Downloads{result=success} (US-7.2/T-7.2.1, ATR-192).
func TestDownloadRecordsSuccessMetric(t *testing.T) {
	m := metrics.New()
	env := newTestEnv(t, adapterhttp.RateLimitConfig{}, withMetrics(m))
	content := []byte("attachra-metrics-download-content")
	packageToken, linkID := env.seedMessage(t, "msg-metrics-success", content, "report.bin", "application/octet-stream")

	req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("POST download status = %d, want 200", rr.Code)
	}
	if got := testutil.ToFloat64(m.Downloads.WithLabelValues("success")); got != 1 {
		t.Errorf("Downloads{result=success} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.Downloads.WithLabelValues("denied")); got != 0 {
		t.Errorf("Downloads{result=denied} = %v, want 0", got)
	}
}

// TestDownloadRecordsDeniedMetric verifies a download against an
// unknown token increments Downloads{result=denied} rather than
// success (SR-125-5's generic-denial outcome).
func TestDownloadRecordsDeniedMetric(t *testing.T) {
	m := metrics.New()
	env := newTestEnv(t, adapterhttp.RateLimitConfig{}, withMetrics(m))

	req := httptest.NewRequest("POST", downloadPath("unknown-token", "unknown-link"), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 404 {
		t.Fatalf("POST download with unknown token status = %d, want 404", rr.Code)
	}
	if got := testutil.ToFloat64(m.Downloads.WithLabelValues("denied")); got != 1 {
		t.Errorf("Downloads{result=denied} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.Downloads.WithLabelValues("success")); got != 0 {
		t.Errorf("Downloads{result=success} = %v, want 0", got)
	}
}

// TestDownloadNilMetricsIsSafe verifies serveDownload still works when
// no Metrics is configured (the pre-ATR-192 default, exercised by
// every other test in this package via newTestEnv without
// withMetrics).
func TestDownloadNilMetricsIsSafe(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := []byte("attachra-nil-metrics-content")
	packageToken, linkID := env.seedMessage(t, "msg-nil-metrics", content, "report.bin", "application/octet-stream")

	req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("POST download status = %d, want 200", rr.Code)
	}
}
