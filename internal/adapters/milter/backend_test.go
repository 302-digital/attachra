package milter

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/302-digital/attachra/internal/core/metrics"
)

func discardLoggerForBackend() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestResolveFailure_RecordsMetrics verifies resolveFailure records the
// correct Prometheus error-stage counter for each configured
// FailureMode (US-7.2/T-7.2.1, ATR-192, SR-116-1).
func TestResolveFailure_RecordsMetrics(t *testing.T) {
	tests := []struct {
		name  string
		mode  FailureMode
		stage string
	}{
		{"fail-open", FailOpen, "milter_fail_open"},
		{"fail-closed", FailClosed, "milter_fail_closed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := metrics.New()
			b := newBackend(Config{FailureMode: tt.mode}, nil, discardLoggerForBackend(), m)

			if _, err := b.resolveFailure("QID-1", errors.New("simulated failure")); err != nil {
				t.Fatalf("resolveFailure() error = %v, want nil", err)
			}

			if got := testutil.ToFloat64(m.Errors.WithLabelValues(tt.stage)); got != 1 {
				t.Errorf("Errors{stage=%s} = %v, want 1", tt.stage, got)
			}
		})
	}
}

// TestResolveFailure_NilMetricsIsSafe verifies resolveFailure does not
// panic when the backend was constructed with a nil *metrics.Metrics
// (the pre-ATR-192 default).
func TestResolveFailure_NilMetricsIsSafe(t *testing.T) {
	b := newBackend(Config{FailureMode: FailOpen}, nil, discardLoggerForBackend(), nil)

	if _, err := b.resolveFailure("QID-1", errors.New("simulated failure")); err != nil {
		t.Fatalf("resolveFailure() error = %v, want nil", err)
	}
}
