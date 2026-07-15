package metrics_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/302-digital/attachra/internal/core/metrics"
)

func TestNewRegistersCollectors(t *testing.T) {
	m := metrics.New()
	if m.Registry == nil {
		t.Fatal("New() Registry = nil, want non-nil")
	}

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Registry.Gather() error = %v, want nil", err)
	}
	if len(families) == 0 {
		t.Fatal("Registry.Gather() returned no metric families, want at least the registered collectors")
	}
}

func TestObserveMessage(t *testing.T) {
	m := metrics.New()

	m.ObserveMessage("accept", 10*time.Millisecond)
	m.ObserveMessage("accept", 20*time.Millisecond)
	m.ObserveMessage("error", 5*time.Millisecond)

	if got := testutil.ToFloat64(m.MessagesProcessed.WithLabelValues("accept")); got != 2 {
		t.Errorf("MessagesProcessed{result=accept} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.MessagesProcessed.WithLabelValues("error")); got != 1 {
		t.Errorf("MessagesProcessed{result=error} = %v, want 1", got)
	}

	count := testutil.CollectAndCount(m.MessageProcessingSeconds)
	if count == 0 {
		t.Error("MessageProcessingSeconds has no observations, want at least one series")
	}
}

func TestObserveAttachmentAction(t *testing.T) {
	m := metrics.New()

	m.ObserveAttachmentAction("pass")
	m.ObserveAttachmentAction("replace")
	m.ObserveAttachmentAction("replace")
	m.ObserveAttachmentAction("block")

	tests := []struct {
		action string
		want   float64
	}{
		{"pass", 1},
		{"replace", 2},
		{"block", 1},
	}
	for _, tt := range tests {
		if got := testutil.ToFloat64(m.AttachmentsDecided.WithLabelValues(tt.action)); got != tt.want {
			t.Errorf("AttachmentsDecided{action=%s} = %v, want %v", tt.action, got, tt.want)
		}
	}
}

func TestObservePolicyDecision(t *testing.T) {
	m := metrics.New()

	m.ObservePolicyDecision("replace", false)
	m.ObservePolicyDecision("replace", true)
	m.ObservePolicyDecision("pass", false)

	if got := testutil.ToFloat64(m.PolicyDecisions.WithLabelValues("replace", "false")); got != 1 {
		t.Errorf("PolicyDecisions{action=replace,dry_run=false} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.PolicyDecisions.WithLabelValues("replace", "true")); got != 1 {
		t.Errorf("PolicyDecisions{action=replace,dry_run=true} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.PolicyDecisions.WithLabelValues("pass", "false")); got != 1 {
		t.Errorf("PolicyDecisions{action=pass,dry_run=false} = %v, want 1", got)
	}
}

func TestObserveDownload(t *testing.T) {
	m := metrics.New()

	m.ObserveDownload("success")
	m.ObserveDownload("success")
	m.ObserveDownload("denied")

	if got := testutil.ToFloat64(m.Downloads.WithLabelValues("success")); got != 2 {
		t.Errorf("Downloads{result=success} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.Downloads.WithLabelValues("denied")); got != 1 {
		t.Errorf("Downloads{result=denied} = %v, want 1", got)
	}
}

func TestObserveError(t *testing.T) {
	m := metrics.New()

	m.ObserveError("pipeline")
	m.ObserveError("milter_fail_open")
	m.ObserveError("milter_fail_open")
	m.ObserveError("milter_fail_closed")

	tests := []struct {
		stage string
		want  float64
	}{
		{"pipeline", 1},
		{"milter_fail_open", 2},
		{"milter_fail_closed", 1},
	}
	for _, tt := range tests {
		if got := testutil.ToFloat64(m.Errors.WithLabelValues(tt.stage)); got != tt.want {
			t.Errorf("Errors{stage=%s} = %v, want %v", tt.stage, got, tt.want)
		}
	}
}

func TestObserveRetentionCleanup(t *testing.T) {
	m := metrics.New()

	m.ObserveRetentionCleanup("deleted")
	m.ObserveRetentionCleanup("deleted")
	m.ObserveRetentionCleanup("held_skipped")
	m.ObserveRetentionCleanup("error")

	tests := []struct {
		result string
		want   float64
	}{
		{"deleted", 2},
		{"held_skipped", 1},
		{"error", 1},
	}
	for _, tt := range tests {
		if got := testutil.ToFloat64(m.RetentionCleanups.WithLabelValues(tt.result)); got != tt.want {
			t.Errorf("RetentionCleanups{result=%s} = %v, want %v", tt.result, got, tt.want)
		}
	}
}

// TestNilMetricsIsSafe verifies every Observe* method is a no-op (never
// panics) on a nil *Metrics, since pipeline/milter/http call sites
// treat an unconfigured Metrics field exactly like a nil logger or
// audit sink (best-effort, optional instrumentation never allowed to
// affect the mail-delivery critical path, CLAUDE.md invariant #3).
func TestNilMetricsIsSafe(_ *testing.T) {
	var m *metrics.Metrics

	m.ObserveMessage("accept", time.Millisecond)
	m.ObserveAttachmentAction("pass")
	m.ObservePolicyDecision("pass", false)
	m.ObserveDownload("success")
	m.ObserveError("pipeline")
	m.ObserveRetentionCleanup("deleted")
}
