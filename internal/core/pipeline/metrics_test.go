package pipeline_test

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/pipeline"
	"github.com/302-digital/attachra/internal/core/policy"
)

// newProcessorWithMetrics mirrors newProcessor (processor_test.go) but
// additionally wires up a *metrics.Metrics, for the metrics-specific
// assertions below (US-7.2/T-7.2.1, ATR-192).
func newProcessorWithMetrics(t *testing.T, h *testHarness, policyYAML string, m *metrics.Metrics) *pipeline.AttachmentProcessor {
	t.Helper()

	policyPath := buildPolicyFile(t, policyYAML)
	store, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v, want nil", err)
	}

	proc, err := pipeline.NewAttachmentProcessor(pipeline.AttachmentProcessorParams{
		PolicyStore:       store,
		Storage:           h.storage,
		LinkEngine:        h.link,
		Templates:         h.tmpl,
		Limits:            message.DefaultLimits(),
		MaxAttachmentSize: 10 << 20,
		PublicBaseURL:     "https://links.example.com",
		AuditSink:         h.auditSink,
		Metrics:           m,
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}
	return proc
}

// TestProcess_RecordsMetricsOnReplace verifies that a successful
// replace-decision run records the expected message/policy/attachment
// metrics with the correct labels and values.
func TestProcess_RecordsMetricsOnReplace(t *testing.T) {
	h := newTestHarness(t)
	m := metrics.New()
	proc := newProcessorWithMetrics(t, h, replaceAllPolicy, m)

	if _, err := proc.Process(context.Background(), envelopeFor(testMessage)); err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}

	if got := testutil.ToFloat64(m.MessagesProcessed.WithLabelValues("rewrite")); got != 1 {
		t.Errorf("MessagesProcessed{result=rewrite} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.PolicyDecisions.WithLabelValues("replace", "false")); got != 1 {
		t.Errorf("PolicyDecisions{action=replace,dry_run=false} = %v, want 1", got)
	}
	// testMessage has two leaf MIME parts (a text/plain body and the
	// "report.bin" attachment). Both are submitted to policy.Evaluate
	// (structural body parts are fully evaluated, not skipped — a
	// security review of ATR-305/306 found that skipping evaluation was
	// itself an enforcement bypass), so replaceAllPolicy's default
	// decides replace for both; the body is then downgraded to pass by
	// protectStructuralBodies, leaving only report.bin as "replace".
	if got := testutil.ToFloat64(m.AttachmentsDecided.WithLabelValues("replace")); got != 1 {
		t.Errorf("AttachmentsDecided{action=replace} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.AttachmentsDecided.WithLabelValues("pass")); got != 1 {
		t.Errorf("AttachmentsDecided{action=pass} = %v, want 1 (the downgraded text/plain body)", got)
	}
	if got := testutil.ToFloat64(m.AttachmentsDecided.WithLabelValues("body_protected")); got != 1 {
		t.Errorf("AttachmentsDecided{action=body_protected} = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.MessageProcessingSeconds); got == 0 {
		t.Error("MessageProcessingSeconds has no observations, want at least one series")
	}
}

// TestProcess_RecordsMetricsOnPass verifies the pass-only path records
// an "accept" message result and a "pass" attachment/policy action.
func TestProcess_RecordsMetricsOnPass(t *testing.T) {
	h := newTestHarness(t)
	m := metrics.New()
	proc := newProcessorWithMetrics(t, h, passAllPolicy, m)

	if _, err := proc.Process(context.Background(), envelopeFor(testMessage)); err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}

	if got := testutil.ToFloat64(m.MessagesProcessed.WithLabelValues("accept")); got != 1 {
		t.Errorf("MessagesProcessed{result=accept} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.PolicyDecisions.WithLabelValues("pass", "false")); got != 1 {
		t.Errorf("PolicyDecisions{action=pass,dry_run=false} = %v, want 1", got)
	}
	// Both of testMessage's two leaf MIME parts (the text/plain body and
	// report.bin) are submitted to policy.Evaluate and both decide pass
	// under passAllPolicy — nothing to protect/downgrade here, since
	// neither was ever decided replace (see
	// TestProcess_RecordsMetricsOnReplace's comment on the fixture).
	if got := testutil.ToFloat64(m.AttachmentsDecided.WithLabelValues("pass")); got != 2 {
		t.Errorf("AttachmentsDecided{action=pass} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.AttachmentsDecided.WithLabelValues("body_protected")); got != 0 {
		t.Errorf("AttachmentsDecided{action=body_protected} = %v, want 0 (nothing was ever decided replace)", got)
	}
}

// TestProcess_RecordsMetricsOnBlock verifies a block decision is
// counted as a "reject" message result and a "block" policy action.
func TestProcess_RecordsMetricsOnBlock(t *testing.T) {
	h := newTestHarness(t)
	m := metrics.New()
	proc := newProcessorWithMetrics(t, h, blockExePolicy, m)

	if _, err := proc.Process(context.Background(), envelopeFor(testMessage)); err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}

	if got := testutil.ToFloat64(m.MessagesProcessed.WithLabelValues("reject")); got != 1 {
		t.Errorf("MessagesProcessed{result=reject} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.PolicyDecisions.WithLabelValues("block", "false")); got != 1 {
		t.Errorf("PolicyDecisions{action=block,dry_run=false} = %v, want 1", got)
	}
}

// TestProcess_NilMetricsIsSafe verifies Process still succeeds when
// AttachmentProcessorParams.Metrics is left nil (the pre-ATR-192
// default), matching Logger/AuditSink's optional-by-design contract.
func TestProcess_NilMetricsIsSafe(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessorWithMetrics(t, h, replaceAllPolicy, nil)

	if _, err := proc.Process(context.Background(), envelopeFor(testMessage)); err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
}
