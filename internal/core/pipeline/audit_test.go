package pipeline_test

import (
	"context"
	"errors"
	"testing"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/pipeline"
	"github.com/302-digital/attachra/internal/core/policy"
)

// collectEvents drains every audit.Recorded event from h's sink, for
// assertions.
func collectEvents(t *testing.T, h *testHarness) []audit.Recorded {
	t.Helper()
	var got []audit.Recorded
	if err := h.auditSink.StreamEvents(context.Background(), audit.Filter{}, func(r audit.Recorded) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents() error = %v, want nil", err)
	}
	return got
}

// countByType tallies events in got by Type.
func countByType(got []audit.Recorded) map[audit.Type]int {
	counts := make(map[audit.Type]int)
	for _, e := range got {
		counts[e.Type]++
	}
	return counts
}

// TestProcess_RecordsAuditEventsOnReplace verifies that a full
// replace-and-rewrite run through Process records every expected event
// type (US-7.1/ATR-190): policy_decision, attachment_stored,
// links_created and a terminal message_processed, all attributed to
// the pipeline actor.
func TestProcess_RecordsAuditEventsOnReplace(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	verdict, err := proc.Process(context.Background(), envelopeFor(testMessage))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Fatalf("verdict.Action = %v, want VerdictRewrite", verdict.Action)
	}

	got := collectEvents(t, h)
	counts := countByType(got)

	if counts[audit.TypePolicyDecision] != 1 {
		t.Errorf("TypePolicyDecision count = %d, want 1", counts[audit.TypePolicyDecision])
	}
	// replaceAllPolicy's default action is replace with no rules, so
	// policy.Evaluate itself decides replace for both leaf parts of
	// testMessage, including the text/plain body — but
	// protectStructuralBodies (ATR-306) downgrades the body's decision
	// to pass before upload, since a structural body part is never
	// actually a replace candidate. Only the report.bin attachment is
	// uploaded and stored.
	if counts[audit.TypeAttachmentStored] != 1 {
		t.Errorf("TypeAttachmentStored count = %d, want 1 (the text/plain body part is downgraded to pass by protectStructuralBodies, ATR-306)", counts[audit.TypeAttachmentStored])
	}
	if counts[audit.TypeLinksCreated] != 1 {
		t.Errorf("TypeLinksCreated count = %d, want 1 (one recipient)", counts[audit.TypeLinksCreated])
	}
	if counts[audit.TypeMessageProcessed] != 1 {
		t.Errorf("TypeMessageProcessed count = %d, want 1", counts[audit.TypeMessageProcessed])
	}
	if counts[audit.TypeError] != 0 {
		t.Errorf("TypeError count = %d, want 0 for a successful run", counts[audit.TypeError])
	}

	for _, e := range got {
		if e.Actor != "milter" {
			t.Errorf("event %q Actor = %q, want %q", e.Type, e.Actor, "milter")
		}
	}

	// Every non-final event should already carry the message ID assigned
	// by link creation (attachment_stored/links_created/message_processed);
	// policy_decision runs before a message ID exists, so it is exempt.
	for _, e := range got {
		if e.Type == audit.TypePolicyDecision {
			continue
		}
		if e.MessageID == "" {
			t.Errorf("event %q has empty MessageID, want it populated once a message ID exists", e.Type)
		}
	}
}

// TestProcess_RecordsMessageProcessedOnAccept verifies that a
// pass-through decision still records exactly one terminal
// message_processed event describing the accept outcome, with no
// storage/link events (since nothing was replaced).
func TestProcess_RecordsMessageProcessedOnAccept(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, passAllPolicy, false)

	if _, err := proc.Process(context.Background(), envelopeFor(testMessage)); err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}

	got := collectEvents(t, h)
	counts := countByType(got)

	if counts[audit.TypeMessageProcessed] != 1 {
		t.Errorf("TypeMessageProcessed count = %d, want 1", counts[audit.TypeMessageProcessed])
	}
	if counts[audit.TypeAttachmentStored] != 0 {
		t.Errorf("TypeAttachmentStored count = %d, want 0 for a pass-only decision", counts[audit.TypeAttachmentStored])
	}
	if counts[audit.TypeLinksCreated] != 0 {
		t.Errorf("TypeLinksCreated count = %d, want 0 for a pass-only decision", counts[audit.TypeLinksCreated])
	}

	for _, e := range got {
		if e.Type != audit.TypeMessageProcessed {
			continue
		}
		if e.Details["action"] != "accept" {
			t.Errorf("message_processed Details[action] = %v, want %q", e.Details["action"], "accept")
		}
	}
}

// TestProcess_RecordsMessageProcessedOnBlock verifies a block decision
// records message_processed with the reject outcome and reason.
func TestProcess_RecordsMessageProcessedOnBlock(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, blockExePolicy, false)

	if _, err := proc.Process(context.Background(), envelopeFor(testMessage)); err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}

	got := collectEvents(t, h)
	for _, e := range got {
		if e.Type != audit.TypeMessageProcessed {
			continue
		}
		if e.Details["action"] != "reject" {
			t.Errorf("message_processed Details[action] = %v, want %q", e.Details["action"], "reject")
		}
		if e.Details["reason"] == "" || e.Details["reason"] == nil {
			t.Error("message_processed Details[reason] is empty, want the block reason")
		}
	}
}

// TestProcess_RecordsErrorEventOnFailure verifies that when Process
// returns an error (here: no envelope recipients despite a
// replace decision), an audit.TypeError event is recorded carrying the
// error text, and no message_processed event is recorded for the same
// call (the deferred recorder is exclusive: error XOR
// message_processed).
func TestProcess_RecordsErrorEventOnFailure(t *testing.T) {
	h := newTestHarness(t)
	proc := newProcessor(t, h, replaceAllPolicy, false)

	env := envelopeFor(testMessage)
	env.Recipients = nil

	_, err := proc.Process(context.Background(), env)
	if err == nil {
		t.Fatal("Process() error = nil, want an error (no recipients for a replace decision)")
	}

	got := collectEvents(t, h)
	counts := countByType(got)

	if counts[audit.TypeError] != 1 {
		t.Errorf("TypeError count = %d, want 1", counts[audit.TypeError])
	}
	if counts[audit.TypeMessageProcessed] != 0 {
		t.Errorf("TypeMessageProcessed count = %d, want 0 when Process itself errors", counts[audit.TypeMessageProcessed])
	}

	for _, e := range got {
		if e.Type != audit.TypeError {
			continue
		}
		if e.Details["error"] == "" || e.Details["error"] == nil {
			t.Error("TypeError Details[error] is empty, want the error text")
		}
	}
}

// TestProcess_AuditSinkFailureDoesNotAffectVerdict verifies the
// mail-must-never-be-lost invariant in the audit dimension: if the
// configured AuditSink itself fails, Process must still return its
// normal Verdict/error —
// audit recording is best-effort and must never cause the message to
// be lost, rejected, or delayed.
func TestProcess_AuditSinkFailureDoesNotAffectVerdict(t *testing.T) {
	h := newTestHarness(t)

	policyPath := buildPolicyFile(t, replaceAllPolicy)
	policyStore, err := policy.NewStore(policyPath)
	if err != nil {
		t.Fatalf("policy.NewStore() error = %v, want nil", err)
	}

	proc, err := pipeline.NewAttachmentProcessor(pipeline.AttachmentProcessorParams{
		PolicyStore:       policyStore,
		Storage:           h.storage,
		LinkEngine:        h.link,
		Templates:         h.tmpl,
		Limits:            message.DefaultLimits(),
		MaxAttachmentSize: 10 << 20,
		PublicBaseURL:     "https://links.example.com",
		AuditSink:         failingAuditSink{},
	})
	if err != nil {
		t.Fatalf("NewAttachmentProcessor() error = %v, want nil", err)
	}

	verdict, err := proc.Process(context.Background(), envelopeFor(testMessage))
	if err != nil {
		t.Fatalf("Process() error = %v, want nil (audit-sink failure must not surface as a Process error)", err)
	}
	if verdict.Action != pipeline.VerdictRewrite {
		t.Errorf("verdict.Action = %v, want VerdictRewrite despite audit-sink failure", verdict.Action)
	}
}

// failingAuditSink is an audit.AuditSink that always fails, for
// TestProcess_AuditSinkFailureDoesNotAffectVerdict.
type failingAuditSink struct{}

var errAuditSinkFailure = errors.New("audit sink unavailable")

func (failingAuditSink) Record(_ context.Context, _ audit.Event) (audit.Recorded, error) {
	return audit.Recorded{}, errAuditSinkFailure
}
