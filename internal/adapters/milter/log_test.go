package milter_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/pipeline"
)

// TestMilter_LogsInfoOnPass verifies that a VerdictAccept from the
// Processor now emits exactly one structured INFO line summarizing the
// message (ATR-304): before this, the milter adapter's happy path
// logged nothing at all, leaving an operator watching journald with no
// way to confirm a message was ever seen unless it hit an error path.
// It also checks the log-redaction requirement: the envelope sender's
// full address must never appear in the line, only its domain.
func TestMilter_LogsInfoOnPass(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	proc := &fakeProcessor{verdict: &pipeline.Verdict{Action: pipeline.VerdictAccept}}
	addr := startTestServerWithLogger(t, proc, logger, nil)

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("hello world\r\n"))
	requireAccept(t, act)

	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Fatalf("expected an INFO line, got:\n%s", out)
	}
	if !strings.Contains(out, `msg="milter: message processed"`) {
		t.Errorf("expected the ATR-304 summary message, got:\n%s", out)
	}
	if !strings.Contains(out, "decision=pass") {
		t.Errorf("expected decision=pass, got:\n%s", out)
	}
	if !strings.Contains(out, "sender_domain=example.com") {
		t.Errorf("expected sender_domain=example.com, got:\n%s", out)
	}
	if !strings.Contains(out, "duration_ms=") {
		t.Errorf("expected a duration_ms field, got:\n%s", out)
	}
	if !strings.Contains(out, "attachments_total=0") {
		t.Errorf("expected attachments_total=0 for a Verdict carrying no Attachments summary, got:\n%s", out)
	}

	// Redaction: the full sender address (local-part@domain) must never
	// appear, only the domain logged above.
	if strings.Contains(out, "sender@example.com") {
		t.Errorf("log line must not contain the full sender address, got:\n%s", out)
	}
	// No filename or recipient address of any kind belongs in this line
	// either (those live only in the audit trail).
	if strings.Contains(out, "rcpt@example.com") {
		t.Errorf("log line must not contain a recipient address, got:\n%s", out)
	}
}

// TestMilter_LogsInfoOnRewrite verifies a VerdictRewrite is logged with
// decision=rewrite (distinguishable from decision=pass) and carries the
// attachment counts the Verdict's Attachments summary reported.
func TestMilter_LogsInfoOnRewrite(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	newBody := "Subject: test message\r\n" +
		"X-Attachra-Processed: version=1; id=deadbeef\r\n" +
		"\r\n" +
		"replacement body\r\n"
	proc := &fakeProcessor{verdict: &pipeline.Verdict{
		Action:  pipeline.VerdictRewrite,
		NewBody: strings.NewReader(newBody),
		Attachments: pipeline.AttachmentSummary{
			Total:           2,
			Replaced:        1,
			InlineProtected: 1,
			BodyProtected:   0,
		},
	}}
	addr := startTestServerWithLogger(t, proc, logger, nil)

	_, act := runSession(t, addr, "sender@corp.example", "rcpt@example.com", []byte("original body\r\n"))
	requireAccept(t, act)

	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Fatalf("expected an INFO line, got:\n%s", out)
	}
	if !strings.Contains(out, "decision=rewrite") {
		t.Errorf("expected decision=rewrite, got:\n%s", out)
	}
	if !strings.Contains(out, "sender_domain=corp.example") {
		t.Errorf("expected sender_domain=corp.example, got:\n%s", out)
	}
	if strings.Contains(out, "sender@corp.example") {
		t.Errorf("log line must not contain the full sender address, got:\n%s", out)
	}
	if !strings.Contains(out, "attachments_total=2") {
		t.Errorf("expected attachments_total=2, got:\n%s", out)
	}
	if !strings.Contains(out, "attachments_replaced=1") {
		t.Errorf("expected attachments_replaced=1, got:\n%s", out)
	}
	if !strings.Contains(out, "attachments_inline_protected=1") {
		t.Errorf("expected attachments_inline_protected=1, got:\n%s", out)
	}
	if !strings.Contains(out, "attachments_body_protected=0") {
		t.Errorf("expected attachments_body_protected=0, got:\n%s", out)
	}
}

// TestMilter_LogsInfoOnBlock verifies a VerdictReject is still logged
// at INFO, not WARN/Error: the message itself deciding "block" is a
// normal policy outcome, not a processing failure (ATR-304's "block is
// also INFO" requirement).
func TestMilter_LogsInfoOnBlock(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	proc := &fakeProcessor{verdict: &pipeline.Verdict{Action: pipeline.VerdictReject, Reason: "policy violation"}}
	addr := startTestServerWithLogger(t, proc, logger, nil)

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("body\r\n"))
	requireReject(t, act)

	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Fatalf("expected an INFO line, got:\n%s", out)
	}
	if !strings.Contains(out, "decision=block") {
		t.Errorf("expected decision=block, got:\n%s", out)
	}
	if strings.Contains(out, "level=WARN") || strings.Contains(out, "level=ERROR") {
		t.Errorf("a policy block must not also log at WARN/Error, got:\n%s", out)
	}
}

// TestMilter_NoInfoLogDuplicateOnProcessorError verifies that a
// Processor error (resolved into the configured fail-open/fail-closed
// behavior, already logged at WARN by resolveFailure) does NOT also
// emit the ATR-304 happy-path INFO summary line — the ticket's "do not
// duplicate" requirement.
func TestMilter_NoInfoLogDuplicateOnProcessorError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	proc := &fakeProcessor{err: errors.New("simulated processor failure")}
	addr := startTestServerWithLogger(t, proc, logger, nil)

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("body\r\n"))
	requireAccept(t, act) // fail-open is startTestServer's default FailureMode

	out := buf.String()
	if strings.Contains(out, "milter: message processed") {
		t.Errorf("fail-open error path must not also emit the ATR-304 happy-path INFO line, got:\n%s", out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected the existing fail-open WARN line, got:\n%s", out)
	}
}
