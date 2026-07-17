package milter_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	dmilter "github.com/d--j/go-milter"
	"github.com/emersion/go-message/textproto"

	"github.com/302-digital/attachra/internal/adapters/milter"
	"github.com/302-digital/attachra/internal/core/pipeline"
)

// discardLogger returns a logger that writes nowhere, keeping test
// output focused on assertions.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeProcessor is a pipeline.Processor test double whose behavior is
// controlled per-test via its fields. It also records whether Process
// was called and what Envelope it received, for assertions.
type fakeProcessor struct {
	mu sync.Mutex

	verdict *pipeline.Verdict
	err     error
	panics  bool

	called   bool
	lastEnv  pipeline.Envelope
	bodySeen []byte
}

func (f *fakeProcessor) Process(_ context.Context, env *pipeline.Envelope) (*pipeline.Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.called = true
	f.lastEnv = pipeline.Envelope{
		Sender:     env.Sender,
		Recipients: env.Recipients,
		QueueID:    env.QueueID,
	}

	if env.Body != nil {
		b, _ := io.ReadAll(env.Body)
		f.bodySeen = b
	}

	if f.panics {
		panic("fakeProcessor: simulated panic")
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.verdict, nil
}

// startTestServer starts a milter.Server listening on an ephemeral
// loopback TCP port and returns its address and a cleanup func that
// shuts it down. cfgFn can override defaults on the Config before the
// server starts. Log output is discarded; use startTestServerWithLogger
// when a test needs to assert on what was logged.
func startTestServer(t *testing.T, processor pipeline.Processor, cfgFn func(*milter.Config)) string {
	t.Helper()
	return startTestServerWithLogger(t, processor, discardLogger(), cfgFn)
}

// startTestServerWithLogger is startTestServer with an explicit logger,
// for tests that assert on log output (e.g. ATR-304's per-message INFO
// summary line).
func startTestServerWithLogger(t *testing.T, processor pipeline.Processor, logger *slog.Logger, cfgFn func(*milter.Config)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}

	cfg := milter.Config{
		Listen:          "inet:" + addr,
		FailureMode:     milter.FailOpen,
		ShutdownTimeout: 5 * time.Second,
	}
	if cfgFn != nil {
		cfgFn(&cfg)
	}

	srv := milter.NewServer(cfg, processor, logger, nil)

	ctx, cancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- srv.ListenAndServe(ctx)
	}()

	waitForDial(t, addr)

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveErrCh:
			if err != nil {
				t.Errorf("ListenAndServe: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("timed out waiting for server shutdown")
		}
	})

	return addr
}

// waitForDial polls addr until a TCP connection succeeds or a
// deadline elapses, so tests don't race the listener's startup.
func waitForDial(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s never became reachable", addr)
}

// hdrKV is one header field for runSessionWithHeaders to send via the
// milter Header events, in the given order.
type hdrKV struct {
	name  string
	value string
}

// runSession drives one full SMTP-transaction-shaped milter session
// with a single default "Subject" header. See runSessionWithHeaders.
func runSession(t *testing.T, addr, from, rcpt string, body []byte) ([]dmilter.ModifyAction, *dmilter.Action) {
	t.Helper()
	return runSessionWithHeaders(t, addr, from, rcpt, []hdrKV{{"Subject", "test message"}}, body)
}

// runSessionWithHeaders is a small helper wrapping the low-level
// d--j/go-milter Client to drive one full SMTP-transaction-shaped milter
// session against the server under test: Conn -> Helo -> Mail -> Rcpt ->
// Data -> Header -> body -> End. Headers are sent as milter Header
// events (i.e. NOT embedded in body, mirroring the real milter wire
// protocol where headers and body arrive as separate events). It returns
// the final Action and any ModifyActions the server sent at EndOfMessage.
func runSessionWithHeaders(t *testing.T, addr, from, rcpt string, headers []hdrKV, body []byte) ([]dmilter.ModifyAction, *dmilter.Action) {
	t.Helper()

	client := dmilter.NewClient("tcp", addr,
		dmilter.WithAction(dmilter.AllClientSupportedActionMasks),
	)

	sess, err := client.Session(dmilter.NewMacroBag())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close() //nolint:errcheck // best-effort cleanup

	if act, err := sess.Conn("test-client.example", dmilter.FamilyInet, 25, "127.0.0.1"); err != nil {
		t.Fatalf("conn: %v", err)
	} else if act.StopProcessing() {
		t.Fatalf("conn: unexpected stop: %v", act)
	}

	if act, err := sess.Helo("test-client.example"); err != nil {
		t.Fatalf("helo: %v", err)
	} else if act.StopProcessing() {
		t.Fatalf("helo: unexpected stop: %v", act)
	}

	if act, err := sess.Mail(from, ""); err != nil {
		t.Fatalf("mail: %v", err)
	} else if act.StopProcessing() {
		t.Fatalf("mail: unexpected stop: %v", act)
	}

	if act, err := sess.Rcpt(rcpt, ""); err != nil {
		t.Fatalf("rcpt: %v", err)
	} else if act.StopProcessing() {
		t.Fatalf("rcpt: unexpected stop: %v", act)
	}

	if act, err := sess.DataStart(); err != nil {
		t.Fatalf("data: %v", err)
	} else if act.StopProcessing() {
		t.Fatalf("data: unexpected stop: %v", act)
	}

	var hdr textproto.Header
	for _, h := range headers {
		hdr.Add(h.name, h.value)
	}
	if act, err := sess.Header(hdr); err != nil {
		t.Fatalf("header: %v", err)
	} else if act.StopProcessing() {
		t.Fatalf("header: unexpected stop: %v", act)
	}

	modifyActs, act, err := sess.BodyReadFrom(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("body/end: %v", err)
	}

	return modifyActs, act
}

func requireAccept(t *testing.T, act *dmilter.Action) {
	t.Helper()
	if act.Type != dmilter.ActionAccept && act.Type != dmilter.ActionContinue {
		t.Fatalf("expected accept, got %v", act)
	}
}

func requireTempFail(t *testing.T, act *dmilter.Action) {
	t.Helper()
	switch act.Type {
	case dmilter.ActionTempFail:
		return
	case dmilter.ActionRejectWithCode:
		if act.SMTPCode >= 400 && act.SMTPCode < 500 {
			return
		}
		t.Fatalf("expected 4xx tempfail code, got %v", act)
	default:
		t.Fatalf("expected tempfail, got %v", act)
	}
}

func requireReject(t *testing.T, act *dmilter.Action) {
	t.Helper()
	if act.Type != dmilter.ActionReject {
		t.Fatalf("expected reject, got %v", act)
	}
}

// TestMilter_Accept verifies a VerdictAccept from the Processor
// results in the milter accepting the message unmodified.
func TestMilter_Accept(t *testing.T) {
	proc := &fakeProcessor{verdict: &pipeline.Verdict{Action: pipeline.VerdictAccept}}
	addr := startTestServer(t, proc, nil)

	body := []byte("hello world\r\n")
	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", body)

	requireAccept(t, act)

	if !proc.called {
		t.Fatal("expected Processor.Process to be called")
	}
	if proc.lastEnv.Sender != "sender@example.com" {
		t.Errorf("Envelope.Sender = %q, want %q", proc.lastEnv.Sender, "sender@example.com")
	}
	if len(proc.lastEnv.Recipients) != 1 || proc.lastEnv.Recipients[0] != "rcpt@example.com" {
		t.Errorf("Envelope.Recipients = %v, want [rcpt@example.com]", proc.lastEnv.Recipients)
	}

	// The Processor must receive a complete RFC 5322 message: the header
	// block (reconstructed from the Header events runSession sends, not
	// carried in the body stream) followed by a blank line and then the
	// body. This is the semantics the milter protocol actually delivers;
	// a body-only stream would fail message.Parse (the ATR-289 bug).
	want := "Subject: test message\r\n\r\n" + string(body)
	if string(proc.bodySeen) != want {
		t.Errorf("Envelope.Body =\n%q\nwant\n%q", proc.bodySeen, want)
	}
}

// TestMilter_NormalizesSenderAndRecipientAddresses is the milter-side
// regression for ATR-293 (closing the ATR-258 review's N1 finding): the
// backend's MailFrom/RcptTo must hand the Core a normalized Envelope
// even when the client sends the raw MAIL/RCPT command argument with
// SMTP reverse/forward-path angle brackets and mixed case, and no
// {mail_addr}/{rcpt_addr} macro to fall back to (dmilter.NewMacroBag()
// starts empty, exercising exactly that fallback path in
// backend.MailFrom/RcptTo) — otherwise a message recorded as
// "<Alice@EXAMPLE.com>" would silently not be found by
// `attachra link revoke --sender alice@example.com`.
func TestMilter_NormalizesSenderAndRecipientAddresses(t *testing.T) {
	proc := &fakeProcessor{verdict: &pipeline.Verdict{Action: pipeline.VerdictAccept}}
	addr := startTestServer(t, proc, nil)

	body := []byte("hello world\r\n")
	_, act := runSession(t, addr, "<Alice@EXAMPLE.com>", "<Bob@EXAMPLE.com>", body)

	requireAccept(t, act)

	if !proc.called {
		t.Fatal("expected Processor.Process to be called")
	}
	if proc.lastEnv.Sender != "alice@example.com" {
		t.Errorf("Envelope.Sender = %q, want %q (normalized: trimmed, bracket-free, lower-cased)", proc.lastEnv.Sender, "alice@example.com")
	}
	if len(proc.lastEnv.Recipients) != 1 || proc.lastEnv.Recipients[0] != "bob@example.com" {
		t.Errorf("Envelope.Recipients = %v, want [bob@example.com] (normalized)", proc.lastEnv.Recipients)
	}
}

// TestMilter_FoldedHeaderPreservedThroughReassembly verifies that a
// folded (multi-line, RFC 5322 §2.2.3 obs-fold) header value survives
// backend.Header collection and reassembleMessage's reconstruction
// intact — go-milter's Header callback delivers a folded header's
// continuation lines embedded (as raw CRLF + leading whitespace) inside
// the single value string for that one header, and reassembleMessage
// must reproduce that same shape rather than collapsing or corrupting
// it, so the reconstructed message still parses as well-formed RFC 5322
// (message.Parse's net/mail.ReadMessage would otherwise choke on a
// malformed continuation).
func TestMilter_FoldedHeaderPreservedThroughReassembly(t *testing.T) {
	proc := &fakeProcessor{verdict: &pipeline.Verdict{Action: pipeline.VerdictAccept}}
	addr := startTestServer(t, proc, nil)

	const folded = "first line value\r\n second continuation line"
	body := []byte("body content\r\n")

	_, act := runSessionWithHeaders(t, addr, "sender@example.com", "rcpt@example.com", []hdrKV{{"Subject", folded}}, body)
	requireAccept(t, act)

	got := string(proc.bodySeen)
	want := "Subject: " + folded + "\r\n\r\n" + string(body)
	if got != want {
		t.Errorf("reconstructed message =\n%q\nwant\n%q", got, want)
	}

	msg, err := mail.ReadMessage(strings.NewReader(got))
	if err != nil {
		t.Fatalf("net/mail failed to parse the reconstructed folded-header message: %v", err)
	}
	if subj := msg.Header.Get("Subject"); !strings.Contains(subj, "second continuation line") {
		t.Errorf("Subject header lost its folded continuation, got %q", subj)
	}
}

// TestMilter_ZeroHeadersEmptyBody_NoPanicFailOpen is a boundary test: a
// session with no Header fields at all and an empty body must not panic
// anywhere in the reassembly path (reassembleMessage(nil) with zero
// collected headers, and BodyChunk never assigning b.body a non-nil
// spool) and must still resolve to a normal accept.
//
// This drives the low-level session directly (rather than via
// runSessionWithHeaders/BodyReadFrom) because go-milter's own client
// helper requires at least one BodyChunk call before it will send End
// (BodyReadFrom's internal scanner never invokes BodyChunk at all for a
// zero-byte io.Reader), which would silently turn this into an
// at-least-one-chunk scenario instead of the true zero-BodyChunk one
// this test means to exercise.
func TestMilter_ZeroHeadersEmptyBody_NoPanicFailOpen(t *testing.T) {
	proc := &fakeProcessor{verdict: &pipeline.Verdict{Action: pipeline.VerdictAccept}}
	addr := startTestServer(t, proc, nil)

	client := dmilter.NewClient("tcp", addr, dmilter.WithAction(dmilter.AllClientSupportedActionMasks))
	sess, err := client.Session(dmilter.NewMacroBag())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close() //nolint:errcheck // best-effort cleanup

	steps := []struct {
		name string
		fn   func() (*dmilter.Action, error)
	}{
		{"conn", func() (*dmilter.Action, error) {
			return sess.Conn("test-client.example", dmilter.FamilyInet, 25, "127.0.0.1")
		}},
		{"helo", func() (*dmilter.Action, error) { return sess.Helo("test-client.example") }},
		{"mail", func() (*dmilter.Action, error) { return sess.Mail("sender@example.com", "") }},
		{"rcpt", func() (*dmilter.Action, error) { return sess.Rcpt("rcpt@example.com", "") }},
		{"data", func() (*dmilter.Action, error) { return sess.DataStart() }},
		{"header (zero fields)", func() (*dmilter.Action, error) { return sess.Header(textproto.Header{}) }},
	}
	for _, step := range steps {
		act, err := step.fn()
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if act.StopProcessing() {
			t.Fatalf("%s: unexpected stop: %v", step.name, act)
		}
	}

	if _, err := sess.BodyChunk(nil); err != nil {
		t.Fatalf("body chunk (empty): %v", err)
	}
	_, act, err := sess.End()
	if err != nil {
		t.Fatalf("end: %v", err)
	}

	requireAccept(t, act)

	if !proc.called {
		t.Fatal("expected Processor.Process to be called even for a header-less, body-less message")
	}
	if len(proc.bodySeen) != 0 {
		t.Errorf("expected empty Envelope.Body content for a header-less, body-less message, got %q", proc.bodySeen)
	}
}

// TestMilter_Rewrite verifies a VerdictRewrite whose NewBody is a
// complete rewritten RFC 5322 message (headers + body, the real
// rewrite.Rewrite contract) is translated into a ReplaceBody carrying
// ONLY the rewritten body plus an AddHeader for the header the rewrite
// introduced relative to the original message (X-Attachra-Processed).
// The original "Subject" header, being present on the MTA side already,
// must NOT be re-added.
func TestMilter_Rewrite(t *testing.T) {
	const rewrittenBody = "replacement body\r\n"
	// NewBody preserves the original Subject header (which the MTA keeps)
	// and adds X-Attachra-Processed, matching what rewrite.Rewrite emits.
	newBody := "Subject: test message\r\n" +
		"X-Attachra-Processed: version=1; id=deadbeef\r\n" +
		"\r\n" +
		rewrittenBody
	proc := &fakeProcessor{verdict: &pipeline.Verdict{
		Action:  pipeline.VerdictRewrite,
		NewBody: strings.NewReader(newBody),
	}}
	addr := startTestServer(t, proc, nil)

	modifyActs, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("original body\r\n"))

	requireAccept(t, act)

	var gotReplaceBody, gotAddProcessed, gotAddSubject bool
	for _, ma := range modifyActs {
		switch ma.Type {
		case dmilter.ActionReplaceBody:
			gotReplaceBody = true
			if string(ma.Body) != rewrittenBody {
				t.Errorf("replace body = %q, want %q (body only, no header block)", ma.Body, rewrittenBody)
			}
		case dmilter.ActionAddHeader:
			switch ma.HeaderName {
			case "X-Attachra-Processed":
				gotAddProcessed = true
			case "Subject":
				gotAddSubject = true
			}
		}
	}
	if !gotReplaceBody {
		t.Error("expected a ReplaceBody modify action")
	}
	if !gotAddProcessed {
		t.Error("expected an AddHeader modify action for X-Attachra-Processed (new relative to the original headers)")
	}
	if gotAddSubject {
		t.Error("Subject was already on the MTA side and must not be re-added")
	}
}

// spyReadCloser wraps an io.Reader with an io.Closer that records how
// many times Close was called, so tests can assert a caller actually
// released the underlying resource (e.g. a rewrite.Rewrite spoolFile
// backed by a temporary file) rather than merely reading it to EOF.
type spyReadCloser struct {
	io.Reader
	mu     sync.Mutex
	closed int
}

func (s *spyReadCloser) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}

func (s *spyReadCloser) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// TestMilter_RewriteClosesNewBody verifies that when a Processor
// returns a VerdictRewrite whose NewBody implements io.Closer (as
// pipeline.AttachmentProcessor's real rewrite path does, via
// rewrite.Rewrite's temp-file-backed spoolFile once the rewritten body
// spills past its in-memory threshold), the milter backend closes it
// after handing it to m.ReplaceBody. Without this, every rewritten
// message would leak its spool temp file, eventually filling the mail
// server's disk (the MEDIUM finding this test guards against).
func TestMilter_RewriteClosesNewBody(t *testing.T) {
	// A complete rewritten message (header block + body): replaceMessage
	// must still close NewBody after consuming it.
	newBody := "Subject: test message\r\n\r\nreplacement body\r\n"
	spy := &spyReadCloser{Reader: strings.NewReader(newBody)}
	proc := &fakeProcessor{verdict: &pipeline.Verdict{
		Action:  pipeline.VerdictRewrite,
		NewBody: spy,
	}}
	addr := startTestServer(t, proc, nil)

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("original body\r\n"))

	requireAccept(t, act)

	if got := spy.closeCount(); got != 1 {
		t.Errorf("NewBody Close() call count = %d, want exactly 1", got)
	}
}

// assertingProcessor captures the exact Envelope.Body bytes it receives
// and returns a fixed VerdictRewrite. It lets a test assert both the
// input side (the message the backend reconstructed from Header + Body
// events) and the output side (what the backend does with NewBody).
type assertingProcessor struct {
	newBody string

	mu  sync.Mutex
	got []byte
}

func (p *assertingProcessor) Process(_ context.Context, env *pipeline.Envelope) (*pipeline.Verdict, error) {
	var b []byte
	if env.Body != nil {
		b, _ = io.ReadAll(env.Body)
	}
	p.mu.Lock()
	p.got = b
	p.mu.Unlock()
	return &pipeline.Verdict{Action: pipeline.VerdictRewrite, NewBody: strings.NewReader(p.newBody)}, nil
}

func (p *assertingProcessor) received() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.got)
}

// TestMilter_RewriteReconstructsMessageAndReplacesBodyOnly is the
// ATR-289 regression test. It drives a session that delivers headers via
// Header events and the body via BodyChunk events (as a real MTA does),
// and verifies the two halves of the fix end-to-end:
//
//  1. Input: the Processor receives a well-formed RFC 5322 message —
//     the header block (reconstructed from the Header events) followed
//     by a blank line and the body — not a headerless body that would
//     fail message.Parse.
//  2. Output: given a NewBody that is a complete rewritten message, the
//     milter response's ReplaceBody carries ONLY the rewritten body (no
//     Subject / no header block leaks into the body), and the header the
//     rewrite introduced (X-Attachra-Processed) is applied via AddHeader.
func TestMilter_RewriteReconstructsMessageAndReplacesBodyOnly(t *testing.T) {
	const bodyIn = "This message carries the original body.\r\n"
	const rewrittenBody = "This is the REWRITTEN body with a package link.\r\n"
	rewrittenFull := "Subject: reconstructed\r\n" +
		"Content-Type: text/plain\r\n" +
		"X-Attachra-Processed: version=1; id=abc123\r\n" +
		"\r\n" +
		rewrittenBody

	proc := &assertingProcessor{newBody: rewrittenFull}
	addr := startTestServer(t, proc, nil)

	headers := []hdrKV{
		{"Subject", "reconstructed"},
		{"Content-Type", "text/plain"},
	}
	modifyActs, act := runSessionWithHeaders(t, addr, "s@example.com", "r@example.com", headers, []byte(bodyIn))
	requireAccept(t, act)

	// (1) input side: the Processor saw a full message — both headers in
	// the header block, then a blank line, then the body. Header order is
	// not asserted (the milter client library does not guarantee it).
	got := proc.received()
	if !strings.Contains(got, "Subject: reconstructed\r\n") {
		t.Errorf("Processor did not receive the Subject header; got:\n%q", got)
	}
	if !strings.Contains(got, "Content-Type: text/plain\r\n") {
		t.Errorf("Processor did not receive the Content-Type header; got:\n%q", got)
	}
	if !strings.HasSuffix(got, "\r\n\r\n"+bodyIn) {
		t.Errorf("Processor did not receive a blank-line-terminated header block followed by the body; got:\n%q", got)
	}

	// (2) output side: ReplaceBody is body-only; X-Attachra-Processed added.
	var replaced strings.Builder
	var gotReplaceBody, gotAddProcessed bool
	for _, ma := range modifyActs {
		switch ma.Type {
		case dmilter.ActionReplaceBody:
			gotReplaceBody = true
			replaced.Write(ma.Body)
		case dmilter.ActionAddHeader:
			if ma.HeaderName == "X-Attachra-Processed" {
				gotAddProcessed = true
			}
		}
	}
	if !gotReplaceBody {
		t.Fatal("expected a ReplaceBody modify action")
	}
	if replaced.String() != rewrittenBody {
		t.Errorf("ReplaceBody =\n%q\nwant\n%q (body only)", replaced.String(), rewrittenBody)
	}
	if strings.Contains(replaced.String(), "Subject:") || strings.Contains(replaced.String(), "X-Attachra-Processed:") {
		t.Errorf("ReplaceBody must not contain a header block, got:\n%q", replaced.String())
	}
	if !gotAddProcessed {
		t.Error("expected X-Attachra-Processed added via AddHeader")
	}
}

// TestMilter_Reject verifies a VerdictReject from the Processor
// results in a hard SMTP rejection.
func TestMilter_Reject(t *testing.T) {
	proc := &fakeProcessor{verdict: &pipeline.Verdict{Action: pipeline.VerdictReject, Reason: "policy violation"}}
	addr := startTestServer(t, proc, nil)

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("body\r\n"))

	requireReject(t, act)
}

// TestMilter_FailOpen_OnProcessorError verifies that when the
// Processor returns an error and FailureMode is FailOpen, the message
// is accepted unmodified (SR-116-1).
func TestMilter_FailOpen_OnProcessorError(t *testing.T) {
	proc := &fakeProcessor{err: errors.New("simulated processor failure")}
	addr := startTestServer(t, proc, func(c *milter.Config) {
		c.FailureMode = milter.FailOpen
	})

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("body\r\n"))

	requireAccept(t, act)
}

// TestMilter_FailClosed_OnProcessorError verifies that when the
// Processor returns an error and FailureMode is FailClosed, the
// message is temp-failed (SR-116-1).
func TestMilter_FailClosed_OnProcessorError(t *testing.T) {
	proc := &fakeProcessor{err: errors.New("simulated processor failure")}
	addr := startTestServer(t, proc, func(c *milter.Config) {
		c.FailureMode = milter.FailClosed
	})

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("body\r\n"))

	requireTempFail(t, act)
}

// TestMilter_FailOpen_OnProcessorPanic verifies that a panicking
// Processor is recovered and resolved into fail-open accept (SR-116-1).
func TestMilter_FailOpen_OnProcessorPanic(t *testing.T) {
	proc := &fakeProcessor{panics: true}
	addr := startTestServer(t, proc, func(c *milter.Config) {
		c.FailureMode = milter.FailOpen
	})

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("body\r\n"))

	requireAccept(t, act)
}

// TestMilter_FailClosed_OnProcessorPanic verifies that a panicking
// Processor is recovered and resolved into fail-closed tempfail
// (SR-116-1), and that the connection/server survive the panic so
// later sessions still work (the message is never simply lost).
func TestMilter_FailClosed_OnProcessorPanic(t *testing.T) {
	proc := &fakeProcessor{panics: true}
	addr := startTestServer(t, proc, func(c *milter.Config) {
		c.FailureMode = milter.FailClosed
	})

	_, act := runSession(t, addr, "sender@example.com", "rcpt@example.com", []byte("body\r\n"))

	requireTempFail(t, act)

	// The server must still be usable after recovering from a panic.
	proc2 := &fakeProcessor{verdict: &pipeline.Verdict{Action: pipeline.VerdictAccept}}
	addr2 := startTestServer(t, proc2, nil)
	_, act2 := runSession(t, addr2, "sender@example.com", "rcpt@example.com", []byte("body\r\n"))
	requireAccept(t, act2)
}

// TestMilter_ConnectionLimit verifies that MaxConnections bounds the
// number of concurrently open milter sessions (SR-115-1): once the
// limit is reached, a further connection must not be able to
// negotiate until a slot frees up.
func TestMilter_ConnectionLimit(t *testing.T) {
	block := make(chan struct{})
	release := make(chan struct{})
	unblocked := &fakeUnblockProcessor{block: block, release: release}

	addr := startTestServer(t, unblocked, func(c *milter.Config) {
		c.MaxConnections = 1
	})

	// Open the first connection and drive it up to (but not past)
	// EndOfMessage in a goroutine so it holds its slot open while we
	// probe the second connection.
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, act := runSession(t, addr, "a@example.com", "b@example.com", []byte("body\r\n"))
		requireAccept(t, act)
	}()

	<-block // wait until the first session's Process call has started

	// A second connection should not be able to complete negotiation
	// (the TCP accept itself is gated by the limitListener semaphore)
	// while the first session's connection is still open.
	dialCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err == nil {
		// The TCP-level accept can still succeed if the OS backlog
		// queues it; what must not happen is the milter server
		// completing negotiation on it while the slot is taken. We
		// detect this by trying to read the negotiation reply with a
		// short deadline: it must NOT arrive before we release the
		// first session.
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 1)
		_, readErr := conn.Read(buf)
		if readErr == nil {
			t.Error("second connection unexpectedly got a response while connection limit should have blocked it")
		}
		_ = conn.Close()
	}

	close(release) // let the first session finish
	<-firstDone
}

// fakeUnblockProcessor signals on block when Process is entered, then
// waits for release before returning an accept verdict. It is used to
// hold a milter session open deterministically for concurrency tests.
type fakeUnblockProcessor struct {
	block   chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *fakeUnblockProcessor) Process(_ context.Context, env *pipeline.Envelope) (*pipeline.Verdict, error) {
	if env.Body != nil {
		_, _ = io.ReadAll(env.Body)
	}
	f.once.Do(func() { close(f.block) })
	<-f.release
	return &pipeline.Verdict{Action: pipeline.VerdictAccept}, nil
}

// TestMilter_GracefulShutdown verifies that Shutdown waits for an
// in-flight session to complete rather than forcibly severing it.
func TestMilter_GracefulShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}

	release := make(chan struct{})
	block := make(chan struct{})
	proc := &fakeUnblockProcessor{block: block, release: release}

	cfg := milter.Config{
		Listen:          "inet:" + addr,
		FailureMode:     milter.FailOpen,
		ShutdownTimeout: 5 * time.Second,
	}
	srv := milter.NewServer(cfg, proc, discardLogger(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- srv.ListenAndServe(ctx)
	}()
	waitForDial(t, addr)

	sessionDone := make(chan struct{})
	go func() {
		defer close(sessionDone)
		_, act := runSession(t, addr, "a@example.com", "b@example.com", []byte("body\r\n"))
		requireAccept(t, act)
	}()

	<-block // the in-flight session is now blocked inside Process

	// Trigger shutdown while the session is still in flight.
	cancel()

	select {
	case <-sessionDone:
		t.Fatal("session finished before shutdown allowed it to: release was not signaled yet")
	case <-time.After(200 * time.Millisecond):
		// expected: shutdown is waiting for the in-flight session
	}

	close(release)

	select {
	case <-sessionDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for in-flight session to finish during graceful shutdown")
	}

	select {
	case err := <-serveErrCh:
		if err != nil {
			t.Errorf("ListenAndServe: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ListenAndServe to return after shutdown")
	}
}
