//go:build e2e

// Package e2e contains end-to-end tests that run against the compose
// dev environment (see deploy/dev/docker-compose.yml). They are gated
// behind the "e2e" build tag so they never run as part of `go test ./...`
// or `make test`; invoke them explicitly with:
//
//	go test -tags e2e ./test/e2e/...
//
// The tests skip themselves (t.Skip) when the environment is not
// reachable, so `make e2e` is safe to run on a machine without the
// compose stack up, at the cost of a skipped rather than failed run.
package e2e

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	dmilter "github.com/d--j/go-milter"
	dmessagetextproto "github.com/emersion/go-message/textproto"
)

// Environment defaults match deploy/dev/docker-compose.yml's published
// host ports. They can be overridden via environment variables so the
// same test can target a differently-mapped or remote compose stack.
const (
	defaultSMTPAddr   = "localhost:2525"
	defaultMinIOAddr  = "localhost:9000"
	defaultMilterAddr = "localhost:7357"
	defaultHTTPAddr   = "localhost:8080"
	defaultFrom       = "sender@attachra-dev.local"
	defaultTo         = "recipient@attachra-dev.local"

	dialTimeout = 3 * time.Second
)

func smtpAddr() string {
	return envOr("ATTACHRA_E2E_SMTP_ADDR", defaultSMTPAddr)
}

func minioAddr() string {
	return envOr("ATTACHRA_E2E_MINIO_ADDR", defaultMinIOAddr)
}

func milterAddr() string {
	return envOr("ATTACHRA_E2E_MILTER_ADDR", defaultMilterAddr)
}

func httpAddr() string {
	return envOr("ATTACHRA_E2E_HTTP_ADDR", defaultHTTPAddr)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// requireReachable dials addr and skips the test if it cannot connect,
// so the e2e suite is a no-op (not a failure) on a host without the
// compose environment running.
func requireReachable(t *testing.T, name, addr string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		t.Skipf("skipping: %s not reachable at %s: %v (start deploy/dev/docker-compose.yml first)", name, addr, err)
		return
	}
	_ = conn.Close() //nolint:errcheck // best-effort close of a probe connection
}

// TestSMTPReachable verifies the compose Postfix service accepts TCP
// connections on the mapped SMTP port.
func TestSMTPReachable(t *testing.T) {
	requireReachable(t, "SMTP", smtpAddr())
}

// TestMinIOReachable verifies the compose MinIO service accepts TCP
// connections on the mapped S3 API port and responds to HTTP.
func TestMinIOReachable(t *testing.T) {
	requireReachable(t, "MinIO", minioAddr())

	resp, err := http.Get(fmt.Sprintf("http://%s/minio/health/live", minioAddr()))
	if err != nil {
		t.Fatalf("MinIO health check request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a health-check response

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("MinIO health check: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestMilterReachable verifies the compose Attachra service accepts
// TCP connections on the published milter port (see
// deploy/dev/docker-compose.yml, deploy/dev/attachra.yaml).
func TestMilterReachable(t *testing.T) {
	requireReachable(t, "Attachra milter", milterAddr())
}

// TestMilterAcceptsMessage drives a full milter session (the same
// stages Postfix itself drives: Conn/Helo/Mail/Rcpt/Data/Header/Body/
// End) directly against the compose Attachra service with a body-only
// message (no MIME attachment part at all). Even though
// deploy/dev/policy.yaml's default action is `replace` (ATR-167), a
// message with no attachments never triggers attachment policy at all
// (docs/architecture/policy-format-v1.md §3.1: "messages without
// attachments do not run the attachment policy; the message's action
// is delivered as-is"), so this message is still expected to come back
// as a plain accept, exercising that codepath specifically rather than
// the compose stack's PassthroughProcessor default (which no longer
// applies once deploy/dev/attachra.yaml configures a policy — see
// TestMilterReplacesAttachment below for the replace-path scenario).
//
// This is the T-2.1.5 "real Postfix" integration test's skeleton: it
// exercises the real milter wire protocol end-to-end against the
// running Attachra binary (not an in-process test double, unlike
// internal/adapters/milter's unit tests), but talks to Attachra
// directly rather than through Postfix, since scripting Postfix's own
// SMTP-to-milter handoff and observing the result requires the
// compose stack's mailbox/queue tooling that is out of scope here.
func TestMilterAcceptsMessage(t *testing.T) {
	requireReachable(t, "Attachra milter", milterAddr())

	client := dmilter.NewClient("tcp", milterAddr())
	sess, err := client.Session(dmilter.NewMacroBag())
	if err != nil {
		t.Fatalf("milter session: %v", err)
	}
	defer sess.Close() //nolint:errcheck // best-effort cleanup

	steps := []struct {
		name string
		fn   func() (*dmilter.Action, error)
	}{
		{"conn", func() (*dmilter.Action, error) {
			return sess.Conn("e2e-test.example", dmilter.FamilyInet, 25, "127.0.0.1")
		}},
		{"helo", func() (*dmilter.Action, error) { return sess.Helo("e2e-test.example") }},
		{"mail", func() (*dmilter.Action, error) { return sess.Mail(defaultFrom, "") }},
		{"rcpt", func() (*dmilter.Action, error) { return sess.Rcpt(defaultTo, "") }},
		{"data", func() (*dmilter.Action, error) { return sess.DataStart() }},
		{"header", func() (*dmilter.Action, error) {
			var hdr dmessagetextproto.Header
			hdr.Add("Subject", "Attachra e2e milter test")
			return sess.Header(hdr)
		}},
	}

	for _, step := range steps {
		act, err := step.fn()
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if act.StopProcessing() {
			t.Fatalf("%s: unexpected stop-processing action: %v", step.name, act)
		}
	}

	_, act, err := sess.BodyReadFrom(strings.NewReader("This is an Attachra e2e milter test body.\r\n"))
	if err != nil {
		t.Fatalf("body/end: %v", err)
	}
	if act.Type != dmilter.ActionAccept && act.Type != dmilter.ActionContinue {
		t.Fatalf("expected accept for an attachment-less message, got %v", act)
	}
}

// TestMilterReplacesAttachment drives a full milter session carrying a
// message with one MIME attachment part directly against the compose
// Attachra service (ATR-167) and asserts the real end-to-end path:
// deploy/dev/policy.yaml's default `replace` action fires, the server
// returns an ActionReplaceBody modify action, and the rewritten body
// no longer contains the original attachment's raw bytes but does
// contain a package-page link
// (docs/architecture/package-page-decision.md §4.1) pointing at
// deploy/dev/attachra.yaml's public_base_url.
//
// This talks to Attachra's milter port directly rather than through
// Postfix, for the same reason TestMilterAcceptsMessage does (see its
// doc comment): scripting Postfix's SMTP-to-milter handoff and
// observing the final delivered message requires mailbox/queue
// tooling this compose stack does not provide.
//
// ATR-344: beyond the milter-visible rewrite, this test also drives
// the two-step download flow the resulting package-page URL points at
// (GET /p/<token> then POST /p/<token>/d/<link-id>, see
// internal/adapters/http/package_page.go and download.go) and
// compares the downloaded bytes against the original attachment
// content by sha256 — the gap a manual check caught at the v0.2.1
// release gate (the milter-level assertions above only confirm the
// bytes were *removed* from the rewritten message, not that the
// replacement link actually serves the *same* bytes back from
// storage).
func TestMilterReplacesAttachment(t *testing.T) {
	requireReachable(t, "Attachra milter", milterAddr())

	const attachmentContent = "synthetic e2e attachment payload for ATR-167"
	body := "" +
		"--e2e-boundary\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"This message carries one attachment that the dev-compose policy replaces.\r\n" +
		"--e2e-boundary\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"e2e-report.bin\"\r\n" +
		"\r\n" +
		attachmentContent + "\r\n" +
		"--e2e-boundary--\r\n"

	client := dmilter.NewClient("tcp", milterAddr(),
		dmilter.WithAction(dmilter.AllClientSupportedActionMasks),
	)
	sess, err := client.Session(dmilter.NewMacroBag())
	if err != nil {
		t.Fatalf("milter session: %v", err)
	}
	defer sess.Close() //nolint:errcheck // best-effort cleanup

	steps := []struct {
		name string
		fn   func() (*dmilter.Action, error)
	}{
		{"conn", func() (*dmilter.Action, error) {
			return sess.Conn("e2e-test.example", dmilter.FamilyInet, 25, "127.0.0.1")
		}},
		{"helo", func() (*dmilter.Action, error) { return sess.Helo("e2e-test.example") }},
		{"mail", func() (*dmilter.Action, error) { return sess.Mail(defaultFrom, "") }},
		{"rcpt", func() (*dmilter.Action, error) { return sess.Rcpt(defaultTo, "") }},
		{"data", func() (*dmilter.Action, error) { return sess.DataStart() }},
		{"header", func() (*dmilter.Action, error) {
			var hdr dmessagetextproto.Header
			hdr.Add("Subject", "Attachra e2e replace test")
			hdr.Add("MIME-Version", "1.0")
			hdr.Add("Content-Type", `multipart/mixed; boundary="e2e-boundary"`)
			return sess.Header(hdr)
		}},
	}

	for _, step := range steps {
		act, err := step.fn()
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if act.StopProcessing() {
			t.Fatalf("%s: unexpected stop-processing action: %v", step.name, act)
		}
	}

	modifyActs, act, err := sess.BodyReadFrom(strings.NewReader(body))
	if err != nil {
		t.Fatalf("body/end: %v", err)
	}
	if act.Type != dmilter.ActionAccept && act.Type != dmilter.ActionContinue {
		t.Fatalf("expected accept (rewrite), got %v", act)
	}

	var rewritten []byte
	for _, ma := range modifyActs {
		if ma.Type == dmilter.ActionReplaceBody {
			rewritten = append(rewritten, ma.Body...)
		}
	}
	if rewritten == nil {
		t.Fatal("expected a ReplaceBody modify action for a replace-decided attachment, got none")
	}

	rewrittenStr := string(rewritten)
	if strings.Contains(rewrittenStr, attachmentContent) {
		t.Error("rewritten body still contains the original attachment's raw content, want it removed")
	}

	wantURLPrefix := "http://" + httpAddr() + "/p/"
	if !strings.Contains(rewrittenStr, wantURLPrefix) {
		t.Errorf("rewritten body does not contain the expected package URL prefix %q:\n%s", wantURLPrefix, rewrittenStr)
	}
	if !strings.Contains(rewrittenStr, "e2e-report.bin") {
		t.Error("rewritten body does not mention the replaced attachment's file name")
	}

	// ATR-344: follow the package-page link end to end and confirm the
	// bytes served back out are byte-identical to what was replaced,
	// not just that the raw content disappeared from the rewritten
	// body (see the doc comment above).
	packageURL := extractPackageURL(t, rewrittenStr)
	downloadURL := fetchDownloadURL(t, packageURL)
	downloaded, contentDisposition := downloadFile(t, downloadURL)

	wantSum := sha256.Sum256([]byte(attachmentContent))
	gotSum := sha256.Sum256(downloaded)
	if gotSum != wantSum {
		t.Errorf("downloaded attachment sha256 = %x, want %x (content = %q)", gotSum, wantSum, downloaded)
	}
	if !strings.Contains(contentDisposition, "e2e-report.bin") {
		t.Errorf("download Content-Disposition = %q, want it to mention e2e-report.bin", contentDisposition)
	}
}

// downloadLinkRe matches the "Download link: <url>" line rendered by
// internal/core/rewrite/templates/en/block.txt.tmpl's plain-text
// replacement block, capturing the URL itself (which runs to the next
// whitespace, since the template emits nothing else on that line).
var downloadLinkRe = regexp.MustCompile(`Download link:\s*(\S+)`)

// extractPackageURL pulls the package-page URL out of a rewritten
// message body's plain-text replacement block.
func extractPackageURL(t *testing.T, rewrittenBody string) string {
	t.Helper()

	m := downloadLinkRe.FindStringSubmatch(rewrittenBody)
	if m == nil {
		t.Fatalf("rewritten body has no %q line:\n%s", "Download link: <url>", rewrittenBody)
	}
	return m[1]
}

// downloadFormActionRe matches the package page's single-use download
// form action attribute (internal/adapters/http/templates.go's
// packagePageTemplate: `<form method="post" action="{{$.PackagePath}}/d/{{.Ref}}">`).
var downloadFormActionRe = regexp.MustCompile(`action="([^"]+/d/[^"]+)"`)

// fetchDownloadURL performs step 1 of the two-step download flow
// (SR-125-3, docs/architecture/package-page-decision.md §4.1 item 3):
// GET the package page and extract the step-2 download URL from its
// download form, exactly as a recipient's browser would.
func fetchDownloadURL(t *testing.T, packageURL string) string {
	t.Helper()

	resp, err := http.Get(packageURL) //nolint:gosec // packageURL is produced by this test itself, not attacker-controlled
	if err != nil {
		t.Fatalf("GET package page %s: %v", packageURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a test response

	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read package page body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET package page %s: status %d, body:\n%s", packageURL, resp.StatusCode, page)
	}

	m := downloadFormActionRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("package page has no download form action:\n%s", page)
	}

	base, err := url.Parse(packageURL)
	if err != nil {
		t.Fatalf("parse package URL %q: %v", packageURL, err)
	}
	ref, err := url.Parse(string(m[1]))
	if err != nil {
		t.Fatalf("parse download form action %q: %v", m[1], err)
	}
	return base.ResolveReference(ref).String()
}

// downloadFile performs step 2 of the two-step download flow (POST
// the download URL with an empty body, per
// internal/adapters/http/download.go's serveDownload) and returns the
// streamed attachment bytes plus the response's Content-Disposition
// header.
func downloadFile(t *testing.T, downloadURL string) ([]byte, string) {
	t.Helper()

	resp, err := http.Post(downloadURL, "", nil) //nolint:gosec // downloadURL is produced by this test itself, not attacker-controlled
	if err != nil {
		t.Fatalf("POST download %s: %v", downloadURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a test response

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read download response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST download %s: status %d, body:\n%s", downloadURL, resp.StatusCode, body)
	}
	return body, resp.Header.Get("Content-Disposition")
}

// TestSendMailWithAttachmentDelivers sends a test email with a small
// synthetic attachment through the compose Postfix service and only
// asserts that SMTP delivery itself succeeds. The full replace-path
// assertions (rewritten body, package link, MinIO-retrievable object)
// are covered directly against the milter port by
// TestMilterReplacesAttachment above, since this compose stack has no
// mailbox/queue tooling to observe what Postfix ultimately delivers
// (see TestMilterAcceptsMessage's doc comment for the same
// limitation).
func TestSendMailWithAttachmentDelivers(t *testing.T) {
	requireReachable(t, "SMTP", smtpAddr())

	attachmentPath := writeTempAttachment(t, 64*1024) // 64 KiB synthetic attachment.

	msg, err := buildTestMessage(defaultFrom, defaultTo, "Attachra e2e test", attachmentPath)
	if err != nil {
		t.Fatalf("build test message: %v", err)
	}

	if err := sendMailInsecureTLS(smtpAddr(), defaultFrom, []string{defaultTo}, msg); err != nil {
		t.Fatalf("send mail via %s: %v", smtpAddr(), err)
	}

	// TODO(US-7.1): once audit logging exists, poll it (or an API
	// endpoint) here to confirm the message was actually processed,
	// rather than only asserting that SMTP accepted it.
}

// sendMailInsecureTLS delivers msg over SMTP much like smtp.SendMail,
// but when the server advertises STARTTLS it upgrades the connection
// with certificate verification disabled.
//
// smtp.SendMail always attempts STARTTLS with full certificate
// verification when the server offers it, and the compose dev Postfix
// (boky/postfix) presents a self-signed certificate that Go rejects
// ("x509: certificate is not standards compliant"). Disabling
// verification is acceptable ONLY here: this file is behind the "e2e"
// build tag and targets a local dev stack (never a production relay),
// and Attachra itself never speaks SMTP — it is a milter. Production
// delivery does not run this code.
func sendMailInsecureTLS(addr, from string, to []string, msg []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("split host/port %q: %w", addr, err)
	}

	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer c.Close() //nolint:errcheck // best-effort close; Quit below is the real close

	if err := c.Hello("attachra-e2e.local"); err != nil {
		return fmt.Errorf("helo: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		// #nosec G402 -- self-signed dev Postfix cert; e2e-only, never production (see doc comment).
		if err := c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("mail from %q: %w", from, err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt to %q: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write message body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data writer: %w", err)
	}
	return c.Quit()
}

// writeTempAttachment creates a temp file of size bytes filled with
// random content and registers cleanup with t.
func writeTempAttachment(t *testing.T, size int64) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "attachra-e2e-*.bin")
	if err != nil {
		t.Fatalf("create temp attachment: %v", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close, write errors are checked below

	if _, err := io.CopyN(f, rand.Reader, size); err != nil {
		t.Fatalf("write temp attachment: %v", err)
	}

	return f.Name()
}

// buildTestMessage renders a minimal RFC 5322 multipart/mixed message
// with one attachment. It mirrors hack/sendmail-test's message builder
// but stays self-contained so the e2e suite has no dependency on
// hack/, keeping the "e2e" build-tagged package free of cross-cutting
// build concerns.
//
// ATR-342: the attachment is base64-encoded (RFC 2045 §6.8) rather
// than sent with "Content-Transfer-Encoding: binary", for the same
// reason hack/sendmail-test's attachFile is (see its doc comment):
// sendMailInsecureTLS below writes msg through net/smtp's textproto
// dotWriter, which canonicalizes bare LF bytes to CRLF and would
// silently corrupt a raw binary payload.
func buildTestMessage(from, to, subject, attachmentPath string) ([]byte, error) {
	var buf strings.Builder
	writer := multipart.NewWriter(&buf)

	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", to)
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/mixed; boundary=%q\r\n", writer.Boundary())
	fmt.Fprintf(&buf, "\r\n")

	bodyPart, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/plain; charset=utf-8"},
	})
	if err != nil {
		return nil, fmt.Errorf("create body part: %w", err)
	}
	if _, err := io.WriteString(bodyPart, "This is an Attachra e2e test email.\r\n"); err != nil {
		return nil, fmt.Errorf("write body part: %w", err)
	}

	f, err := os.Open(attachmentPath) //nolint:gosec // attachmentPath is generated by this test, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("open attachment: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close after a successful read

	name := filepath.Base(attachmentPath)
	contentType := mime.TypeByExtension(filepath.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {contentType},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Disposition":       {fmt.Sprintf("attachment; filename=%q", name)},
	})
	if err != nil {
		return nil, fmt.Errorf("create attachment part: %w", err)
	}
	if err := writeBase64Encoded(part, f); err != nil {
		return nil, fmt.Errorf("copy attachment: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	return []byte(buf.String()), nil
}

// base64EncodedLineLength is the maximum number of base64-encoded
// characters per line, matching RFC 2045 §6.8's 76-character limit for
// base64 MIME body content.
const base64EncodedLineLength = 76

// writeBase64Encoded streams src into dst as base64 (RFC 2045 §6.8),
// wrapped at base64EncodedLineLength characters per line with CRLF
// line breaks, without buffering the whole encoded attachment in
// memory. It mirrors hack/sendmail-test's base64LineWriter (ATR-342).
func writeBase64Encoded(dst io.Writer, src io.Reader) error {
	lw := &base64LineWriter{w: dst}
	enc := base64.NewEncoder(base64.StdEncoding, lw)
	if _, err := io.Copy(enc, src); err != nil {
		return fmt.Errorf("base64-encode: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close base64 encoder: %w", err)
	}
	if lw.lineLen > 0 {
		if _, err := lw.w.Write([]byte("\r\n")); err != nil {
			return fmt.Errorf("write trailing line break: %w", err)
		}
	}
	return nil
}

// base64LineWriter wraps an underlying writer, inserting a CRLF line
// break every base64EncodedLineLength bytes written to it. See
// hack/sendmail-test/main.go's identical type for the full rationale;
// duplicated here rather than imported so the "e2e" build-tagged
// package stays free of a dependency on hack/'s package main.
type base64LineWriter struct {
	w       io.Writer
	lineLen int
}

func (lw *base64LineWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		remaining := base64EncodedLineLength - lw.lineLen
		n := remaining
		if n > len(p) {
			n = len(p)
		}
		if _, err := lw.w.Write(p[:n]); err != nil {
			return total, err
		}
		total += n
		lw.lineLen += n
		p = p[n:]

		if lw.lineLen == base64EncodedLineLength {
			if _, err := lw.w.Write([]byte("\r\n")); err != nil {
				return total, err
			}
			lw.lineLen = 0
		}
	}
	return total, nil
}
