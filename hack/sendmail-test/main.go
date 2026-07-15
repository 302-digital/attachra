// Command sendmail-test is a small development utility that sends a test
// email with one or more attachments over SMTP. It exists to exercise the
// Attachra dev environment (see deploy/dev/docker-compose.yml) end to end
// without needing a full mail client, and is reused by the e2e test
// harness (see test/e2e).
//
// Usage:
//
//	go run ./hack/sendmail-test --smtp localhost:2525 \
//	    --from sender@attachra-dev.local --to recipient@attachra-dev.local \
//	    --attach ./report.pdf --size 10
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// attachList collects repeated --attach flag values.
type attachList []string

func (a *attachList) String() string {
	return strings.Join(*a, ",")
}

func (a *attachList) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sendmail-test", flag.ContinueOnError)
	fs.SetOutput(stderr)

	smtpAddr := fs.String("smtp", "localhost:2525", "SMTP server address (host:port)")
	from := fs.String("from", "sender@attachra-dev.local", "envelope and header From address")
	to := fs.String("to", "recipient@attachra-dev.local", "envelope and header To address")
	subject := fs.String("subject", "Attachra dev test email", "email subject")
	sizeMB := fs.Int("size", 0, "generate a synthetic attachment of N MiB (in addition to any --attach files)")

	var attachments attachList
	fs.Var(&attachments, "attach", "path to a file to attach (repeatable)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *sizeMB > 0 {
		syntheticPath, err := writeSyntheticAttachment(*sizeMB)
		if err != nil {
			fmt.Fprintf(stderr, "sendmail-test: generate synthetic attachment: %v\n", err) //nolint:errcheck // best-effort diagnostic
			return 1
		}
		defer os.Remove(syntheticPath) //nolint:errcheck // best-effort cleanup of a temp file
		attachments = append(attachments, syntheticPath)
	}

	msg, err := buildMessage(*from, *to, *subject, attachments)
	if err != nil {
		fmt.Fprintf(stderr, "sendmail-test: build message: %v\n", err) //nolint:errcheck // best-effort diagnostic
		return 1
	}

	if err := smtp.SendMail(*smtpAddr, nil, *from, []string{*to}, msg); err != nil {
		fmt.Fprintf(stderr, "sendmail-test: send mail: %v\n", err) //nolint:errcheck // best-effort diagnostic
		return 1
	}

	fmt.Fprintf(stdout, "sendmail-test: sent message from %s to %s via %s (%d attachment(s))\n", //nolint:errcheck // best-effort diagnostic
		*from, *to, *smtpAddr, len(attachments))
	return 0
}

// writeSyntheticAttachment creates a temporary file of sizeMB mebibytes
// filled with random bytes, and returns its path.
func writeSyntheticAttachment(sizeMB int) (string, error) {
	f, err := os.CreateTemp("", "attachra-sendmail-test-*.bin")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close, write errors are checked below

	const mib = 1 << 20
	if _, err := io.CopyN(f, rand.Reader, int64(sizeMB)*mib); err != nil {
		os.Remove(f.Name()) //nolint:errcheck // best-effort cleanup on error path
		return "", fmt.Errorf("write %d MiB: %w", sizeMB, err)
	}

	return f.Name(), nil
}

// buildMessage renders a full RFC 5322 message with a multipart/mixed
// body containing a plain-text part and the given attachments.
func buildMessage(from, to, subject string, attachments []string) ([]byte, error) {
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
	if _, err := io.WriteString(bodyPart, "This is a test email sent by hack/sendmail-test.\r\n"); err != nil {
		return nil, fmt.Errorf("write body part: %w", err)
	}

	for _, path := range attachments {
		if err := attachFile(writer, path); err != nil {
			return nil, fmt.Errorf("attach %q: %w", path, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	return []byte(buf.String()), nil
}

// attachFile streams the file at path into the multipart writer as a
// base64-free binary attachment part (SMTP transport encoding, if
// needed, is left to the sending MTA in this dev utility).
func attachFile(writer *multipart.Writer, path string) error {
	f, err := os.Open(path) //nolint:gosec // path is an operator-supplied CLI flag, not untrusted input
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close after a successful read

	name := filepath.Base(path)
	contentType := mime.TypeByExtension(filepath.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	header := textproto.MIMEHeader{
		"Content-Type":              {contentType},
		"Content-Transfer-Encoding": {"binary"},
		"Content-Disposition":       {fmt.Sprintf("attachment; filename=%q", name)},
	}

	part, err := writer.CreatePart(header)
	if err != nil {
		return fmt.Errorf("create part: %w", err)
	}

	if _, err := io.Copy(part, f); err != nil {
		return fmt.Errorf("copy contents: %w", err)
	}

	return nil
}
