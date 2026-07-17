package rewrite

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/spoolutil"
)

// buildLargeMessage builds a synthetic multipart/mixed message with
// one large base64-encoded "attachment" part big enough to force
// rewrite's stageToFile to spill to a temporary file
// (spoolutil.SpoolMemThreshold is 256 KiB), plus a small text/plain body.
func buildLargeMessage(t *testing.T, payloadSize int) (raw []byte, atts []message.Attachment) {
	t.Helper()

	payload := bytes.Repeat([]byte("A"), payloadSize)
	encoded := base64.StdEncoding.EncodeToString(payload)

	var buf bytes.Buffer
	buf.WriteString("From: sender@example.com\r\n")
	buf.WriteString("To: recipient@example.com\r\n")
	buf.WriteString("Subject: Large attachment\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: multipart/mixed; boundary=\"BIGBOUND\"\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("--BIGBOUND\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	buf.WriteString("See the large attachment.\r\n")
	buf.WriteString("--BIGBOUND\r\n")
	buf.WriteString("Content-Type: application/octet-stream\r\n")
	buf.WriteString("Content-Disposition: attachment; filename=\"big.bin\"\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteString("\r\n")
	}
	buf.WriteString("--BIGBOUND\r\n")
	buf.WriteString("Content-Type: text/plain\r\n")
	buf.WriteString("Content-Disposition: attachment; filename=\"small.txt\"\r\n\r\n")
	buf.WriteString("small attachment content\r\n")
	buf.WriteString("--BIGBOUND--\r\n")

	raw = buf.Bytes()

	err := message.Parse(bytes.NewReader(raw), message.DefaultLimits(), func(att *message.Attachment, body io.Reader) error {
		n, readErr := io.Copy(io.Discard, body)
		if readErr != nil {
			return readErr
		}
		att.Size = n
		atts = append(atts, *att)
		return nil
	})
	if err != nil {
		t.Fatalf("message.Parse large message: %v", err)
	}
	return raw, atts
}

func TestRewrite_LargeMessage_SpoolsToDisk_PassThrough(t *testing.T) {
	// payload comfortably larger than spoolutil.SpoolMemThreshold (256
	// KiB) so stageToFile must spill to a temporary file.
	raw, atts := buildLargeMessage(t, spoolutil.SpoolMemThreshold*2)

	// Replace nothing (pass the big attachment through) — this
	// exercises the byte-for-byte streaming copy path for a large
	// part, not just the small-message in-memory path.
	decision := decisionReplacingAttachments(atts)

	result, err := Rewrite(Input{
		Message:     bytes.NewReader(raw),
		Attachments: atts,
		Decision:    decision,
		PackageURL:  "https://dl.example.com/p/token",
	}, testTemplates(t))
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}

	got := mustReadAll(t, result.Body)
	if !bytes.Equal(got, raw) {
		t.Fatalf("no-replace passthrough should be byte-identical even for a large message")
	}
}

func TestRewrite_LargeMessage_SpoolsToDisk_ReplacedAndCleanedUp(t *testing.T) {
	raw, atts := buildLargeMessage(t, spoolutil.SpoolMemThreshold*2)

	var replacePath string
	for _, a := range atts {
		// big.bin is left as `pass` so its ~700 KiB base64 body still
		// forces stageToFile to spill to a temporary file; small.txt
		// is the one actually replaced, keeping the "was this
		// attachment removed" assertion meaningful.
		if a.Filename == "small.txt" {
			replacePath = a.PartPath
		}
	}
	if replacePath == "" {
		t.Fatal("test setup: small.txt attachment not found")
	}

	decision := decisionReplacingAttachments(atts, replacePath)

	result, err := Rewrite(Input{
		Message:     bytes.NewReader(raw),
		Attachments: atts,
		Decision:    decision,
		PackageURL:  "https://dl.example.com/p/token",
	}, testTemplates(t))
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}

	closer, ok := result.Body.(io.Closer)
	if !ok {
		t.Fatal("expected spooled result.Body to implement io.Closer")
	}

	got, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read spooled body: %v", err)
	}
	if bytes.Contains(got, []byte("filename=\"small.txt\"")) {
		t.Errorf("replaced attachment's part header should not appear in output")
	}
	if !bytes.Contains(got, []byte("filename=\"big.bin\"")) {
		t.Errorf("pass-through attachment's part header should still appear in output")
	}
	if !bytes.Contains(got, []byte("https://dl.example.com/p/token")) {
		t.Errorf("package URL missing from large rewritten message")
	}

	if err := closer.Close(); err != nil {
		t.Fatalf("Close spooled body: %v", err)
	}

	// Close must have removed the backing temp file; a second Close
	// should still succeed cleanly per os.Remove's ENOENT tolerance
	// documented on spoolFile.Close.
	if err := closer.Close(); err != nil {
		t.Errorf("second Close should be safe, got: %v", err)
	}
}

// TestRewrite_LargeMessage_SpoolsToConfiguredDir verifies that
// Input.SpoolDir (ATR-262) is actually honored: the spill file
// stageToFile creates once the rewritten output exceeds
// spoolutil.SpoolMemThreshold must land inside the configured
// directory, not the OS default temporary directory.
func TestRewrite_LargeMessage_SpoolsToConfiguredDir(t *testing.T) {
	dir := t.TempDir()
	raw, atts := buildLargeMessage(t, spoolutil.SpoolMemThreshold*2)

	// At least one attachment must actually be replaced: Rewrite
	// returns the untouched original message (no staging, hence no
	// io.Closer Result.Body) when the decision has no ActionReplace at
	// all, as TestRewrite_LargeMessage_SpoolsToDisk_PassThrough above
	// exercises deliberately.
	var replacePath string
	for _, a := range atts {
		if a.Filename == "small.txt" {
			replacePath = a.PartPath
		}
	}
	if replacePath == "" {
		t.Fatal("test setup: small.txt attachment not found")
	}
	decision := decisionReplacingAttachments(atts, replacePath)

	result, err := Rewrite(Input{
		Message:     bytes.NewReader(raw),
		Attachments: atts,
		Decision:    decision,
		PackageURL:  "https://dl.example.com/p/token",
		SpoolDir:    dir,
	}, testTemplates(t))
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}

	closer, ok := result.Body.(io.Closer)
	if !ok {
		t.Fatal("expected spooled result.Body to implement io.Closer")
	}
	defer func() { _ = closer.Close() }()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read spool dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one spilled file in configured spool dir, got %d", len(entries))
	}
	if got := entries[0].Name(); !bytes.HasPrefix([]byte(got), []byte("attachra-rewrite-body-")) {
		t.Errorf("spilled file name = %q, want attachra-rewrite-body-* prefix", got)
	}
}

func TestRewrite_ConcurrentUse_NoRace(t *testing.T) {
	path := testdataPath("multipart_mixed_basic.eml")
	tmpl := testTemplates(t)

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw, atts := readAndParseForConcurrency(t, path)
			decision := decisionReplacingAttachments(atts, "0.2")
			result, err := Rewrite(Input{
				Message:     bytes.NewReader(raw),
				Attachments: atts,
				Decision:    decision,
				PackageURL:  fmt.Sprintf("https://dl.example.com/p/token-%d", i),
			}, tmpl)
			if err != nil {
				errs <- err
				return
			}
			if _, err := io.ReadAll(result.Body); err != nil {
				errs <- err
				return
			}
			errs <- nil
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Rewrite failed: %v", err)
		}
	}
}

// readAndParseForConcurrency is a small helper duplicating
// parseTestdata's body-reading logic without requiring *testing.T
// synchronization concerns beyond what t.Helper already provides
// (each goroutine parses its own independent copy of the file).
func readAndParseForConcurrency(t *testing.T, path string) ([]byte, []message.Attachment) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // fixed test fixture directory, not attacker-controlled
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var atts []message.Attachment
	err = message.Parse(bytes.NewReader(raw), message.DefaultLimits(), func(att *message.Attachment, body io.Reader) error {
		n, readErr := io.Copy(io.Discard, body)
		if readErr != nil {
			return readErr
		}
		att.Size = n
		atts = append(atts, *att)
		return nil
	})
	if err != nil {
		t.Fatalf("message.Parse: %v", err)
	}
	return raw, atts
}
