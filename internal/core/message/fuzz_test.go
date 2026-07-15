package message

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParse is the fuzzing seed for Parse (ATR-159 / T-3.1.4). It
// seeds the fuzzer with the whole synthetic testdata/ corpus plus a
// handful of hand-picked edge cases, then asserts the one invariant
// that must hold for arbitrary attacker-controlled input: Parse must
// never panic, and DetectType/extractFilename (exercised on every
// discovered leaf) must never panic either. Parse returning an error
// is an expected, safe outcome for malformed input; only a panic is a
// bug here — the fail-open/fail-closed decision for a returned error
// belongs to the milter adapter (CLAUDE.md invariant #3), not to this
// package.
func FuzzParse(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("read testdata dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".eml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join("testdata", entry.Name()))
		if err != nil {
			f.Fatalf("read testdata %q: %v", entry.Name(), err)
		}
		f.Add(data)
	}

	f.Add([]byte(""))
	f.Add([]byte("not a mime message at all"))
	f.Add([]byte("Content-Type: multipart/mixed\r\n\r\nno boundary declared"))
	f.Add([]byte("From: a@example.com\r\nContent-Type: multipart/mixed; boundary=\"x\"\r\n\r\n--x\r\n--x\r\n--x--\r\n"))
	f.Add([]byte("Content-Type: message/rfc822\r\n\r\nContent-Type: message/rfc822\r\n\r\nContent-Type: message/rfc822\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Parse panicked on input %q: %v", data, r)
			}
		}()

		limits := Limits{
			MaxDepth:     8,
			MaxParts:     200,
			MaxHeaders:   100,
			MaxPartSize:  1 << 20,
			MaxTotalSize: 4 << 20,
		}

		_ = Parse(bytes.NewReader(data), limits, func(att *Attachment, body io.Reader) error {
			content, _ := io.ReadAll(io.LimitReader(body, sniffLen))
			// Must not panic regardless of how malformed the
			// declared/decoded name or content is.
			att.DetectedType = DetectType(content)
			_ = extractFilename("", att.DeclaredType)
			return nil
		})
	})
}
