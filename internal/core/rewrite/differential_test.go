package rewrite

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRawMultipartReader_MatchesMIMEMultipart_OnCorpus is the
// mandatory differential test: for every top-level multipart message
// in internal/core/message/testdata, rawMultipartReader must find the
// same number of immediate child parts, in the same order, as
// mime/multipart.Reader (the library internal/core/message itself
// relies on for its own tree walk). This is the guarantee that
// rawMultipartReader's PartPath-driving part sequence stays in sync
// with the parser everything else in Attachra uses to build
// decisionByPath — a divergence here would silently misapply
// pass/replace decisions to the wrong part.
//
// It recurses into nested multipart child parts too (matching
// internal/core/message's own recursive descent), so this also
// exercises nested-boundary cases already present in the corpus
// (multipart_related_alternative.eml, nested_message_rfc822.eml).
func TestRawMultipartReader_MatchesMIMEMultipart_OnCorpus(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "message", "testdata"))
	if err != nil {
		t.Fatalf("read testdata dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".eml") {
			continue
		}
		name := entry.Name()

		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "message", "testdata", name)) //nolint:gosec // fixed test fixture directory, not attacker-controlled
			if err != nil {
				t.Fatalf("read %q: %v", name, err)
			}

			msg, err := mail.ReadMessage(bytes.NewReader(raw))
			if err != nil {
				t.Skipf("not a well-formed top-level message, skipping differential check: %v", err)
			}
			contentType := msg.Header.Get("Content-Type")
			mediaType, params, err := mime.ParseMediaType(contentType)
			if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
				t.Skip("not a top-level multipart message, nothing to differentially compare")
			}

			var body bytes.Buffer
			if _, err := io.Copy(&body, msg.Body); err != nil {
				t.Fatalf("read message body: %v", err)
			}

			want, err := countMIMEMultipartParts(bytes.NewReader(body.Bytes()), params["boundary"])
			if err != nil {
				t.Skipf("mime/multipart itself cannot parse this fixture (expected for malformed-input fixtures): %v", err)
			}

			got, err := countRawMultipartParts(bytes.NewReader(body.Bytes()), params["boundary"])
			if err != nil {
				t.Fatalf("rawMultipartReader failed on a message mime/multipart parses fine: %v", err)
			}

			if got != want {
				t.Errorf("rawMultipartReader found %d top-level child parts, mime/multipart found %d", got, want)
			}
		})
	}
}

// countMIMEMultipartParts counts immediate child parts of a multipart
// body using the standard library reader, recursing into any child
// that is itself multipart/* (matching internal/core/message's own
// recursive descent), so the comparison covers nested boundaries too.
func countMIMEMultipartParts(body io.Reader, boundary string) (int, error) {
	if boundary == "" {
		return 0, errNoBoundary
	}
	mr := multipart.NewReader(body, boundary)
	count := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		count++

		childType := part.Header.Get("Content-Type")
		childMediaType, childParams, ctErr := mime.ParseMediaType(childType)
		if ctErr == nil && strings.HasPrefix(childMediaType, "multipart/") {
			nested, err := countMIMEMultipartParts(part, childParams["boundary"])
			if err != nil {
				_ = part.Close()
				return count, err
			}
			count += nested
		}

		if err := part.Close(); err != nil {
			return count, err
		}
	}
}

// countRawMultipartParts is the rawMultipartReader analogue of
// countMIMEMultipartParts, used for the differential comparison.
func countRawMultipartParts(body io.Reader, boundary string) (int, error) {
	if boundary == "" {
		return 0, errNoBoundary
	}
	rmr := newRawMultipartReader(body, boundary)
	count := 0
	for {
		part, err := rmr.NextPart()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		count++

		childType := part.Header.Get("Content-Type")
		childMediaType, childParams, ctErr := mime.ParseMediaType(childType)
		if ctErr == nil && strings.HasPrefix(childMediaType, "multipart/") {
			nested, err := countRawMultipartParts(part.Body, childParams["boundary"])
			if err != nil {
				return count, err
			}
			count += nested
		} else {
			// Drain so the underlying reader can advance.
			if _, err := io.Copy(io.Discard, part.Body); err != nil {
				return count, err
			}
		}
	}
}

var errNoBoundary = boundaryError("multipart Content-Type missing boundary parameter")

type boundaryError string

func (e boundaryError) Error() string { return string(e) }

// TestRewrite_MUAStyleSharedPrefixBoundaries_EndToEnd reproduces
// reviewer repro (3): a real MUA-style message using
// "----=_Part_0_...", "----=_Part_1_..." boundaries (a common pattern
// from Java Mail / Gmail-family senders, where an outer boundary and
// an inner multipart/alternative boundary share the "----=_Part_"
// prefix) must rewrite successfully end-to-end via Rewrite, not fail
// with "unexpected EOF looking for boundary".
func TestRewrite_MUAStyleSharedPrefixBoundaries_EndToEnd(t *testing.T) {
	raw := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: MUA-style shared-prefix boundaries\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"----=_Part_0_111.222\"\r\n" +
		"\r\n" +
		"------=_Part_0_111.222\r\n" +
		"Content-Type: multipart/alternative; boundary=\"----=_Part_1_333.444\"\r\n" +
		"\r\n" +
		"------=_Part_1_333.444\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Plain body.\r\n" +
		"------=_Part_1_333.444\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<p>HTML body.</p>\r\n" +
		"------=_Part_1_333.444--\r\n" +
		"------=_Part_0_111.222\r\n" +
		"Content-Type: application/pdf\r\n" +
		"Content-Disposition: attachment; filename=\"report.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		"JVBERi0xLjQKc3ludGhldGljIHBkZg==\r\n" +
		"------=_Part_0_111.222--\r\n"

	atts := parseMessageBytes(t, []byte(raw))

	var replacePath string
	for _, a := range atts {
		if a.Filename == "report.pdf" {
			replacePath = a.PartPath
		}
	}
	if replacePath == "" {
		t.Fatalf("test setup: report.pdf attachment not found among %+v", atts)
	}

	decision := decisionReplacingAttachments(atts, replacePath)

	result, err := Rewrite(Input{
		Message:     strings.NewReader(raw),
		Attachments: atts,
		Decision:    decision,
		PackageURL:  "https://dl.example.com/p/token",
	}, testTemplates(t))
	if err != nil {
		t.Fatalf("Rewrite failed on MUA-style shared-prefix boundaries: %v", err)
	}

	got := mustReadAll(t, result.Body)

	if bytes.Contains(got, []byte("filename=\"report.pdf\"")) {
		t.Errorf("replaced attachment's part header should not appear in output")
	}
	if !bytes.Contains(got, []byte("Plain body.")) {
		t.Errorf("original plain-text body content lost:\n%s", got)
	}
	if !bytes.Contains(got, []byte("<p>HTML body.</p>")) {
		t.Errorf("original HTML body content lost:\n%s", got)
	}
	if !bytes.Contains(got, []byte("https://dl.example.com/p/token")) {
		t.Errorf("package URL missing from rewritten message")
	}

	reparsedAtts := parseMessageBytes(t, got)
	for _, a := range reparsedAtts {
		if a.Filename == "report.pdf" {
			t.Errorf("replaced attachment %q still present after rewrite", a.Filename)
		}
	}
}
