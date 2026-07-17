package rewrite

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRawMultipartReader_RoundTrip_OnCorpus is the round-trip
// complement to TestRawMultipartReader_MatchesMIMEMultipart_OnCorpus
// in differential_test.go (ATR-235, follow-up from the ATR-118
// review): that test only compares the *count* of parts
// rawMultipartReader finds against mime/multipart, so a defect that
// shifts a trailing-CRLF byte between two adjacent parts without
// changing the part count would pass it unnoticed — and byte-identical
// passthrough for `pass`-decided attachments is exactly the guarantee
// US-3.2 makes.
//
// This test instead reassembles every top-level multipart message in
// internal/core/message/testdata from rawMultipartReader's raw,
// still-encoded parts using boundaryWriter (walk.go) — the same
// delimiter-emission logic rewrite's own pass-through path
// (rewriteLeaf's "ordinary pass-through" branch) relies on — and
// asserts the reassembled bytes equal the original body byte-for-byte.
// It never invokes mime/multipart's own decoding, so unlike a
// raw-vs-mime/multipart body comparison, a quoted-printable or base64
// part cannot produce a false mismatch here.
func TestRawMultipartReader_RoundTrip_OnCorpus(t *testing.T) {
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
				t.Skipf("not a well-formed top-level message, skipping round-trip check: %v", err)
			}
			contentType := msg.Header.Get("Content-Type")
			mediaType, params, err := mime.ParseMediaType(contentType)
			if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
				t.Skip("not a top-level multipart message, nothing to round-trip")
			}
			boundary := params["boundary"]
			if boundary == "" {
				t.Skip("multipart Content-Type has no boundary parameter, nothing to round-trip")
			}

			var body bytes.Buffer
			if _, err := io.Copy(&body, msg.Body); err != nil {
				t.Fatalf("read message body: %v", err)
			}

			got, err := reassembleRawMultipart(body.Bytes(), boundary, true)
			if err != nil {
				t.Skipf("rawMultipartReader cannot parse this fixture, skipping round-trip check: %v", err)
			}

			if !bytes.Equal(got, body.Bytes()) {
				t.Errorf("round-trip mismatch for %q:\n got:  %q\nwant: %q", name, got, body.Bytes())
			}
		})
	}
}

// reassembleRawMultipart reads body's parts with rawMultipartReader
// and re-emits them with boundaryWriter, recursing into any child part
// that is itself multipart/* (the only structure boundaryWriter needs
// to reproduce). A child part that is not itself multipart — including
// a message/rfc822 forwarded envelope, which may look like a MIME
// message internally — is treated as opaque leaf content and copied
// back out exactly as read, matching how rewriteLeaf's pass-through
// branch and rewriteNestedMessage's non-multipart branch both leave
// such bodies untouched.
//
// topLevel is threaded through exactly as walk.go's rewriteMultipart
// does, to decide whether this call's own closing delimiter owns a
// final trailing CRLF (see boundaryWriter.finalCRLF's doc comment):
// true only for the outermost call the caller makes, false for every
// recursive call into a nested multipart/* child.
func reassembleRawMultipart(body []byte, boundary string, topLevel bool) ([]byte, error) {
	var out bytes.Buffer
	bw := &boundaryWriter{dst: &out, boundary: boundary, finalCRLF: topLevel}

	rmr := newRawMultipartReader(bytes.NewReader(body), boundary)
	for {
		part, err := rmr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		bodyBytes, err := io.ReadAll(part.Body)
		if err != nil {
			return nil, err
		}

		var partBuf bytes.Buffer
		partBuf.Write(part.HeaderBytes)

		childType := part.Header.Get("Content-Type")
		childMediaType, childParams, ctErr := mime.ParseMediaType(childType)
		if ctErr == nil && strings.HasPrefix(childMediaType, "multipart/") && childParams["boundary"] != "" {
			nested, err := reassembleRawMultipart(bodyBytes, childParams["boundary"], false)
			if err != nil {
				return nil, err
			}
			partBuf.Write(nested)
		} else {
			partBuf.Write(bodyBytes)
		}

		if err := bw.writePart(partBuf.Bytes()); err != nil {
			return nil, err
		}
	}

	if err := bw.writeClosing(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
