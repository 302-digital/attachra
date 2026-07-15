package rewrite

import (
	"bytes"
	"io"
	"testing"
)

// TestClassifyBoundaryLine_RFC2046Grammar exercises
// classifyBoundaryLine directly against RFC 2046 §5.1.1's
// dash-boundary / close-delimiter / transport-padding grammar.
func TestClassifyBoundaryLine_RFC2046Grammar(t *testing.T) {
	boundary := []byte("--b")

	tests := []struct {
		name string
		line string
		want boundaryLineKind
	}{
		{"exact delimiter", "--b", delimiter},
		{"exact close delimiter", "--b--", closeDelimiter},
		{"delimiter with trailing space padding", "--b  ", delimiter},
		{"delimiter with trailing tab padding", "--b\t", delimiter},
		{"close delimiter with trailing padding", "--b--  ", closeDelimiter},
		{"body line sharing boundary prefix, more text", "--because I said so", notBoundary},
		{"body line sharing boundary prefix, letter suffix", "--bxyz", notBoundary},
		{"nested boundary with shared prefix (b vs bx)", "--bx", notBoundary},
		{"ordinary content", "just some content", notBoundary},
		{"padding with non-LWS char is not a delimiter", "--b abc", notBoundary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyBoundaryLine([]byte(tt.line), boundary)
			if got != tt.want {
				t.Errorf("classifyBoundaryLine(%q, %q) = %v, want %v", tt.line, boundary, got, tt.want)
			}
		})
	}
}

// TestRawMultipartReader_BodyLineSharesBoundaryPrefix reproduces
// reviewer repro (1): a body content line "--because I said so"
// against boundary "b" must not be mistaken for a delimiter and must
// not truncate the part's body.
func TestRawMultipartReader_BodyLineSharesBoundaryPrefix(t *testing.T) {
	raw := "--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"intro line\r\n" +
		"--because I said so\r\n" +
		"more content\r\n" +
		"--b--\r\n"

	rmr := newRawMultipartReader(bytes.NewReader([]byte(raw)), "b")
	part, err := rmr.NextPart()
	if err != nil {
		t.Fatalf("NextPart: %v", err)
	}
	body, err := io.ReadAll(part.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	want := "intro line\r\n--because I said so\r\nmore content"
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}

	_, err = rmr.NextPart()
	if err != io.EOF {
		t.Fatalf("expected io.EOF after the single part, got %v", err)
	}
}

// TestRawMultipartReader_NestedBoundarySharedPrefix reproduces
// reviewer repro (2): an outer boundary "MIX" and an inner
// (nested-multipart) boundary "MIXa" sharing a prefix must not be
// confused for one another when reading raw, undecoded bytes — the
// inner boundary lines must not be treated as delimiters of the outer
// part, and vice versa.
func TestRawMultipartReader_NestedBoundarySharedPrefix(t *testing.T) {
	// Outer body: one part whose Content-Type is itself
	// multipart/mixed with boundary "MIXa", nested inside outer
	// boundary "MIX".
	raw := "--MIX\r\n" +
		"Content-Type: multipart/mixed; boundary=\"MIXa\"\r\n" +
		"\r\n" +
		"--MIXa\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"inner part 1\r\n" +
		"--MIXa\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"inner part 2\r\n" +
		"--MIXa--\r\n" +
		"--MIX--\r\n"

	outer := newRawMultipartReader(bytes.NewReader([]byte(raw)), "MIX")
	outerPart, err := outer.NextPart()
	if err != nil {
		t.Fatalf("outer NextPart: %v", err)
	}

	// The outer part's raw body must contain the FULL nested
	// multipart/mixed structure (both inner parts and the inner
	// closing delimiter), not be cut short at "--MIXa" (which shares
	// "--MIX" as a prefix).
	outerBody, err := io.ReadAll(outerPart.Body)
	if err != nil {
		t.Fatalf("read outer body: %v", err)
	}

	inner := newRawMultipartReader(bytes.NewReader(outerBody), "MIXa")
	var innerBodies []string
	for {
		p, err := inner.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("inner NextPart: %v (outer body was %q)", err, outerBody)
		}
		b, err := io.ReadAll(p.Body)
		if err != nil {
			t.Fatalf("read inner body: %v", err)
		}
		innerBodies = append(innerBodies, string(b))
	}

	want := []string{"inner part 1", "inner part 2"}
	if len(innerBodies) != len(want) {
		t.Fatalf("got %d inner parts %q, want %d %q", len(innerBodies), innerBodies, len(want), want)
	}
	for i := range want {
		if innerBodies[i] != want[i] {
			t.Errorf("inner part %d = %q, want %q", i, innerBodies[i], want[i])
		}
	}

	_, err = outer.NextPart()
	if err != io.EOF {
		t.Fatalf("expected io.EOF after the single outer part, got %v", err)
	}
}

// TestRawMultipartReader_TransportPadding reproduces reviewer repro
// (c): RFC 2046 §5.1.1 permits transport-padding (LWS) after a
// dash-boundary or close-delimiter before the line's CRLF; such
// padding must still be recognized as a real delimiter.
func TestRawMultipartReader_TransportPadding(t *testing.T) {
	raw := "--b \r\n" + // delimiter with trailing space padding
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"hello\r\n" +
		"--b--  \r\n" // close-delimiter with trailing space padding

	rmr := newRawMultipartReader(bytes.NewReader([]byte(raw)), "b")
	part, err := rmr.NextPart()
	if err != nil {
		t.Fatalf("NextPart: %v", err)
	}
	body, err := io.ReadAll(part.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want %q", body, "hello")
	}

	_, err = rmr.NextPart()
	if err != io.EOF {
		t.Fatalf("expected io.EOF (close-delimiter with padding should still close the body), got %v", err)
	}
}
