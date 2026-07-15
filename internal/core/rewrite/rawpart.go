package rewrite

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/textproto"
)

// rawPart is one part read by rawMultipartReader: its header block and
// body exactly as they appeared on the wire (still
// Content-Transfer-Encoding-encoded, not decoded), so a caller that
// only wants to forward the part untouched (a `pass` decision, US-3.2)
// can copy HeaderBytes and Body verbatim without any risk of a
// decode/re-encode round trip changing a single byte.
type rawPart struct {
	// HeaderBytes is the exact bytes of the part's header block,
	// including the terminating CRLF CRLF (or LF LF) before the body,
	// as they appeared in the input.
	HeaderBytes []byte

	// Header is HeaderBytes parsed via textproto, for callers that
	// need to inspect Content-Type/Content-Disposition/etc. to make a
	// routing decision. It is derived information, not used when
	// re-emitting the part (HeaderBytes is used for that instead) so
	// that canonicalization performed by textproto never affects what
	// is written out for a `pass` part.
	Header textproto.MIMEHeader

	// Body streams the part's raw, still-encoded body bytes, up to
	// (not including) the boundary line that follows it. It must be
	// fully read (or discarded via io.Copy(io.Discard, ...)) before
	// advancing the rawMultipartReader to the next part.
	Body io.Reader
}

// rawMultipartReader splits a multipart body into its constituent
// parts without decoding anything, unlike mime/multipart.Reader
// (which transparently decodes a quoted-printable
// Content-Transfer-Encoding — see mime/multipart.Part.Read). US-3.2's
// byte-for-byte requirement for `pass` attachments means rewrite
// cannot use mime/multipart.Reader for body content it intends to
// re-emit unmodified: decoding quoted-printable and writing it back
// out verbatim would not reproduce the original bytes (the original
// encoding is lost) or would require re-encoding (forbidden: pass-through
// parts must stay byte-identical).
type rawMultipartReader struct {
	r        *bufio.Reader
	boundary []byte
	done     bool

	// boundaryConsumed is set once the boundary line that separates
	// two parts has already been read from r (by the previous part's
	// partBody detecting it while looking for end-of-body), so the
	// next NextPart call must not search for another boundary line
	// before reading the next part's header — that boundary is
	// already behind us.
	boundaryConsumed bool
}

// newRawMultipartReader creates a rawMultipartReader over body, which
// must be positioned at the start of a multipart body (i.e.
// immediately before the first boundary line).
func newRawMultipartReader(body io.Reader, boundary string) *rawMultipartReader {
	return &rawMultipartReader{
		r:        bufio.NewReaderSize(body, 32*1024),
		boundary: []byte("--" + boundary),
	}
}

// boundaryLineKind classifies a candidate line against a "--boundary"
// prefix per RFC 2046 §5.1.1's dash-boundary/close-delimiter grammar.
type boundaryLineKind int

const (
	// notBoundary: the line is ordinary body content. This includes
	// the case where the line merely starts with the same bytes as
	// the boundary but continues with something other than optional
	// linear whitespace (LWS) or a close-delimiter "--" — e.g. a body
	// line "--because I said so" against boundary "b", or a nested
	// part's boundary "MIXa" being mistaken for a match against outer
	// boundary "MIX".
	notBoundary boundaryLineKind = iota
	// delimiter: "--boundary" followed by only LWS (tab/space) to end
	// of line — a normal part delimiter.
	delimiter
	// closeDelimiter: "--boundary--" followed by only LWS to end of
	// line — the final delimiter closing the multipart body.
	closeDelimiter
)

// classifyBoundaryLine reports what kind of boundary line (if any)
// trimmed is, given dashBoundary (== "--"+the declared boundary
// parameter, with no trailing CRLF). Per RFC 2046 §5.1.1:
//
//	dash-boundary := "--" boundary
//	delimiter     := CRLF dash-boundary
//	close-delimiter := delimiter "--"
//	transport-padding := *LWS
//
// After the dash-boundary (or close-delimiter's extra "--"), only
// transport-padding (spaces/tabs) may follow before the line ends —
// anything else means this line is body content that merely happens
// to share the boundary string's prefix, not an actual delimiter.
// This is essential when one MIME part's boundary is a prefix of
// another's (a common real-world pattern, e.g. "----=_Part_0" and
// "----=_Part_1" sharing "----=_Part_", or a nested envelope
// deliberately naming its boundary "MIXa" against an outer "MIX").
func classifyBoundaryLine(trimmed, dashBoundary []byte) boundaryLineKind {
	if !bytes.HasPrefix(trimmed, dashBoundary) {
		return notBoundary
	}
	rest := trimmed[len(dashBoundary):]

	if isTransportPadding(rest) {
		return delimiter
	}
	if bytes.HasPrefix(rest, []byte("--")) && isTransportPadding(rest[2:]) {
		return closeDelimiter
	}
	return notBoundary
}

// isTransportPadding reports whether b consists solely of RFC 2046
// "transport-padding" (spaces and/or tabs), including the empty
// string.
func isTransportPadding(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' {
			return false
		}
	}
	return true
}

// NextPart advances to and returns the next part, or io.EOF once the
// closing boundary has been consumed.
func (r *rawMultipartReader) NextPart() (*rawPart, error) {
	if r.done {
		return nil, io.EOF
	}

	if r.boundaryConsumed {
		// The previous part's partBody already read the boundary
		// line that precedes this part while detecting its own
		// end-of-body; searching for another one here would consume
		// this part's header instead.
		r.boundaryConsumed = false
	} else if err := r.skipToBoundary(); err != nil {
		return nil, err
	}
	if r.done {
		return nil, io.EOF
	}

	headerBytes, header, err := r.readHeader()
	if err != nil {
		return nil, err
	}

	pb := &partBody{r: r}
	return &rawPart{HeaderBytes: headerBytes, Header: header, Body: pb}, nil
}

// skipToBoundary reads and discards lines up to and including the
// next boundary line, setting r.done if it is the closing boundary
// ("--boundary--"). On the very first call it also discards any
// preamble text before the first boundary, matching
// mime/multipart.Reader's own behavior.
func (r *rawMultipartReader) skipToBoundary() error {
	for {
		line, err := r.r.ReadSlice('\n')
		if err != nil && len(line) == 0 {
			if err == io.EOF {
				return fmt.Errorf("rewrite: rawMultipartReader: unexpected EOF looking for boundary")
			}
			return fmt.Errorf("rewrite: rawMultipartReader: read line: %w", err)
		}

		trimmed := bytes.TrimRight(line, "\r\n")
		if kind := classifyBoundaryLine(trimmed, r.boundary); kind != notBoundary {
			r.done = kind == closeDelimiter
			return nil
		}

		if err == io.EOF {
			return fmt.Errorf("rewrite: rawMultipartReader: unexpected EOF looking for boundary")
		}
	}
}

// readHeader reads a part's header block (up to and including the
// blank line separating headers from body), returning both the exact
// bytes read and the textproto-parsed form.
func (r *rawMultipartReader) readHeader() ([]byte, textproto.MIMEHeader, error) {
	var buf bytes.Buffer
	for {
		line, err := r.r.ReadSlice('\n')
		if err != nil && len(line) == 0 {
			return nil, nil, fmt.Errorf("rewrite: rawMultipartReader: read header: %w", err)
		}
		buf.Write(line)

		if isBlankLine(line) {
			break
		}
		if err == io.EOF {
			break
		}
	}

	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	header, err := tp.ReadMIMEHeader()
	if err != nil && !isEOFAfterHeaders(err) {
		return nil, nil, fmt.Errorf("rewrite: rawMultipartReader: parse header: %w", err)
	}
	if header == nil {
		header = textproto.MIMEHeader{}
	}
	return buf.Bytes(), header, nil
}

// isEOFAfterHeaders reports whether err is the harmless "EOF"
// textproto.ReadMIMEHeader returns when the header block it was given
// has no trailing data after the blank line (our buffer contains
// exactly the header block, nothing more).
func isEOFAfterHeaders(err error) bool {
	return err == io.EOF
}

// isBlankLine reports whether line (including its line terminator) is
// an empty line, i.e. "\n" or "\r\n".
func isBlankLine(line []byte) bool {
	trimmed := bytes.TrimRight(line, "\r\n")
	return len(trimmed) == 0
}

// partBody is the io.Reader returned as rawPart.Body: it streams raw
// bytes from the underlying rawMultipartReader up to (not including)
// the next boundary line, without buffering the whole part in memory.
//
// Per RFC 2046 §5.1, the line break immediately preceding a boundary
// delimiter is considered part of the delimiter, not the body content
// (a body that ends exactly at the boundary with no trailing newline
// of its own is indistinguishable, on the wire, from one whose last
// content line ends in a newline that "belongs" to the boundary).
// partBody therefore holds back one pending line at a time: it only
// releases a line to the caller once it has confirmed the *next* line
// is not a boundary, and strips the held-back line's own trailing
// CRLF when the line that follows turns out to be the boundary.
type partBody struct {
	r       *rawMultipartReader
	pending []byte // a content line read but not yet confirmed non-final
	out     []byte // bytes ready to be copied out via Read
	atEOF   bool
}

func (pb *partBody) Read(p []byte) (int, error) {
	for len(pb.out) == 0 && !pb.atEOF {
		if err := pb.fill(); err != nil {
			return 0, err
		}
	}
	if len(pb.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, pb.out)
	pb.out = pb.out[n:]
	return n, nil
}

// fill reads one more line from the underlying reader and resolves
// the previously pending line: if the new line is a boundary, the
// pending line's trailing CRLF is stripped before being released and
// atEOF is set; otherwise the pending line is released verbatim and
// the new line becomes pending in its place.
func (pb *partBody) fill() error {
	line, err := pb.r.r.ReadSlice('\n')
	if err != nil && len(line) == 0 {
		if err == io.EOF {
			return fmt.Errorf("rewrite: rawMultipartReader: unexpected EOF in part body")
		}
		return fmt.Errorf("rewrite: rawMultipartReader: read body line: %w", err)
	}
	// ReadSlice aliases the bufio.Reader's internal buffer, which is
	// invalidated by the next read call; copy it since pending/out may
	// outlive the next fill().
	lineCopy := append([]byte(nil), line...)

	trimmed := bytes.TrimRight(lineCopy, "\r\n")
	kind := classifyBoundaryLine(trimmed, pb.r.boundary)

	if kind != notBoundary {
		if kind == closeDelimiter {
			pb.r.done = true
		}
		pb.r.boundaryConsumed = true
		pb.out = append(pb.out, stripTrailingCRLF(pb.pending)...)
		pb.pending = nil
		pb.atEOF = true
		return nil
	}

	if pb.pending != nil {
		pb.out = append(pb.out, pb.pending...)
	}
	pb.pending = lineCopy

	if err == io.EOF {
		// Input ended without a closing boundary line at all; flush
		// the pending line as-is (best effort — a genuinely malformed
		// or truncated message either way).
		pb.out = append(pb.out, pb.pending...)
		pb.pending = nil
		pb.atEOF = true
	}
	return nil
}

// stripTrailingCRLF removes one trailing "\r\n" or "\n" from line, if
// present.
func stripTrailingCRLF(line []byte) []byte {
	if bytes.HasSuffix(line, []byte("\r\n")) {
		return line[:len(line)-2]
	}
	if bytes.HasSuffix(line, []byte("\n")) {
		return line[:len(line)-1]
	}
	return line
}
