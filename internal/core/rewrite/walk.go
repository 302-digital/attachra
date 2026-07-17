package rewrite

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/302-digital/attachra/internal/core/policy"
)

// textprotoHeader is a small alias to keep rewrite.go's signatures
// readable without importing net/textproto there directly.
type textprotoHeader = textproto.MIMEHeader

// parseHeaderBlock parses a raw header block (header lines plus their
// terminating blank line) via textproto, matching the same parsing
// rules internal/core/message relies on for interpreting
// Content-Type/Content-Disposition/etc.
func parseHeaderBlock(raw []byte) (textprotoHeader, error) {
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	header, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, err
	}
	if header == nil {
		header = textproto.MIMEHeader{}
	}
	return header, nil
}

// rewriteMultipart re-emits a multipart body read from br (raw,
// undecoded) to dst, recursing into each child part per its own
// Content-Type, looking up ActionReplace/ActionPass decisions by
// PartPath (dotted index notation matching internal/core/message's
// convention). It re-emits the boundary delimiter lines itself (the
// underlying rawMultipartReader consumes but does not forward them),
// using the same boundary string the original message declared, and
// injects the replacement block as a new multipart/alternative
// sibling if descending never found an existing text/plain or
// text/html leaf to append it to (see rewriteLeaf).
// topLevel reports whether this call's output is written directly to
// Rewrite's final output (true) rather than being embedded as the
// body of some enclosing part — a nested multipart/* child, a
// message/rfc822 envelope's own body, or the synthesized
// attachra-block-* alternative part (false). It is threaded through so
// the boundaryWriter constructed here knows whether its own closing
// delimiter owns the message's final trailing CRLF; see
// boundaryWriter.finalCRLF's doc comment for why getting this wrong
// corrupts the message.
func (rw *rewriter) rewriteMultipart(br *bufio.Reader, dst io.Writer, boundary, partPath string, topLevel bool) error {
	if boundary == "" {
		return fmt.Errorf("rewrite: part %q: multipart Content-Type missing boundary parameter", partPath)
	}

	rmr := newRawMultipartReader(br, boundary)
	bw := &boundaryWriter{dst: dst, boundary: boundary, finalCRLF: topLevel}

	for i := 1; ; i++ {
		part, err := rmr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("rewrite: part %q: read child %d: %w", partPath, i, err)
		}

		childPath := partPath + "." + strconv.Itoa(i)
		contentType := part.Header.Get("Content-Type")
		mediaType, params, ctErr := mime.ParseMediaType(contentType)
		if ctErr != nil {
			mediaType = "text/plain"
			params = map[string]string{}
		}

		// The boundary line for this slot is only emitted once we
		// know the part actually produces output: a dropped
		// (ActionReplace) leaf must not leave a dangling boundary
		// line with no part after it.
		var buf bytes.Buffer

		switch {
		case strings.HasPrefix(mediaType, "multipart/"):
			if _, err := buf.Write(part.HeaderBytes); err != nil {
				return fmt.Errorf("rewrite: part %q: write header: %w", childPath, err)
			}
			if err := rw.rewriteMultipart(bufio.NewReaderSize(part.Body, 32*1024), &buf, params["boundary"], childPath, false); err != nil {
				return err
			}
			if err := bw.writePart(buf.Bytes()); err != nil {
				return err
			}

		case mediaType == "message/rfc822":
			// Recurse into the forwarded/embedded message's own
			// envelope, continuing the same dotted PartPath
			// (matching internal/core/message's walkNestedMessage),
			// so a replace decision targeting a leaf inside a
			// forwarded message is still honored.
			if _, err := buf.Write(part.HeaderBytes); err != nil {
				return fmt.Errorf("rewrite: part %q: write header: %w", childPath, err)
			}
			if err := rw.rewriteNestedMessage(part.Body, &buf, childPath); err != nil {
				return err
			}
			if err := bw.writePart(buf.Bytes()); err != nil {
				return err
			}

		default:
			wrote, err := rw.rewriteLeaf(&buf, part, mediaType, childPath)
			if err != nil {
				return err
			}
			if wrote {
				if err := bw.writePart(buf.Bytes()); err != nil {
					return err
				}
			}
		}
	}

	if !rw.blockInjected {
		if err := rw.appendFallbackAlternativePart(bw); err != nil {
			return err
		}
	}

	if err := bw.writeClosing(); err != nil {
		return fmt.Errorf("rewrite: part %q: write closing boundary: %w", partPath, err)
	}
	return nil
}

// boundaryWriter emits a multipart body's boundary delimiter lines
// correctly per RFC 2046 §5.1: the CRLF immediately before a boundary
// line belongs to the delimiter, not to the preceding part's body, so
// every delimiter line after the first is preceded by its own "\r\n"
// rather than each part supplying a trailing one itself (parts here
// never carry a trailing CRLF of their own — see partBody's handling
// of the pending line in rawpart.go).
type boundaryWriter struct {
	dst      io.Writer
	boundary string
	wroteAny bool

	// finalCRLF controls whether writeClosing appends a trailing CRLF
	// after the closing "--boundary--" delimiter it writes.
	//
	// This must be true only for a boundaryWriter whose output is
	// written directly to Rewrite's final output — the truly
	// outermost multipart structure of the entire rewritten message
	// (rw.run's top-level rewriteMultipart call, topLevel=true) and
	// rewriteTopLevelSinglePart's synthesized wrapper — matching every
	// fixture in internal/core/message/testdata, which all end with a
	// single trailing CRLF after the top-level closing delimiter.
	//
	// It must be false for every other boundaryWriter: a nested
	// multipart/* child (rewriteMultipart's own recursion), a
	// message/rfc822 envelope's own body (rewriteNestedMessage), or
	// the synthesized attachra-block-* alternative part
	// (appendFallbackAlternativePart). All of these write into a
	// buffer that becomes the *body* of some enclosing part, written
	// out via that enclosing boundaryWriter's own writePart. Per RFC
	// 2046 §5.1, the CRLF that would follow such a closing delimiter
	// is not this boundary's own to give — it is supplied by whatever
	// comes next in the enclosing structure (the next sibling's own
	// leading "\r\n--boundary" prefix, or, transitively, the outermost
	// writeClosing's own final CRLF). Setting this true unconditionally
	// duplicated that CRLF, corrupting every nested-multipart message
	// with a spurious blank line before each nested closing delimiter
	// — the exact defect ATR-235's round-trip corpus test
	// (roundtrip_test.go) was written to catch, and did.
	finalCRLF bool
}

// writePart writes the delimiter line for the next part slot (with a
// leading "\r\n" unless this is the first part written) followed by
// partBytes.
func (bw *boundaryWriter) writePart(partBytes []byte) error {
	prefix := "--"
	if bw.wroteAny {
		prefix = "\r\n--"
	}
	if _, err := fmt.Fprintf(bw.dst, "%s%s\r\n", prefix, bw.boundary); err != nil {
		return fmt.Errorf("rewrite: write boundary: %w", err)
	}
	if _, err := bw.dst.Write(partBytes); err != nil {
		return fmt.Errorf("rewrite: write part: %w", err)
	}
	bw.wroteAny = true
	return nil
}

// writeClosing writes the closing "--boundary--" delimiter, followed
// by a trailing CRLF only if bw.finalCRLF is set (see its doc
// comment).
func (bw *boundaryWriter) writeClosing() error {
	prefix := "--"
	if bw.wroteAny {
		prefix = "\r\n--"
	}
	suffix := ""
	if bw.finalCRLF {
		suffix = "\r\n"
	}
	if _, err := fmt.Fprintf(bw.dst, "%s%s--%s", prefix, bw.boundary, suffix); err != nil {
		return fmt.Errorf("rewrite: write closing boundary: %w", err)
	}
	return nil
}

// rewriteLeaf handles a single leaf MIME part: pass parts are copied
// byte-for-byte; parts decided ActionReplace are dropped; the
// message's primary text/plain and text/html body parts (identified
// by media type, matched only once each — the first text/plain and
// first text/html leaf encountered with no policy decision of their
// own, since internal/core/message classifies inline body parts as
// DispositionInline and callers are not expected to submit those to
// policy.Evaluate) get the replacement block appended to their body.
// It reports whether anything was written to dst (false only for a
// dropped ActionReplace part), so the caller knows whether to emit
// this slot's boundary delimiter line.
func (rw *rewriter) rewriteLeaf(dst io.Writer, part *rawPart, mediaType, partPath string) (bool, error) {
	decision, hasDecision := rw.decisionByPath[partPath]

	if hasDecision && decision.Action == policy.ActionReplace {
		// Drop the part entirely: no header, no body written.
		if _, err := io.Copy(io.Discard, part.Body); err != nil {
			return false, fmt.Errorf("rewrite: part %q: drain dropped body: %w", partPath, err)
		}
		return false, nil
	}

	wantsPlain := mediaType == "text/plain" && !hasDecision && !rw.plainAppended
	wantsHTML := mediaType == "text/html" && !hasDecision && !rw.htmlAppended

	if !wantsPlain && !wantsHTML {
		// Ordinary pass-through: copy header and body verbatim, no
		// decode/re-encode (US-3.2: pass-through parts must stay byte-identical).
		if _, err := dst.Write(part.HeaderBytes); err != nil {
			return false, fmt.Errorf("rewrite: part %q: write header: %w", partPath, err)
		}
		if _, err := io.Copy(dst, part.Body); err != nil {
			return false, fmt.Errorf("rewrite: part %q: copy body: %w", partPath, err)
		}
		return true, nil
	}

	bodyBytes, err := io.ReadAll(part.Body)
	if err != nil {
		return false, fmt.Errorf("rewrite: part %q: read body for block append: %w", partPath, err)
	}

	appended, err := appendBlockToBody(bodyBytes, part.Header, wantsHTML, rw.plainBlock, rw.htmlBlock)
	if err != nil {
		return false, fmt.Errorf("rewrite: part %q: append block: %w", partPath, err)
	}

	if _, err := dst.Write(part.HeaderBytes); err != nil {
		return false, fmt.Errorf("rewrite: part %q: write header: %w", partPath, err)
	}
	if _, err := dst.Write(appended); err != nil {
		return false, fmt.Errorf("rewrite: part %q: write appended body: %w", partPath, err)
	}

	rw.blockInjected = true
	if wantsHTML {
		rw.htmlAppended = true
	} else {
		rw.plainAppended = true
	}
	return true, nil
}

// rewriteNestedMessage rewrites the envelope of a message/rfc822 part:
// its own header block plus recursively-rewritten body, continuing
// the same partPath (no ".N" suffix added, matching
// internal/core/message.walkNestedMessage).
func (rw *rewriter) rewriteNestedMessage(body io.Reader, dst io.Writer, partPath string) error {
	br := bufio.NewReaderSize(body, 32*1024)
	headerBytes, header, err := readRawHeader(br)
	if err != nil {
		return fmt.Errorf("rewrite: part %q: read nested message header: %w", partPath, err)
	}
	if _, err := dst.Write(headerBytes); err != nil {
		return fmt.Errorf("rewrite: part %q: write nested message header: %w", partPath, err)
	}

	mediaType, params, ctErr := mime.ParseMediaType(header.Get("Content-Type"))
	if ctErr != nil {
		mediaType = "text/plain"
		params = map[string]string{}
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		// The nested envelope's own multipart body is embedded as this
		// leaf's content within the outer structure, not written
		// directly to Rewrite's final output, so it must not own a
		// final trailing CRLF either (see boundaryWriter.finalCRLF's
		// doc comment; internal/core/message/testdata/nested_message_rfc822.eml
		// confirms real messages have no blank line between a nested
		// envelope's own closing delimiter and the outer envelope's
		// next boundary).
		return rw.rewriteMultipart(br, dst, params["boundary"], partPath, false)
	}

	// A non-multipart nested message: its single body is one leaf at
	// partPath itself (not partPath+".1"), matching
	// internal/core/message's convention. Reuse rewriteLeaf's logic
	// via a synthetic rawPart wrapping the remaining reader.
	rest, err := io.ReadAll(br)
	if err != nil {
		return fmt.Errorf("rewrite: part %q: read nested single-part body: %w", partPath, err)
	}
	synthetic := &rawPart{HeaderBytes: nil, Header: header, Body: bytes.NewReader(rest)}
	_, err = rw.rewriteLeaf(dst, synthetic, mediaType, partPath)
	return err
}

// appendFallbackAlternativePart adds a brand-new multipart/alternative
// child part (text/plain + text/html) to the multipart body bw is
// writing, containing only the replacement block. It is used when the
// message's body has no existing text/plain or text/html leaf for
// rewriteLeaf to append into (e.g. an attachment-only message, or a
// body encoded as something rewrite does not specially recognize).
func (rw *rewriter) appendFallbackAlternativePart(bw *boundaryWriter) error {
	innerBoundary := "attachra-block-" + bw.boundary

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", innerBoundary)

	inner := &boundaryWriter{dst: &buf, boundary: innerBoundary}
	if err := inner.writePart([]byte(fmt.Sprintf("Content-Type: text/plain; charset=utf-8\r\n\r\n%s", strings.TrimSuffix(rw.plainBlock, "\r\n")))); err != nil {
		return err
	}
	if err := inner.writePart([]byte(fmt.Sprintf("Content-Type: text/html; charset=utf-8\r\n\r\n%s", strings.TrimSuffix(rw.htmlBlock, "\r\n")))); err != nil {
		return err
	}
	if err := inner.writeClosing(); err != nil {
		return err
	}

	if err := bw.writePart(buf.Bytes()); err != nil {
		return fmt.Errorf("rewrite: write fallback alternative part: %w", err)
	}

	rw.blockInjected = true
	rw.plainAppended = true
	rw.htmlAppended = true
	return nil
}
