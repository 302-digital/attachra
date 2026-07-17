package message

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
)

// PartFunc is called once for every leaf MIME part discovered while
// walking a message (SR-117-3), in document order. att describes the
// part and may be mutated by the callback (e.g. to set DetectedType
// after sniffing body); body streams the part's decoded content (any
// Content-Transfer-Encoding such as base64 or quoted-printable has
// already been removed by mime/multipart).
//
// Implementations that need the real content type must read body (or
// a prefix of it) themselves and call DetectType; Parse does not read
// leaf bodies itself for detection, so callers fully control how much
// of a part they buffer for that purpose, keeping the walk itself
// allocation-free with respect to attachment content (the streaming
// invariant). After the callback returns, Parse drains any
// remaining unread bytes of body (so the underlying multipart reader
// can advance to the next part) and sets att.Size to the total number
// of body bytes observed, whether read by the callback or drained
// afterward.
//
// Returning a non-nil error aborts the walk; Parse returns that error
// wrapped with the offending part's path to the caller of Parse.
type PartFunc func(att *Attachment, body io.Reader) error

// walkState carries the mutable bookkeeping threaded through the
// recursive descent: the configured limits, counters shared across
// the whole message, and the callback to invoke per leaf part.
type walkState struct {
	limits     Limits
	fn         PartFunc
	partsSeen  int
	totalBytes int64
}

// Parse walks the MIME structure of the message read from r, invoking
// fn for every leaf part (inline or attachment), including leaves
// found by descending into nested message/rfc822 parts up to
// limits.MaxDepth (SR-117-3). It never buffers the message body as a
// whole: the top-level message is read via net/mail (which itself
// streams), and nested multipart bodies are walked incrementally via
// mime/multipart.Reader (the streaming invariant).
//
// Zero-valued fields in limits fall back to DefaultLimits (see
// Limits.normalized). Exceeding any configured limit returns a
// *LimitError; callers resolve that into their configured
// fail-open/fail-closed policy (the mail-must-never-be-lost invariant)
// rather than Parse deciding that policy itself.
func Parse(r io.Reader, limits Limits, fn PartFunc) error {
	limits = limits.normalized()

	msg, err := mail.ReadMessage(r)
	if err != nil {
		return fmt.Errorf("message: read top-level message: %w", err)
	}

	if err := checkHeaderCount(textproto.MIMEHeader(msg.Header), limits, "0"); err != nil {
		return err
	}

	st := &walkState{limits: limits, fn: fn}

	contentType := msg.Header.Get("Content-Type")
	disposition := msg.Header.Get("Content-Disposition")
	transferEncoding := msg.Header.Get("Content-Transfer-Encoding")
	contentID := msg.Header.Get("Content-ID")

	// The top-level part has no enclosing multipart container, so its
	// parentMediaType is "" — it can never itself be classified an
	// InlineAsset (ADR-016 requires a multipart/related parent).
	return st.walkPart(msg.Body, contentType, disposition, transferEncoding, contentID, "0", 0, "")
}

// walkPart processes a single MIME part body given its raw
// Content-Type, Content-Disposition, Content-Transfer-Encoding and
// Content-ID header values, dispatching to a multipart or
// message/rfc822 sub-walk when applicable, or invoking the leaf
// callback otherwise. parentMediaType is the media type of the
// immediately enclosing multipart container (e.g. "multipart/related"),
// or "" if this part is not inside any multipart container (the
// top-level part, or the root of a nested message/rfc822 envelope) —
// see emitLeaf's use of it for ADR-016's InlineAsset classification.
func (st *walkState) walkPart(body io.Reader, contentType, disposition, transferEncoding, contentID, partPath string, depth int, parentMediaType string) error {
	st.partsSeen++
	if st.partsSeen > st.limits.MaxParts {
		return newLimitError(LimitParts, partPath, int64(st.limits.MaxParts))
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Malformed or absent Content-Type defaults to text/plain,
		// matching RFC 2045 §5.2 and net/mail's own convention. This
		// is a lenient parse fallback, not a limit violation: the
		// message is still walked, just conservatively typed.
		mediaType = "text/plain"
		params = map[string]string{}
	}

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		return st.walkMultipart(body, params["boundary"], partPath, depth, mediaType)
	case mediaType == "message/rfc822":
		return st.walkNestedMessage(body, partPath, depth)
	default:
		return st.emitLeaf(body, mediaType, contentType, disposition, transferEncoding, contentID, partPath, parentMediaType)
	}
}

// walkMultipart reads each child part of a multipart body in turn and
// recurses into walkPart for each, enforcing depth and per-part
// header limits. mediaType is this multipart part's own media type
// (e.g. "multipart/related"), passed down as each child's
// parentMediaType.
func (st *walkState) walkMultipart(body io.Reader, boundary, partPath string, depth int, mediaType string) error {
	if boundary == "" {
		return fmt.Errorf("message: part %q: multipart Content-Type missing boundary parameter", partPath)
	}
	if depth+1 > st.limits.MaxDepth {
		return newLimitError(LimitDepth, partPath, int64(st.limits.MaxDepth))
	}

	mr := multipart.NewReader(body, boundary)

	for i := 1; ; i++ {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("message: part %q: read child part %d: %w", partPath, i, err)
		}

		childPath := partPath + "." + strconv.Itoa(i)

		if err := checkHeaderCount(part.Header, st.limits, childPath); err != nil {
			_ = part.Close()
			return err
		}

		childContentType := part.Header.Get("Content-Type")
		childDisposition := part.Header.Get("Content-Disposition")
		// mime/multipart already transparently decodes
		// quoted-printable bodies (see multipart.Reader.NextPart), so
		// that case is treated as "no further decoding needed" here;
		// base64 is not auto-decoded and must be handled in emitLeaf.
		childTransferEncoding := part.Header.Get("Content-Transfer-Encoding")
		childContentID := part.Header.Get("Content-ID")

		if err := st.walkPart(part, childContentType, childDisposition, childTransferEncoding, childContentID, childPath, depth+1, mediaType); err != nil {
			_ = part.Close()
			return err
		}

		if err := part.Close(); err != nil {
			return fmt.Errorf("message: part %q: close child part %d: %w", partPath, i, err)
		}
	}
}

// walkNestedMessage reads body as a full RFC 5322 message (a
// message/rfc822 part's payload) and recurses into its single body
// part, allowing further multipart nesting within it up to the
// remaining depth budget (SR-117-3). The nested envelope's own root
// part has no enclosing multipart container of its own (its
// parentMediaType resets to ""), matching the top-level Parse call.
func (st *walkState) walkNestedMessage(body io.Reader, partPath string, depth int) error {
	if depth+1 > st.limits.MaxDepth {
		return newLimitError(LimitDepth, partPath, int64(st.limits.MaxDepth))
	}

	nested, err := mail.ReadMessage(body)
	if err != nil {
		return fmt.Errorf("message: part %q: read nested message/rfc822: %w", partPath, err)
	}

	if err := checkHeaderCount(textproto.MIMEHeader(nested.Header), st.limits, partPath); err != nil {
		return err
	}

	contentType := nested.Header.Get("Content-Type")
	disposition := nested.Header.Get("Content-Disposition")
	transferEncoding := nested.Header.Get("Content-Transfer-Encoding")
	contentID := nested.Header.Get("Content-ID")

	return st.walkPart(nested.Body, contentType, disposition, transferEncoding, contentID, partPath, depth+1, "")
}

// emitLeaf builds the Attachment for a leaf part and invokes the
// caller's PartFunc with a size- and limit-tracking wrapper around
// body, then drains any bytes the callback left unread so the
// underlying multipart reader can advance to the next sibling part.
//
// mime/multipart transparently decodes a "quoted-printable"
// Content-Transfer-Encoding, but not "base64" (the other encoding
// commonly used for binary attachments), so base64 is decoded here;
// this keeps DetectType (magic-byte sniffing) and Size operating on
// the real decoded content rather than base64 text.
func (st *walkState) emitLeaf(body io.Reader, mediaType, rawContentType, disposition, transferEncoding, contentID, partPath string, parentMediaType string) error {
	att := Attachment{
		PartPath:     partPath,
		Filename:     extractFilename(disposition, rawContentType),
		DeclaredType: mediaType,
		Disposition:  classifyDisposition(disposition, mediaType),
		ContentID:    normalizeContentID(contentID),
	}
	// ADR-016: a part is a presentation-inline asset (e.g. a cid:
	// referenced logo/signature image) iff it carries a Content-ID AND
	// its immediate parent container is multipart/related. Neither
	// signal alone is reliable: Content-Disposition is not trustworthy
	// (some MUAs mark genuine downloadable attachments "inline"), and a
	// bare Content-ID with no multipart/related container does not
	// establish the RFC 2387 embedding relationship.
	att.InlineAsset = att.ContentID != "" && parentMediaType == "multipart/related"

	decoded := decodeTransferEncoding(body, transferEncoding)

	counted := &limitedCountingReader{
		r:         decoded,
		partPath:  partPath,
		partLimit: st.limits.MaxPartSize,
		state:     st,
	}

	if err := st.fn(&att, counted); err != nil {
		return fmt.Errorf("message: part %q: %w", partPath, err)
	}

	if _, err := io.Copy(io.Discard, counted); err != nil {
		return fmt.Errorf("message: part %q: drain body: %w", partPath, err)
	}

	att.Size = counted.partRead
	return nil
}

// decodeTransferEncoding wraps body with a streaming decoder matching
// the given Content-Transfer-Encoding value, so leaf content handed to
// PartFunc is always the real decoded bytes rather than their wire
// encoding. "quoted-printable" is already decoded transparently by
// mime/multipart.Part.Read and is passed through unchanged here;
// "7bit", "8bit", "binary" and an absent/unrecognized value need no
// transformation. Decoding is itself streaming (base64.NewDecoder
// wraps body without buffering it), preserving the streaming invariant.
func decodeTransferEncoding(body io.Reader, transferEncoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(transferEncoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, body)
	default:
		return body
	}
}

// classifyDisposition derives Disposition from a raw
// Content-Disposition header value, defaulting to Attachment for any
// leaf part that is not explicitly marked inline: this favors never
// missing a possible exfiltration path (SR-117-3 requires visiting
// every leaf) over guessing intent from content type.
func classifyDisposition(rawDisposition, mediaType string) Disposition {
	dtype, _, err := mime.ParseMediaType(rawDisposition)
	if err != nil {
		dtype = ""
	}
	dtype = strings.ToLower(strings.TrimSpace(dtype))

	switch dtype {
	case "inline":
		return DispositionInline
	case "attachment":
		return DispositionAttachment
	default:
		// No explicit disposition: text/plain and text/html are
		// conventionally the primary displayed body, everything else
		// defaults to attachment so it is not silently skipped by
		// policy evaluation.
		if mediaType == "text/plain" || mediaType == "text/html" {
			return DispositionInline
		}
		return DispositionAttachment
	}
}

// normalizeContentID strips the angle brackets a Content-ID header
// value is conventionally wrapped in (RFC 2045 §7; the same bare
// identifier is what a `cid:` URL per RFC 2392 references) along with
// any surrounding whitespace, returning "" when the header was absent
// or empty after normalization.
func normalizeContentID(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return strings.TrimSpace(s)
}

// checkHeaderCount enforces limits.MaxHeaders (SR-117-2) against a
// part's (or the top-level message's) header set.
func checkHeaderCount(h textproto.MIMEHeader, limits Limits, partPath string) error {
	count := 0
	for _, values := range h {
		count += len(values)
	}
	if count > limits.MaxHeaders {
		return newLimitError(LimitHeaders, partPath, int64(limits.MaxHeaders))
	}
	return nil
}

// limitedCountingReader wraps a part's body reader to enforce
// per-part and total message size limits (SR-117-2) as bytes are
// read, whether by the PartFunc callback or by emitLeaf's post-callback
// drain, and to accumulate the byte count emitLeaf later assigns to
// Attachment.Size.
type limitedCountingReader struct {
	r         io.Reader
	partPath  string
	partLimit int64
	partRead  int64
	state     *walkState
}

func (lr *limitedCountingReader) Read(p []byte) (int, error) {
	n, err := lr.r.Read(p)
	if n > 0 {
		lr.partRead += int64(n)
		lr.state.totalBytes += int64(n)

		if lr.partRead > lr.partLimit {
			return n, newLimitError(LimitPartSize, lr.partPath, lr.partLimit)
		}
		if lr.state.totalBytes > lr.state.limits.MaxTotalSize {
			return n, newLimitError(LimitTotalSize, "", lr.state.limits.MaxTotalSize)
		}
	}
	return n, err
}
