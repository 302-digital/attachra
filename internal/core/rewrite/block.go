package rewrite

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"strings"
	"time"
)

// BlockFile describes one replaced attachment as displayed in the
// replacement block's file listing (package-page-decision.md §4.1:
// the block lists file names as plain text, it does not link to them
// individually).
type BlockFile struct {
	// Name is the attachment's display file name (e.g.
	// message.Attachment.Filename). It is sanitized for CR/LF before
	// rendering (SR-118-1) regardless of any sanitization already
	// applied upstream, since this package must not assume its caller
	// did so.
	Name string
	// Size is the attachment's size in bytes, used to render
	// SizeHuman.
	Size int64
}

// blockFileView is the template-facing projection of BlockFile, with
// derived/sanitized fields precomputed so templates need no custom
// function map.
type blockFileView struct {
	Name      string
	SizeHuman string
}

// BlockData is the input to rendering the replacement block (both
// text/plain and HTML variants share the same data).
type BlockData struct {
	// Files lists the attachments removed from this message.
	Files []BlockFile

	// PackageURL is the single link to the package page for this
	// message (`/p/<message-link-token>`), supplied by the future
	// Link Engine (package-page-decision.md §4.1). Rewrite treats it
	// as an opaque, already-final URL string.
	PackageURL string

	// ExpiresAt, if non-zero, is rendered as a human-readable
	// expiry note. Zero suppresses that line.
	ExpiresAt time.Time

	// SenderName, if non-empty, is rendered as a "sent by" note.
	// Typically the envelope sender address or a display name
	// extracted from the From header; either way it is
	// attacker-controlled message content and is sanitized before
	// rendering (SR-118-1).
	SenderName string
}

// blockView is the template-facing projection of BlockData.
type blockView struct {
	Files      []blockFileView
	PackageURL string
	ExpiresAt  string
	SenderName string
}

// toView sanitizes and derives the template-facing fields from data.
// Every field that can contain attacker-controlled message content
// (file names, sender name) is passed through sanitizeHeaderValue
// (SR-118-1) even though the block is body content rather than a
// header, since a raw CR/LF here could still be used to forge
// additional lines in the text/plain rendering of the message body
// that a careless downstream reader (e.g. a header-scraping tool)
// might misinterpret as header-like content.
func (d BlockData) toView() blockView {
	files := make([]blockFileView, len(d.Files))
	for i, f := range d.Files {
		files[i] = blockFileView{
			Name:      sanitizeHeaderValue(f.Name),
			SizeHuman: humanSize(f.Size),
		}
	}

	view := blockView{
		Files:      files,
		PackageURL: sanitizeHeaderValue(d.PackageURL),
		SenderName: sanitizeHeaderValue(d.SenderName),
	}
	if !d.ExpiresAt.IsZero() {
		view.ExpiresAt = d.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	return view
}

// humanSize renders n bytes as a short human-readable size (e.g.
// "1.5 MB"), using decimal (1000-based) units to match how file sizes
// are commonly presented to end users in mail/download contexts.
func humanSize(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	units := []string{"kB", "MB", "GB", "TB", "PB"}
	if exp >= len(units) {
		exp = len(units) - 1
	}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), units[exp])
}

// renderBlock renders both the text/plain and HTML variants of the
// replacement block for data using tmpl, returning the plain text and
// HTML strings respectively. It never returns partially-rendered
// output: if either template execution fails, both are discarded and
// the error is returned so the caller does not embed a broken block.
func renderBlock(tmpl *Templates, data BlockData) (plainText string, html string, err error) {
	view := data.toView()

	var textBuf bytes.Buffer
	if execErr := tmpl.text.Execute(&textBuf, view); execErr != nil {
		return "", "", fmt.Errorf("rewrite: render text block: %w", execErr)
	}

	var htmlBuf bytes.Buffer
	if execErr := tmpl.html.Execute(&htmlBuf, view); execErr != nil {
		return "", "", fmt.Errorf("rewrite: render html block: %w", execErr)
	}

	return normalizeNewlines(textBuf.String()), htmlBuf.String(), nil
}

// appendBlockToBody appends block (rw.htmlBlock if useHTML, else
// rw.plainBlock) to a text/plain or text/html leaf part's raw body
// bytes, decoding and re-encoding the part's
// Content-Transfer-Encoding as needed. Unlike pass-through
// attachments, this leaf's content is intentionally being modified
// (the block is new content the message did not originally carry), so
// a decode/append/re-encode round trip here does not violate the
// "no re-encoding" requirement, which applies only to attachments
// forwarded unmodified.
func appendBlockToBody(rawBody []byte, header textprotoHeader, useHTML bool, plainBlock, htmlBlock string) ([]byte, error) {
	block := plainBlock
	if useHTML {
		block = htmlBlock
	}

	encoding := strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding")))

	decoded, err := decodeBody(rawBody, encoding)
	if err != nil {
		return nil, fmt.Errorf("decode body (encoding=%q): %w", encoding, err)
	}

	combined := append(append([]byte(nil), decoded...), []byte(block)...)

	return encodeBody(combined, encoding)
}

// decodeBody decodes rawBody per the given Content-Transfer-Encoding
// value ("base64" or "quoted-printable"; anything else, including
// empty, is treated as already-plain content).
func decodeBody(rawBody []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "base64":
		out := make([]byte, base64.StdEncoding.DecodedLen(len(rawBody)))
		n, err := base64.StdEncoding.Decode(out, stripBase64Whitespace(rawBody))
		if err != nil {
			return nil, err
		}
		return out[:n], nil
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(bytes.NewReader(rawBody)))
	default:
		return rawBody, nil
	}
}

// encodeBody re-encodes combined per the given Content-Transfer-Encoding
// value, mirroring decodeBody's cases, and CRLF-terminated lines
// (RFC 5322 §2.3) matching what mail clients expect on the wire.
func encodeBody(combined []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "base64":
		var buf bytes.Buffer
		enc := base64.NewEncoder(base64.StdEncoding, &lineWrapper{w: &buf, width: 76})
		if _, err := enc.Write(combined); err != nil {
			return nil, err
		}
		if err := enc.Close(); err != nil {
			return nil, err
		}
		buf.WriteString("\r\n")
		return buf.Bytes(), nil
	case "quoted-printable":
		var buf bytes.Buffer
		w := quotedprintable.NewWriter(&buf)
		if _, err := w.Write(combined); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return combined, nil
	}
}

// stripBase64Whitespace removes whitespace/newlines from base64
// input so base64.Decode (which does not tolerate embedded newlines)
// can process a body that was wrapped at 76 columns, as
// base64-encoded MIME bodies conventionally are.
func stripBase64Whitespace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			out = append(out, c)
		}
	}
	return out
}

// lineWrapper wraps base64 output at width columns with CRLF, the
// conventional line length for base64-encoded MIME body content.
type lineWrapper struct {
	w     *bytes.Buffer
	width int
	col   int
}

func (l *lineWrapper) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		space := l.width - l.col
		if space > len(p) {
			space = len(p)
		}
		l.w.Write(p[:space])
		l.col += space
		p = p[space:]
		if l.col == l.width {
			l.w.WriteString("\r\n")
			l.col = 0
		}
	}
	return n, nil
}

// normalizeNewlines rewrites the template output to canonical CRLF
// line endings as required for MIME body parts (RFC 5322 §2.3), since
// text/template execution and the source .tmpl files themselves use
// plain "\n".
func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}
