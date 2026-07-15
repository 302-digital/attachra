package message

// Disposition classifies how a MIME part is meant to be presented,
// derived from its Content-Disposition header (defaulting to Attachment
// when the header is absent but the part is otherwise a leaf part
// with a filename, and to Inline for parts with no filename that are
// not the primary displayable body).
type Disposition string

// Recognized Disposition values.
const (
	// DispositionInline marks a part meant to be rendered inline
	// (e.g. an image referenced from HTML body via Content-ID, or a
	// text/plain or text/html primary body part).
	DispositionInline Disposition = "inline"
	// DispositionAttachment marks a part meant to be offered as a
	// downloadable attachment.
	DispositionAttachment Disposition = "attachment"
)

// Attachment describes a single leaf MIME part discovered while
// walking a message (SR-117-3: every leaf part is visited, inline or
// attachment). It intentionally does not embed the part's raw bytes;
// callers read the body from the Reader supplied to their PartFunc
// callback so the message is never buffered whole in memory.
type Attachment struct {
	// PartPath identifies the part's position in the MIME tree using
	// dotted 1-based indices, e.g. "2.1" is the first child of the
	// second top-level part. A part reached by descending into a
	// message/rfc822 envelope continues the same dotted path through
	// the envelope's single body part.
	PartPath string

	// Filename is the decoded, sanitized attachment file name (see
	// SR-117-5 / T-3.1.3), derived from Content-Disposition's
	// "filename" parameter or, failing that, Content-Type's "name"
	// parameter. Empty if the part carries no name at all.
	Filename string

	// DeclaredType is the MIME type as declared by the message's
	// Content-Type header for this part (lower-cased, parameters
	// stripped), e.g. "application/pdf". Empty Content-Type defaults
	// to "text/plain" per RFC 2045 §5.2, matching net/mail semantics.
	DeclaredType string

	// DetectedType is the real content type as detected from the
	// part's leading bytes (magic bytes), independent of what the
	// message declared (SR-117-4). It is populated by callers using
	// package-level DetectType against the bytes they read from the
	// part; Parse itself does not read part bodies for content
	// detection so it can remain a pure streaming tree walk.
	DetectedType string

	// Size is the number of bytes in the part's body, in octets,
	// after any Content-Transfer-Encoding has been removed. It is
	// filled in as the caller's PartFunc reads the part (Parse
	// reports the final value once the callback returns).
	Size int64

	// Disposition classifies the part as inline or attachment.
	Disposition Disposition

	// ContentID is the part's Content-ID header value (RFC 2045 §7),
	// normalized: surrounding angle brackets and whitespace are
	// stripped (e.g. a raw header of "<logo123@example.com>" becomes
	// "logo123@example.com"). Empty if the part carries no Content-ID.
	// This is the identifier an HTML body's `cid:` URL scheme (RFC
	// 2392) references to embed the part inline, e.g. as an
	// `<img src="cid:logo123@example.com">`.
	ContentID string

	// InlineAsset is true when the part is a presentation-inline asset
	// referenced from elsewhere in the message (e.g. a logo or
	// signature image embedded via `cid:` in an HTML body), as opposed
	// to a genuine downloadable attachment (ADR-016). It holds iff
	// ContentID is non-empty AND the part's immediate parent container
	// is multipart/related — both signals must agree, since
	// Content-Disposition alone is unreliable (some MUAs mark real
	// downloadable attachments "inline"). InlineAsset is computed by
	// the parser from structural signals only, independent of
	// Disposition (which is derived from the raw Content-Disposition
	// header and left untouched by this field).
	InlineAsset bool
}
