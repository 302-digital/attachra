package rewrite

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"os"
	"strings"
	"time"

	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/spoolutil"
)

// ProcessedHeaderVersion is the value written in the "version"
// component of the X-Attachra-Processed header (US-3.2 acceptance
// criteria: "a header X-Attachra-Processed is added").
const ProcessedHeaderVersion = "1"

// Input is the input to Rewrite.
type Input struct {
	// Message streams the original, complete RFC 5322 message
	// (headers + body) to rewrite.
	Message io.Reader

	// Attachments is the flat list of attachments discovered by
	// message.Parse for this same Message, in the same order and with
	// the same PartPath values as were passed to policy.Evaluate to
	// produce Decision. Rewrite uses PartPath to look up each leaf
	// part's verdict while re-walking the MIME tree.
	Attachments []message.Attachment

	// Decision is the policy verdict for the message, aligned
	// index-for-index with Attachments (policy.MessageDecision's own
	// documented contract).
	Decision policy.MessageDecision

	// PackageURL is the single package-page link
	// (package-page-decision.md §4.1) to embed in the replacement
	// block, supplied by the (future) Link Engine. Rewrite treats it
	// as an opaque string and sanitizes it before use (SR-118-1).
	PackageURL string

	// ExpiresAt, if non-zero, is rendered in the replacement block as
	// the link's expiry.
	ExpiresAt time.Time

	// SenderName is displayed in the replacement block as "sent by".
	// Typically the envelope sender address.
	SenderName string

	// ProcessedID, if non-empty, is used verbatim (after sanitization)
	// as the short id component of X-Attachra-Processed. If empty, a
	// random id is generated.
	ProcessedID string

	// SpoolDir selects the directory stageToFile creates its temporary
	// spill file in once the rewritten output exceeds
	// spoolutil.SpoolMemThreshold (ATR-262). It is expected to be
	// config.SpoolConfig.Dir; the empty string (the default) uses the
	// OS default temporary directory ($TMPDIR / os.TempDir()), matching
	// os.CreateTemp's own documented behavior for an empty dir argument.
	SpoolDir string
}

// Result is the output of a successful Rewrite.
type Result struct {
	// Body streams the complete rewritten message (headers + body).
	// The caller must fully read (or close, if it implements io.Closer
	// — spooled results do) Body.
	Body io.Reader

	// Replaced lists the attachments that were actually removed from
	// the message (Decision.Attachments[i].Action == policy.ActionReplace),
	// in document order, for the caller to pass to the Link Engine.
	Replaced []message.Attachment

	// ProcessedID is the id written into X-Attachra-Processed.
	ProcessedID string
}

// hasReplace reports whether in.Decision has at least one
// ActionReplace verdict.
func (in Input) hasReplace() bool {
	for _, d := range in.Decision.Attachments {
		if d.Action == policy.ActionReplace {
			return true
		}
	}
	return false
}

// Rewrite rewrites in.Message per in.Decision (T-3.2.1):
//   - attachments decided ActionReplace are removed from the MIME
//     tree; the tree's remaining structure (multipart boundaries,
//     multipart/related and multipart/alternative nesting) is
//     preserved;
//   - a replacement block (text/plain and, where applicable,
//     text/html) is added, linking to in.PackageURL and listing the
//     removed files by name;
//   - attachments decided ActionPass are copied byte-for-byte, with
//     no decode/re-encode of their Content-Transfer-Encoding;
//   - an X-Attachra-Processed header is added.
//
// If in.Decision contains no ActionReplace verdict at all, Rewrite
// returns in.Message completely untouched (not even re-serialized) as
// Result.Body, satisfying the "message passes through byte-for-byte
// when nothing is replaced" requirement trivially and cheaply.
//
// tmpl supplies the replacement block's rendered text; see
// LoadTemplates.
func Rewrite(in Input, tmpl *Templates) (*Result, error) {
	if !in.hasReplace() {
		return &Result{Body: in.Message}, nil
	}

	processedID := sanitizeHeaderValue(in.ProcessedID)
	if processedID == "" {
		id, err := randomID()
		if err != nil {
			return nil, fmt.Errorf("rewrite: generate processed id: %w", err)
		}
		processedID = id
	}

	decisionByPath := make(map[string]policy.AttachmentDecision, len(in.Attachments))
	for i, att := range in.Attachments {
		decisionByPath[att.PartPath] = in.Decision.Attachments[i]
	}

	var replaced []message.Attachment
	for i, d := range in.Decision.Attachments {
		if d.Action == policy.ActionReplace {
			replaced = append(replaced, in.Attachments[i])
		}
	}

	block := BlockData{
		PackageURL: in.PackageURL,
		ExpiresAt:  in.ExpiresAt,
		SenderName: in.SenderName,
	}
	for _, att := range replaced {
		block.Files = append(block.Files, BlockFile{Name: att.Filename, Size: att.Size})
	}
	plainBlock, htmlBlock, err := renderBlock(tmpl, block)
	if err != nil {
		return nil, err
	}

	body, err := stageToFile(in.SpoolDir, func(w io.Writer) error {
		rw := &rewriter{
			decisionByPath: decisionByPath,
			plainBlock:     plainBlock,
			htmlBlock:      htmlBlock,
			processedID:    processedID,
		}
		return rw.run(in.Message, w)
	})
	if err != nil {
		return nil, err
	}

	return &Result{Body: body, Replaced: replaced, ProcessedID: processedID}, nil
}

// randomID returns a short random hex id (SR "short id") for
// X-Attachra-Processed, from crypto/rand per the token-hygiene
// invariant (the same primitive used for link tokens, even though
// this id is not a security-sensitive secret — consistency avoids a
// second pattern for "generate a random identifier").
func randomID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// stageToFile invokes write with a destination writer, spooling the
// output to memory up to spoolutil.SpoolMemThreshold bytes and to a
// temporary file beyond that (mirroring internal/adapters/milter's
// spool, SR-115-3, the streaming invariant), then returns a reader
// over the complete staged result positioned at the start. dir
// selects the directory any spilled temporary file is created in
// (ATR-262); the empty string uses the OS default temporary
// directory ($TMPDIR / os.TempDir()), matching os.CreateTemp's own
// documented behavior for an empty dir argument.
//
// Rewriting a MIME tree fundamentally requires knowing, for the
// outermost multipart/mixed envelope, whether a block needs to be
// injected as a new sibling part or appended into existing
// text/plain-or-html siblings — a decision that in general depends on
// having seen those siblings, which may come before or after the
// replaced attachment in document order. Staging the output (rather
// than piping it directly to the caller as it is produced) keeps the
// writer side of rewrite a straightforward single top-to-bottom pass
// instead of a two-pass or backtracking one, at the cost of one
// bounded buffer/temp-file per rewritten message — the same trade-off
// milter's own spool already makes for the *input* side.
func stageToFile(dir string, write func(io.Writer) error) (io.Reader, error) {
	var mem bytes.Buffer
	limited := &thresholdWriter{buf: &mem, threshold: spoolutil.SpoolMemThreshold, dir: dir}

	if err := write(limited); err != nil {
		if limited.file != nil {
			_ = limited.file.Close()
			_ = os.Remove(limited.file.Name())
		}
		return nil, err
	}

	if limited.file == nil {
		return bytes.NewReader(mem.Bytes()), nil
	}
	if err := limited.file.Sync(); err != nil {
		_ = limited.file.Close()
		_ = os.Remove(limited.file.Name())
		return nil, fmt.Errorf("rewrite: sync spool file: %w", err)
	}
	if _, err := limited.file.Seek(0, io.SeekStart); err != nil {
		_ = limited.file.Close()
		_ = os.Remove(limited.file.Name())
		return nil, fmt.Errorf("rewrite: seek spool file: %w", err)
	}
	return &spoolFile{f: limited.file}, nil
}

// thresholdWriter accumulates writes in buf until threshold bytes
// have been written, then spills buf's contents (and all subsequent
// writes) to a newly created temporary file in dir (the empty string
// meaning the OS default temporary directory).
type thresholdWriter struct {
	buf       *bytes.Buffer
	threshold int
	dir       string
	file      *os.File
}

func (w *thresholdWriter) Write(p []byte) (int, error) {
	if w.file == nil && w.buf.Len()+len(p) > w.threshold {
		f, err := os.CreateTemp(w.dir, "attachra-rewrite-body-*.spool")
		if err != nil {
			return 0, fmt.Errorf("rewrite: create spool temp file: %w", err)
		}
		if _, err := f.Write(w.buf.Bytes()); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return 0, fmt.Errorf("rewrite: write spool temp file: %w", err)
		}
		w.buf.Reset()
		w.file = f
	}
	if w.file != nil {
		return w.file.Write(p)
	}
	return w.buf.Write(p)
}

// spoolFile is an io.Reader (and io.Closer) over a temporary file
// created by stageToFile, removing the file once closed.
type spoolFile struct {
	f      *os.File
	closed bool
}

func (s *spoolFile) Read(p []byte) (int, error) { return s.f.Read(p) }

// Close closes and removes the backing temporary file. Callers that
// obtain a *Result from Rewrite should Close Result.Body when done if
// it implements io.Closer, to avoid leaking the temp file; callers
// that only ever read small (in-memory) results still get a plain
// *bytes.Reader, which has no Close method, so a type assertion is
// required either way. Close is idempotent: a second call is a no-op
// returning nil, matching the common defer-Close-plus-explicit-Close
// pattern.
func (s *spoolFile) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true

	name := s.f.Name()
	closeErr := s.f.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return fmt.Errorf("rewrite: close spool temp file: %w", closeErr)
	}
	if removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("rewrite: remove spool temp file: %w", removeErr)
	}
	return nil
}

// rewriter carries the bookkeeping threaded through the recursive
// MIME rewrite walk: the per-attachment decisions keyed by PartPath,
// the rendered replacement block, and the processed-message id.
type rewriter struct {
	decisionByPath map[string]policy.AttachmentDecision
	plainBlock     string
	htmlBlock      string
	processedID    string

	// blockInjected is set once the replacement block has been
	// written somewhere in the output, so run() can add a fallback
	// top-level part if the walk never found a natural home for it
	// (e.g. the message had no multipart/alternative body at all).
	blockInjected bool

	// plainAppended / htmlAppended are set once the block's
	// text/plain (resp. text/html) rendering has been appended to a
	// leaf, so at most one text/plain and one text/html leaf receive
	// it even if the message has several (e.g. multiple
	// multipart/alternative groups).
	plainAppended bool
	htmlAppended  bool
}

// run reads the top-level message from src and writes the rewritten
// message to dst.
func (rw *rewriter) run(src io.Reader, dst io.Writer) error {
	br := bufio.NewReaderSize(src, 32*1024)

	headerBytes, header, err := readRawHeader(br)
	if err != nil {
		return fmt.Errorf("rewrite: read top-level header: %w", err)
	}

	contentType := header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "text/plain"
		params = map[string]string{}
	}

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		// The top-level Content-Type is already multipart and does not
		// change, so the original header block is emitted verbatim (plus
		// the synthesized X-Attachra-Processed) before its child parts.
		if _, err := dst.Write(withProcessedHeader(headerBytes, rw.processedID)); err != nil {
			return fmt.Errorf("rewrite: write top-level header: %w", err)
		}
		// true: this is the message's genuinely outermost multipart
		// structure, written directly to Rewrite's final output, so its
		// closing delimiter owns the final trailing CRLF (see
		// boundaryWriter.finalCRLF's doc comment in walk.go).
		if err := rw.rewriteMultipart(br, dst, params["boundary"], "0", true); err != nil {
			return err
		}
	default:
		// A non-multipart top-level message that still has a
		// replace-decision "attachment" can only mean the whole
		// message body itself was classified as a single attachment
		// leaf (PartPath "0"). Promote it into a small
		// multipart/mixed envelope so the replacement block has a
		// well-formed place to live alongside the (dropped) original
		// body. rewriteTopLevelSinglePart writes its OWN top-level
		// header block: promotion changes the top-level Content-Type
		// (and drops the single part's other content headers), which
		// must land INSIDE the header block, before its terminating
		// blank line — writing it after the block, as this path used to,
		// pushed the promoted Content-Type into the body (ATR-291).
		if err := rw.rewriteTopLevelSinglePart(br, dst, headerBytes, "0"); err != nil {
			return err
		}
	}

	if !rw.blockInjected {
		return fmt.Errorf("rewrite: internal error: replacement block was never written to output")
	}
	return nil
}

// rewriteTopLevelSinglePart handles the rare case where the entire
// message is a single, non-multipart part (Content-Type is not
// "multipart/..."): there is no sibling structure to preserve, so
// rewrite promotes the message into a small multipart/mixed envelope
// wrapping the (possibly dropped, possibly kept) original body plus a
// new multipart/alternative part carrying the replacement block.
//
// Unlike the multipart path, this promotion CHANGES the top-level
// Content-Type (application/... -> multipart/mixed), so this function
// emits the whole top-level header block itself rather than relying on
// run() having emitted the original one: promoteHeaderBlock preserves
// every original envelope header verbatim, drops the single part's own
// content headers (Content-Type, Content-Transfer-Encoding,
// Content-Disposition, ... — they describe the wrapped body, not the new
// multipart envelope, and moving them down/dropping them is what keeps
// the promoted Content-Type inside the header block rather than in the
// body, ATR-291), and appends the multipart/mixed Content-Type,
// MIME-Version and X-Attachra-Processed.
func (rw *rewriter) rewriteTopLevelSinglePart(br *bufio.Reader, dst io.Writer, headerBytes []byte, partPath string) error {
	rest, err := io.ReadAll(br)
	if err != nil {
		return fmt.Errorf("rewrite: read top-level single-part body: %w", err)
	}

	boundary := "attachra-top-" + rw.processedID
	if _, err := dst.Write(promoteHeaderBlock(headerBytes, boundary, rw.processedID)); err != nil {
		return fmt.Errorf("rewrite: write promoted top-level header: %w", err)
	}

	// This writes directly to Rewrite's final output (dst), the same
	// as rw.run's top-level rewriteMultipart call, so its closing
	// delimiter owns the message's final trailing CRLF too (see
	// boundaryWriter.finalCRLF's doc comment).
	bw := &boundaryWriter{dst: dst, boundary: boundary, finalCRLF: true}

	decision, hasDecision := rw.decisionByPath[partPath]
	if !hasDecision || decision.Action != policy.ActionReplace {
		// The original body is kept: re-emit it as a wrapped part
		// carrying only its own content headers (the ones dropped from
		// the promoted top-level block). Envelope headers stay on the
		// top-level block above and must not be duplicated here.
		var partBuf bytes.Buffer
		partBuf.Write(contentHeaderLines(headerBytes))
		partBuf.WriteString("\r\n")
		partBuf.Write(rest)

		if err := bw.writePart(partBuf.Bytes()); err != nil {
			return err
		}
	}

	if err := rw.appendFallbackAlternativePart(bw); err != nil {
		return err
	}
	return bw.writeClosing()
}

// readRawHeader reads a header block (message- or part-level) from
// br, returning both the raw bytes and the textproto-parsed form, the
// same way rawMultipartReader.readHeader does for multipart child
// parts.
func readRawHeader(br *bufio.Reader) ([]byte, textprotoHeader, error) {
	var buf bytes.Buffer
	for {
		line, err := br.ReadSlice('\n')
		if err != nil && len(line) == 0 {
			return nil, nil, fmt.Errorf("read header line: %w", err)
		}
		buf.Write(line)
		if isBlankLine(line) {
			break
		}
		if err == io.EOF {
			break
		}
	}

	header, err := parseHeaderBlock(buf.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("parse header block: %w", err)
	}
	return buf.Bytes(), header, nil
}

// withProcessedHeader appends an X-Attachra-Processed header line to
// headerBytes, just before the blank line that terminates the header
// block. version and id are sanitized against CR/LF (SR-118-1) even
// though id is generated internally here, since Input.ProcessedID may
// originate from a caller that derived it from message content.
func withProcessedHeader(headerBytes []byte, id string) []byte {
	value := sanitizeHeaderValue(fmt.Sprintf("version=%s; id=%s", ProcessedHeaderVersion, id))
	line := []byte("X-Attachra-Processed: " + value + "\r\n")

	// headerBytes ends with the blank-line terminator (either "\r\n"
	// or "\n", possibly with no preceding header at all for a
	// pathological empty header block). Insert the new header
	// immediately before that terminator.
	if idx := bytes.LastIndex(headerBytes, []byte("\n")); idx >= 0 {
		// Find the start of the blank line itself: walk back to the
		// previous newline (or start of buffer).
		blankStart := lastLineStart(headerBytes, idx)
		out := make([]byte, 0, len(headerBytes)+len(line))
		out = append(out, headerBytes[:blankStart]...)
		out = append(out, line...)
		out = append(out, headerBytes[blankStart:]...)
		return out
	}
	return append(append([]byte{}, line...), headerBytes...)
}

// lastLineStart returns the byte offset of the start of the line
// whose trailing '\n' is at index nlIdx within b.
func lastLineStart(b []byte, nlIdx int) int {
	// Search for the newline before this line's own newline.
	prev := bytes.LastIndex(b[:nlIdx], []byte("\n"))
	if prev < 0 {
		return 0
	}
	return prev + 1
}
