package milter

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/textproto"
	"sort"
	"strings"
	"time"

	dmilter "github.com/d--j/go-milter"

	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/pipeline"
)

// backend implements the d--j/go-milter low-level Milter interface
// for a single MTA connection. A new backend is created per
// connection (see WithDynamicMilter in server.go); it accumulates one
// message's envelope and body, then hands it to the Core Processor at
// EndOfMessage.
//
// backend contains no policy logic itself: it only collects transport
// data (sender, recipients, queue ID, streamed body) and translates
// between the milter wire protocol and internal/core/pipeline types
// (ADR-002).
type backend struct {
	dmilter.NoOpMilter

	cfg       Config
	processor pipeline.Processor
	logger    *slog.Logger
	metrics   *metrics.Metrics

	sender     string
	recipients []string
	headers    []messageHeader
	body       *spool
}

// messageHeader is one message header as delivered by the MTA via the
// Header callback, kept in arrival order so EndOfMessage can rebuild the
// complete RFC 5322 message (header block + body) for the Core pipeline.
//
// value is stored exactly as go-milter delivers it: since this adapter
// does not negotiate OptHeaderLeadingSpace, the MTA has already stripped
// the single space that followed the colon on the wire, so value carries
// no leading space and reassembleMessage re-adds one canonical "SP".
type messageHeader struct {
	name  string
	value string
}

// newBackend creates a fresh backend for one milter connection. m may
// be nil (metrics.Metrics methods are nil-safe, US-7.2/T-7.2.1).
func newBackend(cfg Config, processor pipeline.Processor, logger *slog.Logger, m *metrics.Metrics) *backend {
	return &backend{
		cfg:       cfg,
		processor: processor,
		logger:    logger,
		metrics:   m,
	}
}

// MailFrom records the envelope sender, preferring the {mail_addr}
// macro (set by Postfix/Sendmail) and falling back to the raw
// argument the MTA passed on the MAIL command.
func (b *backend) MailFrom(from string, _ string, m dmilter.Modifier) (*dmilter.Response, error) {
	if v, ok := m.GetEx(dmilter.MacroMailAddr); ok && v != "" {
		b.sender = v
	} else {
		b.sender = from
	}
	return dmilter.RespContinue, nil
}

// RcptTo records one envelope recipient, preferring the {rcpt_addr}
// macro over the raw RCPT argument.
func (b *backend) RcptTo(rcptTo string, _ string, m dmilter.Modifier) (*dmilter.Response, error) {
	if v, ok := m.GetEx(dmilter.MacroRcptAddr); ok && v != "" {
		b.recipients = append(b.recipients, v)
	} else {
		b.recipients = append(b.recipients, rcptTo)
	}
	return dmilter.RespContinue, nil
}

// Header records one message header, in arrival order, so EndOfMessage
// can reconstruct the complete RFC 5322 message the MTA delivered
// piecewise. The milter protocol delivers a message as separate Header
// events followed by BodyChunk events (headers are NOT part of the body
// stream); without collecting them here the Core pipeline would receive
// a body with no header block and message.Parse would reject it as
// malformed, dropping every real message into the configured
// fail-open/fail-closed path.
//
// name is the field name without the colon; value is everything after
// the colon with the terminating CRLF and (because we do not negotiate
// OptHeaderLeadingSpace) the leading space already removed by the MTA.
func (b *backend) Header(name, value string, _ dmilter.Modifier) (*dmilter.Response, error) {
	b.headers = append(b.headers, messageHeader{name: name, value: value})
	return dmilter.RespContinue, nil
}

// BodyChunk streams the next chunk of the message body into the
// session's spool (SR-115-3: no full in-memory buffering). The spool
// itself enforces cfg.MaxMessageSize.
func (b *backend) BodyChunk(chunk []byte, _ dmilter.Modifier) (*dmilter.Response, error) {
	if b.body == nil {
		b.body = newSpool(b.cfg.MaxMessageSize)
	}
	if _, err := b.body.Write(chunk); err != nil {
		return nil, fmt.Errorf("milter: body chunk: %w", err)
	}
	return dmilter.RespContinue, nil
}

// EndOfMessage is called once the whole message has been received. It
// builds the pipeline.Envelope, hands it to the configured
// pipeline.Processor, and translates the resulting pipeline.Verdict
// (or any processing error/panic) into a milter response.
//
// Any error or panic from the Processor is resolved into the
// configured fail-open/fail-closed behavior (SR-116-1): the message
// is never dropped silently.
func (b *backend) EndOfMessage(m dmilter.Modifier) (resp *dmilter.Response, err error) {
	queueID, _ := m.GetEx(dmilter.MacroQueueId)
	start := time.Now()

	defer func() {
		if b.body != nil {
			if cerr := b.body.Close(); cerr != nil {
				b.logger.Warn("milter: failed to clean up body spool",
					"queue_id", queueID, "error", cerr)
			}
		}
	}()

	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("milter: recovered from panic while processing message",
				"queue_id", queueID, "panic", fmt.Sprintf("%v", r))
			resp, err = b.resolveFailure(queueID, fmt.Errorf("milter: processor panicked: %v", r))
		}
	}()

	var bodyReader io.Reader
	if b.body != nil {
		bodyReader, err = b.body.Reader()
		if err != nil {
			return b.resolveFailure(queueID, fmt.Errorf("milter: read spooled body: %w", err))
		}
	}

	env := &pipeline.Envelope{
		Sender:     b.sender,
		Recipients: b.recipients,
		QueueID:    queueID,
		Body:       b.reassembleMessage(bodyReader),
	}

	verdict, procErr := b.processor.Process(context.Background(), env)
	if procErr != nil {
		b.logger.Error("milter: processor returned an error",
			"queue_id", queueID, "error", procErr)
		return b.resolveFailure(queueID, procErr)
	}

	return b.applyVerdict(queueID, m, verdict, start)
}

// applyVerdict translates a successful pipeline.Verdict into the
// corresponding milter response and, for VerdictRewrite, applies the
// body replacement and header additions via m. On every outcome that
// is not itself routed through resolveFailure (i.e. every path that
// does NOT already log a WARN/Error for this message), it logs one
// INFO summary line via logOutcome (ATR-304) so the happy path is no
// longer silent — see logOutcome's doc comment for exactly what it
// logs and why.
func (b *backend) applyVerdict(queueID string, m dmilter.Modifier, v *pipeline.Verdict, start time.Time) (*dmilter.Response, error) {
	if v == nil {
		// Defensive: a nil verdict with no error is a Processor bug,
		// not a message we're willing to drop. Treat it like any
		// other processing failure.
		return b.resolveFailure(queueID, fmt.Errorf("milter: processor returned a nil verdict"))
	}

	switch v.Action {
	case pipeline.VerdictAccept:
		b.logOutcome(queueID, v, time.Since(start))
		return dmilter.RespAccept, nil

	case pipeline.VerdictRewrite:
		// Apply any explicit header additions first, so every header
		// modification precedes the ReplaceBody sequence: MTAs such as
		// Postfix require ReplaceBody chunks to be sent in one
		// uninterrupted run, not interleaved with other modifications
		// (see go-milter's Modifier.ReplaceBody doc). The real
		// AttachmentProcessor leaves AddHeaders empty (it embeds every
		// header change inside NewBody's header block instead), but this
		// path honors it for adapter/processor callers that use it.
		for _, h := range v.AddHeaders {
			if err := m.AddHeader(h.Name, h.Value); err != nil {
				b.logger.Error("milter: failed to add header", "queue_id", queueID, "header", h.Name, "error", err)
				return b.resolveFailure(queueID, fmt.Errorf("milter: add header %q: %w", h.Name, err))
			}
		}
		if v.NewBody != nil {
			if err := b.replaceMessage(queueID, m, v.NewBody); err != nil {
				b.logger.Error("milter: failed to apply rewritten message", "queue_id", queueID, "error", err)
				return b.resolveFailure(queueID, err)
			}
		}
		b.logOutcome(queueID, v, time.Since(start))
		return dmilter.RespAccept, nil

	case pipeline.VerdictReject:
		b.logOutcome(queueID, v, time.Since(start))
		return dmilter.RespReject, nil

	case pipeline.VerdictTempFail:
		b.logOutcome(queueID, v, time.Since(start))
		return dmilter.RespTempFail, nil

	default:
		return b.resolveFailure(queueID, fmt.Errorf("milter: processor returned unknown verdict action %v", v.Action))
	}
}

// logOutcome emits the one structured INFO line per completed message
// that the milter happy path was previously missing entirely (ATR-304):
// operators watching journald had no confirmation a message was ever
// seen unless it hit an error path (WARN/Error) or they went digging in
// the audit trail. It is called from applyVerdict on every outcome that
// is not itself routed through resolveFailure, so the fail-open/
// fail-closed WARN logging there is never duplicated by this one
// (ticket ATR-304's "do not duplicate" requirement).
//
// Fields are deliberately limited to what an operator needs to confirm
// "this message was processed and here's what happened to it", with no
// content that could leak message contents or a recipient's full
// address into the log stream:
//   - sender_domain is the domain portion only of the envelope sender,
//     never the full address (see senderDomain's doc comment) — the full
//     address is only ever written to the audit trail, which is a
//     separate, access-controlled record (audit.TypeMessageProcessed).
//   - no filenames, recipient addresses, or message content appear here
//     at all (those live in audit.TypeAttachmentStored/TypeLinksCreated
//     instead).
func (b *backend) logOutcome(queueID string, v *pipeline.Verdict, dur time.Duration) {
	b.logger.Info("milter: message processed",
		"queue_id", queueID,
		"sender_domain", senderDomain(b.sender),
		"decision", verdictDecision(v.Action),
		"attachments_total", v.Attachments.Total,
		"attachments_replaced", v.Attachments.Replaced,
		"attachments_inline_protected", v.Attachments.InlineProtected,
		"attachments_body_protected", v.Attachments.BodyProtected,
		"duration_ms", dur.Milliseconds(),
	)
}

// verdictDecision maps a pipeline.VerdictAction to the short decision
// name logOutcome writes: "pass"/"rewrite"/"block" match the vocabulary
// operators already know from policy.yaml's own action names (US-4.x),
// rather than VerdictAction.String()'s "accept"/"reject" wire-protocol
// naming.
func verdictDecision(a pipeline.VerdictAction) string {
	switch a {
	case pipeline.VerdictAccept:
		return "pass"
	case pipeline.VerdictRewrite:
		return "rewrite"
	case pipeline.VerdictReject:
		return "block"
	case pipeline.VerdictTempFail:
		return "tempfail"
	default:
		return "unknown"
	}
}

// senderDomain extracts the domain portion of a full email address for
// logging, per the log redaction practice this adapter otherwise
// follows (never writing a filename or full address into the log
// stream — see logOutcome's doc comment): only the audit trail, a
// separate access-controlled record, carries the complete sender
// address. It returns "" for an address with no "@" (e.g. the empty
// MAIL FROM:<> bounce sender, or a malformed address a permissive MTA
// still handed us) or one ending in "@" — callers should read an empty
// result as "no sender domain available", not as an error.
func senderDomain(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	return addr[i+1:]
}

// reassembleMessage rebuilds the complete RFC 5322 message the MTA
// delivered piecewise over the milter protocol: the header block
// collected by Header (serialized as canonical "Name: value" lines with
// CRLF endings, then the blank line that terminates the header block)
// followed by body, the streamed message body. It returns body
// unchanged when no headers were collected, and nil when there is
// neither a header nor a body.
//
// CRLF is the canonical SMTP/RFC 5322 line ending; the Core parser
// (net/mail via internal/core/message) accepts LF too, but this adapter
// emits CRLF so the reconstructed message matches what a compliant
// client would have sent. The header block is small and bounded (the
// MTA enforces its own header-size limits), so serializing it into a
// single reader does not violate CLAUDE.md invariant #4; body is never
// buffered here — io.MultiReader streams it straight through.
func (b *backend) reassembleMessage(body io.Reader) io.Reader {
	if len(b.headers) == 0 {
		return body
	}

	var hb strings.Builder
	for _, h := range b.headers {
		hb.WriteString(h.name)
		hb.WriteString(": ")
		hb.WriteString(h.value)
		hb.WriteString("\r\n")
	}
	hb.WriteString("\r\n")

	header := strings.NewReader(hb.String())
	if body == nil {
		return header
	}
	return io.MultiReader(header, body)
}

// replaceMessage applies a VerdictRewrite's NewBody to the message.
//
// NewBody is the complete rewritten RFC 5322 message (headers + body):
// a self-contained message the Core produced without knowing how any
// given transport replaces content (ADR-002). The milter ReplaceBody
// wire operation (SMFIR_REPLBODY) replaces only the body — the MTA
// keeps the headers it already holds — so replaceMessage splits NewBody
// into its header block and body: it streams the body into
// m.ReplaceBody (never buffering it whole, CLAUDE.md invariant #4) and
// re-adds, via m.AddHeader, every header the rewrite introduced relative
// to the message the MTA already has. "Introduced" is decided by
// canonical field name: a header whose name the original message did
// not carry is added (in practice just X-Attachra-Processed, US-3.2);
// headers the rewrite left unchanged are already on the MTA side and are
// not touched, avoiding duplicates. AddHeader calls are issued in
// sorted-by-name order for deterministic, reproducible behavior (Go map
// iteration order is randomized).
//
// Fail-safe (ATR-289 review, TD-8 in docs/architecture/tech-debt.md):
// this adapter can only ADD a header via milter's AddHeader; it cannot
// change the value of a header the MTA already has (that needs
// OptChangeHeader / m.ChangeHeader, tracked separately as ATR-290). If a
// rewrite ever needed to CHANGE an existing header's value — rather than
// only add new ones — silently proceeding here would delivver a message
// whose body no longer matches a header still holding its original
// value (CLAUDE.md invariant #3's "never silently corrupt" reading of
// "never lose a message"). So replaceMessage detects two shapes of that
// hazard before issuing a single AddHeader/ReplaceBody call, and returns
// an error (which the caller resolves into fail-open/fail-closed) the
// moment either is seen — see headerValueChanged and
// bodyLooksLikeHeaderBlock's own doc comments for what each one guards
// against and why. Detection runs to completion, and only THEN are any
// modifier calls made, so a detected hazard leaves the milter session
// completely untouched (a true fail-open delivers the original message
// verbatim, not a partially-modified one).
func (b *backend) replaceMessage(queueID string, m dmilter.Modifier, newBody io.Reader) error {
	// NewBody may be a temp-file-backed io.ReadCloser
	// (internal/core/rewrite.Rewrite's spoolFile, once the rewritten body
	// spills past its in-memory threshold): if nothing closes it, every
	// rewritten message leaks its spool temp file, eventually filling the
	// mail server's disk. Close it here regardless of outcome — go-milter
	// reads it synchronously to completion (or first error) and never
	// retains it, so closing after we are done reading is safe. A Close
	// failure is logged but never changes the outcome: the body has
	// already been handed to the MTA (or the attempt already failed).
	defer func() {
		if closer, ok := newBody.(io.Closer); ok {
			if cerr := closer.Close(); cerr != nil {
				b.logger.Warn("milter: failed to close rewritten body spool", "queue_id", queueID, "error", cerr)
			}
		}
	}()

	// Read the rewritten header block from the front of the stream; the
	// bufio.Reader is then positioned at the first body byte and is what
	// we stream into ReplaceBody.
	br := bufio.NewReader(newBody)
	rewrittenHeader, err := textproto.NewReader(br).ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return fmt.Errorf("milter: parse rewritten header block: %w", err)
	}

	originalValues := make(map[string][]string, len(b.headers))
	for _, h := range b.headers {
		name := textproto.CanonicalMIMEHeaderKey(h.name)
		originalValues[name] = append(originalValues[name], h.value)
	}

	var toAdd []string
	for name, values := range rewrittenHeader {
		orig, hadOriginal := originalValues[name]
		if !hadOriginal {
			toAdd = append(toAdd, name)
			continue
		}
		if changedName, changedOrig, changedNew, changed := headerValueChanged(name, orig, values); changed {
			b.logger.Warn("milter: rewritten message changes an existing header value, which this adapter cannot apply (AddHeader only adds, see ATR-290)",
				"queue_id", queueID, "header", changedName)
			return fmt.Errorf("milter: rewritten header %q changed value (original %q, rewritten %q): %w",
				changedName, changedOrig, changedNew, errHeaderValueChanged)
		}
		// Values match (after normalization): this header is already on
		// the MTA side and unchanged, so it is neither re-added nor
		// otherwise touched.
	}

	// Promotion-path fail-safe (TD-8 / ATR-291): a changed Content-Type
	// that internal/core/rewrite's single-part-to-multipart promotion
	// writes past the header block (into what this adapter treats as
	// body) never appears in rewrittenHeader at all, so the per-header
	// comparison above cannot see it. bodyLooksLikeHeaderBlock catches
	// that specific shape by inspecting the body's own first line.
	if bodyLooksLikeHeaderBlock(br) {
		b.logger.Warn("milter: rewritten message body begins with what looks like another header block, refusing to apply (see TD-8 / ATR-291)",
			"queue_id", queueID)
		return fmt.Errorf("milter: rewritten message body looks like a header block: %w", errPromotedContentType)
	}

	sort.Strings(toAdd)
	for _, name := range toAdd {
		for _, value := range rewrittenHeader[name] {
			if err := m.AddHeader(name, value); err != nil {
				return fmt.Errorf("milter: add rewritten header %q: %w", name, err)
			}
		}
	}

	if err := m.ReplaceBody(br); err != nil {
		return fmt.Errorf("milter: replace body: %w", err)
	}
	return nil
}

// errHeaderValueChanged and errPromotedContentType are sentinel causes
// wrapped by replaceMessage's two fail-safes, giving log/test call sites
// something stable to match on independent of the queue-id-specific
// message text.
var (
	errHeaderValueChanged  = fmt.Errorf("milter: existing header value changed")
	errPromotedContentType = fmt.Errorf("milter: rewritten body looks like a promoted header block")
)

// headerValueChanged reports whether orig and rewritten (both value
// lists for the same canonical header name across possibly-repeated
// headers, e.g. "Received") differ once normalizeHeaderValue is applied
// to every element pairwise, positionally. A length mismatch also
// counts as changed. On a match it returns ("", "", "", false); on a
// mismatch it returns the header name and the first differing pair of
// (normalized) values for use in an error/log message.
func headerValueChanged(name string, orig, rewritten []string) (changedName, changedOrig, changedNew string, changed bool) {
	if len(orig) != len(rewritten) {
		return name, strings.Join(orig, " / "), strings.Join(rewritten, " / "), true
	}
	for i := range orig {
		o, r := normalizeHeaderValue(orig[i]), normalizeHeaderValue(rewritten[i])
		if o != r {
			return name, o, r, true
		}
	}
	return "", "", "", false
}

// normalizeHeaderValue prepares a header value for content-equality
// comparison in headerValueChanged, making the comparison robust to
// superficial differences that do not change the header's meaning
// rather than to its actual content:
//   - a leading run of spaces/tabs is trimmed — go-milter's Header
//     callback already strips the single mandatory space after the
//     field-name's colon (we do not negotiate OptHeaderLeadingSpace),
//     but textproto.ReadMIMEHeader (used to parse NewBody's rewritten
//     header block) does not necessarily agree byte-for-byte on
//     leading whitespace;
//   - any folded continuation ("\r\n" or "\n" followed by one or more
//     spaces/tabs, RFC 5322 §2.2.3 obs-fold) collapses to one space,
//     matching how a folded header's *value* is semantically a single
//     unfolded string.
func normalizeHeaderValue(v string) string {
	v = strings.TrimLeft(v, " \t")
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); {
		switch {
		case v[i] == '\r' && i+1 < len(v) && v[i+1] == '\n':
			i += 2
			for i < len(v) && (v[i] == ' ' || v[i] == '\t') {
				i++
			}
			b.WriteByte(' ')
		case v[i] == '\n':
			i++
			for i < len(v) && (v[i] == ' ' || v[i] == '\t') {
				i++
			}
			b.WriteByte(' ')
		default:
			b.WriteByte(v[i])
			i++
		}
	}
	return strings.TrimRight(b.String(), " \t")
}

// promotionHeaderSniffLen bounds how many bytes of the "body" portion
// (the bytes immediately following NewBody's parsed header block)
// bodyLooksLikeHeaderBlock inspects. Only the first line matters, but a
// generous bound tolerates a long Content-Type line (e.g. a lengthy
// boundary parameter) without needing to grow bufio.Reader's default
// internal buffer (4096 bytes), so Peek never itself triggers a read
// past what br already buffers.
const promotionHeaderSniffLen = 512

// bodyLooksLikeHeaderBlock peeks (without consuming — bufio.Reader.Peek
// does not advance the read position) up to promotionHeaderSniffLen
// bytes from br and reports whether they begin with what looks like
// another RFC 5322 header field line ("field-name: value") rather than
// ordinary message content.
//
// This is a narrow, deliberately blunt fail-safe for one specific known
// gap (TD-8, ATR-291): internal/core/rewrite's rewriteTopLevelSinglePart
// (invoked when a whole single-part message is promoted into a
// multipart/mixed envelope so the replacement block has somewhere to
// live) writes its new "Content-Type: multipart/mixed; boundary=...
// \r\nMIME-Version: 1.0\r\n\r\n" preamble to the output stream AFTER the
// top-level header block (and its terminating blank line) has already
// been written by run(). That means the changed Content-Type lands in
// what this adapter treats as "body", never in NewBody's parsed header
// block — so headerValueChanged above never sees it and cannot detect
// that the message's real Content-Type has silently gone out of sync
// with the (unchanged, original) Content-Type still in the header
// block.
//
// Every legitimate rewrite output this adapter otherwise receives always
// begins its body with a MIME boundary delimiter line ("--boundary"),
// never a bare "field-name: value" line — verified directly against
// rewrite.Rewrite's actual promotion-path output (see
// TestRewriteMessage_PromotionPath in backend_promotion_test.go, which
// dumps the real bytes this function is checking). A body that DOES
// start that way is therefore a reliable, specific signal of this one
// known gap rather than of ordinary message content coincidentally
// containing a colon on its first line. ATR-290/291 track the real fix
// (using milter's ChangeHeader to update Content-Type in place); until
// then, tripping this check routes the message through the same
// fail-open/fail-closed path as any other processing error, rather than
// silently delivering a message whose Content-Type header and body have
// gone out of sync.
func bodyLooksLikeHeaderBlock(br *bufio.Reader) bool {
	peek, _ := br.Peek(promotionHeaderSniffLen)
	if len(peek) == 0 {
		return false
	}

	line := peek
	if nl := bytes.IndexAny(peek, "\r\n"); nl >= 0 {
		line = peek[:nl]
	}
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return false
	}

	name := line[:colon]
	for i := 0; i < len(name); i++ {
		// RFC 5322 §2.2's field-name is one or more printable US-ASCII
		// characters (33-126) excluding ':'. Anything outside that
		// range (spaces included) rules out "this line is a header
		// field", which is exactly what distinguishes a header line
		// from ordinary body content that merely happens to contain a
		// colon somewhere.
		c := name[i]
		if c < '!' || c > '~' || c == ':' {
			return false
		}
	}
	return true
}

// resolveFailure maps a processing error to the configured
// fail-open/fail-closed response (SR-116-1). It always logs the
// queue ID and the underlying cause, and never returns a Go error
// itself for a fail-open/fail-closed outcome: doing so would close
// the milter connection instead of delivering the configured
// response, which for fail-open would mean losing the accept
// decision.
func (b *backend) resolveFailure(queueID string, cause error) (*dmilter.Response, error) {
	switch b.cfg.FailureMode {
	case FailClosed:
		b.logger.Warn("milter: fail-closed: temp-failing message after processing error",
			"queue_id", queueID, "cause", cause)
		b.metrics.ObserveError("milter_fail_closed")
		resp, err := dmilter.RejectWithCodeAndReason(tempFailSMTPCode, tempFailReason)
		if err != nil {
			// Building the canned temp-fail response itself failed;
			// fall back to the library's built-in RespTempFail so we
			// still never silently drop the message.
			b.logger.Error("milter: failed to build tempfail response, using default", "error", err)
			return dmilter.RespTempFail, nil
		}
		return resp, nil

	case FailOpen:
		fallthrough
	default:
		b.logger.Warn("milter: fail-open: accepting message unmodified after processing error",
			"queue_id", queueID, "cause", cause)
		b.metrics.ObserveError("milter_fail_open")
		return dmilter.RespAccept, nil
	}
}

// Cleanup resets per-message state. NoOpMilter's Cleanup is a no-op,
// but we override it to make sure a spool from an aborted message
// (Abort called instead of EndOfMessage) is not leaked.
func (b *backend) Cleanup(_ dmilter.Modifier) {
	if b.body != nil {
		if err := b.body.Close(); err != nil {
			b.logger.Warn("milter: failed to clean up body spool during Cleanup", "error", err)
		}
		b.body = nil
	}
	b.headers = nil
}

// Abort resets per-message state so leftover spool data from an
// aborted transaction is not mistakenly reused for the next message
// in the same connection, and so its temp file (if any) is removed
// promptly rather than waiting for Cleanup.
func (b *backend) Abort(_ dmilter.Modifier) error {
	if b.body != nil {
		if err := b.body.Close(); err != nil {
			b.logger.Warn("milter: failed to clean up body spool during Abort", "error", err)
		}
		b.body = nil
	}
	b.sender = ""
	b.recipients = nil
	b.headers = nil
	return nil
}
