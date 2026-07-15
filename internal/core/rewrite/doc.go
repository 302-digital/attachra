// Package rewrite rewrites an outgoing message's MIME structure so
// that attachments matched by a `replace` policy verdict
// (internal/core/policy) are removed and substituted with a
// human-readable replacement block (US-3.2), while attachments
// matched by `pass` are forwarded byte-for-byte, unmodified.
//
// It must not depend on any adapter-specific code (e.g. Postfix
// milter) — see ADR-002. The replacement block links to a single
// package-page URL per message (docs/architecture/package-page-decision.md
// §4.1); it does not embed a link per attachment. The rewriter never
// buffers the whole message in memory: parts are copied as streams,
// spilling to a temporary file only when the configured in-memory
// threshold is exceeded (CLAUDE.md invariant #4), mirroring the
// approach used by internal/adapters/milter's spool.
//
// # SR-118-2 (RFC 5987) scope
//
// This package never emits a file name into a Content-Disposition (or
// any other) header: `replace`-verdict parts are removed outright (no
// header survives at all), and `pass`-verdict parts are copied
// byte-for-byte, including their original Content-Disposition header
// bytes verbatim — rewrite never re-derives or re-encodes a filename
// for them. The only place a removed attachment's name is written at
// all is the replacement block's plain-text/HTML file listing
// (package-page-decision.md §4.1), which is body content, not a
// header, so RFC 5987 does not apply there.
//
// SR-118-2 becomes relevant once a download endpoint (T-6.2.1) serves
// the actual file bytes and must set a Content-Disposition header
// naming the file for the browser's Save As dialog. sanitize.go's
// encodeContentDispositionFilename implements the RFC 5987
// extended-parameter encoding for that future use and is unit-tested
// here (sanitize_test.go) even though nothing in this package's own
// Rewrite path calls it yet.
package rewrite
