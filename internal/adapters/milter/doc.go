// Package milter implements the Postfix Milter adapter (see ADR-008),
// built on the low-level API of github.com/d--j/go-milter (never its
// higher-level mailfilter package, which buffers the whole message
// body — see docs/architecture/spike-milter-library.md). It depends
// on internal/core/pipeline to apply attachment policies; core must
// never depend back on this package — see ADR-002.
//
// The message body is streamed into a bounded spool (see spool.go) as
// it arrives, never buffered whole in memory (the streaming invariant),
// and any processing error or panic is resolved into the configured
// fail-open/fail-closed behavior (see config.go, backend.go; the
// mail-must-never-be-lost invariant).
package milter
