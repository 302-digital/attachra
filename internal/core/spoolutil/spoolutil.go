// Package spoolutil holds small, dependency-free constants and helpers
// that historically were copy-pasted, independently, across
// internal/core/pipeline, internal/core/rewrite, internal/adapters/milter,
// internal/core/link and internal/core/message: the in-memory spool
// threshold shared by every
// component that spills a stream to a temporary file past a size bound,
// the crypto/rand-backed opaque-id generator used for store row ids, and
// the MIME content-sniffing window length. Each of those used to be a
// small, separately-maintained copy that could silently drift if only
// one call site were ever updated; this package makes each one a single
// definition instead.
//
// spoolutil has no dependencies beyond the standard library and lives
// under internal/core (not internal/adapters) specifically so
// internal/adapters/milter may import it while the dependency direction
// required by ADR-002 (adapters depend on core, never the reverse)
// stays intact.
package spoolutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SpoolMemThreshold bounds how much of a spooled stream (a message
// body, a single attachment's decoded content, or rewritten MIME
// output) is held in memory before the holder spills it to a temporary
// file on disk (SR-115-3, the streaming invariant): small, common inputs
// stay fast, while large ones never occupy this many bytes of memory
// per in-flight message beyond this bound.
const SpoolMemThreshold = 256 * 1024 // 256 KiB

// SniffLen is the number of leading bytes inspected for MIME
// content-type/signature sniffing. It matches the window
// http.DetectContentType itself considers (at most 512 bytes per the
// WHATWG MIME Sniffing spec), so callers never need to buffer more than
// this before calling a DetectType-style function.
const SniffLen = 512

// randomIDBytes is the number of crypto/rand bytes NewRandomID reads,
// i.e. 128 bits of entropy — enough that collisions never happen in
// practice, matching the token-hygiene invariant and the rest of the
// codebase's identifier scheme (see internal/core/storage.NewObjectKey).
const randomIDBytes = 16

// NewRandomID generates a new opaque, hex-encoded identifier suitable
// for a store row id (messages.id, attachments.id, links.id) or any
// other internal, non-secret identifier that must be unpredictable and
// never derived from message content (SR-121-3). It always uses
// crypto/rand, never math/rand or a content-derived hash.
//
// NewRandomID is not itself used for link tokens: those go through
// internal/core/link's own GenerateToken/HashToken pair, which has a
// distinct security contract (the raw token is the secret handed to a
// recipient; only its hash is ever persisted).
func NewRandomID() (string, error) {
	b := make([]byte, randomIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("spoolutil: generate random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
