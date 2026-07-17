package link

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// MinTokenBytes is the minimum number of random bytes a token may be
// generated with, giving the 128-bit floor the token-hygiene invariant
// and SR-124-1 require (16 bytes = 128 bits). Callers may request more
// entropy but never less.
const MinTokenBytes = 16

// GenerateToken returns a new bearer token with numBytes bytes of
// crypto/rand entropy (numBytes must be >= MinTokenBytes), encoded
// URL-safe without padding (SR-124-1) so it can be embedded directly
// in a download URL path segment without further escaping.
//
// The returned token is the only place the raw secret ever exists
// outside the recipient's copy of it: callers must persist only its
// HashToken result (the token-hygiene invariant, SR-124-2) and must not log
// or otherwise retain the raw token after handing it to the caller
// that embeds it in the rewritten message body.
func GenerateToken(numBytes int) (string, error) {
	if numBytes < MinTokenBytes {
		return "", fmt.Errorf("link: generate token: numBytes %d is below the %d-byte (128-bit) minimum", numBytes, MinTokenBytes)
	}

	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("link: generate token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken returns the hex-encoded SHA-256 hash of token, the only
// form of a token ever written to the metadata store (the token-hygiene
// invariant, SR-124-2). Hashing (rather than encrypting or storing
// in the clear) means a database compromise does not expose usable
// bearer tokens, while lookup by exact hash match remains a single
// indexed equality query — no per-row comparison is needed to resolve
// a token, so there is no timing side-channel from a linear scan.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
