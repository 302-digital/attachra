package link

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// idRandomBytes is the number of random bytes used to build a
// store-internal row identifier (messages.id, attachments.id,
// links.id). These IDs are never exposed to recipients (unlike link
// tokens, which use GenerateToken/HashToken); 128 bits of entropy is
// used anyway so identifiers never collide in practice and stay
// consistent with the rest of the codebase's identifier scheme (see
// internal/core/storage.NewObjectKey).
const idRandomBytes = 16

// newID generates a new opaque, hex-encoded row identifier.
func newID() (string, error) {
	buf := make([]byte, idRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("link: generate id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
