package link

import (
	"fmt"

	"github.com/302-digital/attachra/internal/core/spoolutil"
)

// newID generates a new opaque, hex-encoded row identifier (128 bits
// of entropy via spoolutil.NewRandomID). These IDs are never
// exposed to recipients (unlike link tokens, which use
// GenerateToken/HashToken); 128 bits of entropy is used anyway so
// identifiers never collide in practice and stay consistent with the
// rest of the codebase's identifier scheme (see
// internal/core/storage.NewObjectKey).
func newID() (string, error) {
	id, err := spoolutil.NewRandomID()
	if err != nil {
		return "", fmt.Errorf("link: generate id: %w", err)
	}
	return id, nil
}
