package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// keyRandomBytes is the number of random bytes used to build an
// object key, giving 128 bits of entropy — matching the token-hygiene
// invariant's minimum bar for unguessable identifiers, even though
// object keys (unlike link tokens) are never exposed to end users.
const keyRandomBytes = 16

// shardPrefixLen is the number of leading hex characters of the
// random ID used as a shard directory prefix (e.g. "aa/", "1f/"),
// keeping any single directory from accumulating an unbounded number
// of entries as the object count grows.
const shardPrefixLen = 2

// NewObjectKey generates a new opaque, unguessable object key for
// storing an attachment payload.
//
// The key is derived solely from crypto/rand output: it never
// contains the original file name, sender address, or recipient
// address (SR-121-3). That information belongs exclusively to the
// metadata database (ADR-011), addressed by this same key. The key
// is prefixed by a fixed-width hex shard so drivers that map keys
// onto a directory tree (see fs.Driver) or bucket layout do not end
// up with a single flat namespace of millions of entries.
//
// The returned key has the form "<shard>/<id>", e.g.
// "a1/a1b2c3d4e5f6...". It contains only lowercase hex digits and
// '/', so it is always a valid, non-traversing relative path
// component for filesystem-backed drivers and a valid S3 object key.
func NewObjectKey() (string, error) {
	buf := make([]byte, keyRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("storage: generate object key: %w", err)
	}

	id := hex.EncodeToString(buf)
	shard := id[:shardPrefixLen]

	return shard + "/" + id, nil
}
