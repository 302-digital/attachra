package storage

import (
	"errors"
	"path"
	"strings"
)

// ErrInvalidKey is returned by driver implementations when a caller
// passes a key that is not a well-formed opaque object key (e.g. it
// attempts path traversal, is absolute, or is empty). Drivers must
// reject such keys outright rather than normalizing them, per
// SR-122-1 / SR-122-2.
var ErrInvalidKey = errors.New("storage: invalid object key")

// ValidateKey checks that key is a well-formed relative object key as
// produced by NewObjectKey: non-empty, using '/' separators, with no
// "." or ".." path segments and no absolute-path or backslash
// component. Driver implementations (fs, s3) call this before using
// key to build a backend-specific path, so that a malicious or
// malformed key can never escape the intended storage root
// (SR-122-1) or reach an unintended backend key.
//
// ValidateKey is intentionally stricter than plain filepath.Clean
// traversal checks: it rejects any key containing "..", even one
// that would not currently escape the base directory, since such
// keys are never produced by NewObjectKey and their presence
// indicates either a bug or an attack.
func ValidateKey(key string) error {
	if key == "" {
		return ErrInvalidKey
	}
	if strings.ContainsRune(key, 0) {
		return ErrInvalidKey
	}
	if strings.Contains(key, "\\") {
		return ErrInvalidKey
	}
	if path.IsAbs(key) {
		return ErrInvalidKey
	}

	for _, segment := range strings.Split(key, "/") {
		switch segment {
		case "":
			return ErrInvalidKey
		case ".", "..":
			return ErrInvalidKey
		}
	}

	return nil
}
