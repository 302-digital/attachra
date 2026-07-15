package storage

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned by Get, Delete and Stat when no object
// exists for the given key. Drivers must translate their
// backend-specific "not found" signal (e.g. an S3 NoSuchKey error or
// a filesystem os.ErrNotExist) into this typed error so callers in
// internal/core can distinguish "missing object" from any other
// storage failure without depending on driver internals.
var ErrNotFound = errors.New("storage: object not found")

// ObjectInfo describes an existing object's storage-level metadata.
// It intentionally carries no file name, sender, or recipient
// information (SR-121-3, ADR-011): that data lives exclusively in the
// metadata database, keyed by the same opaque object key used here.
type ObjectInfo struct {
	// Key is the opaque object key, as produced by NewObjectKey.
	Key string
	// Size is the object's size in bytes.
	Size int64
}

// Driver is the domain interface for storing and retrieving
// attachment payloads in an object storage backend (see ADR-007).
// Implementations live under internal/core/storage/<name> (e.g. s3,
// fs) and must not depend on any adapter-specific code (ADR-002).
//
// All methods must be safe for concurrent use by multiple goroutines.
//
// Keys passed to any method are expected to be opaque identifiers
// produced by NewObjectKey; implementations must reject any key that
// is not well-formed (e.g. path traversal attempts) rather than
// silently normalizing it.
type Driver interface {
	// Put stores size bytes read from r under key, streaming the
	// data without buffering the whole payload in memory
	// (CLAUDE.md invariant #4). It must not succeed partially: on
	// error, no object (or a truncated/partial one) must be left
	// reachable under key.
	Put(ctx context.Context, key string, r io.Reader, size int64) error

	// Get returns a stream over the object stored under key. The
	// caller owns the returned io.ReadCloser and must Close it. If no
	// object exists for key, Get returns an error wrapping
	// ErrNotFound.
	Get(ctx context.Context, key string) (io.ReadCloser, error)

	// Delete removes the object stored under key. If no object
	// exists for key, Delete returns an error wrapping ErrNotFound.
	Delete(ctx context.Context, key string) error

	// Stat returns storage-level metadata for the object stored under
	// key, without reading its contents. If no object exists for
	// key, Stat returns an error wrapping ErrNotFound.
	Stat(ctx context.Context, key string) (ObjectInfo, error)
}
