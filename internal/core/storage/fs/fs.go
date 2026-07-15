// Package fs implements storage.Driver on top of the local
// filesystem (US-5.2, ATR-176), for installations that do not want to
// operate an S3-compatible service (see docs/Attachra_Backlog.md).
package fs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/302-digital/attachra/internal/core/storage"
)

// DriverName is the name this driver registers itself under via
// storage.Register, and the expected value of config.StorageConfig.Driver
// to select it.
const DriverName = "fs"

func init() {
	storage.Register(DriverName, func(cfg any) (storage.Driver, error) {
		c, ok := cfg.(Config)
		if !ok {
			return nil, fmt.Errorf("fs: New: expected fs.Config, got %T", cfg)
		}
		return New(c)
	})
}

// Config configures the filesystem driver.
type Config struct {
	// BaseDir is the root directory under which all objects are
	// stored. If it does not exist yet, New creates it (mode 0700);
	// if it exists, it must be a directory. Every object path is
	// validated to resolve inside BaseDir (SR-122-1); any key that
	// would escape it is rejected.
	BaseDir string
}

// Driver implements storage.Driver by storing each object as a
// regular file under Config.BaseDir, mirroring the key's own "/"
// separators as the directory layout (so the shard prefix from
// storage.NewObjectKey becomes a subdirectory).
type Driver struct {
	baseDir string
}

// New constructs a filesystem Driver rooted at cfg.BaseDir. BaseDir
// must be a non-empty path; if it does not exist, New creates it
// (mode 0700). Any other stat failure (e.g. a permission error) is
// returned as-is rather than papered over.
func New(cfg Config) (*Driver, error) {
	if cfg.BaseDir == "" {
		return nil, errors.New("fs: base_dir must not be empty")
	}

	base, err := filepath.Abs(cfg.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("fs: resolve base_dir %q: %w", cfg.BaseDir, err)
	}

	info, err := os.Stat(base)
	switch {
	case err == nil:
		if !info.IsDir() {
			return nil, fmt.Errorf("fs: base_dir %q is not a directory", cfg.BaseDir)
		}
	case errors.Is(err, fs.ErrNotExist):
		// The directory itself is missing (as opposed to a permission or
		// other stat failure): create it. This covers fresh installs
		// where systemd's StateDirectory= only creates the top-level
		// state directory, not this driver's configured base_dir
		// subpath, which would otherwise crash-loop the service before
		// it ever writes an object (ATR-309). Any other stat error
		// (e.g. EACCES on a parent component) still fails fast below
		// instead of attempting to silently create part of the path.
		if err := os.MkdirAll(base, 0o700); err != nil {
			return nil, fmt.Errorf("fs: create base_dir %q: %w", cfg.BaseDir, err)
		}
	default:
		return nil, fmt.Errorf("fs: base_dir %q: %w", cfg.BaseDir, err)
	}

	return &Driver{baseDir: base}, nil
}

// Ping is a lightweight readiness probe (US-7.2/T-7.2.3, ATR-194): it
// confirms d.baseDir still exists and is a directory, without reading
// or writing any object. It is not part of storage.Driver's interface
// (a filesystem-specific readiness check has no S3-side equivalent
// call); internal/adapters/http's readiness handler type-asserts for
// this method opportunistically (see its storagePinger interface).
func (d *Driver) Ping(_ context.Context) error {
	info, err := os.Stat(d.baseDir)
	if err != nil {
		return fmt.Errorf("fs: ping: base_dir %q: %w", d.baseDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("fs: ping: base_dir %q is not a directory", d.baseDir)
	}
	return nil
}

// resolvePath validates key and returns the absolute filesystem path
// it maps to under d.baseDir (SR-122-1). It first rejects any key
// that is not a well-formed opaque object key via storage.ValidateKey
// (no "..", no absolute path, no backslash, no NUL). As defense in
// depth, it then independently re-derives the path relative to
// d.baseDir with filepath.Rel and confirms it does not start with
// ".." or equal "..", so a bug in ValidateKey alone could never
// result in a path escaping the base directory.
func (d *Driver) resolvePath(key string) (string, error) {
	if err := storage.ValidateKey(key); err != nil {
		return "", fmt.Errorf("fs: %s: %w", key, err)
	}

	cleaned := filepath.Join(d.baseDir, filepath.FromSlash(key))

	rel, err := filepath.Rel(d.baseDir, cleaned)
	if err != nil {
		return "", fmt.Errorf("fs: key %q escapes base dir: %w", key, storage.ErrInvalidKey)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("fs: key %q escapes base dir: %w", key, storage.ErrInvalidKey)
	}

	return cleaned, nil
}

// checkNoSymlink verifies that no path component from d.baseDir down
// to path is itself a symlink, approximating O_NOFOLLOW semantics
// (SR-122-1) for platforms/cases where the O_NOFOLLOW open flag alone
// would not cover intermediate directory components. The final path
// component is allowed to not exist yet (the caller may be about to
// create it).
func checkNoSymlink(baseDir, path string) error {
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return fmt.Errorf("fs: resolve relative path: %w", err)
	}
	if rel == "." {
		return nil
	}

	segments := strings.Split(filepath.ToSlash(rel), "/")
	current := baseDir
	for i, seg := range segments {
		current = filepath.Join(current, seg)

		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				if i == len(segments)-1 {
					return nil // leaf may not exist yet
				}
				return fmt.Errorf("fs: %w", storage.ErrNotFound)
			}
			return fmt.Errorf("fs: stat %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("fs: %q is a symlink, refusing to follow: %w", current, storage.ErrInvalidKey)
		}
	}
	return nil
}

// Put implements storage.Driver. It writes to a temporary file in the
// same target directory, then atomically renames it into place
// (SR-122-1), so a concurrent Get never observes a partially written
// object and a failed Put never leaves a corrupt file at key's path.
func (d *Driver) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	target, err := d.resolvePath(key)
	if err != nil {
		return err
	}

	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("fs: create directory %q: %w", dir, err)
	}
	if err := checkNoSymlink(d.baseDir, dir); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("fs: create temp file in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()

	if err := writeAndClose(tmp, r, size); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, target); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fs: rename %q to %q: %w", tmpPath, target, err)
	}

	return nil
}

// writeAndClose copies r into f, then closes f, returning a wrapped
// error from whichever step failed first. If size is non-negative,
// the number of bytes written must match it exactly.
func writeAndClose(f *os.File, r io.Reader, size int64) error {
	n, err := io.Copy(f, r)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("fs: write object: %w", err)
	}
	if size >= 0 && n != size {
		_ = f.Close()
		return fmt.Errorf("fs: write object: wrote %d bytes, want %d", n, size)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("fs: close temp file: %w", err)
	}
	return nil
}

// Get implements storage.Driver, returning a stream over the object's
// contents without reading it into memory.
func (d *Driver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	target, err := d.resolvePath(key)
	if err != nil {
		return nil, err
	}
	if err := checkNoSymlink(d.baseDir, target); err != nil {
		return nil, err
	}

	f, err := os.Open(target) //nolint:gosec // target is validated by resolvePath to be contained within d.baseDir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("fs: %s: %w", key, storage.ErrNotFound)
		}
		return nil, fmt.Errorf("fs: open %q: %w", key, err)
	}
	return f, nil
}

// Delete implements storage.Driver.
func (d *Driver) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	target, err := d.resolvePath(key)
	if err != nil {
		return err
	}
	if err := checkNoSymlink(d.baseDir, target); err != nil {
		return err
	}

	if err := os.Remove(target); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("fs: %s: %w", key, storage.ErrNotFound)
		}
		return fmt.Errorf("fs: remove %q: %w", key, err)
	}
	return nil
}

// Stat implements storage.Driver.
func (d *Driver) Stat(ctx context.Context, key string) (storage.ObjectInfo, error) {
	if err := ctx.Err(); err != nil {
		return storage.ObjectInfo{}, err
	}

	target, err := d.resolvePath(key)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	if err := checkNoSymlink(d.baseDir, target); err != nil {
		return storage.ObjectInfo{}, err
	}

	info, err := os.Stat(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return storage.ObjectInfo{}, fmt.Errorf("fs: %s: %w", key, storage.ErrNotFound)
		}
		return storage.ObjectInfo{}, fmt.Errorf("fs: stat %q: %w", key, err)
	}

	return storage.ObjectInfo{Key: key, Size: info.Size()}, nil
}
