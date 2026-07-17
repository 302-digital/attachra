package sqlite

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnsureDBDir_CreatesMissingNestedDir is the sqlite-side regression
// for ATR-310: a database.path whose parent directory does not exist
// yet (e.g. a systemd StateDirectory= that only created the top-level
// state directory) must be created automatically, mode 0700, mirroring
// the fs storage driver's own ATR-309 fix
// (internal/core/storage/fs.New's TestNew_CreatesMissingNestedBaseDir).
func TestEnsureDBDir_CreatesMissingNestedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "db")
	path := filepath.Join(dir, "attachra.db")

	if err := ensureDBDir(path); err != nil {
		t.Fatalf("ensureDBDir(%q) error = %v, want nil", path, err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat database directory after ensureDBDir(): %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("database directory %q exists but is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("database directory mode = %o, want 0700", perm)
	}
}

// TestEnsureDBDir_AlreadyExists asserts ensureDBDir does not touch the
// mode of a pre-existing directory.
func TestEnsureDBDir_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // directory mode for a test fixture, not a file permission
		t.Fatalf("chmod pre-existing directory: %v", err)
	}
	path := filepath.Join(dir, "attachra.db")

	if err := ensureDBDir(path); err != nil {
		t.Fatalf("ensureDBDir(%q) error = %v, want nil", path, err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat directory after ensureDBDir(): %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o750 {
		t.Errorf("pre-existing directory mode changed to %o, want unchanged 0750", perm)
	}
}

// TestEnsureDBDir_ParentIsNotADirectory asserts ensureDBDir fails fast
// (rather than trying to MkdirAll through it) when a path component
// that should be a directory is actually a regular file.
func TestEnsureDBDir_ParentIsNotADirectory(t *testing.T) {
	base := t.TempDir()
	notADir := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	path := filepath.Join(notADir, "nested", "attachra.db")

	if err := ensureDBDir(path); err == nil {
		t.Fatal("ensureDBDir() error = nil, want error when a path component is a regular file")
	}
}

// TestEnsureDBDir_PermissionDeniedIsNotPaperedOver asserts a stat
// failure on the directory other than ENOENT (e.g. EACCES on an
// inaccessible parent component) is returned as-is instead of being
// treated as "missing, so create it" - matching
// internal/core/storage/fs.New's TestNew_PermissionDeniedIsNotPaperedOver.
func TestEnsureDBDir_PermissionDeniedIsNotPaperedOver(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: permission checks are bypassed")
	}

	parent := t.TempDir()
	noAccess := filepath.Join(parent, "no-access")
	if err := os.MkdirAll(noAccess, 0o000); err != nil {
		t.Fatalf("mkdir unreadable parent: %v", err)
	}
	t.Cleanup(func() {
		// Restore permissions so t.TempDir() cleanup can remove it.
		_ = os.Chmod(noAccess, 0o700) //nolint:gosec // directory mode for test cleanup, not a file permission
	})

	dir := filepath.Join(noAccess, "db")
	path := filepath.Join(dir, "attachra.db")

	if err := ensureDBDir(path); err == nil {
		t.Fatal("ensureDBDir() error = nil, want permission error for a directory under an inaccessible parent")
	}

	if _, statErr := os.Stat(dir); statErr == nil {
		t.Errorf("database directory %q should not have been created and made statable", dir)
	}
}
