package fs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/302-digital/attachra/internal/core/storage"
	"github.com/302-digital/attachra/internal/core/storage/storagetest"
)

func newTestDriver(t *testing.T) *Driver {
	t.Helper()
	drv, err := New(Config{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	return drv
}

func TestDriver_ContractSuite(t *testing.T) {
	drv := newTestDriver(t)
	i := 0
	storagetest.Run(t, drv, func() string {
		i++
		key, err := storage.NewObjectKey()
		if err != nil {
			t.Fatalf("NewObjectKey() error = %v", err)
		}
		return key
	})
}

func TestNew_RequiresBaseDir(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("New() error = nil, want error for empty base_dir")
	}
}

func TestNew_CreatesMissingBaseDir(t *testing.T) {
	base := filepath.Join(t.TempDir(), "does-not-exist")

	drv, err := New(Config{BaseDir: base})
	if err != nil {
		t.Fatalf("New() error = %v, want nil for missing base_dir", err)
	}

	info, err := os.Stat(base)
	if err != nil {
		t.Fatalf("stat base_dir after New(): %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("base_dir %q exists but is not a directory", base)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("base_dir mode = %o, want 0700", perm)
	}

	// The driver must be immediately usable against the directory it
	// just created.
	if err := drv.Put(context.Background(), "ab/ab1234567890", strReader("data"), 4); err != nil {
		t.Errorf("Put() after auto-created base_dir error = %v, want nil", err)
	}
}

func TestNew_CreatesMissingNestedBaseDir(t *testing.T) {
	// Regression for ATR-309: on a fresh install systemd's
	// StateDirectory= only creates the top-level directory
	// (e.g. /var/lib/attachra), not the configured storage.fs.base_dir
	// subpath (e.g. /var/lib/attachra/files) underneath it.
	base := filepath.Join(t.TempDir(), "state", "files")

	if _, err := New(Config{BaseDir: base}); err != nil {
		t.Fatalf("New() error = %v, want nil for missing nested base_dir", err)
	}

	info, err := os.Stat(base)
	if err != nil {
		t.Fatalf("stat base_dir after New(): %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("base_dir %q exists but is not a directory", base)
	}
}

func TestNew_BaseDirAlreadyExists(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o750); err != nil { //nolint:gosec // directory mode for a test fixture, not a file permission
		t.Fatalf("chmod pre-existing base_dir: %v", err)
	}

	if _, err := New(Config{BaseDir: base}); err != nil {
		t.Fatalf("New() error = %v, want nil for pre-existing base_dir", err)
	}

	info, err := os.Stat(base)
	if err != nil {
		t.Fatalf("stat base_dir after New(): %v", err)
	}
	// New() must not have touched the mode of a directory that already
	// existed.
	if perm := info.Mode().Perm(); perm != 0o750 {
		t.Errorf("pre-existing base_dir mode changed to %o, want unchanged 0750", perm)
	}
}

func TestNew_PermissionDeniedIsNotPaperedOver(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: permission checks are bypassed")
	}

	parent := t.TempDir()
	base := filepath.Join(parent, "no-access", "files")

	if err := os.MkdirAll(filepath.Join(parent, "no-access"), 0o000); err != nil {
		t.Fatalf("mkdir unreadable parent: %v", err)
	}
	t.Cleanup(func() {
		// Restore permissions so t.TempDir() cleanup can remove it.
		_ = os.Chmod(filepath.Join(parent, "no-access"), 0o700) //nolint:gosec // directory mode for test cleanup, not a file permission
	})

	_, err := New(Config{BaseDir: base})
	if err == nil {
		t.Fatal("New() error = nil, want permission error for base_dir under an inaccessible parent")
	}

	// Must not have created anything under the inaccessible parent. The
	// parent's own permissions block us from even statting the child
	// directly, so this only confirms New() didn't leave a usable
	// directory behind (getting anything but an error here would be
	// surprising given the parent is unreadable).
	if _, statErr := os.Stat(base); statErr == nil {
		t.Errorf("base_dir %q should not have been created and made statable", base)
	}
}

func TestNew_BaseDirMustBeDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := New(Config{BaseDir: file})
	if err == nil {
		t.Fatal("New() error = nil, want error when base_dir is a file")
	}
}

func TestPut_ShardsIntoSubdirectory(t *testing.T) {
	drv := newTestDriver(t)
	key := "ab/ab1234567890"

	if err := drv.Put(context.Background(), key, strReader("data"), 4); err != nil {
		t.Fatalf("Put() error = %v, want nil", err)
	}

	path := filepath.Join(drv.baseDir, "ab", "ab1234567890")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected object file at %q: %v", path, err)
	}
}

func TestPut_AtomicWrite_NoPartialFileVisibleOnFailure(t *testing.T) {
	drv := newTestDriver(t)
	key := "cc/cc112233"

	// A reader that fails partway through simulates an interrupted
	// upload; Put must not leave a file visible at the target path.
	r := &failingReader{failAfter: 2, data: []byte("some data that fails midway")}

	if err := drv.Put(context.Background(), key, r, int64(len(r.data))); err == nil {
		t.Fatal("Put() error = nil, want error from failing reader")
	}

	target := filepath.Join(drv.baseDir, "cc", "cc112233")
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("expected no file at %q after failed Put, stat err = %v", target, err)
	}

	// No leftover temp files either.
	entries, err := os.ReadDir(filepath.Join(drv.baseDir, "cc"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file after failed Put: %s", e.Name())
		}
	}
}

func TestResolvePath_RejectsTraversal(t *testing.T) {
	drv := newTestDriver(t)

	badKeys := []string{
		"../outside",
		"../../etc/passwd",
		"a/../../b",
		"/etc/passwd",
	}

	for _, key := range badKeys {
		t.Run(key, func(t *testing.T) {
			if _, err := drv.resolvePath(key); !errors.Is(err, storage.ErrInvalidKey) {
				t.Errorf("resolvePath(%q) error = %v, want wrapping storage.ErrInvalidKey", key, err)
			}
		})
	}
}

func TestGet_RefusesSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outsideDir := t.TempDir()
	secretPath := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(secretPath, []byte("outside-base-dir-secret"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	// Craft a symlink inside base that points outside it, at the path
	// an object key would resolve to.
	linkDir := filepath.Join(base, "sl")
	if err := os.MkdirAll(linkDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	linkPath := filepath.Join(linkDir, "sl0011223344")
	if err := os.Symlink(secretPath, linkPath); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	drv, err := New(Config{BaseDir: base})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := drv.Get(context.Background(), "sl/sl0011223344"); err == nil {
		t.Fatal("Get() through a symlink escaping base dir succeeded, want rejection")
	} else if !errors.Is(err, storage.ErrInvalidKey) {
		t.Errorf("Get() error = %v, want wrapping storage.ErrInvalidKey", err)
	}
}

// strReader is a minimal io.Reader over a fixed string, to avoid
// importing strings.NewReader repeatedly with matching size args.
func strReader(s string) io.Reader { return strings.NewReader(s) }

// failingReader returns an error after emitting failAfter bytes.
type failingReader struct {
	data      []byte
	failAfter int
	sent      int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.sent >= r.failAfter {
		return 0, errors.New("simulated read failure")
	}
	end := min(r.sent+r.failAfter-r.sent, len(r.data))
	n := copy(p, r.data[r.sent:end])
	r.sent += n
	return n, nil
}
