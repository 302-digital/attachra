package pipeline

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/302-digital/attachra/internal/core/spoolutil"
)

func TestSpoolReader_SmallStreamStaysInMemory(t *testing.T) {
	data := []byte("hello world")
	s, err := spoolReader(bytes.NewReader(data), "")
	if err != nil {
		t.Fatalf("spoolReader: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.file != nil {
		t.Fatal("expected small stream to stay in memory, but it spilled to disk")
	}

	r, err := s.Reader()
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Reader() content = %q, want %q", got, data)
	}
}

// TestSpoolReader_SpillsToConfiguredDir verifies that spoolReader's
// dir argument (ATR-262) is honored: the temp file it spills to
// once the in-memory threshold is crossed must land inside the
// configured directory, not the OS default temporary directory.
func TestSpoolReader_SpillsToConfiguredDir(t *testing.T) {
	dir := t.TempDir()
	data := bytes.Repeat([]byte("a"), spoolutil.SpoolMemThreshold+1)

	s, err := spoolReader(bytes.NewReader(data), dir)
	if err != nil {
		t.Fatalf("spoolReader: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.file == nil {
		t.Fatal("expected stream larger than threshold to spill to disk")
	}

	gotDir := s.file.Name()[:len(dir)]
	if gotDir != dir {
		t.Errorf("spool temp file %q was not created inside configured dir %q", s.file.Name(), dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read spool dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one spilled file in configured spool dir, got %d", len(entries))
	}

	r, err := s.Reader()
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("spilled content did not round-trip byte-for-byte")
	}
}

func TestSpoolReader_DefaultDirUsesOSTemp(t *testing.T) {
	data := bytes.Repeat([]byte("b"), spoolutil.SpoolMemThreshold+1)

	s, err := spoolReader(bytes.NewReader(data), "")
	if err != nil {
		t.Fatalf("spoolReader: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.file == nil {
		t.Fatal("expected stream larger than threshold to spill to disk")
	}
	wantPrefix := os.TempDir()
	if got := s.file.Name(); len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Errorf("spool temp file %q was not created under os.TempDir() %q", got, wantPrefix)
	}
}
