package milter

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

func TestSpool_SmallBodyStaysInMemory(t *testing.T) {
	s := newSpool(0)
	data := []byte("hello world")

	if _, err := s.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if s.file != nil {
		t.Fatal("expected small body to stay in memory, but it spilled to disk")
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

	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestSpool_LargeBodySpillsToDisk(t *testing.T) {
	s := newSpool(0)

	chunk := bytes.Repeat([]byte("x"), 4096)
	total := 0
	for total < spoolMemThreshold+1 {
		if _, err := s.Write(chunk); err != nil {
			t.Fatalf("Write: %v", err)
		}
		total += len(chunk)
	}

	if s.file == nil {
		t.Fatal("expected body larger than threshold to spill to disk")
	}

	path := s.file.Name()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected spool temp file to exist: %v", err)
	}

	r, err := s.Reader()
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != total {
		t.Errorf("read %d bytes, want %d", len(got), total)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected temp file to be removed after Close, stat err = %v", err)
	}
}

func TestSpool_EnforcesMaxSize(t *testing.T) {
	s := newSpool(10)

	if _, err := s.Write([]byte("0123456789")); err != nil {
		t.Fatalf("Write within limit: %v", err)
	}

	_, err := s.Write([]byte("x"))
	if err == nil {
		t.Fatal("expected error writing past maxSize, got nil")
	}
	if !errors.Is(err, errSpoolTooLarge) {
		t.Errorf("error = %v, want wrapping errSpoolTooLarge", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSpool_CloseIsIdempotent(t *testing.T) {
	s := newSpool(0)
	chunk := bytes.Repeat([]byte("y"), spoolMemThreshold+1)
	if _, err := s.Write(chunk); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSpool_Len(t *testing.T) {
	s := newSpool(0)
	if _, err := s.Write([]byte("abc")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := s.Write([]byte("de")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := s.Len(); got != 5 {
		t.Errorf("Len() = %d, want 5", got)
	}
	_ = s.Close()
}
