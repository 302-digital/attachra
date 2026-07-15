package pipeline

import (
	"bytes"
	"io"
	"testing"
)

// TestLimitedReader_ExactlyAtLimit verifies that content whose total
// size exactly equals the configured limit is read in full without
// error: only content that actually exceeds the limit should be
// treated as oversized. This guards against an off-by-one where
// exhausting the budget was conflated with exceeding it.
func TestLimitedReader_ExactlyAtLimit(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 100)
	lr := &limitedReader{r: bytes.NewReader(data), remaining: 100}

	got, err := io.ReadAll(lr)
	if err != nil {
		t.Fatalf("ReadAll() error = %v, want nil for exact-boundary content", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content = %q, want %q", got, data)
	}
}

// TestLimitedReader_OverLimit verifies that content exceeding the
// configured limit by even one byte is rejected.
func TestLimitedReader_OverLimit(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 101)
	lr := &limitedReader{r: bytes.NewReader(data), remaining: 100}

	_, err := io.ReadAll(lr)
	if err == nil {
		t.Fatal("ReadAll() error = nil, want an error for over-limit content")
	}
}

// TestLimitedReader_WellUnderLimit is a sanity check that ordinary,
// well-under-budget content round-trips unchanged.
func TestLimitedReader_WellUnderLimit(t *testing.T) {
	data := []byte("hello")
	lr := &limitedReader{r: bytes.NewReader(data), remaining: 1024}

	got, err := io.ReadAll(lr)
	if err != nil {
		t.Fatalf("ReadAll() error = %v, want nil", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content = %q, want %q", got, data)
	}
}
