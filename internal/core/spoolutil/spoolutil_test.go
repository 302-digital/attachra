package spoolutil

import (
	"encoding/hex"
	"testing"
)

func TestConstants(t *testing.T) {
	if SpoolMemThreshold != 256*1024 {
		t.Errorf("SpoolMemThreshold = %d, want %d", SpoolMemThreshold, 256*1024)
	}
	if SniffLen != 512 {
		t.Errorf("SniffLen = %d, want %d", SniffLen, 512)
	}
}

func TestNewRandomID(t *testing.T) {
	id, err := NewRandomID()
	if err != nil {
		t.Fatalf("NewRandomID() error = %v", err)
	}

	// 16 bytes (128 bits) hex-encoded is 32 hex characters.
	if len(id) != 32 {
		t.Errorf("NewRandomID() len = %d, want 32", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("NewRandomID() = %q is not valid hex: %v", id, err)
	}
}

func TestNewRandomID_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := NewRandomID()
		if err != nil {
			t.Fatalf("NewRandomID() error = %v", err)
		}
		if seen[id] {
			t.Fatalf("NewRandomID() produced duplicate id %q", id)
		}
		seen[id] = true
	}
}
