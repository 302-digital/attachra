package storage

import (
	"strings"
	"testing"
)

func TestNewObjectKey_Format(t *testing.T) {
	key, err := NewObjectKey()
	if err != nil {
		t.Fatalf("NewObjectKey() error = %v, want nil", err)
	}

	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		t.Fatalf("NewObjectKey() = %q, want \"<shard>/<id>\" form", key)
	}
	shard, id := parts[0], parts[1]

	if len(shard) != shardPrefixLen {
		t.Errorf("shard = %q, want length %d", shard, shardPrefixLen)
	}
	if !strings.HasPrefix(id, shard) {
		t.Errorf("id %q does not start with its own shard prefix %q", id, shard)
	}
	if len(id) != keyRandomBytes*2 {
		t.Errorf("id length = %d, want %d (hex of %d random bytes)", len(id), keyRandomBytes*2, keyRandomBytes)
	}

	if err := ValidateKey(key); err != nil {
		t.Errorf("ValidateKey(%q) = %v, want nil for a freshly generated key", key, err)
	}
}

func TestNewObjectKey_Unique(t *testing.T) {
	seen := make(map[string]bool)
	const n = 1000

	for i := 0; i < n; i++ {
		key, err := NewObjectKey()
		if err != nil {
			t.Fatalf("NewObjectKey() error = %v", err)
		}
		if seen[key] {
			t.Fatalf("NewObjectKey() produced duplicate key %q", key)
		}
		seen[key] = true
	}
}

func TestNewObjectKey_NoIdentifyingData(t *testing.T) {
	// SR-121-3: the key must never be derived from or contain
	// caller-supplied identifying strings. Since NewObjectKey takes
	// no arguments, this is true by construction; this test guards
	// the signature against regressions that would add such a
	// parameter without review.
	key, err := NewObjectKey()
	if err != nil {
		t.Fatalf("NewObjectKey() error = %v", err)
	}
	for _, forbidden := range []string{"filename", "sender", "recipient", "@"} {
		if strings.Contains(strings.ToLower(key), forbidden) {
			t.Errorf("NewObjectKey() = %q unexpectedly contains %q", key, forbidden)
		}
	}
}

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"empty", "", true},
		{"valid generated shape", "ab/ab1234567890", false},
		{"valid flat", "abcdef", false},
		{"dot segment", "ab/./ab1234", true},
		{"dotdot segment", "ab/../ab1234", true},
		{"leading dotdot", "../etc/passwd", true},
		{"absolute", "/etc/passwd", true},
		{"backslash", `ab\..\etc`, true},
		{"double slash empty segment", "ab//ab1234", true},
		{"trailing slash", "ab/ab1234/", true},
		{"nul byte", "ab/ab1234\x00", true},
		{"just dotdot", "..", true},
		{"just dot", ".", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}
