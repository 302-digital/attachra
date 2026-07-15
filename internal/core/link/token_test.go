package link

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestGenerateTokenEntropyAndUniqueness is a sanity check for
// SR-124-1: it does not attempt to prove 128 bits of entropy
// statistically (that would need a much larger sample and dedicated
// randomness test suite), but does verify the byte length matches the
// requested entropy and that a reasonably large batch of generated
// tokens never collides, which would immediately fail if GenerateToken
// were, say, always returning the same value or using a
// low-entropy source.
func TestGenerateTokenEntropyAndUniqueness(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)

	for i := 0; i < n; i++ {
		tok, err := GenerateToken(MinTokenBytes)
		if err != nil {
			t.Fatalf("GenerateToken() error = %v, want nil", err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("GenerateToken() produced a duplicate token after %d calls: %q", i, tok)
		}
		seen[tok] = struct{}{}

		decoded, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("token %q is not valid URL-safe base64 without padding: %v", tok, err)
		}
		if len(decoded) != MinTokenBytes {
			t.Fatalf("decoded token length = %d bytes, want %d (128 bits)", len(decoded), MinTokenBytes)
		}

		if strings.ContainsAny(tok, "+/=") {
			t.Fatalf("token %q contains non-URL-safe characters", tok)
		}
	}
}

func TestGenerateTokenRejectsBelowMinimum(t *testing.T) {
	if _, err := GenerateToken(MinTokenBytes - 1); err == nil {
		t.Fatalf("GenerateToken(%d) error = nil, want an error (below 128-bit minimum)", MinTokenBytes-1)
	}
}

func TestGenerateTokenAcceptsAboveMinimum(t *testing.T) {
	tok, err := GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken(32) error = %v, want nil", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("token is not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded length = %d, want 32", len(decoded))
	}
}

func TestHashTokenDeterministicAndDistinct(t *testing.T) {
	tokA, err := GenerateToken(MinTokenBytes)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v, want nil", err)
	}
	tokB, err := GenerateToken(MinTokenBytes)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v, want nil", err)
	}

	firstHash := HashToken(tokA)
	secondHash := HashToken(tokA)
	if firstHash != secondHash {
		t.Errorf("HashToken(tokA) is not deterministic across calls: %q != %q", firstHash, secondHash)
	}
	if HashToken(tokA) == HashToken(tokB) {
		t.Errorf("HashToken(tokA) == HashToken(tokB) for distinct tokens, want distinct hashes")
	}
	if HashToken(tokA) == tokA {
		t.Errorf("HashToken(tokA) returned the token unchanged, want a SHA-256 hash")
	}

	// 32 bytes of SHA-256 output, hex-encoded, is 64 hex characters.
	if got := len(HashToken(tokA)); got != 64 {
		t.Errorf("len(HashToken(...)) = %d, want 64 (hex-encoded SHA-256)", got)
	}
}
