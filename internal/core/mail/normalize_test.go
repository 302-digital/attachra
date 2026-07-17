package mail

import "testing"

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "alice@example.com", "alice@example.com"},
		{"angle brackets", "<alice@example.com>", "alice@example.com"},
		{"mixed case local and domain", "Alice@EXAMPLE.com", "alice@example.com"},
		{"angle brackets and mixed case", "<Alice@EXAMPLE.com>", "alice@example.com"},
		{"surrounding whitespace", "  alice@example.com  ", "alice@example.com"},
		{"whitespace outside brackets", "  <alice@example.com>  ", "alice@example.com"},
		{"whitespace inside brackets", "< alice@example.com >", "alice@example.com"},
		{"plus-tag preserved", "Alice+Newsletter@EXAMPLE.com", "alice+newsletter@example.com"},
		{"plus-tag with brackets", "<alice+newsletter@example.com>", "alice+newsletter@example.com"},
		{"null bounce sender", "<>", ""},
		{"empty string", "", ""},
		{"only whitespace", "   ", ""},
		{"unicode/IDN domain lower-cased", "User@BÜCHER.example", "user@bücher.example"},
		{"single leading bracket only (malformed, left as-is but lower-cased)", "<alice@example.com", "<alice@example.com"},
		{"single trailing bracket only (malformed, left as-is but lower-cased)", "alice@example.com>", "alice@example.com>"},
		{"no domain", "postmaster", "postmaster"},
		{"already lowercase idempotent", "alice@example.com", "alice@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeAddress(tt.in)
			if got != tt.want {
				t.Errorf("NormalizeAddress(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeAddressIdempotent verifies applying NormalizeAddress
// twice never changes the result further, a property both the query-
// time SQL matching (internal/core/store/sqlite) and the ATR-293
// migration rely on: normalizing already-normalized data must be a
// no-op.
func TestNormalizeAddressIdempotent(t *testing.T) {
	inputs := []string{
		"alice@example.com",
		"<Alice@EXAMPLE.com>",
		"  <Bob+tag@Example.COM>  ",
		"",
		"<>",
	}
	for _, in := range inputs {
		once := NormalizeAddress(in)
		twice := NormalizeAddress(once)
		if once != twice {
			t.Errorf("NormalizeAddress(%q) = %q, but NormalizeAddress(that) = %q, want idempotent", in, once, twice)
		}
	}
}
