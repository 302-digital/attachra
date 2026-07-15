package policy

import (
	"testing"
	"time"
)

// TestParseDuration covers §2.4: suffixes s/m/h/d (d = 24h), no
// fractional or composite forms, and "0" is always rejected.
func TestParseDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"30d", 30 * 24 * time.Hour, false},
		{"48h", 48 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"1s", 1 * time.Second, false},
		{"1d", 24 * time.Hour, false},
		{"0", 0, true},  // explicitly forbidden
		{"0d", 0, true}, // zero magnitude, any unit
		{"", 0, true},
		{"1d12h", 0, true}, // composite, not supported
		{"1.5h", 0, true},  // fractional, not supported
		{"-1d", 0, true},   // negative
		{"d", 0, true},     // missing numeric value
		{"30w", 0, true},   // unsupported unit
		{"30", 0, true},    // missing suffix
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseDuration(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseDuration(%q) = %v, nil; want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDuration(%q) returned error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseDuration(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
