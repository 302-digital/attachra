package config

import (
	"encoding"
	"fmt"
	"testing"
)

func TestSecret_RedactsInAllFormats(t *testing.T) {
	s := Secret("super-secret-value")

	tests := []struct {
		name string
		got  string
	}{
		{"String()", s.String()},
		{"%v", fmt.Sprintf("%v", s)},
		{"%q", fmt.Sprintf("%q", s)},
		{"%#v", fmt.Sprintf("%#v", s)},
		{"Sprint", fmt.Sprint(s)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got == string(s) {
				t.Fatalf("%s leaked the raw secret value: %q", tt.name, tt.got)
			}
			if want := redacted; tt.got != want && tt.got != fmt.Sprintf("%q", want) {
				t.Errorf("%s = %q, want redacted placeholder %q", tt.name, tt.got, want)
			}
		})
	}
}

func TestSecret_MarshalText(t *testing.T) {
	var s Secret = "super-secret-value"

	var _ encoding.TextMarshaler = s // compile-time contract check

	b, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	if string(b) != redacted {
		t.Errorf("MarshalText() = %q, want %q", b, redacted)
	}
}

func TestSecret_Value(t *testing.T) {
	const want = "super-secret-value"
	s := Secret(want)

	if got := s.Value(); got != want {
		t.Errorf("Value() = %q, want %q", got, want)
	}
}

func TestSecret_Empty(t *testing.T) {
	tests := []struct {
		name string
		s    Secret
		want bool
	}{
		{"empty", Secret(""), true},
		{"non-empty", Secret("x"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Empty(); got != tt.want {
				t.Errorf("Empty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSecret_ErrorWrappingDoesNotLeak(t *testing.T) {
	s := Secret("super-secret-value")
	err := fmt.Errorf("failed to connect with credential %v", s)

	if got := err.Error(); got != "failed to connect with credential [REDACTED]" {
		t.Errorf("error message leaked secret: %q", got)
	}
}
