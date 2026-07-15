package policy

import "testing"

// TestParseBound covers the unit table in §2.3.2: decimal KB/MB/GB
// (base 1000) vs binary KiB/MiB/GiB (base 1024), bare integers, and
// malformed inputs.
func TestParseBound(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"0", 0, false},
		{"512", 512, false},
		{"10MB", 10_000_000, false},
		{"512KB", 512_000, false},
		{"1GB", 1_000_000_000, false},
		{"1KiB", 1024, false},
		{"1MiB", 1024 * 1024, false},
		{"1GiB", 1024 * 1024 * 1024, false},
		{"1kb", 1000, false},         // case-insensitive
		{"1Kb", 1000, false},         // case-insensitive
		{"1kib", 1024, false},        // case-insensitive, still distinct from KB
		{"10 MB", 10_000_000, false}, // internal space before unit is tolerated
		{"", 0, true},
		{"MB", 0, true},   // missing numeric value
		{"10XB", 0, true}, // unknown unit
		{"-5MB", 0, true}, // negative
		{"-1", 0, true},   // negative bare integer
		{"abc", 0, true},  // not a number at all
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseBound(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseBound(%q) = %d, nil; want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseBound(%q) returned error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseBound(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestBound_UnmarshalYAML_PlainInteger covers the "or integer in
// bytes" alternative form from §2.3.2.
func TestBound_UnmarshalYAML_PlainInteger(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "plain int size"
    when:
      attachment:
        size: { min: 1000, max: 2000 }
    then:
      action: pass
default:
  action: pass
`)
	p, warnings, err := Parse(data, "plain-int-size.yaml")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	size := p.Rules[0].When.Attachment.Size
	if size.Min.Bytes() != 1000 {
		t.Errorf("Min = %d, want 1000", size.Min.Bytes())
	}
	if size.Max.Bytes() != 2000 {
		t.Errorf("Max = %d, want 2000", size.Max.Bytes())
	}
}

func TestBound_UnmarshalYAML_NegativeIntegerRejected(t *testing.T) {
	data := []byte(`
version: 1
name: "policy"
rules:
  - name: "negative size"
    when:
      attachment:
        size: { min: -1 }
    then:
      action: pass
default:
  action: pass
`)
	_, _, err := Parse(data, "negative-size.yaml")
	if err == nil {
		t.Fatal("Parse returned nil error for a negative integer size")
	}
}
