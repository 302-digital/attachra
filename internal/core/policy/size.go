package policy

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Bound is a byte-size scalar accepted in SizeRange.Min/Max
// (docs/architecture/policy-format-v1.md §2.3.2). It unmarshals from
// either a plain YAML integer (interpreted as a byte count) or a
// unit-suffixed string such as "10MB", "512KB" or "1GiB".
//
// Decimal units (KB/MB/GB) use a 1000 base, matching how a business
// user reads a marketing file size; binary units (KiB/MiB/GiB) use a
// 1024 base. Unit matching is case-insensitive except for the
// KB-vs-KiB distinction itself.
type Bound int64

// byteUnits maps a recognized size-unit suffix to its byte multiplier.
// Longer suffixes are checked first by parseBound so "KiB" is not
// mistaken for "KB" plus a stray "i".
var byteUnits = []struct {
	suffix     string
	multiplier int64
}{
	{"GIB", 1024 * 1024 * 1024},
	{"MIB", 1024 * 1024},
	{"KIB", 1024},
	{"GB", 1000 * 1000 * 1000},
	{"MB", 1000 * 1000},
	{"KB", 1000},
	{"B", 1},
}

// parseBound parses a size string such as "10MB", "512KiB" or a bare
// integer (bytes) into a byte count.
func parseBound(s string) (int64, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("empty size value")
	}

	upper := strings.ToUpper(trimmed)
	for _, u := range byteUnits {
		if strings.HasSuffix(upper, u.suffix) {
			numPart := strings.TrimSpace(trimmed[:len(trimmed)-len(u.suffix)])
			if numPart == "" {
				return 0, fmt.Errorf("invalid size %q: missing numeric value before unit", s)
			}
			n, err := strconv.ParseFloat(numPart, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size %q: %w", s, err)
			}
			if n < 0 {
				return 0, fmt.Errorf("invalid size %q: must not be negative", s)
			}
			return int64(n * float64(u.multiplier)), nil
		}
	}

	// No recognized unit suffix: require a plain non-negative integer.
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: expected an integer byte count or a value with a KB/MB/GB/KiB/MiB/GiB suffix", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q: must not be negative", s)
	}
	return n, nil
}

// UnmarshalYAML implements yaml.Unmarshaler, accepting either a plain
// integer (bytes) or a unit-suffixed string.
func (b *Bound) UnmarshalYAML(value *yaml.Node) error {
	switch value.Tag {
	case "!!int":
		var n int64
		if err := value.Decode(&n); err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("invalid size %d: must not be negative", n)
		}
		*b = Bound(n)
		return nil
	case "!!str":
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		n, err := parseBound(s)
		if err != nil {
			return err
		}
		*b = Bound(n)
		return nil
	default:
		return fmt.Errorf("invalid size value: expected an integer or a string, got %s", value.Tag)
	}
}

// Bytes returns the bound as a plain byte count.
func (b Bound) Bytes() int64 {
	return int64(b)
}
