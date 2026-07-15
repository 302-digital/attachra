package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a policy-file duration scalar (docs/architecture/
// policy-format-v1.md §2.4), used for `ttl` and `retention`. Unlike
// Go's time.ParseDuration, only a single integer followed by exactly
// one of the suffixes s/m/h/d is accepted ("30d", "48h"); fractional
// ("1.5h") and composite ("1d12h") forms are rejected in v1 to keep
// the format simple to read. "d" means exactly 24h. The literal value
// "0" (with no unit) is also rejected — a zero-duration TTL/retention
// is never a meaningful policy choice and is far more likely to be an
// author mistake or an accidentally-omitted value.
type Duration time.Duration

// durationUnits maps a duration-string suffix to its time.Duration
// multiplier.
var durationUnits = map[byte]time.Duration{
	's': time.Second,
	'm': time.Minute,
	'h': time.Hour,
	'd': 24 * time.Hour,
}

// parseDuration parses a single integer+suffix duration string such
// as "30d", "48h" or "90m".
func parseDuration(s string) (time.Duration, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("empty duration value")
	}
	if trimmed == "0" {
		return 0, fmt.Errorf("invalid duration %q: a zero duration is not allowed", s)
	}

	last := trimmed[len(trimmed)-1]
	mult, ok := durationUnits[last]
	if !ok {
		return 0, fmt.Errorf("invalid duration %q: expected a suffix of s, m, h or d", s)
	}

	numPart := trimmed[:len(trimmed)-1]
	if numPart == "" {
		return 0, fmt.Errorf("invalid duration %q: missing numeric value before unit", s)
	}
	n, err := strconv.ParseInt(numPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: expected a whole number followed by s, m, h or d (fractional and composite durations like %q are not supported)", s, "1d12h")
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid duration %q: must be positive", s)
	}

	return time.Duration(n) * mult, nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("invalid duration: expected a string like \"30d\" or \"48h\": %w", err)
	}
	parsed, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// Duration returns d as a standard library time.Duration.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}
