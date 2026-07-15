package config

// redacted is the placeholder printed instead of a Secret's real value
// in logs, error messages, and any other formatted output.
const redacted = "[REDACTED]"

// Secret wraps a string configuration value (credential, API key,
// token, etc.) so that it never leaks into logs, error messages, or
// fmt output by accident. The underlying value is only accessible via
// an explicit call to Value().
//
// Secret implements fmt.Stringer and encoding.TextMarshaler so that
// both direct formatting (fmt.Sprintf("%v", secret), %s, %q) and YAML
// marshaling render "[REDACTED]" instead of the real value. YAML
// unmarshaling still reads the real value from the config file/env
// substitution, since UnmarshalText/UnmarshalYAML are intentionally
// not overridden to block input.
type Secret string

// String implements fmt.Stringer, redacting the value.
func (Secret) String() string {
	return redacted
}

// MarshalText implements encoding.TextMarshaler, redacting the value.
// This also prevents leaking the secret if the config is ever
// marshaled back to YAML/JSON via encoding/json or gopkg.in/yaml.v3,
// both of which prefer TextMarshaler over struct field encoding.
func (Secret) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}

// GoString implements fmt.GoStringer, redacting the value for %#v too.
func (Secret) GoString() string {
	return redacted
}

// Value returns the underlying secret value. Callers must not log,
// print, or otherwise persist the returned value.
func (s Secret) Value() string {
	return string(s)
}

// Empty reports whether the secret has no value set.
func (s Secret) Empty() bool {
	return s == ""
}
