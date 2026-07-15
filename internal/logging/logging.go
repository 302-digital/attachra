// Package logging provides a slog.Logger factory configured from
// Attachra's logging configuration (level and output format).
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// redacted is the placeholder value written instead of a sensitive
// attribute's real value.
const redacted = "[REDACTED]"

// sensitiveKeys enumerates attribute keys (case-insensitive) whose
// values must never be written to the log output, however deeply
// they are nested inside slog.Group attributes. This is a
// defense-in-depth backstop: callers should still avoid logging
// secrets directly (e.g. by using config.Secret, which redacts itself
// on String()/MarshalText()), but attribute keys named like this are
// redacted unconditionally.
var sensitiveKeys = map[string]bool{
	"token":    true,
	"secret":   true,
	"password": true,
	"apikey":   true,
}

// New builds a *slog.Logger writing to w, using the given level
// ("debug", "info", "warn", "error") and format ("json" or "text").
// An unknown level or format returns a descriptive error.
//
// The returned logger's handler redacts the value of any attribute
// whose key matches a sensitive name (token, secret, password,
// api_key, and common variants), including attributes nested inside
// slog.Group values, so that a secret accidentally logged as a field
// value does not leak into the log output.
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{
		Level:       lvl,
		ReplaceAttr: redactSensitiveAttr,
	}

	var handler slog.Handler
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	case "text":
		handler = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("logging: unknown format %q (want one of: json, text)", format)
	}

	return slog.New(handler), nil
}

// redactSensitiveAttr is an slog.HandlerOptions.ReplaceAttr function
// that replaces the value of any attribute whose key matches a
// sensitive name (see sensitiveKeys) with a redacted placeholder.
// slog calls ReplaceAttr for every attribute, including those nested
// inside slog.Group values, so this also covers grouped/nested
// secrets (e.g. slog.Group("s3", "secret_key", ...)).
func redactSensitiveAttr(_ []string, a slog.Attr) slog.Attr {
	if isSensitiveKey(a.Key) {
		a.Value = slog.StringValue(redacted)
	}
	return a
}

// isSensitiveKey reports whether key names a sensitive attribute,
// matching case-insensitively and ignoring "_"/"-" separators so that
// keys like "API_Key", "api-key", "user_password", or "secret_key"
// are all caught, whether the sensitive word is a prefix, suffix, or
// the whole key of a compound attribute name.
func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(key)
	normalized = strings.NewReplacer("_", "", "-", "", " ", "").Replace(normalized)

	if normalized == "" {
		return false
	}

	for word := range sensitiveKeys {
		if strings.Contains(normalized, word) {
			return true
		}
	}

	return false
}

// parseLevel converts a textual log level into a slog.Level.
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: unknown level %q (want one of: debug, info, warn, error)", level)
	}
}
