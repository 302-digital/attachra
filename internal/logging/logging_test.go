package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNew_FormatsAndLevels(t *testing.T) {
	tests := []struct {
		name       string
		level      string
		format     string
		wantErr    bool
		wantSubstr string // expected in output when logging at Info
	}{
		{name: "json info", level: "info", format: "json", wantSubstr: `"msg":"hello"`},
		{name: "text info", level: "info", format: "text", wantSubstr: "msg=hello"},
		{name: "debug level uppercase", level: "DEBUG", format: "json", wantSubstr: `"msg":"hello"`},
		{name: "warn level", level: "warn", format: "text", wantSubstr: "msg=hello"},
		{name: "error level", level: "error", format: "text", wantSubstr: "msg=hello"},
		{name: "invalid level", level: "verbose", format: "json", wantErr: true},
		{name: "invalid format", level: "info", format: "xml", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger, err := New(&buf, tt.level, tt.format)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Log at Error, the highest level, so the message always
			// passes the configured threshold regardless of tt.level.
			logger.Error("hello")

			out := buf.String()
			if tt.wantSubstr != "" && !strings.Contains(out, tt.wantSubstr) {
				t.Errorf("output = %q, want substring %q", out, tt.wantSubstr)
			}
		})
	}
}

func TestNew_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(&buf, "warn", "text")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	logger.Info("should not appear")
	if buf.Len() != 0 {
		t.Errorf("expected no output for Info below Warn level, got %q", buf.String())
	}

	logger.Warn("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("expected Warn output, got %q", buf.String())
	}
}

func TestNew_RedactsSensitiveAttrs(t *testing.T) {
	const secretValue = "s3cr3t-value-12345"

	tests := []struct {
		name   string
		format string
		logFn  func(l *slog.Logger)
	}{
		{
			name:   "top-level token, json",
			format: "json",
			logFn: func(l *slog.Logger) {
				l.Info("event", "token", secretValue)
			},
		},
		{
			name:   "top-level secret, text",
			format: "text",
			logFn: func(l *slog.Logger) {
				l.Info("event", "secret", secretValue)
			},
		},
		{
			name:   "password, json",
			format: "json",
			logFn: func(l *slog.Logger) {
				l.Info("event", "password", secretValue)
			},
		},
		{
			name:   "api_key snake_case, json",
			format: "json",
			logFn: func(l *slog.Logger) {
				l.Info("event", "api_key", secretValue)
			},
		},
		{
			name:   "compound key db_password, json",
			format: "json",
			logFn: func(l *slog.Logger) {
				l.Info("event", "db_password", secretValue)
			},
		},
		{
			name:   "nested in group, json",
			format: "json",
			logFn: func(l *slog.Logger) {
				l.Info("event", slog.Group("s3", "secret_key", secretValue, "bucket", "my-bucket"))
			},
		},
		{
			name:   "uppercase key, json",
			format: "json",
			logFn: func(l *slog.Logger) {
				l.Info("event", "API_KEY", secretValue)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger, err := New(&buf, "info", tt.format)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			tt.logFn(logger)

			out := buf.String()
			if strings.Contains(out, secretValue) {
				t.Fatalf("output leaked the secret value: %q", out)
			}
			if !strings.Contains(out, "REDACTED") {
				t.Errorf("output = %q, want redaction placeholder present", out)
			}
		})
	}
}

func TestNew_DoesNotRedactUnrelatedFields(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(&buf, "info", "json")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	logger.Info("event", "username", "alice", "tokenized", false, "count", 3)

	out := buf.String()
	if !strings.Contains(out, "alice") {
		t.Errorf("expected unrelated field value to be preserved, got %q", out)
	}
}

func TestIsSensitiveKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"token", true},
		{"secret", true},
		{"password", true},
		{"api_key", true},
		{"apikey", true},
		{"API-Key", true},
		{"db_password", true},
		{"secret_key", true},
		{"username", false},
		{"count", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := isSensitiveKey(tt.key); got != tt.want {
				t.Errorf("isSensitiveKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    slog.Level
		wantErr bool
	}{
		{input: "debug", want: slog.LevelDebug},
		{input: "info", want: slog.LevelInfo},
		{input: "warn", want: slog.LevelWarn},
		{input: "warning", want: slog.LevelWarn},
		{input: "error", want: slog.LevelError},
		{input: "INFO", want: slog.LevelInfo},
		{input: "bogus", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
