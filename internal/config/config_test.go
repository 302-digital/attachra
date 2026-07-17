package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoad_ValidYAML(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: debug
  format: json
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "0.0.0.0:9090"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, "json")
	}
	if cfg.Milter.Listen != "inet:127.0.0.1:6785" {
		t.Errorf("Milter.Listen = %q, want %q", cfg.Milter.Listen, "inet:127.0.0.1:6785")
	}
	if cfg.HTTP.Listen != "0.0.0.0:9090" {
		t.Errorf("HTTP.Listen = %q, want %q", cfg.HTTP.Listen, "0.0.0.0:9090")
	}
}

func TestLoad_DefaultsWithoutPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") error = %v, want nil", err)
	}

	want := Default()
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("Load(\"\") = %+v, want defaults %+v", cfg, want)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("Load() error = nil, want error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "log: [this is not a mapping")

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want parse error for invalid YAML")
	}
}

func TestLoad_InvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "bad log level",
			content: `
log:
  level: verbose
  format: json
milter:
  listen: "x"
http:
  listen: "y"
`,
		},
		{
			name: "bad log format",
			content: `
log:
  level: info
  format: xml
milter:
  listen: "x"
http:
  listen: "y"
`,
		},
		{
			name: "empty milter listen",
			content: `
log:
  level: info
  format: json
milter:
  listen: ""
http:
  listen: "y"
`,
		},
		{
			name: "bad milter failure_mode",
			content: `
log:
  level: info
  format: json
milter:
  listen: "x"
  failure_mode: "explode"
http:
  listen: "y"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, tt.content)
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
		})
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
`)

	t.Setenv("ATTACHRA_LOG_LEVEL", "debug")
	t.Setenv("ATTACHRA_LOG_FORMAT", "json")
	t.Setenv("ATTACHRA_MILTER_LISTEN", "inet:0.0.0.0:9999")
	t.Setenv("ATTACHRA_HTTP_LISTEN", "0.0.0.0:8888")
	t.Setenv("ATTACHRA_ADMIN_LISTEN", "0.0.0.0:9999")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want env override %q", cfg.Log.Level, "debug")
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want env override %q", cfg.Log.Format, "json")
	}
	if cfg.Milter.Listen != "inet:0.0.0.0:9999" {
		t.Errorf("Milter.Listen = %q, want env override %q", cfg.Milter.Listen, "inet:0.0.0.0:9999")
	}
	if cfg.HTTP.Listen != "0.0.0.0:8888" {
		t.Errorf("HTTP.Listen = %q, want env override %q", cfg.HTTP.Listen, "0.0.0.0:8888")
	}
	if cfg.Admin.Listen != "0.0.0.0:9999" {
		t.Errorf("Admin.Listen = %q, want env override %q", cfg.Admin.Listen, "0.0.0.0:9999")
	}
}

// TestLoad_AdminFoldIntoHTTPEnvOverride verifies
// ATTACHRA_ADMIN_FOLD_INTO_HTTP is parsed the same way as
// ATTACHRA_POLICY_DRY_RUN ("true"/"1", case-insensitive for "true").
func TestLoad_AdminFoldIntoHTTPEnvOverride(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
`)

	t.Setenv("ATTACHRA_ADMIN_FOLD_INTO_HTTP", "true")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if !cfg.Admin.FoldIntoHTTP {
		t.Error("Admin.FoldIntoHTTP = false, want true (env override)")
	}
}

// TestDefault_AdminPopulated verifies Default() sets a loopback-only
// admin.listen (ATR-292) on a port that is NOT Prometheus's own default
// (9090 — the most likely co-located neighbor), matching http.listen's
// own default posture, with FoldIntoHTTP off, and that the default
// value passes validation.
func TestDefault_AdminPopulated(t *testing.T) {
	d := Default()

	if d.Admin.Listen != "127.0.0.1:18090" {
		t.Errorf("Admin.Listen = %q, want %q", d.Admin.Listen, "127.0.0.1:18090")
	}
	if d.Admin.Listen == "127.0.0.1:9090" {
		t.Error("Admin.Listen defaults to Prometheus's own default port 9090 — likely bind collision with a co-located Prometheus server")
	}
	if d.Admin.FoldIntoHTTP {
		t.Error("Admin.FoldIntoHTTP = true, want false (hardened separated-surface default)")
	}
	if err := d.Validate(); err != nil {
		t.Errorf("Default().Validate() = %v, want nil", err)
	}
}

// TestLoad_AdminFromYAML verifies admin.listen loads from the YAML
// file, overriding Default()'s value.
func TestLoad_AdminFromYAML(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
admin:
  listen: "127.0.0.1:9191"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Admin.Listen != "127.0.0.1:9191" {
		t.Errorf("Admin.Listen = %q, want %q", cfg.Admin.Listen, "127.0.0.1:9191")
	}
}

// TestLoad_AdminListenEmptyIsNormalizedNotDisabled is the core ATR-292
// security-review regression test: an explicit empty admin.listen in
// YAML (mirroring the same failure mode as an empty-but-present
// ATTACHRA_ADMIN_LISTEN env var, exercised in TestLoad_EnvOverride's
// sibling below) must NOT silently disable the admin/public surface
// separation. It is normalized back to the safe default instead.
func TestLoad_AdminListenEmptyIsNormalizedNotDisabled(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
admin:
  listen: ""
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Admin.Listen != Default().Admin.Listen {
		t.Errorf("Admin.Listen = %q, want the safe default %q (empty is not an opt-out)", cfg.Admin.Listen, Default().Admin.Listen)
	}
}

// TestLoad_AdminListenEmptyEnvIsNormalizedNotDisabled reproduces the
// exact bug the ATR-292 security review flagged: an ATTACHRA_ADMIN_LISTEN
// environment variable that is *present but empty* (a common accident
// with CI/tooling that exports variables unconditionally) must not
// silently fold the admin routes onto the public listener.
func TestLoad_AdminListenEmptyEnvIsNormalizedNotDisabled(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
`)
	t.Setenv("ATTACHRA_ADMIN_LISTEN", "")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Admin.Listen != Default().Admin.Listen {
		t.Errorf("Admin.Listen = %q, want the safe default %q (empty env override is not an opt-out)", cfg.Admin.Listen, Default().Admin.Listen)
	}
}

// TestLoad_AdminFoldIntoHTTPTrue verifies the ONLY way to actually fold
// admin routes onto the public listener: an explicit
// admin.fold_into_http: true. Listen may be left empty in this mode
// (internal/adapters/http.Server ignores it) — normalization skips it
// specifically because fold_into_http is set.
func TestLoad_AdminFoldIntoHTTPTrue(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
admin:
  listen: ""
  fold_into_http: true
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if !cfg.Admin.FoldIntoHTTP {
		t.Error("Admin.FoldIntoHTTP = false, want true")
	}
	if cfg.Admin.Listen != "" {
		t.Errorf("Admin.Listen = %q, want empty (not normalized when fold_into_http is true)", cfg.Admin.Listen)
	}
}

// TestValidate_AdminListenEmptyWithoutFoldIsRejected verifies
// Config.Validate's defense-in-depth check: a Config built directly
// (bypassing Load's normalization) with an empty admin.listen and
// FoldIntoHTTP false fails validation rather than silently reaching
// internal/adapters/http as an implicit fold.
func TestValidate_AdminListenEmptyWithoutFoldIsRejected(t *testing.T) {
	cfg := Default()
	cfg.Admin.Listen = ""
	cfg.Admin.FoldIntoHTTP = false

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() error = nil, want error (empty admin.listen without fold_into_http)")
	}

	cfg.Admin.FoldIntoHTTP = true
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil (empty admin.listen IS valid when fold_into_http is true)", err)
	}
}

func TestValidate(t *testing.T) {
	validLimits := Default().Limits

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "valid defaults",
			cfg:     Default(),
			wantErr: false,
		},
		{
			name: "invalid level",
			cfg: Config{
				Log:    LogConfig{Level: "trace", Format: "json"},
				Milter: MilterConfig{Listen: "x"},
				HTTP:   HTTPConfig{Listen: "y"},
				Limits: validLimits,
			},
			wantErr: true,
		},
		{
			name: "invalid format",
			cfg: Config{
				Log:    LogConfig{Level: "info", Format: "yaml"},
				Milter: MilterConfig{Listen: "x"},
				HTTP:   HTTPConfig{Listen: "y"},
				Limits: validLimits,
			},
			wantErr: true,
		},
		{
			name: "valid public_base_url",
			cfg: func() Config {
				c := Default()
				c.PublicBaseURL = "https://dl.example.com"
				return c
			}(),
			wantErr: false,
		},
		{
			name: "invalid public_base_url scheme",
			cfg: func() Config {
				c := Default()
				c.PublicBaseURL = "ftp://dl.example.com"
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid public_base_url no host",
			cfg: func() Config {
				c := Default()
				c.PublicBaseURL = "/just/a/path"
				return c
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLimitsConfig_Validate(t *testing.T) {
	valid := Default().Limits

	tests := []struct {
		name    string
		mutate  func(*LimitsConfig)
		wantErr bool
	}{
		{name: "valid defaults", mutate: func(*LimitsConfig) {}, wantErr: false},
		{name: "zero max_message_size", mutate: func(l *LimitsConfig) { l.MaxMessageSize = 0 }, wantErr: true},
		{name: "negative max_message_size", mutate: func(l *LimitsConfig) { l.MaxMessageSize = -1 }, wantErr: true},
		{name: "zero max_attachment_size", mutate: func(l *LimitsConfig) { l.MaxAttachmentSize = 0 }, wantErr: true},
		{name: "zero max_mime_parts", mutate: func(l *LimitsConfig) { l.MaxMIMEParts = 0 }, wantErr: true},
		{name: "negative max_mime_depth", mutate: func(l *LimitsConfig) { l.MaxMIMEDepth = -5 }, wantErr: true},
		{name: "zero max_header_bytes", mutate: func(l *LimitsConfig) { l.MaxHeaderBytes = 0 }, wantErr: true},
		{name: "zero milter_max_connections", mutate: func(l *LimitsConfig) { l.MilterMaxConnections = 0 }, wantErr: true},
		{name: "zero milter_timeout", mutate: func(l *LimitsConfig) { l.MilterTimeout = 0 }, wantErr: true},
		{name: "zero http_timeout", mutate: func(l *LimitsConfig) { l.HTTPTimeout = 0 }, wantErr: true},
		{name: "zero inline_max_size", mutate: func(l *LimitsConfig) { l.InlineMaxSize = 0 }, wantErr: true},
		{name: "negative inline_max_size", mutate: func(l *LimitsConfig) { l.InlineMaxSize = -1 }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := valid
			tt.mutate(&l)
			errs := l.validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validate() errs = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}

func TestDefault_LimitsPopulated(t *testing.T) {
	d := Default().Limits

	if d.MaxMessageSize != 100*1024*1024 {
		t.Errorf("MaxMessageSize = %d, want 100MiB", d.MaxMessageSize)
	}
	if d.MaxMIMEParts != 1000 {
		t.Errorf("MaxMIMEParts = %d, want 1000", d.MaxMIMEParts)
	}
	if d.MaxMIMEDepth != 20 {
		t.Errorf("MaxMIMEDepth = %d, want 20", d.MaxMIMEDepth)
	}
	if d.InlineMaxSize != 256*1024 {
		t.Errorf("InlineMaxSize = %d, want 256KiB", d.InlineMaxSize)
	}

	if errs := d.validate(); len(errs) != 0 {
		t.Errorf("Default().Limits.validate() = %v, want no errors", errs)
	}
}

func TestLoad_EnvVarSubstitution(t *testing.T) {
	t.Setenv("ATTACHRA_TEST_SECRET", "s3cr3t-value")

	path := writeTempConfig(t, `
log:
  level: info
  format: json
milter:
  listen: "${ATTACHRA_TEST_SECRET}"
http:
  listen: "127.0.0.1:8080"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Milter.Listen != "s3cr3t-value" {
		t.Errorf("Milter.Listen = %q, want substituted %q", cfg.Milter.Listen, "s3cr3t-value")
	}
}

func TestLoad_EnvVarSubstitution_UnsetLeftVerbatim(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: json
milter:
  listen: "${ATTACHRA_DEFINITELY_UNSET_VAR}"
http:
  listen: "127.0.0.1:8080"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Milter.Listen != "${ATTACHRA_DEFINITELY_UNSET_VAR}" {
		t.Errorf("Milter.Listen = %q, want placeholder left verbatim", cfg.Milter.Listen)
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("ATTACHRA_TEST_FOO", "foo-value")

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "value: ${ATTACHRA_TEST_FOO}", "value: foo-value"},
		{"multiple", "${ATTACHRA_TEST_FOO}-${ATTACHRA_TEST_FOO}", "foo-value-foo-value"},
		{"unset preserved", "value: ${ATTACHRA_TEST_UNSET_XYZ}", "value: ${ATTACHRA_TEST_UNSET_XYZ}"},
		{"no placeholder", "value: plain", "value: plain"},
		{"unterminated", "value: ${ATTACHRA_TEST_FOO", "value: ${ATTACHRA_TEST_FOO"},
		{"empty braces", "value: ${}", "value: ${}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(expandEnv([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("expandEnv(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoad_PublicBaseURLEnvOverride(t *testing.T) {
	t.Setenv("ATTACHRA_PUBLIC_BASE_URL", "https://dl.example.com")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") error = %v, want nil", err)
	}
	if cfg.PublicBaseURL != "https://dl.example.com" {
		t.Errorf("PublicBaseURL = %q, want env override", cfg.PublicBaseURL)
	}
}

func TestDefault_StoragePopulated(t *testing.T) {
	d := Default()

	if d.Storage.Driver != "fs" {
		t.Errorf("Storage.Driver = %q, want %q", d.Storage.Driver, "fs")
	}
	if d.Storage.FS.BaseDir == "" {
		t.Error("Storage.FS.BaseDir is empty, want a default path")
	}
	if err := d.Validate(); err != nil {
		t.Errorf("Default().Validate() = %v, want nil", err)
	}
}

func TestStorageConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     StorageConfig
		wantErr bool
	}{
		{
			name:    "valid fs",
			cfg:     StorageConfig{Driver: "fs", FS: FSStorageConfig{BaseDir: "/var/lib/attachra"}},
			wantErr: false,
		},
		{
			name:    "fs missing base_dir",
			cfg:     StorageConfig{Driver: "fs", FS: FSStorageConfig{BaseDir: ""}},
			wantErr: true,
		},
		{
			name: "valid s3",
			cfg: StorageConfig{
				Driver: "s3",
				S3:     S3Config{Bucket: "attachra", Region: "us-east-1"},
			},
			wantErr: false,
		},
		{
			name: "s3 missing bucket",
			cfg: StorageConfig{
				Driver: "s3",
				S3:     S3Config{Region: "us-east-1"},
			},
			wantErr: true,
		},
		{
			name: "s3 missing region",
			cfg: StorageConfig{
				Driver: "s3",
				S3:     S3Config{Bucket: "attachra"},
			},
			wantErr: true,
		},
		{
			name: "s3 invalid sse",
			cfg: StorageConfig{
				Driver: "s3",
				S3:     S3Config{Bucket: "attachra", Region: "us-east-1", SSE: "rot13"},
			},
			wantErr: true,
		},
		{
			name: "s3 valid sse AES256",
			cfg: StorageConfig{
				Driver: "s3",
				S3:     S3Config{Bucket: "attachra", Region: "us-east-1", SSE: "AES256"},
			},
			wantErr: false,
		},
		{
			name: "s3 valid sse aws:kms",
			cfg: StorageConfig{
				Driver: "s3",
				S3:     S3Config{Bucket: "attachra", Region: "us-east-1", SSE: "aws:kms"},
			},
			wantErr: false,
		},
		{
			name:    "invalid driver",
			cfg:     StorageConfig{Driver: "ftp"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validate() errs = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}

func TestStorageConfig_SecretsNotLeakedInValidationErrors(t *testing.T) {
	cfg := Default()
	cfg.Storage = StorageConfig{
		Driver: "s3",
		S3: S3Config{
			// Missing bucket/region on purpose to trigger errors, with
			// secrets set so we can check they never appear in the
			// resulting error text.
			AccessKey: Secret("super-secret-access-key"),
			SecretKey: Secret("super-secret-secret-key"),
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want validation error for missing bucket/region")
	}
	if strings.Contains(err.Error(), "super-secret-access-key") || strings.Contains(err.Error(), "super-secret-secret-key") {
		t.Errorf("Validate() error leaked a secret value: %v", err)
	}
}

func TestLoad_StorageEnvOverride(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
storage:
  driver: fs
  fs:
    base_dir: /tmp/should-be-overridden
`)

	t.Setenv("ATTACHRA_STORAGE_DRIVER", "s3")
	t.Setenv("ATTACHRA_STORAGE_S3_ENDPOINT", "http://localhost:9000")
	t.Setenv("ATTACHRA_STORAGE_S3_REGION", "us-east-1")
	t.Setenv("ATTACHRA_STORAGE_S3_BUCKET", "attachra-dev")
	t.Setenv("ATTACHRA_STORAGE_S3_ACCESS_KEY", "test-access-key")
	t.Setenv("ATTACHRA_STORAGE_S3_SECRET_KEY", "test-secret-key")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Storage.Driver != "s3" {
		t.Errorf("Storage.Driver = %q, want %q", cfg.Storage.Driver, "s3")
	}
	if cfg.Storage.S3.Endpoint != "http://localhost:9000" {
		t.Errorf("Storage.S3.Endpoint = %q, want env override", cfg.Storage.S3.Endpoint)
	}
	if cfg.Storage.S3.Bucket != "attachra-dev" {
		t.Errorf("Storage.S3.Bucket = %q, want env override", cfg.Storage.S3.Bucket)
	}
	if cfg.Storage.S3.AccessKey.Value() != "test-access-key" {
		t.Errorf("Storage.S3.AccessKey = %q, want env override", cfg.Storage.S3.AccessKey.Value())
	}
	if cfg.Storage.S3.SecretKey.Value() != "test-secret-key" {
		t.Errorf("Storage.S3.SecretKey = %q, want env override", cfg.Storage.S3.SecretKey.Value())
	}
}

func TestDefault_DatabaseAndLinksPopulated(t *testing.T) {
	d := Default()

	if d.Database.Driver != "sqlite" {
		t.Errorf("Database.Driver = %q, want %q", d.Database.Driver, "sqlite")
	}
	if d.Database.Path == "" {
		t.Error("Database.Path is empty, want a default path")
	}
	if d.Links.DefaultTTLSeconds <= 0 {
		t.Errorf("Links.DefaultTTLSeconds = %d, want positive", d.Links.DefaultTTLSeconds)
	}
	if d.Links.TokenBytes < 16 {
		t.Errorf("Links.TokenBytes = %d, want >= 16", d.Links.TokenBytes)
	}
	if d.Links.DefaultRetentionSeconds < d.Links.DefaultTTLSeconds {
		t.Errorf("Links.DefaultRetentionSeconds = %d, want >= DefaultTTLSeconds (%d)", d.Links.DefaultRetentionSeconds, d.Links.DefaultTTLSeconds)
	}
	if !d.Retention.Enabled {
		t.Error("Retention.Enabled = false, want true by default")
	}
	if d.Retention.IntervalSeconds <= 0 {
		t.Errorf("Retention.IntervalSeconds = %d, want positive", d.Retention.IntervalSeconds)
	}
	if d.Retention.ChunkSize <= 0 {
		t.Errorf("Retention.ChunkSize = %d, want positive", d.Retention.ChunkSize)
	}
	if err := d.Validate(); err != nil {
		t.Errorf("Default().Validate() = %v, want nil", err)
	}
}

func TestDatabaseConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DatabaseConfig
		wantErr bool
	}{
		{name: "valid sqlite", cfg: DatabaseConfig{Driver: "sqlite", Path: "./data/attachra.db"}, wantErr: false},
		{name: "missing path", cfg: DatabaseConfig{Driver: "sqlite", Path: ""}, wantErr: true},
		{name: "unsupported driver postgres", cfg: DatabaseConfig{Driver: "postgres", Path: "unused"}, wantErr: true},
		{name: "unknown driver", cfg: DatabaseConfig{Driver: "mysql", Path: "unused"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validate() errs = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}

func TestLinksConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     LinksConfig
		wantErr bool
	}{
		{name: "valid", cfg: LinksConfig{DefaultTTLSeconds: 3600, DefaultMaxDownloads: 0, TokenBytes: 16}, wantErr: false},
		{name: "valid unlimited downloads is zero", cfg: LinksConfig{DefaultTTLSeconds: 3600, DefaultMaxDownloads: 0, TokenBytes: 32}, wantErr: false},
		{name: "zero ttl", cfg: LinksConfig{DefaultTTLSeconds: 0, DefaultMaxDownloads: 0, TokenBytes: 16}, wantErr: true},
		{name: "negative ttl", cfg: LinksConfig{DefaultTTLSeconds: -1, DefaultMaxDownloads: 0, TokenBytes: 16}, wantErr: true},
		{name: "negative max downloads", cfg: LinksConfig{DefaultTTLSeconds: 3600, DefaultMaxDownloads: -1, TokenBytes: 16}, wantErr: true},
		{name: "token bytes below 128 bits", cfg: LinksConfig{DefaultTTLSeconds: 3600, DefaultMaxDownloads: 0, TokenBytes: 8}, wantErr: true},
		{name: "zero retention (unset, falls back to ttl at runtime)", cfg: LinksConfig{DefaultTTLSeconds: 3600, TokenBytes: 16, DefaultRetentionSeconds: 0}, wantErr: false},
		{name: "retention equal to ttl", cfg: LinksConfig{DefaultTTLSeconds: 3600, TokenBytes: 16, DefaultRetentionSeconds: 3600}, wantErr: false},
		{name: "retention greater than ttl", cfg: LinksConfig{DefaultTTLSeconds: 3600, TokenBytes: 16, DefaultRetentionSeconds: 7200}, wantErr: false},
		{name: "retention shorter than ttl is rejected", cfg: LinksConfig{DefaultTTLSeconds: 3600, TokenBytes: 16, DefaultRetentionSeconds: 1800}, wantErr: true},
		{name: "negative retention", cfg: LinksConfig{DefaultTTLSeconds: 3600, TokenBytes: 16, DefaultRetentionSeconds: -1}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validate() errs = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}

func TestRetentionConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RetentionConfig
		wantErr bool
	}{
		{name: "valid enabled", cfg: RetentionConfig{Enabled: true, IntervalSeconds: 3600, ChunkSize: 200}, wantErr: false},
		{name: "disabled ignores otherwise-invalid tuning", cfg: RetentionConfig{Enabled: false, IntervalSeconds: 0, ChunkSize: 0}, wantErr: false},
		{name: "enabled with zero interval", cfg: RetentionConfig{Enabled: true, IntervalSeconds: 0, ChunkSize: 200}, wantErr: true},
		{name: "enabled with negative interval", cfg: RetentionConfig{Enabled: true, IntervalSeconds: -1, ChunkSize: 200}, wantErr: true},
		{name: "enabled with zero chunk size", cfg: RetentionConfig{Enabled: true, IntervalSeconds: 3600, ChunkSize: 0}, wantErr: true},
		{name: "audit retention zero is valid (opt-in off)", cfg: RetentionConfig{Enabled: true, IntervalSeconds: 3600, ChunkSize: 200, AuditRetentionSeconds: 0}, wantErr: false},
		{name: "audit retention positive is valid", cfg: RetentionConfig{Enabled: true, IntervalSeconds: 3600, ChunkSize: 200, AuditRetentionSeconds: 7776000}, wantErr: false},
		{name: "audit retention negative is invalid", cfg: RetentionConfig{Enabled: true, IntervalSeconds: 3600, ChunkSize: 200, AuditRetentionSeconds: -1}, wantErr: true},
		{name: "audit retention negative invalid even when disabled", cfg: RetentionConfig{Enabled: false, AuditRetentionSeconds: -5}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validate() errs = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}

func TestHTTPRateLimitConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     HTTPRateLimitConfig
		wantErr bool
	}{
		{name: "valid", cfg: HTTPRateLimitConfig{PerIPPerMinute: 120, PerIPBurst: 20, GlobalPerMinute: 6000, GlobalBurst: 200, NotFoundPerIPPerMinute: 20, TarpitDelaySeconds: 1}, wantErr: false},
		{name: "all zero disables limits, valid", cfg: HTTPRateLimitConfig{}, wantErr: false},
		{name: "negative per_ip_per_minute", cfg: HTTPRateLimitConfig{PerIPPerMinute: -1}, wantErr: true},
		{name: "negative global_per_minute", cfg: HTTPRateLimitConfig{GlobalPerMinute: -1}, wantErr: true},
		{name: "negative not_found_per_ip_per_minute", cfg: HTTPRateLimitConfig{NotFoundPerIPPerMinute: -1}, wantErr: true},
		{name: "negative tarpit_delay_seconds", cfg: HTTPRateLimitConfig{TarpitDelaySeconds: -0.5}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validate() errs = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}

func TestHTTPConfig_ValidateTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
	}{
		{name: "nil is valid (default: trust nothing)", cidrs: nil, wantErr: false},
		{name: "empty slice is valid", cidrs: []string{}, wantErr: false},
		{name: "single IPv4 CIDR", cidrs: []string{"127.0.0.1/32"}, wantErr: false},
		{name: "single IPv6 CIDR", cidrs: []string{"::1/128"}, wantErr: false},
		{name: "mixed IPv4 and IPv6", cidrs: []string{"10.0.0.0/8", "fd00::/8"}, wantErr: false},
		{name: "malformed CIDR", cidrs: []string{"not-a-cidr"}, wantErr: true},
		{name: "bare IP without prefix length", cidrs: []string{"127.0.0.1"}, wantErr: true},
		{name: "one good one bad", cidrs: []string{"127.0.0.1/32", "garbage"}, wantErr: true},
		{name: "out-of-range octet", cidrs: []string{"999.0.0.1/32"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := HTTPConfig{TrustedProxies: tt.cidrs}
			errs := h.validateTrustedProxies()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validateTrustedProxies() errs = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}

func TestLoad_TrustedProxiesFromYAML(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
  trusted_proxies:
    - "127.0.0.1/32"
    - "::1/128"
database:
  driver: sqlite
  path: /tmp/db
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	want := []string{"127.0.0.1/32", "::1/128"}
	if !reflect.DeepEqual(cfg.HTTP.TrustedProxies, want) {
		t.Errorf("HTTP.TrustedProxies = %v, want %v", cfg.HTTP.TrustedProxies, want)
	}
}

func TestLoad_InvalidTrustedProxyCIDR(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
  trusted_proxies:
    - "not-a-cidr"
database:
  driver: sqlite
  path: /tmp/db
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want error for invalid http.trusted_proxies entry")
	}
	if !strings.Contains(err.Error(), "http.trusted_proxies[0]") {
		t.Errorf("Load() error = %v, want it to mention http.trusted_proxies[0]", err)
	}
}

func TestLoad_HTTPRateLimitEnvOverride(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
database:
  driver: sqlite
  path: /tmp/db
`)

	t.Setenv("ATTACHRA_HTTP_RATE_LIMIT_PER_IP_PER_MINUTE", "42")
	t.Setenv("ATTACHRA_HTTP_RATE_LIMIT_GLOBAL_PER_MINUTE", "4242")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.HTTP.RateLimit.PerIPPerMinute != 42 {
		t.Errorf("HTTP.RateLimit.PerIPPerMinute = %d, want 42", cfg.HTTP.RateLimit.PerIPPerMinute)
	}
	if cfg.HTTP.RateLimit.GlobalPerMinute != 4242 {
		t.Errorf("HTTP.RateLimit.GlobalPerMinute = %d, want 4242", cfg.HTTP.RateLimit.GlobalPerMinute)
	}
}

func TestLoad_DatabaseAndLinksEnvOverride(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
database:
  driver: sqlite
  path: /tmp/should-be-overridden.db
`)

	t.Setenv("ATTACHRA_DATABASE_DRIVER", "sqlite")
	t.Setenv("ATTACHRA_DATABASE_PATH", "/var/lib/attachra/attachra.db")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Database.Path != "/var/lib/attachra/attachra.db" {
		t.Errorf("Database.Path = %q, want env override", cfg.Database.Path)
	}
}

func TestLoad_InvalidLimits(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: json
milter:
  listen: "x"
http:
  listen: "y"
limits:
  max_message_size: 0
  max_attachment_size: 1
  max_mime_parts: 1
  max_mime_depth: 1
  max_header_bytes: 1
  milter_max_connections: 1
  milter_timeout: 1
  http_timeout: 1
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want validation error for zero max_message_size")
	}
}

func TestLoad_PolicyDefaultsEmpty(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: json
milter:
  listen: "x"
http:
  listen: "y"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Policy.Path != "" {
		t.Errorf("Policy.Path = %q, want empty (no policy configured means PassthroughProcessor)", cfg.Policy.Path)
	}
	if cfg.Policy.DryRun {
		t.Error("Policy.DryRun = true, want false by default")
	}
}

func TestLoad_PolicyFromYAML(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: json
milter:
  listen: "x"
http:
  listen: "y"
policy:
  path: "/etc/attachra/policy.yaml"
  dry_run: true
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Policy.Path != "/etc/attachra/policy.yaml" {
		t.Errorf("Policy.Path = %q, want %q", cfg.Policy.Path, "/etc/attachra/policy.yaml")
	}
	if !cfg.Policy.DryRun {
		t.Error("Policy.DryRun = false, want true")
	}
}

func TestLoad_PolicyEnvOverride(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: json
milter:
  listen: "x"
http:
  listen: "y"
`)

	t.Setenv("ATTACHRA_POLICY_PATH", "/opt/attachra/policy.yaml")
	t.Setenv("ATTACHRA_POLICY_DRY_RUN", "true")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Policy.Path != "/opt/attachra/policy.yaml" {
		t.Errorf("Policy.Path = %q, want env override %q", cfg.Policy.Path, "/opt/attachra/policy.yaml")
	}
	if !cfg.Policy.DryRun {
		t.Error("Policy.DryRun = false, want env override true")
	}
}

func TestDefault_SpoolPopulated(t *testing.T) {
	cfg := Default()
	if cfg.Spool.Dir != "" {
		t.Errorf("Spool.Dir = %q, want empty (OS default temp dir)", cfg.Spool.Dir)
	}
}

func TestSpoolConfig_Validate(t *testing.T) {
	writableDir := t.TempDir()

	unwritableDir := t.TempDir()
	if err := os.Chmod(unwritableDir, 0o500); err != nil { //nolint:gosec // test fixture: a read+execute-only *directory* deliberately made unwritable, not a sensitive file
		t.Fatalf("chmod unwritable dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unwritableDir, 0o700) }) //nolint:gosec // restoring the same test-fixture *directory* so TempDir cleanup can remove it

	fileNotDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileNotDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{name: "empty is valid (OS default temp dir)", dir: "", wantErr: false},
		{name: "existing writable directory", dir: writableDir, wantErr: false},
		{name: "nonexistent directory", dir: filepath.Join(writableDir, "does-not-exist"), wantErr: true},
		{name: "path is a file, not a directory", dir: fileNotDir, wantErr: true},
		{name: "existing but unwritable directory", dir: unwritableDir, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip the unwritable-directory case when running as a user
			// (e.g. root in some CI containers) that ignores directory
			// permission bits and can write there anyway.
			if tt.name == "existing but unwritable directory" {
				probe := filepath.Join(unwritableDir, ".probe")
				if err := os.WriteFile(probe, []byte("x"), 0o600); err == nil {
					_ = os.Remove(probe)
					t.Skip("running as a user that bypasses directory write permissions")
				}
			}

			errs := SpoolConfig{Dir: tt.dir}.validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("validate() errs = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}

func TestLoad_SpoolDirFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := writeTempConfig(t, fmt.Sprintf(`
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
spool:
  dir: %q
`, dir))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Spool.Dir != dir {
		t.Errorf("Spool.Dir = %q, want %q", cfg.Spool.Dir, dir)
	}
}

func TestLoad_SpoolDirInvalid_FailsFast(t *testing.T) {
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
spool:
  dir: /this/path/does/not/exist/anywhere
`)

	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want error for nonexistent spool.dir")
	}
}

func TestLoad_SpoolDirEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := writeTempConfig(t, `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
`)

	t.Setenv("ATTACHRA_SPOOL_DIR", dir)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Spool.Dir != dir {
		t.Errorf("Spool.Dir = %q, want env override %q", cfg.Spool.Dir, dir)
	}
}
