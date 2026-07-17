// Package config loads and validates Attachra application configuration
// from a YAML file, with overrides from environment variables using the
// ATTACHRA_ prefix (e.g. ATTACHRA_LOG_LEVEL, ATTACHRA_MILTER_LISTEN).
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root application configuration. It is intentionally
// minimal for the project skeleton: only logging and the listen
// address placeholders for the future milter and HTTP adapters.
type Config struct {
	Log           LogConfig       `yaml:"log"`
	Milter        MilterConfig    `yaml:"milter"`
	HTTP          HTTPConfig      `yaml:"http"`
	Admin         AdminConfig     `yaml:"admin"`
	Limits        LimitsConfig    `yaml:"limits"`
	Storage       StorageConfig   `yaml:"storage"`
	Database      DatabaseConfig  `yaml:"database"`
	Links         LinksConfig     `yaml:"links"`
	Policy        PolicyConfig    `yaml:"policy"`
	Retention     RetentionConfig `yaml:"retention"`
	Spool         SpoolConfig     `yaml:"spool"`
	PublicBaseURL string          `yaml:"public_base_url"`
}

// LogConfig controls the application logger.
type LogConfig struct {
	// Level is one of: debug, info, warn, error.
	Level string `yaml:"level"`
	// Format is one of: json, text.
	Format string `yaml:"format"`
}

// MilterConfig holds settings for the Postfix milter adapter
// (internal/adapters/milter).
type MilterConfig struct {
	// Listen is the milter listen address, in Postfix milter syntax
	// (e.g. "inet:127.0.0.1:6785" or "unix:/var/run/attachra.sock").
	Listen string `yaml:"listen"`

	// FailureMode selects how the milter adapter resolves any error
	// or panic encountered while processing a message (SR-116-1):
	// "open" accepts the message unmodified, "closed" temp-fails it
	// (SMTP 4xx) so the sending MTA retries later. Per the
	// mail-must-never-be-lost invariant. Default: "open".
	FailureMode string `yaml:"failure_mode"`
}

// HTTPConfig holds settings for the download adapter
// (internal/adapters/http, US-6.2): the public package-page/download
// endpoint's listen address and rate limiting.
type HTTPConfig struct {
	// Listen is the TCP address the download server binds to (e.g.
	// "127.0.0.1:8080").
	Listen string `yaml:"listen"`

	// RateLimit configures per-IP and global request throttling plus
	// the enumeration tarpit (SR-125-7).
	RateLimit HTTPRateLimitConfig `yaml:"rate_limit"`

	// TrustedProxies lists CIDR ranges (IPv4 and/or IPv6, e.g.
	// "127.0.0.1/32" or "10.0.0.0/8") of reverse proxies allowed to set
	// the client identity via X-Forwarded-For/X-Real-IP (ATR-311,
	// SR-125-7's proxy-aware follow-up). Empty (the default) means no
	// proxy is trusted: internal/adapters/http.clientIP always uses the
	// TCP peer address and ignores both headers, matching the
	// fail-secure behavior this field's absence has always had — a
	// deployment that puts a reverse proxy (e.g. nginx) in front of
	// Attachra must opt in explicitly by listing that proxy's address
	// here, or every download/audit/rate-limit decision will key off the
	// proxy's own loopback address instead of the real client.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// AdminConfig holds settings for the admin/operational HTTP surface
// (internal/adapters/http, ATR-292): GET /metrics and the dependency-
// detailed GET /readyz, kept off the internet-facing download listener
// (http.listen) so a deployment that ever exposes http.listen publicly
// does not also leak build/runtime fingerprinting data (Go version,
// goroutine counts, memory stats) or the names of internal dependencies.
// GET /healthz (liveness only — a static "ok", no dependency detail) is
// intentionally still mounted on http.listen too, matching the existing
// operational convention (systemd/container health probes and
// `attachra doctor` hit the same port they already know about) — see
// internal/adapters/http.Server's own doc comment for the full route
// map.
//
// Security review of the first ATR-292 version (2026-07-16) flagged
// that treating an empty Listen as "fold admin routes onto http.listen"
// let a merely-*present*-but-empty ATTACHRA_ADMIN_LISTEN env var (or an
// explicit `listen: ""` in YAML) silently disable the hardening with no
// log line — env vars are frequently exported empty by tooling/CI by
// accident, so "absent" and "empty" must not be conflated with "opt
// out". Load() now normalizes Listen back to Default()'s safe loopback
// value whenever it comes out empty from ANY source (missing YAML key,
// explicit `listen: ""`, empty env override) and FoldIntoHTTP is not
// set; FoldIntoHTTP is the only way to opt into folding, and doing so
// is logged loudly by internal/adapters/http.NewServer at startup (see
// its doc comment).
type AdminConfig struct {
	// Listen is the TCP address the admin server binds to (e.g.
	// "127.0.0.1:18090"). Defaults to loopback-only, matching
	// http.listen's own default posture (Default()). Ignored entirely
	// when FoldIntoHTTP is true. An empty value here, from any source,
	// is NOT an opt-out (see the type doc comment) — Load() resets it
	// to the safe default unless FoldIntoHTTP is also set.
	Listen string `yaml:"listen"`

	// FoldIntoHTTP, when true, is the explicit, auditable opt-out from
	// the separate admin listener: /metrics and /readyz are mounted on
	// http.listen instead (reproducing the pre-ATR-292 single-listener
	// behavior), and Listen's value is ignored. Default: false (the
	// hardened, separated-surface posture). Setting this to true is
	// logged at Error or Warn level on every startup by
	// internal/adapters/http.NewServer, so it can never silently
	// degrade a deployment's security posture unnoticed.
	FoldIntoHTTP bool `yaml:"fold_into_http"`
}

// HTTPRateLimitConfig configures the download adapter's rate limiting
// (SR-125-7, T1.1, T1.2). All *PerMinute fields are sustained-rate
// budgets refilled continuously (a token-bucket, not a fixed window);
// a value <= 0 disables the corresponding limit.
type HTTPRateLimitConfig struct {
	// PerIPPerMinute is the sustained request rate allowed for a
	// single client IP across all routes this adapter serves.
	PerIPPerMinute int `yaml:"per_ip_per_minute"`

	// PerIPBurst is the maximum short burst size for a single client
	// IP. 0 defaults to PerIPPerMinute.
	PerIPBurst int `yaml:"per_ip_burst"`

	// GlobalPerMinute is the sustained request rate allowed across all
	// clients combined.
	GlobalPerMinute int `yaml:"global_per_minute"`

	// GlobalBurst is the maximum short burst size across all clients
	// combined. 0 defaults to GlobalPerMinute.
	GlobalBurst int `yaml:"global_burst"`

	// NotFoundPerIPPerMinute is the tighter sustained rate allowed for
	// requests from a single IP that resolve to the generic
	// not-found/expired/revoked/exhausted response, the signature of
	// token enumeration (T1.1). Exceeding it triggers TarpitDelay on
	// further responses to that IP.
	NotFoundPerIPPerMinute int `yaml:"not_found_per_ip_per_minute"`

	// TarpitDelaySeconds is the artificial delay (in seconds, may be
	// fractional, e.g. 0.5) added to a not-found-shaped response once
	// an IP has exceeded NotFoundPerIPPerMinute.
	TarpitDelaySeconds float64 `yaml:"tarpit_delay_seconds"`
}

// LimitsConfig holds global resource limits enforced across the
// application (milter session handling, MIME parsing, HTTP serving).
// These fields are configuration placeholders for now: consumers
// (milter adapter, MIME parser, HTTP server) will read them once
// implemented (ATR-115, ATR-117, ATR-125).
type LimitsConfig struct {
	// MaxMessageSize is the maximum accepted size, in bytes, of an
	// entire email message (headers + body). Messages larger than
	// this are rejected per the configured fail-open/fail-closed
	// policy. Default: 100 MiB.
	MaxMessageSize int64 `yaml:"max_message_size"`

	// MaxAttachmentSize is the maximum accepted size, in bytes, of a
	// single MIME part/attachment. Default: 25 MiB.
	MaxAttachmentSize int64 `yaml:"max_attachment_size"`

	// MaxMIMEParts is the maximum number of MIME parts (leaf and
	// container) a message may contain before parsing is aborted.
	// Guards against part-count exhaustion attacks. Default: 1000.
	MaxMIMEParts int `yaml:"max_mime_parts"`

	// MaxMIMEDepth is the maximum nesting depth of MIME
	// multipart/message containers before parsing is aborted. Guards
	// against stack/resource exhaustion from deeply nested MIME
	// trees. Default: 20.
	MaxMIMEDepth int `yaml:"max_mime_depth"`

	// MaxHeaderBytes is the maximum total size, in bytes, of a
	// message's header block. Default: 1 MiB.
	MaxHeaderBytes int64 `yaml:"max_header_bytes"`

	// MilterMaxConnections is the maximum number of concurrent milter
	// sessions accepted by the milter adapter. Default: 100.
	MilterMaxConnections int `yaml:"milter_max_connections"`

	// MilterTimeout is the maximum duration, in seconds, a single
	// milter session may remain open before being closed. Default: 30.
	MilterTimeout int `yaml:"milter_timeout"`

	// HTTPTimeout is the maximum duration, in seconds, for a single
	// HTTP request/response cycle (e.g. download endpoint). Default: 30.
	HTTPTimeout int `yaml:"http_timeout"`

	// InlineMaxSize is the maximum size, in bytes, of a presentation-
	// inline asset (a `cid:`-referenced image inside multipart/related,
	// ADR-016) eligible for the policy engine's protective downgrade:
	// an InlineAsset part whose resolved action is `replace` is
	// downgraded to `pass` (unless the policy explicitly opted it in
	// via `when.attachment.disposition`) only when its detected type is
	// image/* AND its size is within this bound. Default: 256 KiB
	// (262144 bytes).
	InlineMaxSize int64 `yaml:"inline_max_size"`
}

// StorageConfig selects and configures the attachment object storage
// backend (US-5.1, US-5.2; internal/core/storage). Exactly one of the
// S3 or FS sections is used, chosen by Driver.
type StorageConfig struct {
	// Driver selects the storage backend: "s3" or "fs".
	Driver string          `yaml:"driver"`
	S3     S3Config        `yaml:"s3"`
	FS     FSStorageConfig `yaml:"fs"`
}

// S3Config configures the S3-compatible storage driver
// (internal/core/storage/s3, ATR-173). AccessKey and SecretKey are
// typed as Secret so they are never printed in logs or error
// messages (see internal/config/secret.go).
type S3Config struct {
	// Endpoint is the S3-compatible service endpoint URL (e.g.
	// "https://s3.amazonaws.com" or "http://localhost:9000" for
	// MinIO). Empty means "use the AWS SDK's default resolution for
	// Region".
	Endpoint string `yaml:"endpoint"`

	// Region is the AWS region (or a placeholder region such as
	// "us-east-1" for MinIO, which ignores it but the SDK requires a
	// value).
	Region string `yaml:"region"`

	// Bucket is the name of the S3 bucket objects are stored in.
	Bucket string `yaml:"bucket"`

	// AccessKey and SecretKey are static credentials. If either is
	// empty, the AWS SDK's default credential chain (env vars,
	// shared config, instance/task role) is used instead.
	AccessKey Secret `yaml:"access_key"`
	SecretKey Secret `yaml:"secret_key"`

	// PathStyle forces path-style bucket addressing
	// (https://endpoint/bucket/key instead of
	// https://bucket.endpoint/key), required by MinIO and most
	// non-AWS S3-compatible services.
	PathStyle bool `yaml:"path_style"`

	// SSE selects server-side encryption applied to objects on Put,
	// at the storage-service level (SR-121-2): one of "" (no SSE
	// header sent), "AES256" (SSE-S3), or "aws:kms" (SSE-KMS). See
	// internal/core/storage/s3 godoc for the client-side encryption
	// extension point this does not yet cover.
	SSE string `yaml:"sse"`

	// SSEKMSKeyID is the KMS key ID/ARN to use when SSE is
	// "aws:kms". Ignored otherwise.
	SSEKMSKeyID string `yaml:"sse_kms_key_id"`
}

// FSStorageConfig configures the local filesystem storage driver
// (internal/core/storage/fs, ATR-176).
type FSStorageConfig struct {
	// BaseDir is the root directory under which all objects are
	// stored. Must be an existing directory the process can write
	// to; every object path is validated to resolve inside it
	// (SR-122-1).
	BaseDir string `yaml:"base_dir"`
}

// PolicyConfig selects and configures the attachment policy engine
// (US-4.1/US-4.2; internal/core/policy).
type PolicyConfig struct {
	// Path is the filesystem path to the policy YAML document (see
	// docs/architecture/policy-format-v1.md). Empty (the default)
	// means no policy is loaded at all: the application falls back to
	// pipeline.PassthroughProcessor, preserving the pre-US-4.x
	// behavior for backward compatibility. When non-empty, the path
	// must point to a file that parses and validates (internal/core/
	// policy.Load); attachra fails to start otherwise, since starting
	// with no policy loaded when one was explicitly configured would
	// silently accept every attachment.
	Path string `yaml:"path"`

	// DryRun, when true, makes the policy engine compute and log every
	// decision as usual but always return ActionPass to the caller
	// (US-4.2/T-4.2.2), so operators can validate a new policy's
	// effect against live traffic before enforcing it. A rule's own
	// `then.dry_run` (see policy.ActionSpec.DryRun) overrides this
	// global default for matches of that specific rule. See
	// internal/core/policy.ApplyMode for where this is applied.
	DryRun bool `yaml:"dry_run"`
}

// DatabaseConfig selects and configures the metadata database backend
// (US-6.1, ADR-011; internal/core/store). MVP supports only the
// embedded sqlite driver: adding a postgres driver/DSN is explicitly
// out of scope until v0.2 (ADR-011 "What we lock into MVP code"), so
// no dsn/host/credential fields exist here yet.
type DatabaseConfig struct {
	// Driver selects the metadata store backend. Only "sqlite" is
	// supported in this build.
	Driver string `yaml:"driver"`

	// Path is the filesystem path to the SQLite database file. The
	// containing directory is created automatically on first start if
	// missing (mode 0700, ATR-310); the file itself is created on
	// first run.
	Path string `yaml:"path"`
}

// LinksConfig configures the Link Engine's fallback parameters
// (T-6.1.2; internal/core/link), applied whenever a matched policy
// rule (or Policy.Defaults) leaves a field unset.
type LinksConfig struct {
	// DefaultTTL is the link lifetime used when a policy does not set
	// `ttl`, expressed in seconds to keep this section a plain,
	// comparable struct (matching the rest of Config) rather than
	// depending on internal/core/policy's Duration scalar type.
	DefaultTTLSeconds int64 `yaml:"default_ttl_seconds"`

	// DefaultMaxDownloads is the download budget used when a policy
	// does not set `max_downloads`. 0 means unlimited.
	DefaultMaxDownloads int `yaml:"default_max_downloads"`

	// TokenBytes is the number of crypto/rand bytes used to generate
	// each link token. Must be >= 16 (128 bits, the token-hygiene
	// invariant / SR-124-1).
	TokenBytes int `yaml:"token_bytes"`

	// DefaultRetentionSeconds is the storage retention used when a
	// policy does not set `retention` (US-5.3/ATR-178, SR-123-1),
	// expressed in seconds like DefaultTTLSeconds. 0 means "no explicit
	// global floor": internal/core/link.Engine then falls back to
	// whichever TTL applies to the same link, which is always a valid,
	// non-zero retention (link.resolveParams guarantees retention >=
	// ttl unconditionally). If set, it must not be shorter than
	// DefaultTTLSeconds (validate() rejects that combination at load
	// time as an operator misconfiguration, rather than silently
	// clamping it).
	DefaultRetentionSeconds int64 `yaml:"default_retention_seconds"`
}

// RetentionConfig configures the background storage-retention cleanup
// job (US-5.3/ATR-179, T-5.3.2; internal/core/retention).
type RetentionConfig struct {
	// Enabled toggles the background cleanup loop. Default: true.
	Enabled bool `yaml:"enabled"`

	// IntervalSeconds is how often a sweep pass runs. Must be positive
	// when Enabled. Default: 3600 (hourly).
	IntervalSeconds int64 `yaml:"interval_seconds"`

	// ChunkSize bounds how many expired attachments are fetched per
	// database round trip within a single sweep pass (ADR-011's
	// "chunked DELETE" guidance; see retention.Params.ChunkSize). Must
	// be positive when Enabled. Default: 200.
	ChunkSize int `yaml:"chunk_size"`

	// AuditRetentionSeconds is how long audit-log events are kept before
	// the sweep truncates them (ATR-308, ADR-017). Default: 0 =
	// DISABLED: the tamper-evident audit log stays append-only forever,
	// byte-for-byte the historical behavior. This is opt-in and separate
	// from the file/link retention (links.default_retention_seconds);
	// truncation preserves hash-chain verifiability via a checkpoint
	// anchor and respects legal hold (see ADR-017). When > 0 it runs
	// inside this same sweep, so it also requires Enabled = true. Must
	// not be negative.
	AuditRetentionSeconds int64 `yaml:"audit_retention_seconds"`
}

// SpoolConfig configures where temporary spool files are created:
// message bodies staged by the milter adapter and the core pipeline,
// and rewritten MIME output staged by internal/core/rewrite, once a
// stream exceeds spoolutil.SpoolMemThreshold (ATR-262).
type SpoolConfig struct {
	// Dir is the directory os.CreateTemp writes spool files into.
	// Empty (the default) means "use the OS default temporary
	// directory" ($TMPDIR / os.TempDir()), preserving pre-ATR-262
	// behavior.
	//
	// When set, Dir must already exist and be writable by the Attachra
	// process; Validate checks both at startup (fail fast), rather
	// than deferring the failure to the first message that needs to
	// spill to disk.
	//
	// Deployments packaged with systemd's PrivateTmp=true (Attachra's
	// own deb unit is, see deploy/deb/systemd/attachra.service) already
	// give the process a private, writable /tmp isolated from the
	// host's — Dir does not need to be set in that case. Dir exists
	// for deployments that lock down or quota /tmp itself (e.g.
	// noexec/nosuid mounts, a size-limited tmpfs, or a shared host
	// without PrivateTmp) and need spool files to land somewhere else
	// entirely. If Dir is set under a systemd unit with
	// ProtectSystem=strict (as the packaged unit has), it must also be
	// listed in that unit's ReadWritePaths=, or writes to it will be
	// rejected by the sandbox regardless of filesystem permissions.
	Dir string `yaml:"dir"`
}

// validate checks the spool directory configuration, returning a
// slice of field-specific error strings. An empty Dir is always valid
// (it means "use the OS default temporary directory"); Validate never
// creates a configured Dir on the caller's behalf, unlike
// storage.fs.Driver's handling of base_dir — an operator-specified
// spool directory failing to exist is treated as a configuration
// mistake to fail fast on, not something to paper over.
func (s SpoolConfig) validate() []string {
	if strings.TrimSpace(s.Dir) == "" {
		return nil
	}

	info, err := os.Stat(s.Dir)
	if err != nil {
		return []string{fmt.Sprintf("spool.dir: %v", err)}
	}
	if !info.IsDir() {
		return []string{fmt.Sprintf("spool.dir: %q is not a directory", s.Dir)}
	}

	probe, err := os.CreateTemp(s.Dir, ".attachra-spool-probe-*")
	if err != nil {
		return []string{fmt.Sprintf("spool.dir: %q is not writable: %v", s.Dir, err)}
	}
	name := probe.Name()
	_ = probe.Close()
	if err := os.Remove(name); err != nil {
		return []string{fmt.Sprintf("spool.dir: failed to clean up write probe in %q: %v", s.Dir, err)}
	}

	return nil
}

// Default returns a Config populated with sane defaults.
func Default() Config {
	return Config{
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
		Milter: MilterConfig{
			Listen:      "inet:127.0.0.1:6785",
			FailureMode: "open",
		},
		HTTP: HTTPConfig{
			Listen: "127.0.0.1:8080",
			RateLimit: HTTPRateLimitConfig{
				PerIPPerMinute:         120,
				PerIPBurst:             20,
				GlobalPerMinute:        6000,
				GlobalBurst:            200,
				NotFoundPerIPPerMinute: 20,
				TarpitDelaySeconds:     1.0,
			},
		},
		Admin: AdminConfig{
			// 18090, not 9090: 9090 is Prometheus's OWN default listen
			// port, the single most likely co-located neighbor on a
			// host running Attachra — binding it here would collide
			// with a local Prometheus server (which typically binds
			// 0.0.0.0, covering this loopback address too) more often
			// than not (ATR-292 security review). 18090 pairs with the
			// deb package's http.listen override of 18080 (see
			// deploy/deb/etc/attachra.yaml).
			Listen: "127.0.0.1:18090",
		},
		Limits: LimitsConfig{
			MaxMessageSize:       100 * 1024 * 1024, // 100 MiB
			MaxAttachmentSize:    25 * 1024 * 1024,  // 25 MiB
			MaxMIMEParts:         1000,
			MaxMIMEDepth:         20,
			MaxHeaderBytes:       1 * 1024 * 1024, // 1 MiB
			MilterMaxConnections: 100,
			MilterTimeout:        30,
			HTTPTimeout:          30,
			InlineMaxSize:        256 * 1024, // 256 KiB.
		},
		Storage: StorageConfig{
			Driver: "fs",
			FS: FSStorageConfig{
				BaseDir: "./data/attachments",
			},
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			Path:   "./data/attachra.db",
		},
		Links: LinksConfig{
			DefaultTTLSeconds:       int64((7 * 24 * time.Hour).Seconds()),  // 7 days.
			DefaultMaxDownloads:     0,                                      // Unlimited.
			TokenBytes:              16,                                     // 128 bits.
			DefaultRetentionSeconds: int64((30 * 24 * time.Hour).Seconds()), // 30 days (outlives the default TTL, ATR-178).
		},
		Retention: RetentionConfig{
			Enabled:         true,
			IntervalSeconds: int64((1 * time.Hour).Seconds()), // Hourly.
			ChunkSize:       200,
		},
	}
}

// envPrefix is the prefix used for environment variable overrides.
const envPrefix = "ATTACHRA_"

// Load reads configuration from the YAML file at path (if path is
// non-empty and the file exists), then applies environment variable
// overrides, and finally validates the result.
//
// Before parsing, any ${ENV_VAR} placeholders in the raw file content
// are substituted with the value of the corresponding environment
// variable. This allows secrets (S3 credentials, DB passwords, API
// keys) to be referenced from the config file without being hardcoded
// in it. A placeholder referencing an unset environment variable is
// left as-is (substituted with the empty string is deliberately not
// done, to avoid silently coercing an operator typo into an empty
// secret); validation of the resulting config catches missing
// required values.
//
// Environment variables use the form ATTACHRA_<SECTION>_<FIELD>, e.g.
// ATTACHRA_LOG_LEVEL, ATTACHRA_LOG_FORMAT, ATTACHRA_MILTER_LISTEN,
// ATTACHRA_HTTP_LISTEN, ATTACHRA_ADMIN_LISTEN,
// ATTACHRA_ADMIN_FOLD_INTO_HTTP, ATTACHRA_POLICY_PATH,
// ATTACHRA_POLICY_DRY_RUN.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied CLI/config flag, not untrusted input
		if err != nil {
			return Config{}, fmt.Errorf("config: read %q: %w", path, err)
		}
		data = expandEnv(data)
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("config: parse %q: %w", path, err)
		}
	}

	applyEnvOverrides(&cfg)

	// admin.listen empty (YAML key absent, an explicit `listen: ""`, or
	// an empty-but-present ATTACHRA_ADMIN_LISTEN) is never treated as
	// an opt-out: it always resolves to the safe default loopback
	// address unless admin.fold_into_http explicitly requested folding
	// (ATR-292 security review — see AdminConfig's doc comment for
	// why "absent" and "opt out" must not be conflated).
	if !cfg.Admin.FoldIntoHTTP && strings.TrimSpace(cfg.Admin.Listen) == "" {
		cfg.Admin.Listen = Default().Admin.Listen
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: validate: %w", err)
	}

	return cfg, nil
}

// applyEnvOverrides overrides cfg fields from environment variables
// prefixed with ATTACHRA_, if set.
func applyEnvOverrides(cfg *Config) {
	if v, ok := lookupEnv("LOG_LEVEL"); ok {
		cfg.Log.Level = v
	}
	if v, ok := lookupEnv("LOG_FORMAT"); ok {
		cfg.Log.Format = v
	}
	if v, ok := lookupEnv("MILTER_LISTEN"); ok {
		cfg.Milter.Listen = v
	}
	if v, ok := lookupEnv("MILTER_FAILURE_MODE"); ok {
		cfg.Milter.FailureMode = v
	}
	if v, ok := lookupEnv("HTTP_LISTEN"); ok {
		cfg.HTTP.Listen = v
	}
	if v, ok := lookupEnv("ADMIN_LISTEN"); ok {
		cfg.Admin.Listen = v
	}
	if v, ok := lookupEnv("ADMIN_FOLD_INTO_HTTP"); ok {
		cfg.Admin.FoldIntoHTTP = strings.EqualFold(v, "true") || v == "1"
	}
	if v, ok := lookupEnvInt("HTTP_RATE_LIMIT_PER_IP_PER_MINUTE"); ok {
		cfg.HTTP.RateLimit.PerIPPerMinute = v
	}
	if v, ok := lookupEnvInt("HTTP_RATE_LIMIT_GLOBAL_PER_MINUTE"); ok {
		cfg.HTTP.RateLimit.GlobalPerMinute = v
	}
	if v, ok := lookupEnv("PUBLIC_BASE_URL"); ok {
		cfg.PublicBaseURL = v
	}
	if v, ok := lookupEnv("STORAGE_DRIVER"); ok {
		cfg.Storage.Driver = v
	}
	if v, ok := lookupEnv("STORAGE_S3_ENDPOINT"); ok {
		cfg.Storage.S3.Endpoint = v
	}
	if v, ok := lookupEnv("STORAGE_S3_REGION"); ok {
		cfg.Storage.S3.Region = v
	}
	if v, ok := lookupEnv("STORAGE_S3_BUCKET"); ok {
		cfg.Storage.S3.Bucket = v
	}
	if v, ok := lookupEnv("STORAGE_S3_ACCESS_KEY"); ok {
		cfg.Storage.S3.AccessKey = Secret(v)
	}
	if v, ok := lookupEnv("STORAGE_S3_SECRET_KEY"); ok {
		cfg.Storage.S3.SecretKey = Secret(v)
	}
	if v, ok := lookupEnv("STORAGE_FS_BASE_DIR"); ok {
		cfg.Storage.FS.BaseDir = v
	}
	if v, ok := lookupEnv("POLICY_PATH"); ok {
		cfg.Policy.Path = v
	}
	if v, ok := lookupEnv("POLICY_DRY_RUN"); ok {
		cfg.Policy.DryRun = strings.EqualFold(v, "true") || v == "1"
	}
	if v, ok := lookupEnv("DATABASE_DRIVER"); ok {
		cfg.Database.Driver = v
	}
	if v, ok := lookupEnv("DATABASE_PATH"); ok {
		cfg.Database.Path = v
	}
	if v, ok := lookupEnv("SPOOL_DIR"); ok {
		cfg.Spool.Dir = v
	}
}

// lookupEnv looks up ATTACHRA_<name> in the environment.
func lookupEnv(name string) (string, bool) {
	return os.LookupEnv(envPrefix + name)
}

// lookupEnvInt looks up ATTACHRA_<name> in the environment and parses
// it as an int. A missing or unparsable value returns ok == false (an
// unparsable value is silently ignored rather than surfaced as a
// startup error, matching this package's existing lenient env-override
// posture — Validate() still catches an eventually-invalid resulting
// config).
func lookupEnvInt(name string) (int, bool) {
	v, ok := lookupEnv(name)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// validLogLevels, validLogFormats and validMilterFailureModes
// enumerate accepted values.
var (
	validLogLevels          = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	validLogFormats         = map[string]bool{"json": true, "text": true}
	validMilterFailureModes = map[string]bool{"open": true, "closed": true}
)

// Validate checks that the configuration is well-formed, returning a
// descriptive error identifying the offending field(s).
//
// Validate never includes secret field values in its error messages:
// secret-typed fields are only checked for presence/absence, never
// formatted into the returned error.
func (c Config) Validate() error {
	var errs []string

	level := strings.ToLower(c.Log.Level)
	if !validLogLevels[level] {
		errs = append(errs, fmt.Sprintf("log.level: invalid value %q (want one of: debug, info, warn, error)", c.Log.Level))
	}

	format := strings.ToLower(c.Log.Format)
	if !validLogFormats[format] {
		errs = append(errs, fmt.Sprintf("log.format: invalid value %q (want one of: json, text)", c.Log.Format))
	}

	if strings.TrimSpace(c.Milter.Listen) == "" {
		errs = append(errs, "milter.listen: must not be empty")
	}

	failureMode := strings.ToLower(c.Milter.FailureMode)
	if !validMilterFailureModes[failureMode] {
		errs = append(errs, fmt.Sprintf("milter.failure_mode: invalid value %q (want one of: open, closed)", c.Milter.FailureMode))
	}

	if strings.TrimSpace(c.HTTP.Listen) == "" {
		errs = append(errs, "http.listen: must not be empty")
	}
	errs = append(errs, c.HTTP.RateLimit.validate()...)
	errs = append(errs, c.HTTP.validateTrustedProxies()...)

	// Defense in depth for AdminConfig's "empty is never an opt-out"
	// contract (ATR-292 security review): Load() already normalizes an
	// empty admin.listen back to the safe default before calling
	// Validate, so this only ever fires for a Config built directly
	// (bypassing Load) — fail closed rather than let it silently reach
	// internal/adapters/http as an implicit fold.
	if !c.Admin.FoldIntoHTTP && strings.TrimSpace(c.Admin.Listen) == "" {
		errs = append(errs, "admin.listen: must not be empty unless admin.fold_into_http is true")
	}

	errs = append(errs, c.Limits.validate()...)
	errs = append(errs, c.Storage.validate()...)
	errs = append(errs, c.Database.validate()...)
	errs = append(errs, c.Links.validate()...)
	errs = append(errs, c.Retention.validate()...)
	errs = append(errs, c.Spool.validate()...)

	if c.PublicBaseURL != "" {
		if err := validatePublicBaseURL(c.PublicBaseURL); err != nil {
			errs = append(errs, fmt.Sprintf("public_base_url: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}

// validate checks that all limits are positive (a zero or negative
// value would either disable enforcement by accident or make the
// limit trivially impossible to satisfy), returning a slice of
// field-specific error strings.
func (l LimitsConfig) validate() []string {
	var errs []string

	checks := []struct {
		name  string
		value int64
	}{
		{"limits.max_message_size", l.MaxMessageSize},
		{"limits.max_attachment_size", l.MaxAttachmentSize},
		{"limits.max_mime_parts", int64(l.MaxMIMEParts)},
		{"limits.max_mime_depth", int64(l.MaxMIMEDepth)},
		{"limits.max_header_bytes", l.MaxHeaderBytes},
		{"limits.milter_max_connections", int64(l.MilterMaxConnections)},
		{"limits.milter_timeout", int64(l.MilterTimeout)},
		{"limits.http_timeout", int64(l.HTTPTimeout)},
		{"limits.inline_max_size", l.InlineMaxSize},
	}

	for _, c := range checks {
		if c.value <= 0 {
			errs = append(errs, fmt.Sprintf("%s: must be a positive value, got %d", c.name, c.value))
		}
	}

	return errs
}

// validStorageDrivers enumerates accepted storage.driver values.
var validStorageDrivers = map[string]bool{"s3": true, "fs": true}

// validSSEModes enumerates accepted storage.s3.sse values. The empty
// string means "no SSE header sent".
var validSSEModes = map[string]bool{"": true, "AES256": true, "aws:kms": true}

// validate checks the storage configuration, returning a slice of
// field-specific error strings. Only the section matching the
// selected Driver is validated in detail; the other section's fields
// are ignored (an operator may leave defaults or a previous driver's
// leftover config in the unused section).
//
// validate never includes Secret field values in its error messages
// (only presence/absence is checked), matching the contract of
// Config.Validate.
func (s StorageConfig) validate() []string {
	var errs []string

	driver := s.Driver
	if !validStorageDrivers[driver] {
		errs = append(errs, fmt.Sprintf("storage.driver: invalid value %q (want one of: s3, fs)", s.Driver))
		return errs
	}

	switch driver {
	case "s3":
		if strings.TrimSpace(s.S3.Bucket) == "" {
			errs = append(errs, "storage.s3.bucket: must not be empty")
		}
		if strings.TrimSpace(s.S3.Region) == "" {
			errs = append(errs, "storage.s3.region: must not be empty")
		}
		if !validSSEModes[s.S3.SSE] {
			errs = append(errs, fmt.Sprintf("storage.s3.sse: invalid value %q (want one of: \"\", AES256, aws:kms)", s.S3.SSE))
		}
	case "fs":
		if strings.TrimSpace(s.FS.BaseDir) == "" {
			errs = append(errs, "storage.fs.base_dir: must not be empty")
		}
	}

	return errs
}

// validDatabaseDrivers enumerates accepted database.driver values.
// Only "sqlite" ships in MVP (ADR-011): a postgres driver/DSN is a
// deliberately out-of-scope v0.2 addition, not a placeholder left
// here to fill in later.
var validDatabaseDrivers = map[string]bool{"sqlite": true}

// validate checks the database configuration, returning a slice of
// field-specific error strings.
func (d DatabaseConfig) validate() []string {
	var errs []string

	if !validDatabaseDrivers[d.Driver] {
		errs = append(errs, fmt.Sprintf("database.driver: invalid value %q (want one of: sqlite)", d.Driver))
	}
	if strings.TrimSpace(d.Path) == "" {
		errs = append(errs, "database.path: must not be empty")
	}

	return errs
}

// validate checks the links configuration, returning a slice of
// field-specific error strings.
func (l LinksConfig) validate() []string {
	var errs []string

	if l.DefaultTTLSeconds <= 0 {
		errs = append(errs, fmt.Sprintf("links.default_ttl_seconds: must be a positive value, got %d", l.DefaultTTLSeconds))
	}
	if l.DefaultMaxDownloads < 0 {
		errs = append(errs, fmt.Sprintf("links.default_max_downloads: must not be negative, got %d", l.DefaultMaxDownloads))
	}
	const minTokenBytes = 16 // Mirrors link.MinTokenBytes; internal/config must not import internal/core/link (ADR-002 keeps the dependency one-directional).
	if l.TokenBytes < minTokenBytes {
		errs = append(errs, fmt.Sprintf("links.token_bytes: must be at least %d (128 bits), got %d", minTokenBytes, l.TokenBytes))
	}

	if l.DefaultRetentionSeconds < 0 {
		errs = append(errs, fmt.Sprintf("links.default_retention_seconds: must not be negative, got %d", l.DefaultRetentionSeconds))
	} else if l.DefaultRetentionSeconds > 0 && l.DefaultRetentionSeconds < l.DefaultTTLSeconds {
		// An explicitly configured retention shorter than the default
		// TTL is always an operator mistake (a link would then
		// outlive the object it points to): fail fast at load time
		// instead of silently clamping it at resolve time the way
		// link.resolveParams does for a per-policy value (that clamp
		// exists to keep an ambiguous *policy* value safe at runtime;
		// a misconfigured *global default* should be caught up front).
		errs = append(errs, fmt.Sprintf(
			"links.default_retention_seconds: must be at least links.default_ttl_seconds (%d) when set, got %d",
			l.DefaultTTLSeconds, l.DefaultRetentionSeconds))
	}

	return errs
}

// validate checks the retention cleanup job configuration, returning a
// slice of field-specific error strings. IntervalSeconds/ChunkSize are
// only required to be positive when Enabled, since a disabled job's
// tuning values are inert.
func (r RetentionConfig) validate() []string {
	var errs []string

	// A negative audit retention is always a misconfiguration, even when
	// the job is disabled (a disabled job's inert tuning values may stay
	// unvalidated, but a negative duration is never a meaningful value).
	if r.AuditRetentionSeconds < 0 {
		errs = append(errs, fmt.Sprintf("retention.audit_retention_seconds: must not be negative, got %d", r.AuditRetentionSeconds))
	}

	if !r.Enabled {
		return errs
	}

	if r.IntervalSeconds <= 0 {
		errs = append(errs, fmt.Sprintf("retention.interval_seconds: must be a positive value, got %d", r.IntervalSeconds))
	}
	if r.ChunkSize <= 0 {
		errs = append(errs, fmt.Sprintf("retention.chunk_size: must be a positive value, got %d", r.ChunkSize))
	}

	return errs
}

// validate checks the download adapter's rate-limit configuration,
// returning a slice of field-specific error strings. Negative values
// are rejected; zero is a valid "disabled" sentinel for every *PerMinute
// field (internal/adapters/http treats <= 0 as no limit), so only
// negative values are an error here.
func (r HTTPRateLimitConfig) validate() []string {
	var errs []string

	checks := []struct {
		name  string
		value int
	}{
		{"http.rate_limit.per_ip_per_minute", r.PerIPPerMinute},
		{"http.rate_limit.per_ip_burst", r.PerIPBurst},
		{"http.rate_limit.global_per_minute", r.GlobalPerMinute},
		{"http.rate_limit.global_burst", r.GlobalBurst},
		{"http.rate_limit.not_found_per_ip_per_minute", r.NotFoundPerIPPerMinute},
	}
	for _, c := range checks {
		if c.value < 0 {
			errs = append(errs, fmt.Sprintf("%s: must not be negative, got %d", c.name, c.value))
		}
	}

	if r.TarpitDelaySeconds < 0 {
		errs = append(errs, fmt.Sprintf("http.rate_limit.tarpit_delay_seconds: must not be negative, got %v", r.TarpitDelaySeconds))
	}

	return errs
}

// validateTrustedProxies checks that every entry in TrustedProxies
// parses as a CIDR prefix (IPv4 or IPv6), returning a slice of
// field-specific error strings identifying the offending entry by
// index (ATR-311). This is deliberately just a parse check, not a
// duplication of the []netip.Prefix values themselves — cmd/attachra
// re-parses the same, now-known-valid strings via
// internal/adapters/http.ParseTrustedProxies when wiring the download
// and API adapters, so the CIDR-parsing logic and its error format live
// in exactly one place (that adapter package, which is also where the
// parsed values are consumed).
func (h HTTPConfig) validateTrustedProxies() []string {
	var errs []string
	for i, cidr := range h.TrustedProxies {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			errs = append(errs, fmt.Sprintf("http.trusted_proxies[%d]: invalid CIDR %q: %v", i, cidr, err))
		}
	}
	return errs
}

// validatePublicBaseURL checks that the given base URL for download
// links is an absolute, well-formed http(s) URL.
func validatePublicBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("must include a host")
	}
	return nil
}

// expandEnv substitutes ${ENV_VAR} placeholders in data with the
// value of the corresponding environment variable. Placeholders
// referencing an unset variable are left unchanged in the output so
// that a missing secret is not silently replaced with an empty
// string. This is intentionally simpler than os.Expand/os.ExpandEnv:
// only the ${NAME} form is recognized (not bare $NAME), and unset
// variables are preserved verbatim rather than removed.
func expandEnv(data []byte) []byte {
	const (
		prefix = "${"
		suffix = "}"
	)

	s := string(data)
	var b strings.Builder
	b.Grow(len(s))

	for {
		start := strings.Index(s, prefix)
		if start < 0 {
			b.WriteString(s)
			break
		}
		end := strings.Index(s[start+len(prefix):], suffix)
		if end < 0 {
			b.WriteString(s)
			break
		}
		end += start + len(prefix)

		name := s[start+len(prefix) : end]
		b.WriteString(s[:start])

		if v, ok := os.LookupEnv(name); ok && isValidEnvName(name) {
			b.WriteString(v)
		} else {
			b.WriteString(s[start : end+len(suffix)])
		}

		s = s[end+len(suffix):]
	}

	return []byte(b.String())
}

// isValidEnvName reports whether name looks like a plausible
// environment variable name, guarding against accidentally expanding
// unrelated "${...}" occurrences (e.g. YAML anchors or literal
// strings) that are not intended as substitutions.
func isValidEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
