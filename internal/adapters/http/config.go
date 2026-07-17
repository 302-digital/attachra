package http

import (
	"net/netip"
	"time"
)

// Config holds the settings the download adapter needs beyond the
// listen address (internal/config.HTTPConfig / LimitsConfig carry the
// operator-facing values; cmd/attachra translates them into this
// adapter-local shape, mirroring the milter adapter's Config in
// internal/adapters/milter/config.go).
type Config struct {
	// Listen is the TCP address the download server binds to (e.g.
	// "127.0.0.1:8080").
	Listen string

	// AdminListen is the TCP address the admin server (GET /metrics,
	// the dependency-detailed GET /readyz) binds to (ATR-292, e.g.
	// "127.0.0.1:18090"). Empty folds the admin routes onto Listen
	// instead, reproducing the pre-ATR-292 single-listener behavior —
	// NewServer logs this loudly at startup, since it is a deliberate
	// hardening downgrade (see its own doc comment). The caller
	// (cmd/attachra) is responsible for only ever passing an empty
	// value here when the operator explicitly opted in via
	// internal/config.AdminConfig.FoldIntoHTTP: this package's own
	// "empty means fold" contract does not itself distinguish an
	// intentional opt-out from an accidental one — that guarantee
	// lives in internal/config.Load's normalization instead (a merely
	// absent or empty admin.listen, from YAML or an env override, is
	// never enough to reach this field as empty).
	AdminListen string

	// ReadTimeout, WriteTimeout and IdleTimeout bound how long a single
	// connection may take at each phase (T1.2/SR-125-1). Zero disables
	// the corresponding timeout (not recommended).
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// MaxConnections bounds the number of concurrent connections the
	// server will accept (SR-115-2, via the shared
	// internal/adapters/netutil.LimitListener the milter adapter also
	// uses). A value <= 0 disables the limit.
	MaxConnections int

	// ShutdownTimeout bounds how long Shutdown waits for in-flight
	// requests to finish before forcibly closing them.
	ShutdownTimeout time.Duration

	// RateLimit configures per-IP and global request throttling
	// (SR-125-7).
	RateLimit RateLimitConfig

	// TrustedProxies is the parsed form of internal/config.HTTPConfig.
	// TrustedProxies (see ParseTrustedProxies), the set of reverse-proxy
	// CIDR ranges clientIP trusts to set X-Forwarded-For/X-Real-IP
	// (ATR-311). Empty (the default) means no proxy is trusted: every
	// request's client identity is RemoteAddr, ignoring both headers.
	TrustedProxies []netip.Prefix
}

// RateLimitConfig configures the token-bucket rate limiters applied to
// every request before it reaches a handler (SR-125-7: per-IP and
// global limits, plus a tighter budget for requests that end up
// resolving to a generic not-found response, which absorbs the
// deliberate tarpit/backoff behavior for enumeration bursts).
type RateLimitConfig struct {
	// PerIPRequestsPerMinute is the sustained request rate allowed for
	// a single client IP. A value <= 0 disables the per-IP limit.
	PerIPRequestsPerMinute int

	// PerIPBurst is the maximum number of requests a single client IP
	// may make in a short burst before being throttled. A value <= 0
	// defaults to PerIPRequestsPerMinute.
	PerIPBurst int

	// GlobalRequestsPerMinute is the sustained request rate allowed
	// across all clients combined. A value <= 0 disables the global
	// limit.
	GlobalRequestsPerMinute int

	// GlobalBurst is the maximum burst size for the global limiter. A
	// value <= 0 defaults to GlobalRequestsPerMinute.
	GlobalBurst int

	// NotFoundPerIPPerMinute is the (tighter) sustained rate allowed
	// for requests from a single IP that resolve to the generic
	// not-found/expired/revoked/exhausted response. Repeated 404s are
	// the signature of token enumeration (T1.1); once this budget is
	// exceeded further requests from the same IP are tarpitted
	// (delayed) in addition to being throttled. A value <= 0 disables
	// this tighter accounting (the general per-IP limit still applies).
	NotFoundPerIPPerMinute int

	// TarpitDelay is the artificial delay added to a response once an
	// IP has exceeded NotFoundPerIPPerMinute, making automated
	// enumeration slower without an outright hard failure. Zero
	// disables the delay (the request is still rate-limited/rejected
	// once the harder limit is hit).
	TarpitDelay time.Duration

	// EvictionMaxEntries bounds the number of distinct client IPs each
	// per-IP bucket map (the general request budget and the
	// not-found/tarpit budget) tracks at once (ATR-297): once exceeded,
	// the least-recently-used entries are evicted first, giving a hard
	// ceiling on memory under a distributed attack. A value <= 0
	// defaults to defaultBucketMapMaxEntries.
	EvictionMaxEntries int

	// EvictionTTL evicts a per-IP bucket entry once it has been idle
	// this long (ATR-297), keeping steady-state memory well under
	// EvictionMaxEntries rather than only bounding the worst case. A
	// value <= 0 defaults to defaultBucketMapTTL.
	EvictionTTL time.Duration
}

// normalized returns a copy of c with defaulted fields filled in,
// mirroring internal/adapters/milter.Config.normalized.
func (c Config) normalized() Config {
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	if c.RateLimit.PerIPBurst <= 0 {
		c.RateLimit.PerIPBurst = c.RateLimit.PerIPRequestsPerMinute
	}
	if c.RateLimit.GlobalBurst <= 0 {
		c.RateLimit.GlobalBurst = c.RateLimit.GlobalRequestsPerMinute
	}
	if c.RateLimit.EvictionMaxEntries <= 0 {
		c.RateLimit.EvictionMaxEntries = defaultBucketMapMaxEntries
	}
	if c.RateLimit.EvictionTTL <= 0 {
		c.RateLimit.EvictionTTL = defaultBucketMapTTL
	}
	return c
}
