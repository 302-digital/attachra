package milter

import "time"

// FailureMode selects how the adapter resolves any error or panic
// raised while processing a message (SR-116-1): whether the message
// is passed through unmodified (fail-open) or temporarily rejected so
// the sending MTA retries later (fail-closed). Per the
// mail-must-never-be-lost invariant.
type FailureMode string

// Recognized FailureMode values.
const (
	// FailOpen accepts the message unmodified whenever an error or
	// panic occurs while processing it. This is the default: it
	// favors mail delivery continuity over strict policy enforcement
	// when Attachra itself is unhealthy.
	FailOpen FailureMode = "open"

	// FailClosed temporarily rejects the message (SMTP 4xx) whenever
	// an error or panic occurs while processing it, so the sending
	// MTA retries later. This favors strict policy enforcement over
	// delivery continuity.
	FailClosed FailureMode = "closed"
)

// Valid reports whether m is a recognized FailureMode value.
func (m FailureMode) Valid() bool {
	switch m {
	case FailOpen, FailClosed:
		return true
	default:
		return false
	}
}

// tempFailSMTPCode is the SMTP status code returned to the MTA for a
// fail-closed temporary rejection (4xx: try again later).
const tempFailSMTPCode = 451

// tempFailReason is the SMTP response text returned to the MTA for a
// fail-closed temporary rejection. It intentionally contains no
// message-derived content (no CR/LF injection risk).
const tempFailReason = "4.7.1 Attachra temporarily unavailable, please try again later"

// Config holds the settings the milter adapter needs beyond the
// listen address (internal/config.MilterConfig / LimitsConfig carry
// the operator-facing values; Server translates them into this
// adapter-local shape).
type Config struct {
	// Listen is the milter listen address, in Postfix milter syntax
	// (e.g. "inet:127.0.0.1:6785" or "unix:/var/run/attachra.sock").
	Listen string

	// FailureMode selects fail-open or fail-closed behavior on error
	// (SR-116-1). Defaults to FailOpen if empty.
	FailureMode FailureMode

	// MaxConnections bounds the number of concurrent milter sessions
	// the adapter will accept (SR-115-1). A value <= 0 disables the
	// limit.
	MaxConnections int

	// SessionTimeout bounds how long a single milter session may
	// remain open (SR-115-1). Zero disables the timeout.
	SessionTimeout time.Duration

	// MaxMessageSize is the maximum accepted size, in bytes, of an
	// entire message body streamed through the milter session. Zero
	// disables the limit.
	MaxMessageSize int64

	// ShutdownTimeout bounds how long Server.Shutdown waits for
	// in-flight sessions to finish before forcibly closing them.
	ShutdownTimeout time.Duration

	// SpoolDir selects the directory a session's message-body spool
	// spills to once it exceeds spoolutil.SpoolMemThreshold
	// (ATR-262). It is expected to be config.SpoolConfig.Dir; the
	// empty string (the default) uses the OS default temporary
	// directory ($TMPDIR / os.TempDir()), preserving pre-ATR-262
	// behavior.
	SpoolDir string
}

// normalized returns a copy of c with defaulted fields filled in.
func (c Config) normalized() Config {
	if c.FailureMode == "" {
		c.FailureMode = FailOpen
	}
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	return c
}
