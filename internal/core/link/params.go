package link

import (
	"fmt"
	"time"

	"github.com/302-digital/attachra/internal/core/policy"
)

// Defaults holds the fallback link parameters applied when a policy's
// ActionParams leaves a field unset (T-6.1.2). It is populated from
// configuration (internal/config, section `links`) rather than
// hardcoded, so operators can tune the out-of-the-box behavior without
// editing policy files.
type Defaults struct {
	// TTL is used when a matching ActionSpec/Policy.Defaults does not
	// set TTL. Must be positive.
	TTL time.Duration

	// MaxDownloads is used when a matching ActionSpec/Policy.Defaults
	// does not set MaxDownloads. Zero means unlimited, matching
	// policy.ActionParams.MaxDownloads's own nil-means-unlimited
	// convention.
	MaxDownloads int

	// TokenBytes is the number of crypto/rand bytes used to generate
	// each link token (>= MinTokenBytes).
	TokenBytes int

	// Retention is used when a matching ActionSpec/Policy.Defaults does
	// not set `retention` (US-5.3/ATR-178, SR-123-1). Zero means "no
	// configured global floor": resolveParams then falls back to TTL
	// itself (see resolveParams' doc comment), which is always a safe,
	// valid retention value. This field is deliberately not required to
	// be positive by Validate — unlike TTL/MaxDownloads/TokenBytes,
	// which have no such fallback — so existing callers that construct
	// Defaults without setting it (every call site that predates
	// ATR-178) keep working unchanged.
	Retention time.Duration
}

// Validate checks that d is well-formed: TTL positive, MaxDownloads
// non-negative, TokenBytes at least MinTokenBytes.
func (d Defaults) Validate() error {
	if d.TTL <= 0 {
		return fmt.Errorf("link: defaults: ttl must be positive, got %s", d.TTL)
	}
	if d.MaxDownloads < 0 {
		return fmt.Errorf("link: defaults: max_downloads must not be negative, got %d", d.MaxDownloads)
	}
	if d.TokenBytes < MinTokenBytes {
		return fmt.Errorf("link: defaults: token_bytes must be at least %d, got %d", MinTokenBytes, d.TokenBytes)
	}
	return nil
}

// resolvedParams is the fully-materialized set of per-link parameters
// after merging an ActionSpec's params with Defaults (T-6.1.2): every
// field is concrete, no more nils.
type resolvedParams struct {
	ttl          time.Duration
	maxDownloads int
	retention    time.Duration

	// retentionClamped is true when retention (below) was raised to
	// equal ttl because a non-zero, explicitly configured value — the
	// policy's `then.retention` or, absent that, a non-zero
	// Defaults.Retention — was shorter than ttl (ATR-294). This is
	// deliberately false when neither the policy nor Defaults set a
	// retention at all (requestedRetention == 0): that is the designed
	// "no floor configured, use ttl" fallback documented on
	// Defaults.Retention, not a value silently overridden, so it must
	// not be reported as a clamp. The clamp itself is required and
	// silent by design (T-5.3.1/ATR-178: "retention >= ttl"), but a
	// clamp firing on a genuinely-configured value is operator-visible
	// information: it means storage data outlives what the matched
	// policy or global config literally asked for, which is worth
	// surfacing for data-minimization review (GDPR art. 5(1)(e)). See
	// CreateLinks' use of this field for where it is logged.
	retentionClamped bool

	// requestedRetention is the retention value that would have
	// applied absent the ttl floor: params.Retention if set, else
	// d.Retention (0 if neither set it). Equal to retention whenever
	// retentionClamped is false. Kept only for diagnostics (the
	// clamp-warning log message); it never reaches persistence —
	// retention (the clamped value) is what CreateLinks actually
	// writes as RetainUntil.
	requestedRetention time.Duration
}

// resolveParams merges params (from a matched Rule's ActionSpec or,
// absent an override, Policy.Defaults — the caller is responsible for
// picking the right policy.ActionParams to pass in, since that
// precedence is a policy-engine concern, not link's) with d, filling
// in any field params leaves nil.
//
// retention is additionally clamped so it is never shorter than ttl
// (T-5.3.1/ATR-178 acceptance criterion: "retention ≥ ttl"), regardless
// of which of the four possible sources (policy ttl/retention, default
// ttl/retention) produced each value: a link must never outlive the
// storage object it points to. When neither the policy nor Defaults
// sets a retention, this clamp is exactly what supplies the "default
// from config when absent" half of that acceptance criterion — the
// resolved retention becomes equal to ttl, which is always a valid,
// non-zero value since Defaults.Validate requires a positive TTL.
// resolvedParams.retentionClamped/requestedRetention (ATR-294) record
// whether this happened and what was asked for, so a caller can log it.
func resolveParams(params policy.ActionParams, d Defaults) resolvedParams {
	out := resolvedParams{
		ttl:          d.TTL,
		maxDownloads: d.MaxDownloads,
		retention:    d.Retention,
	}

	if params.TTL != nil {
		out.ttl = params.TTL.Duration()
	}
	if params.MaxDownloads != nil {
		out.maxDownloads = *params.MaxDownloads
	}
	if params.Retention != nil {
		out.retention = params.Retention.Duration()
	}

	out.requestedRetention = out.retention
	if out.retention < out.ttl {
		// A zero requestedRetention means nothing configured a
		// retention at all (see Defaults.Retention's own doc comment)
		// — that is the designed default-to-ttl fallback, not a
		// surprising override, so it is not flagged as a clamp.
		out.retentionClamped = out.retention != 0
		out.retention = out.ttl
	}

	return out
}
