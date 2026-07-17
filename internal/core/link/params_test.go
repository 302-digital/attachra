package link

import (
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/policy"
)

func durationPtr(d time.Duration) *policy.Duration {
	pd := policy.Duration(d)
	return &pd
}

func intPtr(n int) *int {
	return &n
}

// TestResolveParamsRetention covers T-5.3.1/ATR-178's acceptance
// criteria: retention comes from the policy when set, falls back to
// Defaults.Retention when the policy leaves it unset, and is always
// clamped up to at least ttl regardless of which source produced each
// value (a link must never outlive the storage object it points to).
func TestResolveParamsRetention(t *testing.T) {
	tests := []struct {
		name              string
		params            policy.ActionParams
		defaults          Defaults
		wantTTL           time.Duration
		wantRetention     time.Duration
		wantClamped       bool
		wantRequestedZero bool
	}{
		{
			name:          "no retention anywhere falls back to ttl",
			params:        policy.ActionParams{},
			defaults:      Defaults{TTL: 24 * time.Hour},
			wantTTL:       24 * time.Hour,
			wantRetention: 24 * time.Hour,
			// Nothing configured a retention at all: this is the
			// designed default-to-ttl fallback (ATR-178), not a
			// surprising override, so it must not be reported as a
			// clamp (ATR-294) even though the raw comparison
			// (0 < ttl) looks identical to a genuine clamp.
			wantClamped:       false,
			wantRequestedZero: true,
		},
		{
			name:          "global default retention used when policy omits it",
			params:        policy.ActionParams{},
			defaults:      Defaults{TTL: 24 * time.Hour, Retention: 30 * 24 * time.Hour},
			wantTTL:       24 * time.Hour,
			wantRetention: 30 * 24 * time.Hour,
			wantClamped:   false,
		},
		{
			name:          "policy retention overrides global default",
			params:        policy.ActionParams{Retention: durationPtr(90 * 24 * time.Hour)},
			defaults:      Defaults{TTL: 24 * time.Hour, Retention: 30 * 24 * time.Hour},
			wantTTL:       24 * time.Hour,
			wantRetention: 90 * 24 * time.Hour,
			wantClamped:   false,
		},
		{
			name:          "retention shorter than ttl is clamped up to ttl (policy retention)",
			params:        policy.ActionParams{TTL: durationPtr(48 * time.Hour), Retention: durationPtr(1 * time.Hour)},
			defaults:      Defaults{TTL: 24 * time.Hour},
			wantTTL:       48 * time.Hour,
			wantRetention: 48 * time.Hour,
			wantClamped:   true,
		},
		{
			name:          "retention shorter than ttl is clamped up to ttl (default retention, policy ttl)",
			params:        policy.ActionParams{TTL: durationPtr(48 * time.Hour)},
			defaults:      Defaults{TTL: 24 * time.Hour, Retention: 1 * time.Hour},
			wantTTL:       48 * time.Hour,
			wantRetention: 48 * time.Hour,
			wantClamped:   true,
		},
		{
			name:          "max_downloads override does not disturb retention resolution",
			params:        policy.ActionParams{MaxDownloads: intPtr(5)},
			defaults:      Defaults{TTL: 24 * time.Hour, Retention: 30 * 24 * time.Hour},
			wantTTL:       24 * time.Hour,
			wantRetention: 30 * 24 * time.Hour,
			wantClamped:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveParams(tt.params, tt.defaults)
			if got.ttl != tt.wantTTL {
				t.Errorf("resolveParams().ttl = %s, want %s", got.ttl, tt.wantTTL)
			}
			if got.retention != tt.wantRetention {
				t.Errorf("resolveParams().retention = %s, want %s", got.retention, tt.wantRetention)
			}
			if got.retention < got.ttl {
				t.Errorf("resolveParams().retention = %s < ttl %s, invariant violated", got.retention, got.ttl)
			}
			if got.retentionClamped != tt.wantClamped {
				t.Errorf("resolveParams().retentionClamped = %v, want %v", got.retentionClamped, tt.wantClamped)
			}
			if tt.wantRequestedZero && got.requestedRetention != 0 {
				t.Errorf("resolveParams().requestedRetention = %s, want 0", got.requestedRetention)
			}
			if !tt.wantClamped && !tt.wantRequestedZero && got.requestedRetention != got.retention {
				t.Errorf("resolveParams().requestedRetention = %s, want equal to retention %s when not clamped", got.requestedRetention, got.retention)
			}
		})
	}
}
