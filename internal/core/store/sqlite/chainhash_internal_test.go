package sqlite

import (
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
)

// TestChainHashDeterministic asserts chainHash is a pure function of
// its inputs: calling it twice with identical arguments produces the
// identical hash.
func TestChainHashDeterministic(t *testing.T) {
	ts := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	a := chainHash("prev", "id-1", 1, ts, audit.TypeDownload, "actor", "msg-1", "user@example.com", `{"k":"v"}`)
	b := chainHash("prev", "id-1", 1, ts, audit.TypeDownload, "actor", "msg-1", "user@example.com", `{"k":"v"}`)
	if a != b {
		t.Errorf("chainHash() is not deterministic: %q != %q", a, b)
	}
}

// TestChainHashSensitiveToEveryField asserts that changing any single
// input field (including prevHash, which is how a tampered/removed
// earlier row would be detected) changes the resulting hash — the
// property the tamper-evidence hook (SR-128-1) depends on.
func TestChainHashSensitiveToEveryField(t *testing.T) {
	ts := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	base := chainHash("prev", "id-1", 1, ts, audit.TypeDownload, "actor", "msg-1", "user@example.com", `{"k":"v"}`)

	variants := map[string]string{
		"prevHash":  chainHash("different-prev", "id-1", 1, ts, audit.TypeDownload, "actor", "msg-1", "user@example.com", `{"k":"v"}`),
		"id":        chainHash("prev", "id-2", 1, ts, audit.TypeDownload, "actor", "msg-1", "user@example.com", `{"k":"v"}`),
		"seq":       chainHash("prev", "id-1", 2, ts, audit.TypeDownload, "actor", "msg-1", "user@example.com", `{"k":"v"}`),
		"timestamp": chainHash("prev", "id-1", 1, ts.Add(time.Second), audit.TypeDownload, "actor", "msg-1", "user@example.com", `{"k":"v"}`),
		"type":      chainHash("prev", "id-1", 1, ts, audit.TypeRevoke, "actor", "msg-1", "user@example.com", `{"k":"v"}`),
		"actor":     chainHash("prev", "id-1", 1, ts, audit.TypeDownload, "other-actor", "msg-1", "user@example.com", `{"k":"v"}`),
		"messageID": chainHash("prev", "id-1", 1, ts, audit.TypeDownload, "actor", "msg-2", "user@example.com", `{"k":"v"}`),
		"recipient": chainHash("prev", "id-1", 1, ts, audit.TypeDownload, "actor", "msg-1", "other@example.com", `{"k":"v"}`),
		"details":   chainHash("prev", "id-1", 1, ts, audit.TypeDownload, "actor", "msg-1", "user@example.com", `{"k":"other"}`),
	}

	for field, variant := range variants {
		if variant == base {
			t.Errorf("changing %s did not change chainHash() output, want a different hash", field)
		}
	}
}
