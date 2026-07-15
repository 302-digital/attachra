package policy

import (
	"fmt"
	"sync/atomic"
)

// Store holds the currently active Policy and allows it to be
// hot-reloaded from disk without disrupting concurrent readers
// (US-4.2/T-4.2.1). The zero value is not usable; use NewStore.
//
// Concurrency: Store's exported methods are safe for concurrent use
// by multiple goroutines. Current wraps an atomic.Pointer[Policy], so
// a reader calling Current always observes either the previously
// loaded Policy or a newer one — never a partially-constructed value
// — regardless of how many Reload calls race with it.
type Store struct {
	path    string
	current atomic.Pointer[Policy]
}

// NewStore loads the policy file at path (via Load: parse + validate)
// and returns a *Store holding it. An error is returned if the file
// cannot be read or fails validation; in that case the returned Store
// is nil, matching the invariant that an invalid policy is never held
// live (SR-119-1).
//
// path must be non-empty; callers that want to run without a policy
// loaded (community-edition passthrough behavior) should not
// construct a Store at all — see cmd/attachra's use of
// config.Policy.Path.
func NewStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("policy: store path must not be empty")
	}

	p, err := Load(path)
	if err != nil {
		return nil, fmt.Errorf("policy: initial load of %q: %w", path, err)
	}

	s := &Store{path: path}
	s.current.Store(p)
	return s, nil
}

// Current returns the currently active Policy. It never returns nil
// once the Store has been constructed via NewStore. The returned
// pointer must be treated as read-only: callers must not mutate the
// Policy or any of its nested slices/maps, since it may be shared
// concurrently with other readers and with a subsequent Reload.
func (s *Store) Current() *Policy {
	return s.current.Load()
}

// Path returns the policy file path this Store reloads from.
func (s *Store) Path() string {
	return s.path
}

// Reload re-reads and re-validates the policy file at s.Path(),
// atomically swapping it in as the active policy on success. On
// failure (read error or validation error), Reload leaves the
// previously active policy in place — Current continues to return
// the last-known-good Policy — and returns a descriptive error the
// caller should log; the policy engine keeps running on the old
// policy rather than failing closed or falling back to an unvalidated
// document (§3.5, SR-119-1: "an invalid policy must never be
// applied").
//
// On success, Reload returns the newly active Policy and any
// non-fatal warnings produced while validating it (§3.5), so the
// caller can log a summary (name, rule count, warnings).
//
// Reload is safe to call concurrently with itself and with Current;
// concurrent Reload calls each parse and validate their own snapshot
// of the file independently, and the swap is atomic, so a reader can
// never observe a half-applied policy. If two Reloads race, the last
// one to complete its atomic.Pointer.Store wins — there is no
// ordering guarantee beyond that, which matches SIGHUP's
// at-least-once, unordered delivery semantics.
func (s *Store) Reload() (*Policy, []string, error) {
	p, warnings, err := loadWithWarnings(s.path)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: reload %q: %w (keeping previous policy)", s.path, err)
	}

	s.current.Store(p)
	return p, warnings, nil
}

// loadWithWarnings is like Load but also returns the warnings Parse
// produced, which Load discards (Load's doc comment directs callers
// who need warnings to call Parse directly).
func loadWithWarnings(path string) (*Policy, []string, error) {
	data, err := readPolicyFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Parse(data, path)
}
