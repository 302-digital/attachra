package policy

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// writeStorePolicy writes content to a fresh file under t.TempDir()
// and returns its path, for tests that need a real file for
// NewStore/Reload to read from.
func writeStorePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

const validPolicyV1 = `
version: 1
name: "Policy v1"
rules: []
default:
  action: pass
`

const validPolicyV2 = `
version: 1
name: "Policy v2"
rules:
  - name: "block executables"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "no executables"
default:
  action: pass
`

const invalidPolicyMissingDefault = `
version: 1
name: "Invalid policy"
rules:
  - name: "Pass everything"
    then:
      action: pass
`

const warningPolicy = `
version: 1
name: "Policy with warning"
rules:
  - name: "catch-all"
    then:
      action: pass
  - name: "unreachable"
    when:
      attachment:
        extension: ["exe"]
    then:
      action: block
      reason: "never reached"
default:
  action: pass
`

func TestNewStore_LoadsInitialPolicy(t *testing.T) {
	path := writeStorePolicy(t, validPolicyV1)

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v, want nil", err)
	}

	got := s.Current()
	if got == nil {
		t.Fatal("Current() = nil, want loaded policy")
	}
	if got.Name != "Policy v1" {
		t.Errorf("Current().Name = %q, want %q", got.Name, "Policy v1")
	}
	if s.Path() != path {
		t.Errorf("Path() = %q, want %q", s.Path(), path)
	}
}

func TestNewStore_EmptyPathRejected(t *testing.T) {
	if _, err := NewStore(""); err == nil {
		t.Fatal("NewStore(\"\") error = nil, want error")
	}
}

func TestNewStore_InvalidInitialPolicyFails(t *testing.T) {
	path := writeStorePolicy(t, invalidPolicyMissingDefault)

	if _, err := NewStore(path); err == nil {
		t.Fatal("NewStore() error = nil, want validation error")
	}
}

func TestNewStore_MissingFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	if _, err := NewStore(path); err == nil {
		t.Fatal("NewStore() error = nil, want read error")
	}
}

func TestStore_ReloadSuccess_SwapsPolicy(t *testing.T) {
	path := writeStorePolicy(t, validPolicyV1)
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	if err := os.WriteFile(path, []byte(validPolicyV2), 0o600); err != nil {
		t.Fatalf("rewrite policy file: %v", err)
	}

	reloaded, warnings, err := s.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Errorf("Reload() warnings = %v, want none", warnings)
	}
	if reloaded.Name != "Policy v2" {
		t.Errorf("Reload() returned policy name = %q, want %q", reloaded.Name, "Policy v2")
	}
	if len(reloaded.Rules) != 1 {
		t.Errorf("Reload() returned policy rule count = %d, want 1", len(reloaded.Rules))
	}

	current := s.Current()
	if current.Name != "Policy v2" {
		t.Errorf("Current().Name after Reload = %q, want %q", current.Name, "Policy v2")
	}
}

func TestStore_ReloadSuccess_ReturnsWarnings(t *testing.T) {
	path := writeStorePolicy(t, validPolicyV1)
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	if err := os.WriteFile(path, []byte(warningPolicy), 0o600); err != nil {
		t.Fatalf("rewrite policy file: %v", err)
	}

	_, warnings, err := s.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("Reload() warnings = %v, want exactly 1", warnings)
	}
}

// TestStore_ReloadFailure_KeepsPreviousPolicy is the core safety
// guarantee of T-4.2.1 (SR-119-1 extended to hot reload): a reload
// that fails validation must never replace the currently active,
// known-good policy.
func TestStore_ReloadFailure_KeepsPreviousPolicy(t *testing.T) {
	path := writeStorePolicy(t, validPolicyV1)
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	if err := os.WriteFile(path, []byte(invalidPolicyMissingDefault), 0o600); err != nil {
		t.Fatalf("rewrite policy file: %v", err)
	}

	_, _, err = s.Reload()
	if err == nil {
		t.Fatal("Reload() error = nil, want validation error")
	}

	current := s.Current()
	if current.Name != "Policy v1" {
		t.Errorf("Current().Name after failed Reload = %q, want unchanged %q", current.Name, "Policy v1")
	}
	if len(current.Rules) != 0 {
		t.Errorf("Current().Rules after failed Reload = %d, want unchanged 0", len(current.Rules))
	}
}

func TestStore_ReloadFailure_MissingFileKeepsPreviousPolicy(t *testing.T) {
	path := writeStorePolicy(t, validPolicyV1)
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove policy file: %v", err)
	}

	if _, _, err := s.Reload(); err == nil {
		t.Fatal("Reload() error = nil, want read error")
	}

	if got := s.Current().Name; got != "Policy v1" {
		t.Errorf("Current().Name after failed Reload = %q, want unchanged %q", got, "Policy v1")
	}
}

// TestStore_ConcurrentReloadAndRead exercises the atomic swap under
// -race: many goroutines continuously call Current() while another
// goroutine repeatedly alternates the file between a valid and an
// invalid document and calls Reload(). Readers must always observe a
// complete, previously-valid Policy — never a nil, zero-value, or
// partially-applied one.
func TestStore_ConcurrentReloadAndRead(t *testing.T) {
	path := writeStorePolicy(t, validPolicyV1)
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	const iterations = 200
	var wg sync.WaitGroup

	// Readers: assert Current() is always a fully-formed, valid-named
	// policy (never nil, never a zero value).
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				p := s.Current()
				if p == nil {
					t.Error("Current() = nil during concurrent reload")
					return
				}
				if p.Name != "Policy v1" && p.Name != "Policy v2" {
					t.Errorf("Current().Name = %q, want one of the known valid policy names", p.Name)
					return
				}
			}
		}()
	}

	// Writer: alternates the file content and reloads. Some Reload
	// calls will legitimately fail (when the file momentarily holds
	// the invalid document); that is expected and not a test failure
	// by itself — what matters is that Current() never breaks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < iterations; j++ {
			content := validPolicyV2
			if j%2 == 1 {
				content = invalidPolicyMissingDefault
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Errorf("rewrite policy file: %v", err)
				return
			}
			_, _, _ = s.Reload() //nolint:errcheck // failures are expected for the invalid half of the alternation
		}
	}()

	wg.Wait()

	// After the loop, restore a valid document so the final Current()
	// check below is deterministic (the loop may have ended on the
	// invalid alternation, which is fine — Current() must still be
	// whatever the last successful Reload produced).
	final := s.Current()
	if final == nil {
		t.Fatal("Current() = nil after concurrent test, want a valid policy")
	}
	if final.Name != "Policy v1" && final.Name != "Policy v2" {
		t.Errorf("final Current().Name = %q, want a known valid policy name", final.Name)
	}
}
