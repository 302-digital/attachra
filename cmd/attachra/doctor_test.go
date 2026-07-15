package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/config"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// --- helpers ---------------------------------------------------------

// noopDoctorDeps returns a doctorDeps whose every field errors/fails
// deterministically, so a test only needs to override the one or two
// fields it actually exercises.
func noopDoctorDeps() doctorDeps {
	errNoop := errors.New("noop dep: not stubbed for this test")
	return doctorDeps{
		dial: func(_ context.Context, _, _ string) (net.Conn, error) { return nil, errNoop },
		listen: func(network, address string) (net.Listener, error) {
			return net.Listen(network, address) // real, ephemeral loopback listen is fine and deterministic in tests.
		},
		httpGet: func(_ context.Context, _ string) (int, []byte, error) { return 0, nil, errNoop },
		lookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return nil, errNoop
		},
		lookupHost: func(_ context.Context, _ string) ([]string, error) {
			return nil, errNoop
		},
		interfaceAddrs: func() ([]net.Addr, error) { return nil, nil },
		lookPath:       func(_ string) (string, error) { return "", errNoop },
		runCommand:     func(_ string, _ ...string) ([]byte, error) { return nil, errNoop },
	}
}

func findResult(t *testing.T, results []checkResult, check string) checkResult {
	t.Helper()
	for _, r := range results {
		if r.Check == check {
			return r
		}
	}
	t.Fatalf("no result for check %q in %+v", check, results)
	return checkResult{}
}

// --- splitListenAddr -------------------------------------------------

func TestSplitListenAddr(t *testing.T) {
	tests := []struct {
		in          string
		wantNetwork string
		wantAddress string
	}{
		{"inet:127.0.0.1:6785", "tcp", "127.0.0.1:6785"},
		{"unix:/var/run/attachra.sock", "unix", "/var/run/attachra.sock"},
		{"127.0.0.1:6785", "tcp", "127.0.0.1:6785"},
	}
	for _, tt := range tests {
		network, address := splitListenAddr(tt.in)
		if network != tt.wantNetwork || address != tt.wantAddress {
			t.Errorf("splitListenAddr(%q) = (%q, %q), want (%q, %q)", tt.in, network, address, tt.wantNetwork, tt.wantAddress)
		}
	}
}

// --- checkConfig -------------------------------------------------------

func TestCheckConfig_MissingFile_Fail(t *testing.T) {
	_, result := checkConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if result.Status != statusFail {
		t.Errorf("Status = %s, want %s", result.Status, statusFail)
	}
	if result.Hint == "" {
		t.Error("Hint is empty, want a remediation hint")
	}
}

func TestCheckConfig_ValidFile_Pass(t *testing.T) {
	path := writeDoctorTestFile(t, "attachra.yaml", `
log:
  level: info
  format: text
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
`)
	cfg, result := checkConfig(path)
	if result.Status != statusPass {
		t.Fatalf("Status = %s, want %s (detail=%s)", result.Status, statusPass, result.Detail)
	}
	if cfg.Milter.Listen != "inet:127.0.0.1:6785" {
		t.Errorf("cfg.Milter.Listen = %q, want inet:127.0.0.1:6785", cfg.Milter.Listen)
	}
	if strings.Contains(result.Detail, "secret") {
		t.Errorf("Detail unexpectedly mentions a literal secret value: %s", result.Detail)
	}
}

func TestCheckConfig_S3Secrets_Redacted(t *testing.T) {
	path := writeDoctorTestFile(t, "attachra.yaml", `
milter:
  listen: "inet:127.0.0.1:6785"
http:
  listen: "127.0.0.1:8080"
storage:
  driver: s3
  s3:
    bucket: my-bucket
    region: us-east-1
    access_key: "AKIASUPERSECRET"
    secret_key: "supersecretvalue"
`)
	_, result := checkConfig(path)
	if result.Status != statusPass {
		t.Fatalf("Status = %s, want %s (detail=%s)", result.Status, statusPass, result.Detail)
	}
	if strings.Contains(result.Detail, "AKIASUPERSECRET") || strings.Contains(result.Detail, "supersecretvalue") {
		t.Fatalf("Detail leaks a secret value: %s", result.Detail)
	}
	if !strings.Contains(result.Detail, "[REDACTED]") {
		t.Errorf("Detail does not show the redaction placeholder: %s", result.Detail)
	}
}

func writeDoctorTestFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// --- checkPolicy ---------------------------------------------------------

func TestCheckPolicy_NotConfigured_Warn(t *testing.T) {
	cfg := config.Default()
	cfg.Policy.Path = ""
	pol, results := checkPolicy(cfg)
	if pol != nil {
		t.Error("expected nil policy")
	}
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
}

func TestCheckPolicy_MissingFile_Fail(t *testing.T) {
	cfg := config.Default()
	cfg.Policy.Path = filepath.Join(t.TempDir(), "missing-policy.yaml")
	_, results := checkPolicy(cfg)
	if len(results) != 1 || results[0].Status != statusFail {
		t.Fatalf("results = %+v, want single FAIL", results)
	}
}

func TestCheckPolicy_Valid_Pass(t *testing.T) {
	path := writeDoctorTestFile(t, "policy.yaml", `
version: 1
name: "test policy"
rules:
  - name: "replace for example.com"
    when:
      sender:
        domain: ["example.com"]
    then:
      action: replace
      ttl: "7d"
      retention: "30d"
default:
  action: pass
`)
	cfg := config.Default()
	cfg.Policy.Path = path
	pol, results := checkPolicy(cfg)
	if pol == nil {
		t.Fatal("expected a parsed policy")
	}
	if len(results) != 1 || results[0].Status != statusPass {
		t.Fatalf("results = %+v, want single PASS", results)
	}
}

func TestCheckPolicy_DryRun_ExtraWarn(t *testing.T) {
	path := writeDoctorTestFile(t, "policy.yaml", `
version: 1
name: "test policy"
rules: []
default:
  action: pass
`)
	cfg := config.Default()
	cfg.Policy.Path = path
	cfg.Policy.DryRun = true
	_, results := checkPolicy(cfg)
	if len(results) != 2 {
		t.Fatalf("results = %+v, want PASS + WARN(dry_run)", results)
	}
	if results[0].Status != statusPass {
		t.Errorf("results[0].Status = %s, want PASS", results[0].Status)
	}
	if results[1].Status != statusWarn || !strings.Contains(results[1].Detail, "enforcement disabled") {
		t.Errorf("results[1] = %+v, want a WARN mentioning 'enforcement disabled'", results[1])
	}
}

// --- checkDirWritable ------------------------------------------------

// stubNonRootOwner stubs the package-level lookupOwnerUID (normally
// backed by syscall.Stat_t) to report a fixed, non-root owner UID for
// every path, restoring the original on test cleanup.
//
// Without this, any test asserting checkDirWritable's PASS path is at
// the mercy of the uid the test binary itself runs as: CI's
// build-test job runs `go test` as root inside the GitLab runner
// container, so t.TempDir() is root-owned there, and the real
// lookupOwnerUID's uid==0 branch (the DynamicUser root-owned-file
// trap detector, see checkDirWritable) then WARNs exactly where a
// local, non-root dev run PASSes - the CI failure this stub fixes.
func stubNonRootOwner(t *testing.T) {
	t.Helper()
	const nonRootUID = 1000
	orig := lookupOwnerUID
	lookupOwnerUID = func(_ os.FileInfo) (uint32, bool) { return nonRootUID, true }
	t.Cleanup(func() { lookupOwnerUID = orig })
}

func TestCheckDirWritable_ExistsAndWritable_Pass(t *testing.T) {
	stubNonRootOwner(t)
	dir := t.TempDir()
	result := checkDirWritable("storage_dir", dir, true)
	if result.Status != statusPass {
		t.Errorf("Status = %s, want %s (detail=%s)", result.Status, statusPass, result.Detail)
	}
}

func TestCheckDirWritable_MissingAutoCreated_Warn(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-there-yet")
	result := checkDirWritable("storage_dir", dir, true)
	if result.Status != statusWarn {
		t.Errorf("Status = %s, want %s", result.Status, statusWarn)
	}
}

func TestCheckDirWritable_MissingNotAutoCreated_Fail(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-there-yet")
	result := checkDirWritable("database_dir", dir, false)
	if result.Status != statusFail {
		t.Errorf("Status = %s, want %s", result.Status, statusFail)
	}
	if result.Hint == "" {
		t.Error("Hint is empty, want a mkdir remediation hint")
	}
}

func TestCheckDirWritable_NotADirectory_Fail(t *testing.T) {
	path := writeDoctorTestFile(t, "file.txt", "not a directory")
	result := checkDirWritable("storage_dir", path, true)
	if result.Status != statusFail {
		t.Errorf("Status = %s, want %s", result.Status, statusFail)
	}
}

// TestCheckDirWritable_RootOwned_Warn simulates the DynamicUser
// root-owned-file trap (docs/deploy/grommunio-debian.md Troubleshooting)
// by faking lookupOwnerUID rather than requiring actual root privileges
// to chown a file in CI.
func TestCheckDirWritable_RootOwned_Warn(t *testing.T) {
	dir := t.TempDir()

	orig := lookupOwnerUID
	lookupOwnerUID = func(_ os.FileInfo) (uint32, bool) { return 0, true }
	t.Cleanup(func() { lookupOwnerUID = orig })

	result := checkDirWritable("database_dir", dir, false)
	if result.Status != statusWarn {
		t.Errorf("Status = %s, want %s", result.Status, statusWarn)
	}
	if !strings.Contains(result.Detail, "root") {
		t.Errorf("Detail = %q, want it to mention root ownership", result.Detail)
	}
	if !strings.Contains(result.Hint, "chown") {
		t.Errorf("Hint = %q, want a chown remediation", result.Hint)
	}
}

// --- checkStorageDir / checkDatabaseDir -------------------------------

func TestCheckStorageDir_S3Driver_Skip(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.Driver = "s3"
	results := checkStorageDir(cfg)
	if len(results) != 1 || results[0].Status != statusSkip {
		t.Fatalf("results = %+v, want single SKIP", results)
	}
}

func TestCheckDatabaseDir_UsesDirOfPath(t *testing.T) {
	stubNonRootOwner(t)
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(dir, "attachra.db")
	results := checkDatabaseDir(cfg)
	if len(results) != 1 || results[0].Status != statusPass {
		t.Fatalf("results = %+v, want single PASS", results)
	}
}

// TestCheckDatabaseDir_FailsWhileSqliteDoesNotAutoCreate pins today's
// behavior for a missing database directory: FAIL, not WARN, because
// internal/core/store/sqlite does not create its parent directory
// (ATR-310, open as of this writing) the way the fs storage driver
// creates storage.fs.base_dir (ATR-309). checkDatabaseDir's
// autoCreated=false argument is exactly what makes this FAIL instead
// of WARN.
//
// Whoever closes ATR-310 (making the sqlite store create its parent
// directory) MUST flip checkDatabaseDir's autoCreated argument to true
// in cmd/attachra/doctor.go in the same change, and update this test's
// expectation to statusWarn (matching TestCheckStorageDir's/
// TestCheckDirWritable_MissingAutoCreated_Warn's sibling behavior for
// storage.fs.base_dir) - otherwise `attachra doctor` will keep FAILing
// on a condition the service itself no longer treats as fatal. This
// test exists specifically so that discrepancy cannot be missed.
func TestCheckDatabaseDir_FailsWhileSqliteDoesNotAutoCreate(t *testing.T) {
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(t.TempDir(), "no-such-dir", "attachra.db")
	results := checkDatabaseDir(cfg)
	if len(results) != 1 || results[0].Status != statusFail {
		t.Fatalf("results = %+v, want single FAIL (see this test's doc comment if ATR-310 has since been fixed)", results)
	}
}

// --- checkDatabase -------------------------------------------------------

func TestCheckDatabase_MissingFile_Warn(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(dir, "attachra.db")
	results := checkDatabase(cfg)
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
}

func TestCheckDatabase_MissingDir_Skip(t *testing.T) {
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(t.TempDir(), "no-such-dir", "attachra.db")
	results := checkDatabase(cfg)
	if len(results) != 1 || results[0].Status != statusSkip {
		t.Fatalf("results = %+v, want single SKIP", results)
	}
}

func TestCheckDatabase_ValidSQLite_Pass(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "attachra.db")

	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	_ = st.Close()

	cfg := config.Default()
	cfg.Database.Path = dbPath
	results := checkDatabase(cfg)
	if len(results) != 1 || results[0].Status != statusPass {
		t.Fatalf("results = %+v, want single PASS", results)
	}
}

func TestCheckDatabase_CorruptFile_Fail(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "attachra.db")
	if err := os.WriteFile(dbPath, []byte("this is not a sqlite database"), 0o600); err != nil {
		t.Fatalf("write corrupt db: %v", err)
	}

	cfg := config.Default()
	cfg.Database.Path = dbPath
	results := checkDatabase(cfg)
	if len(results) != 1 || results[0].Status != statusFail {
		t.Fatalf("results = %+v, want single FAIL", results)
	}
	if results[0].Hint == "" {
		t.Error("Hint is empty, want a remediation hint")
	}
}

// --- checkHTTPService ------------------------------------------------

func TestCheckHTTPService_Healthy_PassPass(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.Listen = "127.0.0.1:1"
	deps := noopDoctorDeps()
	deps.httpGet = func(_ context.Context, target string) (int, []byte, error) {
		if strings.HasSuffix(target, "/healthz") {
			return 200, []byte("ok"), nil
		}
		return 200, []byte(`{"status":"ok","checks":[]}`), nil
	}

	results := checkHTTPService(context.Background(), cfg, deps)
	http := findResult(t, results, "http_port")
	if http.Status != statusPass {
		t.Errorf("http_port Status = %s, want PASS", http.Status)
	}
	ready := findResult(t, results, "readyz")
	if ready.Status != statusPass {
		t.Errorf("readyz Status = %s, want PASS", ready.Status)
	}
}

func TestCheckHTTPService_HealthyButNotReady_Warn(t *testing.T) {
	cfg := config.Default()
	deps := noopDoctorDeps()
	deps.httpGet = func(_ context.Context, target string) (int, []byte, error) {
		if strings.HasSuffix(target, "/healthz") {
			return 200, []byte("ok"), nil
		}
		return 503, []byte(`{"status":"unavailable","checks":[{"name":"database","ok":false}]}`), nil
	}

	results := checkHTTPService(context.Background(), cfg, deps)
	ready := findResult(t, results, "readyz")
	if ready.Status != statusWarn {
		t.Errorf("readyz Status = %s, want WARN (detail=%s)", ready.Status, ready.Detail)
	}
}

func TestCheckHTTPService_NotRunning_PortFree_Warn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // free again immediately, port is deterministic and (briefly) unused.

	cfg := config.Default()
	cfg.HTTP.Listen = addr
	deps := defaultDoctorDeps() // real net.Listen probe, no server running on addr.

	results := checkHTTPService(context.Background(), cfg, deps)
	http := findResult(t, results, "http_port")
	if http.Status != statusWarn {
		t.Errorf("Status = %s, want WARN (detail=%s)", http.Status, http.Detail)
	}
}

func TestCheckHTTPService_NotRunning_PortOccupied_Fail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	// Accept and immediately drop every connection: this makes the
	// httpGet probe fail fast (connection reset) instead of hanging
	// until doctorNetTimeout waiting for an HTTP response nothing here
	// ever sends.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	addr := ln.Addr().String()

	cfg := config.Default()
	cfg.HTTP.Listen = addr
	deps := defaultDoctorDeps() // httpGet fails (nothing serves HTTP on addr); listen probe hits the real occupied port.

	results := checkHTTPService(context.Background(), cfg, deps)
	http := findResult(t, results, "http_port")
	if http.Status != statusFail {
		t.Errorf("Status = %s, want FAIL (detail=%s)", http.Status, http.Detail)
	}
}

// --- checkMilterPort ---------------------------------------------------

func TestCheckMilterPort_UnixSocketExists_Pass(t *testing.T) {
	// A short-named temp dir, not t.TempDir(): the latter nests under
	// the test name, easily exceeding unix's ~104-byte sun_path limit
	// once combined with "attachra.sock".
	dir, err := os.MkdirTemp("", "atr-doctor-sock")
	if err != nil {
		t.Fatalf("os.MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sockPath := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix): %v", err)
	}
	defer func() { _ = ln.Close() }()

	cfg := config.Default()
	cfg.Milter.Listen = "unix:" + sockPath
	results := checkMilterPort(context.Background(), cfg, noopDoctorDeps())
	if len(results) != 1 || results[0].Status != statusPass {
		t.Fatalf("results = %+v, want single PASS", results)
	}
}

func TestCheckMilterPort_UnixSocketMissing_Warn(t *testing.T) {
	cfg := config.Default()
	cfg.Milter.Listen = "unix:" + filepath.Join(t.TempDir(), "missing.sock")
	results := checkMilterPort(context.Background(), cfg, noopDoctorDeps())
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
}

func TestCheckMilterPort_TCPDialSucceeds_Pass(t *testing.T) {
	cfg := config.Default()
	cfg.Milter.Listen = "inet:127.0.0.1:6785"
	deps := noopDoctorDeps()
	deps.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:6785" {
			t.Errorf("dial(%s, %s), want tcp 127.0.0.1:6785", network, address)
		}
		return &net.TCPConn{}, nil
	}
	results := checkMilterPort(context.Background(), cfg, deps)
	if len(results) != 1 || results[0].Status != statusPass {
		t.Fatalf("results = %+v, want single PASS", results)
	}
}

func TestCheckMilterPort_TCPDialFails_PortFree_Warn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := config.Default()
	cfg.Milter.Listen = "inet:" + addr
	deps := defaultDoctorDeps()
	results := checkMilterPort(context.Background(), cfg, deps)
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
}

// --- checkPublicURL ------------------------------------------------------

func TestCheckPublicURL_SkipExternal_Skip(t *testing.T) {
	cfg := config.Default()
	cfg.PublicBaseURL = "https://mail.example.com"
	results := checkPublicURL(context.Background(), cfg, noopDoctorDeps(), true)
	if len(results) != 1 || results[0].Status != statusSkip {
		t.Fatalf("results = %+v, want single SKIP", results)
	}
}

func TestCheckPublicURL_NotConfigured_Skip(t *testing.T) {
	cfg := config.Default()
	cfg.PublicBaseURL = ""
	results := checkPublicURL(context.Background(), cfg, noopDoctorDeps(), false)
	if len(results) != 1 || results[0].Status != statusSkip {
		t.Fatalf("results = %+v, want single SKIP", results)
	}
}

func TestCheckPublicURL_Healthy_PassPass(t *testing.T) {
	cfg := config.Default()
	cfg.PublicBaseURL = "https://mail.example.com"
	deps := noopDoctorDeps()
	deps.lookupHost = func(_ context.Context, host string) ([]string, error) {
		if host != "mail.example.com" {
			t.Errorf("lookupHost(%s), want mail.example.com", host)
		}
		return []string{"203.0.113.10"}, nil
	}
	deps.httpGet = func(_ context.Context, target string) (int, []byte, error) {
		if target != "https://mail.example.com/healthz" {
			t.Errorf("httpGet(%s), want https://mail.example.com/healthz", target)
		}
		return 200, nil, nil
	}

	results := checkPublicURL(context.Background(), cfg, deps, false)
	if len(results) != 2 {
		t.Fatalf("results = %+v, want DNS PASS + healthz PASS", results)
	}
	for _, r := range results {
		if r.Status != statusPass {
			t.Errorf("result %+v, want PASS", r)
		}
	}
}

func TestCheckPublicURL_DNSFails_Warn(t *testing.T) {
	cfg := config.Default()
	cfg.PublicBaseURL = "https://mail.example.com"
	deps := noopDoctorDeps()
	// deps.httpGet also errors (noopDoctorDeps default), so both entries should be WARN.

	results := checkPublicURL(context.Background(), cfg, deps, false)
	if len(results) != 2 {
		t.Fatalf("results = %+v, want 2 entries", results)
	}
	for _, r := range results {
		if r.Status != statusWarn {
			t.Errorf("result %+v, want WARN", r)
		}
	}
}

// --- SPF helpers -----------------------------------------------------

func TestCollectSenderDomains(t *testing.T) {
	path := writeDoctorTestFile(t, "policy.yaml", `
version: 1
name: "test"
rules:
  - name: "a"
    when:
      sender:
        domain: ["Example.com", "other.org"]
    then:
      action: replace
      ttl: "7d"
      retention: "30d"
  - name: "b"
    when:
      sender:
        domain: ["example.com"]
    then:
      action: block
      reason: "dup"
default:
  action: pass
`)
	cfg := config.Default()
	cfg.Policy.Path = path
	pol, results := checkPolicy(cfg)
	if results[0].Status != statusPass {
		t.Fatalf("policy failed to parse: %+v", results)
	}

	domains := collectSenderDomains(pol)
	want := []string{"example.com", "other.org"}
	if len(domains) != len(want) {
		t.Fatalf("domains = %v, want %v", domains, want)
	}
	for i := range want {
		if domains[i] != want[i] {
			t.Errorf("domains[%d] = %q, want %q", i, domains[i], want[i])
		}
	}
}

func TestFindSPFRecord(t *testing.T) {
	txts := []string{"some-other-txt-record", "v=spf1 ip4:203.0.113.0/24 -all"}
	got := findSPFRecord(txts)
	if got != "v=spf1 ip4:203.0.113.0/24 -all" {
		t.Errorf("findSPFRecord() = %q", got)
	}
	if findSPFRecord([]string{"no spf here"}) != "" {
		t.Error("expected no match")
	}
}

func TestParseSPFMechanisms(t *testing.T) {
	prefixes, includes, other := parseSPFMechanisms("v=spf1 ip4:203.0.113.10 ip4:198.51.100.0/24 ip6:2001:db8::1 include:_spf.example.net -all")
	if len(prefixes) != 3 {
		t.Fatalf("prefixes = %v, want 3", prefixes)
	}
	if len(includes) != 1 || includes[0] != "_spf.example.net" {
		t.Fatalf("includes = %v, want [_spf.example.net]", includes)
	}
	if len(other) != 0 {
		t.Fatalf("other = %v, want none", other)
	}
}

// TestParseSPFMechanisms_OtherUnverifiableMechanisms covers NIT-1 from
// the atr-architect review: a/mx/exists:/redirect= mechanisms must be
// recognized as "not automatically verifiable" (checkSPF's WARN), not
// silently ignored (which previously fell through to a misleading
// "add ip4:<ip>" WARN even though the record might already authorize
// the server via one of these).
func TestParseSPFMechanisms_OtherUnverifiableMechanisms(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   []string
	}{
		{"bare a", "v=spf1 a -all", []string{"a"}},
		{"a with domain", "v=spf1 a:mail.example.com -all", []string{"a"}},
		{"a with cidr", "v=spf1 a/24 -all", []string{"a"}},
		{"bare mx", "v=spf1 mx -all", []string{"mx"}},
		{"mx with domain and cidr", "v=spf1 mx:example.com/24 -all", []string{"mx"}},
		{"exists", "v=spf1 exists:%{i}.example.com -all", []string{"exists"}},
		{"redirect modifier", "v=spf1 redirect=_spf.example.com", []string{"redirect"}},
		{"qualifier prefixed a and mx", "v=spf1 ~a ?mx -all", []string{"a", "mx"}},
		{"all is not mistaken for a", "v=spf1 ip4:203.0.113.10 -all", nil},
		{"combined", "v=spf1 a mx include:_spf.example.net exists:%{i}.example.com redirect=_spf.example.com -all", []string{"a", "mx", "exists", "redirect"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, other := parseSPFMechanisms(tt.record)
			if len(other) != len(tt.want) {
				t.Fatalf("other = %v, want %v", other, tt.want)
			}
			for i := range tt.want {
				if other[i] != tt.want[i] {
					t.Errorf("other[%d] = %q, want %q (other=%v)", i, other[i], tt.want[i], other)
				}
			}
		})
	}
}

func TestIPsMatchAny(t *testing.T) {
	prefixes, _, _ := parseSPFMechanisms("v=spf1 ip4:203.0.113.0/24")
	if !ipsMatchAny([]string{"203.0.113.10"}, prefixes) {
		t.Error("expected match")
	}
	if ipsMatchAny([]string{"198.51.100.10"}, prefixes) {
		t.Error("expected no match")
	}
}

// --- checkSPF ------------------------------------------------------------

func policyWithSenderDomain(t *testing.T, domain string) *config.Config {
	t.Helper()
	path := writeDoctorTestFile(t, "policy.yaml", `
version: 1
name: "test"
rules:
  - name: "a"
    when:
      sender:
        domain: ["`+domain+`"]
    then:
      action: replace
      ttl: "7d"
      retention: "30d"
default:
  action: pass
`)
	cfg := config.Default()
	cfg.Policy.Path = path
	return &cfg
}

func TestCheckSPF_SkipExternal_Skip(t *testing.T) {
	cfg := policyWithSenderDomain(t, "example.com")
	pol, _ := checkPolicy(*cfg)
	results := checkSPF(context.Background(), pol, noopDoctorDeps(), true)
	if len(results) != 1 || results[0].Status != statusSkip {
		t.Fatalf("results = %+v, want single SKIP", results)
	}
}

func TestCheckSPF_NoDomains_Skip(t *testing.T) {
	results := checkSPF(context.Background(), nil, noopDoctorDeps(), false)
	if len(results) != 1 || results[0].Status != statusSkip {
		t.Fatalf("results = %+v, want single SKIP", results)
	}
}

func TestCheckSPF_MatchingIP_Pass(t *testing.T) {
	cfg := policyWithSenderDomain(t, "example.com")
	pol, _ := checkPolicy(*cfg)

	deps := noopDoctorDeps()
	deps.lookupTXT = func(_ context.Context, domain string) ([]string, error) {
		if domain != "example.com" {
			t.Errorf("lookupTXT(%s)", domain)
		}
		return []string{"v=spf1 ip4:203.0.113.10/32 -all"}, nil
	}
	deps.interfaceAddrs = func() ([]net.Addr, error) {
		_, ipNet, _ := net.ParseCIDR("203.0.113.10/32")
		return []net.Addr{ipNet}, nil
	}

	results := checkSPF(context.Background(), pol, deps, false)
	if len(results) != 1 || results[0].Status != statusPass {
		t.Fatalf("results = %+v, want single PASS", results)
	}
}

func TestCheckSPF_NoRecord_Warn(t *testing.T) {
	cfg := policyWithSenderDomain(t, "example.com")
	pol, _ := checkPolicy(*cfg)

	deps := noopDoctorDeps()
	deps.lookupTXT = func(_ context.Context, _ string) ([]string, error) { return []string{"unrelated"}, nil }
	deps.interfaceAddrs = func() ([]net.Addr, error) { return nil, nil }

	results := checkSPF(context.Background(), pol, deps, false)
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
}

func TestCheckSPF_NoPublicIP_Warn(t *testing.T) {
	cfg := policyWithSenderDomain(t, "example.com")
	pol, _ := checkPolicy(*cfg)

	deps := noopDoctorDeps()
	deps.lookupTXT = func(_ context.Context, _ string) ([]string, error) {
		return []string{"v=spf1 ip4:203.0.113.10/32 -all"}, nil
	}
	deps.interfaceAddrs = func() ([]net.Addr, error) {
		_, ipNet, _ := net.ParseCIDR("10.0.0.5/32") // private only.
		return []net.Addr{ipNet}, nil
	}

	results := checkSPF(context.Background(), pol, deps, false)
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
	if !strings.Contains(results[0].Detail, "public IP") {
		t.Errorf("Detail = %q, want it to mention the public IP being undeterminable", results[0].Detail)
	}
}

// TestCheckSPF_UnverifiableMechanism_WarnsNotAutomaticallyVerifiable
// covers NIT-1 from the atr-architect review: a record whose only
// non-ip4/ip6 mechanism is a/mx/exists:/redirect= must not get the
// misleading "add ip4:<ip>" WARN (worded as if the record definitely
// lacks the server's IP) - it may well authorize it, this check just
// cannot confirm that without recursive DNS resolution.
func TestCheckSPF_UnverifiableMechanism_WarnsNotAutomaticallyVerifiable(t *testing.T) {
	cfg := policyWithSenderDomain(t, "example.com")
	pol, _ := checkPolicy(*cfg)

	deps := noopDoctorDeps()
	deps.lookupTXT = func(_ context.Context, _ string) ([]string, error) {
		return []string{"v=spf1 a mx -all"}, nil
	}
	deps.interfaceAddrs = func() ([]net.Addr, error) {
		_, ipNet, _ := net.ParseCIDR("203.0.113.10/32")
		return []net.Addr{ipNet}, nil
	}

	results := checkSPF(context.Background(), pol, deps, false)
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
	if strings.Contains(results[0].Detail, "add ip4:") {
		t.Errorf("Detail = %q, should not suggest adding ip4: - the record may already authorize the IP via a/mx", results[0].Detail)
	}
	if !strings.Contains(results[0].Detail, "not automatically verifiable") {
		t.Errorf("Detail = %q, want it to say the record is not automatically verifiable", results[0].Detail)
	}
	if !strings.Contains(results[0].Detail, "a") || !strings.Contains(results[0].Detail, "mx") {
		t.Errorf("Detail = %q, want it to name the a/mx mechanisms found", results[0].Detail)
	}
}

// --- checkPostfix --------------------------------------------------------

func TestCheckPostfix_NoPostconf_Skip(t *testing.T) {
	results := checkPostfix(config.Default(), noopDoctorDeps())
	if len(results) != 1 || results[0].Status != statusSkip {
		t.Fatalf("results = %+v, want single SKIP", results)
	}
}

func TestCheckPostfix_MilterPresent_Pass(t *testing.T) {
	cfg := config.Default()
	cfg.Milter.Listen = "inet:127.0.0.1:6785"
	deps := noopDoctorDeps()
	deps.lookPath = func(_ string) (string, error) { return "/usr/sbin/postconf", nil }
	deps.runCommand = func(_ string, _ ...string) ([]byte, error) {
		return []byte("smtpd_milters = inet:127.0.0.1:6785\nnon_smtpd_milters = \n"), nil
	}

	results := checkPostfix(cfg, deps)
	if len(results) != 1 || results[0].Status != statusPass {
		t.Fatalf("results = %+v, want single PASS", results)
	}
}

func TestCheckPostfix_MilterAbsent_Warn(t *testing.T) {
	cfg := config.Default()
	cfg.Milter.Listen = "inet:127.0.0.1:6785"
	deps := noopDoctorDeps()
	deps.lookPath = func(_ string) (string, error) { return "/usr/sbin/postconf", nil }
	deps.runCommand = func(_ string, _ ...string) ([]byte, error) {
		return []byte("smtpd_milters = \nnon_smtpd_milters = \n"), nil
	}

	results := checkPostfix(cfg, deps)
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
}

func TestCheckPostfix_CommandFails_Warn(t *testing.T) {
	deps := noopDoctorDeps()
	deps.lookPath = func(_ string) (string, error) { return "/usr/sbin/postconf", nil }
	deps.runCommand = func(_ string, _ ...string) ([]byte, error) { return nil, errors.New("boom") }

	results := checkPostfix(config.Default(), deps)
	if len(results) != 1 || results[0].Status != statusWarn {
		t.Fatalf("results = %+v, want single WARN", results)
	}
}

// --- runDoctorChecks / integration --------------------------------------

// doctorTestInstall lays out a minimal, self-consistent config+policy
// pair (no running server, no real network) under a fresh t.TempDir(),
// mirroring the packaged deployment's directory layout closely enough
// for the doctor checks under test.
func doctorTestInstall(t *testing.T) (configPath string, cfg config.Config) {
	t.Helper()
	root := t.TempDir()

	policyPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
version: 1
name: "test policy"
rules: []
default:
  action: pass
`), 0o600); err != nil {
		t.Fatalf("write policy.yaml: %v", err)
	}

	baseDir := filepath.Join(root, "files")
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		t.Fatalf("mkdir base_dir: %v", err)
	}

	dbPath := filepath.Join(root, "attachra.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	_ = st.Close()

	configPath = filepath.Join(root, "attachra.yaml")
	yaml := `
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
    base_dir: "` + baseDir + `"
database:
  path: "` + dbPath + `"
policy:
  path: "` + policyPath + `"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write attachra.yaml: %v", err)
	}

	cfg, err = config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return configPath, cfg
}

func TestRunDoctorChecks_ConfigFails_EverythingSkipped(t *testing.T) {
	results := runDoctorChecks(filepath.Join(t.TempDir(), "missing.yaml"), true, noopDoctorDeps())

	cfgResult := findResult(t, results, "config")
	if cfgResult.Status != statusFail {
		t.Fatalf("config Status = %s, want FAIL", cfgResult.Status)
	}

	for _, check := range []string{"policy", "storage_dir", "database_dir", "database", "http_port", "milter_port", "public_url", "spf", "postfix"} {
		r := findResult(t, results, check)
		if r.Status != statusSkip {
			t.Errorf("%s Status = %s, want SKIP", check, r.Status)
		}
	}
}

func TestRunDoctorChecks_HealthyInstall_NoFail(t *testing.T) {
	configPath, _ := doctorTestInstall(t)

	results := runDoctorChecks(configPath, true, noopDoctorDeps())

	for _, r := range results {
		if r.Status == statusFail {
			t.Errorf("unexpected FAIL: %+v", r)
		}
	}

	// database file exists and is valid -> PASS, not just "will be created".
	db := findResult(t, results, "database")
	if db.Status != statusPass {
		t.Errorf("database Status = %s, want PASS (detail=%s)", db.Status, db.Detail)
	}
}

func TestRunDoctorChecks_PanicInCheck_IsolatedToOneResult(t *testing.T) {
	// runChecked is exercised indirectly by every check above; this test
	// verifies the isolation contract directly.
	results := runChecked("some_check", func() []checkResult {
		panic("boom")
	})
	if len(results) != 1 {
		t.Fatalf("results = %+v, want exactly one", results)
	}
	if results[0].Status != statusFail {
		t.Errorf("Status = %s, want FAIL", results[0].Status)
	}
	if !strings.Contains(results[0].Detail, "boom") {
		t.Errorf("Detail = %q, want it to mention the panic value", results[0].Detail)
	}
}

// --- output formatting -----------------------------------------------

func TestWriteDoctorJSON_SchemaStable(t *testing.T) {
	results := []checkResult{
		{Check: "config", Status: statusPass, Detail: "ok"},
		{Check: "policy", Status: statusWarn, Detail: "dry run", Hint: "turn it off eventually"},
	}
	var buf bytes.Buffer
	writeDoctorJSON(&buf, results)

	var raw []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(raw) != 2 {
		t.Fatalf("len(raw) = %d, want 2", len(raw))
	}
	for _, obj := range raw {
		for _, key := range []string{"check", "status", "detail", "hint"} {
			if _, ok := obj[key]; !ok {
				t.Errorf("object %+v missing key %q (schema must be stable)", obj, key)
			}
		}
	}
	if raw[0]["hint"] != "" {
		t.Errorf(`raw[0]["hint"] = %v, want "" (present but empty)`, raw[0]["hint"])
	}
}

func TestWriteDoctorTable_ContainsHeaderAndRows(t *testing.T) {
	results := []checkResult{
		{Check: "config", Status: statusPass, Detail: "loaded ok"},
		{Check: "database", Status: statusFail, Detail: "cannot open", Hint: "chown it"},
	}
	var buf bytes.Buffer
	writeDoctorTable(&buf, results)

	out := buf.String()
	if !strings.Contains(out, "STATUS") || !strings.Contains(out, "CHECK") || !strings.Contains(out, "DETAIL") {
		t.Errorf("missing table header: %s", out)
	}
	if !strings.Contains(out, "PASS") || !strings.Contains(out, "FAIL") {
		t.Errorf("missing status values: %s", out)
	}
	if !strings.Contains(out, "hint: chown it") {
		t.Errorf("missing hint line: %s", out)
	}
	if !strings.Contains(out, "1 pass, 0 warn, 1 fail, 0 skip") {
		t.Errorf("missing/incorrect summary line: %s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("summary should reflect a FAIL verdict: %s", out)
	}
}

// --- runDoctorCommand (full CLI entrypoint) -------------------------------

func TestRunDoctorCommand_HealthyInstall_ExitZero(t *testing.T) {
	configPath, _ := doctorTestInstall(t)
	var stdout, stderr bytes.Buffer

	code := runDoctorCommand([]string{"--config", configPath, "--skip-external"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDoctorCommand() = %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "STATUS") {
		t.Errorf("stdout missing table header: %s", stdout.String())
	}
}

func TestRunDoctorCommand_MissingConfig_ExitOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runDoctorCommand([]string{"--config", filepath.Join(t.TempDir(), "missing.yaml"), "--skip-external"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runDoctorCommand() = %d, want 1", code)
	}
}

func TestRunDoctorCommand_JSONFlag_ProducesValidJSON(t *testing.T) {
	configPath, _ := doctorTestInstall(t)
	var stdout, stderr bytes.Buffer

	code := runDoctorCommand([]string{"--config", configPath, "--skip-external", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDoctorCommand() = %d, want 0; stderr=%s", code, stderr.String())
	}

	var results []checkResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("json.Unmarshal: %v; stdout=%s", err, stdout.String())
	}
	if len(results) == 0 {
		t.Fatal("no results in JSON output")
	}
}

func TestRunDoctorCommand_ExtraArgs_Usage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runDoctorCommand([]string{"extra-arg"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runDoctorCommand() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "usage") {
		t.Errorf("stderr = %q, want a usage message", stderr.String())
	}
}

// TestDoctorNetTimeout_Sane guards against a regression where the
// shared timeout constant is accidentally set to something that would
// make every doctor run slow (or, worse, 0 -> instant context
// cancellation on every probe).
func TestDoctorNetTimeout_Sane(t *testing.T) {
	if doctorNetTimeout <= 0 || doctorNetTimeout > 30*time.Second {
		t.Errorf("doctorNetTimeout = %v, want a small positive bound", doctorNetTimeout)
	}
}
