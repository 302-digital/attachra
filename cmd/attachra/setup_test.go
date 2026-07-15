package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- validators ---

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"simple", "example.com", false},
		{"subdomain", "mail.example.com", false},
		{"hyphenated label", "my-mail.example.com", false},
		{"empty", "", true},
		{"single label, no dot", "example", true},
		{"leading hyphen", "-example.com", true},
		{"trailing hyphen", "example-.com", true},
		{"space", "exa mple.com", true},
		{"empty label", "example..com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestParseDomains(t *testing.T) {
	got, err := parseDomains(" Example.com , example.org ,,")
	if err != nil {
		t.Fatalf("parseDomains() error = %v, want nil", err)
	}
	want := []string{"example.com", "example.org"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("parseDomains() = %v, want %v", got, want)
	}

	if _, err := parseDomains(""); err == nil {
		t.Error("parseDomains(\"\") error = nil, want error (at least one domain required)")
	}

	if _, err := parseDomains("not a domain"); err == nil {
		t.Error("parseDomains(\"not a domain\") error = nil, want error")
	}
}

func TestValidateBaseURLFormat(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https", "https://mail.example.com", false},
		{"http", "http://127.0.0.1:8080", false},
		{"missing scheme", "mail.example.com", true},
		{"wrong scheme", "ftp://mail.example.com", true},
		{"no host", "https://", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBaseURLFormat(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBaseURLFormat(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// --- listen probing ---

func TestProbeHTTPListen_DetectsOccupiedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer func() { _ = ln.Close() }()

	addr := ln.Addr().String()
	if err := probeHTTPListen(addr); err == nil {
		t.Errorf("probeHTTPListen(%q) error = nil, want error (port is occupied)", addr)
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close() error = %v", err)
	}
	if err := probeHTTPListen(addr); err != nil {
		t.Errorf("probeHTTPListen(%q) error = %v, want nil (port was released)", addr, err)
	}
}

func TestProbeMilterListen(t *testing.T) {
	if err := probeMilterListen("inet:127.0.0.1:0"); err != nil {
		t.Errorf("probeMilterListen(inet:127.0.0.1:0) error = %v, want nil", err)
	}
	if err := probeMilterListen("bogus:whatever"); err == nil {
		t.Error("probeMilterListen(bogus:whatever) error = nil, want error (unrecognized syntax)")
	}
	if runtime.GOOS != "windows" {
		sock := filepath.Join(t.TempDir(), "attachra.sock")
		if err := probeMilterListen("unix:" + sock); err != nil {
			t.Errorf("probeMilterListen(unix:%s) error = %v, want nil", sock, err)
		}
	}
}

// --- non-interactive ---

func TestRunSetupCommand_NonInteractive_FSHappyPath(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	args := []string{
		"--config-dir", dir,
		"--non-interactive",
		"--domains", "example.com,example.org",
		"--public-base-url", "https://mail.example.com",
		"--http-listen", "127.0.0.1:0",
		"--milter-listen", "inet:127.0.0.1:0",
	}
	code := runSetupCommand(args, strings.NewReader(""), &stdout, &stderr)
	if code != setupOK {
		t.Fatalf("runSetupCommand() = %d, want %d; stderr = %q", code, setupOK, stderr.String())
	}

	attachraYAML := readFileString(t, filepath.Join(dir, "attachra.yaml"))
	if !strings.Contains(attachraYAML, `public_base_url: "https://mail.example.com"`) {
		t.Errorf("attachra.yaml missing public_base_url; got:\n%s", attachraYAML)
	}
	if !strings.Contains(attachraYAML, "driver: fs") {
		t.Errorf("attachra.yaml missing storage.driver: fs; got:\n%s", attachraYAML)
	}
	if !strings.Contains(attachraYAML, "dry_run: true") {
		t.Errorf("attachra.yaml missing dry_run: true (the recommended default); got:\n%s", attachraYAML)
	}

	policyYAML := readFileString(t, filepath.Join(dir, "policy.yaml"))
	if !strings.Contains(policyYAML, `"example.com"`) || !strings.Contains(policyYAML, `"example.org"`) {
		t.Errorf("policy.yaml missing configured domains; got:\n%s", policyYAML)
	}
	if !strings.Contains(policyYAML, "action: replace") {
		t.Errorf("policy.yaml missing action: replace rule; got:\n%s", policyYAML)
	}
	if !strings.Contains(policyYAML, "action: pass") {
		t.Errorf("policy.yaml missing default action: pass fallback (SR-119-1); got:\n%s", policyYAML)
	}

	if _, err := os.Stat(filepath.Join(dir, "attachra.env")); !os.IsNotExist(err) {
		t.Errorf("attachra.env should not be written for the fs driver; stat err = %v", err)
	}
}

func TestRunSetupCommand_NonInteractive_S3WithEnvFile(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	args := []string{
		"--config-dir", dir,
		"--non-interactive",
		"--domains", "example.com",
		"--public-base-url", "https://mail.example.com",
		"--storage", "s3",
		"--s3-endpoint", "http://localhost:9000",
		"--s3-region", "us-east-1",
		"--s3-bucket", "attachra",
		"--s3-access-key", "AKIAEXAMPLE",
		"--s3-secret-key", "supersecretvalue",
		"--s3-path-style",
		"--http-listen", "127.0.0.1:0",
		"--milter-listen", "inet:127.0.0.1:0",
	}
	code := runSetupCommand(args, strings.NewReader(""), &stdout, &stderr)
	if code != setupOK {
		t.Fatalf("runSetupCommand() = %d, want %d; stderr = %q", code, setupOK, stderr.String())
	}

	attachraYAML := readFileString(t, filepath.Join(dir, "attachra.yaml"))
	if strings.Contains(attachraYAML, "supersecretvalue") || strings.Contains(attachraYAML, "AKIAEXAMPLE") {
		t.Errorf("attachra.yaml must not contain the raw S3 secret/access key; got:\n%s", attachraYAML)
	}
	if !strings.Contains(attachraYAML, `access_key: "${ATTACHRA_S3_ACCESS_KEY}"`) {
		t.Errorf("attachra.yaml missing ${ATTACHRA_S3_ACCESS_KEY} placeholder; got:\n%s", attachraYAML)
	}
	if !strings.Contains(attachraYAML, "path_style: true") {
		t.Errorf("attachra.yaml missing path_style: true; got:\n%s", attachraYAML)
	}

	envPath := filepath.Join(dir, "attachra.env")
	fi, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat attachra.env: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("attachra.env mode = %v, want 0600", fi.Mode().Perm())
	}
	env := readFileString(t, envPath)
	if !strings.Contains(env, "ATTACHRA_S3_ACCESS_KEY=AKIAEXAMPLE") {
		t.Errorf("attachra.env missing access key line; got:\n%s", env)
	}
	if !strings.Contains(env, "ATTACHRA_S3_SECRET_KEY=supersecretvalue") {
		t.Errorf("attachra.env missing secret key line; got:\n%s", env)
	}
}

// TestRunSetupCommand_ForceOverwrite_EnvFilePermissionIsNotInherited is
// the regression test for ATR-320 review NIT-2: overwriting a
// pre-existing attachra.env (e.g. left over 0644 by an older,
// pre-fix version of this command, or hand-created loosely) must
// produce a freshly-created 0600 file, not silently keep the old
// file's looser mode via an in-place O_TRUNC write.
func TestRunSetupCommand_ForceOverwrite_EnvFilePermissionIsNotInherited(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions do not apply on windows")
	}
	dir := t.TempDir()
	envPath := filepath.Join(dir, "attachra.env")
	if err := os.WriteFile(envPath, []byte("ATTACHRA_S3_ACCESS_KEY=stale\n"), 0o644); err != nil { //nolint:gosec // deliberately seeding a loose-permission file to test that the overwrite fixes it to 0600
		t.Fatalf("seed attachra.env: %v", err)
	}

	args := []string{
		"--config-dir", dir, "--non-interactive", "--force",
		"--domains", "example.com",
		"--public-base-url", "https://mail.example.com",
		"--storage", "s3",
		"--s3-endpoint", "http://localhost:9000",
		"--s3-region", "us-east-1",
		"--s3-bucket", "attachra",
		"--s3-access-key", "AKIAEXAMPLE",
		"--s3-secret-key", "supersecretvalue",
		"--http-listen", "127.0.0.1:0",
		"--milter-listen", "inet:127.0.0.1:0",
	}
	var stdout, stderr bytes.Buffer
	if code := runSetupCommand(args, strings.NewReader(""), &stdout, &stderr); code != setupOK {
		t.Fatalf("runSetupCommand() = %d, want %d; stderr = %q", code, setupOK, stderr.String())
	}

	fi, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat attachra.env: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("attachra.env mode = %v, want 0600 (must not inherit the pre-existing file's 0644)", fi.Mode().Perm())
	}
}

func TestRunSetupCommand_NonInteractive_MissingRequiredFlags(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := runSetupCommand([]string{"--config-dir", dir, "--non-interactive"}, strings.NewReader(""), &stdout, &stderr)
	if code != setupError {
		t.Fatalf("runSetupCommand() = %d, want %d", code, setupError)
	}
	if !strings.Contains(stderr.String(), "--domains") || !strings.Contains(stderr.String(), "--public-base-url") {
		t.Errorf("stderr should list both missing required flags; got %q", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "attachra.yaml")); !os.IsNotExist(err) {
		t.Errorf("attachra.yaml should not have been written; stat err = %v", err)
	}
}

func TestRunSetupCommand_NonInteractive_InvalidStorageDriver(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	args := []string{
		"--config-dir", dir, "--non-interactive",
		"--domains", "example.com",
		"--public-base-url", "https://mail.example.com",
		"--storage", "azure",
	}
	code := runSetupCommand(args, strings.NewReader(""), &stdout, &stderr)
	if code != setupError {
		t.Fatalf("runSetupCommand() = %d, want %d; stderr = %q", code, setupError, stderr.String())
	}
}

func TestRunSetupCommand_RefusesWithoutForce_ThenForceOverwrites(t *testing.T) {
	dir := t.TempDir()

	baseArgs := func(domain string) []string {
		return []string{
			"--config-dir", dir, "--non-interactive",
			"--domains", domain,
			"--public-base-url", "https://mail.example.com",
			"--http-listen", "127.0.0.1:0",
			"--milter-listen", "inet:127.0.0.1:0",
		}
	}

	var stdout1, stderr1 bytes.Buffer
	if code := runSetupCommand(baseArgs("example.com"), strings.NewReader(""), &stdout1, &stderr1); code != setupOK {
		t.Fatalf("first runSetupCommand() = %d, want %d; stderr = %q", code, setupOK, stderr1.String())
	}
	original := readFileString(t, filepath.Join(dir, "policy.yaml"))

	var stdout2, stderr2 bytes.Buffer
	code := runSetupCommand(baseArgs("example.net"), strings.NewReader(""), &stdout2, &stderr2)
	if code != setupError {
		t.Fatalf("second runSetupCommand() (no --force) = %d, want %d", code, setupError)
	}
	if !strings.Contains(stderr2.String(), "--force") {
		t.Errorf("stderr should mention --force; got %q", stderr2.String())
	}
	if got := readFileString(t, filepath.Join(dir, "policy.yaml")); got != original {
		t.Error("policy.yaml was modified despite missing --force")
	}

	forceArgs := append(baseArgs("example.net"), "--force")
	var stdout3, stderr3 bytes.Buffer
	if code := runSetupCommand(forceArgs, strings.NewReader(""), &stdout3, &stderr3); code != setupOK {
		t.Fatalf("third runSetupCommand() (--force) = %d, want %d; stderr = %q", code, setupOK, stderr3.String())
	}
	updated := readFileString(t, filepath.Join(dir, "policy.yaml"))
	if !strings.Contains(updated, `"example.net"`) {
		t.Errorf("policy.yaml should reflect the --force overwrite; got:\n%s", updated)
	}

	// A successful --force run must not leave its backup sidecars
	// behind (writeManagedFile's commit path removes them).
	for _, name := range []string{"attachra.yaml" + setupBackupSuffix, "policy.yaml" + setupBackupSuffix} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist after a successful run; stat err = %v", name, err)
		}
	}
}

// TestApplySetupAnswers_ForceOverwrite_ValidationFailure_RestoresOriginal
// is the regression test for the ATR-320 architect-review MUST-FIX: a
// --force re-run whose answers fail the end-of-run
// config.Load/policy.Parse verification must restore the operator's
// previously valid attachra.yaml/policy.yaml byte-for-byte, not delete
// them. applySetupAnswers is exercised directly (rather than through
// runSetupCommand's CLI flag parsing) because every flag-reachable
// answer combination that collectNonInteractiveAnswers accepts also
// passes config.Validate today — the failure this test injects
// (FailureMode: "not-a-real-mode") is deliberately only reachable by
// constructing setupAnswers directly, exactly like
// TestApplySetupAnswers_ValidationFailureCleansUp does for the
// newly-created-file case.
func TestApplySetupAnswers_ForceOverwrite_ValidationFailure_RestoresOriginal(t *testing.T) {
	dir := t.TempDir()

	validAnswers := setupAnswers{
		Domains:       []string{"example.com"},
		PublicBaseURL: "https://mail.example.com",
		StorageDriver: "fs",
		FSBaseDir:     "/var/lib/attachra/files",
		HTTPListen:    "127.0.0.1:0",
		MilterListen:  "inet:127.0.0.1:0",
		FailureMode:   "open",
		DryRun:        true,
	}
	var stdout1, stderr1 bytes.Buffer
	if code := applySetupAnswers(dir, validAnswers, mailEnvUnknown, &stdout1, &stderr1); code != setupOK {
		t.Fatalf("initial applySetupAnswers() = %d, want %d; stderr = %q", code, setupOK, stderr1.String())
	}

	attachraPath := filepath.Join(dir, "attachra.yaml")
	policyPath := filepath.Join(dir, "policy.yaml")
	originalAttachra := readFileString(t, attachraPath)
	originalPolicy := readFileString(t, policyPath)

	invalidAnswers := validAnswers
	invalidAnswers.Domains = []string{"example.net"} // Different, so a byte-for-byte match below proves a real restore, not a coincidence.
	invalidAnswers.FailureMode = "not-a-real-mode"   // Rejected by config.Validate(), not by any of applySetupAnswers' own pre-checks.

	var stdout2, stderr2 bytes.Buffer
	code := applySetupAnswers(dir, invalidAnswers, mailEnvUnknown, &stdout2, &stderr2)
	if code != setupError {
		t.Fatalf("applySetupAnswers() over an existing valid config = %d, want %d", code, setupError)
	}
	if !strings.Contains(stderr2.String(), "failed validation") {
		t.Errorf("stderr should explain the validation failure; got %q", stderr2.String())
	}

	if got := readFileString(t, attachraPath); got != originalAttachra {
		t.Errorf("attachra.yaml was not restored byte-for-byte after the failed --force overwrite\n--- got ---\n%s\n--- want ---\n%s", got, originalAttachra)
	}
	if got := readFileString(t, policyPath); got != originalPolicy {
		t.Errorf("policy.yaml was not restored byte-for-byte after the failed --force overwrite\n--- got ---\n%s\n--- want ---\n%s", got, originalPolicy)
	}

	for _, name := range []string{"attachra.yaml" + setupBackupSuffix, "policy.yaml" + setupBackupSuffix} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should not remain after a restore; stat err = %v", name, err)
		}
	}
}

func TestValidateEnvSecretValue(t *testing.T) {
	if err := validateEnvSecretValue("a-normal-secret"); err != nil {
		t.Errorf("validateEnvSecretValue(normal) error = %v, want nil", err)
	}
	if err := validateEnvSecretValue(""); err != nil {
		t.Errorf("validateEnvSecretValue(\"\") error = %v, want nil", err)
	}
	if err := validateEnvSecretValue("line1\nline2"); err == nil {
		t.Error("validateEnvSecretValue with \\n error = nil, want error")
	}
	if err := validateEnvSecretValue("line1\rline2"); err == nil {
		t.Error("validateEnvSecretValue with \\r error = nil, want error")
	}
}

func TestRunSetupCommand_NonInteractive_RejectsSecretWithNewline(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	args := []string{
		"--config-dir", dir, "--non-interactive",
		"--domains", "example.com",
		"--public-base-url", "https://mail.example.com",
		"--storage", "s3",
		"--s3-endpoint", "http://localhost:9000",
		"--s3-region", "us-east-1",
		"--s3-bucket", "attachra",
		"--s3-secret-key", "bad\nvalue",
	}
	code := runSetupCommand(args, strings.NewReader(""), &stdout, &stderr)
	if code != setupError {
		t.Fatalf("runSetupCommand() = %d, want %d; stderr = %q", code, setupError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--s3-secret-key") {
		t.Errorf("stderr should name --s3-secret-key; got %q", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "attachra.env")); !os.IsNotExist(err) {
		t.Errorf("attachra.env should not have been written; stat err = %v", err)
	}
}

func TestCheckNoExistingConfig_IncludesEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "attachra.env")
	if err := os.WriteFile(envPath, []byte("ATTACHRA_S3_ACCESS_KEY=someone-elses-key\n"), 0o600); err != nil {
		t.Fatalf("write attachra.env: %v", err)
	}

	if err := checkNoExistingConfig(dir); err == nil {
		t.Fatal("checkNoExistingConfig() error = nil, want error naming the existing attachra.env")
	} else if !strings.Contains(err.Error(), "attachra.env") {
		t.Errorf("checkNoExistingConfig() error = %q, want it to mention attachra.env", err.Error())
	}
}

// --- interactive ---

func TestRunSetupCommand_Interactive_FSHappyPath(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	// Answers in prompt order: domains, public base URL, storage
	// (blank -> default "fs"), fs base dir (blank -> default), HTTP
	// listen, milter listen, failure mode (blank -> default "open"),
	// dry-run (blank -> default true).
	input := strings.Join([]string{
		"example.com",
		"https://mail.example.com",
		"",
		"",
		"127.0.0.1:0",
		"inet:127.0.0.1:0",
		"",
		"",
	}, "\n") + "\n"

	code := runSetupCommand([]string{"--config-dir", dir}, strings.NewReader(input), &stdout, &stderr)
	if code != setupOK {
		t.Fatalf("runSetupCommand() = %d, want %d; stderr = %q, stdout = %q", code, setupOK, stderr.String(), stdout.String())
	}

	attachraYAML := readFileString(t, filepath.Join(dir, "attachra.yaml"))
	if !strings.Contains(attachraYAML, `public_base_url: "https://mail.example.com"`) {
		t.Errorf("attachra.yaml missing public_base_url; got:\n%s", attachraYAML)
	}
	if !strings.Contains(attachraYAML, "driver: fs") {
		t.Errorf("attachra.yaml should default to the fs driver; got:\n%s", attachraYAML)
	}
	if !strings.Contains(attachraYAML, "failure_mode: open") {
		t.Errorf("attachra.yaml should default failure_mode to open; got:\n%s", attachraYAML)
	}
	if !strings.Contains(attachraYAML, "dry_run: true") {
		t.Errorf("attachra.yaml should default dry_run to true; got:\n%s", attachraYAML)
	}
	if !strings.Contains(stdout.String(), "Setup complete") {
		t.Errorf("stdout should confirm completion and print next steps; got:\n%s", stdout.String())
	}
}

func TestRunSetupCommand_Interactive_RejectsInvalidDomainThenAccepts(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	input := strings.Join([]string{
		"not a domain", // rejected, re-prompted
		"example.com",  // accepted
		"not-a-url",    // rejected, re-prompted
		"https://mail.example.com",
		"",
		"",
		"127.0.0.1:0",
		"inet:127.0.0.1:0",
		"",
		"",
	}, "\n") + "\n"

	code := runSetupCommand([]string{"--config-dir", dir}, strings.NewReader(input), &stdout, &stderr)
	if code != setupOK {
		t.Fatalf("runSetupCommand() = %d, want %d; stderr = %q, stdout = %q", code, setupOK, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "invalid:") {
		t.Errorf("stdout should have shown at least one 'invalid:' re-prompt; got:\n%s", stdout.String())
	}
}

func TestRunSetupCommand_Interactive_NonTTYStdin_Errors(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("os.Open(os.DevNull) error = %v", err)
	}
	defer func() { _ = f.Close() }()

	var stdout, stderr bytes.Buffer
	code := runSetupCommand([]string{"--config-dir", dir}, f, &stdout, &stderr)
	if code != setupError {
		t.Fatalf("runSetupCommand() = %d, want %d", code, setupError)
	}
	if !strings.Contains(stderr.String(), "--non-interactive") {
		t.Errorf("stderr should point at --non-interactive; got %q", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "attachra.yaml")); !os.IsNotExist(err) {
		t.Errorf("attachra.yaml should not have been written; stat err = %v", err)
	}
}

// --- cleanup on validation failure ---

func TestApplySetupAnswers_ValidationFailureCleansUp(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	answers := setupAnswers{
		Domains:       []string{"example.com"},
		PublicBaseURL: "https://mail.example.com",
		StorageDriver: "fs",
		FSBaseDir:     "/var/lib/attachra/files",
		HTTPListen:    "127.0.0.1:0",
		MilterListen:  "inet:127.0.0.1:0",
		FailureMode:   "not-a-real-mode", // Invalid: config.Validate() must reject this.
		DryRun:        true,
	}

	code := applySetupAnswers(dir, answers, mailEnvUnknown, &stdout, &stderr)
	if code != setupError {
		t.Fatalf("applySetupAnswers() = %d, want %d", code, setupError)
	}
	if !strings.Contains(stderr.String(), "failed validation") {
		t.Errorf("stderr should explain the validation failure; got %q", stderr.String())
	}

	for _, name := range []string{"attachra.yaml", "policy.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should have been removed after validation failure; stat err = %v", name, err)
		}
	}
}

// --- ATR-337: detected mail environment wired into the wizard's defaults ---

// TestCollectNonInteractiveAnswers_HTTPListenDefault_FollowsDetectedEnv
// exercises collectNonInteractiveAnswers directly (bypassing
// runSetupCommand's own real detectMailEnv call) with an explicit env,
// confirming the http-listen default it falls back to (when the
// operator did not pass --http-listen) tracks httpListenDefaultFor:
// 18080 for grommunio, and the same unchanged default for an
// undetected ("empty system") environment — no regression.
func TestCollectNonInteractiveAnswers_HTTPListenDefault_FollowsDetectedEnv(t *testing.T) {
	tests := []struct {
		name string
		env  mailEnv
	}{
		{"grommunio detected", mailEnvGrommunio},
		{"empty system (unknown): unchanged default", mailEnvUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := setupFlags{
				domains:       "example.com",
				publicBaseURL: "https://mail.example.com",
				// http-listen deliberately left blank: this is exactly
				// the default collectNonInteractiveAnswers must resolve
				// via httpListenDefaultFor(env).
			}
			var stderr bytes.Buffer
			answers, err := collectNonInteractiveAnswers(raw, tt.env, &stderr)
			if err != nil {
				t.Fatalf("collectNonInteractiveAnswers() error = %v", err)
			}
			if answers.HTTPListen != httpListenDefaultFor(tt.env) {
				t.Errorf("collectNonInteractiveAnswers(env=%v).HTTPListen = %q, want %q", tt.env, answers.HTTPListen, httpListenDefaultFor(tt.env))
			}
		})
	}
}

// TestRunSetupWizard_HTTPListenPromptDefault_FollowsDetectedEnv is the
// interactive-mode counterpart: a bare Enter at the HTTP listen prompt
// must accept httpListenDefaultFor(env), same as the non-interactive
// path above.
func TestRunSetupWizard_HTTPListenPromptDefault_FollowsDetectedEnv(t *testing.T) {
	tests := []struct {
		name string
		env  mailEnv
	}{
		{"grommunio detected", mailEnvGrommunio},
		{"empty system (unknown): unchanged default", mailEnvUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Join([]string{
				"example.com",
				"https://mail.example.com",
				"", // storage -> default fs
				"", // fs base dir -> default
				"", // HTTP listen -> bare Enter, must accept the env-specific default
				"inet:127.0.0.1:0",
				"", // failure mode -> default open
				"", // dry-run -> default true
			}, "\n") + "\n"

			var stdout bytes.Buffer
			answers, err := runSetupWizard(newPrompter(strings.NewReader(input), &stdout), setupFlags{}, tt.env)
			if err != nil {
				t.Fatalf("runSetupWizard() error = %v; stdout = %q", err, stdout.String())
			}
			want := httpListenDefaultFor(tt.env)
			if answers.HTTPListen != want {
				t.Errorf("runSetupWizard(env=%v).HTTPListen = %q, want %q", tt.env, answers.HTTPListen, want)
			}
		})
	}
}

// TestPrintSetupNextSteps_MilterChain_PrefersDetectedExisting fakes
// existingMilters (the same package-level function-value swap pattern
// doctor.go's lookupOwnerUID uses) to confirm the printed postconf
// example keeps a previously configured milter (e.g. rspamd) first and
// appends Attachra's own listen address, instead of the bare
// "<existing>" placeholder.
func TestPrintSetupNextSteps_MilterChain_PrefersDetectedExisting(t *testing.T) {
	original := existingMilters
	existingMilters = func() (string, string, bool) {
		return "inet:127.0.0.1:11332", "", true
	}
	defer func() { existingMilters = original }()

	a := setupAnswers{MilterListen: "inet:127.0.0.1:6785"}
	var stdout bytes.Buffer
	printSetupNextSteps(&stdout, "/etc/attachra", "/etc/attachra/attachra.yaml", "/etc/attachra/policy.yaml", a, mailEnvUnknown)

	out := stdout.String()
	if !strings.Contains(out, "smtpd_milters = inet:127.0.0.1:11332, inet:127.0.0.1:6785") {
		t.Errorf("stdout should keep the detected existing milter first; got:\n%s", out)
	}
	if !strings.Contains(out, "non_smtpd_milters = inet:127.0.0.1:6785") {
		t.Errorf("stdout non_smtpd_milters line should be just Attachra's own listener (no existing detected); got:\n%s", out)
	}
	if strings.Contains(out, "<existing>") {
		t.Errorf("stdout should not fall back to the <existing> placeholder once a real value was detected; got:\n%s", out)
	}
}

// TestPrintSetupNextSteps_MilterChain_FallsBackToPlaceholder confirms
// the pre-existing "<existing>" placeholder behavior is unchanged when
// existingMilters cannot determine anything (postconf missing/failed) —
// the common case on a dev machine or CI runner with no Postfix
// installed at all.
func TestPrintSetupNextSteps_MilterChain_FallsBackToPlaceholder(t *testing.T) {
	original := existingMilters
	existingMilters = func() (string, string, bool) { return "", "", false }
	defer func() { existingMilters = original }()

	a := setupAnswers{MilterListen: "inet:127.0.0.1:6785"}
	var stdout bytes.Buffer
	printSetupNextSteps(&stdout, "/etc/attachra", "/etc/attachra/attachra.yaml", "/etc/attachra/policy.yaml", a, mailEnvUnknown)

	out := stdout.String()
	if !strings.Contains(out, "smtpd_milters = <existing>, inet:127.0.0.1:6785") {
		t.Errorf("stdout should fall back to the <existing> placeholder; got:\n%s", out)
	}
}

// TestPrintSetupNextSteps_EnvSpecificGuidance confirms each detected
// environment's next-steps output names the right doc/warning (ATR-337
// acceptance: grommunio references its own deploy guide; mailcow warns
// that this .deb targets a host Postfix, not its containerized stack).
func TestPrintSetupNextSteps_EnvSpecificGuidance(t *testing.T) {
	original := existingMilters
	existingMilters = func() (string, string, bool) { return "", "", false }
	defer func() { existingMilters = original }()

	a := setupAnswers{MilterListen: "inet:127.0.0.1:6785"}

	tests := []struct {
		name           string
		env            mailEnv
		wantSubstrings []string
	}{
		{
			name: "grommunio",
			env:  mailEnvGrommunio,
			wantSubstrings: []string{
				"docs/deploy/grommunio-debian.md",
				"nginx-grommunio.conf",
			},
		},
		{
			name: "mailcow",
			env:  mailEnvMailcow,
			wantSubstrings: []string{
				"docs/integrations/postfix.md",
				"mailcow-dockerized runs its own",
			},
		},
		{
			name:           "iredmail",
			env:            mailEnvIRedMail,
			wantSubstrings: []string{"docs/integrations/postfix.md"},
		},
		{
			name:           "unknown (empty system)",
			env:            mailEnvUnknown,
			wantSubstrings: []string{"docs/integrations/postfix.md"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			printSetupNextSteps(&stdout, "/etc/attachra", "/etc/attachra/attachra.yaml", "/etc/attachra/policy.yaml", a, tt.env)
			out := stdout.String()
			for _, want := range tt.wantSubstrings {
				if !strings.Contains(out, want) {
					t.Errorf("env=%v: stdout missing %q; got:\n%s", tt.env, want, out)
				}
			}
		})
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test fixture path under t.TempDir()
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return string(data)
}
