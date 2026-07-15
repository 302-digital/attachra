package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/302-digital/attachra/internal/config"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/mattn/go-isatty"
)

// Exit codes for `attachra setup` (ATR-320).
const (
	setupOK    = 0
	setupError = 1
)

const setupUsage = "attachra: usage: attachra setup [--config-dir DIR] [--force] [--non-interactive] [flags...] (see attachra setup --help)"

// setupAnswers holds every value the wizard collects, whether from
// interactive prompts or from --non-interactive flags, before they are
// rendered into attachra.yaml/policy.yaml.
type setupAnswers struct {
	Domains       []string
	PublicBaseURL string
	StorageDriver string // "fs" or "s3".
	FSBaseDir     string
	S3Endpoint    string
	S3Region      string
	S3Bucket      string
	S3AccessKey   string
	S3SecretKey   string
	S3PathStyle   bool
	HTTPListen    string
	MilterListen  string
	FailureMode   string // "open" or "closed".
	DryRun        bool
}

// setupFlags holds the raw --non-interactive answer flags. It doubles
// as the source of interactive-mode prompt defaults ("preset" a value
// via flag, still confirm/override it at the prompt) for every
// string-valued field; the two boolean fields (S3PathStyle, DryRun) are
// only consulted in --non-interactive mode, since a boolean flag's
// zero value is indistinguishable from "operator did not set this" and
// prompting fresh in interactive mode sidesteps that ambiguity
// entirely.
type setupFlags struct {
	domains       string
	publicBaseURL string
	storage       string
	fsBaseDir     string
	s3Endpoint    string
	s3Region      string
	s3Bucket      string
	s3AccessKey   string
	s3SecretKey   string
	s3PathStyle   bool
	httpListen    string
	milterListen  string
	failureMode   string
	dryRun        bool
}

// runSetupCommand implements `attachra setup` (ATR-320): a first-run
// wizard that generates a working attachra.yaml/policy.yaml pair
// (defaulting to dry-run) so a new operator does not have to
// hand-author YAML from the packaged templates in deploy/deb/etc/ to
// get started. It is dispatched from run() in main.go before
// config.Load, the same short-circuit precedent `policy validate`
// established: setup's entire purpose is to CREATE a config, so it
// cannot itself require one to already exist.
//
// stdin is accepted as an explicit io.Reader (rather than reading
// os.Stdin directly) so the interactive prompt flow is unit-testable
// with a scripted answer script; see isTerminal's doc comment for how
// the real-TTY gate interacts with that.
func runSetupCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attachra setup", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configDirFlag := fs.String("config-dir", "/etc/attachra", "directory to write attachra.yaml/policy.yaml (and attachra.env, if S3 credentials are given) into")
	force := fs.Bool("force", false, "overwrite an existing attachra.yaml/policy.yaml in --config-dir")
	nonInteractive := fs.Bool("non-interactive", false, "skip prompts entirely; every answer must be supplied via the flags below")

	var raw setupFlags
	fs.StringVar(&raw.domains, "domains", "", "comma-separated sender domain(s) to process (required with --non-interactive)")
	fs.StringVar(&raw.publicBaseURL, "public-base-url", "", "public base URL embedded in download links, e.g. https://mail.example.com (required with --non-interactive)")
	fs.StringVar(&raw.storage, "storage", "", "storage driver: fs or s3 (default: fs)")
	fs.StringVar(&raw.fsBaseDir, "fs-base-dir", "", "fs driver: base directory for stored attachments (default: /var/lib/attachra/files)")
	fs.StringVar(&raw.s3Endpoint, "s3-endpoint", "", "s3 driver: S3-compatible endpoint URL (required for --storage=s3)")
	fs.StringVar(&raw.s3Region, "s3-region", "", "s3 driver: region (required for --storage=s3)")
	fs.StringVar(&raw.s3Bucket, "s3-bucket", "", "s3 driver: bucket name (required for --storage=s3)")
	fs.StringVar(&raw.s3AccessKey, "s3-access-key", "", "s3 driver: access key (written to <config-dir>/attachra.env, never to attachra.yaml; leave blank to use the AWS SDK's default credential chain)")
	fs.StringVar(&raw.s3SecretKey, "s3-secret-key", "", "s3 driver: secret key (written to <config-dir>/attachra.env, never to attachra.yaml)")
	fs.BoolVar(&raw.s3PathStyle, "s3-path-style", false, "s3 driver: use path-style bucket addressing (required by MinIO and most non-AWS S3 services)")
	fs.StringVar(&raw.httpListen, "http-listen", "", "download server listen address (default: 127.0.0.1:18080)")
	fs.StringVar(&raw.milterListen, "milter-listen", "", "milter listen address, Postfix syntax (default: inet:127.0.0.1:6785)")
	fs.StringVar(&raw.failureMode, "failure-mode", "", "milter failure resolution: open or closed (default: open)")
	fs.BoolVar(&raw.dryRun, "dry-run", true, "start the policy in dry-run mode: log would-be decisions without replacing attachments (recommended)")

	if err := fs.Parse(args); err != nil {
		return setupError
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, setupUsage) //nolint:errcheck // best-effort diagnostic on stderr
		return setupError
	}

	configDir, err := filepath.Abs(*configDirFlag)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: setup: --config-dir %q: %v\n", *configDirFlag, err) //nolint:errcheck // best-effort diagnostic on stderr
		return setupError
	}

	// Fail fast, before prompting for anything, if the target files
	// already exist and --force was not given (ATR-320: "existing
	// attachra.yaml/policy.yaml without --force are not overwritten").
	if err := checkNoExistingConfig(configDir); !*force && err != nil {
		fmt.Fprintf(stderr, "attachra: setup: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return setupError
	}

	// Best-effort, advisory-only guess at the local mail stack (ATR-337):
	// never fails the wizard, only adjusts a couple of defaults/hints
	// below. See maildetect.go.
	detected := detectMailEnv(defaultMailEnvDeps())

	var answers setupAnswers
	if *nonInteractive {
		answers, err = collectNonInteractiveAnswers(raw, detected.Env, stderr)
	} else {
		// Only a real, non-redirected terminal drives the interactive
		// prompt flow. The type assertion to *os.File is deliberate:
		// os.Stdin (passed by main.go's run()) is always *os.File, so a
		// real invocation with redirected/piped/non-TTY stdin correctly
		// hits the isTerminal check and is told to use
		// --non-interactive. A test-injected io.Reader (bytes.Reader,
		// strings.Reader, ...) is never an *os.File, so it skips this
		// gate entirely and is read from directly — this is what makes
		// the wizard's prompt flow unit-testable with a scripted answer
		// script, without needing a real pty.
		if f, ok := stdin.(*os.File); ok && !isTerminal(f) {
			fmt.Fprintln(stderr, "attachra: setup: stdin is not a terminal; re-run with --non-interactive and the appropriate flags (see attachra setup --help)") //nolint:errcheck // best-effort diagnostic on stderr
			return setupError
		}
		answers, err = runSetupWizard(newPrompter(stdin, stdout), raw, detected.Env)
	}
	if err != nil {
		fmt.Fprintf(stderr, "attachra: setup: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return setupError
	}

	return applySetupAnswers(configDir, answers, detected.Env, stdout, stderr)
}

// setupManagedFiles lists every file applySetupAnswers may write,
// relative to configDir. attachra.env is included even though it is
// only actually written for the s3 driver with credentials: an
// operator's existing attachra.env (e.g. from a previous s3 setup)
// must not be silently clobbered by a --force re-run that happens to
// choose the fs driver or leave credentials blank, so its presence is
// checked and backed up unconditionally, same as the two YAML files.
var setupManagedFiles = []string{"attachra.yaml", "policy.yaml", "attachra.env"}

// checkNoExistingConfig reports an error naming every one of
// setupManagedFiles that already exists under configDir. It is always
// safe to call (no side effects); the caller decides whether to act on
// the error based on --force.
func checkNoExistingConfig(configDir string) error {
	var existing []string
	for _, name := range setupManagedFiles {
		path := filepath.Join(configDir, name)
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	if len(existing) > 0 {
		return fmt.Errorf("refusing to overwrite existing file(s): %s (re-run with --force to overwrite)", strings.Join(existing, ", "))
	}
	return nil
}

// isTerminal reports whether f is a real interactive terminal, as
// opposed to a regular file, pipe, socket, or /dev/null (which is a
// character device too, but not a terminal — os.ModeCharDevice alone
// is not a sufficient test, so this uses an actual isatty(3) ioctl
// probe). github.com/mattn/go-isatty was already an indirect
// dependency (pulled in transitively) before this change, so using it
// directly here adds no new third-party code to the build (CLAUDE.md
// invariant #6 / minimal dependencies).
func isTerminal(f *os.File) bool {
	return isatty.IsTerminal(f.Fd())
}

// collectNonInteractiveAnswers validates raw and turns it into a
// setupAnswers, applying the same defaults the interactive wizard
// offers for any field whose flag was left empty. It never prompts.
// env is the detected local mail environment (ATR-337), consulted only
// for the HTTP listen default (httpListenDefaultFor).
func collectNonInteractiveAnswers(raw setupFlags, env mailEnv, stderr io.Writer) (setupAnswers, error) {
	var missing []string
	if raw.domains == "" {
		missing = append(missing, "--domains")
	}
	if raw.publicBaseURL == "" {
		missing = append(missing, "--public-base-url")
	}

	storageDriver := firstNonEmpty(raw.storage, "fs")
	if storageDriver != "fs" && storageDriver != "s3" {
		return setupAnswers{}, fmt.Errorf("--storage: invalid value %q (want fs or s3)", raw.storage)
	}
	if storageDriver == "s3" {
		if raw.s3Endpoint == "" {
			missing = append(missing, "--s3-endpoint")
		}
		if raw.s3Region == "" {
			missing = append(missing, "--s3-region")
		}
		if raw.s3Bucket == "" {
			missing = append(missing, "--s3-bucket")
		}
	}
	if len(missing) > 0 {
		return setupAnswers{}, fmt.Errorf("--non-interactive requires: %s", strings.Join(missing, ", "))
	}

	domains, err := parseDomains(raw.domains)
	if err != nil {
		return setupAnswers{}, fmt.Errorf("--domains: %w", err)
	}
	if err := validateBaseURLFormat(raw.publicBaseURL); err != nil {
		return setupAnswers{}, fmt.Errorf("--public-base-url: %w", err)
	}

	if err := validateEnvSecretValue(raw.s3AccessKey); err != nil {
		return setupAnswers{}, fmt.Errorf("--s3-access-key: %w", err)
	}
	if err := validateEnvSecretValue(raw.s3SecretKey); err != nil {
		return setupAnswers{}, fmt.Errorf("--s3-secret-key: %w", err)
	}

	failureMode := firstNonEmpty(raw.failureMode, "open")
	if failureMode != "open" && failureMode != "closed" {
		return setupAnswers{}, fmt.Errorf("--failure-mode: invalid value %q (want open or closed)", raw.failureMode)
	}

	httpListen := firstNonEmpty(raw.httpListen, httpListenDefaultFor(env))
	milterListen := firstNonEmpty(raw.milterListen, "inet:127.0.0.1:6785")
	fsBaseDir := firstNonEmpty(raw.fsBaseDir, "/var/lib/attachra/files")

	// Port-in-use is a warning, not a hard failure: there is no
	// operator here to offer an alternative to (ATR-320's "in use ->
	// warn and offer another" only applies to the
	// interactive wizard, which loops and re-prompts).
	if perr := probeHTTPListen(httpListen); perr != nil {
		fmt.Fprintf(stderr, "attachra: setup: warning: http-listen %s: %v\n", httpListen, perr) //nolint:errcheck // best-effort diagnostic on stderr
	}
	if perr := probeMilterListen(milterListen); perr != nil {
		fmt.Fprintf(stderr, "attachra: setup: warning: milter-listen %s: %v\n", milterListen, perr) //nolint:errcheck // best-effort diagnostic on stderr
	}

	return setupAnswers{
		Domains:       domains,
		PublicBaseURL: raw.publicBaseURL,
		StorageDriver: storageDriver,
		FSBaseDir:     fsBaseDir,
		S3Endpoint:    raw.s3Endpoint,
		S3Region:      raw.s3Region,
		S3Bucket:      raw.s3Bucket,
		S3AccessKey:   raw.s3AccessKey,
		S3SecretKey:   raw.s3SecretKey,
		S3PathStyle:   raw.s3PathStyle,
		HTTPListen:    httpListen,
		MilterListen:  milterListen,
		FailureMode:   failureMode,
		DryRun:        raw.dryRun,
	}, nil
}

// runSetupWizard drives the interactive prompt flow, in the fixed
// order ATR-320 specifies: sender domain(s), public base URL, storage,
// HTTP/milter listen addresses, failure mode, dry-run. Any non-empty
// field in presets pre-fills the corresponding prompt's default (a
// value supplied via flag is still confirmed/overridable at the
// prompt, never silently applied without the operator seeing it). env
// is the detected local mail environment (ATR-337), consulted only for
// the HTTP listen prompt's default (httpListenDefaultFor).
func runSetupWizard(p *prompter, presets setupFlags, env mailEnv) (setupAnswers, error) {
	fmt.Fprintln(p.out, "Attachra setup wizard") //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "=====================") //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out)                          //nolint:errcheck // best-effort wizard prompt output

	rawDomains, err := p.askValidated("Sender domain(s) to process (comma-separated, e.g. example.com,example.org)", presets.domains, func(s string) error {
		_, e := parseDomains(s)
		return e
	})
	if err != nil {
		return setupAnswers{}, err
	}
	domains, _ := parseDomains(rawDomains) // Already validated above.

	publicBaseURL, err := p.askValidated("Public base URL embedded in download links (e.g. https://mail.example.com)", presets.publicBaseURL, validateBaseURLFormat)
	if err != nil {
		return setupAnswers{}, err
	}

	fmt.Fprintln(p.out) //nolint:errcheck // best-effort wizard prompt output
	storageDriver, err := p.askValidated("Storage driver: fs (local filesystem) or s3 (S3-compatible)", firstNonEmpty(presets.storage, "fs"), func(s string) error {
		if s != "fs" && s != "s3" {
			return errors.New("must be fs or s3")
		}
		return nil
	})
	if err != nil {
		return setupAnswers{}, err
	}

	var fsBaseDir, s3Endpoint, s3Region, s3Bucket, s3AccessKey, s3SecretKey string
	var s3PathStyle bool
	if storageDriver == "fs" {
		fsBaseDir, err = p.ask("Filesystem base directory for stored attachments", firstNonEmpty(presets.fsBaseDir, "/var/lib/attachra/files"))
		if err != nil {
			return setupAnswers{}, err
		}
	} else {
		s3Endpoint, err = p.askRequired("S3 endpoint URL (e.g. https://s3.amazonaws.com or http://localhost:9000 for MinIO)")
		if err != nil {
			return setupAnswers{}, err
		}
		s3Region, err = p.askRequired("S3 region")
		if err != nil {
			return setupAnswers{}, err
		}
		s3Bucket, err = p.askRequired("S3 bucket name")
		if err != nil {
			return setupAnswers{}, err
		}
		s3PathStyle, err = p.askYesNo("Use path-style bucket addressing (required by MinIO and most non-AWS S3 services)", false)
		if err != nil {
			return setupAnswers{}, err
		}
		fmt.Fprintln(p.out, "Note: keys typed below are echoed to the screen (no terminal echo suppression) —") //nolint:errcheck // best-effort wizard prompt output
		fmt.Fprintln(p.out, "prefer --non-interactive with flags, or leave these blank now and edit")           //nolint:errcheck // best-effort wizard prompt output
		fmt.Fprintln(p.out, "<config-dir>/attachra.env by hand afterwards if that matters to you.")             //nolint:errcheck // best-effort wizard prompt output
		s3AccessKey, err = p.ask("S3 access key (blank = use the AWS SDK's default credential chain; if set, written to <config-dir>/attachra.env, never to the world-readable attachra.yaml)", "")
		if err != nil {
			return setupAnswers{}, err
		}
		s3SecretKey, err = p.ask("S3 secret key (same handling as the access key)", "")
		if err != nil {
			return setupAnswers{}, err
		}
	}

	fmt.Fprintln(p.out) //nolint:errcheck // best-effort wizard prompt output
	httpListen, err := p.askListen("HTTP listen address for the download server", firstNonEmpty(presets.httpListen, httpListenDefaultFor(env)), probeHTTPListen)
	if err != nil {
		return setupAnswers{}, err
	}
	milterListen, err := p.askListen("Milter listen address (Postfix syntax, e.g. inet:host:port or unix:/path)", firstNonEmpty(presets.milterListen, "inet:127.0.0.1:6785"), probeMilterListen)
	if err != nil {
		return setupAnswers{}, err
	}

	fmt.Fprintln(p.out)                                                                                    //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "Failure mode controls what happens if Attachra itself fails while processing")    //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "a message: \"open\" delivers it unmodified (mail is never lost because Attachra") //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "is down — the safe default); \"closed\" temp-fails it (SMTP 4xx) so the sending") //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "MTA retries later, for deployments that require attachments to be provably")      //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "policy-checked before delivery.")                                                 //nolint:errcheck // best-effort wizard prompt output
	failureMode, err := p.askValidated("Failure mode: open or closed", firstNonEmpty(presets.failureMode, "open"), func(s string) error {
		if s != "open" && s != "closed" {
			return errors.New("must be open or closed")
		}
		return nil
	})
	if err != nil {
		return setupAnswers{}, err
	}

	fmt.Fprintln(p.out)                                                                                //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "Dry-run mode logs every policy decision (audit trail) without actually")      //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "replacing attachments — recommended for a first rollout, so you can verify")  //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "behavior against real traffic before enforcing it. Disable later by setting") //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "`dry_run: false` under `policy:` in attachra.yaml and running")               //nolint:errcheck // best-effort wizard prompt output
	fmt.Fprintln(p.out, "`systemctl reload attachra`.")                                                //nolint:errcheck // best-effort wizard prompt output
	dryRun, err := p.askYesNo("Start in dry-run mode", true)
	if err != nil {
		return setupAnswers{}, err
	}

	return setupAnswers{
		Domains:       domains,
		PublicBaseURL: publicBaseURL,
		StorageDriver: storageDriver,
		FSBaseDir:     fsBaseDir,
		S3Endpoint:    s3Endpoint,
		S3Region:      s3Region,
		S3Bucket:      s3Bucket,
		S3AccessKey:   s3AccessKey,
		S3SecretKey:   s3SecretKey,
		S3PathStyle:   s3PathStyle,
		HTTPListen:    httpListen,
		MilterListen:  milterListen,
		FailureMode:   failureMode,
		DryRun:        dryRun,
	}, nil
}

// setupBackupSuffix names the sidecar backup file writeManagedFile
// renames a pre-existing target to before overwriting it.
const setupBackupSuffix = ".setup-bak"

// writeManagedFile writes content to path, replacing perm's bits only
// on a freshly created file (matching os.WriteFile's own semantics,
// which is also why this doubles as ATR-320 review NIT-2's fix for
// attachra.env: renaming any pre-existing file out of the way first,
// rather than truncating it in place, guarantees the replacement is
// created fresh with exactly perm — 0600 for the env file — instead of
// silently inheriting a looser mode, e.g. 0644, left over from an
// earlier run).
//
// If path already exists, it is renamed to path+setupBackupSuffix
// before the new content is written, and the returned rollback
// restores that backup (renaming it back over path) instead of simply
// deleting path — otherwise a --force re-run whose answers fail the
// end-of-run config.Load/policy.Parse verification would destroy an
// operator's previously valid, already-deployed config (ATR-320 review
// MUST-FIX). If path did not exist, rollback just removes the file
// writeManagedFile itself created. The returned commit must be called
// once the overall setup has fully succeeded; it discards the backup
// (if any). Exactly one of rollback/commit should ever be called, and
// at most once.
func writeManagedFile(path string, content []byte, perm os.FileMode) (rollback, commit func(), err error) {
	backupPath := path + setupBackupSuffix
	hadExisting := false
	if _, statErr := os.Stat(path); statErr == nil {
		hadExisting = true
		// A leftover backup from an earlier, interrupted run (e.g. the
		// process was killed between the rename and the write below)
		// would otherwise make this rename fail with "file exists"; a
		// stale backup that old is not this run's to preserve.
		_ = os.Remove(backupPath)
		if renameErr := os.Rename(path, backupPath); renameErr != nil {
			return nil, nil, fmt.Errorf("back up existing %q: %w", path, renameErr)
		}
	}

	if writeErr := os.WriteFile(path, content, perm); writeErr != nil { //nolint:gosec // path is derived from operator-supplied --config-dir, not untrusted input; perm is caller-controlled (0644 for the world-readable YAML conffiles, 0600 for attachra.env)
		if hadExisting {
			_ = os.Rename(backupPath, path) // Best-effort: restore the original before reporting the write failure.
		}
		return nil, nil, writeErr
	}

	if hadExisting {
		rollback = func() { _ = os.Rename(backupPath, path) }
		commit = func() { _ = os.Remove(backupPath) }
	} else {
		rollback = func() { _ = os.Remove(path) }
		commit = func() {}
	}
	return rollback, commit, nil
}

// validateEnvSecretValue rejects a secret value that would corrupt the
// generated attachra.env (a simple KEY=VALUE-per-line format): an
// embedded newline would either truncate the value or inject a
// spurious extra line (ATR-320 review NIT-4).
func validateEnvSecretValue(v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return errors.New("must not contain newline characters (would corrupt the generated attachra.env)")
	}
	return nil
}

// applySetupAnswers renders answers into attachra.yaml/policy.yaml (and
// attachra.env, if S3 credentials were given) under configDir, then
// verifies the result by running it through the exact same
// config.Load/policy.Parse validation the real binary uses at startup.
//
// Every file this call writes goes through writeManagedFile, so a
// failed verification rolls each one back to its exact prior state:
// removed if it was newly created, restored from backup if it
// overwrote an existing file (e.g. a --force re-run) — a failed
// `attachra setup` never leaves a half-written config directory behind
// NOR destroys a previously valid one (ATR-320: "never leave a
// half-created state behind"). env is the detected local mail
// environment (ATR-337), forwarded to printSetupNextSteps to tailor its
// final guidance.
func applySetupAnswers(configDir string, a setupAnswers, env mailEnv, stdout, stderr io.Writer) int {
	if err := validateEnvSecretValue(a.S3AccessKey); err != nil {
		fmt.Fprintf(stderr, "attachra: setup: s3 access key: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return setupError
	}
	if err := validateEnvSecretValue(a.S3SecretKey); err != nil {
		fmt.Fprintf(stderr, "attachra: setup: s3 secret key: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return setupError
	}

	if err := os.MkdirAll(configDir, 0o755); err != nil { //nolint:gosec // operator-supplied --config-dir, world-readable by design (matches attachra.yaml's own conffile permissions)
		fmt.Fprintf(stderr, "attachra: setup: create config dir %q: %v\n", configDir, err) //nolint:errcheck // best-effort diagnostic on stderr
		return setupError
	}

	attachraPath := filepath.Join(configDir, "attachra.yaml")
	policyPath := filepath.Join(configDir, "policy.yaml")
	envPath := filepath.Join(configDir, "attachra.env")

	var rollbacks, commits []func()
	rollbackAll := func() {
		for i := len(rollbacks) - 1; i >= 0; i-- {
			rollbacks[i]()
		}
	}
	commitAll := func() {
		for _, c := range commits {
			c()
		}
	}
	// write centralizes the "call writeManagedFile, report the error,
	// unwind everything written so far" pattern so each call site below
	// only differs in path/content/perm.
	write := func(path string, content []byte, perm os.FileMode) bool {
		rb, ci, err := writeManagedFile(path, content, perm)
		if err != nil {
			fmt.Fprintf(stderr, "attachra: setup: write %q: %v\n", path, err) //nolint:errcheck // best-effort diagnostic on stderr
			rollbackAll()
			return false
		}
		rollbacks = append(rollbacks, rb)
		commits = append(commits, ci)
		return true
	}

	// 0644: matches the packaged conffile's own world-readable
	// permissions (deploy/deb/etc/attachra.yaml, policy.yaml).
	if !write(attachraPath, []byte(generateAttachraYAML(a, policyPath)), 0o644) {
		return setupError
	}
	if !write(policyPath, []byte(generatePolicyYAML(a)), 0o644) {
		return setupError
	}

	if a.StorageDriver == "s3" && (a.S3AccessKey != "" || a.S3SecretKey != "") {
		var env strings.Builder
		if a.S3AccessKey != "" {
			fmt.Fprintf(&env, "ATTACHRA_S3_ACCESS_KEY=%s\n", a.S3AccessKey)
		}
		if a.S3SecretKey != "" {
			fmt.Fprintf(&env, "ATTACHRA_S3_SECRET_KEY=%s\n", a.S3SecretKey)
		}
		// 0600: keeps the secret root-only, matching
		// docs/deploy/grommunio-debian.md's manual instructions.
		if !write(envPath, []byte(env.String()), 0o600) {
			return setupError
		}
	}

	// Verify: run the generated files through the exact same
	// validation the real binary applies at startup, so a config that
	// `attachra setup` accepts is guaranteed to also be one `attachra
	// --config ...` accepts.
	if _, err := config.Load(attachraPath); err != nil {
		fmt.Fprintf(stderr, "attachra: setup: generated config failed validation: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		rollbackAll()
		return setupError
	}
	policyData, err := os.ReadFile(policyPath) //nolint:gosec // policyPath was just written by this same call, not untrusted input
	if err != nil {
		fmt.Fprintf(stderr, "attachra: setup: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		rollbackAll()
		return setupError
	}
	_, warnings, err := policy.Parse(policyData, policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: setup: generated policy failed validation: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		rollbackAll()
		return setupError
	}
	for _, w := range warnings {
		fmt.Fprintf(stdout, "attachra: setup: policy warning: %s\n", w) //nolint:errcheck // best-effort diagnostic on stdout
	}

	commitAll()
	printSetupNextSteps(stdout, configDir, attachraPath, policyPath, a, env)
	return setupOK
}

// printSetupNextSteps prints the operator's remaining manual steps
// after a successful `attachra setup`: none of these are things setup
// can safely do on its own (they touch Postfix/nginx config outside
// attachra's own files, or require root/systemd). env is the detected
// local mail environment (ATR-337): it never changes what setup writes
// to disk, only which of these printed hints/doc references apply.
func printSetupNextSteps(stdout io.Writer, configDir, attachraPath, policyPath string, a setupAnswers, env mailEnv) {
	fmt.Fprintln(stdout)                               //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "Setup complete. Generated:") //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintf(stdout, "  %s\n", attachraPath)        //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintf(stdout, "  %s\n", policyPath)          //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout)                               //nolint:errcheck // best-effort diagnostic on stdout

	if a.DryRun {
		fmt.Fprintln(stdout, "Policy started in DRY-RUN mode: attachments are NOT replaced yet, but every")  //nolint:errcheck // best-effort diagnostic on stdout
		fmt.Fprintln(stdout, "would-be decision is logged and recorded in the audit trail. Review it, then") //nolint:errcheck // best-effort diagnostic on stdout
		fmt.Fprintln(stdout, "enable enforcement by setting `dry_run: false` under `policy:` in")            //nolint:errcheck // best-effort diagnostic on stdout
		fmt.Fprintf(stdout, "%s and running `systemctl reload attachra`.\n", attachraPath)                   //nolint:errcheck // best-effort diagnostic on stdout
		fmt.Fprintln(stdout)                                                                                 //nolint:errcheck // best-effort diagnostic on stdout
	}

	fmt.Fprintln(stdout, "Next steps:")                            //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "  1. Review the generated files above.") //nolint:errcheck // best-effort diagnostic on stdout
	if configDir == "/etc/attachra" {
		fmt.Fprintln(stdout, "  2. sudo systemctl enable --now attachra") //nolint:errcheck // best-effort diagnostic on stdout
	} else {
		fmt.Fprintf(stdout, "  2. attachra --config %s   (or copy these files into /etc/attachra to use the packaged systemd unit)\n", attachraPath) //nolint:errcheck // best-effort diagnostic on stdout
	}
	fmt.Fprintln(stdout, "  3. Wire Attachra into the Postfix milter chain, AFTER any existing filter")          //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "     (e.g. rspamd) — its verdict should be settled before Attachra spends effort")     //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "     uploading attachments and rewriting the message:")                                //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "       postconf -h smtpd_milters non_smtpd_milters   # see what's already configured") //nolint:errcheck // best-effort diagnostic on stdout
	smtpdMilters, nonSMTPdMilters, foundMilters := existingMilters()
	if !foundMilters {
		smtpdMilters, nonSMTPdMilters = "<existing>", "<existing>"
	}
	fmt.Fprintf(stdout, "       sudo postconf -e 'smtpd_milters = %s'\n", milterChain(smtpdMilters, a.MilterListen))        //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintf(stdout, "       sudo postconf -e 'non_smtpd_milters = %s'\n", milterChain(nonSMTPdMilters, a.MilterListen)) //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "       sudo systemctl reload postfix")                                                            //nolint:errcheck // best-effort diagnostic on stdout
	if env == mailEnvMailcow {
		fmt.Fprintln(stdout, "     WARNING: this .deb targets a host Postfix install. mailcow-dockerized runs its own") //nolint:errcheck // best-effort diagnostic on stdout
		fmt.Fprintln(stdout, "     Postfix inside a container (postfix-mailcow), which the command above does not")     //nolint:errcheck // best-effort diagnostic on stdout
		fmt.Fprintln(stdout, "     touch — see docs/integrations/postfix.md for wiring Attachra into a containerized")  //nolint:errcheck // best-effort diagnostic on stdout
		fmt.Fprintln(stdout, "     Postfix instead.")                                                                   //nolint:errcheck // best-effort diagnostic on stdout
	}
	fmt.Fprintln(stdout, "  4. Publish the package/download page (ONLY the /p/ path, never /api/v1 or") //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "     /metrics) through a reverse proxy")                                      //nolint:errcheck // best-effort diagnostic on stdout
	if env == mailEnvGrommunio {
		fmt.Fprintln(stdout, "     — see /usr/share/attachra/examples/nginx-grommunio.conf and") //nolint:errcheck // best-effort diagnostic on stdout
		fmt.Fprintln(stdout, "     docs/deploy/grommunio-debian.md.")                            //nolint:errcheck // best-effort diagnostic on stdout
	} else {
		fmt.Fprintln(stdout, "     — see docs/integrations/postfix.md.") //nolint:errcheck // best-effort diagnostic on stdout
	}
	fmt.Fprintln(stdout, "     If that proxy is co-located on this host, also set http.trusted_proxies in")         //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "     attachra.yaml (ATR-311), or audit/rate-limiting will see the proxy's address")       //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "     instead of the real client.")                                                        //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintf(stdout, "  5. Validate the policy any time you edit it: attachra policy validate %s\n", policyPath) //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "  6. Run `attachra doctor` for a one-shot health check across these steps; or use")       //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout, "     GET /healthz and GET /readyz on the http.listen address directly.")                  //nolint:errcheck // best-effort diagnostic on stdout
	fmt.Fprintln(stdout)                                                                                            //nolint:errcheck // best-effort diagnostic on stdout

	switch env {
	case mailEnvGrommunio:
		fmt.Fprintln(stdout, "Detected: grommunio. Full guide: docs/deploy/grommunio-debian.md in the attachra source tree.") //nolint:errcheck // best-effort diagnostic on stdout
	case mailEnvMailcow:
		fmt.Fprintln(stdout, "Detected: mailcow-dockerized. See docs/integrations/postfix.md in the attachra source tree.") //nolint:errcheck // best-effort diagnostic on stdout
	case mailEnvIRedMail:
		fmt.Fprintln(stdout, "Detected: iRedMail. See docs/integrations/postfix.md in the attachra source tree.") //nolint:errcheck // best-effort diagnostic on stdout
	case mailEnvPostfix:
		fmt.Fprintln(stdout, "Detected: Postfix. Full guide: docs/integrations/postfix.md in the attachra source tree.") //nolint:errcheck // best-effort diagnostic on stdout
	default:
		fmt.Fprintln(stdout, "Full guide: docs/integrations/postfix.md in the attachra source tree.") //nolint:errcheck // best-effort diagnostic on stdout
	}
}

// milterChain renders the postconf -e assignment value for a single
// milter setting (smtpd_milters or non_smtpd_milters): existing is
// either a previously configured value read via existingMilters (kept
// first, so an already-wired filter like rspamd keeps running before
// Attachra) or the "<existing>" placeholder when that could not be
// determined, and ours is this run's own a.MilterListen, always
// appended last.
func milterChain(existing, ours string) string {
	if strings.TrimSpace(existing) == "" {
		return ours
	}
	return existing + ", " + ours
}

// generateAttachraYAML renders a.'s answers into an attachra.yaml
// document, deliberately mirroring the structure and comment style of
// deploy/deb/etc/attachra.yaml so a generated file reads the same as
// the packaged template an operator might otherwise have hand-edited.
// policyPath is embedded as policy.path so the generated attachra.yaml
// points at the policy.yaml this same setup run writes alongside it.
func generateAttachraYAML(a setupAnswers, policyPath string) string {
	var b strings.Builder

	b.WriteString("# Attachra configuration — generated by `attachra setup` (ATR-320).\n")
	b.WriteString("#\n")
	b.WriteString("# See internal/config/config.go in the attachra source tree for the full\n")
	b.WriteString("# schema, every field's meaning, and its default value (config.Default()) —\n")
	b.WriteString("# fields not written out below simply keep their built-in default. After\n")
	b.WriteString("# editing, `systemctl restart attachra` (or `systemctl reload attachra` for\n")
	b.WriteString("# policy.yaml-only changes) to apply.\n\n")

	b.WriteString("log:\n  level: info\n  format: text\n\n")

	b.WriteString("milter:\n")
	fmt.Fprintf(&b, "  listen: %q\n", a.MilterListen)
	if a.FailureMode == "closed" {
		b.WriteString("  # \"closed\": a message is temp-failed (SMTP 4xx) if Attachra cannot process\n")
		b.WriteString("  # it, so the sending MTA retries later, rather than delivering it unchecked.\n")
	} else {
		b.WriteString("  # \"open\": if Attachra cannot process a message (crash, timeout, bug), the\n")
		b.WriteString("  # message is delivered unmodified rather than blocked — mail must never be\n")
		b.WriteString("  # lost because of an Attachra failure.\n")
	}
	fmt.Fprintf(&b, "  failure_mode: %s\n\n", a.FailureMode)

	b.WriteString("http:\n")
	fmt.Fprintf(&b, "  listen: %q\n\n", a.HTTPListen)

	b.WriteString("# Base URL embedded in every rewritten message's download link. Must be\n")
	b.WriteString("# reachable by the mail recipients this system sends to.\n")
	fmt.Fprintf(&b, "public_base_url: %q\n\n", a.PublicBaseURL)

	b.WriteString("storage:\n")
	fmt.Fprintf(&b, "  driver: %s\n", a.StorageDriver)
	if a.StorageDriver == "fs" {
		b.WriteString("  fs:\n")
		fmt.Fprintf(&b, "    base_dir: %q\n\n", a.FSBaseDir)
	} else {
		b.WriteString("  s3:\n")
		fmt.Fprintf(&b, "    endpoint: %q\n", a.S3Endpoint)
		fmt.Fprintf(&b, "    region: %q\n", a.S3Region)
		fmt.Fprintf(&b, "    bucket: %q\n", a.S3Bucket)
		fmt.Fprintf(&b, "    path_style: %t\n", a.S3PathStyle)
		if a.S3AccessKey != "" || a.S3SecretKey != "" {
			b.WriteString("    # Credentials are kept OUT of this world-readable file — see\n")
			b.WriteString("    # <config-dir>/attachra.env, substituted in via ${ENV_VAR} (internal/config's\n")
			b.WriteString("    # expandEnv) and loaded by systemd's EnvironmentFile= before the service\n")
			b.WriteString("    # drops privileges.\n")
			b.WriteString("    access_key: \"${ATTACHRA_S3_ACCESS_KEY}\"\n")
			b.WriteString("    secret_key: \"${ATTACHRA_S3_SECRET_KEY}\"\n")
		} else {
			b.WriteString("    # No access/secret key set: the AWS SDK's default credential chain (env\n")
			b.WriteString("    # vars, shared config, instance/task role) is used instead.\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("database:\n  driver: sqlite\n  path: /var/lib/attachra/attachra.db\n\n")

	b.WriteString("# Policy document controlling which attachments get replaced with a download\n")
	b.WriteString("# link. docs/architecture/policy-format-v1.md has the full grammar.\n")
	b.WriteString("policy:\n")
	fmt.Fprintf(&b, "  path: %q\n", policyPath)
	fmt.Fprintf(&b, "  dry_run: %t\n", a.DryRun)

	return b.String()
}

// generatePolicyYAML renders a.'s domains into a policy.yaml document
// scoped to exactly those sender domains, mirroring
// deploy/deb/etc/policy.yaml's shape: every other sender passes
// through untouched (SR-119-1's required explicit fallback).
func generatePolicyYAML(a setupAnswers) string {
	var b strings.Builder

	b.WriteString("# Attachra policy — generated by `attachra setup` (ATR-320).\n")
	b.WriteString("#\n")
	b.WriteString("# Validate any change with:\n")
	b.WriteString("#\n")
	b.WriteString("#   attachra policy validate <this file>\n")
	b.WriteString("#\n")
	b.WriteString("# then `systemctl reload attachra` (SIGHUP) to pick it up without a restart.\n")
	b.WriteString("# Full grammar: docs/architecture/policy-format-v1.md.\n\n")

	b.WriteString("version: 1\n")
	fmt.Fprintf(&b, "name: %q\n", fmt.Sprintf("replace attachments from %s", strings.Join(a.Domains, ", ")))
	b.WriteString("description: >\n")
	b.WriteString("  Replaces every attachment on outbound mail from the configured sender\n")
	b.WriteString("  domain(s) with a personal, revocable download link. All other senders pass\n")
	b.WriteString("  through unmodified.\n\n")

	b.WriteString("rules:\n")
	b.WriteString("  # Inline logo/signature images (referenced from the HTML body via cid:,\n")
	b.WriteString("  # inside multipart/related) are protected from replacement automatically\n")
	b.WriteString("  # (ADR-016), so this broad \"replace everything\" scope is safe by default.\n")
	b.WriteString("  - name: \"configured senders: replace attachments with a download link\"\n")
	b.WriteString("    when:\n")
	b.WriteString("      sender:\n")
	b.WriteString("        domain:\n")
	for _, d := range a.Domains {
		fmt.Fprintf(&b, "          - %q\n", d)
	}
	b.WriteString("    then:\n")
	b.WriteString("      action: replace\n")
	b.WriteString("      ttl: \"7d\"\n")
	b.WriteString("      retention: \"30d\"\n\n")

	b.WriteString("# Every other sender (any domain not listed above) is left untouched:\n")
	b.WriteString("# attachments pass through exactly as sent (required fallback, SR-119-1).\n")
	b.WriteString("default:\n  action: pass\n")

	return b.String()
}

// domainLabelRe matches a single DNS label: alphanumeric, optionally
// hyphenated, but never starting or ending with a hyphen.
var domainLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validateDomain reports whether d looks like a well-formed DNS domain
// name (at least two dot-separated labels, each a valid DNS label).
func validateDomain(d string) error {
	if d == "" {
		return errors.New("empty domain")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q: must contain at least one dot (e.g. example.com)", d)
	}
	for _, l := range labels {
		if !domainLabelRe.MatchString(l) {
			return fmt.Errorf("%q: invalid domain label %q", d, l)
		}
	}
	return nil
}

// parseDomains splits raw on commas, trims whitespace, lower-cases and
// validates each entry, and requires at least one to remain.
func parseDomains(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		d := strings.ToLower(strings.TrimSpace(part))
		if d == "" {
			continue
		}
		if err := validateDomain(d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	return out, nil
}

// validateBaseURLFormat checks that raw is an absolute, well-formed
// http(s) URL, mirroring internal/config.validatePublicBaseURL's own
// (unexported) check. It is intentionally duplicated rather than
// exported from internal/config purely for this CLI's early,
// user-facing feedback — config.Load's own Validate() is still the
// final authority, run again once the file is written
// (applySetupAnswers).
func validateBaseURLFormat(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("must include a host")
	}
	return nil
}

// probeHTTPListen reports whether addr is currently free to bind by
// briefly binding and immediately releasing it. A non-nil error does
// not necessarily mean the address is unusable by the real attachra
// process (e.g. it may run under a different UID with CAP_NET_BIND or
// after this check's own listener released the port) — it is a
// best-effort, advisory check only.
func probeHTTPListen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// probeMilterListen parses listen in Postfix milter syntax
// ("inet:host:port" or "unix:/path") and probes it the same
// best-effort way as probeHTTPListen.
func probeMilterListen(listen string) error {
	switch {
	case strings.HasPrefix(listen, "inet:"):
		return probeHTTPListen(strings.TrimPrefix(listen, "inet:"))
	case strings.HasPrefix(listen, "unix:"):
		path := strings.TrimPrefix(listen, "unix:")
		ln, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		return ln.Close()
	default:
		return fmt.Errorf("unrecognized syntax %q (want inet:host:port or unix:/path)", listen)
	}
}

// firstNonEmpty returns a if it is non-empty, else b. Used throughout
// this file to apply a --non-interactive flag (or interactive preset)
// only when the operator actually set it, falling back to the wizard's
// documented default otherwise.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// prompter drives the interactive wizard's question/answer loop over
// an arbitrary io.Reader (bufio-wrapped for line-oriented reads) and
// io.Writer, so it needs neither a real terminal nor os.Stdin/os.Stdout
// specifically to be exercised in tests.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter(in io.Reader, out io.Writer) *prompter {
	return &prompter{in: bufio.NewReader(in), out: out}
}

// readLine reads one line, trimming surrounding whitespace. A final
// line with no trailing newline (as a test's last scripted answer
// often is) is still returned successfully; running out of input
// entirely (io.EOF with nothing left to read) is reported as an error,
// so a wizard that outruns its scripted answers fails clearly instead
// of looping forever on empty reads.
func (p *prompter) readLine() (string, error) {
	line, err := p.in.ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return line, nil
		}
		return "", err
	}
	return line, nil
}

// ask prints question (with def shown as the value Enter accepts, if
// def is non-empty) and returns the operator's answer, or def if they
// just pressed Enter.
func (p *prompter) ask(question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", question, def) //nolint:errcheck // best-effort prompt output
	} else {
		fmt.Fprintf(p.out, "%s: ", question) //nolint:errcheck // best-effort prompt output
	}
	line, err := p.readLine()
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	if line == "" {
		return def, nil
	}
	return line, nil
}

// askRequired loops until a non-empty answer is given.
func (p *prompter) askRequired(question string) (string, error) {
	for {
		v, err := p.ask(question, "")
		if err != nil {
			return "", err
		}
		if v != "" {
			return v, nil
		}
		fmt.Fprintln(p.out, "  (required, please enter a value)") //nolint:errcheck // best-effort prompt output
	}
}

// askValidated loops, re-prompting with the operator's own (invalid)
// answer as the new default, until parse accepts the answer.
func (p *prompter) askValidated(question, def string, parse func(string) error) (string, error) {
	for {
		raw, err := p.ask(question, def)
		if err != nil {
			return "", err
		}
		if verr := parse(raw); verr != nil {
			fmt.Fprintf(p.out, "  invalid: %v\n", verr) //nolint:errcheck // best-effort prompt output
			def = raw
			continue
		}
		return raw, nil
	}
}

// askYesNo prompts a y/n question, defaulting to def on a bare Enter.
func (p *prompter) askYesNo(question string, def bool) (bool, error) {
	defStr := "Y/n"
	if !def {
		defStr = "y/N"
	}
	for {
		v, err := p.ask(fmt.Sprintf("%s [%s]", question, defStr), "")
		if err != nil {
			return false, err
		}
		if v == "" {
			return def, nil
		}
		switch strings.ToLower(v) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.out, "  please answer y or n") //nolint:errcheck // best-effort prompt output
	}
}

// askListen prompts for a listen address, probing it with probe and,
// on failure, warning and offering the operator a chance to either
// enter a different address or force-keep the one they gave
// (ATR-320's "in use -> warn and offer another").
func (p *prompter) askListen(question, def string, probe func(string) error) (string, error) {
	for {
		v, err := p.ask(question, def)
		if err != nil {
			return "", err
		}
		if perr := probe(v); perr != nil {
			fmt.Fprintf(p.out, "  warning: %s: %v\n", v, perr) //nolint:errcheck // best-effort prompt output
			keep, err := p.askYesNo("  use it anyway", false)
			if err != nil {
				return "", err
			}
			if keep {
				return v, nil
			}
			def = "" // Force a fresh answer rather than re-offering the address that just failed.
			continue
		}
		return v, nil
	}
}
