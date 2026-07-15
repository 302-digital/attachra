package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver used by probeSQLiteReadOnly below.

	"github.com/302-digital/attachra/internal/config"
	"github.com/302-digital/attachra/internal/core/policy"
)

// ATR-321: `attachra doctor` is a standalone, read-only diagnostic
// subcommand for an already-configured (or partially configured)
// installation. It exists to cut support back-and-forth on the public
// repo ("please run attachra doctor and paste the output") by
// reproducing, in one command, the checks the grommunio pilot needed
// human debugging for (docs/deploy/grommunio-debian.md
// "Troubleshooting"): config/policy loading, the DynamicUser
// root-owned-file trap, the SQLITE_CANTOPEN trap, whether the
// milter/HTTP listeners are actually up, whether the public download
// URL and SPF records look right, and whether postfix is actually
// wired to the milter.
//
// This file intentionally lives entirely in cmd/attachra (no new
// internal/core package): every check here is either a thin read over
// already-loaded config/policy state or a direct OS/network probe, not
// domain logic, so ADR-002's adapter/core boundary does not apply.

// Doctor check statuses. These four are the entire status vocabulary
// (also the JSON `status` value set) - the numbered checklist this
// command implements also mentions "INFO" for a couple of genuinely
// unknowable outcomes (e.g. SPF verification when the server's public
// IP can't be determined), but that maps to statusWarn here: it is
// non-blocking (never contributes to a FAIL exit code) but still
// something an operator should read, and a 4-value enum keeps the
// output/JSON schema simple and stable.
const (
	statusPass = "PASS"
	statusWarn = "WARN"
	statusFail = "FAIL"
	statusSkip = "SKIP"
)

// checkResult is one row of `attachra doctor` output, and (with --json)
// the exact shape of each element in the emitted JSON array. Hint is
// always present (as "" when there is nothing actionable to add) so the
// JSON schema is stable across runs regardless of which checks have
// something to suggest.
type checkResult struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Hint   string `json:"hint"`
}

// defaultDoctorConfigPath matches deploy/deb/systemd/attachra.service's
// ExecStart (`--config /etc/attachra/attachra.yaml`), the only
// configuration path a packaged install ever uses. A developer running
// `attachra doctor` against a local checkout without that file present
// gets a clear FAIL on the `config` check pointing at --config, rather
// than a silently-defaulted, not-actually-diagnostic run.
const defaultDoctorConfigPath = "/etc/attachra/attachra.yaml"

// doctorNetTimeout bounds every individual network probe this command
// performs (TCP connect, HTTP GET, DNS lookup), so a single hung
// dependency cannot make `attachra doctor` itself hang.
const doctorNetTimeout = 3 * time.Second

// runDoctorCommand implements `attachra doctor [--config <path>] [--json]
// [--skip-external]` (ATR-321).
func runDoctorCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attachra doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultDoctorConfigPath, "path to YAML configuration file")
	jsonOut := fs.Bool("json", false, "print results as a JSON array instead of a table")
	skipExternal := fs.Bool("skip-external", false, "skip checks that require outbound network/DNS access (public URL reachability, SPF lookups)")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "attachra: usage: attachra doctor [--config <path>] [--json] [--skip-external]") //nolint:errcheck // best-effort diagnostic on stderr
		return 1
	}

	results := runDoctorChecks(*configPath, *skipExternal, defaultDoctorDeps())

	if *jsonOut {
		writeDoctorJSON(stdout, results)
	} else {
		writeDoctorTable(stdout, results)
	}

	for _, r := range results {
		if r.Status == statusFail {
			return 1
		}
	}
	return 0
}

// writeDoctorJSON writes results as a JSON array. Encoding errors are
// deliberately swallowed (best-effort diagnostic output, matching this
// package's other stdout-writing helpers): there is no meaningful
// recovery for a failed write to the process's own stdout.
func writeDoctorJSON(w io.Writer, results []checkResult) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}

// writeDoctorTable writes results as an aligned STATUS/CHECK/DETAIL
// table (plus an indented hint line under any row that has one),
// followed by a one-line pass/warn/fail/skip summary.
func writeDoctorTable(w io.Writer, results []checkResult) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK\tDETAIL") //nolint:errcheck // best-effort diagnostic output
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Status, r.Check, r.Detail) //nolint:errcheck // best-effort diagnostic output
		if r.Hint != "" {
			fmt.Fprintf(tw, "\t\thint: %s\n", r.Hint) //nolint:errcheck // best-effort diagnostic output
		}
	}
	_ = tw.Flush()

	var pass, warn, fail, skip int
	for _, r := range results {
		switch r.Status {
		case statusPass:
			pass++
		case statusWarn:
			warn++
		case statusFail:
			fail++
		case statusSkip:
			skip++
		}
	}
	verdict := "OK"
	if fail > 0 {
		verdict = "FAIL (see hints above)"
	}
	fmt.Fprintf(w, "\n%d pass, %d warn, %d fail, %d skip - %s\n", pass, warn, fail, skip, verdict) //nolint:errcheck // best-effort diagnostic output
}

// runDoctorChecks runs every check in order and returns the flattened
// result list. Each check group is isolated via runChecked: a panic in
// one check (a bug in that check, or an unexpected environment) is
// turned into a single FAIL row for that check rather than aborting the
// rest of the diagnostic run - the whole point of this command is to
// surface as much signal as possible in one pass.
func runDoctorChecks(configPath string, skipExternal bool, deps doctorDeps) []checkResult {
	var results []checkResult
	ctx := context.Background()

	cfg, cfgResult := checkConfig(configPath)
	results = append(results, cfgResult)
	if cfgResult.Status == statusFail {
		for _, check := range []string{"policy", "storage_dir", "database_dir", "database", "http_port", "milter_port", "public_url", "spf", "postfix"} {
			results = append(results, checkResult{Check: check, Status: statusSkip, Detail: "skipped: config failed to load, see the config check"})
		}
		return results
	}

	pol, polResults := checkPolicy(cfg)
	results = append(results, polResults...)

	results = append(results, runChecked("storage_dir", func() []checkResult { return checkStorageDir(cfg) })...)
	results = append(results, runChecked("database_dir", func() []checkResult { return checkDatabaseDir(cfg) })...)
	results = append(results, runChecked("database", func() []checkResult { return checkDatabase(cfg) })...)
	results = append(results, runChecked("http_port", func() []checkResult { return checkHTTPService(ctx, cfg, deps) })...)
	results = append(results, runChecked("milter_port", func() []checkResult { return checkMilterPort(ctx, cfg, deps) })...)
	results = append(results, runChecked("public_url", func() []checkResult { return checkPublicURL(ctx, cfg, deps, skipExternal) })...)
	results = append(results, runChecked("spf", func() []checkResult { return checkSPF(ctx, pol, deps, skipExternal) })...)
	results = append(results, runChecked("postfix", func() []checkResult { return checkPostfix(cfg, deps) })...)

	return results
}

// runChecked runs fn and recovers any panic into a single FAIL result
// named check, so one broken check can never take the rest of
// `attachra doctor` down with it.
func runChecked(check string, fn func() []checkResult) (results []checkResult) {
	defer func() {
		if r := recover(); r != nil {
			results = []checkResult{{
				Check:  check,
				Status: statusFail,
				Detail: fmt.Sprintf("internal error (panic): %v", r),
				Hint:   "this is a bug in `attachra doctor`, not your installation; please report it",
			}}
		}
	}()
	return fn()
}

// --- 1. config ---------------------------------------------------------

// checkConfig implements check #1: does the config file exist and does
// config.Load succeed, and (on success) a summary of the effective,
// secret-redacted configuration an operator would otherwise have to go
// read attachra.yaml themselves to see.
func checkConfig(path string) (config.Config, checkResult) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, checkResult{
			Check:  "config",
			Status: statusFail,
			Detail: err.Error(),
			Hint:   "fix the reported field(s) - internal/config/config.go documents valid values; if this is a dev checkout without a packaged install, pass --config explicitly",
		}
	}
	return cfg, checkResult{Check: "config", Status: statusPass, Detail: formatConfigDetail(path, cfg)}
}

// formatConfigDetail summarizes the effective configuration cfg loaded
// from path. Secret-typed fields (S3 access/secret key) are never
// formatted directly: config.Secret's fmt.Stringer implementation
// already substitutes "[REDACTED]" for %v, so this function gets that
// masking for free by never calling .Value().
func formatConfigDetail(path string, cfg config.Config) string {
	src := path
	if src == "" {
		src = "built-in defaults (no --config given)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "loaded from %s | log.level=%s log.format=%s milter.listen=%s milter.failure_mode=%s http.listen=%s storage.driver=%s database.path=%s policy.path=%s policy.dry_run=%t public_base_url=%s",
		src, cfg.Log.Level, cfg.Log.Format, cfg.Milter.Listen, cfg.Milter.FailureMode, cfg.HTTP.Listen, cfg.Storage.Driver, cfg.Database.Path, orNone(cfg.Policy.Path), cfg.Policy.DryRun, orNone(cfg.PublicBaseURL))

	switch cfg.Storage.Driver {
	case "fs":
		fmt.Fprintf(&b, " storage.fs.base_dir=%s", cfg.Storage.FS.BaseDir)
	case "s3":
		fmt.Fprintf(&b, " storage.s3.bucket=%s storage.s3.endpoint=%s storage.s3.access_key=%v storage.s3.secret_key=%v",
			cfg.Storage.S3.Bucket, cfg.Storage.S3.Endpoint, cfg.Storage.S3.AccessKey, cfg.Storage.S3.SecretKey)
	}

	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// --- 2. policy -----------------------------------------------------------

// checkPolicy implements check #2. It returns the parsed *policy.Policy
// (nil if none is configured or it failed to load) so checkSPF below
// can reuse the already-parsed sender domains instead of re-reading and
// re-parsing the file.
func checkPolicy(cfg config.Config) (*policy.Policy, []checkResult) {
	if strings.TrimSpace(cfg.Policy.Path) == "" {
		return nil, []checkResult{{
			Check:  "policy",
			Status: statusWarn,
			Detail: "no policy configured (policy.path is empty): passthrough mode, attachments are never processed",
			Hint:   "set policy.path in attachra.yaml and provide a policy document (docs/architecture/policy-format-v1.md)",
		}}
	}

	data, err := os.ReadFile(cfg.Policy.Path) //nolint:gosec // path comes from the operator's own config file, not untrusted input
	if err != nil {
		return nil, []checkResult{{
			Check:  "policy",
			Status: statusFail,
			Detail: fmt.Sprintf("cannot read %s: %v", cfg.Policy.Path, err),
			Hint:   "check policy.path in attachra.yaml and the file's permissions",
		}}
	}

	p, warnings, err := policy.Parse(data, cfg.Policy.Path)
	if err != nil {
		return nil, []checkResult{{
			Check:  "policy",
			Status: statusFail,
			Detail: err.Error(),
			Hint:   fmt.Sprintf("run `attachra policy validate %s` for details", cfg.Policy.Path),
		}}
	}

	results := []checkResult{{
		Check:  "policy",
		Status: statusPass,
		Detail: fmt.Sprintf("%q loaded from %s: %d rule(s), %d warning(s)", p.Name, cfg.Policy.Path, len(p.Rules), len(warnings)),
	}}
	if cfg.Policy.DryRun {
		results = append(results, checkResult{
			Check:  "policy",
			Status: statusWarn,
			Detail: "policy.dry_run is true: decisions are computed and logged but enforcement disabled",
			Hint:   "set policy.dry_run: false once you have validated the dry-run decisions in the audit log",
		})
	}
	return p, results
}

// --- 3. dirs/ownership -----------------------------------------------

// lookupOwnerUID returns the numeric owner UID of the given
// os.FileInfo, if the platform's os.FileInfo.Sys() exposes one (true on
// every unix attachra targets - ADR-001 only ships linux/amd64+arm64,
// and this also works when running the test suite on darwin). It is a
// package-level var so tests can simulate root ownership (uid 0) - the
// DynamicUser trap this function's caller detects - without needing
// actual root privileges to chown a file.
var lookupOwnerUID = func(info os.FileInfo) (uid uint32, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(st.Uid), true //nolint:unconvert // st.Uid's width differs across GOOS (uint16 vs uint32); the explicit conversion is a no-op on some platforms but required on others.
}

// checkStorageDir implements the storage.fs.base_dir half of check #3.
// It only applies to the fs storage driver; the s3 driver has no local
// directory to check.
func checkStorageDir(cfg config.Config) []checkResult {
	if cfg.Storage.Driver != "fs" {
		return []checkResult{{
			Check:  "storage_dir",
			Status: statusSkip,
			Detail: fmt.Sprintf("storage.driver is %q, not fs: no local base_dir to check", cfg.Storage.Driver),
		}}
	}
	// autoCreated=true: the fs storage driver creates base_dir itself on
	// first Put/start if missing (ATR-309), so a missing directory here
	// is only a WARN, not a FAIL.
	return []checkResult{checkDirWritable("storage_dir", cfg.Storage.FS.BaseDir, true)}
}

// checkDatabaseDir implements the database-directory half of check #3.
// Unlike storage.fs.base_dir, the sqlite driver does NOT currently
// create its containing directory (ATR-310, open as of this writing):
// a missing directory here is a FAIL, since the service will
// crash-loop on SQLITE_CANTOPEN rather than recover on its own.
//
// autoCreated=false is that ATR-310 gap encoded as a doctor check, not
// a permanent design choice: whoever fixes ATR-310 (making the sqlite
// store create its parent directory, mirroring the fs storage driver's
// own ATR-309 fix) MUST flip this to true in the same change, or this
// check will keep reporting a FAIL for a condition the service itself
// no longer treats as fatal. TestCheckDatabaseDir_FailsWhileSqliteDoesNotAutoCreate
// (doctor_test.go) exists specifically to make that discrepancy
// impossible to miss - its own doc comment repeats this instruction.
func checkDatabaseDir(cfg config.Config) []checkResult {
	dir := filepath.Dir(cfg.Database.Path)
	return []checkResult{checkDirWritable("database_dir", dir, false)}
}

// checkDirWritable is the shared implementation behind checkStorageDir
// and checkDatabaseDir: it reports whether path exists, is a directory,
// is not the classic DynamicUser root-owned-file trap (a root-owned
// path a non-root systemd DynamicUser service can never write to,
// docs/deploy/grommunio-debian.md "Troubleshooting" SQLITE_CANTOPEN/
// fs base_dir entries), and is actually writable by the account running
// `attachra doctor` (a non-destructive create+remove probe file).
func checkDirWritable(check, path string, autoCreated bool) checkResult {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if autoCreated {
				return checkResult{Check: check, Status: statusWarn, Detail: fmt.Sprintf("%s does not exist yet; attachra creates it automatically on start", path)}
			}
			return checkResult{
				Check:  check,
				Status: statusFail,
				Detail: fmt.Sprintf("%s does not exist and will NOT be created automatically", path),
				Hint:   fmt.Sprintf("mkdir -p %s (see docs/deploy/grommunio-debian.md Troubleshooting)", path),
			}
		}
		return checkResult{Check: check, Status: statusFail, Detail: fmt.Sprintf("cannot stat %s: %v", path, err)}
	}
	if !info.IsDir() {
		return checkResult{Check: check, Status: statusFail, Detail: fmt.Sprintf("%s exists but is not a directory", path)}
	}

	if uid, ok := lookupOwnerUID(info); ok && uid == 0 {
		return checkResult{
			Check:  check,
			Status: statusWarn,
			Detail: fmt.Sprintf("%s is owned by root (uid 0)", path),
			Hint:   fmt.Sprintf("a DynamicUser-hardened systemd unit runs as a non-root UID and can never write to a root-owned path - it was likely created by a command run as root before the service's first start; chown %q to the service's dynamic UID/GID (see docs/deploy/grommunio-debian.md Troubleshooting) or delete it and let the service recreate it", path),
		}
	}

	probe := filepath.Join(path, fmt.Sprintf(".attachra-doctor-probe-%d", os.Getpid()))
	f, werr := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600) //nolint:gosec // probe is built from the operator's own config (storage.fs.base_dir / database.path), not untrusted input; O_EXCL keeps it from ever clobbering an existing file
	if werr != nil {
		return checkResult{
			Check:  check,
			Status: statusWarn,
			Detail: fmt.Sprintf("%s exists but does not appear writable: %v", path, werr),
			Hint:   "check ownership/permissions for the account that runs attachra",
		}
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return checkResult{Check: check, Status: statusPass, Detail: fmt.Sprintf("%s exists and is writable", path)}
}

// --- 4. db ---------------------------------------------------------------

// checkDatabase implements check #4: does the SQLite database file open
// and respond to a trivial query. It deliberately does NOT use
// internal/core/store/sqlite.Open (which creates the file and runs
// migrations if missing) - that would recreate the exact DynamicUser
// root-owned-file trap this command exists to detect, if `attachra
// doctor` itself happens to be run as root against a not-yet-started
// installation. Instead it opens the file read-only (mode=ro in the
// DSN), which fails with SQLITE_CANTOPEN rather than creating anything
// if the file is missing or unreadable.
func checkDatabase(cfg config.Config) []checkResult {
	dir := filepath.Dir(cfg.Database.Path)
	if _, err := os.Stat(dir); err != nil {
		return []checkResult{{Check: "database", Status: statusSkip, Detail: "database directory is missing or inaccessible, see the database_dir check"}}
	}

	info, err := os.Stat(cfg.Database.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return []checkResult{{Check: "database", Status: statusWarn, Detail: fmt.Sprintf("%s does not exist yet: it will be created on first start", cfg.Database.Path)}}
		}
		return []checkResult{{Check: "database", Status: statusFail, Detail: fmt.Sprintf("cannot stat %s: %v", cfg.Database.Path, err)}}
	}
	if info.IsDir() {
		return []checkResult{{Check: "database", Status: statusFail, Detail: fmt.Sprintf("%s is a directory, expected a file", cfg.Database.Path)}}
	}

	if err := probeSQLiteReadOnly(cfg.Database.Path); err != nil {
		return []checkResult{{
			Check:  "database",
			Status: statusFail,
			Detail: fmt.Sprintf("cannot open %s: %v", cfg.Database.Path, err),
			Hint:   fmt.Sprintf(`likely SQLITE_CANTOPEN from a root-owned file - chown "$(stat -c '%%u:%%g' %s)" %s* (see docs/deploy/grommunio-debian.md Troubleshooting)`, dir, cfg.Database.Path),
		}}
	}
	return []checkResult{{Check: "database", Status: statusPass, Detail: fmt.Sprintf("%s opens read-only and responds to a query", cfg.Database.Path)}}
}

// probeSQLiteReadOnly opens the sqlite file at path with mode=ro (never
// creates or writes anything) and runs a trivial SELECT.
func probeSQLiteReadOnly(path string) error {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(2000)", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), doctorNetTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return err
	}
	var one int
	return db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

// --- doctorDeps: injectable I/O for checks 5-9 ----------------------------

// doctorDeps bundles every network/process dependency checks #5-#9 use,
// so tests can substitute deterministic fakes instead of touching a
// real network, DNS resolver, or postconf binary (per ATR-321's
// acceptance criteria: "no real network is used in tests").
type doctorDeps struct {
	dial           func(ctx context.Context, network, address string) (net.Conn, error)
	listen         func(network, address string) (net.Listener, error)
	httpGet        func(ctx context.Context, url string) (status int, body []byte, err error)
	lookupTXT      func(ctx context.Context, name string) ([]string, error)
	lookupHost     func(ctx context.Context, host string) ([]string, error)
	interfaceAddrs func() ([]net.Addr, error)
	lookPath       func(file string) (string, error)
	runCommand     func(name string, args ...string) ([]byte, error)
}

func defaultDoctorDeps() doctorDeps {
	var dialer net.Dialer
	client := &http.Client{}
	return doctorDeps{
		dial:   dialer.DialContext,
		listen: net.Listen,
		httpGet: func(ctx context.Context, target string) (int, []byte, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				return 0, nil, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return 0, nil, err
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
			if err != nil {
				return resp.StatusCode, nil, err
			}
			return resp.StatusCode, body, nil
		},
		lookupTXT:      net.DefaultResolver.LookupTXT,
		lookupHost:     net.DefaultResolver.LookupHost,
		interfaceAddrs: net.InterfaceAddrs,
		lookPath:       exec.LookPath,
		runCommand: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput() //nolint:gosec // name/args are fixed literals ("postconf", known flag names), never attacker- or config-controlled
		},
	}
}

// --- shared listen-address helpers ----------------------------------------

// splitListenAddr mirrors internal/adapters/milter's own (unexported)
// parseListenAddr: it splits a Postfix-style milter listen address into
// a Go net.Listen network/address pair. It is duplicated here (rather
// than exported from that package) because it is ~5 lines and doctor.go
// deliberately avoids importing internal/adapters/milter at all, to
// keep this diagnostic command decoupled from that adapter's internals.
func splitListenAddr(addr string) (network, address string) {
	switch {
	case strings.HasPrefix(addr, "inet:"):
		return "tcp", strings.TrimPrefix(addr, "inet:")
	case strings.HasPrefix(addr, "unix:"):
		return "unix", strings.TrimPrefix(addr, "unix:")
	default:
		return "tcp", addr
	}
}

// portStatusResult is the shared "not responding, is the port free or
// taken" probe used by checks #5 and #6 once the higher-level
// (healthz/milter-connect) probe has already failed: it tells an
// operator whether attachra simply isn't running (WARN, port free) or
// something else is squatting on its configured port (FAIL, port
// occupied).
func portStatusResult(check, network, address string, deps doctorDeps) checkResult {
	ln, err := deps.listen(network, address)
	if err == nil {
		_ = ln.Close()
		return checkResult{
			Check:  check,
			Status: statusWarn,
			Detail: fmt.Sprintf("attachra is not running: %s is free", address),
			Hint:   "start the service: systemctl start attachra (or run attachra directly)",
		}
	}
	return checkResult{
		Check:  check,
		Status: statusFail,
		Detail: fmt.Sprintf("attachra is not running and %s is occupied by another process: %v", address, err),
		Hint:   fmt.Sprintf("identify the process, e.g. ss -ltnp | grep %q, then free the port or reconfigure attachra to use a different one", address),
	}
}

// --- 5. service ports (http) ----------------------------------------------

// checkHTTPService implements check #5: if /healthz responds, attachra
// is up (and /readyz is checked too, distinguishing "up" from "up but
// not ready"); otherwise, is the configured port free or occupied.
func checkHTTPService(ctx context.Context, cfg config.Config, deps doctorDeps) []checkResult {
	addr := cfg.HTTP.Listen

	hctx, hcancel := context.WithTimeout(ctx, doctorNetTimeout)
	status, _, err := deps.httpGet(hctx, "http://"+addr+"/healthz")
	hcancel()

	if err != nil || status != http.StatusOK {
		return []checkResult{portStatusResult("http_port", "tcp", addr, deps)}
	}

	results := []checkResult{{Check: "http_port", Status: statusPass, Detail: fmt.Sprintf("attachra is running and healthy at http://%s (healthz 200)", addr)}}

	rctx, rcancel := context.WithTimeout(ctx, doctorNetTimeout)
	rstatus, rbody, rerr := deps.httpGet(rctx, "http://"+addr+"/readyz")
	rcancel()

	switch {
	case rerr != nil:
		results = append(results, checkResult{Check: "readyz", Status: statusWarn, Detail: fmt.Sprintf("readyz request failed: %v", rerr)})
	case rstatus == http.StatusOK:
		results = append(results, checkResult{Check: "readyz", Status: statusPass, Detail: "all readiness checks passing"})
	default:
		results = append(results, checkResult{
			Check:  "readyz",
			Status: statusWarn,
			Detail: fmt.Sprintf("not ready (HTTP %d): %s", rstatus, strings.TrimSpace(string(rbody))),
			Hint:   "check journalctl -u attachra for the failing dependency named in the response body",
		})
	}
	return results
}

// --- 6. milter port --------------------------------------------------------

// checkMilterPort implements check #6: for a unix socket, whether the
// socket file exists (os.Stat only, per ATR-321's design - dialing an
// abandoned socket file has its own confusing failure modes); for a TCP
// address, an actual connect probe, falling back to the same
// free-vs-occupied probe check #5 uses.
func checkMilterPort(ctx context.Context, cfg config.Config, deps doctorDeps) []checkResult {
	network, address := splitListenAddr(cfg.Milter.Listen)

	if network == "unix" {
		info, err := os.Stat(address)
		switch {
		case err == nil && info.Mode()&os.ModeSocket != 0:
			return []checkResult{{Check: "milter_port", Status: statusPass, Detail: fmt.Sprintf("unix socket %s exists", address)}}
		case err == nil:
			return []checkResult{{Check: "milter_port", Status: statusFail, Detail: fmt.Sprintf("%s exists but is not a socket", address)}}
		case os.IsNotExist(err):
			return []checkResult{{Check: "milter_port", Status: statusWarn, Detail: fmt.Sprintf("unix socket %s does not exist: attachra is not running", address), Hint: "systemctl start attachra"}}
		default:
			return []checkResult{{Check: "milter_port", Status: statusFail, Detail: fmt.Sprintf("cannot stat %s: %v", address, err)}}
		}
	}

	cctx, cancel := context.WithTimeout(ctx, doctorNetTimeout)
	conn, err := deps.dial(cctx, network, address)
	cancel()
	if err == nil {
		_ = conn.Close()
		return []checkResult{{Check: "milter_port", Status: statusPass, Detail: fmt.Sprintf("milter listener accepting connections at %s", address)}}
	}
	return []checkResult{portStatusResult("milter_port", network, address, deps)}
}

// --- 7. public URL ---------------------------------------------------------

// checkPublicURL implements check #7: DNS resolution of
// public_base_url's hostname, then a GET <public_base_url>/healthz.
// Skipped entirely by --skip-external.
func checkPublicURL(ctx context.Context, cfg config.Config, deps doctorDeps, skipExternal bool) []checkResult {
	if skipExternal {
		return []checkResult{{Check: "public_url", Status: statusSkip, Detail: "--skip-external passed"}}
	}
	if strings.TrimSpace(cfg.PublicBaseURL) == "" {
		return []checkResult{{Check: "public_url", Status: statusSkip, Detail: "public_base_url is not configured"}}
	}

	u, err := url.Parse(cfg.PublicBaseURL)
	if err != nil {
		return []checkResult{{Check: "public_url", Status: statusFail, Detail: fmt.Sprintf("public_base_url does not parse: %v", err)}}
	}
	host := u.Hostname()

	var results []checkResult

	dctx, dcancel := context.WithTimeout(ctx, doctorNetTimeout)
	addrs, derr := deps.lookupHost(dctx, host)
	dcancel()
	if derr != nil || len(addrs) == 0 {
		results = append(results, checkResult{
			Check:  "public_url",
			Status: statusWarn,
			Detail: fmt.Sprintf("DNS lookup for %s failed: %v", host, derr),
			Hint:   "verify a DNS A/AAAA record exists for the hostname in public_base_url",
		})
	} else {
		results = append(results, checkResult{Check: "public_url", Status: statusPass, Detail: fmt.Sprintf("%s resolves to %s", host, strings.Join(addrs, ", "))})
	}

	target := strings.TrimRight(cfg.PublicBaseURL, "/") + "/healthz"
	hctx, hcancel := context.WithTimeout(ctx, doctorNetTimeout)
	status, _, herr := deps.httpGet(hctx, target)
	hcancel()

	switch {
	case herr != nil:
		results = append(results, checkResult{
			Check:  "public_url",
			Status: statusWarn,
			Detail: fmt.Sprintf("GET %s failed: %v", target, herr),
			Hint:   "check that the reverse proxy is running and forwards to http.listen (docs/deploy/grommunio-debian.md step 4)",
		})
	case status == http.StatusOK:
		results = append(results, checkResult{Check: "public_url", Status: statusPass, Detail: fmt.Sprintf("GET %s returned 200", target)})
	default:
		results = append(results, checkResult{
			Check:  "public_url",
			Status: statusWarn,
			Detail: fmt.Sprintf("GET %s returned HTTP %d (expected 200)", target, status),
			Hint:   "check the reverse proxy configuration and firewall rules",
		})
	}
	return results
}

// --- 8. SPF (best-effort) -------------------------------------------------

// checkSPF implements check #8: for every distinct when.sender.domain
// in the loaded policy, look up its SPF TXT record and best-effort
// verify this server's own outbound IP is authorized by it. Any
// ambiguity (no public IP determinable, SPF delegates via include:,
// etc.) is reported as WARN, never FAIL - SPF misconfiguration hurts
// deliverability, it does not mean attachra itself is broken. Skipped
// entirely by --skip-external.
func checkSPF(ctx context.Context, pol *policy.Policy, deps doctorDeps, skipExternal bool) []checkResult {
	if skipExternal {
		return []checkResult{{Check: "spf", Status: statusSkip, Detail: "--skip-external passed"}}
	}

	domains := collectSenderDomains(pol)
	if len(domains) == 0 {
		return []checkResult{{Check: "spf", Status: statusSkip, Detail: "no when.sender.domain entries found in the policy"}}
	}

	publicIPs, natLikely := publicCandidateIPs(deps)

	var results []checkResult
	for _, domain := range domains {
		dctx, cancel := context.WithTimeout(ctx, doctorNetTimeout)
		txts, err := deps.lookupTXT(dctx, domain)
		cancel()
		if err != nil {
			results = append(results, checkResult{
				Check:  "spf",
				Status: statusWarn,
				Detail: fmt.Sprintf("TXT lookup for %s failed: %v", domain, err),
				Hint:   "verify DNS is reachable from this host",
			})
			continue
		}

		record := findSPFRecord(txts)
		if record == "" {
			results = append(results, checkResult{
				Check:  "spf",
				Status: statusWarn,
				Detail: fmt.Sprintf("no SPF TXT record (v=spf1) found for domain %s", domain),
				Hint:   fmt.Sprintf(`add an SPF record for %s, e.g. "v=spf1 ip4:<server-ip> -all"`, domain),
			})
			continue
		}

		if len(publicIPs) == 0 {
			detail := fmt.Sprintf("SPF record found for %s; could not determine this server's public IP to verify inclusion", domain)
			if natLikely {
				detail += " (only private/NAT-range addresses detected on local interfaces)"
			}
			results = append(results, checkResult{
				Check:  "spf",
				Status: statusWarn,
				Detail: detail,
				Hint:   "verify manually that your outbound mail server's public IP is authorized by this SPF record",
			})
			continue
		}

		prefixes, includes, other := parseSPFMechanisms(record)
		switch {
		case ipsMatchAny(publicIPs, prefixes):
			results = append(results, checkResult{Check: "spf", Status: statusPass, Detail: fmt.Sprintf("SPF record for %s authorizes server IP(s) %s", domain, strings.Join(publicIPs, ", "))})
		case len(includes) > 0 || len(other) > 0:
			// The record has no direct ip4:/ip6: match, but does use a
			// mechanism this best-effort check cannot resolve itself:
			// include: (needs recursive SPF lookups), or a/mx/exists:/
			// redirect= (need A/MX/other DNS resolution against the
			// mechanism's own domain). Any of these MAY still authorize
			// the server IP - reporting a bare "not found" WARN here
			// would be misleading, so this branch is deliberately worded
			// as "not automatically verifiable" rather than "missing".
			var via []string
			if len(includes) > 0 {
				via = append(via, "include:"+strings.Join(includes, ", include:"))
			}
			via = append(via, other...)
			results = append(results, checkResult{
				Check:  "spf",
				Status: statusWarn,
				Detail: fmt.Sprintf("SPF record for %s does not directly list server IP(s) %s; it uses mechanisms not automatically verifiable here (%s)", domain, strings.Join(publicIPs, ", "), strings.Join(via, ", ")),
				Hint:   "manually confirm the record (including any include:/a/mx/exists:/redirect= chain) authorizes your server's IP",
			})
		default:
			results = append(results, checkResult{
				Check:  "spf",
				Status: statusWarn,
				Detail: fmt.Sprintf("server IP(s) %s not found in SPF record for %s", strings.Join(publicIPs, ", "), domain),
				Hint:   fmt.Sprintf("add ip4:<ip> or ip6:<ip> for %s to the SPF record", domain),
			})
		}
	}
	return results
}

// collectSenderDomains gathers every distinct when.sender.domain value
// referenced in p's rules (case-insensitively, sorted for determinism).
// A nil p (no policy configured, or it failed to load) returns nil.
func collectSenderDomains(p *policy.Policy) []string {
	if p == nil {
		return nil
	}
	seen := make(map[string]bool)
	var domains []string
	for _, r := range p.Rules {
		if r.When == nil || r.When.Sender == nil {
			continue
		}
		for _, d := range r.When.Sender.Domain {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			domains = append(domains, d)
		}
	}
	sort.Strings(domains)
	return domains
}

// findSPFRecord returns the first TXT record in txts that looks like an
// SPF record (case-insensitive "v=spf1" prefix), or "" if none does.
func findSPFRecord(txts []string) string {
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			return t
		}
	}
	return ""
}

// parseSPFMechanisms extracts every ip4:/ip6: mechanism from an SPF
// record as netip.Prefix values, every include: mechanism's target
// domain, and the distinct set of other mechanisms present that this
// best-effort check cannot resolve itself: a/mx (need A/MX lookups
// against either the record's own domain or an explicit target),
// exists: (needs a DNS existence check), and redirect= (needs a
// recursive SPF lookup, same as include:). checkSPF's caller uses
// len(other) > 0 (alongside len(includes) > 0) to phrase its WARN as
// "not automatically verifiable" rather than a flat "server IP not
// found" - a record using any of these MAY still authorize the
// server's IP, this check just cannot confirm it without recursive DNS
// resolution. Unparsable ip4:/ip6: values are silently skipped rather
// than failing the whole record - a single malformed mechanism should
// not block evaluating the rest.
func parseSPFMechanisms(record string) (prefixes []netip.Prefix, includes []string, other []string) {
	seenOther := make(map[string]bool)
	addOther := func(name string) {
		if !seenOther[name] {
			seenOther[name] = true
			other = append(other, name)
		}
	}

	for _, tok := range strings.Fields(record) {
		tok = stripSPFQualifier(tok)
		lower := strings.ToLower(tok)
		switch {
		case strings.HasPrefix(lower, "ip4:"), strings.HasPrefix(lower, "ip6:"):
			v := tok[strings.Index(tok, ":")+1:]
			if p, err := parseIPOrCIDR(v); err == nil {
				prefixes = append(prefixes, p)
			}
		case strings.HasPrefix(lower, "include:"):
			includes = append(includes, tok[strings.Index(tok, ":")+1:])
		case lower == "a", strings.HasPrefix(lower, "a/"), strings.HasPrefix(lower, "a:"):
			addOther("a")
		case lower == "mx", strings.HasPrefix(lower, "mx/"), strings.HasPrefix(lower, "mx:"):
			addOther("mx")
		case strings.HasPrefix(lower, "exists:"):
			addOther("exists")
		case strings.HasPrefix(lower, "redirect="):
			addOther("redirect")
		}
	}
	return prefixes, includes, other
}

// stripSPFQualifier removes a leading SPF qualifier character from a
// mechanism token, if present: "+" (pass, the default and rarely
// spelled out explicitly), "-" (fail), "~" (softfail), "?" (neutral).
// Modifiers like redirect= never carry a qualifier, so this is a no-op
// for them.
func stripSPFQualifier(tok string) string {
	if tok == "" {
		return tok
	}
	switch tok[0] {
	case '+', '-', '~', '?':
		return tok[1:]
	default:
		return tok
	}
}

// parseIPOrCIDR parses s as either a bare IP address (returned as a
// host-bits-set /32 or /128 prefix) or a CIDR range.
func parseIPOrCIDR(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ipsMatchAny reports whether any of ips is contained in any of
// prefixes.
func ipsMatchAny(ips []string, prefixes []netip.Prefix) bool {
	for _, ipStr := range ips {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		for _, p := range prefixes {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// publicCandidateIPs returns this host's non-loopback, non-link-local
// interface addresses that are NOT in a private/NAT range (RFC 1918/
// RFC 4193 etc., via net.IP.IsPrivate). natLikely is true when at least
// one non-loopback address exists but all of them are private (the
// "server behind NAT, can't verify SPF automatically" case check #8
// describes) - it is only meaningful when the returned slice is empty.
func publicCandidateIPs(deps doctorDeps) (public []string, natLikely bool) {
	addrs, err := deps.interfaceAddrs()
	if err != nil {
		return nil, false
	}
	var sawAny bool
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		sawAny = true
		if ip.IsPrivate() {
			continue
		}
		public = append(public, ip.String())
	}
	return public, sawAny && len(public) == 0
}

// --- 9. postfix (best-effort) ---------------------------------------------

// checkPostfix implements check #9: if `postconf` is on PATH, confirm
// milter.listen appears in smtpd_milters or non_smtpd_milters.
func checkPostfix(cfg config.Config, deps doctorDeps) []checkResult {
	if _, err := deps.lookPath("postconf"); err != nil {
		return []checkResult{{Check: "postfix", Status: statusSkip, Detail: "postconf not found in PATH"}}
	}

	out, err := deps.runCommand("postconf", "-h", "smtpd_milters", "non_smtpd_milters")
	if err != nil {
		return []checkResult{{
			Check:  "postfix",
			Status: statusWarn,
			Detail: fmt.Sprintf("postconf failed: %v", err),
			Hint:   "run `postconf -h smtpd_milters non_smtpd_milters` manually to see the underlying error",
		}}
	}

	text := string(out)
	if strings.Contains(text, cfg.Milter.Listen) {
		return []checkResult{{Check: "postfix", Status: statusPass, Detail: fmt.Sprintf("milter %q is present in postfix smtpd_milters/non_smtpd_milters", cfg.Milter.Listen)}}
	}
	return []checkResult{{
		Check:  "postfix",
		Status: statusWarn,
		Detail: fmt.Sprintf("milter %q was not found in postfix smtpd_milters/non_smtpd_milters (got: %s)", cfg.Milter.Listen, strings.TrimSpace(text)),
		Hint:   fmt.Sprintf("postconf -e 'smtpd_milters = %s' (see docs/deploy/grommunio-debian.md step 5)", cfg.Milter.Listen),
	}}
}
