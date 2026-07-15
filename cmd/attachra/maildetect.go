package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ATR-337: `attachra setup` runs on a host that may already have a mail
// stack installed (a plain Postfix box, or a packaged distribution like
// grommunio, mailcow, or iRedMail that wraps its own Postfix instance).
// detectMailEnv gives the wizard a best-effort, advisory-only guess at
// which one it is running alongside, so it can pick a listen-address
// default that does not collide with that stack's own admin UI and
// print next-step guidance (milter chain ordering, which doc to point
// at) tailored to it. Detection never blocks or fails the wizard: any
// probe that cannot run (missing binary, unreadable directory, no
// docker daemon, ...) is simply a marker that did not fire, and an
// unrecognized host falls through to mailEnvUnknown — today's
// unmodified behavior.

// mailEnv identifies the local mail stack detectMailEnv believes it is
// running alongside.
type mailEnv int

const (
	mailEnvUnknown mailEnv = iota
	mailEnvPostfix
	mailEnvGrommunio
	mailEnvMailcow
	mailEnvIRedMail
)

func (e mailEnv) String() string {
	switch e {
	case mailEnvPostfix:
		return "postfix"
	case mailEnvGrommunio:
		return "grommunio"
	case mailEnvMailcow:
		return "mailcow"
	case mailEnvIRedMail:
		return "iredmail"
	default:
		return "unknown"
	}
}

// mailEnvDetection is detectMailEnv's result. Env is the single best
// guess: when markers for more than one stack fire (grommunio and
// iRedMail both wrap a local Postfix, so their own markers imply
// mailEnvPostfix would also match), the most specific stack wins over
// the generic Postfix fallback — see detectMailEnv's final switch.
// Markers lists every individual signal that fired, for diagnostics;
// `attachra setup` does not currently print these itself, but they cost
// nothing to keep and let tests assert on *why* a guess was made, not
// just the guess.
type mailEnvDetection struct {
	Env     mailEnv
	Markers []string
}

// mailEnvDeps bundles every OS-probing dependency detectMailEnv uses,
// so table tests can supply deterministic fakes instead of touching the
// real filesystem, PATH, or a docker daemon that will plainly not exist
// in CI — mirrors doctor.go's doctorDeps, which solves the exact same
// problem for `attachra doctor`'s checks.
type mailEnvDeps struct {
	// lookPath reports whether name is on PATH (exec.LookPath's own
	// signature).
	lookPath func(name string) (string, error)
	// unitExists reports whether a systemd unit file matching pattern
	// (a literal name like "postfix.service", or a glob like
	// "gromox-*.service") exists in any well-known systemd unit
	// directory.
	unitExists func(pattern string) bool
	// pathExists reports whether path exists on disk (file or
	// directory; detectMailEnv never needs to tell the two apart).
	pathExists func(path string) bool
	// dockerContainerNames lists docker container names (running and
	// stopped). A non-nil error (docker not installed, daemon not
	// reachable, permission denied, ...) is treated exactly like an
	// empty result — detectMailEnv never fails because of it.
	dockerContainerNames func() ([]string, error)
}

// systemdUnitDirs are the well-known locations a systemd unit file can
// live in, checked in this order. /run/systemd/system (transient units)
// is deliberately omitted: every marker unit detectMailEnv looks for is
// installed by a package, never generated at runtime.
var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// defaultMailEnvDeps wires mailEnvDeps to the real OS: exec.LookPath, a
// glob over systemdUnitDirs, os.Stat, and `docker ps` (its own error is
// swallowed here, never surfaced to detectMailEnv).
func defaultMailEnvDeps() mailEnvDeps {
	return mailEnvDeps{
		lookPath: exec.LookPath,
		unitExists: func(pattern string) bool {
			for _, dir := range systemdUnitDirs {
				matches, err := filepath.Glob(filepath.Join(dir, pattern))
				if err == nil && len(matches) > 0 {
					return true
				}
			}
			return false
		},
		pathExists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		dockerContainerNames: listDockerContainerNames,
	}
}

// listDockerContainerNames runs `docker ps -a --format {{.Names}}` with
// a short timeout, best-effort: docker not being installed, the daemon
// being unreachable, or the current user lacking permission are all
// reported as a plain error and never panic or hang the wizard.
func listDockerContainerNames() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--format", "{{.Names}}").Output() //nolint:gosec // fixed literal command/args, never attacker- or config-controlled
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}

	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

// detectMailEnv probes deps for known local mail stacks. It never
// returns an error: any single probe failing just means that marker
// does not fire, and a host with no recognized stack yields
// mailEnvUnknown with an empty Markers list — the wizard's ordinary,
// unmodified behavior.
func detectMailEnv(deps mailEnvDeps) mailEnvDetection {
	var markers []string
	add := func(format string, args ...any) {
		markers = append(markers, fmt.Sprintf(format, args...))
	}

	postfixFound := false
	if _, err := deps.lookPath("postconf"); err == nil {
		postfixFound = true
		add("postconf found in PATH")
	}
	if deps.unitExists("postfix.service") {
		postfixFound = true
		add("systemd unit postfix.service found")
	}

	// grommunio ships its admin UI (grommunio-admin-api) and its
	// groupware backend (gromox-*) as separate systemd units/packages
	// on top of a stock Postfix install (docs/deploy/grommunio-debian.md).
	grommunioFound := false
	if deps.unitExists("grommunio-admin-api.service") {
		grommunioFound = true
		add("systemd unit grommunio-admin-api.service found")
	}
	if deps.unitExists("gromox-*.service") {
		grommunioFound = true
		add("systemd unit(s) matching gromox-*.service found")
	}
	if deps.pathExists("/etc/grommunio-common") {
		grommunioFound = true
		add("/etc/grommunio-common found")
	}
	if deps.pathExists("/usr/share/grommunio-admin-web") {
		grommunioFound = true
		add("/usr/share/grommunio-admin-web found")
	}

	// mailcow-dockerized is a fully containerized stack: its own
	// Postfix instance runs inside a container (postfix-mailcow), not
	// on the host, so its markers are independent of postfixFound.
	// docker may simply not be installed on this host — dockerContainerNames'
	// error is ignored, not treated as "no mailcow".
	mailcowFound := false
	if deps.pathExists("/opt/mailcow-dockerized") {
		mailcowFound = true
		add("/opt/mailcow-dockerized found")
	}
	if names, err := deps.dockerContainerNames(); err == nil {
		for _, n := range names {
			if strings.Contains(strings.ToLower(n), "mailcow") {
				mailcowFound = true
				add("docker container %q found", n)
				break
			}
		}
	}

	// /etc/iredmail-release is iRedMail's own long-standing,
	// community-documented marker file (used by their own support
	// forum/iRedAdmin to identify an installation) — but it is not
	// guaranteed present on every install (some installs report it
	// missing), so this is one signal among several a future change
	// could add, not a claim that this covers every iRedMail install.
	iredmailFound := false
	if deps.pathExists("/etc/iredmail-release") {
		iredmailFound = true
		add("/etc/iredmail-release found")
	}

	// Most specific stack wins: grommunio, mailcow and iRedMail all
	// imply (or wrap their own) Postfix, so reporting the more specific
	// stack is more useful to the wizard than falling back to the
	// generic mailEnvPostfix guess.
	switch {
	case grommunioFound:
		return mailEnvDetection{Env: mailEnvGrommunio, Markers: markers}
	case iredmailFound:
		return mailEnvDetection{Env: mailEnvIRedMail, Markers: markers}
	case mailcowFound:
		return mailEnvDetection{Env: mailEnvMailcow, Markers: markers}
	case postfixFound:
		return mailEnvDetection{Env: mailEnvPostfix, Markers: markers}
	default:
		return mailEnvDetection{Env: mailEnvUnknown, Markers: markers}
	}
}

// httpListenDefaultFor returns the wizard's HTTP-listen default for the
// detected environment: grommunio-admin occupies 127.0.0.1:8080 on a
// stock grommunio host (docs/deploy/grommunio-debian.md), so Attachra's
// own default must avoid it. Every other environment (including
// mailEnvUnknown, i.e. a plain/unrecognized host) keeps the wizard's
// existing default unchanged — no regression on a system detectMailEnv
// does not recognize.
func httpListenDefaultFor(env mailEnv) string {
	const listen = "127.0.0.1:18080"
	switch env {
	case mailEnvGrommunio:
		return listen
	default:
		return listen
	}
}

// existingMilters best-effort reads Postfix's currently configured
// smtpd_milters/non_smtpd_milters via `postconf`, so
// printSetupNextSteps can show the operator's real, existing milter(s)
// ahead of Attachra's own in its worked example instead of a bare
// "<existing>" placeholder (ATR-337: preserve whatever is already
// wired, e.g. rspamd, as the first entry). ok is false whenever this
// cannot be determined (postconf missing, command failed, both
// parameters came back empty) — the caller falls back to the
// placeholder text unchanged.
//
// This is a package-level function value (not a mailEnvDeps field, and
// not threaded through detectMailEnv) so it can be swapped in tests the
// same way doctor.go's lookupOwnerUID is: printSetupNextSteps' own
// signature stays free of a dependency-injection struct for what is a
// single, low-stakes, advisory read.
var existingMilters = func() (smtpdMilters, nonSMTPdMilters string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "postconf", "-h", "smtpd_milters", "non_smtpd_milters").Output() //nolint:gosec // fixed literal command/args, never attacker- or config-controlled
	if err != nil {
		return "", "", false
	}

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 2 {
		return "", "", false
	}
	smtpdMilters = strings.TrimSpace(lines[0])
	nonSMTPdMilters = strings.TrimSpace(lines[1])
	if smtpdMilters == "" && nonSMTPdMilters == "" {
		return "", "", false
	}
	return smtpdMilters, nonSMTPdMilters, true
}
