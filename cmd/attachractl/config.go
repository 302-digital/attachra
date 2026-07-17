package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// connectFlags holds the raw, unresolved values of every persistent
// connection flag (root.go). resolveConnectConfig turns these, plus the
// environment and the config file, into a single connectConfig.
type connectFlags struct {
	configPath string
	url        string
	tokenFile  string
	insecure   bool
	jsonOut    bool
	timeout    time.Duration
}

// fileConfig is the YAML shape of the on-disk config file
// (~/.config/attachractl/config.yaml by default). Every field is
// optional: a caller relying entirely on flags/env needs no file at
// all, and a missing file is not an error (see loadFileConfig).
type fileConfig struct {
	URL string `yaml:"url"`
	// Token is the raw bearer secret, inline in the file. Prefer
	// TokenFile (or the ATTACHRACTL_TOKEN environment variable) so the
	// secret lives in one file the operator controls the permissions
	// of independently of this config file, but a plain inline Token is
	// still accepted for simple single-file setups — the CLI never
	// echoes it back regardless of which of the two is used.
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token_file"`
	Insecure  bool   `yaml:"insecure"`
}

// connectConfig is the fully resolved connection configuration a
// *Client is built from.
type connectConfig struct {
	URL      string
	Token    string
	Insecure bool
	Timeout  time.Duration
	// Warnings holds non-fatal advisories collected while resolving the
	// config (currently: an on-disk file carrying the bearer token is
	// readable/writable by group or other). root.go prints each of
	// these to stderr once the config has fully resolved, the same way
	// it already does for --insecure.
	Warnings []string
}

// unsafeSecretFilePermBits mirrors the bits ssh(1) warns/refuses on for
// a private key file: group or world read/write/execute. A bearer
// token — whether the dedicated --token-file or an inline token: in
// the YAML config file — is exactly the same kind of secret, so the
// same permission hygiene applies (SR-130-2).
const unsafeSecretFilePermBits = 0o077

// secretFilePermWarning returns a human-readable warning if info's
// permission bits grant group or other access, or "" if the file is
// already owner-only. info may be nil (the Stat that produced it
// failed) in which case there is nothing to warn about here — the
// read that follows will surface its own, clearer error.
func secretFilePermWarning(path string, info os.FileInfo) string {
	if info == nil {
		return ""
	}
	if info.Mode().Perm()&unsafeSecretFilePermBits == 0 {
		return ""
	}
	return fmt.Sprintf("%q holds a bearer token secret and is readable or writable by group/other (mode %s); run \"chmod 0600 %s\"", path, info.Mode().Perm(), path)
}

// defaultConfigPath returns ~/.config/attachractl/config.yaml, or ""
// if the current user's home directory cannot be determined (in which
// case resolveConnectConfig simply finds no file and falls back to
// flags/env).
func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "attachractl", "config.yaml")
}

// loadFileConfig reads and parses path as a fileConfig. A missing file
// is not an error — most invocations that rely solely on flags/env
// have no config file at all, so this must not force one into
// existence — but a present-and-unreadable-or-malformed file is,
// since silently ignoring a broken config a user believes is in
// effect would be confusing.
//
// The returned warning is non-empty only when the file carries an
// inline "token:" (SR-130-2) and its permissions are group/other
// accessible; a file that only references a separate token_file is not
// itself a secret, so its own permissions are not checked here (that
// file's permissions are checked by readTokenFile instead).
func loadFileConfig(path string) (fc fileConfig, warning string, err error) {
	if path == "" {
		return fileConfig{}, "", nil
	}
	info, _ := os.Stat(path)
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path, not untrusted input
	if err != nil {
		if os.IsNotExist(err) {
			return fileConfig{}, "", nil
		}
		return fileConfig{}, "", fmt.Errorf("read config file %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return fileConfig{}, "", fmt.Errorf("parse config file %q: %w", path, err)
	}
	if fc.Token != "" {
		warning = secretFilePermWarning(path, info)
	}
	return fc, warning, nil
}

// readTokenFile reads and trims a file expected to contain nothing but
// a bearer token secret (optionally with a trailing newline). The
// returned warning is non-empty when the file's permissions grant
// group or other access — this CLI does not refuse to use such a file
// (an operator may have deliberate reasons, e.g. a read-only mount
// inside a container image with its own access controls), but staying
// silent about a genuine misconfiguration would defeat the whole point
// of keeping the secret out of a flag/argv (SR-130-2, doc.go).
func readTokenFile(path string) (token, warning string, err error) {
	info, _ := os.Stat(path)
	warning = secretFilePermWarning(path, info)
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied token file path, not untrusted input
	if err != nil {
		return "", "", fmt.Errorf("read token file %q: %w", path, err)
	}
	token = strings.TrimSpace(string(data))
	if token == "" {
		return "", "", fmt.Errorf("token file %q is empty", path)
	}
	return token, warning, nil
}

// resolveConnectConfig resolves the endpoint URL, bearer token and TLS
// verification setting with the precedence documented in doc.go:
// flags, then environment variables, then the config file. getenv is
// injected (rather than calling os.Getenv directly) so unit tests can
// exercise every precedence combination without mutating real process
// environment.
//
// The token is deliberately never accepted as a plain flag value — only
// --token-file (a path), the ATTACHRACTL_TOKEN environment variable, or
// the config file's token/token_file field — so it never appears in
// argv (visible to other local users via /proc/<pid>/cmdline or ps).
func resolveConnectConfig(flags connectFlags, getenv func(string) string) (connectConfig, error) {
	fc, fcWarning, err := loadFileConfig(flags.configPath)
	if err != nil {
		return connectConfig{}, err
	}

	cfg := connectConfig{Timeout: flags.timeout}
	if fcWarning != "" {
		cfg.Warnings = append(cfg.Warnings, fcWarning)
	}

	switch {
	case flags.url != "":
		cfg.URL = flags.url
	case getenv("ATTACHRACTL_URL") != "":
		cfg.URL = getenv("ATTACHRACTL_URL")
	default:
		cfg.URL = fc.URL
	}
	cfg.URL = strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if cfg.URL == "" {
		return connectConfig{}, fmt.Errorf("no API URL configured (use --url, ATTACHRACTL_URL, or \"url\" in %s)", configPathForMessage(flags.configPath))
	}

	switch {
	case flags.tokenFile != "":
		token, warning, err := readTokenFile(flags.tokenFile)
		if err != nil {
			return connectConfig{}, err
		}
		cfg.Token = token
		if warning != "" {
			cfg.Warnings = append(cfg.Warnings, warning)
		}
	case getenv("ATTACHRACTL_TOKEN") != "":
		cfg.Token = getenv("ATTACHRACTL_TOKEN")
	case fc.TokenFile != "":
		token, warning, err := readTokenFile(fc.TokenFile)
		if err != nil {
			return connectConfig{}, err
		}
		cfg.Token = token
		if warning != "" {
			cfg.Warnings = append(cfg.Warnings, warning)
		}
	case fc.Token != "":
		cfg.Token = fc.Token
	}
	if cfg.Token == "" {
		return connectConfig{}, fmt.Errorf("no API token configured (use --token-file, ATTACHRACTL_TOKEN, or \"token\"/\"token_file\" in %s)", configPathForMessage(flags.configPath))
	}

	cfg.Insecure = flags.insecure || fc.Insecure

	return cfg, nil
}

// configPathForMessage renders an empty configPath as a description
// suitable for an error message (rather than an empty string, which
// would render the message as "... in " with nothing after it).
func configPathForMessage(path string) string {
	if path == "" {
		return "the config file"
	}
	return path
}
