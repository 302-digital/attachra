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
func loadFileConfig(path string) (fileConfig, error) {
	if path == "" {
		return fileConfig{}, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path, not untrusted input
	if err != nil {
		if os.IsNotExist(err) {
			return fileConfig{}, nil
		}
		return fileConfig{}, fmt.Errorf("read config file %q: %w", path, err)
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return fileConfig{}, fmt.Errorf("parse config file %q: %w", path, err)
	}
	return fc, nil
}

// readTokenFile reads and trims a file expected to contain nothing but
// a bearer token secret (optionally with a trailing newline).
func readTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied token file path, not untrusted input
	if err != nil {
		return "", fmt.Errorf("read token file %q: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file %q is empty", path)
	}
	return token, nil
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
	fc, err := loadFileConfig(flags.configPath)
	if err != nil {
		return connectConfig{}, err
	}

	cfg := connectConfig{Timeout: flags.timeout}

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
		token, err := readTokenFile(flags.tokenFile)
		if err != nil {
			return connectConfig{}, err
		}
		cfg.Token = token
	case getenv("ATTACHRACTL_TOKEN") != "":
		cfg.Token = getenv("ATTACHRACTL_TOKEN")
	case fc.TokenFile != "":
		token, err := readTokenFile(fc.TokenFile)
		if err != nil {
			return connectConfig{}, err
		}
		cfg.Token = token
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
