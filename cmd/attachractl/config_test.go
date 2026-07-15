package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeEnv returns a getenv function backed by a plain map, so
// precedence tests never touch real process environment variables.
func fakeEnv(vars map[string]string) func(string) string {
	return func(key string) string {
		return vars[key]
	}
}

func TestResolveConnectConfig_Precedence(t *testing.T) {
	dir := t.TempDir()
	tokenFilePath := filepath.Join(dir, "token-from-flag.txt")
	if err := os.WriteFile(tokenFilePath, []byte("flag-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	fileTokenFilePath := filepath.Join(dir, "token-from-config.txt")
	if err := os.WriteFile(fileTokenFilePath, []byte("file-referenced-token"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	configPath := filepath.Join(dir, "config.yaml")

	tests := []struct {
		name       string
		configYAML string
		flags      connectFlags
		env        map[string]string
		wantURL    string
		wantToken  string
		wantInsec  bool
		wantErr    bool
	}{
		{
			name:      "flag wins over env and file",
			flags:     connectFlags{configPath: configPath, url: "https://flag.example.com", tokenFile: tokenFilePath},
			env:       map[string]string{"ATTACHRACTL_URL": "https://env.example.com", "ATTACHRACTL_TOKEN": "env-token"},
			wantURL:   "https://flag.example.com",
			wantToken: "flag-token",
		},
		{
			name:       "env wins over file",
			configYAML: "url: https://file.example.com\ntoken: file-token\n",
			flags:      connectFlags{configPath: configPath},
			env:        map[string]string{"ATTACHRACTL_URL": "https://env.example.com", "ATTACHRACTL_TOKEN": "env-token"},
			wantURL:    "https://env.example.com",
			wantToken:  "env-token",
		},
		{
			name:       "file token_file is read and trimmed",
			configYAML: "url: https://file.example.com\ntoken_file: " + fileTokenFilePath + "\n",
			flags:      connectFlags{configPath: configPath},
			env:        map[string]string{},
			wantURL:    "https://file.example.com",
			wantToken:  "file-referenced-token",
		},
		{
			name:       "file inline token used as last resort",
			configYAML: "url: https://file.example.com\ntoken: file-token\n",
			flags:      connectFlags{configPath: configPath},
			env:        map[string]string{},
			wantURL:    "https://file.example.com",
			wantToken:  "file-token",
		},
		{
			name:      "trailing slash on URL is trimmed",
			flags:     connectFlags{configPath: configPath, url: "https://flag.example.com/", tokenFile: tokenFilePath},
			env:       map[string]string{},
			wantURL:   "https://flag.example.com",
			wantToken: "flag-token",
		},
		{
			name:       "insecure flag or file both set it",
			configYAML: "url: https://file.example.com\ntoken: file-token\ninsecure: true\n",
			flags:      connectFlags{configPath: configPath},
			env:        map[string]string{},
			wantURL:    "https://file.example.com",
			wantToken:  "file-token",
			wantInsec:  true,
		},
		{
			name:    "missing URL is an error",
			flags:   connectFlags{configPath: configPath, tokenFile: tokenFilePath},
			env:     map[string]string{},
			wantErr: true,
		},
		{
			name:    "missing token is an error",
			flags:   connectFlags{configPath: configPath, url: "https://flag.example.com"},
			env:     map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.configYAML != "" {
				if err := os.WriteFile(configPath, []byte(tt.configYAML), 0o600); err != nil {
					t.Fatalf("write config file: %v", err)
				}
			} else {
				_ = os.Remove(configPath)
			}

			cfg, err := resolveConnectConfig(tt.flags, fakeEnv(tt.env))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveConnectConfig() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveConnectConfig() error = %v, want nil", err)
			}
			if cfg.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", cfg.URL, tt.wantURL)
			}
			if cfg.Token != tt.wantToken {
				t.Errorf("Token = %q, want %q", cfg.Token, tt.wantToken)
			}
			if cfg.Insecure != tt.wantInsec {
				t.Errorf("Insecure = %v, want %v", cfg.Insecure, tt.wantInsec)
			}
		})
	}
}

func TestResolveConnectConfig_MissingConfigFileIsNotAnError(t *testing.T) {
	flags := connectFlags{
		configPath: filepath.Join(t.TempDir(), "does-not-exist.yaml"),
		url:        "https://example.com",
	}
	env := fakeEnv(map[string]string{"ATTACHRACTL_TOKEN": "some-token"})

	cfg, err := resolveConnectConfig(flags, env)
	if err != nil {
		t.Fatalf("resolveConnectConfig() error = %v, want nil", err)
	}
	if cfg.URL != "https://example.com" || cfg.Token != "some-token" {
		t.Errorf("cfg = %+v, unexpected", cfg)
	}
}

func TestReadTokenFile_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := readTokenFile(path); err == nil {
		t.Fatal("readTokenFile() error = nil, want an error for an empty (whitespace-only) file")
	}
}

func TestNewClient_RejectsInvalidURL(t *testing.T) {
	if _, err := newClient(connectConfig{URL: "not-a-url", Token: "t", Timeout: time.Second}); err == nil {
		t.Fatal("newClient() error = nil, want an error for a URL with no scheme/host")
	}
}
