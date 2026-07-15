package main

import (
	"errors"
	"strings"
	"testing"
)

// fakeMailEnvDeps builds a mailEnvDeps backed by in-memory sets, so
// these tests never touch the real filesystem, PATH, or a docker
// daemon.
func fakeMailEnvDeps(onPath map[string]bool, units map[string]bool, paths map[string]bool, dockerNames []string, dockerErr error) mailEnvDeps {
	return mailEnvDeps{
		lookPath: func(name string) (string, error) {
			if onPath[name] {
				return "/usr/sbin/" + name, nil
			}
			return "", errors.New("not found")
		},
		unitExists: func(pattern string) bool {
			// Support the one glob pattern detectMailEnv actually uses
			// ("gromox-*.service") by checking a fixed key, and every
			// other pattern as a literal lookup.
			if pattern == "gromox-*.service" {
				return units["gromox-*.service"]
			}
			return units[pattern]
		},
		pathExists: func(path string) bool {
			return paths[path]
		},
		dockerContainerNames: func() ([]string, error) {
			if dockerErr != nil {
				return nil, dockerErr
			}
			return dockerNames, nil
		},
	}
}

func TestDetectMailEnv(t *testing.T) {
	tests := []struct {
		name        string
		onPath      map[string]bool
		units       map[string]bool
		paths       map[string]bool
		dockerNames []string
		dockerErr   error
		want        mailEnv
	}{
		{
			name: "empty system: no markers at all",
			want: mailEnvUnknown,
		},
		{
			name:   "plain postfix: postconf on PATH only",
			onPath: map[string]bool{"postconf": true},
			want:   mailEnvPostfix,
		},
		{
			name:  "plain postfix: postfix.service unit only, no postconf",
			units: map[string]bool{"postfix.service": true},
			want:  mailEnvPostfix,
		},
		{
			name:   "grommunio: admin-api unit alongside postfix",
			onPath: map[string]bool{"postconf": true},
			units:  map[string]bool{"grommunio-admin-api.service": true},
			want:   mailEnvGrommunio,
		},
		{
			name:  "grommunio: gromox-* unit glob alone is enough",
			units: map[string]bool{"gromox-*.service": true},
			want:  mailEnvGrommunio,
		},
		{
			name:  "grommunio: /etc/grommunio-common directory",
			paths: map[string]bool{"/etc/grommunio-common": true},
			want:  mailEnvGrommunio,
		},
		{
			name:  "grommunio: /usr/share/grommunio-admin-web directory",
			paths: map[string]bool{"/usr/share/grommunio-admin-web": true},
			want:  mailEnvGrommunio,
		},
		{
			name:  "mailcow: /opt/mailcow-dockerized directory",
			paths: map[string]bool{"/opt/mailcow-dockerized": true},
			want:  mailEnvMailcow,
		},
		{
			name:        "mailcow: docker container name suffix",
			dockerNames: []string{"postfix-mailcow", "sogo-mailcow"},
			want:        mailEnvMailcow,
		},
		{
			name:      "mailcow markers absent, docker unavailable: does not panic, falls through",
			dockerErr: errors.New("docker: command not found"),
			want:      mailEnvUnknown,
		},
		{
			name:   "iredmail: release marker file",
			paths:  map[string]bool{"/etc/iredmail-release": true},
			onPath: map[string]bool{"postconf": true},
			want:   mailEnvIRedMail,
		},
		{
			name:   "grommunio wins over plain postfix when both fire",
			onPath: map[string]bool{"postconf": true},
			units:  map[string]bool{"postfix.service": true, "grommunio-admin-api.service": true},
			want:   mailEnvGrommunio,
		},
		{
			name:  "grommunio wins over iredmail and mailcow when all fire",
			units: map[string]bool{"grommunio-admin-api.service": true},
			paths: map[string]bool{"/etc/iredmail-release": true, "/opt/mailcow-dockerized": true},
			want:  mailEnvGrommunio,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := fakeMailEnvDeps(tt.onPath, tt.units, tt.paths, tt.dockerNames, tt.dockerErr)
			got := detectMailEnv(deps)
			if got.Env != tt.want {
				t.Errorf("detectMailEnv() = %v (markers: %v), want %v", got.Env, got.Markers, tt.want)
			}
		})
	}
}

func TestDetectMailEnv_MarkersExplainTheGuess(t *testing.T) {
	deps := fakeMailEnvDeps(map[string]bool{"postconf": true}, map[string]bool{"grommunio-admin-api.service": true}, nil, nil, nil)
	got := detectMailEnv(deps)
	if got.Env != mailEnvGrommunio {
		t.Fatalf("detectMailEnv().Env = %v, want %v", got.Env, mailEnvGrommunio)
	}
	if len(got.Markers) == 0 {
		t.Fatal("detectMailEnv().Markers is empty, want at least one marker explaining the guess")
	}
	joined := strings.Join(got.Markers, "; ")
	if !strings.Contains(joined, "grommunio-admin-api.service") {
		t.Errorf("Markers = %v, want a mention of grommunio-admin-api.service", got.Markers)
	}
}

func TestMailEnvString(t *testing.T) {
	tests := []struct {
		env  mailEnv
		want string
	}{
		{mailEnvUnknown, "unknown"},
		{mailEnvPostfix, "postfix"},
		{mailEnvGrommunio, "grommunio"},
		{mailEnvMailcow, "mailcow"},
		{mailEnvIRedMail, "iredmail"},
	}
	for _, tt := range tests {
		if got := tt.env.String(); got != tt.want {
			t.Errorf("mailEnv(%d).String() = %q, want %q", tt.env, got, tt.want)
		}
	}
}

// TestHTTPListenDefaultFor is the regression test ATR-337 explicitly
// calls for: a grommunio host must default to 127.0.0.1:18080 (its own
// grommunio-admin occupies 8080), and every other environment —
// including mailEnvUnknown, the "empty system" case — must keep the
// wizard's existing default unchanged, so this wiring introduces no
// regression for hosts detectMailEnv does not recognize.
func TestHTTPListenDefaultFor(t *testing.T) {
	const wantDefault = "127.0.0.1:18080"

	tests := []struct {
		name string
		env  mailEnv
	}{
		{"grommunio", mailEnvGrommunio},
		{"unknown (empty system): unchanged default", mailEnvUnknown},
		{"plain postfix: unchanged default", mailEnvPostfix},
		{"mailcow: unchanged default", mailEnvMailcow},
		{"iredmail: unchanged default", mailEnvIRedMail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpListenDefaultFor(tt.env); got != wantDefault {
				t.Errorf("httpListenDefaultFor(%v) = %q, want %q", tt.env, got, wantDefault)
			}
		})
	}
}

func TestMilterChain(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		ours     string
		want     string
	}{
		{"no existing value: just ours", "", "inet:127.0.0.1:6785", "inet:127.0.0.1:6785"},
		{"placeholder existing: placeholder kept first", "<existing>", "inet:127.0.0.1:6785", "<existing>, inet:127.0.0.1:6785"},
		{"real existing value: kept first", "inet:127.0.0.1:11332", "inet:127.0.0.1:6785", "inet:127.0.0.1:11332, inet:127.0.0.1:6785"},
		{"existing is whitespace-only: treated as none", "   ", "inet:127.0.0.1:6785", "inet:127.0.0.1:6785"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := milterChain(tt.existing, tt.ours); got != tt.want {
				t.Errorf("milterChain(%q, %q) = %q, want %q", tt.existing, tt.ours, got, tt.want)
			}
		})
	}
}
