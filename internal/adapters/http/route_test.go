package http

import "testing"

func TestParsePackagePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantToken string
		wantRef   string
		wantOK    bool
	}{
		{"package page", "/p/abc123", "abc123", "", true},
		{"download", "/p/abc123/d/link-id-1", "abc123", "link-id-1", true},
		{"missing prefix", "/x/abc123", "", "", false},
		{"empty token", "/p/", "", "", false},
		{"root", "/", "", "", false},
		{"empty", "", "", "", false},
		{"trailing slash only", "/p/abc123/", "", "", false},
		{"malformed d marker", "/p/abc123/x/ref", "", "", false},
		{"missing ref after d", "/p/abc123/d/", "", "", false},
		{"extra path segments", "/p/abc123/d/ref/extra", "", "", false},
		{"token with slash rejected", "/p/abc/123", "", "", false},
		{"double slash after p", "/p//d/ref", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, ref, ok := parsePackagePath(tt.path)
			if ok != tt.wantOK {
				t.Fatalf("parsePackagePath(%q) ok = %v, want %v", tt.path, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if token != tt.wantToken {
				t.Errorf("parsePackagePath(%q) token = %q, want %q", tt.path, token, tt.wantToken)
			}
			if ref != tt.wantRef {
				t.Errorf("parsePackagePath(%q) ref = %q, want %q", tt.path, ref, tt.wantRef)
			}
		})
	}
}
