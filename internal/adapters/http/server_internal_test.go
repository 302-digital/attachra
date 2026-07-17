package http

import "testing"

// TestIsLoopbackAddr covers isLoopbackAddr's ATR-292 fold-warning
// escalation logic directly: it must positively identify loopback
// addresses and, deliberately conservatively, treat anything it cannot
// identify as loopback (wildcard binds, unparsable hosts) as NOT
// loopback, so the caller favors escalating to Error over silently
// staying at Warn.
func TestIsLoopbackAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{"IPv4 loopback with port", "127.0.0.1:8080", true},
		{"IPv4 loopback bare", "127.0.0.1", true},
		{"IPv6 loopback with port", "[::1]:8080", true},
		{"localhost hostname", "localhost:8080", true},
		{"IPv4 wildcard", "0.0.0.0:8080", false},
		{"IPv6 wildcard", "[::]:8080", false},
		{"bare port only (all interfaces)", ":8080", false},
		{"empty", "", false},
		{"real hostname", "mail.example.com:8080", false},
		{"non-loopback IPv4", "10.0.0.5:8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLoopbackAddr(tt.addr); got != tt.want {
				t.Errorf("isLoopbackAddr(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}
