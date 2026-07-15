package http

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

// mustPrefixes parses cidrs into []netip.Prefix, failing the test on any
// parse error — a test-only convenience mirroring ParseTrustedProxies
// without needing to thread its error return through every table entry.
func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	prefixes, err := ParseTrustedProxies(cidrs)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v) error = %v, want nil", cidrs, err)
	}
	return prefixes
}

func TestParseTrustedProxies(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		got, err := ParseTrustedProxies(nil)
		if err != nil {
			t.Fatalf("ParseTrustedProxies(nil) error = %v, want nil", err)
		}
		if got != nil {
			t.Errorf("ParseTrustedProxies(nil) = %v, want nil", got)
		}
	})

	t.Run("empty slice returns nil", func(t *testing.T) {
		got, err := ParseTrustedProxies([]string{})
		if err != nil {
			t.Fatalf("ParseTrustedProxies([]) error = %v, want nil", err)
		}
		if got != nil {
			t.Errorf("ParseTrustedProxies([]) = %v, want nil", got)
		}
	})

	t.Run("valid IPv4 and IPv6 CIDRs", func(t *testing.T) {
		got, err := ParseTrustedProxies([]string{"127.0.0.1/32", "::1/128", "10.0.0.0/8"})
		if err != nil {
			t.Fatalf("ParseTrustedProxies() error = %v, want nil", err)
		}
		if len(got) != 3 {
			t.Fatalf("ParseTrustedProxies() = %d prefixes, want 3", len(got))
		}
	})

	t.Run("malformed CIDR returns an error, not a panic", func(t *testing.T) {
		_, err := ParseTrustedProxies([]string{"garbage"})
		if err == nil {
			t.Fatal("ParseTrustedProxies([\"garbage\"]) error = nil, want error")
		}
	})

	t.Run("one bad entry among good ones still errors", func(t *testing.T) {
		_, err := ParseTrustedProxies([]string{"127.0.0.1/32", "not-a-cidr"})
		if err == nil {
			t.Fatal("ParseTrustedProxies() error = nil, want error")
		}
	})
}

func TestClientIP_NoTrustedProxiesConfigured(t *testing.T) {
	// The default, pre-ATR-311 posture: with no trusted CIDRs at all,
	// clientIP must always return RemoteAddr's host and never consult
	// the forwarding headers, no matter what a caller sends.
	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	r.Header.Set("X-Real-IP", "198.51.100.9")

	got := clientIP(r, nil)
	if got != "203.0.113.7" {
		t.Errorf("clientIP() = %q, want %q (headers must be ignored)", got, "203.0.113.7")
	}
}

func TestClientIP_UntrustedPeerHeadersIgnored(t *testing.T) {
	// trusted is configured, but the direct TCP peer (RemoteAddr) is NOT
	// in it: an attacker connecting directly and setting the forwarding
	// headers themselves must not be able to spoof their IP.
	trusted := mustPrefixes(t, "127.0.0.1/32")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "203.0.113.7:54321" // Not in trusted.
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	r.Header.Set("X-Real-IP", "198.51.100.9")

	got := clientIP(r, trusted)
	if got != "203.0.113.7" {
		t.Errorf("clientIP() = %q, want %q (untrusted peer's headers must be ignored)", got, "203.0.113.7")
	}
}

func TestClientIP_AppendSpoofingDefended(t *testing.T) {
	// A malicious client sends its own X-Forwarded-For value; the
	// trusted proxy (nginx, using $proxy_add_x_forwarded_for) appends
	// the real peer address it saw after it, rather than overwriting the
	// header. The real (rightmost, non-trusted) address must win.
	trusted := mustPrefixes(t, "127.0.0.1/32")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "127.0.0.1:9999" // The trusted nginx peer.
	r.Header.Set("X-Forwarded-For", "198.51.100.9, 203.0.113.42")

	got := clientIP(r, trusted)
	if got != "203.0.113.42" {
		t.Errorf("clientIP() = %q, want %q (the real, rightmost hop)", got, "203.0.113.42")
	}
}

func TestClientIP_MultipleTrustedHops(t *testing.T) {
	// A chain of several trusted proxies (e.g. an internal load balancer
	// in front of nginx) all get skipped from the right until the first
	// non-trusted (client) address is found.
	trusted := mustPrefixes(t, "127.0.0.1/32", "10.0.0.0/8")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.42, 10.0.0.5, 10.0.0.6")

	got := clientIP(r, trusted)
	if got != "203.0.113.42" {
		t.Errorf("clientIP() = %q, want %q", got, "203.0.113.42")
	}
}

func TestClientIP_EmptyXFFFallsBackToXRealIP(t *testing.T) {
	trusted := mustPrefixes(t, "127.0.0.1/32")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Real-IP", "203.0.113.42")
	// X-Forwarded-For deliberately not set.

	got := clientIP(r, trusted)
	if got != "203.0.113.42" {
		t.Errorf("clientIP() = %q, want %q (X-Real-IP fallback)", got, "203.0.113.42")
	}
}

func TestClientIP_GarbageXFFFallsBackToRemoteAddr(t *testing.T) {
	// A malformed X-Forwarded-For entry makes the whole header
	// untrustworthy; the fallback is RemoteAddr, deliberately NOT
	// X-Real-IP (X-Real-IP is only consulted when XFF is empty/absent).
	trusted := mustPrefixes(t, "127.0.0.1/32")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	r.Header.Set("X-Real-IP", "203.0.113.42")

	got := clientIP(r, trusted)
	if got != "127.0.0.1" {
		t.Errorf("clientIP() = %q, want %q (RemoteAddr fallback, not X-Real-IP)", got, "127.0.0.1")
	}
}

func TestClientIP_GarbageXFFAmongValidHopsFallsBackToRemoteAddr(t *testing.T) {
	trusted := mustPrefixes(t, "127.0.0.1/32")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.42, garbage")

	got := clientIP(r, trusted)
	if got != "127.0.0.1" {
		t.Errorf("clientIP() = %q, want %q", got, "127.0.0.1")
	}
}

func TestClientIP_AllHopsTrustedFallsBackToRemoteAddr(t *testing.T) {
	// A chain made up of nothing but trusted proxies (no client hop ever
	// recorded) has nothing usable to extract.
	trusted := mustPrefixes(t, "127.0.0.1/32", "10.0.0.0/8")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "10.0.0.5, 10.0.0.6")

	got := clientIP(r, trusted)
	if got != "127.0.0.1" {
		t.Errorf("clientIP() = %q, want %q", got, "127.0.0.1")
	}
}

func TestClientIP_UnparseableRemoteAddrFallsBackVerbatim(t *testing.T) {
	trusted := mustPrefixes(t, "127.0.0.1/32")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "not-a-valid-remote-addr" // No host:port at all.
	r.Header.Set("X-Forwarded-For", "203.0.113.42")

	got := clientIP(r, trusted)
	if got != "not-a-valid-remote-addr" {
		t.Errorf("clientIP() = %q, want %q (verbatim RemoteAddr, not a crash)", got, "not-a-valid-remote-addr")
	}
}

func TestClientIP_IPv6(t *testing.T) {
	trusted := mustPrefixes(t, "::1/128")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "[::1]:9999"
	r.Header.Set("X-Forwarded-For", "2001:db8::1")

	got := clientIP(r, trusted)
	if got != "2001:db8::1" {
		t.Errorf("clientIP() = %q, want %q", got, "2001:db8::1")
	}
}

func TestClientIP_IPv6Normalization(t *testing.T) {
	// netip.Addr.String() produces the canonical, compressed form
	// regardless of how the header spelled the same address.
	trusted := mustPrefixes(t, "::1/128")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "[::1]:9999"
	r.Header.Set("X-Forwarded-For", "2001:0db8:0000:0000:0000:0000:0000:0001")

	got := clientIP(r, trusted)
	if got != "2001:db8::1" {
		t.Errorf("clientIP() = %q, want canonical form %q", got, "2001:db8::1")
	}
}

func TestClientIP_TrustedIPv4MappedIPv6Peer(t *testing.T) {
	// A dual-stack listener can surface an IPv4 peer as an IPv4-mapped
	// IPv6 address (::ffff:127.0.0.1); an operator-configured IPv4 CIDR
	// must still match it once unmapped.
	trusted := mustPrefixes(t, "127.0.0.1/32")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "[::ffff:127.0.0.1]:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.42")

	got := clientIP(r, trusted)
	if got != "203.0.113.42" {
		t.Errorf("clientIP() = %q, want %q", got, "203.0.113.42")
	}
}

func TestClientIP_NoXFFOrXRealIPFallsBackToRemoteAddr(t *testing.T) {
	trusted := mustPrefixes(t, "127.0.0.1/32")

	r := httptest.NewRequest("GET", "/p/tok", nil)
	r.RemoteAddr = "127.0.0.1:9999"

	got := clientIP(r, trusted)
	if got != "127.0.0.1" {
		t.Errorf("clientIP() = %q, want %q", got, "127.0.0.1")
	}
}
