package http

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses cidrs (each an IPv4 or IPv6 CIDR, e.g.
// "127.0.0.1/32" or "10.0.0.0/8") into the []netip.Prefix form Config
// and APIConfig expect for their TrustedProxies field (ATR-311).
// cmd/attachra calls this once at startup with the already-validated
// internal/config.HTTPConfig.TrustedProxies strings (config.Config.
// Validate parses the same strings for its own load-time error
// reporting, so a malformed entry is rejected before this point in
// practice) — an error here is still returned rather than ignored, so
// a future caller that skips config validation fails closed instead of
// silently trusting nothing or panicking. A nil or empty cidrs returns
// a nil result, the "trust nothing" value clientIP already treats as
// "ignore forwarding headers".
func ParseTrustedProxies(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// clientIP extracts the client IP address for rate limiting and audit
// purposes (SR-125-7/T1.1).
//
// By default (trusted is empty) it returns r.RemoteAddr's host
// verbatim and never consults X-Forwarded-For/X-Real-IP: those headers
// are client-supplied, and trusting them unconditionally would let any
// caller spoof the identity the rate limiter and audit log key off — a
// classic bypass of exactly the enumeration defenses SR-125-7/T1.1
// require. This is the same fail-secure behavior this function has
// always had.
//
// When trusted is non-empty (internal/config.HTTPConfig.TrustedProxies,
// translated by cmd/attachra via ParseTrustedProxies) and RemoteAddr's
// host parses as an address belonging to one of trusted's CIDR ranges —
// i.e. the direct TCP peer is a reverse proxy this deployment
// configured Attachra to trust — the forwarding headers are consulted
// via forwardedClientIP to recover the real client address the proxy
// saw. If RemoteAddr is not in a trusted range, the headers are ignored
// exactly as in the no-config case: an untrusted peer's claimed
// X-Forwarded-For/X-Real-IP is never honored, so a client that connects
// directly (bypassing the proxy) cannot spoof its address just by
// setting the header itself.
//
// Any value this function cannot cleanly parse (an unparsable
// RemoteAddr, a garbled header) falls back to RemoteAddr's raw host
// rather than failing the request: clientIP feeds a best-effort
// identity used for throttling/logging, not an authorization decision,
// so "degrade to the least trusted signal available" — never crash,
// never block the request — is the correct failure mode.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if len(trusted) == 0 {
		return host
	}

	remote, err := netip.ParseAddr(host)
	if err != nil || !addrTrusted(remote, trusted) {
		return host
	}

	if ip, ok := forwardedClientIP(r, trusted); ok {
		return ip
	}
	return host
}

// addrTrusted reports whether addr falls within any of trusted's CIDR
// ranges. addr is unmapped first (net.SplitHostPort + netip.ParseAddr
// can yield an IPv4-mapped IPv6 address, e.g. "::ffff:127.0.0.1", for a
// connection accepted on a dual-stack listener) so an operator-
// configured IPv4 CIDR like "127.0.0.1/32" still matches the same peer
// connecting over an IPv4-mapped IPv6 socket.
func addrTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// forwardedClientIP extracts the real client address from the
// forwarding headers a trusted reverse proxy set, or ok=false if
// neither header yields a usable one.
//
// X-Forwarded-For is read as the proxy chain it conventionally is:
// each hop appends its peer's address, so the chain is walked
// right-to-left, skipping every address that itself belongs to a
// trusted range, and the first non-trusted address found is treated as
// the real client. This defeats append-spoofing, where a malicious
// client sends its own X-Forwarded-For and the trusted proxy appends
// the true peer address after it (SR-125-7) — e.g. deploy/deb/examples/
// nginx-grommunio.conf sets X-Forwarded-For to
// $proxy_add_x_forwarded_for, which appends rather than overwrites.
//
// Any hop that fails to parse as an IP address makes the whole header
// untrustworthy — rather than silently skipping just that one entry
// (which could let an attacker craft a garbage hop to hide which
// prefix of the chain is genuine), the header is abandoned entirely and
// the caller falls back to RemoteAddr, never to X-Real-IP: X-Real-IP is
// only consulted when X-Forwarded-For is absent or empty, not when it
// is present but broken. A chain made up of nothing but trusted
// addresses (no client hop ever recorded) is likewise treated as
// nothing usable.
//
// X-Real-IP is consulted only when X-Forwarded-For is empty, matching
// its role as the single-value fallback some proxies set instead of
// (or in addition to) the chain header.
func forwardedClientIP(r *http.Request, trusted []netip.Prefix) (string, bool) {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return parseHeaderAddr(r.Header.Get("X-Real-IP"))
	}

	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// A malformed hop anywhere in the chain makes the whole
			// header suspect (it may have been tampered with); abandon
			// it rather than guess which remaining prefix is intact.
			return "", false
		}
		if addrTrusted(addr, trusted) {
			continue
		}
		return addr.Unmap().String(), true
	}
	return "", false
}

// parseHeaderAddr parses raw (typically an X-Real-IP header value) as a
// single IP address, returning ok=false for an empty or unparsable
// value rather than an error: this is a best-effort fallback lookup,
// not a place to fail the request.
func parseHeaderAddr(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	return addr.Unmap().String(), true
}
