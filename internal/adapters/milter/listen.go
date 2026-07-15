package milter

import (
	"fmt"
	"net"
	"strings"
)

// listen creates a net.Listener from an address string using the
// Postfix-style milter listen syntax:
//
//   - "inet:host:port"      -> TCP listener on host:port
//   - "unix:/path/to/sock"  -> Unix domain socket listener at /path/to/sock
//   - "host:port"           -> TCP listener (network prefix omitted)
//
// This matches the syntax Postfix itself accepts for smtpd_milters /
// non_smtpd_milters entries (see docs/integrations/postfix.md), so
// operators can copy the same value into Attachra's milter.listen
// configuration field.
func listen(addr string) (net.Listener, error) {
	network, address, err := parseListenAddr(addr)
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, fmt.Errorf("milter: listen on %s %s: %w", network, address, err)
	}
	return ln, nil
}

// parseListenAddr splits a Postfix-style milter listen address into a
// Go net.Listen network and address pair.
func parseListenAddr(addr string) (network, address string, err error) {
	switch {
	case strings.HasPrefix(addr, "inet:"):
		return "tcp", strings.TrimPrefix(addr, "inet:"), nil
	case strings.HasPrefix(addr, "unix:"):
		return "unix", strings.TrimPrefix(addr, "unix:"), nil
	case addr == "":
		return "", "", fmt.Errorf("milter: listen address must not be empty")
	default:
		// No recognized network prefix: assume a plain "host:port" TCP
		// address, matching the fallback the Postfix docs describe.
		return "tcp", addr, nil
	}
}
