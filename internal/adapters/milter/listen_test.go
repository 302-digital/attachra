package milter

import "testing"

func TestParseListenAddr(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		wantNetwork string
		wantAddress string
		wantErr     bool
	}{
		{name: "inet prefix", addr: "inet:127.0.0.1:6785", wantNetwork: "tcp", wantAddress: "127.0.0.1:6785"},
		{name: "unix prefix", addr: "unix:/var/run/attachra.sock", wantNetwork: "unix", wantAddress: "/var/run/attachra.sock"},
		{name: "bare host:port", addr: "127.0.0.1:6785", wantNetwork: "tcp", wantAddress: "127.0.0.1:6785"},
		{name: "empty", addr: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, address, err := parseListenAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseListenAddr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if network != tt.wantNetwork {
				t.Errorf("network = %q, want %q", network, tt.wantNetwork)
			}
			if address != tt.wantAddress {
				t.Errorf("address = %q, want %q", address, tt.wantAddress)
			}
		})
	}
}

func TestListen_TCP(t *testing.T) {
	ln, err := listen("inet:127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // best-effort cleanup

	if ln.Addr().Network() != "tcp" {
		t.Errorf("Addr().Network() = %q, want tcp", ln.Addr().Network())
	}
}

func TestListen_InvalidAddr(t *testing.T) {
	if _, err := listen(""); err == nil {
		t.Fatal("expected error for empty listen address")
	}
}
