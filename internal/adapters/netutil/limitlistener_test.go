package netutil

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewLimitListenerDisabled verifies that a non-positive n and a
// non-positive sessionTimeout together disable wrapping entirely: the
// original listener is returned unchanged.
func TestNewLimitListenerDisabled(t *testing.T) {
	ln := newLoopbackListener(t)
	defer ln.Close() //nolint:errcheck // test cleanup

	got := NewLimitListener(ln, 0, 0)
	if got != ln {
		t.Errorf("NewLimitListener(l, 0, 0) = %v, want l itself unwrapped", got)
	}
}

// TestLimitListenerBoundsConcurrentConnections verifies the core
// SR-115-1/SR-125-1 contract: with n=1, a second Accept must not
// succeed until the first accepted connection is closed.
func TestLimitListenerBoundsConcurrentConnections(t *testing.T) {
	ln := newLoopbackListener(t)
	defer ln.Close() //nolint:errcheck // test cleanup

	limited := NewLimitListener(ln, 1, 0)

	dial := func() net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial() error = %v, want nil", err)
		}
		return c
	}

	acceptCh := make(chan net.Conn, 2)
	acceptErrCh := make(chan error, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := limited.Accept()
			if err != nil {
				acceptErrCh <- err
				return
			}
			acceptCh <- c
		}
	}()

	client1 := dial()
	defer client1.Close() //nolint:errcheck // test cleanup

	var first net.Conn
	select {
	case first = <-acceptCh:
	case err := <-acceptErrCh:
		t.Fatalf("Accept() error = %v, want nil", err)
	case <-time.After(2 * time.Second):
		t.Fatal("first Accept() did not complete in time")
	}

	client2 := dial()
	defer client2.Close() //nolint:errcheck // test cleanup

	select {
	case <-acceptCh:
		t.Fatal("second Accept() completed before the first connection's slot was released")
	case <-time.After(200 * time.Millisecond):
		// Expected: the semaphore holds the second Accept back.
	}

	if err := first.Close(); err != nil {
		t.Fatalf("first.Close() error = %v, want nil", err)
	}

	select {
	case c := <-acceptCh:
		defer c.Close() //nolint:errcheck // test cleanup
	case err := <-acceptErrCh:
		t.Fatalf("Accept() error = %v, want nil", err)
	case <-time.After(2 * time.Second):
		t.Fatal("second Accept() did not complete after the first connection's slot was released")
	}
}

// TestLimitConnCloseIsRaceFree is the regression test for ATR-238
// minor-2: many goroutines calling Close concurrently on the same
// accepted connection must release the semaphore slot exactly once,
// never more. Run with -race: the previous plain-bool releaseOnce
// guard was a genuine data race under concurrent Close, not just a
// logical double-release bug.
func TestLimitConnCloseIsRaceFree(t *testing.T) {
	var released int32
	c := &limitConn{
		Conn:    fakeConn{},
		release: func() { atomic.AddInt32(&released, 1) },
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = c.Close()
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&released); got != 1 {
		t.Errorf("release() called %d times across %d concurrent Close() calls, want exactly 1", got, goroutines)
	}
}

// TestLimitListenerSessionTimeoutClosesIdleConnection verifies the
// milter adapter's per-session deadline behavior: a connection that
// stays idle past sessionTimeout is closed by the runtime's deadline
// enforcement, independent of the connection-count limit.
func TestLimitListenerSessionTimeoutClosesIdleConnection(t *testing.T) {
	ln := newLoopbackListener(t)
	defer ln.Close() //nolint:errcheck // test cleanup

	limited := NewLimitListener(ln, 0, 50*time.Millisecond)

	serverConnCh := make(chan net.Conn, 1)
	go func() {
		c, err := limited.Accept()
		if err == nil {
			serverConnCh <- c
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v, want nil", err)
	}
	defer client.Close() //nolint:errcheck // test cleanup

	var serverConn net.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Accept() did not complete in time")
	}
	defer serverConn.Close() //nolint:errcheck // test cleanup

	buf := make([]byte, 1)
	if _, err := serverConn.Read(buf); err == nil {
		t.Error("Read() after sessionTimeout elapsed with no client data error = nil, want a deadline-exceeded error")
	}
}

// newLoopbackListener opens a TCP listener on an ephemeral loopback
// port, registering cleanup.
func newLoopbackListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v, want nil", err)
	}
	return ln
}

// fakeConn is a minimal net.Conn stub for exercising limitConn.Close
// without a real socket.
type fakeConn struct {
	net.Conn
}

func (fakeConn) Close() error { return nil }
