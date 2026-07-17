// Package netutil holds small connection-limiting/timeout primitives
// shared between Attachra's adapter servers (SR-115-2, ATR-238
// minor-2). internal/adapters/http and internal/adapters/milter both
// bound the number of concurrent connections they accept, and milter
// additionally applies a fixed per-session deadline; this package
// gives both a single implementation to depend on instead of each
// maintaining its own copy that can silently drift.
//
// netutil depends on nothing beyond the standard library. It is not
// internal/core: adapter-only connection-limiting concerns belong
// here, never in core (ADR-002).
package netutil

import (
	"net"
	"sync"
	"time"
)

// LimitListener wraps a net.Listener and bounds the number of
// simultaneously open connections accepted from it, optionally
// applying a fixed deadline to each accepted connection.
type LimitListener struct {
	net.Listener
	sem            chan struct{}
	sessionTimeout time.Duration
}

// NewLimitListener returns a Listener that accepts at most n
// simultaneous connections from l (SR-115-1/SR-125-1), each closed
// after sessionTimeout if it is still open by then. A non-positive n
// disables the connection-count limit; a non-positive sessionTimeout
// disables the per-session deadline. If both are non-positive, l is
// returned unwrapped.
func NewLimitListener(l net.Listener, n int, sessionTimeout time.Duration) net.Listener {
	if n <= 0 && sessionTimeout <= 0 {
		return l
	}
	var sem chan struct{}
	if n > 0 {
		sem = make(chan struct{}, n)
	}
	return &LimitListener{Listener: l, sem: sem, sessionTimeout: sessionTimeout}
}

// Accept waits for a free slot (if a connection limit is configured),
// then accepts the next connection and applies the session deadline
// (if configured). On any failure after a slot was taken, the slot is
// released before Accept returns.
func (l *LimitListener) Accept() (net.Conn, error) {
	if l.sem != nil {
		l.sem <- struct{}{}
	}

	c, err := l.Listener.Accept()
	if err != nil {
		l.release()
		return nil, err
	}

	if l.sessionTimeout > 0 {
		if err := c.SetDeadline(time.Now().Add(l.sessionTimeout)); err != nil {
			_ = c.Close()
			l.release()
			return nil, err
		}
	}

	return &limitConn{Conn: c, release: l.release}, nil
}

func (l *LimitListener) release() {
	if l.sem != nil {
		<-l.sem
	}
}

// limitConn wraps a net.Conn, releasing its LimitListener slot exactly
// once when Close is called, no matter how many times Close itself is
// called or how many goroutines call it concurrently.
//
// The previous per-adapter implementations (internal/adapters/http and
// internal/adapters/milter, before ATR-238) guarded this with a plain
// releaseOnce bool instead of sync.Once. Without synchronization, two
// goroutines racing on Close (net/http.Server itself may close a
// connection concurrently with the handler's own defer, and the
// milter library independently closes and lets callers close too) can
// both observe releaseOnce == false, both flip it to true, and both
// call release(): the semaphore is released twice for one accepted
// connection, silently letting one extra connection past
// MaxConnections per double-release. sync.Once makes exactly one
// release happen regardless of how Close is invoked (verified under
// go test -race by TestLimitConnCloseIsRaceFree).
type limitConn struct {
	net.Conn
	release     func()
	releaseOnce sync.Once
}

// Close closes the underlying connection and releases the semaphore
// slot exactly once, safe for concurrent callers.
func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}
