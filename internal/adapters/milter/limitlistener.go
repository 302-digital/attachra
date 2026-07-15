package milter

import (
	"net"
	"time"
)

// limitListener wraps a net.Listener and bounds the number of
// simultaneously open connections accepted from it to n (SR-115-1).
// Once n connections are open, Accept blocks new callers until one of
// the existing connections is closed. This mirrors the standard
// library's golang.org/x/net/netutil.LimitListener, reimplemented
// here to avoid adding a dependency for a handful of lines.
//
// It also optionally applies a fixed deadline to each accepted
// connection (sessionTimeout), bounding how long a single milter
// session may stay open regardless of individual read/write
// timeouts (SR-115-1).
type limitListener struct {
	net.Listener
	sem            chan struct{}
	sessionTimeout time.Duration
}

// newLimitListener returns a Listener that accepts at most n
// simultaneous connections from the given Listener, each closed after
// sessionTimeout if it is still open by then. A non-positive n
// disables the connection-count limit; a non-positive sessionTimeout
// disables the per-session deadline.
func newLimitListener(l net.Listener, n int, sessionTimeout time.Duration) net.Listener {
	if n <= 0 && sessionTimeout <= 0 {
		return l
	}
	var sem chan struct{}
	if n > 0 {
		sem = make(chan struct{}, n)
	}
	return &limitListener{Listener: l, sem: sem, sessionTimeout: sessionTimeout}
}

// Accept waits for a free slot (if a connection limit is configured),
// then accepts the next connection and applies the session deadline
// (if configured).
func (l *limitListener) Accept() (net.Conn, error) {
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

func (l *limitListener) release() {
	if l.sem != nil {
		<-l.sem
	}
}

// limitConn wraps a net.Conn, releasing its limitListener slot exactly
// once when Close is called.
type limitConn struct {
	net.Conn
	release     func()
	releaseOnce bool
}

// Close closes the underlying connection and releases the semaphore
// slot, regardless of how many times Close is called.
func (c *limitConn) Close() error {
	err := c.Conn.Close()
	if !c.releaseOnce {
		c.releaseOnce = true
		c.release()
	}
	return err
}
