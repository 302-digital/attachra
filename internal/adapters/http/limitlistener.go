package http

import "net"

// limitListener wraps a net.Listener and bounds the number of
// simultaneously open connections accepted from it to n (SR-125-1,
// reusing the DoS-mitigation shape T1.2 requires for this endpoint
// too).
//
// This duplicates internal/adapters/milter.limitListener almost
// verbatim rather than sharing it: both are unexported types in
// separate adapter packages, and internal/core must not become the
// shared home for adapter-only connection-limiting concerns (ADR-002).
// Promoting this into a small shared internal package (e.g.
// internal/adapters/netutil) is tracked as an explicit debt item per
// SR-115-2 ("reuse the same timeout/limit primitives for the HTTP
// download server") rather than done silently here.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

// newLimitListener returns a Listener that accepts at most n
// simultaneous connections from the given Listener. A non-positive n
// disables the limit.
func newLimitListener(l net.Listener, n int) net.Listener {
	if n <= 0 {
		return l
	}
	return &limitListener{Listener: l, sem: make(chan struct{}, n)}
}

// Accept waits for a free slot, then accepts the next connection.
func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}

	c, err := l.Listener.Accept()
	if err != nil {
		l.release()
		return nil, err
	}
	return &limitConn{Conn: c, release: l.release}, nil
}

func (l *limitListener) release() {
	<-l.sem
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
