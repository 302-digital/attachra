package http

import "time"

// tarpitSleep blocks the current goroutine for d before the caller
// writes its response (SR-125-7): once an IP has exceeded the
// not-found rate budget, every further generic-error response to that
// IP is deliberately slowed down, making automated token enumeration
// (T1.1) more expensive without an outright connection drop (which
// would just prompt an immediate reconnect). The request's own
// ReadTimeout/WriteTimeout (see Config) still bounds the connection's
// total lifetime, so a slow client cannot combine with the tarpit to
// hold a connection open indefinitely.
//
// This owns no goroutine of its own — it blocks the handler's request
// goroutine only, which net/http already tracks and will tear down
// alongside the connection on server Shutdown/timeout.
func tarpitSleep(d time.Duration) {
	time.Sleep(d)
}
