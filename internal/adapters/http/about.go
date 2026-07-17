package http

import "net/http"

// serveAbout implements GET /about (ATR-271, second layer of the
// Recipient Trust Kit, ATR-230): a static, unauthenticated page on the
// same public download listener as /p/ that lets the IT administrator
// of an email's recipient verify an unfamiliar download-domain link
// before whitelisting or reporting it.
//
// It deliberately shares Handler's own per-IP rate limiter and
// trusted-proxy configuration with the package-page path (SR-125-7:
// every public route gets the same throttling, not just /p/), and
// renders a single static template with no request-derived or
// configuration-derived data (SR-130-1-style: this installation's
// version, config, recipients, or traffic volume are never disclosed
// here, matching /healthz and /readyz's own "no leakage" contract).
func (h *Handler) serveAbout(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r, h.trustedProxies)
	if !h.limiter.allowRequest(ip) {
		writeTooManyRequests(w)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		setAntiCacheHeaders(w)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setPageSecurityHeaders(w)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	// Best-effort render: headers/status are already committed, so a
	// write failure here means the client disconnected — not itself a
	// security-relevant condition worth failing the request over
	// (mirrors servePackagePage's own handling).
	_ = aboutPageTemplate.Execute(w, nil)
}
