package http

import "net/http"

// setAntiCacheHeaders sets the response headers required by SR-125-2 /
// T1.4 on every response served by this package's handlers (package
// page and download alike): they prevent CDNs, corporate proxies,
// browser caches and link-preview bots from retaining or re-serving
// content or a stale package-page listing after a link expires or is
// revoked.
func setAntiCacheHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "private, no-store, max-age=0")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("X-Content-Type-Options", "nosniff")
}

// pageCSP is the Content-Security-Policy applied to the package page
// and the generic error page (SR-125-4, T1.5). Both are static,
// server-rendered HTML with no external resources and no inline
// scripts, so the tightest policy applies: nothing is allowed to load,
// and no <script> may execute even if one were ever reflected.
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// setPageSecurityHeaders sets the anti-cache headers plus the headers
// specific to an HTML page response (CSP, frame denial).
func setPageSecurityHeaders(w http.ResponseWriter) {
	setAntiCacheHeaders(w)
	w.Header().Set("Content-Security-Policy", pageCSP)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}
