package http

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/storage"
)

// serveDownload implements POST /p/<token>/d/<link-id>: step 2 of the
// two-step download flow (SR-125-3). linkID is the store-assigned,
// non-secret Link.ID selecting which per-attachment link within the
// package to charge; the package token itself is the authorization
// (see link.Engine.RegisterPackageDownload's doc comment).
// RegisterPackageDownload atomically registers the download against
// that Link (SR-125-6) after confirming it belongs to the message the
// package token resolves to, then this handler streams the object
// straight from storage.Driver to the response without buffering the
// whole payload in memory (SR-125-1, the streaming invariant).
func (h *Handler) serveDownload(w http.ResponseWriter, r *http.Request, token, linkID string) {
	registeredLink, err := h.engine.RegisterPackageDownload(r.Context(), token, linkID)
	if err != nil {
		reason := "register package download failed"
		if !errors.Is(err, link.ErrNotFound) {
			reason = "register package download error: " + err.Error()
		}
		h.metrics.ObserveDownload("denied")
		h.notFound(w, r, "download", token, reason)
		return
	}

	att, err := h.store.GetAttachment(r.Context(), registeredLink.AttachmentID)
	if err != nil {
		h.metrics.ObserveDownload("denied")
		h.notFound(w, r, "download", token, "attachment metadata missing: "+err.Error())
		return
	}

	rc, err := h.storage.Get(r.Context(), att.StorageKey)
	if err != nil {
		h.metrics.ObserveDownload("denied")
		if errors.Is(err, storage.ErrNotFound) {
			h.notFound(w, r, "download", token, "storage object missing")
			return
		}
		h.notFound(w, r, "download", token, "storage get error: "+err.Error())
		return
	}
	defer rc.Close() //nolint:errcheck // best-effort close after streaming; any error here cannot change the already-sent response

	h.metrics.ObserveDownload("success")
	setAntiCacheHeaders(w)
	w.Header().Set("Content-Type", responseContentType(att.DetectedType))
	w.Header().Set("Content-Disposition", contentDisposition(att.Filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", pageCSP)
	// Content-Length must reflect the object actually being streamed,
	// not the metadata DB's att.Size: the two can drift (e.g. a
	// storage object replaced or re-uploaded out of band), and a
	// Content-Length that promises more or fewer bytes than io.Copy
	// below actually writes produces a truncated/hanging response for
	// the client rather than a clean error (ATR-238 minor-4). h.storage
	// is asked for the object's own size via Stat (a metadata-only
	// call, not a second read of the payload) and that value is
	// trusted instead. If Stat fails for any reason, the response
	// simply omits Content-Length and net/http falls back to chunked
	// transfer encoding, which is always correct regardless of size.
	if info, err := h.storage.Stat(r.Context(), att.StorageKey); err == nil && info.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	} else if err != nil {
		h.logger.Warn("download content-length stat failed, streaming without Content-Length", "token_ref", tokenRef(token), "error", err.Error())
	}
	w.WriteHeader(http.StatusOK)

	recordAudit(r.Context(), h.audit, h.logger, auditEvent{
		Action:    "download",
		Token:     token,
		MessageID: registeredLink.MessageID,
		RemoteIP:  clientIP(r, h.trustedProxies),
		UserAgent: truncateUserAgent(r.UserAgent()),
	})

	// io.Copy streams directly from the storage backend to the
	// response writer: neither side is ever fully buffered in memory
	// (SR-125-1, the streaming invariant). A copy error after headers
	// are already sent cannot be surfaced as a different status code
	// (the response is committed), so it is only logged.
	if _, err := io.Copy(w, rc); err != nil {
		h.logger.Warn("download stream interrupted", "token_ref", tokenRef(token), "error", err.Error())
	}
}
