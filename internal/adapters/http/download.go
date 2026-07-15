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
// whole payload in memory (SR-125-1, CLAUDE.md invariant #4).
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
	if att.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(att.Size, 10))
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
	// (SR-125-1, CLAUDE.md invariant #4). A copy error after headers
	// are already sent cannot be surfaced as a different status code
	// (the response is committed), so it is only logged.
	if _, err := io.Copy(w, rc); err != nil {
		h.logger.Warn("download stream interrupted", "token_ref", tokenRef(token), "error", err.Error())
	}
}
