package http

import (
	"net/http"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
)

// servePackagePage implements GET /p/<token>: step 1 of the two-step
// download flow (SR-125-3, docs/architecture/package-page-decision.md
// §4.1 item 3). It resolves token, lists every Link belonging to the
// message and addressed to the token's own recipient (ATR-237: other
// recipients' Link rows for the same message are never shown here),
// renders each as an available/unavailable row, and returns without
// ever streaming attachment bytes or touching any Link's download
// counter — a link-preview bot fetching this URL costs the recipient
// nothing.
func (h *Handler) servePackagePage(w http.ResponseWriter, r *http.Request, token string) {
	messageID, recipient, ok := h.resolvePackage(w, r, token)
	if !ok {
		return
	}

	links, err := h.engine.ListPackageFiles(r.Context(), messageID, recipient)
	if err != nil {
		h.notFound(w, r, "package_page_view", token, "list package files failed: "+err.Error())
		return
	}

	data := packagePageData{
		PackagePath: "/p/" + token,
		Files:       make([]packageFileView, 0, len(links)),
	}

	for _, l := range links {
		data.Files = append(data.Files, h.fileView(r, l))
	}

	recordAudit(r.Context(), h.audit, h.logger, auditEvent{
		Action:    "package_page_view",
		Token:     token,
		MessageID: messageID,
		RemoteIP:  clientIP(r, h.trustedProxies),
		UserAgent: truncateUserAgent(r.UserAgent()),
	})

	setPageSecurityHeaders(w)
	w.WriteHeader(http.StatusOK)
	// Best-effort render: headers/status are already committed: a
	// write failure here means the client disconnected, which is not
	// itself a security-relevant condition worth failing the request
	// over.
	_ = packagePageTemplate.Execute(w, data)
}

// fileView resolves l's attachment metadata for display and reports
// it as available only if l itself is currently usable (active,
// unexpired, not exhausted): a revoked or exhausted per-attachment
// link renders as an inert "not available" row on an otherwise-live
// package page, matching the graceful-degradation UX
// package-page-decision.md §3 calls for, without revealing which of
// revoked/expired/exhausted applies (SR-125-5 extends to this listing
// too, not just the top-level token resolve).
func (h *Handler) fileView(r *http.Request, l store.Link) packageFileView {
	name := l.AttachmentID
	size := ""
	if att, err := h.store.GetAttachment(r.Context(), l.AttachmentID); err == nil {
		name = att.Filename
		size = humanSize(att.Size)
	}

	return packageFileView{
		// Ref is the store-assigned, non-secret Link.ID (not
		// AttachmentID): it becomes the POST form's target path
		// segment and, on the download side,
		// link.Engine.RegisterPackageDownload looks the Link up by
		// this same ID after verifying it belongs to the resolved
		// package's message. See that method's doc comment for why a
		// row ID — not a second bearer token — is the correct and
		// safe path segment here.
		Ref:       l.ID,
		Name:      name,
		Size:      size,
		Available: linkStillUsable(l),
	}
}

// linkStillUsable reports whether l may still be downloaded: active
// status, not past its expiry, and (if a limit is set) still under its
// download budget. This mirrors link.Engine's own isUsable/
// RegisterDownload guard so the page listing and the actual download
// path agree on what "available" means, without exposing the
// distinction between expired/revoked/exhausted to the viewer
// (SR-125-5): all three simply render as unavailable.
func linkStillUsable(l store.Link) bool {
	if l.Status != store.LinkStatusActive {
		return false
	}
	if !time.Now().Before(l.ExpiresAt) {
		return false
	}
	if l.MaxDownloads != 0 && l.Downloads >= l.MaxDownloads {
		return false
	}
	return true
}
