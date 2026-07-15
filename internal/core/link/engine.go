package link

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/store"
)

// Engine is the Link Engine domain service (US-6.1): it generates
// personal download tokens, persists only their hashes via a
// store.MetadataStore, resolves a presented token back to the link it
// belongs to, and enforces revoke/hold semantics. Engine holds no
// adapter-specific state and depends only on internal/core packages
// (ADR-002).
type Engine struct {
	metadata store.MetadataStore
	defaults Defaults
	audit    audit.AuditSink

	// now is overridable for deterministic tests; production code
	// always uses the zero value, which falls back to time.Now.
	now func() time.Time
}

// NewEngine constructs an Engine backed by metadata, using d as the
// fallback link parameters for any field a policy leaves unset
// (T-6.1.2). It returns an error if d is invalid. sink receives an
// audit.Event for every revoke this Engine performs (US-7.1, ATR-190);
// a nil sink is treated as audit.NopSink{}.
func NewEngine(metadata store.MetadataStore, d Defaults, sink audit.AuditSink) (*Engine, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if sink == nil {
		sink = audit.NopSink{}
	}
	return &Engine{metadata: metadata, defaults: d, audit: sink}, nil
}

func (e *Engine) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

func (e *Engine) nowText() string {
	return e.clock().UTC().Format(time.RFC3339Nano)
}

// recordAudit appends ev via e.audit, logging failures nowhere itself
// (Engine holds no logger) but never propagating them: a revoke that
// already durably updated the store must still succeed even if the
// audit trail could not be written (CLAUDE.md invariant #3's spirit
// extended to the audit path — see recordAudit's counterparts in
// pipeline and internal/adapters/http for the same contract). Callers
// that need failure visibility should inspect the returned error from
// a wrapping AuditSink implementation if they require it; Engine's own
// callers (Revoke/RevokeMessage/RevokeSender) intentionally do not.
func (e *Engine) recordAudit(ctx context.Context, ev audit.Event) {
	_, _ = e.audit.Record(ctx, ev) //nolint:errcheck // best-effort: a revoke must not fail because the audit sink is unavailable.
}

// MessageInput describes the message a set of links is being created
// for (T-6.1.3: messages table).
type MessageInput struct {
	ID      string
	QueueID string
	Sender  string

	// Status is the aggregated policy decision for this message
	// (ATR-198/T-8.1.4, store.Message.Status's own doc comment):
	// typically policy.MessageDecision.Action, converted to
	// store.MessageStatus by CreateLinks since store does not itself
	// depend on the policy package.
	Status policy.Action
}

// AttachmentInput describes one replaced attachment belonging to the
// message (T-6.1.3: attachments table).
type AttachmentInput struct {
	ID           string
	PartRef      string
	Filename     string
	DeclaredType string
	DetectedType string
	Size         int64
	StorageKey   string
}

// CreatedLink is one freshly minted link, returned to the caller so it
// can build the rewritten message body. Token is the raw bearer
// secret — it exists only in this return value and the recipient's
// copy embedded in the download URL; it is never persisted (CLAUDE.md
// invariant #5).
type CreatedLink struct {
	AttachmentID string
	Recipient    string
	Token        string
	ExpiresAt    time.Time
	MaxDownloads int
}

// CreateLinksParams bundles the inputs to CreateLinks.
type CreateLinksParams struct {
	Message     MessageInput
	Attachments []AttachmentInput
	Recipients  []string

	// Params selects the per-link TTL/MaxDownloads override to apply
	// to every created link (T-6.1.2). Typically the matched Rule's
	// ActionSpec.ActionParams, or Policy.Defaults, or a zero value to
	// take the Engine's own Defaults verbatim. Per
	// docs/architecture/package-page-decision.md §7 item 3, MVP applies
	// one set of parameters per message (the caller is responsible for
	// pre-resolving worst-case aggregation across recipients before
	// calling CreateLinks).
	Params policy.ActionParams
}

// CreateLinks persists the Message once, every AttachmentInput once,
// and one Link per (attachment, recipient) pair, returning the raw
// tokens for each (T-6.1.1, T-6.1.3). It also creates a single
// MessageLink for the package page
// (docs/architecture/package-page-decision.md §4.1 item 1), one per
// distinct recipient in Recipients.
//
// CreateLinks is not fully transactional across the underlying store
// calls (store.MetadataStore does not expose cross-aggregate
// transactions to core); on a partial failure it returns an error
// wrapping the underlying cause and the caller must treat the message
// as failed (fail-open/fail-closed per CLAUDE.md invariant #3 is
// decided by the milter adapter, not here).
func (e *Engine) CreateLinks(ctx context.Context, p CreateLinksParams) ([]CreatedLink, error) {
	if len(p.Attachments) == 0 {
		return nil, errors.New("link: create links: at least one attachment is required")
	}
	if len(p.Recipients) == 0 {
		return nil, errors.New("link: create links: at least one recipient is required")
	}

	resolved := resolveParams(p.Params, e.defaults)
	expiresAt := e.clock().Add(resolved.ttl).UTC()
	expiresAtText := expiresAt.Format(time.RFC3339Nano)

	// retainUntilText is the storage retention deadline (US-5.3/ATR-178,
	// SR-123-1), applied identically to every attachment created for
	// this message (resolved.retention is already the single,
	// worst-case-merged value for the whole message — see
	// pipeline.worstCaseReplaceParams — matching how expiresAt/TTL is
	// already applied per message rather than per attachment).
	// resolveParams guarantees resolved.retention >= resolved.ttl, so a
	// link can never outlive the object it points to.
	retainUntilText := e.clock().Add(resolved.retention).UTC().Format(time.RFC3339Nano)

	if err := e.metadata.CreateMessage(ctx, store.NewMessageParams{
		ID:      p.Message.ID,
		QueueID: p.Message.QueueID,
		Sender:  p.Message.Sender,
		Status:  store.MessageStatus(p.Message.Status),
	}); err != nil {
		return nil, fmt.Errorf("link: create links: create message: %w", err)
	}

	for _, a := range p.Attachments {
		if err := e.metadata.CreateAttachment(ctx, store.NewAttachmentParams{
			ID:           a.ID,
			MessageID:    p.Message.ID,
			PartRef:      a.PartRef,
			Filename:     a.Filename,
			DeclaredType: a.DeclaredType,
			DetectedType: a.DetectedType,
			Size:         a.Size,
			StorageKey:   a.StorageKey,
			RetainUntil:  retainUntilText,
		}); err != nil {
			return nil, fmt.Errorf("link: create links: create attachment %q: %w", a.ID, err)
		}
	}

	var created []CreatedLink

	for _, recipient := range p.Recipients {
		for _, a := range p.Attachments {
			token, err := GenerateToken(e.defaults.TokenBytes)
			if err != nil {
				return nil, fmt.Errorf("link: create links: %w", err)
			}

			linkID, err := newID()
			if err != nil {
				return nil, fmt.Errorf("link: create links: %w", err)
			}

			if err := e.metadata.CreateLink(ctx, store.NewLinkParams{
				ID:           linkID,
				MessageID:    p.Message.ID,
				AttachmentID: a.ID,
				Recipient:    recipient,
				TokenHash:    HashToken(token),
				ExpiresAt:    expiresAtText,
				MaxDownloads: resolved.maxDownloads,
			}); err != nil {
				return nil, fmt.Errorf("link: create links: create link for attachment %q recipient %q: %w", a.ID, recipient, err)
			}

			created = append(created, CreatedLink{
				AttachmentID: a.ID,
				Recipient:    recipient,
				Token:        token,
				ExpiresAt:    expiresAt,
				MaxDownloads: resolved.maxDownloads,
			})
		}

		packageToken, err := GenerateToken(e.defaults.TokenBytes)
		if err != nil {
			return nil, fmt.Errorf("link: create links: package token: %w", err)
		}
		if err := e.metadata.CreateMessageLink(ctx, store.NewMessageLinkParams{
			TokenHash: HashToken(packageToken),
			MessageID: p.Message.ID,
			Recipient: recipient,
			ExpiresAt: expiresAtText,
		}); err != nil {
			return nil, fmt.Errorf("link: create links: create message link for recipient %q: %w", recipient, err)
		}
		created = append(created, CreatedLink{
			AttachmentID: "", // Empty AttachmentID marks the package-page token itself.
			Recipient:    recipient,
			Token:        packageToken,
			ExpiresAt:    expiresAt,
			MaxDownloads: 0,
		})
	}

	return created, nil
}

// Resolve looks up the link identified by the raw bearer token,
// returning ErrNotFound (wrapped) both when no link was ever created
// for this token and when the matching link has expired or been
// revoked (SR-125-5): callers must render one generic response for
// every case in this method's error return, never branching UI/API
// behavior on which specific condition occurred (that distinction
// belongs only in the audit log, populated from the store's raw
// status/expiry fields if the caller chooses to look further, not
// from this method).
//
// Resolve hashes token and performs a single indexed-hash lookup
// (SR-124-2): it never iterates stored links, so there is no timing
// side-channel proportional to the number of active links.
func (e *Engine) Resolve(ctx context.Context, token string) (store.Link, error) {
	l, err := e.metadata.GetLinkByTokenHash(ctx, HashToken(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Link{}, fmt.Errorf("link: resolve: %w", ErrNotFound)
		}
		return store.Link{}, fmt.Errorf("link: resolve: %w", err)
	}

	if !isUsable(l, e.clock()) {
		return store.Link{}, fmt.Errorf("link: resolve: %w", ErrNotFound)
	}

	return l, nil
}

// ResolvePackage looks up the package-page MessageLink identified by
// the raw bearer token, with the same generic not-found contract as
// Resolve (SR-125-5).
func (e *Engine) ResolvePackage(ctx context.Context, token string) (store.MessageLink, error) {
	ml, err := e.metadata.GetMessageLinkByTokenHash(ctx, HashToken(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.MessageLink{}, fmt.Errorf("link: resolve package: %w", ErrNotFound)
		}
		return store.MessageLink{}, fmt.Errorf("link: resolve package: %w", err)
	}

	if ml.Status != store.LinkStatusActive || !e.clock().Before(ml.ExpiresAt) {
		return store.MessageLink{}, fmt.Errorf("link: resolve package: %w", ErrNotFound)
	}

	return ml, nil
}

// ListPackageFiles returns every Link belonging to messageID, for
// rendering the package page's file list
// (docs/architecture/package-page-decision.md §4.1 item 4: "package on
// the page = SELECT ... FROM link WHERE message_id = ?").
func (e *Engine) ListPackageFiles(ctx context.Context, messageID string) ([]store.Link, error) {
	links, err := e.metadata.ListLinksByMessage(ctx, messageID)
	if err != nil {
		return nil, fmt.Errorf("link: list package files: %w", err)
	}
	return links, nil
}

// isUsable reports whether l may still be resolved to bytes: active
// status and not past its expiry, evaluated against now. It
// deliberately ignores Hold: hold blocks revoke and retention, not
// resolution or download (see store.Link.Hold godoc).
func isUsable(l store.Link, now time.Time) bool {
	if l.Status != store.LinkStatusActive {
		return false
	}
	return now.Before(l.ExpiresAt)
}

// RegisterDownload records a single download against the link
// identified by token, enforcing MaxDownloads atomically
// (docs/architecture/adr-011-metadata-db.md: the guarded UPDATE is the
// sole enforcement mechanism, never read-then-write). It returns the
// Link so the caller can look up which attachment/storage key to
// stream, or an error wrapping ErrNotFound if the token does not
// resolve to a currently usable link (expired/revoked/exhausted are
// all folded into the same not-found-shaped error here too, per
// SR-125-5 — the HTTP layer must not distinguish them to the
// recipient).
func (e *Engine) RegisterDownload(ctx context.Context, token string) (store.Link, error) {
	l, err := e.metadata.RegisterDownload(ctx, HashToken(token), e.nowText())
	if err != nil {
		if errors.Is(err, store.ErrDownloadLimitReached) || errors.Is(err, store.ErrNotFound) {
			return store.Link{}, fmt.Errorf("link: register download: %w", ErrNotFound)
		}
		return store.Link{}, fmt.Errorf("link: register download: %w", err)
	}
	return l, nil
}

// RegisterPackageDownload is the step-2 counterpart to the package
// page (docs/architecture/package-page-decision.md §4.1 item 3): it
// records a single download of the Link identified by linkID, but only
// after verifying that Link belongs to the message packageToken
// resolves to. Possession of the unguessable packageToken (the
// package-page bearer secret) is the authorization; linkID is a
// non-secret store row identifier that merely selects which file
// within that already-authorized package to charge — it is never the
// per-attachment bearer token, which is never persisted anywhere and
// so cannot be presented again here (CLAUDE.md invariant #5).
//
// Every failure — unknown/expired/revoked package token, linkID
// belonging to a different message, or the target link itself being
// expired/revoked/exhausted — folds into a single wrapped ErrNotFound
// (SR-125-5): callers must render one generic response for all of
// them, exactly like Resolve/ResolvePackage.
//
// The membership check (linkID belongs to the resolved message) is
// performed against a plain read (GetLinkByID) purely for
// authorization scoping; it is not itself the enforcement of
// MaxDownloads/expiry/status, which remains solely
// RegisterDownloadByID's guarded atomic UPDATE (never read-then-write,
// docs/architecture/adr-011-metadata-db.md).
func (e *Engine) RegisterPackageDownload(ctx context.Context, packageToken, linkID string) (store.Link, error) {
	ml, err := e.ResolvePackage(ctx, packageToken)
	if err != nil {
		return store.Link{}, fmt.Errorf("link: register package download: %w", err)
	}

	target, err := e.metadata.GetLinkByID(ctx, linkID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Link{}, fmt.Errorf("link: register package download: %w", ErrNotFound)
		}
		return store.Link{}, fmt.Errorf("link: register package download: %w", err)
	}
	if target.MessageID != ml.MessageID {
		return store.Link{}, fmt.Errorf("link: register package download: %w", ErrNotFound)
	}

	l, err := e.metadata.RegisterDownloadByID(ctx, linkID, e.nowText())
	if err != nil {
		if errors.Is(err, store.ErrDownloadLimitReached) || errors.Is(err, store.ErrNotFound) {
			return store.Link{}, fmt.Errorf("link: register package download: %w", ErrNotFound)
		}
		return store.Link{}, fmt.Errorf("link: register package download: %w", err)
	}
	return l, nil
}

// Revoke revokes the single link identified by its store-assigned
// linkID, recording a TypeRevoke audit event attributed to actor
// (US-7.1, ATR-190) on every outcome — including the ErrHeld/ErrNotFound
// refusal paths, so a rejected revoke attempt is itself part of the
// audit trail, not just successful ones. It refuses with a wrapped
// ErrHeld if the link is currently under legal hold
// (docs/compliance/journaling-position.md §4): the caller must lift
// the hold via an explicit, audited action before revoke can proceed.
func (e *Engine) Revoke(ctx context.Context, actor, linkID string) error {
	l, err := e.metadata.GetLinkByID(ctx, linkID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			e.recordRevokeAudit(ctx, actor, "", linkID, false, "link not found")
			return fmt.Errorf("link: revoke %q: %w", linkID, ErrNotFound)
		}
		e.recordRevokeAudit(ctx, actor, "", linkID, false, err.Error())
		return fmt.Errorf("link: revoke %q: %w", linkID, err)
	}
	if l.Hold {
		e.recordRevokeAudit(ctx, actor, l.MessageID, linkID, false, "link is under legal hold")
		return fmt.Errorf("link: revoke %q: %w", linkID, ErrHeld)
	}

	if err := e.metadata.RevokeLink(ctx, linkID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			e.recordRevokeAudit(ctx, actor, l.MessageID, linkID, false, "link not found")
			return fmt.Errorf("link: revoke %q: %w", linkID, ErrNotFound)
		}
		e.recordRevokeAudit(ctx, actor, l.MessageID, linkID, false, err.Error())
		return fmt.Errorf("link: revoke %q: %w", linkID, err)
	}
	e.recordRevokeAudit(ctx, actor, l.MessageID, linkID, true, "")
	return nil
}

// RevokeMessage revokes every link belonging to messageID, skipping
// (leaving active) any link currently under legal hold, and records a
// single TypeRevoke audit event summarizing the outcome (US-7.1,
// ATR-190). It returns both the number of links actually revoked and
// the number skipped due to hold, so a caller (the CLI, or the
// RevokeByMessageResult DTO in internal/adapters/http) can report a
// partial revoke's held count precisely rather than only learning
// "some link was held" from the wrapped ErrHeld. If at least one link
// was skipped due to hold, RevokeMessage returns a wrapped ErrHeld
// alongside both counts, so the caller can report a partial revoke
// distinctly from a clean one (docs/compliance/journaling-position.md
// §4).
func (e *Engine) RevokeMessage(ctx context.Context, actor, messageID string) (revoked, held int, err error) {
	total, err := e.metadata.ListLinksByMessage(ctx, messageID)
	if err != nil {
		e.recordAudit(ctx, audit.Event{
			Type:      audit.TypeRevoke,
			Actor:     actor,
			MessageID: messageID,
			Details:   map[string]any{"scope": "message", "error": err.Error()},
		})
		return 0, 0, fmt.Errorf("link: revoke message %q: %w", messageID, err)
	}

	for _, l := range total {
		if l.Hold && l.Status == store.LinkStatusActive {
			held++
		}
	}

	revoked, err = e.metadata.RevokeLinksByMessage(ctx, messageID)
	if err != nil {
		e.recordAudit(ctx, audit.Event{
			Type:      audit.TypeRevoke,
			Actor:     actor,
			MessageID: messageID,
			Details:   map[string]any{"scope": "message", "error": err.Error()},
		})
		return 0, 0, fmt.Errorf("link: revoke message %q: %w", messageID, err)
	}

	e.recordAudit(ctx, audit.Event{
		Type:      audit.TypeRevoke,
		Actor:     actor,
		MessageID: messageID,
		Details:   map[string]any{"scope": "message", "revoked": revoked, "held": held},
	})

	if held > 0 {
		return revoked, held, fmt.Errorf("link: revoke message %q: %d link(s) skipped: %w", messageID, held, ErrHeld)
	}
	return revoked, held, nil
}

// RevokeSender revokes every link belonging to every message sent by
// sender. It is a thin convenience wrapper: the caller (API/CLI layer)
// is expected to already have resolved which message IDs belong to
// sender via a messages listing; Engine itself does not expose a
// by-sender query on links directly since that fan-out belongs at the
// message level (US-6.3 revoke-by-sender). Each constituent message's
// revoke is already audited individually by RevokeMessage; RevokeSender
// does not additionally record its own summary event, to avoid
// double-counting a single sender-scoped operator action as N+1
// audit rows for the same intent.
func (e *Engine) RevokeSender(ctx context.Context, actor string, messageIDs []string) (revoked int, heldMessages int, err error) {
	for _, id := range messageIDs {
		n, _, err := e.RevokeMessage(ctx, actor, id)
		revoked += n
		if err != nil {
			if errors.Is(err, ErrHeld) {
				heldMessages++
				continue
			}
			return revoked, heldMessages, fmt.Errorf("link: revoke sender: message %q: %w", id, err)
		}
	}
	if heldMessages > 0 {
		return revoked, heldMessages, fmt.Errorf("link: revoke sender: %d message(s) had held links: %w", heldMessages, ErrHeld)
	}
	return revoked, heldMessages, nil
}

// recordRevokeAudit records a single-link Revoke outcome as a
// TypeRevoke event, folding success/failure and the reason into
// Details so the untrusted/diagnostic reason string never influences
// query structure (SR-128-2).
func (e *Engine) recordRevokeAudit(ctx context.Context, actor, messageID, linkID string, ok bool, reason string) {
	details := map[string]any{"scope": "link", "link_id": linkID, "ok": ok}
	if reason != "" {
		details["reason"] = reason
	}
	e.recordAudit(ctx, audit.Event{
		Type:      audit.TypeRevoke,
		Actor:     actor,
		MessageID: messageID,
		Details:   details,
	})
}

// SetHold sets (hold=true) or clears (hold=false) the legal-hold flag
// on the link identified by linkID, recording a TypeHold audit event
// attributed to actor on every outcome — including the not-found
// refusal path — so a hold change is itself part of the audit trail
// regardless of success (ATR-257, SR-128-2,
// docs/compliance/journaling-position.md §4: lifting a hold must be an
// audited action by an authorized actor). While Hold is true, Revoke/
// RevokeMessage/RevokeSender refuse with ErrHeld for this link until an
// authorized actor clears it via another SetHold call with hold=false.
func (e *Engine) SetHold(ctx context.Context, actor, linkID string, hold bool) error {
	l, err := e.metadata.GetLinkByID(ctx, linkID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			e.recordHoldAudit(ctx, actor, "", linkID, hold, false, "link not found")
			return fmt.Errorf("link: set hold %q: %w", linkID, ErrNotFound)
		}
		e.recordHoldAudit(ctx, actor, "", linkID, hold, false, err.Error())
		return fmt.Errorf("link: set hold %q: %w", linkID, err)
	}

	if err := e.metadata.SetHold(ctx, linkID, hold, actor, e.nowText()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			e.recordHoldAudit(ctx, actor, l.MessageID, linkID, hold, false, "link not found")
			return fmt.Errorf("link: set hold %q: %w", linkID, ErrNotFound)
		}
		e.recordHoldAudit(ctx, actor, l.MessageID, linkID, hold, false, err.Error())
		return fmt.Errorf("link: set hold %q: %w", linkID, err)
	}

	e.recordHoldAudit(ctx, actor, l.MessageID, linkID, hold, true, "")
	return nil
}

// recordHoldAudit records a single-link SetHold outcome as a TypeHold
// event, mirroring recordRevokeAudit's ok/reason Details shape so both
// event families are consistent for a downstream SIEM/export consumer
// (SR-128-2: reason is a diagnostic string, always carried in Details,
// never concatenated into a query).
func (e *Engine) recordHoldAudit(ctx context.Context, actor, messageID, linkID string, hold, ok bool, reason string) {
	details := map[string]any{"link_id": linkID, "hold": hold, "ok": ok}
	if reason != "" {
		details["reason"] = reason
	}
	e.recordAudit(ctx, audit.Event{
		Type:      audit.TypeHold,
		Actor:     actor,
		MessageID: messageID,
		Details:   details,
	})
}
