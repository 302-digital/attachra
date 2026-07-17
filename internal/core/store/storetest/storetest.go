// Package storetest provides a contract test suite shared by every
// store.MetadataStore implementation (ATR-182, mirroring the
// internal/core/storage/storagetest pattern for storage.Driver). MVP
// ships only the sqlite implementation, but ADR-011 commits to a
// Postgres implementation in v0.2; storetest.Run lets that future
// driver be exercised against the exact same behavioral contract
// without duplicating test logic.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
)

// Run executes the full contract test suite against st, a freshly
// migrated, empty MetadataStore.
func Run(t *testing.T, st store.MetadataStore) {
	t.Helper()

	t.Run("MessageAttachmentLinkRoundTrip", func(t *testing.T) { testRoundTrip(t, st) })
	t.Run("GetMissingReturnsErrNotFound", func(t *testing.T) { testGetMissing(t, st) })
	t.Run("RegisterDownloadEnforcesLimit", func(t *testing.T) { testRegisterDownloadLimit(t, st) })
	t.Run("RegisterDownloadRejectsExpired", func(t *testing.T) { testRegisterDownloadExpired(t, st) })
	t.Run("RegisterDownloadByIDEnforcesLimit", func(t *testing.T) { testRegisterDownloadByIDLimit(t, st) })
	t.Run("RegisterDownloadByIDConcurrentRespectsLimit", func(t *testing.T) { testRegisterDownloadByIDConcurrent(t, st) })
	t.Run("RevokeLinksByMessageCascades", func(t *testing.T) { testRevokeCascade(t, st) })
	t.Run("RevokeLinksByMessageSkipsHeld", func(t *testing.T) { testRevokeSkipsHeld(t, st) })
	t.Run("ListMessagesBySender", func(t *testing.T) { testListMessagesBySender(t, st) })
	t.Run("ListLinksFiltersAndPaginates", func(t *testing.T) { testListLinks(t, st) })
	t.Run("ListMessagesFiltersAndPaginates", func(t *testing.T) { testListMessages(t, st) })
	t.Run("GetMessageSummaryAggregatesRecipientsAndAttachments", func(t *testing.T) { testGetMessageSummary(t, st) })
	t.Run("ListAttachmentsFiltersAndPaginates", func(t *testing.T) { testListAttachments(t, st) })
	t.Run("ListExpiredAttachmentsExcludesHeldAndFuture", func(t *testing.T) { testListExpiredAttachments(t, st) })
	t.Run("ListExpiredAttachmentsRespectsLimit", func(t *testing.T) { testListExpiredAttachmentsLimit(t, st) })
	t.Run("DeleteAttachmentCascadesLinksAndIsIdempotent", func(t *testing.T) { testDeleteAttachment(t, st) })
	t.Run("DeleteAttachmentRefusesHeldAttachment", func(t *testing.T) { testDeleteAttachmentRefusesHeld(t, st) })
	t.Run("DeleteMessageCascadesAttachmentsLinksAndIsIdempotent", func(t *testing.T) { testDeleteMessage(t, st) })
	t.Run("DeleteMessageRefusesHeldLink", func(t *testing.T) { testDeleteMessageRefusesHeld(t, st) })
	t.Run("IsAttachmentHeld", func(t *testing.T) { testIsAttachmentHeld(t, st) })
	t.Run("ExpireStaleLinksMarksPastExpiry", func(t *testing.T) { testExpireStaleLinks(t, st) })
}

// seedMessage creates a Message + one Attachment for it, returning
// their IDs.
func seedMessage(t *testing.T, ctx context.Context, st store.MetadataStore, id string) (messageID, attachmentID string) {
	t.Helper()

	messageID = id
	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      messageID,
		QueueID: "queue-" + id,
		Sender:  "sender@example.com",
	}); err != nil {
		t.Fatalf("CreateMessage() error = %v, want nil", err)
	}

	attachmentID = id + "-att"
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    messageID,
		PartRef:      "2",
		Filename:     "report.pdf",
		DeclaredType: "application/pdf",
		DetectedType: "application/pdf",
		Size:         1024,
		StorageKey:   "ab/abc123",
	}); err != nil {
		t.Fatalf("CreateAttachment() error = %v, want nil", err)
	}

	return messageID, attachmentID
}

// seedMessageWithSender is seedMessage with a caller-chosen Sender,
// for tests (testListMessages) that need several messages grouped
// under a distinct sender rather than seedMessage's fixed
// "sender@example.com".
func seedMessageWithSender(t *testing.T, ctx context.Context, st store.MetadataStore, id, sender string) (messageID, attachmentID string) {
	t.Helper()

	messageID = id
	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      messageID,
		QueueID: "queue-" + id,
		Sender:  sender,
	}); err != nil {
		t.Fatalf("CreateMessage() error = %v, want nil", err)
	}

	attachmentID = id + "-att"
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    messageID,
		PartRef:      "2",
		Filename:     "report.pdf",
		DeclaredType: "application/pdf",
		DetectedType: "application/pdf",
		Size:         1024,
		StorageKey:   "ab/abc123",
	}); err != nil {
		t.Fatalf("CreateAttachment() error = %v, want nil", err)
	}

	return messageID, attachmentID
}

func testRoundTrip(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-roundtrip")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	tokenHash := "hash-roundtrip"

	if err := st.CreateLink(ctx, store.NewLinkParams{
		ID:           "link-roundtrip",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    tokenHash,
		ExpiresAt:    expiresAt,
		MaxDownloads: 3,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	got, err := st.GetLinkByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetLinkByTokenHash() error = %v, want nil", err)
	}
	if got.MessageID != messageID || got.AttachmentID != attachmentID {
		t.Errorf("GetLinkByTokenHash() = %+v, want message %q attachment %q", got, messageID, attachmentID)
	}
	if got.Status != store.LinkStatusActive {
		t.Errorf("GetLinkByTokenHash().Status = %q, want %q", got.Status, store.LinkStatusActive)
	}
	if got.Hold {
		t.Errorf("GetLinkByTokenHash().Hold = true, want false for a freshly created link")
	}
	if got.Downloads != 0 {
		t.Errorf("GetLinkByTokenHash().Downloads = %d, want 0", got.Downloads)
	}

	if err := st.CreateMessageLink(ctx, store.NewMessageLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		TokenHash: "msg-token-roundtrip",
		MessageID: messageID,
		Recipient: "recipient@example.com",
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("CreateMessageLink() error = %v, want nil", err)
	}

	ml, err := st.GetMessageLinkByTokenHash(ctx, "msg-token-roundtrip")
	if err != nil {
		t.Fatalf("GetMessageLinkByTokenHash() error = %v, want nil", err)
	}
	if ml.MessageID != messageID {
		t.Errorf("GetMessageLinkByTokenHash().MessageID = %q, want %q", ml.MessageID, messageID)
	}

	links, err := st.ListLinksByMessage(ctx, messageID)
	if err != nil {
		t.Fatalf("ListLinksByMessage() error = %v, want nil", err)
	}
	if len(links) != 1 || links[0].TokenHash != tokenHash {
		t.Errorf("ListLinksByMessage() = %+v, want exactly one link with token hash %q", links, tokenHash)
	}
}

func testGetMissing(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()

	if _, err := st.GetLinkByTokenHash(ctx, "does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetLinkByTokenHash() error = %v, want wrapping ErrNotFound", err)
	}
	if _, err := st.GetMessageLinkByTokenHash(ctx, "does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetMessageLinkByTokenHash() error = %v, want wrapping ErrNotFound", err)
	}
	if _, err := st.GetMessage(ctx, "does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetMessage() error = %v, want wrapping ErrNotFound", err)
	}
	if _, err := st.GetAttachment(ctx, "does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetAttachment() error = %v, want wrapping ErrNotFound", err)
	}
}

func testRegisterDownloadLimit(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-dl-limit")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	tokenHash := "hash-dl-limit" //nolint:gosec // test fixture placeholder hash, not a credential

	if err := st.CreateLink(ctx, store.NewLinkParams{
		ID:           "link-dl-limit",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    tokenHash,
		ExpiresAt:    expiresAt,
		MaxDownloads: 3,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	for i := 0; i < 3; i++ {
		if _, err := st.RegisterDownload(ctx, tokenHash, now); err != nil {
			t.Fatalf("RegisterDownload() call %d error = %v, want nil", i+1, err)
		}
	}

	if _, err := st.RegisterDownload(ctx, tokenHash, now); !errors.Is(err, store.ErrDownloadLimitReached) {
		t.Errorf("RegisterDownload() 4th call error = %v, want wrapping ErrDownloadLimitReached", err)
	}

	got, err := st.GetLinkByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetLinkByTokenHash() error = %v, want nil", err)
	}
	if got.Downloads != 3 {
		t.Errorf("Downloads = %d, want 3 (limit must not be exceeded)", got.Downloads)
	}
}

func testRegisterDownloadExpired(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-dl-expired")

	pastExpiry := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)
	tokenHash := "hash-dl-expired" //nolint:gosec // test fixture placeholder hash, not a credential

	if err := st.CreateLink(ctx, store.NewLinkParams{
		ID:           "link-dl-expired",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    tokenHash,
		ExpiresAt:    pastExpiry,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.RegisterDownload(ctx, tokenHash, now); !errors.Is(err, store.ErrDownloadLimitReached) {
		t.Errorf("RegisterDownload() on expired link error = %v, want wrapping ErrDownloadLimitReached", err)
	}
}

func testRegisterDownloadByIDLimit(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-dl-id-limit")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	linkID := "link-dl-id-limit"

	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           linkID,
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-dl-id-limit",
		ExpiresAt:    expiresAt,
		MaxDownloads: 2,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	for i := 0; i < 2; i++ {
		if _, err := st.RegisterDownloadByID(ctx, linkID, now); err != nil {
			t.Fatalf("RegisterDownloadByID() call %d error = %v, want nil", i+1, err)
		}
	}

	if _, err := st.RegisterDownloadByID(ctx, linkID, now); !errors.Is(err, store.ErrDownloadLimitReached) {
		t.Errorf("RegisterDownloadByID() 3rd call error = %v, want wrapping ErrDownloadLimitReached", err)
	}

	got, err := st.GetLinkByID(ctx, linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != 2 {
		t.Errorf("Downloads = %d, want 2 (limit must not be exceeded)", got.Downloads)
	}

	if _, err := st.RegisterDownloadByID(ctx, "does-not-exist", now); !errors.Is(err, store.ErrDownloadLimitReached) {
		t.Errorf("RegisterDownloadByID() on unknown id error = %v, want wrapping ErrDownloadLimitReached", err)
	}
}

// testRegisterDownloadByIDConcurrent hammers a single link's download
// budget from many goroutines at once, asserting the guarded atomic
// UPDATE (not a read-then-write race) is what enforces MaxDownloads:
// exactly MaxDownloads calls must succeed regardless of how many race
// to increment concurrently. Run with -race (critical counters must be
// race-safe).
func testRegisterDownloadByIDConcurrent(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-dl-id-concurrent")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	linkID := "link-dl-id-concurrent"
	const limit = 5
	const attempts = 20

	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           linkID,
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-dl-id-concurrent",
		ExpiresAt:    expiresAt,
		MaxDownloads: limit,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := st.RegisterDownloadByID(ctx, linkID, now)
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
				return
			}
			if !errors.Is(err, store.ErrDownloadLimitReached) {
				t.Errorf("RegisterDownloadByID() error = %v, want nil or wrapping ErrDownloadLimitReached", err)
			}
		}()
	}
	wg.Wait()

	if successes != limit {
		t.Errorf("successful RegisterDownloadByID() calls = %d, want exactly %d (MaxDownloads must never be exceeded under concurrency)", successes, limit)
	}

	got, err := st.GetLinkByID(ctx, linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != limit {
		t.Errorf("Downloads = %d, want %d", got.Downloads, limit)
	}
}

func testRevokeCascade(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-revoke-cascade")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)

	for i, hash := range []string{"hash-cascade-1", "hash-cascade-2"} {
		if err := st.CreateLink(ctx, store.NewLinkParams{
			ID:           "link-cascade-" + hash,
			MessageID:    messageID,
			AttachmentID: attachmentID,
			Recipient:    "recipient@example.com",
			TokenHash:    hash,
			ExpiresAt:    expiresAt,
			MaxDownloads: 0,
		}); err != nil {
			t.Fatalf("CreateLink() #%d error = %v, want nil", i, err)
		}
	}

	if err := st.CreateMessageLink(ctx, store.NewMessageLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		TokenHash: "msg-token-cascade",
		MessageID: messageID,
		Recipient: "recipient@example.com",
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("CreateMessageLink() error = %v, want nil", err)
	}

	revoked, err := st.RevokeLinksByMessage(ctx, messageID)
	if err != nil {
		t.Fatalf("RevokeLinksByMessage() error = %v, want nil", err)
	}
	if revoked != 2 {
		t.Errorf("RevokeLinksByMessage() revoked = %d, want 2", revoked)
	}

	links, err := st.ListLinksByMessage(ctx, messageID)
	if err != nil {
		t.Fatalf("ListLinksByMessage() error = %v, want nil", err)
	}
	for _, l := range links {
		if l.Status != store.LinkStatusRevoked {
			t.Errorf("link %q Status = %q after cascade revoke, want %q", l.ID, l.Status, store.LinkStatusRevoked)
		}
	}

	ml, err := st.GetMessageLinkByTokenHash(ctx, "msg-token-cascade")
	if err != nil {
		t.Fatalf("GetMessageLinkByTokenHash() error = %v, want nil", err)
	}
	if ml.Status != store.LinkStatusRevoked {
		t.Errorf("MessageLink.Status = %q after cascade revoke, want %q", ml.Status, store.LinkStatusRevoked)
	}
}

func testRevokeSkipsHeld(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-revoke-held")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)

	heldID := "link-held"
	if err := st.CreateLink(ctx, store.NewLinkParams{
		ID:           heldID,
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-held",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	notHeldID := "link-not-held"
	if err := st.CreateLink(ctx, store.NewLinkParams{
		ID:           notHeldID,
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient2@example.com",
		TokenHash:    "hash-not-held",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	setAt := time.Now().UTC().Format(time.RFC3339Nano)
	if err := st.SetHold(ctx, heldID, true, "compliance-officer", setAt); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	revoked, err := st.RevokeLinksByMessage(ctx, messageID)
	if err != nil {
		t.Fatalf("RevokeLinksByMessage() error = %v, want nil", err)
	}
	if revoked != 1 {
		t.Errorf("RevokeLinksByMessage() revoked = %d, want 1 (held link must be skipped)", revoked)
	}

	held, err := st.GetLinkByTokenHash(ctx, "hash-held")
	if err != nil {
		t.Fatalf("GetLinkByTokenHash(held) error = %v, want nil", err)
	}
	if held.Status != store.LinkStatusActive {
		t.Errorf("held link Status = %q after cascade revoke, want still %q", held.Status, store.LinkStatusActive)
	}
	if !held.Hold {
		t.Errorf("held link Hold = false, want true to remain set")
	}

	notHeld, err := st.GetLinkByTokenHash(ctx, "hash-not-held")
	if err != nil {
		t.Fatalf("GetLinkByTokenHash(not held) error = %v, want nil", err)
	}
	if notHeld.Status != store.LinkStatusRevoked {
		t.Errorf("non-held link Status = %q after cascade revoke, want %q", notHeld.Status, store.LinkStatusRevoked)
	}
}

// testListMessagesBySender verifies ListMessagesBySender returns every
// Message for an exact sender match, in creation order, and an empty
// (not error) result for a sender with no messages (ATR-258,
// US-6.3 revoke-by-sender).
func testListMessagesBySender(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	sender := "sender-bysender@example.com"

	for _, id := range []string{"msg-bysender-1", "msg-bysender-2"} {
		if err := st.CreateMessage(ctx, store.NewMessageParams{
			ID:      id,
			QueueID: "queue-" + id,
			Sender:  sender,
		}); err != nil {
			t.Fatalf("CreateMessage(%q) error = %v, want nil", id, err)
		}
	}
	// A message from a different sender must not be included.
	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      "msg-bysender-other",
		QueueID: "queue-msg-bysender-other",
		Sender:  "someone-else@example.com",
	}); err != nil {
		t.Fatalf("CreateMessage(other sender) error = %v, want nil", err)
	}

	got, err := st.ListMessagesBySender(ctx, sender)
	if err != nil {
		t.Fatalf("ListMessagesBySender(%q) error = %v, want nil", sender, err)
	}
	if len(got) != 2 {
		t.Fatalf("ListMessagesBySender(%q) returned %d messages, want 2: %+v", sender, len(got), got)
	}
	for _, m := range got {
		if m.Sender != sender {
			t.Errorf("ListMessagesBySender(%q) returned message %q with Sender = %q", sender, m.ID, m.Sender)
		}
	}

	none, err := st.ListMessagesBySender(ctx, "no-such-sender@example.com")
	if err != nil {
		t.Fatalf("ListMessagesBySender(unknown sender) error = %v, want nil", err)
	}
	if len(none) != 0 {
		t.Errorf("ListMessagesBySender(unknown sender) = %+v, want empty", none)
	}

	// ATR-293 (closing the ATR-258 review's N1 finding): every write
	// path now stores the sender in mail.NormalizeAddress's canonical
	// form (milter ingest normalizes it; see
	// internal/adapters/milter/backend.go's MailFrom), so a message
	// recorded exactly like that — lower-case, bracket-free, as
	// "alice-bysender@example.com" below — must still be found by a
	// revoke-by-sender query typed with different case and/or SMTP
	// angle brackets (an operator pasting an address straight out of a
	// raw mail log). ListMessagesBySender normalizes its own argument
	// via mail.NormalizeAddress before matching, which is what makes
	// this work. (Legacy rows written before this fix, in the raw
	// unnormalized shape itself, are covered separately by migration
	// 000007 — see TestMigration000007NormalizesExistingAddresses in
	// package sqlite, which seeds exactly that shape and asserts the
	// migration cleans it up.)
	canonicalSender := "alice-bysender@example.com"
	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      "msg-bysender-canonical",
		QueueID: "queue-msg-bysender-canonical",
		Sender:  canonicalSender,
	}); err != nil {
		t.Fatalf("CreateMessage(canonical sender) error = %v, want nil", err)
	}

	byBracketedQuery, err := st.ListMessagesBySender(ctx, "<Alice-Bysender@EXAMPLE.com>")
	if err != nil {
		t.Fatalf("ListMessagesBySender(bracketed, mixed-case query) error = %v, want nil", err)
	}
	if len(byBracketedQuery) != 1 || byBracketedQuery[0].ID != "msg-bysender-canonical" {
		t.Fatalf("ListMessagesBySender(bracketed, mixed-case query) = %+v, want exactly [msg-bysender-canonical] (stored as %q)",
			byBracketedQuery, canonicalSender)
	}
}

// testListLinks verifies ListLinks' filters (message_id, recipient,
// status) and its opaque cursor pagination (US-8.1/T-8.1.3,
// api/openapi.yaml `GET /links`), mirroring the keyset-pagination
// contract ListAPITokens already exercises: every link is seen exactly
// once across pages, and an invalid cursor is reported distinctly via
// ErrInvalidCursor rather than folded into a generic failure.
func testListLinks(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-list-links")
	otherMessageID, otherAttachmentID := seedMessage(t, ctx, st, "msg-list-links-other")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)

	// Three links on messageID: two for recipient-a, one for
	// recipient-b; one of recipient-a's links is later revoked so the
	// status filter has something to distinguish.
	for i, rec := range []string{"recipient-a@example.com", "recipient-a@example.com", "recipient-b@example.com"} {
		id := fmt.Sprintf("link-list-%d", i)
		if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
			ID:           id,
			MessageID:    messageID,
			AttachmentID: attachmentID,
			Recipient:    rec,
			TokenHash:    "hash-list-" + id,
			ExpiresAt:    expiresAt,
			MaxDownloads: 0,
		}); err != nil {
			t.Fatalf("CreateLink(%d) error = %v, want nil", i, err)
		}
	}
	if err := st.RevokeLink(ctx, "link-list-0"); err != nil {
		t.Fatalf("RevokeLink() error = %v, want nil", err)
	}

	// One link on a different message, so the message_id filter has
	// something to exclude.
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-list-other",
		MessageID:    otherMessageID,
		AttachmentID: otherAttachmentID,
		Recipient:    "recipient-c@example.com",
		TokenHash:    "hash-list-other",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink(other message) error = %v, want nil", err)
	}

	// message_id filter: only the three links on messageID.
	page, err := st.ListLinks(ctx, store.LinkListParams{MessageID: messageID, Limit: 100})
	if err != nil {
		t.Fatalf("ListLinks(message_id) error = %v, want nil", err)
	}
	if len(page.Links) != 3 {
		t.Fatalf("ListLinks(message_id) returned %d links, want 3: %+v", len(page.Links), page.Links)
	}

	// recipient filter: exact, case-insensitive match.
	page, err = st.ListLinks(ctx, store.LinkListParams{MessageID: messageID, Recipient: "RECIPIENT-A@EXAMPLE.COM", Limit: 100})
	if err != nil {
		t.Fatalf("ListLinks(recipient) error = %v, want nil", err)
	}
	if len(page.Links) != 2 {
		t.Errorf("ListLinks(recipient, case-insensitive) returned %d links, want 2: %+v", len(page.Links), page.Links)
	}

	// status filter: only the one revoked link.
	page, err = st.ListLinks(ctx, store.LinkListParams{MessageID: messageID, Status: store.LinkStatusRevoked, Limit: 100})
	if err != nil {
		t.Fatalf("ListLinks(status) error = %v, want nil", err)
	}
	if len(page.Links) != 1 || page.Links[0].ID != "link-list-0" {
		t.Errorf("ListLinks(status=revoked) = %+v, want exactly link-list-0", page.Links)
	}

	// Pagination: page through messageID's 3 links one at a time,
	// following NextCursor, and confirm every link is seen exactly
	// once with no repeats or gaps (the correctness property opaque
	// keyset pagination exists for).
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		p, err := st.ListLinks(ctx, store.LinkListParams{MessageID: messageID, Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListLinks(paginated) page %d error = %v, want nil", i, err)
		}
		if len(p.Links) != 1 {
			t.Fatalf("ListLinks(paginated) page %d returned %d links, want 1", i, len(p.Links))
		}
		if seen[p.Links[0].ID] {
			t.Fatalf("ListLinks(paginated) repeated link %q", p.Links[0].ID)
		}
		seen[p.Links[0].ID] = true
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if len(seen) != 3 {
		t.Errorf("ListLinks(paginated) saw %d distinct links, want 3: %+v", len(seen), seen)
	}

	// An invalid cursor is reported distinctly from any other failure.
	if _, err := st.ListLinks(ctx, store.LinkListParams{Cursor: "not-a-real-cursor"}); !errors.Is(err, store.ErrInvalidCursor) {
		t.Errorf("ListLinks(invalid cursor) error = %v, want wrapping ErrInvalidCursor", err)
	}
}

// seedAttachmentWithRetention creates a Message + one Attachment for it
// with the given RetainUntil (RFC3339Nano UTC, or "" for the legacy
// no-retention sentinel), returning their IDs (ATR-178/179).
func seedAttachmentWithRetention(t *testing.T, ctx context.Context, st store.MetadataStore, id, retainUntil string) (messageID, attachmentID string) {
	t.Helper()

	messageID = id
	if err := st.CreateMessage(ctx, store.NewMessageParams{
		ID:      messageID,
		QueueID: "queue-" + id,
		Sender:  "sender@example.com",
	}); err != nil {
		t.Fatalf("CreateMessage() error = %v, want nil", err)
	}

	attachmentID = id + "-att"
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID:           attachmentID,
		MessageID:    messageID,
		PartRef:      "2",
		Filename:     "report.pdf",
		DeclaredType: "application/pdf",
		DetectedType: "application/pdf",
		Size:         1024,
		StorageKey:   "ab/" + id,
		RetainUntil:  retainUntil,
	}); err != nil {
		t.Fatalf("CreateAttachment() error = %v, want nil", err)
	}

	return messageID, attachmentID
}

// testListExpiredAttachments covers ATR-178/179's core contract:
// ListExpiredAttachments returns attachments whose retention has
// elapsed, excludes attachments with a still-future RetainUntil,
// excludes legacy rows with an empty RetainUntil, and — critically for
// ATR-259 — excludes an expired attachment entirely at the query level
// when any of its links is under legal hold, never relying on the
// caller to filter a held row out afterward.
// CountHeldExpiredAttachments must report exactly the complementary
// count.
func testListExpiredAttachments(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour).Format(time.RFC3339Nano)
	future := now.Add(1 * time.Hour).Format(time.RFC3339Nano)
	nowText := now.Format(time.RFC3339Nano)

	_, expiredID := seedAttachmentWithRetention(t, ctx, st, "msg-exp-past", past)
	_, futureID := seedAttachmentWithRetention(t, ctx, st, "msg-exp-future", future)
	_, heldID := seedAttachmentWithRetention(t, ctx, st, "msg-exp-held", past)
	_, legacyID := seedAttachmentWithRetention(t, ctx, st, "msg-exp-legacy", "")

	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-exp-held",
		MessageID:    "msg-exp-held",
		AttachmentID: heldID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-exp-held",
		ExpiresAt:    future,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}
	if err := st.SetHold(ctx, "link-exp-held", true, "compliance-officer", nowText); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	got, err := st.ListExpiredAttachments(ctx, nowText, 100)
	if err != nil {
		t.Fatalf("ListExpiredAttachments() error = %v, want nil", err)
	}

	ids := map[string]bool{}
	for _, a := range got {
		ids[a.ID] = true
	}
	if !ids[expiredID] {
		t.Errorf("ListExpiredAttachments() missing expired, non-held attachment %q: %+v", expiredID, got)
	}
	if ids[futureID] {
		t.Errorf("ListExpiredAttachments() unexpectedly included attachment %q with future RetainUntil", futureID)
	}
	if ids[heldID] {
		t.Errorf("ListExpiredAttachments() unexpectedly included held attachment %q (ATR-259 requires SQL-level exclusion)", heldID)
	}
	if ids[legacyID] {
		t.Errorf("ListExpiredAttachments() unexpectedly included legacy attachment %q with empty RetainUntil", legacyID)
	}

	heldCount, err := st.CountHeldExpiredAttachments(ctx, nowText)
	if err != nil {
		t.Fatalf("CountHeldExpiredAttachments() error = %v, want nil", err)
	}
	if heldCount != 1 {
		t.Errorf("CountHeldExpiredAttachments() = %d, want 1", heldCount)
	}
}

// testListExpiredAttachmentsLimit verifies limit is honored, so a
// caller (internal/core/retention) can safely chunk a large sweep
// (ADR-011's "chunked DELETE" guidance) without ever loading every
// expired attachment at once (the streaming invariant).
func testListExpiredAttachmentsLimit(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	past := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)

	for i := 0; i < 3; i++ {
		seedAttachmentWithRetention(t, ctx, st, fmt.Sprintf("msg-exp-limit-%d", i), past)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	got, err := st.ListExpiredAttachments(ctx, now, 2)
	if err != nil {
		t.Fatalf("ListExpiredAttachments() error = %v, want nil", err)
	}
	if len(got) != 2 {
		t.Errorf("ListExpiredAttachments(limit=2) returned %d rows, want 2", len(got))
	}
}

// testDeleteAttachment covers SR-123-2's "consistent" requirement:
// deleting an Attachment also removes every Link row referencing it
// (the FK from links.attachment_id has no ON DELETE behavior, so a
// caller must never be able to observe one without the other), leaves
// the parent Message row untouched, and is idempotent (a retry after
// the row is already gone returns ErrNotFound rather than succeeding
// silently a second time or erroring in some other way).
func testDeleteAttachment(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-delete-att")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-delete-att",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-delete-att",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	if err := st.DeleteAttachment(ctx, attachmentID); err != nil {
		t.Fatalf("DeleteAttachment() error = %v, want nil", err)
	}

	if _, err := st.GetAttachment(ctx, attachmentID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetAttachment() after delete error = %v, want wrapping ErrNotFound", err)
	}
	if _, err := st.GetLinkByTokenHash(ctx, "hash-delete-att"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetLinkByTokenHash() after attachment delete error = %v, want wrapping ErrNotFound (cascade)", err)
	}

	if err := st.DeleteAttachment(ctx, attachmentID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second DeleteAttachment() (idempotent retry) error = %v, want wrapping ErrNotFound", err)
	}

	if _, err := st.GetMessage(ctx, messageID); err != nil {
		t.Errorf("GetMessage() after attachment delete error = %v, want nil (message row must survive)", err)
	}
}

// testDeleteAttachmentRefusesHeld covers the ATR-259 security-review
// fix (B1): DeleteAttachment's guarded DELETE must refuse to remove an
// attachment that has a held link, returning a wrapped ErrHeld, and
// must leave BOTH the attachment row and every one of its links
// completely untouched — never partially pruning the non-held links of
// a held attachment. This is the store-layer's own authoritative check,
// independent of whatever a caller did or didn't verify beforehand
// (ListExpiredAttachments already excludes held attachments at list
// time, but a hold can be set later, in the window before a specific
// attachment's turn to be deleted — this test exercises DeleteAttachment
// being called directly against a held attachment, as if that window
// had elapsed).
func testDeleteAttachmentRefusesHeld(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-delete-att-held")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-delete-att-held",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-delete-att-held",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}
	if err := st.SetHold(ctx, "link-delete-att-held", true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	if err := st.DeleteAttachment(ctx, attachmentID); !errors.Is(err, store.ErrHeld) {
		t.Errorf("DeleteAttachment(held) error = %v, want wrapping ErrHeld", err)
	}

	if _, err := st.GetAttachment(ctx, attachmentID); err != nil {
		t.Errorf("GetAttachment() after refused delete error = %v, want nil (held attachment must survive)", err)
	}
	if _, err := st.GetLinkByTokenHash(ctx, "hash-delete-att-held"); err != nil {
		t.Errorf("GetLinkByTokenHash() after refused delete error = %v, want nil (held link must survive)", err)
	}
}

// testDeleteMessage covers ATR-239's core contract: deleting a Message
// also removes every Attachment, Link and MessageLink row belonging to
// it (the message_id foreign keys on all three have no ON DELETE
// behavior, so a caller must never be able to observe one without the
// other), and is idempotent (a retry after the row is already gone
// returns ErrNotFound rather than succeeding silently a second time or
// erroring in some other way).
func testDeleteMessage(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-delete-msg")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-delete-msg",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-delete-msg",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}
	if err := st.CreateMessageLink(ctx, store.NewMessageLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		TokenHash: "msg-token-delete-msg",
		MessageID: messageID,
		Recipient: "recipient@example.com",
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("CreateMessageLink() error = %v, want nil", err)
	}

	if err := st.DeleteMessage(ctx, messageID); err != nil {
		t.Fatalf("DeleteMessage() error = %v, want nil", err)
	}

	if _, err := st.GetMessage(ctx, messageID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetMessage() after delete error = %v, want wrapping ErrNotFound", err)
	}
	if _, err := st.GetAttachment(ctx, attachmentID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetAttachment() after message delete error = %v, want wrapping ErrNotFound (cascade)", err)
	}
	if _, err := st.GetLinkByTokenHash(ctx, "hash-delete-msg"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetLinkByTokenHash() after message delete error = %v, want wrapping ErrNotFound (cascade)", err)
	}
	if _, err := st.GetMessageLinkByTokenHash(ctx, "msg-token-delete-msg"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetMessageLinkByTokenHash() after message delete error = %v, want wrapping ErrNotFound (cascade)", err)
	}

	if err := st.DeleteMessage(ctx, messageID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second DeleteMessage() (idempotent retry) error = %v, want wrapping ErrNotFound", err)
	}
}

// testDeleteMessageRefusesHeld covers the ATR-239 hold guard, mirroring
// testDeleteAttachmentRefusesHeld: DeleteMessage's guarded DELETE must
// refuse to remove a message that has a held link, returning a wrapped
// ErrHeld, and must leave the message row, EVERY one of its links (held
// or not), its attachments and its message_links completely untouched
// — never partially pruning the non-held links of a message that has at
// least one held one.
func testDeleteMessageRefusesHeld(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-delete-msg-held")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-delete-msg-held",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-delete-msg-held",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}
	// A second, non-held link on the same message, so the test can
	// confirm it survives too (not just the held one) — a refused
	// DeleteMessage must be a true no-op, not a partial prune of the
	// non-held links alongside a refusal to remove the held one.
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-delete-msg-not-held",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient2@example.com",
		TokenHash:    "hash-delete-msg-not-held",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink(second) error = %v, want nil", err)
	}
	if err := st.SetHold(ctx, "link-delete-msg-held", true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	if err := st.DeleteMessage(ctx, messageID); !errors.Is(err, store.ErrHeld) {
		t.Errorf("DeleteMessage(held) error = %v, want wrapping ErrHeld", err)
	}

	if _, err := st.GetMessage(ctx, messageID); err != nil {
		t.Errorf("GetMessage() after refused delete error = %v, want nil (message must survive)", err)
	}
	if _, err := st.GetAttachment(ctx, attachmentID); err != nil {
		t.Errorf("GetAttachment() after refused delete error = %v, want nil (attachment must survive)", err)
	}
	if _, err := st.GetLinkByTokenHash(ctx, "hash-delete-msg-held"); err != nil {
		t.Errorf("GetLinkByTokenHash(held) after refused delete error = %v, want nil (held link must survive)", err)
	}
	if _, err := st.GetLinkByTokenHash(ctx, "hash-delete-msg-not-held"); err != nil {
		t.Errorf("GetLinkByTokenHash(not held) after refused delete error = %v, want nil (non-held link must also survive: refusal is all-or-nothing)", err)
	}
}

// testIsAttachmentHeld covers the narrow re-check helper
// internal/core/retention.Sweeper calls immediately before a storage
// delete (ATR-259 B1 fix): it must reflect the current Hold state of
// an attachment's links, not a stale snapshot, and must not itself
// require the attachment to be otherwise expired/eligible for cleanup
// (it is a plain, unconditional read).
func testIsAttachmentHeld(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	_, attachmentID := seedMessage(t, ctx, st, "msg-is-held")

	held, err := st.IsAttachmentHeld(ctx, attachmentID)
	if err != nil {
		t.Fatalf("IsAttachmentHeld() error = %v, want nil", err)
	}
	if held {
		t.Errorf("IsAttachmentHeld() = true for an attachment with no links at all, want false")
	}

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-is-held",
		MessageID:    "msg-is-held",
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-is-held",
		ExpiresAt:    expiresAt,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	held, err = st.IsAttachmentHeld(ctx, attachmentID)
	if err != nil {
		t.Fatalf("IsAttachmentHeld() error = %v, want nil", err)
	}
	if held {
		t.Errorf("IsAttachmentHeld() = true before SetHold, want false")
	}

	if err := st.SetHold(ctx, "link-is-held", true, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold() error = %v, want nil", err)
	}

	held, err = st.IsAttachmentHeld(ctx, attachmentID)
	if err != nil {
		t.Fatalf("IsAttachmentHeld() error = %v, want nil", err)
	}
	if !held {
		t.Errorf("IsAttachmentHeld() = false after SetHold(true), want true")
	}

	if err := st.SetHold(ctx, "link-is-held", false, "compliance-officer", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("SetHold(false) error = %v, want nil", err)
	}

	held, err = st.IsAttachmentHeld(ctx, attachmentID)
	if err != nil {
		t.Fatalf("IsAttachmentHeld() error = %v, want nil", err)
	}
	if held {
		t.Errorf("IsAttachmentHeld() = true after the hold was cleared, want false")
	}
}

// testExpireStaleLinks covers the parent US-5.3 acceptance criterion
// "marks links as expired": a link past its own ExpiresAt is marked
// LinkStatusExpired, a link not yet past ExpiresAt is left
// LinkStatusActive, and a second call is a no-op (idempotent).
func testExpireStaleLinks(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-expire-links")

	past := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339Nano)

	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-expire-past",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient@example.com",
		TokenHash:    "hash-expire-past",
		ExpiresAt:    past,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID:           "link-expire-future",
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Recipient:    "recipient2@example.com",
		TokenHash:    "hash-expire-future",
		ExpiresAt:    future,
		MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink() error = %v, want nil", err)
	}

	// n itself is not asserted against an exact count: earlier subtests
	// in this shared-store suite (e.g. RegisterDownloadRejectsExpired)
	// also leave behind links whose ExpiresAt is in the past but whose
	// Status is still LinkStatusActive, so the total affected by a bulk
	// UPDATE here legitimately includes rows beyond this test's own two.
	// What matters is that this test's own past/future links land on the
	// correct side, checked below.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.ExpireStaleLinks(ctx, now); err != nil {
		t.Fatalf("ExpireStaleLinks() error = %v, want nil", err)
	}

	pastLink, err := st.GetLinkByTokenHash(ctx, "hash-expire-past")
	if err != nil {
		t.Fatalf("GetLinkByTokenHash(past) error = %v, want nil", err)
	}
	if pastLink.Status != store.LinkStatusExpired {
		t.Errorf("past link Status = %q, want %q", pastLink.Status, store.LinkStatusExpired)
	}

	futureLink, err := st.GetLinkByTokenHash(ctx, "hash-expire-future")
	if err != nil {
		t.Fatalf("GetLinkByTokenHash(future) error = %v, want nil", err)
	}
	if futureLink.Status != store.LinkStatusActive {
		t.Errorf("future link Status = %q, want %q", futureLink.Status, store.LinkStatusActive)
	}

	n2, err := st.ExpireStaleLinks(ctx, now)
	if err != nil {
		t.Fatalf("ExpireStaleLinks() second call error = %v, want nil", err)
	}
	if n2 != 0 {
		t.Errorf("ExpireStaleLinks() second call (idempotent retry) affected = %d, want 0", n2)
	}
}

// testListMessages verifies ListMessages' filters (sender, recipient,
// status, from/to) and its opaque cursor pagination (US-8.1/T-8.1.4,
// api/openapi.yaml `GET /messages`), mirroring testListLinks' own
// pagination-correctness property: every message is seen exactly once
// across pages, and an invalid cursor is reported distinctly via
// ErrInvalidCursor rather than folded into a generic failure.
func testListMessages(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	sender := "sender-listmsg@example.com"

	msg1, att1 := seedMessageWithSender(t, ctx, st, "msg-list-1", sender)
	msg2, att2 := seedMessageWithSender(t, ctx, st, "msg-list-2", sender)
	otherSenderMsg, _ := seedMessage(t, ctx, st, "msg-list-other-sender")

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	// Two links on msg1 (two distinct recipients), one on msg2, none on
	// otherSenderMsg — so the recipient filter and GetMessageSummary's
	// own aggregation both have something to distinguish.
	for i, rec := range []string{"listmsg-recipient-a@example.com", "listmsg-recipient-b@example.com"} {
		id := fmt.Sprintf("link-list-msg-%d", i)
		if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
			ID: id, MessageID: msg1, AttachmentID: att1, Recipient: rec,
			TokenHash: "hash-" + id, ExpiresAt: expiresAt, MaxDownloads: 0,
		}); err != nil {
			t.Fatalf("CreateLink(%d) error = %v, want nil", i, err)
		}
	}
	if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
		ID: "link-list-msg2", MessageID: msg2, AttachmentID: att2, Recipient: "listmsg-recipient-c@example.com",
		TokenHash: "hash-link-list-msg2", ExpiresAt: expiresAt, MaxDownloads: 0,
	}); err != nil {
		t.Fatalf("CreateLink(msg2) error = %v, want nil", err)
	}

	// sender filter: exact, case-insensitive, excludes otherSenderMsg.
	page, err := st.ListMessages(ctx, store.MessageListParams{Sender: strings.ToUpper(sender), Limit: 100})
	if err != nil {
		t.Fatalf("ListMessages(sender) error = %v, want nil", err)
	}
	if len(page.Messages) != 2 {
		t.Fatalf("ListMessages(sender, case-insensitive) returned %d messages, want 2: %+v", len(page.Messages), page.Messages)
	}
	for _, m := range page.Messages {
		if m.ID == otherSenderMsg {
			t.Errorf("ListMessages(sender) unexpectedly included message %q from a different sender", otherSenderMsg)
		}
	}

	// recipient filter: only msg1 has listmsg-recipient-a.
	page, err = st.ListMessages(ctx, store.MessageListParams{Recipient: "LISTMSG-RECIPIENT-A@EXAMPLE.COM", Limit: 100})
	if err != nil {
		t.Fatalf("ListMessages(recipient) error = %v, want nil", err)
	}
	if len(page.Messages) != 1 || page.Messages[0].ID != msg1 {
		t.Errorf("ListMessages(recipient) = %+v, want exactly %q", page.Messages, msg1)
	}

	// status filter: every seeded message defaults to the empty
	// (legacy/unknown) status via seedMessage, so filtering for
	// MessageStatusReplace must exclude all of them.
	page, err = st.ListMessages(ctx, store.MessageListParams{Status: store.MessageStatusReplace, Sender: sender, Limit: 100})
	if err != nil {
		t.Fatalf("ListMessages(status) error = %v, want nil", err)
	}
	if len(page.Messages) != 0 {
		t.Errorf("ListMessages(status=replace) = %+v, want empty (seedMessage does not set a status)", page.Messages)
	}

	// Pagination: page through sender's 2 messages one at a time,
	// following NextCursor, and confirm every message is seen exactly
	// once with no repeats or gaps.
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		p, err := st.ListMessages(ctx, store.MessageListParams{Sender: sender, Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListMessages(paginated) page %d error = %v, want nil", i, err)
		}
		if len(p.Messages) != 1 {
			t.Fatalf("ListMessages(paginated) page %d returned %d messages, want 1", i, len(p.Messages))
		}
		if seen[p.Messages[0].ID] {
			t.Fatalf("ListMessages(paginated) repeated message %q", p.Messages[0].ID)
		}
		seen[p.Messages[0].ID] = true
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if len(seen) != 2 {
		t.Errorf("ListMessages(paginated) saw %d distinct messages, want 2: %+v", len(seen), seen)
	}

	// An invalid cursor is reported distinctly from any other failure.
	if _, err := st.ListMessages(ctx, store.MessageListParams{Cursor: "not-a-real-cursor"}); !errors.Is(err, store.ErrInvalidCursor) {
		t.Errorf("ListMessages(invalid cursor) error = %v, want wrapping ErrInvalidCursor", err)
	}
}

// testGetMessageSummary verifies GetMessageSummary aggregates the
// distinct recipient set and attachment count for one message
// (api/openapi.yaml Message.recipients/attachment_count: "not a stored
// column"), and that a missing message reports ErrNotFound like every
// other Get method.
func testGetMessageSummary(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	messageID, attachmentID := seedMessage(t, ctx, st, "msg-summary")

	// A second attachment on the same message, so AttachmentCount has
	// something to count beyond 1.
	secondAttachmentID := "msg-summary-att-2"
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID: secondAttachmentID, MessageID: messageID, PartRef: "3",
		Filename: "second.pdf", DeclaredType: "application/pdf", DetectedType: "application/pdf",
		Size: 2048, StorageKey: "cd/cd1234",
	}); err != nil {
		t.Fatalf("CreateAttachment(second) error = %v, want nil", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	// Two links to the same recipient (must collapse to one distinct
	// entry) and one to a different recipient.
	for i, rec := range []string{"recipient-a@example.com", "recipient-a@example.com", "recipient-b@example.com"} {
		id := fmt.Sprintf("link-summary-%d", i)
		if err := st.CreateLink(ctx, store.NewLinkParams{ //nolint:gosec // test fixture placeholder hash, not a credential
			ID: id, MessageID: messageID, AttachmentID: attachmentID, Recipient: rec,
			TokenHash: "hash-" + id, ExpiresAt: expiresAt, MaxDownloads: 0,
		}); err != nil {
			t.Fatalf("CreateLink(%d) error = %v, want nil", i, err)
		}
	}

	summary, err := st.GetMessageSummary(ctx, messageID)
	if err != nil {
		t.Fatalf("GetMessageSummary() error = %v, want nil", err)
	}
	if summary.ID != messageID {
		t.Errorf("GetMessageSummary().ID = %q, want %q", summary.ID, messageID)
	}
	if summary.AttachmentCount != 2 {
		t.Errorf("GetMessageSummary().AttachmentCount = %d, want 2", summary.AttachmentCount)
	}
	if len(summary.Recipients) != 2 {
		t.Errorf("GetMessageSummary().Recipients = %+v, want exactly 2 distinct recipients", summary.Recipients)
	}

	if _, err := st.GetMessageSummary(ctx, "does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetMessageSummary(missing) error = %v, want wrapping ErrNotFound", err)
	}
}

// testListAttachments verifies ListAttachments' filters (message_id,
// filename glob, mime_type glob, min_size/max_size) and its opaque
// cursor pagination (US-8.1/T-8.1.4, api/openapi.yaml `GET
// /attachments`), mirroring testListLinks' own pagination-correctness
// property.
func testListAttachments(t *testing.T, st store.MetadataStore) {
	ctx := context.Background()
	// Bare CreateMessage (not seedMessage, which also creates a
	// "report.pdf" attachment of its own): this test wants exact
	// control over exactly which attachments exist per message so its
	// filter-count assertions below are unambiguous.
	messageID := "msg-list-atts"
	if err := st.CreateMessage(ctx, store.NewMessageParams{ID: messageID, QueueID: "queue-" + messageID, Sender: "sender@example.com"}); err != nil {
		t.Fatalf("CreateMessage() error = %v, want nil", err)
	}
	otherMessageID := "msg-list-atts-other"
	if err := st.CreateMessage(ctx, store.NewMessageParams{ID: otherMessageID, QueueID: "queue-" + otherMessageID, Sender: "sender@example.com"}); err != nil {
		t.Fatalf("CreateMessage(other) error = %v, want nil", err)
	}

	type seed struct {
		id, filename, mimeType string
		size                   int64
	}
	seeds := []seed{
		{"att-list-invoice", "invoice.pdf", "application/pdf", 1000},
		{"att-list-report", "report.PDF", "application/pdf", 5000},
		{"att-list-image", "photo.png", "image/png", 200000},
	}
	for _, s := range seeds {
		if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
			ID: s.id, MessageID: messageID, PartRef: "1", Filename: s.filename,
			DeclaredType: s.mimeType, DetectedType: s.mimeType, Size: s.size, StorageKey: "kk/" + s.id,
		}); err != nil {
			t.Fatalf("CreateAttachment(%q) error = %v, want nil", s.id, err)
		}
	}
	// One attachment on a different message, so the message_id filter
	// has something to exclude.
	if err := st.CreateAttachment(ctx, store.NewAttachmentParams{
		ID: "att-list-other-message", MessageID: otherMessageID, PartRef: "1",
		Filename: "invoice.pdf", DeclaredType: "application/pdf", DetectedType: "application/pdf",
		Size: 1000, StorageKey: "kk/other",
	}); err != nil {
		t.Fatalf("CreateAttachment(other message) error = %v, want nil", err)
	}

	// message_id filter: only the three attachments on messageID.
	page, err := st.ListAttachments(ctx, store.AttachmentListParams{MessageID: messageID, Limit: 100})
	if err != nil {
		t.Fatalf("ListAttachments(message_id) error = %v, want nil", err)
	}
	if len(page.Attachments) != 3 {
		t.Fatalf("ListAttachments(message_id) returned %d attachments, want 3: %+v", len(page.Attachments), page.Attachments)
	}

	// filename glob filter: case-insensitive, matches both PDFs.
	page, err = st.ListAttachments(ctx, store.AttachmentListParams{MessageID: messageID, Filename: "*.pdf", Limit: 100})
	if err != nil {
		t.Fatalf("ListAttachments(filename) error = %v, want nil", err)
	}
	if len(page.Attachments) != 2 {
		t.Errorf("ListAttachments(filename=*.pdf, case-insensitive) returned %d attachments, want 2: %+v", len(page.Attachments), page.Attachments)
	}

	// mime_type glob filter.
	page, err = st.ListAttachments(ctx, store.AttachmentListParams{MessageID: messageID, MimeType: "image/*", Limit: 100})
	if err != nil {
		t.Fatalf("ListAttachments(mime_type) error = %v, want nil", err)
	}
	if len(page.Attachments) != 1 || page.Attachments[0].ID != "att-list-image" {
		t.Errorf("ListAttachments(mime_type=image/*) = %+v, want exactly att-list-image", page.Attachments)
	}

	// min_size/max_size bounds, both inclusive.
	minSize := int64(1000)
	maxSize := int64(5000)
	page, err = st.ListAttachments(ctx, store.AttachmentListParams{MessageID: messageID, MinSize: &minSize, MaxSize: &maxSize, Limit: 100})
	if err != nil {
		t.Fatalf("ListAttachments(size range) error = %v, want nil", err)
	}
	if len(page.Attachments) != 2 {
		t.Errorf("ListAttachments(size 1000..5000) returned %d attachments, want 2 (invoice, report): %+v", len(page.Attachments), page.Attachments)
	}

	// Pagination: page through messageID's 3 attachments one at a
	// time, following NextCursor, and confirm every attachment is seen
	// exactly once with no repeats or gaps.
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		p, err := st.ListAttachments(ctx, store.AttachmentListParams{MessageID: messageID, Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListAttachments(paginated) page %d error = %v, want nil", i, err)
		}
		if len(p.Attachments) != 1 {
			t.Fatalf("ListAttachments(paginated) page %d returned %d attachments, want 1", i, len(p.Attachments))
		}
		if seen[p.Attachments[0].ID] {
			t.Fatalf("ListAttachments(paginated) repeated attachment %q", p.Attachments[0].ID)
		}
		seen[p.Attachments[0].ID] = true
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if len(seen) != 3 {
		t.Errorf("ListAttachments(paginated) saw %d distinct attachments, want 3: %+v", len(seen), seen)
	}

	// An invalid cursor is reported distinctly from any other failure.
	if _, err := st.ListAttachments(ctx, store.AttachmentListParams{Cursor: "not-a-real-cursor"}); !errors.Is(err, store.ErrInvalidCursor) {
		t.Errorf("ListAttachments(invalid cursor) error = %v, want wrapping ErrInvalidCursor", err)
	}
}
