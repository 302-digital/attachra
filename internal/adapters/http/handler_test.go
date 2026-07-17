package http_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/storage/fs"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// testEnv bundles everything a handler test needs: a real sqlite
// store, a real fs storage driver, a link.Engine on top of them, and
// the Handler under test. Using the real implementations (rather than
// hand-rolled fakes) exercises the actual atomic-counter and
// generic-error contracts the security requirements depend on.
type testEnv struct {
	t       *testing.T
	store   *sqlite.Store
	storage *fs.Driver
	engine  *link.Engine
	handler *adapterhttp.Handler
	logger  *slog.Logger
}

// testEnvOption configures optional, less-commonly-needed newTestEnv
// dependencies without changing its signature for the many call sites
// that do not care about them.
type testEnvOption func(*testEnvConfig)

type testEnvConfig struct {
	metrics        *metrics.Metrics
	trustedProxies []netip.Prefix
}

// withMetrics wires m into the constructed Handler, for tests
// asserting on download metrics (US-7.2/T-7.2.1, ATR-192).
func withMetrics(m *metrics.Metrics) testEnvOption {
	return func(c *testEnvConfig) { c.metrics = m }
}

// withTrustedProxies wires trusted into the constructed Handler, for
// tests asserting on proxy-aware client IP resolution (ATR-311).
func withTrustedProxies(trusted []netip.Prefix) testEnvOption {
	return func(c *testEnvConfig) { c.trustedProxies = trusted }
}

func newTestEnv(t *testing.T, rl adapterhttp.RateLimitConfig, opts ...testEnvOption) *testEnv {
	t.Helper()

	var cfg testEnvConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	drv, err := fs.New(fs.Config{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("fs.New() error = %v, want nil", err)
	}

	engine, err := link.NewEngine(st, link.Defaults{
		TTL:          time.Hour,
		MaxDownloads: 0,
		TokenBytes:   link.MinTokenBytes,
	}, st, nil)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	handler := adapterhttp.NewHandler(engine, st, drv, logger, st, rl, cfg.trustedProxies, cfg.metrics)

	return &testEnv{t: t, store: st, storage: drv, engine: engine, handler: handler, logger: logger}
}

// putObject stores content under a fresh object key and returns the
// key, for use as an Attachment's StorageKey.
func (e *testEnv) putObject(content []byte) string {
	e.t.Helper()
	key := fmt.Sprintf("ab/%x", sha256.Sum256(content))[:20]
	if err := e.storage.Put(context.Background(), key, bytes.NewReader(content), int64(len(content))); err != nil {
		e.t.Fatalf("storage.Put() error = %v, want nil", err)
	}
	return key
}

// seedMessage creates a message with one attachment and one recipient
// via link.Engine.CreateLinks, returning the raw package-page token
// and the created per-attachment Link's store ID (looked up back from
// the DB, mirroring what the package page itself would show).
func (e *testEnv) seedMessage(t *testing.T, messageID string, content []byte, filename, detectedType string) (packageToken, linkID string) {
	t.Helper()
	ctx := context.Background()

	key := e.putObject(content)

	created, err := e.engine.CreateLinks(ctx, link.CreateLinksParams{
		Message: link.MessageInput{ID: messageID, QueueID: "q-" + messageID, Sender: "sender@example.com"},
		Attachments: []link.AttachmentInput{{
			ID:           messageID + "-att",
			PartRef:      "2",
			Filename:     filename,
			DeclaredType: detectedType,
			DetectedType: detectedType,
			Size:         int64(len(content)),
			StorageKey:   key,
		}},
		Recipients: []string{"recipient@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	for _, c := range created {
		if c.AttachmentID == "" {
			packageToken = c.Token
		}
	}
	if packageToken == "" {
		t.Fatalf("CreateLinks() did not return a package token")
	}

	links, err := e.store.ListLinksByMessage(ctx, messageID)
	if err != nil {
		t.Fatalf("ListLinksByMessage() error = %v, want nil", err)
	}
	if len(links) != 1 {
		t.Fatalf("ListLinksByMessage() = %d links, want 1", len(links))
	}
	linkID = links[0].ID

	return packageToken, linkID
}

func packagePath(token string) string      { return "/p/" + token }
func downloadPath(token, id string) string { return "/p/" + token + "/d/" + id }

// TestPackagePageDoesNotStreamOrDecrement is the core two-step-model
// assertion (SR-125-3, docs/architecture/package-page-decision.md
// §4.1 item 3): GET /p/<token> must render the listing, never send
// attachment bytes, and never touch the per-attachment Link's download
// counter — a link-preview bot fetching this URL must cost the
// recipient nothing.
func TestPackagePageDoesNotStreamOrDecrement(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := []byte("hello world, this is the attachment body")
	packageToken, linkID := env.seedMessage(t, "msg-get", content, "report.pdf", "application/octet-stream")

	req := httptest.NewRequest("GET", packagePath(packageToken), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("GET package page status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, string(content)) {
		t.Errorf("GET package page body contains raw attachment bytes, want none")
	}
	if !strings.Contains(body, "report.pdf") {
		t.Errorf("GET package page body = %q, want it to mention the file name", body)
	}
	if !strings.Contains(body, downloadPath(packageToken, linkID)) {
		t.Errorf("GET package page body does not contain the expected download form action %q", downloadPath(packageToken, linkID))
	}

	got, err := env.store.GetLinkByID(context.Background(), linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != 0 {
		t.Errorf("Downloads after GET package page = %d, want 0 (must not decrement on step 1)", got.Downloads)
	}
}

// TestDownloadRegistersAndStreams verifies step 2: POST decrements the
// counter exactly once and streams the exact original bytes back
// (SR-125-1, SR-125-6).
func TestDownloadRegistersAndStreams(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := bytes.Repeat([]byte("attachra-download-content-"), 1000) // a few KB, enough to catch accidental truncation.
	packageToken, linkID := env.seedMessage(t, "msg-post", content, "invoice.bin", "application/octet-stream")

	req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("POST download status = %d, want 200, body = %q", rr.Code, rr.Body.String())
	}
	if !bytes.Equal(rr.Body.Bytes(), content) {
		t.Errorf("POST download body length = %d, want %d (content mismatch)", rr.Body.Len(), len(content))
	}

	got, err := env.store.GetLinkByID(context.Background(), linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != 1 {
		t.Errorf("Downloads after one POST = %d, want 1", got.Downloads)
	}

	cd := rr.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "invoice.bin") {
		t.Errorf("Content-Disposition = %q, want it to contain the file name", cd)
	}
	if !strings.HasPrefix(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want it to start with \"attachment\"", cd)
	}

	if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(len(content)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(content))
	}
}

// TestDownloadContentLengthReflectsStorageNotMetadata is the ATR-238
// minor-4 regression test: att.Size (the metadata DB's record of the
// attachment's size) and the storage object's actual size are two
// independently-written values that can drift. Content-Length must
// come from the storage object itself (via Driver.Stat), never from
// the possibly-stale att.Size — otherwise a client sees a
// Content-Length promise the streamed body does not honor.
func TestDownloadContentLengthReflectsStorageNotMetadata(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	ctx := context.Background()

	actualContent := []byte("the real object bytes stored in the driver, longer than declared")
	key := env.putObject(actualContent)

	messageID := "msg-size-drift"
	// Deliberately declare a Size that does not match the object
	// actually stored under key, simulating drift between the
	// metadata DB and the storage backend.
	const declaredSize = 3
	created, err := env.engine.CreateLinks(ctx, link.CreateLinksParams{
		Message:     link.MessageInput{ID: messageID, QueueID: "q-drift", Sender: "s@example.com"},
		Attachments: []link.AttachmentInput{{ID: messageID + "-att", PartRef: "1", Filename: "drift.bin", DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream", Size: declaredSize, StorageKey: key}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}
	var packageToken string
	for _, c := range created {
		if c.AttachmentID == "" {
			packageToken = c.Token
		}
	}
	links, err := env.store.ListLinksByMessage(ctx, messageID)
	if err != nil || len(links) != 1 {
		t.Fatalf("ListLinksByMessage() = %+v, err = %v", links, err)
	}
	linkID := links[0].ID

	req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("POST download status = %d, want 200, body = %q", rr.Code, rr.Body.String())
	}
	if !bytes.Equal(rr.Body.Bytes(), actualContent) {
		t.Errorf("streamed body length = %d, want %d (the real stored object, not the declared size)", rr.Body.Len(), len(actualContent))
	}
	if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(len(actualContent)) {
		t.Errorf("Content-Length = %q, want %d (the storage object's real size, not att.Size=%d)", cl, len(actualContent), declaredSize)
	}
}

// TestDownloadOfRiskyTypeForcesOctetStream covers SR-125-4/T1.5: a
// magic-byte-detected risky type (text/html here) must never be
// echoed as the response Content-Type.
func TestDownloadOfRiskyTypeForcesOctetStream(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := []byte("<html><body><script>alert(1)</script></body></html>")
	packageToken, linkID := env.seedMessage(t, "msg-risky", content, "page.html", "text/html")

	req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("POST download status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream for a risky detected type", ct)
	}
	if xcto := rr.Header().Get("X-Content-Type-Options"); xcto != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", xcto)
	}
}

// TestGenericNotFoundForEveryNegativeCase is the SR-125-5 assertion:
// unknown token, expired link, revoked link, exhausted link and
// cross-message link IDs must all produce byte-identical status code
// and body.
func TestGenericNotFoundForEveryNegativeCase(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	ctx := context.Background()

	// Case 1: unknown package token entirely.
	unknownTokenReq := httptest.NewRequest("GET", packagePath("does-not-exist-at-all-0000000000"), nil)
	unknownTokenRR := httptest.NewRecorder()
	env.handler.ServeHTTP(unknownTokenRR, unknownTokenReq)

	// Case 2: revoked message-link (package token itself revoked).
	content := []byte("case-revoked-package")
	revokedToken, _ := env.seedMessage(t, "msg-revoked-pkg", content, "f.bin", "application/octet-stream")
	if _, _, err := env.engine.RevokeMessage(ctx, "test-actor", "msg-revoked-pkg"); err != nil {
		t.Fatalf("RevokeMessage() error = %v, want nil", err)
	}
	revokedReq := httptest.NewRequest("GET", packagePath(revokedToken), nil)
	revokedRR := httptest.NewRecorder()
	env.handler.ServeHTTP(revokedRR, revokedReq)

	// Case 3: link ID that exists but belongs to a different message.
	content2 := []byte("case-cross-message")
	otherToken, _ := env.seedMessage(t, "msg-other", content2, "g.bin", "application/octet-stream")
	content3 := []byte("case-cross-message-target")
	_, foreignLinkID := env.seedMessage(t, "msg-foreign-target", content3, "h.bin", "application/octet-stream")
	crossReq := httptest.NewRequest("POST", downloadPath(otherToken, foreignLinkID), nil)
	crossRR := httptest.NewRecorder()
	env.handler.ServeHTTP(crossRR, crossReq)

	// Case 4: download-limit exhausted (single-download link, used twice).
	content4 := []byte("case-exhausted")
	key4 := env.putObject(content4)
	exhaustedMessageID := "msg-exhausted"
	created, err := env.engine.CreateLinks(ctx, link.CreateLinksParams{
		Message:     link.MessageInput{ID: exhaustedMessageID, QueueID: "q-exhausted", Sender: "s@example.com"},
		Attachments: []link.AttachmentInput{{ID: exhaustedMessageID + "-att", PartRef: "1", Filename: "x.bin", DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream", Size: int64(len(content4)), StorageKey: key4}},
		Recipients:  []string{"r@example.com"},
		Params:      policy.ActionParams{MaxDownloads: intPtr(1)},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}
	var exhaustedToken string
	for _, c := range created {
		if c.AttachmentID == "" {
			exhaustedToken = c.Token
		}
	}
	links, err := env.store.ListLinksByMessage(ctx, exhaustedMessageID)
	if err != nil || len(links) != 1 {
		t.Fatalf("ListLinksByMessage() = %+v, err = %v", links, err)
	}
	exhaustedLinkID := links[0].ID
	// Use up the single allowed download.
	firstReq := httptest.NewRequest("POST", downloadPath(exhaustedToken, exhaustedLinkID), nil)
	firstRR := httptest.NewRecorder()
	env.handler.ServeHTTP(firstRR, firstReq)
	if firstRR.Code != 200 {
		t.Fatalf("first POST (should succeed) status = %d, want 200", firstRR.Code)
	}
	exhaustedReq := httptest.NewRequest("POST", downloadPath(exhaustedToken, exhaustedLinkID), nil)
	exhaustedRR := httptest.NewRecorder()
	env.handler.ServeHTTP(exhaustedRR, exhaustedReq)

	cases := map[string]*httptest.ResponseRecorder{
		"unknown token":   unknownTokenRR,
		"revoked package": revokedRR,
		"cross-message":   crossRR,
		"exhausted":       exhaustedRR,
	}

	var wantCode int
	var wantBody string
	first := true
	for name, rr := range cases {
		if first {
			wantCode = rr.Code
			wantBody = rr.Body.String()
			first = false
			continue
		}
		if rr.Code != wantCode {
			t.Errorf("case %q status = %d, want %d (must match every other negative case, SR-125-5)", name, rr.Code, wantCode)
		}
		if rr.Body.String() != wantBody {
			t.Errorf("case %q body differs from the other negative cases, want byte-identical generic response (SR-125-5)", name)
		}
	}
}

// intPtr returns a pointer to n, for building a policy.ActionParams
// literal with only MaxDownloads set.
func intPtr(n int) *int { return &n }

// TestPackagePageIsolatesRecipients is the HTTP-level ATR-237
// regression test: a message with two recipients gets one Link row
// per (attachment, recipient) pair, but the milter-MVP body only ever
// carries one recipient's package token. GET /p/<that token> must
// list only that recipient's own file, never the other recipient's
// Link row for the same attachment — otherwise the page leaks that a
// second recipient exists and exposes a linkID that could be used to
// drain their separate download budget (see
// TestDownloadRejectsCrossRecipientLinkID below for that half).
func TestPackagePageIsolatesRecipients(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	ctx := context.Background()
	content := []byte("shared-attachment-body")
	key := env.putObject(content)

	messageID := "msg-two-recipients"
	created, err := env.engine.CreateLinks(ctx, link.CreateLinksParams{
		Message:     link.MessageInput{ID: messageID, QueueID: "q-two", Sender: "s@example.com"},
		Attachments: []link.AttachmentInput{{ID: messageID + "-att", PartRef: "1", Filename: "shared.bin", DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream", Size: int64(len(content)), StorageKey: key}},
		Recipients:  []string{"alice@example.com", "bob@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var aliceToken, bobToken string
	for _, c := range created {
		if c.AttachmentID != "" {
			continue
		}
		switch c.Recipient {
		case "alice@example.com":
			aliceToken = c.Token
		case "bob@example.com":
			bobToken = c.Token
		}
	}
	if aliceToken == "" || bobToken == "" {
		t.Fatalf("CreateLinks() did not return package tokens for both recipients")
	}

	req := httptest.NewRequest("GET", packagePath(aliceToken), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("GET package page status = %d, want 200", rr.Code)
	}

	links, err := env.store.ListLinksByMessage(ctx, messageID)
	if err != nil || len(links) != 2 {
		t.Fatalf("ListLinksByMessage() = %+v, err = %v, want 2 links (one per recipient)", links, err)
	}
	var aliceLinkID, bobLinkID string
	for _, l := range links {
		switch l.Recipient {
		case "alice@example.com":
			aliceLinkID = l.ID
		case "bob@example.com":
			bobLinkID = l.ID
		}
	}

	body := rr.Body.String()
	if !strings.Contains(body, downloadPath(aliceToken, aliceLinkID)) {
		t.Errorf("alice's package page does not list her own file (expected form action %q)", downloadPath(aliceToken, aliceLinkID))
	}
	if strings.Contains(body, bobLinkID) {
		t.Errorf("alice's package page leaks bob's linkID %q — recipients must be isolated (ATR-237)", bobLinkID)
	}

	// bobToken is unused directly here (bob never receives a URL in
	// the MVP's shared body), asserted only to document that it was
	// minted; RegisterPackageDownload's own recipient check is
	// exercised end-to-end below.
	_ = bobToken
}

// TestDownloadRejectsCrossRecipientLinkID is the HTTP-level
// counterpart to link.TestEngineRegisterPackageDownloadRejectsCrossRecipientLinkID:
// even if bob's linkID were somehow learned, POSTing it against
// alice's valid package token must produce the same generic
// not-found response as any other negative case (SR-125-5), and must
// not charge bob's download counter.
func TestDownloadRejectsCrossRecipientLinkID(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	ctx := context.Background()
	content := []byte("shared-attachment-body-2")
	key := env.putObject(content)

	messageID := "msg-two-recipients-dl"
	created, err := env.engine.CreateLinks(ctx, link.CreateLinksParams{
		Message:     link.MessageInput{ID: messageID, QueueID: "q-two-dl", Sender: "s@example.com"},
		Attachments: []link.AttachmentInput{{ID: messageID + "-att", PartRef: "1", Filename: "shared.bin", DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream", Size: int64(len(content)), StorageKey: key}},
		Recipients:  []string{"alice@example.com", "bob@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var aliceToken string
	for _, c := range created {
		if c.AttachmentID == "" && c.Recipient == "alice@example.com" {
			aliceToken = c.Token
		}
	}
	if aliceToken == "" {
		t.Fatalf("CreateLinks() did not return alice's package token")
	}

	links, err := env.store.ListLinksByMessage(ctx, messageID)
	if err != nil || len(links) != 2 {
		t.Fatalf("ListLinksByMessage() = %+v, err = %v, want 2 links", links, err)
	}
	var bobLinkID string
	for _, l := range links {
		if l.Recipient == "bob@example.com" {
			bobLinkID = l.ID
		}
	}
	if bobLinkID == "" {
		t.Fatal("did not find bob's Link row")
	}

	req := httptest.NewRequest("POST", downloadPath(aliceToken, bobLinkID), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code == 200 {
		t.Fatalf("POST download with alice's token + bob's linkID status = 200, want a not-found response")
	}

	got, err := env.store.GetLinkByID(ctx, bobLinkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != 0 {
		t.Errorf("bob's link Downloads = %d, want 0 (must not be charged by alice's token)", got.Downloads)
	}
}

func TestAntiCacheHeadersPresent(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := []byte("anti-cache-header-check")
	packageToken, linkID := env.seedMessage(t, "msg-headers", content, "f.bin", "application/octet-stream")

	for _, tc := range []struct {
		name string
		req  func() *httptest.ResponseRecorder
	}{
		{"package page", func() *httptest.ResponseRecorder {
			req := httptest.NewRequest("GET", packagePath(packageToken), nil)
			rr := httptest.NewRecorder()
			env.handler.ServeHTTP(rr, req)
			return rr
		}},
		{"download", func() *httptest.ResponseRecorder {
			req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
			rr := httptest.NewRecorder()
			env.handler.ServeHTTP(rr, req)
			return rr
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := tc.req()
			checkAntiCacheHeaders(t, rr)
		})
	}
}

func checkAntiCacheHeaders(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	h := rr.Header()
	if got := h.Get("Cache-Control"); got != "private, no-store, max-age=0" {
		t.Errorf("Cache-Control = %q, want %q", got, "private, no-store, max-age=0")
	}
	if got := h.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	if got := h.Get("Expires"); got != "0" {
		t.Errorf("Expires = %q, want 0", got)
	}
	if got := h.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := h.Get("X-Robots-Tag"); !strings.Contains(got, "noindex") {
		t.Errorf("X-Robots-Tag = %q, want it to contain noindex", got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestPreviewBotGetDoesNotBurnLimit simulates a link-preview bot
// fetching the package page many times (GET only, as a bot unrolling a
// URL would) and asserts the download counter never moves and no bytes
// are ever served, regardless of how many times the page is fetched.
func TestPreviewBotGetDoesNotBurnLimit(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := []byte("preview-bot-should-not-consume-this")
	packageToken, linkID := env.seedMessage(t, "msg-bot", content, "f.bin", "application/octet-stream")

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", packagePath(packageToken), nil)
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("GET #%d status = %d, want 200", i, rr.Code)
		}
	}

	got, err := env.store.GetLinkByID(context.Background(), linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != 0 {
		t.Errorf("Downloads after 10 GETs = %d, want 0", got.Downloads)
	}
}

// TestRateLimitTriggers verifies SR-125-7: once the per-IP budget is
// exhausted, further requests get 429 rather than reaching the
// handler logic.
func TestRateLimitTriggers(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{
		PerIPRequestsPerMinute: 2,
		PerIPBurst:             2,
	})
	content := []byte("rate-limit-check")
	packageToken, _ := env.seedMessage(t, "msg-ratelimit", content, "f.bin", "application/octet-stream")

	var lastCode int
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", packagePath(packageToken), nil)
		req.RemoteAddr = "203.0.113.5:12345"
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		lastCode = rr.Code
	}
	if lastCode != 429 {
		t.Errorf("final status after exceeding per-IP burst = %d, want 429", lastCode)
	}
}

// TestRateLimitPerIPBehindTrustedProxyUsesForwardedIP verifies ATR-311:
// once http.trusted_proxies configures the reverse proxy's address as
// trusted, the per-IP rate limiter keys off the real client address
// carried in X-Forwarded-For rather than the proxy's own RemoteAddr —
// two distinct clients proxied through the same nginx instance get
// independent budgets, and a client that exhausts its own budget does
// not also throttle every other client behind the same proxy (the
// "vending machine as gatekeeper" failure ATR-311 exists to fix: before
// this, every request looked like it came from 127.0.0.1).
func TestRateLimitPerIPBehindTrustedProxyUsesForwardedIP(t *testing.T) {
	trusted, err := adapterhttp.ParseTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies() error = %v, want nil", err)
	}
	env := newTestEnv(t, adapterhttp.RateLimitConfig{
		PerIPRequestsPerMinute: 2,
		PerIPBurst:             2,
	}, withTrustedProxies(trusted))
	content := []byte("rate-limit-behind-proxy-check")
	packageToken, _ := env.seedMessage(t, "msg-ratelimit-proxy", content, "f.bin", "application/octet-stream")

	requestAs := func(forwardedFor string) int {
		req := httptest.NewRequest("GET", packagePath(packageToken), nil)
		req.RemoteAddr = "127.0.0.1:44444" // The trusted proxy's own loopback peer address.
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// Client A exhausts its 2-request burst.
	if code := requestAs("203.0.113.1"); code != 200 {
		t.Fatalf("client A request #1 status = %d, want 200", code)
	}
	if code := requestAs("203.0.113.1"); code != 200 {
		t.Fatalf("client A request #2 status = %d, want 200", code)
	}
	if code := requestAs("203.0.113.1"); code != 429 {
		t.Fatalf("client A request #3 status = %d, want 429 (own budget exhausted)", code)
	}

	// Client B, proxied through the same nginx instance (same
	// RemoteAddr), must be unaffected: a different X-Forwarded-For means
	// a different bucket.
	if code := requestAs("203.0.113.2"); code != 200 {
		t.Fatalf("client B request #1 status = %d, want 200 (independent budget)", code)
	}
	if code := requestAs("203.0.113.2"); code != 200 {
		t.Fatalf("client B request #2 status = %d, want 200 (independent budget)", code)
	}
	if code := requestAs("203.0.113.2"); code != 429 {
		t.Fatalf("client B request #3 status = %d, want 429 (own budget now exhausted too)", code)
	}
}

// TestNoXSSInReflectedFilename ensures a hostile file name embedded in
// the package page is escaped by html/template rather than rendered
// as live HTML (SR-125-5/T1.5 extends to the listing, not just error
// pages).
func TestNoXSSInReflectedFilename(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	content := []byte("xss-check")
	hostileName := `<script>alert(1)</script>.txt`
	packageToken, _ := env.seedMessage(t, "msg-xss", content, hostileName, "text/plain")

	req := httptest.NewRequest("GET", packagePath(packageToken), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("package page body contains unescaped script tag: %q", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("package page body = %q, want the hostile filename HTML-escaped", body)
	}
}

// TestLargeDownloadStreamsWithoutBuffering pushes a payload well over a
// typical single-buffer threshold through the handler and confirms it
// round-trips byte-for-byte, exercising the storage.Driver -> handler
// -> ResponseWriter streaming path end to end (SR-125-1).
func TestLargeDownloadStreamsWithoutBuffering(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})

	const size = 4 * 1024 * 1024 // 4 MiB
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i % 251)
	}

	packageToken, linkID := env.seedMessage(t, "msg-large", content, "big.bin", "application/octet-stream")

	req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("POST download status = %d, want 200", rr.Code)
	}
	got := rr.Body.Bytes()
	if len(got) != size {
		t.Fatalf("streamed %d bytes, want %d", len(got), size)
	}
	sum := sha256.Sum256(got)
	wantSum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != hex.EncodeToString(wantSum[:]) {
		t.Error("streamed content hash mismatch")
	}
}

// TestDoubleDownloadRace exercises RegisterPackageDownload's
// concurrency safety through the full HTTP handler (not just the
// store layer), confirming that critical counters are race-safe
// (run with go test -race).
func TestDoubleDownloadRace(t *testing.T) {
	env := newTestEnv(t, adapterhttp.RateLimitConfig{})
	ctx := context.Background()
	content := []byte("race-check-content")
	key := env.putObject(content)

	messageID := "msg-race"
	created, err := env.engine.CreateLinks(ctx, link.CreateLinksParams{
		Message:     link.MessageInput{ID: messageID, QueueID: "q-race", Sender: "s@example.com"},
		Attachments: []link.AttachmentInput{{ID: messageID + "-att", PartRef: "1", Filename: "r.bin", DeclaredType: "application/octet-stream", DetectedType: "application/octet-stream", Size: int64(len(content)), StorageKey: key}},
		Recipients:  []string{"r@example.com"},
		Params:      policy.ActionParams{MaxDownloads: intPtr(3)},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}
	var packageToken string
	for _, c := range created {
		if c.AttachmentID == "" {
			packageToken = c.Token
		}
	}
	links, err := env.store.ListLinksByMessage(ctx, messageID)
	if err != nil || len(links) != 1 {
		t.Fatalf("ListLinksByMessage() = %+v, err = %v", links, err)
	}
	linkID := links[0].ID

	const attempts = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", downloadPath(packageToken, linkID), nil)
			rr := httptest.NewRecorder()
			env.handler.ServeHTTP(rr, req)
			if rr.Code == 200 {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 3 {
		t.Errorf("successful downloads = %d, want exactly 3 (MaxDownloads)", successes)
	}

	got, err := env.store.GetLinkByID(ctx, linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Downloads != 3 {
		t.Errorf("Downloads = %d, want 3", got.Downloads)
	}
}
