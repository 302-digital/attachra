package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/store"
)

// RunAPITokenStore executes the shared store.APITokenStore behavioral
// contract against ts, a freshly migrated, empty store (ATR-201). It is
// a sibling of Run (which covers store.MetadataStore): the sqlite driver
// implements both interfaces on one type, but keeping the suites
// separate lets a future driver adopt them independently.
func RunAPITokenStore(t *testing.T, ts store.APITokenStore) {
	t.Helper()

	t.Run("CreateGetRoundTrip", func(t *testing.T) { testAPITokenRoundTrip(t, ts) })
	t.Run("GetMissingReturnsErrNotFound", func(t *testing.T) { testAPITokenGetMissing(t, ts) })
	t.Run("LookupActiveByHash", func(t *testing.T) { testAPITokenLookupActive(t, ts) })
	t.Run("RevokeIsImmediateAndHidesFromLookup", func(t *testing.T) { testAPITokenRevokeImmediate(t, ts) })
	t.Run("RevokeIsIdempotentAndReportsMissing", func(t *testing.T) { testAPITokenRevokeIdempotent(t, ts) })
	t.Run("TouchUpdatesLastUsedAt", func(t *testing.T) { testAPITokenTouch(t, ts) })
	t.Run("ListPaginatesByCursor", func(t *testing.T) { testAPITokenListPagination(t, ts) })
}

// createToken mints an APIToken with a deterministic secret derived from
// name, returning its id and the raw secret so a test can exercise the
// lookup-by-hash path. The secret is generated via the real
// store.GenerateAPISecret so the stored hash matches what the auth path
// would compute.
func createToken(t *testing.T, ctx context.Context, ts store.APITokenStore, id, name string, role store.Role) (secret string) {
	t.Helper()

	secret, hash, err := store.GenerateAPISecret(store.MinAPISecretBytes)
	if err != nil {
		t.Fatalf("GenerateAPISecret() error = %v, want nil", err)
	}
	if err := ts.CreateAPIToken(ctx, store.NewAPITokenParams{
		ID:        id,
		Name:      name,
		Role:      role,
		TokenHash: hash,
	}); err != nil {
		t.Fatalf("CreateAPIToken(%q) error = %v, want nil", id, err)
	}
	return secret
}

func testAPITokenRoundTrip(t *testing.T, ts store.APITokenStore) {
	ctx := context.Background()
	createToken(t, ctx, ts, "tok-rt", "ci-runner", store.RoleAdmin)

	got, err := ts.GetAPIToken(ctx, "tok-rt")
	if err != nil {
		t.Fatalf("GetAPIToken() error = %v, want nil", err)
	}
	if got.ID != "tok-rt" || got.Name != "ci-runner" || got.Role != store.RoleAdmin {
		t.Errorf("GetAPIToken() = %+v, want id=tok-rt name=ci-runner role=admin", got)
	}
	if got.TokenHash == "" {
		t.Errorf("GetAPIToken().TokenHash is empty, want the stored hash")
	}
	if got.CreatedAt.IsZero() {
		t.Errorf("GetAPIToken().CreatedAt is zero, want a stamped creation time")
	}
	if !got.LastUsedAt.IsZero() {
		t.Errorf("GetAPIToken().LastUsedAt = %v, want zero for a never-used token", got.LastUsedAt)
	}
	if !got.RevokedAt.IsZero() {
		t.Errorf("GetAPIToken().RevokedAt = %v, want zero for an active token", got.RevokedAt)
	}
}

func testAPITokenGetMissing(t *testing.T, ts store.APITokenStore) {
	ctx := context.Background()
	_, err := ts.GetAPIToken(ctx, "does-not-exist")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetAPIToken(missing) error = %v, want ErrNotFound", err)
	}
}

func testAPITokenLookupActive(t *testing.T, ts store.APITokenStore) {
	ctx := context.Background()
	secret := createToken(t, ctx, ts, "tok-lookup", "viewer-token", store.RoleViewer)

	got, err := ts.LookupActiveAPIToken(ctx, store.HashAPISecret(secret))
	if err != nil {
		t.Fatalf("LookupActiveAPIToken() error = %v, want nil", err)
	}
	if got.ID != "tok-lookup" || got.Role != store.RoleViewer {
		t.Errorf("LookupActiveAPIToken() = %+v, want id=tok-lookup role=viewer", got)
	}

	// A wrong secret must not resolve to any token.
	if _, err := ts.LookupActiveAPIToken(ctx, store.HashAPISecret("not-the-secret")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("LookupActiveAPIToken(wrong) error = %v, want ErrNotFound", err)
	}
}

func testAPITokenRevokeImmediate(t *testing.T, ts store.APITokenStore) {
	ctx := context.Background()
	secret := createToken(t, ctx, ts, "tok-revoke", "temp-token", store.RoleAuditor)
	hash := store.HashAPISecret(secret)

	// Active before revoke.
	if _, err := ts.LookupActiveAPIToken(ctx, hash); err != nil {
		t.Fatalf("LookupActiveAPIToken() before revoke error = %v, want nil", err)
	}

	revokedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if err := ts.RevokeAPIToken(ctx, "tok-revoke", revokedAt); err != nil {
		t.Fatalf("RevokeAPIToken() error = %v, want nil", err)
	}

	// Immediately invisible to the authentication path (SR-130-2).
	if _, err := ts.LookupActiveAPIToken(ctx, hash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("LookupActiveAPIToken() after revoke error = %v, want ErrNotFound", err)
	}

	// Still visible as metadata to an admin, now carrying RevokedAt.
	got, err := ts.GetAPIToken(ctx, "tok-revoke")
	if err != nil {
		t.Fatalf("GetAPIToken() after revoke error = %v, want nil", err)
	}
	if got.RevokedAt.IsZero() {
		t.Errorf("GetAPIToken().RevokedAt is zero after revoke, want the revocation time")
	}
}

func testAPITokenRevokeIdempotent(t *testing.T, ts store.APITokenStore) {
	ctx := context.Background()
	createToken(t, ctx, ts, "tok-idem", "idem-token", store.RoleAdmin)

	first := time.Now().UTC().Format(time.RFC3339Nano)
	if err := ts.RevokeAPIToken(ctx, "tok-idem", first); err != nil {
		t.Fatalf("first RevokeAPIToken() error = %v, want nil", err)
	}

	// A second revoke is a no-op success and must not move RevokedAt.
	second := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if err := ts.RevokeAPIToken(ctx, "tok-idem", second); err != nil {
		t.Errorf("second RevokeAPIToken() error = %v, want nil (idempotent)", err)
	}
	got, err := ts.GetAPIToken(ctx, "tok-idem")
	if err != nil {
		t.Fatalf("GetAPIToken() error = %v, want nil", err)
	}
	if gotAt := got.RevokedAt.UTC().Format(time.RFC3339Nano); gotAt != first {
		t.Errorf("RevokedAt = %q after repeat revoke, want the original %q", gotAt, first)
	}

	// Revoking a token that never existed is ErrNotFound.
	if err := ts.RevokeAPIToken(ctx, "tok-nope", first); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RevokeAPIToken(missing) error = %v, want ErrNotFound", err)
	}
}

func testAPITokenTouch(t *testing.T, ts store.APITokenStore) {
	ctx := context.Background()
	createToken(t, ctx, ts, "tok-touch", "touch-token", store.RoleViewer)

	usedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if err := ts.TouchAPIToken(ctx, "tok-touch", usedAt); err != nil {
		t.Fatalf("TouchAPIToken() error = %v, want nil", err)
	}
	got, err := ts.GetAPIToken(ctx, "tok-touch")
	if err != nil {
		t.Fatalf("GetAPIToken() error = %v, want nil", err)
	}
	if got.LastUsedAt.IsZero() {
		t.Errorf("LastUsedAt is zero after Touch, want the touched time")
	}

	// Touching a missing token is a best-effort no-op, not an error.
	if err := ts.TouchAPIToken(ctx, "tok-gone", usedAt); err != nil {
		t.Errorf("TouchAPIToken(missing) error = %v, want nil (best-effort)", err)
	}
}

func testAPITokenListPagination(t *testing.T, ts store.APITokenStore) {
	ctx := context.Background()

	// Seed 5 tokens with strictly increasing created_at so the keyset
	// order is deterministic. Because created_at is stamped by the store
	// at whole-call granularity, a small sleep guarantees distinct,
	// ordered timestamps rather than relying on sub-call resolution.
	const total = 5
	want := make([]string, 0, total)
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("tok-page-%d", i)
		createToken(t, ctx, ts, id, "page-token", store.RoleAdmin)
		want = append(want, id)
		time.Sleep(2 * time.Millisecond)
	}

	// Walk every page with limit=2 and reassemble the full set in order.
	var got []string
	cursor := ""
	pages := 0
	for {
		page, err := ts.ListAPITokens(ctx, store.APITokenListParams{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListAPITokens() error = %v, want nil", err)
		}
		pages++
		if pages > total+2 {
			t.Fatalf("ListAPITokens() did not terminate: cursor pagination looped")
		}
		for _, tok := range page.Tokens {
			// Only count the tokens this sub-test seeded; other sub-tests
			// sharing the same store may have left rows behind.
			if len(tok.ID) >= len("tok-page-") && tok.ID[:len("tok-page-")] == "tok-page-" {
				got = append(got, tok.ID)
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(got) != total {
		t.Fatalf("paginated ListAPITokens returned %d tok-page-* rows (%v), want %d", len(got), got, total)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("page order[%d] = %q, want %q (created_at ascending)", i, got[i], want[i])
		}
	}
}
