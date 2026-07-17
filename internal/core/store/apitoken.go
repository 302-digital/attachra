package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// Role is the access-control role bound to an APIToken (US-8.1/ADR-015,
// SR-130-3). Community edition ships exactly three fixed roles; the type
// is intentionally left open (a plain string newtype rather than an
// iota-based closed enum) so an Enterprise Identity Pack can add custom
// roles without a schema or type change, but Community itself recognizes
// only the three constants below.
type Role string

// Recognized Role values (ADR-015, decision OQ-4 in
// docs/product/open-core-boundary.md).
const (
	// RoleAdmin may perform every read and every mutation, including API
	// token management.
	RoleAdmin Role = "admin"
	// RoleViewer has read-only access to every resource except API token
	// management (which is admin-only, SR-130-3).
	RoleViewer Role = "viewer"
	// RoleAuditor has read-only access to the audit log and its export
	// only — nothing else (ADR-015: a strictly-scoped compliance role).
	RoleAuditor Role = "auditor"
)

// Valid reports whether r is one of the three Community roles. It is the
// single authority for "is this a role Community knows about", used both
// when creating a token and when an Enterprise build wants to reject an
// unknown role at the Community boundary.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleViewer, RoleAuditor:
		return true
	default:
		return false
	}
}

// ParseRole validates s and returns it as a Role, or an error if s is
// not one of the three Community roles. Callers minting a token (the
// CLI bootstrap path and the create-token API handler) must go through
// this rather than casting a raw string, so an invalid role never
// reaches the database.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("store: invalid role %q (must be one of admin, viewer, auditor)", s)
	}
	return r, nil
}

// APIToken is a single issued API credential (US-8.1/T-8.1.7, ATR-201).
// TokenHash is the SHA-256 hash of the bearer secret; the raw secret is
// never persisted (the token-hygiene invariant, SR-130-2) — it is shown once
// at creation time and cannot be recovered. RevokedAt is the zero
// time.Time while the token is active; once set, the token can never
// authenticate again (revocation is immediate, SR-130-2).
type APIToken struct {
	ID         string
	Name       string
	Role       Role
	TokenHash  string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if the token has never authenticated a request.
	RevokedAt  time.Time // zero if the token is still active.
}

// NewAPITokenParams are the fields needed to create an APIToken row. The
// caller supplies an already-computed TokenHash (via HashAPISecret),
// never a raw secret: the raw secret never crosses this boundary (the
// token-hygiene invariant, mirroring NewLinkParams.TokenHash).
type NewAPITokenParams struct {
	ID        string
	Name      string
	Role      Role
	TokenHash string
}

// APITokenListParams bounds a ListAPITokens page (SR-130-5: mandatory
// pagination). Cursor is the opaque string returned as a previous page's
// NextCursor; an empty Cursor requests the first page.
type APITokenListParams struct {
	Limit  int
	Cursor string
}

// APITokenPage is one page of ListAPITokens output. NextCursor is empty
// when the returned page is the last one (no further rows).
type APITokenPage struct {
	Tokens     []APIToken
	NextCursor string
}

// APITokenStore is the repository interface for API-token issuance,
// lookup and revocation (US-8.1/T-8.1.7, ATR-201). It is defined here in
// internal/core, alongside store.MetadataStore, so the auth middleware
// (internal/adapters/http) and the bootstrap CLI depend only on this
// interface, never on a driver package (ADR-002). The sqlite driver's
// store.Store implements both this and MetadataStore against the same
// database file (ADR-011: token hashes live in the same metadata store
// as link-token hashes).
//
// All methods must be safe for concurrent use by multiple goroutines,
// and no method ever receives or returns a raw bearer secret: only
// pre-hashed TokenHash values cross this boundary (the token-hygiene
// invariant).
type APITokenStore interface {
	// CreateAPIToken inserts a new, active (RevokedAt zero) APIToken row.
	CreateAPIToken(ctx context.Context, p NewAPITokenParams) error

	// GetAPIToken returns the APIToken with the given ID regardless of
	// its revoked state (a revoked token's metadata is still visible to
	// an admin via GET /api-tokens/{id}), or an error wrapping
	// ErrNotFound. It is the metadata read behind the get/list API
	// surface, not the authentication path — use LookupActiveAPIToken
	// for the latter.
	GetAPIToken(ctx context.Context, id string) (APIToken, error)

	// LookupActiveAPIToken returns the active (non-revoked) APIToken
	// whose TokenHash equals tokenHash, or an error wrapping ErrNotFound
	// when no such active token exists. This is the authentication path:
	// a revoked token is deliberately indistinguishable from a
	// never-existed one here (both yield ErrNotFound), so revocation
	// takes effect immediately (SR-130-2) and the caller resolves either
	// case to the same generic 401. Lookup is by the unique index on
	// token_hash, so it takes a time independent of the number of stored
	// tokens (no linear scan, no timing side-channel from the query
	// itself); the caller additionally performs a constant-time
	// comparison of the returned hash as defense-in-depth (SR-130-2).
	LookupActiveAPIToken(ctx context.Context, tokenHash string) (APIToken, error)

	// ListAPITokens returns one page of APIToken rows ordered by
	// (created_at, id) ascending, using the opaque cursor pagination the
	// API contract mandates (SR-130-5). It never returns a TokenHash-bearing
	// secret — the hash is carried on the struct for internal use but the
	// API DTO omits it.
	ListAPITokens(ctx context.Context, p APITokenListParams) (APITokenPage, error)

	// RevokeAPIToken sets RevokedAt on the token identified by id to
	// revokedAt (RFC3339Nano UTC), taking effect immediately for
	// subsequent LookupActiveAPIToken calls. Revoking an already-revoked
	// token is idempotent (it leaves the original RevokedAt untouched and
	// returns nil). It returns an error wrapping ErrNotFound if no token
	// exists for id.
	RevokeAPIToken(ctx context.Context, id string, revokedAt string) error

	// TouchAPIToken records that the token identified by id was used to
	// authenticate a request, setting last_used_at to usedAt (RFC3339Nano
	// UTC). It is a best-effort, observability-only write (the caller
	// throttles how often it is issued and never blocks a request on its
	// outcome), so it does not distinguish a missing row: an id that no
	// longer exists simply updates zero rows and returns nil.
	TouchAPIToken(ctx context.Context, id string, usedAt string) error
}

// MinAPISecretBytes is the minimum number of crypto/rand bytes an API
// token secret is generated with: 32 bytes = 256 bits, the floor the
// ATR-201 brief sets (well above the token-hygiene invariant's 128-bit
// link-token minimum, since an API token grants standing administrative
// access rather than a single one-shot download).
const MinAPISecretBytes = 32

// GenerateAPISecret returns a new raw API-token secret with numBytes
// bytes of crypto/rand entropy (numBytes must be >= MinAPISecretBytes),
// together with its HashAPISecret hash. The raw secret is the only place
// the credential ever exists in reversible form: the caller shows it to
// the operator exactly once and persists only the returned hash
// (the token-hygiene invariant, SR-130-2). It is URL-safe base64 without
// padding so it travels cleanly in an Authorization header.
func GenerateAPISecret(numBytes int) (secret, hash string, err error) {
	if numBytes < MinAPISecretBytes {
		return "", "", fmt.Errorf("store: generate api secret: numBytes %d is below the %d-byte (256-bit) minimum", numBytes, MinAPISecretBytes)
	}

	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("store: generate api secret: %w", err)
	}

	secret = base64.RawURLEncoding.EncodeToString(buf)
	return secret, HashAPISecret(secret), nil
}

// apiTokenIDBytes is the number of random bytes used to build an
// api_tokens.id. Like the link/message/attachment identifiers, this is
// an opaque, non-secret row identifier (128 bits so it never collides in
// practice), distinct from the 256-bit token secret above.
const apiTokenIDBytes = 16

// NewTokenID generates a new opaque, hex-encoded api_tokens.id. Both
// callers that mint a token (the CLI bootstrap path and the create-token
// API handler) use it so the ID scheme is defined in one place, matching
// how the link engine centralizes its own row-ID generation.
func NewTokenID() (string, error) {
	buf := make([]byte, apiTokenIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("store: generate api token id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// HashAPISecret returns the hex-encoded SHA-256 hash of secret, the only
// form of an API token ever written to or compared against the store
// (the token-hygiene invariant, SR-130-2). A plain SHA-256 (rather than a
// slow password KDF) is correct here because an API secret is a
// full-entropy 256-bit random value, not a user-chosen password: there
// is nothing to brute-force offline, so the cost of a KDF buys no
// security while adding latency to every authenticated request.
func HashAPISecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
