package http

import (
	"context"

	"github.com/302-digital/attachra/internal/core/store"
)

// principal identifies the authenticated API caller behind a request,
// established by the auth middleware and read by the per-endpoint role
// check and the handlers. It carries only non-secret identity: the
// token's store ID, its operator-chosen name and its role — never the
// bearer secret or its hash.
type principal struct {
	TokenID string
	Name    string
	Role    store.Role
}

// principalContextKey is the unexported context key under which the auth
// middleware stashes the authenticated principal. Being unexported, no
// code outside this package can set or forge it — a handler can only ever
// observe a principal the auth middleware itself installed.
type principalContextKey struct{}

// withPrincipal returns a copy of ctx carrying p.
func withPrincipal(ctx context.Context, p principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// principalFrom returns the principal installed by the auth middleware,
// and ok=false if none is present (which, for any handler mounted behind
// the auth middleware, should never happen — it is treated as an
// internal error rather than silently allowing the request).
func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(principal)
	return p, ok
}
