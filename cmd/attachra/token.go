package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/302-digital/attachra/internal/core/audit"
	"github.com/302-digital/attachra/internal/core/store"
)

// Exit codes for `attachra token <subcommand>` (ATR-201).
const (
	tokenOK    = 0
	tokenError = 1
)

//nolint:gosec // G101 false positive: this is a CLI usage string, not a credential.
const tokenUsage = "attachra: usage: attachra token create --name <name> --role <admin|viewer|auditor> --actor <actor>"

// runTokenCommand dispatches `attachra token <subcommand> ...`. For now
// only `create` exists: it is the bootstrap path for the very first API
// token, since the REST API is deny-by-default and cannot mint its own
// first credential (ATR-201). Listing and revoking tokens are available
// through the REST API itself (GET/DELETE /api/v1/api-tokens), so the CLI
// deliberately does not duplicate them — it exists only to break the
// chicken-and-egg. sink receives a TypeTokenChange audit event for every
// token this command mints (ATR-296, SR-128-2), matching the REST API's
// own create/revoke handlers; a nil sink is treated as audit.NopSink{}.
func runTokenCommand(args []string, tokens store.APITokenStore, sink audit.AuditSink, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, tokenUsage) //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}

	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return runTokenCreate(rest, tokens, sink, stdout, stderr)
	default:
		fmt.Fprintln(stderr, tokenUsage) //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}
}

// runTokenCreate implements `attachra token create --name <name> --role
// <role> --actor <actor>`: it mints a new API token directly against the
// metadata store (no running server required) and prints the raw secret
// to stdout exactly once. The secret is never persisted (only its hash
// is — CLAUDE.md invariant #5, SR-130-2), so this single line of output
// is the operator's only chance to capture it.
func runTokenCreate(args []string, tokens store.APITokenStore, sink audit.AuditSink, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attachra token create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "operator-chosen label for the token (required)")
	roleStr := fs.String("role", "", "token role: admin, viewer or auditor (required)")
	actor := fs.String("actor", "", "identity of the operator performing this action (required; recorded in the audit log, since the CLI has no HTTP-auth principal to attribute it to)")

	if err := fs.Parse(args); err != nil {
		return tokenError
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, tokenUsage) //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}
	if *name == "" {
		fmt.Fprintln(stderr, "attachra: token create: --name is required") //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}
	if *actor == "" {
		fmt.Fprintln(stderr, "attachra: token create: --actor is required") //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}
	role, err := store.ParseRole(*roleStr)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: token create: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}

	id, err := store.NewTokenID()
	if err != nil {
		fmt.Fprintf(stderr, "attachra: token create: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}
	secret, hash, err := store.GenerateAPISecret(store.MinAPISecretBytes)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: token create: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}

	if err := tokens.CreateAPIToken(context.Background(), store.NewAPITokenParams{
		ID:        id,
		Name:      *name,
		Role:      role,
		TokenHash: hash,
	}); err != nil {
		fmt.Fprintf(stderr, "attachra: token create: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return tokenError
	}

	// Recording is best-effort (CLAUDE.md invariant #3's spirit applied
	// here too): the token is already minted and usable at this point, so
	// a sink outage must not turn a successful bootstrap into an error
	// exit code. Failure is only surfaced on stderr, mirroring how the
	// REST API's own create/revoke handlers log rather than fail the
	// response (ATR-296, SR-128-2).
	if sink == nil {
		sink = audit.NopSink{}
	}
	if _, err := sink.Record(context.Background(), audit.Event{
		Type:  audit.TypeTokenChange,
		Actor: *actor,
		Details: map[string]any{
			"action":   "create",
			"token_id": id,
			"name":     *name,
			"role":     string(role),
		},
	}); err != nil {
		fmt.Fprintf(stderr, "attachra: token create: failed to record audit event: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
	}

	// The id and role go to stderr as human-readable confirmation; the raw
	// secret is the sole machine-relevant value and goes to stdout on its
	// own line, so `attachra token create ... | ...` captures exactly the
	// secret and nothing else. It is shown here for the first and last
	// time — losing it means issuing a new token.
	fmt.Fprintf(stderr, "attachra: created token %q (id %s, role %s)\n", *name, id, role) //nolint:errcheck // best-effort diagnostic on stderr
	fmt.Fprintln(stdout, secret)                                                          //nolint:errcheck // best-effort output of the one-time secret
	return tokenOK
}
