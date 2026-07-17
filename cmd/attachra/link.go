package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/store"
)

// Exit codes for `attachra link <subcommand>` (T-9.1.3 precursor,
// ATR-258).
const (
	linkOK    = 0
	linkError = 1
)

const linkUsage = "attachra: usage: attachra link <hold|unhold|revoke> --actor <actor> ..."

// runLinkCommand dispatches `attachra link <subcommand> ...`: hold,
// unhold and revoke (ATR-258). This is an interim, admin/operator-facing
// CLI surface for the hold mechanism (ATR-257) and US-6.3 revoke ahead
// of the full REST API (E8/T-8.1.3, ATR-197) and attachractl CLI
// (E9/T-9.1.3, ATR-204): hold and revoke are emergency operations (a
// misdirected attachment, a litigation hold) that should not have to
// wait for either of those larger surfaces.
func runLinkCommand(args []string, metadataStore store.MetadataStore, engine *link.Engine, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, linkUsage) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}

	sub, rest := args[0], args[1:]
	switch sub {
	case "hold":
		return runLinkSetHold(rest, engine, stdout, stderr, true)
	case "unhold":
		return runLinkSetHold(rest, engine, stdout, stderr, false)
	case "revoke":
		return runLinkRevoke(rest, metadataStore, engine, stdout, stderr)
	default:
		fmt.Fprintln(stderr, linkUsage) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}
}

// runLinkSetHold implements `attachra link hold --actor <actor> <link-id>`
// and its `unhold` counterpart (ATR-257/ATR-258): it sets or clears the
// legal-hold flag on a single link identified by its store-assigned ID.
func runLinkSetHold(args []string, engine *link.Engine, stdout, stderr io.Writer, hold bool) int {
	name, verbed := "hold", "set"
	if !hold {
		name, verbed = "unhold", "cleared"
	}
	usage := fmt.Sprintf("attachra: usage: attachra link %s --actor <actor> <link-id>", name)

	fs := flag.NewFlagSet("attachra link "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	actor := fs.String("actor", "", "identity of the operator performing this action (required; recorded in the audit log, since the CLI has no HTTP-auth principal to attribute it to)")

	if err := fs.Parse(args); err != nil {
		return linkError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, usage) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}
	if *actor == "" {
		fmt.Fprintf(stderr, "attachra: link %s: --actor is required\n", name) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}
	linkID := fs.Arg(0)

	if err := engine.SetHold(context.Background(), *actor, linkID, hold); err != nil {
		fmt.Fprintln(stderr, formatLinkError(fmt.Sprintf("link %s %s", name, linkID), err)) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}

	fmt.Fprintf(stdout, "link %s: hold %s\n", linkID, verbed) //nolint:errcheck // best-effort diagnostic on stdout
	return linkOK
}

// runLinkRevoke implements `attachra link revoke --actor <actor>
// (<link-id> | --message-id <id> | --sender <address>)` (US-6.3,
// ATR-258): exactly one of the three revoke modes must be selected.
func runLinkRevoke(args []string, metadataStore store.MetadataStore, engine *link.Engine, stdout, stderr io.Writer) int {
	usage := "attachra: usage: attachra link revoke --actor <actor> (<link-id> | --message-id <id> | --sender <address>)"

	fs := flag.NewFlagSet("attachra link revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	actor := fs.String("actor", "", "identity of the operator performing this action (required; recorded in the audit log, since the CLI has no HTTP-auth principal to attribute it to)")
	messageID := fs.String("message-id", "", "revoke every link belonging to this message")
	sender := fs.String("sender", "", "revoke every link belonging to every message sent by this address (matched case-insensitively, angle brackets ignored — ATR-293)")

	if err := fs.Parse(args); err != nil {
		return linkError
	}
	if *actor == "" {
		fmt.Fprintln(stderr, "attachra: link revoke: --actor is required") //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}

	modes := 0
	if fs.NArg() > 0 {
		modes++
	}
	if *messageID != "" {
		modes++
	}
	if *sender != "" {
		modes++
	}
	if modes != 1 || fs.NArg() > 1 {
		fmt.Fprintln(stderr, usage) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}

	ctx := context.Background()

	switch {
	case fs.NArg() == 1:
		return runLinkRevokeByLink(ctx, engine, fs.Arg(0), *actor, stdout, stderr)
	case *messageID != "":
		return runLinkRevokeByMessage(ctx, engine, *messageID, *actor, stdout, stderr)
	default:
		return runLinkRevokeBySender(ctx, metadataStore, engine, *sender, *actor, stdout, stderr)
	}
}

func runLinkRevokeByLink(ctx context.Context, engine *link.Engine, linkID, actor string, stdout, stderr io.Writer) int {
	if err := engine.Revoke(ctx, actor, linkID); err != nil {
		fmt.Fprintln(stderr, formatLinkError(fmt.Sprintf("link revoke %s", linkID), err)) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}
	fmt.Fprintf(stdout, "link %s: revoked\n", linkID) //nolint:errcheck // best-effort diagnostic on stdout
	return linkOK
}

func runLinkRevokeByMessage(ctx context.Context, engine *link.Engine, messageID, actor string, stdout, stderr io.Writer) int {
	revoked, held, err := engine.RevokeMessage(ctx, actor, messageID)
	if held > 0 {
		fmt.Fprintf(stdout, "message %s: %d link(s) revoked, %d held\n", messageID, revoked, held) //nolint:errcheck // best-effort diagnostic on stdout
	} else {
		fmt.Fprintf(stdout, "message %s: %d link(s) revoked\n", messageID, revoked) //nolint:errcheck // best-effort diagnostic on stdout
	}
	if err != nil {
		fmt.Fprintln(stderr, formatLinkError(fmt.Sprintf("link revoke --message-id %s", messageID), err)) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}
	return linkOK
}

func runLinkRevokeBySender(ctx context.Context, metadataStore store.MetadataStore, engine *link.Engine, sender, actor string, stdout, stderr io.Writer) int {
	messages, err := metadataStore.ListMessagesBySender(ctx, sender)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: link revoke --sender %s: list messages: %v\n", sender, err) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}
	if len(messages) == 0 {
		fmt.Fprintf(stdout, "sender %s: no messages found, nothing to revoke\n", sender) //nolint:errcheck // best-effort diagnostic on stdout
		return linkOK
	}

	messageIDs := make([]string, len(messages))
	for i, m := range messages {
		messageIDs[i] = m.ID
	}

	revoked, _, err := engine.RevokeSender(ctx, actor, messageIDs)
	fmt.Fprintf(stdout, "sender %s: %d link(s) revoked across %d message(s)\n", sender, revoked, len(messages)) //nolint:errcheck // best-effort diagnostic on stdout
	if err != nil {
		fmt.Fprintln(stderr, formatLinkError(fmt.Sprintf("link revoke --sender %s", sender), err)) //nolint:errcheck // best-effort diagnostic on stderr
		return linkError
	}
	return linkOK
}

// formatLinkError renders err as an operator-facing diagnostic line
// prefixed by op, giving link.ErrHeld a specific, actionable message
// (US-6.3 acceptance criterion: "hold blocks revoke with a clear
// message") instead of just printing the wrapped error text.
func formatLinkError(op string, err error) string {
	switch {
	case errors.Is(err, link.ErrHeld):
		return fmt.Sprintf("attachra: %s: refused, one or more links are under legal hold; clear the hold first (attachra link unhold --actor <actor> <link-id>)", op)
	case errors.Is(err, link.ErrNotFound):
		return fmt.Sprintf("attachra: %s: not found", op)
	default:
		return fmt.Sprintf("attachra: %s: %v", op, err)
	}
}
