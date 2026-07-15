package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
)

// newLinksCmd builds `attachractl links <subcommand>`, a thin client
// over the /links resource (api/openapi.yaml, ATR-197): list, get,
// revoke, hold, unhold.
func newLinksCmd(env *appEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "links",
		Short: "List and manage personal download links",
	}
	cmd.AddCommand(
		newLinksListCmd(env),
		newLinksGetCmd(env),
		newLinksRevokeCmd(env),
		newLinksHoldCmd(env, "hold", true),
		newLinksHoldCmd(env, "unhold", false),
	)
	return cmd
}

// linkView is the subset of schema Link this CLI renders in a table
// (api/openapi.yaml). Unknown fields are ignored by json.Unmarshal.
type linkView struct {
	ID           string `json:"id"`
	MessageID    string `json:"message_id"`
	AttachmentID string `json:"attachment_id"`
	Recipient    string `json:"recipient"`
	ExpiresAt    string `json:"expires_at"`
	MaxDownloads int    `json:"max_downloads"`
	Downloads    int    `json:"downloads"`
	Status       string `json:"status"`
	Hold         bool   `json:"hold"`
	CreatedAt    string `json:"created_at"`
}

var linksTableHeaders = []string{"ID", "MESSAGE_ID", "RECIPIENT", "STATUS", "HOLD", "DOWNLOADS", "EXPIRES_AT"}

func linkRow(l linkView) []string {
	downloads := strconv.Itoa(l.Downloads) + "/" + maxDownloadsLabel(l.MaxDownloads)
	return []string{l.ID, l.MessageID, l.Recipient, l.Status, strconv.FormatBool(l.Hold), downloads, l.ExpiresAt}
}

func maxDownloadsLabel(max int) string {
	if max <= 0 {
		return "unlimited"
	}
	return strconv.Itoa(max)
}

func newLinksListCmd(env *appEnv) *cobra.Command {
	var messageID, recipient, status, from, to string
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List personal download links",
		Long:  "Lists every link matching the given filters, automatically walking every page of GET /links (api/openapi.yaml's opaque cursor pagination) rather than stopping at the first page.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			query := url.Values{}
			setIfNonEmpty(query, "message_id", messageID)
			setIfNonEmpty(query, "recipient", recipient)
			setIfNonEmpty(query, "status", status)
			setIfNonEmpty(query, "from", from)
			setIfNonEmpty(query, "to", to)
			if limit > 0 {
				query.Set("limit", strconv.Itoa(limit))
			}

			var rows [][]string
			err := env.client.fetchAllPages(cmd.Context(), "/links", query, func(raw json.RawMessage) error {
				if env.jsonOut {
					return printJSONLine(env.stdout, raw)
				}
				var l linkView
				if err := json.Unmarshal(raw, &l); err != nil {
					return fmt.Errorf("decode link: %w", err)
				}
				rows = append(rows, linkRow(l))
				return nil
			})
			if err != nil {
				return err
			}
			if !env.jsonOut {
				printTable(env.stdout, linksTableHeaders, rows)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&messageID, "message-id", "", "filter by message ID")
	cmd.Flags().StringVar(&recipient, "recipient", "", "filter by exact, case-insensitive recipient address")
	cmd.Flags().StringVar(&status, "status", "", "filter by status: active, revoked, expired")
	cmd.Flags().StringVar(&from, "from", "", "inclusive lower bound on created_at (RFC3339)")
	cmd.Flags().StringVar(&to, "to", "", "exclusive upper bound on created_at (RFC3339)")
	cmd.Flags().IntVar(&limit, "limit", 0, "page size requested per API call (server default 50, max 200); auto-pagination still fetches every page regardless")

	return cmd
}

func newLinksGetCmd(env *appEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "get <link-id>",
		Short: "Get a single link by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := env.client.get(cmd.Context(), "/links/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			return printLinkResult(env, raw)
		},
	}
}

func printLinkResult(env *appEnv, raw json.RawMessage) error {
	if env.jsonOut {
		return printJSONLine(env.stdout, raw)
	}
	var l linkView
	if err := json.Unmarshal(raw, &l); err != nil {
		return fmt.Errorf("decode link: %w", err)
	}
	printTable(env.stdout, linksTableHeaders, [][]string{linkRow(l)})
	return nil
}

func newLinksHoldCmd(env *appEnv, name string, hold bool) *cobra.Command {
	verb, verbed := "hold", "held"
	if !hold {
		verb, verbed = "unhold", "released from hold"
	}
	return &cobra.Command{
		Use:   name + " <link-id>",
		Short: "Place a link under legal hold (or lift one)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := env.client.postJSON(cmd.Context(), "POST", "/links/"+url.PathEscape(args[0])+"/"+verb, nil, nil)
			if err != nil {
				return err
			}
			if !env.jsonOut {
				fmt.Fprintf(env.stdout, "link %s: %s\n", args[0], verbed) //nolint:errcheck // best-effort confirmation line
			}
			return printLinkResult(env, raw)
		},
	}
}

// revokeByMessageResultView mirrors schema RevokeByMessageResult.
type revokeByMessageResultView struct {
	Revoked int `json:"revoked"`
	Held    int `json:"held"`
}

// revokeBySenderResultView mirrors schema RevokeBySenderResult.
type revokeBySenderResultView struct {
	Revoked      int `json:"revoked"`
	HeldMessages int `json:"held_messages"`
}

func newLinksRevokeCmd(env *appEnv) *cobra.Command {
	var messageID, sender string

	cmd := &cobra.Command{
		Use:   "revoke [link-id]",
		Short: "Revoke one link, every link of a message, or every link of a sender",
		Long:  "Exactly one of a positional link-id, --message-id or --sender must be given. Revoking is admin-only on the API; a link currently under legal hold is refused (single-link mode) or reported as skipped (message/sender cascade mode) rather than revoked.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modes := 0
			if len(args) == 1 {
				modes++
			}
			if messageID != "" {
				modes++
			}
			if sender != "" {
				modes++
			}
			if modes != 1 {
				return newCLIError(exitUsage, "links revoke: exactly one of <link-id>, --message-id or --sender is required")
			}

			switch {
			case len(args) == 1:
				raw, err := env.client.postJSON(cmd.Context(), "POST", "/links/"+url.PathEscape(args[0])+"/revoke", nil, nil)
				if err != nil {
					return err
				}
				if !env.jsonOut {
					fmt.Fprintf(env.stdout, "link %s: revoked\n", args[0]) //nolint:errcheck // best-effort confirmation line
				}
				return printLinkResult(env, raw)

			case messageID != "":
				raw, err := env.client.postJSON(cmd.Context(), "POST", "/links/revoke-by-message", nil, map[string]string{"message_id": messageID})
				if err != nil {
					return err
				}
				if env.jsonOut {
					return printJSONLine(env.stdout, raw)
				}
				var resp revokeByMessageResultView
				if err := json.Unmarshal(raw, &resp); err != nil {
					return fmt.Errorf("decode revoke result: %w", err)
				}
				fmt.Fprintf(env.stdout, "message %s: %d link(s) revoked, %d held\n", messageID, resp.Revoked, resp.Held) //nolint:errcheck // best-effort output
				return nil

			default:
				raw, err := env.client.postJSON(cmd.Context(), "POST", "/links/revoke-by-sender", nil, map[string]string{"sender": sender})
				if err != nil {
					return err
				}
				if env.jsonOut {
					return printJSONLine(env.stdout, raw)
				}
				var resp revokeBySenderResultView
				if err := json.Unmarshal(raw, &resp); err != nil {
					return fmt.Errorf("decode revoke result: %w", err)
				}
				fmt.Fprintf(env.stdout, "sender %s: %d link(s) revoked, %d message(s) had a held link\n", sender, resp.Revoked, resp.HeldMessages) //nolint:errcheck // best-effort output
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&messageID, "message-id", "", "revoke every link belonging to this message")
	cmd.Flags().StringVar(&sender, "sender", "", "revoke every link belonging to every message from this sender")

	return cmd
}

// setIfNonEmpty sets query[key] = v only when v is non-empty, so an
// unset filter flag simply omits the query parameter (matching the
// API's own "absent = no filter" semantics).
func setIfNonEmpty(query url.Values, key, v string) {
	if v != "" {
		query.Set(key, v)
	}
}
