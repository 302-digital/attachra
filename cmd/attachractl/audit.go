package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

// newAuditCmd builds `attachractl audit <subcommand>`, a thin client
// over the /audit resource (api/openapi.yaml, ATR-200): list, tail,
// export.
func newAuditCmd(env *appEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "View and export the audit log",
	}
	cmd.AddCommand(newAuditListCmd(env), newAuditTailCmd(env), newAuditExportCmd(env))
	return cmd
}

// auditEventView is the subset of schema AuditEvent this CLI renders.
type auditEventView struct {
	ID        string `json:"id"`
	Seq       int64  `json:"seq"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Actor     string `json:"actor"`
	MessageID string `json:"message_id"`
	Recipient string `json:"recipient"`
}

var auditTableHeaders = []string{"SEQ", "TIMESTAMP", "TYPE", "ACTOR", "MESSAGE_ID", "RECIPIENT"}

func auditRow(ev auditEventView) []string {
	return []string{strconv.FormatInt(ev.Seq, 10), ev.Timestamp, ev.Type, orDash(ev.Actor), orDash(ev.MessageID), orDash(ev.Recipient)}
}

func auditListQuery(messageID, typ, from, to string, limit int, cursor string) url.Values {
	q := url.Values{}
	setIfNonEmpty(q, "message_id", messageID)
	setIfNonEmpty(q, "type", typ)
	setIfNonEmpty(q, "from", from)
	setIfNonEmpty(q, "to", to)
	setIfNonEmpty(q, "cursor", cursor)
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return q
}

func newAuditListCmd(env *appEnv) *cobra.Command {
	var messageID, typ, from, to, cursor string
	var limit int
	var all bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit log events",
		Long:  "By default fetches a single page of GET /audit (the API's own cursor pagination, exposed via --cursor/--limit); pass --all to auto-paginate through every matching event instead.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			query := auditListQuery(messageID, typ, from, to, limit, cursor)

			if all {
				var rows [][]string
				err := env.client.fetchAllPages(cmd.Context(), "/audit", query, func(raw json.RawMessage) error {
					if env.jsonOut {
						return printJSONLine(env.stdout, raw)
					}
					var ev auditEventView
					if err := json.Unmarshal(raw, &ev); err != nil {
						return fmt.Errorf("decode audit event: %w", err)
					}
					rows = append(rows, auditRow(ev))
					return nil
				})
				if err != nil {
					return err
				}
				if !env.jsonOut {
					printTable(env.stdout, auditTableHeaders, rows)
				}
				return nil
			}

			items, next, err := env.client.fetchOnePage(cmd.Context(), "/audit", query)
			if err != nil {
				return err
			}
			var rows [][]string
			for _, raw := range items {
				if env.jsonOut {
					if err := printJSONLine(env.stdout, raw); err != nil {
						return err
					}
					continue
				}
				var ev auditEventView
				if err := json.Unmarshal(raw, &ev); err != nil {
					return fmt.Errorf("decode audit event: %w", err)
				}
				rows = append(rows, auditRow(ev))
			}
			if !env.jsonOut {
				printTable(env.stdout, auditTableHeaders, rows)
			}
			if next != "" {
				fmt.Fprintf(env.stderr, "attachractl: more results available; pass --cursor %s to continue (or --all to fetch everything)\n", next) //nolint:errcheck // best-effort hint
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&messageID, "message-id", "", "filter by message ID")
	cmd.Flags().StringVar(&typ, "type", "", "filter by audit event type")
	cmd.Flags().StringVar(&from, "from", "", "inclusive lower bound on timestamp (RFC3339)")
	cmd.Flags().StringVar(&to, "to", "", "exclusive upper bound on timestamp (RFC3339)")
	cmd.Flags().StringVar(&cursor, "cursor", "", "opaque pagination cursor from a previous page")
	cmd.Flags().IntVar(&limit, "limit", 0, "page size (server default 50, max 200)")
	cmd.Flags().BoolVar(&all, "all", false, "auto-paginate through every matching event instead of a single page")

	return cmd
}

// printAuditEventLine renders one audit event as a single line: a
// compact JSON line under --json (matching the API's own
// /audit/export format, SR-128-3), or a simple tab-separated line
// otherwise. It is used by `audit tail`, which may run indefinitely
// under --follow and so cannot buffer rows for an aligned table the
// way `audit list` does.
func printAuditEventLine(env *appEnv, raw json.RawMessage) (auditEventView, error) {
	var ev auditEventView
	if err := json.Unmarshal(raw, &ev); err != nil {
		return ev, fmt.Errorf("decode audit event: %w", err)
	}
	if env.jsonOut {
		return ev, printJSONLine(env.stdout, raw)
	}
	_, err := fmt.Fprintln(env.stdout, joinTab(auditRow(ev)))
	return ev, err
}

func joinTab(cols []string) string {
	out := cols[0]
	for _, c := range cols[1:] {
		out += "\t" + c
	}
	return out
}

func newAuditTailCmd(env *appEnv) *cobra.Command {
	var messageID, typ, from, to string
	var lines int
	var follow bool
	var interval time.Duration

	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent audit events, optionally following new ones",
		Long: "Fetches the last --lines matching events (walking every page of GET /audit internally, since the API's cursor only moves forward in ascending seq order), then, with --follow, polls for new events every --interval by filtering on the last seen event's seq/timestamp.\n\n" +
			"Cost note: because the API has no reverse/tail cursor, this always reads the filtered log from its beginning to its end to find the last --lines events, discarding everything but the tail as it goes (ATR-299) — on a large or unfiltered audit log this can mean fetching a lot more than --lines events over the wire. Narrow with --message-id/--type/--from/--to where possible; a server-side tail parameter is tracked as a follow-up, not yet implemented.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if lines <= 0 {
				return newCLIError(exitUsage, "audit tail: --lines must be positive")
			}

			query := auditListQuery(messageID, typ, from, to, maxAuditPageSize, "")

			buf := make([]json.RawMessage, 0, lines)
			err := env.client.fetchAllPages(cmd.Context(), "/audit", query, func(raw json.RawMessage) error {
				if len(buf) == lines {
					buf = append(buf[1:], raw)
				} else {
					buf = append(buf, raw)
				}
				return nil
			})
			if err != nil {
				return err
			}

			var lastSeq int64
			var lastTimestamp string
			for _, raw := range buf {
				ev, err := printAuditEventLine(env, raw)
				if err != nil {
					return err
				}
				lastSeq = ev.Seq
				lastTimestamp = ev.Timestamp
			}

			if !follow {
				return nil
			}
			return followAudit(cmd, env, messageID, typ, interval, lastSeq, lastTimestamp)
		},
	}

	cmd.Flags().StringVar(&messageID, "message-id", "", "filter by message ID")
	cmd.Flags().StringVar(&typ, "type", "", "filter by audit event type")
	cmd.Flags().StringVar(&from, "from", "", "inclusive lower bound on timestamp (RFC3339)")
	cmd.Flags().StringVar(&to, "to", "", "exclusive upper bound on timestamp (RFC3339)")
	cmd.Flags().IntVar(&lines, "lines", 20, "number of recent events to show")
	cmd.Flags().BoolVar(&follow, "follow", false, "keep running and print new events as they are recorded")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "polling interval when --follow is set")

	return cmd
}

// maxAuditPageSize mirrors the API contract's Limit maximum
// (api/openapi.yaml); `audit tail` always requests full pages since it
// discards everything but the last --lines results anyway.
const maxAuditPageSize = 200

// followAudit polls GET /audit every interval for events recorded
// after (lastSeq, lastTimestamp), printing each new one and advancing
// its watermark, until cmd's context is cancelled (e.g. Ctrl+C via the
// signal-derived context main.go builds).
func followAudit(cmd *cobra.Command, env *appEnv, messageID, typ string, interval time.Duration, lastSeq int64, lastTimestamp string) error {
	ctx := cmd.Context()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		// "from" is an inclusive lower bound on timestamp, so a poll may
		// re-see the last event(s) already printed at that exact
		// timestamp; the lastSeq comparison below discards them,
		// avoiding a duplicate print without needing the API to support
		// "seq greater than" filtering directly.
		query := auditListQuery(messageID, typ, lastTimestamp, "", maxAuditPageSize, "")

		err := env.client.fetchAllPages(ctx, "/audit", query, func(raw json.RawMessage) error {
			var ev auditEventView
			if err := json.Unmarshal(raw, &ev); err != nil {
				return fmt.Errorf("decode audit event: %w", err)
			}
			if ev.Seq <= lastSeq {
				return nil
			}
			if _, err := printAuditEventLine(env, raw); err != nil {
				return err
			}
			lastSeq = ev.Seq
			lastTimestamp = ev.Timestamp
			return nil
		})
		if err != nil {
			// A request that was in flight when ctx's deadline/cancellation
			// fired surfaces as a plain request error here, not as
			// ctx.Done() winning the select above — treat that the same
			// way as the graceful stop case, rather than reporting a
			// polling request racing shutdown as a hard CLI failure.
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func newAuditExportCmd(env *appEnv) *cobra.Command {
	var typ, from, to string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the full filtered audit log as JSON Lines",
		Long:  "Streams GET /audit/export directly to stdout without buffering: one JSON object per line, in ascending seq order, unaffected by --json (this command's output is always JSON Lines). Unlike `audit list`/`audit tail`, this is not paginated — narrow the result with --from/--to/--type.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			query := url.Values{}
			setIfNonEmpty(query, "type", typ)
			setIfNonEmpty(query, "from", from)
			setIfNonEmpty(query, "to", to)
			return env.client.streamGet(cmd.Context(), "/audit/export", query, env.stdout)
		},
	}

	cmd.Flags().StringVar(&typ, "type", "", "filter by audit event type")
	cmd.Flags().StringVar(&from, "from", "", "inclusive lower bound on timestamp (RFC3339)")
	cmd.Flags().StringVar(&to, "to", "", "exclusive upper bound on timestamp (RFC3339)")

	return cmd
}
