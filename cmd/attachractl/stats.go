package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
)

// newStatsCmd builds `attachractl stats <subcommand>`, a thin client
// over the /stats resource (api/openapi.yaml, ATR-200/ATR-274):
// summary, deliverability.
func newStatsCmd(env *appEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Aggregated message/policy/download/deliverability statistics",
	}
	cmd.AddCommand(newStatsSummaryCmd(env), newStatsDeliverabilityCmd(env))
	return cmd
}

// dailyCountView mirrors schema DailyCount.
type dailyCountView struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

// labeledCountView mirrors schema LabeledCount.
type labeledCountView struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// statsSummaryView mirrors schema StatsSummary.
type statsSummaryView struct {
	From            string             `json:"from"`
	To              string             `json:"to"`
	MessagesByDay   []dailyCountView   `json:"messages_by_day"`
	ActionBreakdown []labeledCountView `json:"action_breakdown"`
	PolicyBreakdown []labeledCountView `json:"policy_breakdown"`
	Downloads       int64              `json:"downloads"`
	Errors          int64              `json:"errors"`
}

func newStatsSummaryCmd(env *appEnv) *cobra.Command {
	var from, to string

	cmd := &cobra.Command{
		Use:   "summary",
		Short: "Aggregated message/policy/download statistics for a time window",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if from == "" || to == "" {
				return newCLIError(exitUsage, "stats summary: --from and --to are required (RFC3339)")
			}
			query := url.Values{"from": {from}, "to": {to}}

			raw, err := env.client.get(cmd.Context(), "/stats/summary", query)
			if err != nil {
				return err
			}
			if env.jsonOut {
				return printJSONLine(env.stdout, raw)
			}

			var s statsSummaryView
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("decode stats summary: %w", err)
			}

			fmt.Fprintf(env.stdout, "window %s .. %s: downloads=%d errors=%d\n", s.From, s.To, s.Downloads, s.Errors) //nolint:errcheck // best-effort summary line

			fmt.Fprintln(env.stdout, "messages by day:") //nolint:errcheck // best-effort output
			dayRows := make([][]string, 0, len(s.MessagesByDay))
			for _, d := range s.MessagesByDay {
				dayRows = append(dayRows, []string{d.Day, formatCount(d.Count)})
			}
			printTable(env.stdout, []string{"DAY", "COUNT"}, dayRows)

			fmt.Fprintln(env.stdout, "action breakdown:") //nolint:errcheck // best-effort output
			printTable(env.stdout, []string{"ACTION", "COUNT"}, labeledCountRows(s.ActionBreakdown))

			fmt.Fprintln(env.stdout, "policy breakdown:") //nolint:errcheck // best-effort output
			printTable(env.stdout, []string{"POLICY", "COUNT"}, labeledCountRows(s.PolicyBreakdown))

			return nil
		},
	}

	cmd.Flags().StringVar(&from, "from", "", "inclusive lower bound of the window (RFC3339, required)")
	cmd.Flags().StringVar(&to, "to", "", "exclusive upper bound of the window (RFC3339, required)")

	return cmd
}

func labeledCountRows(items []labeledCountView) [][]string {
	rows := make([][]string, 0, len(items))
	for _, i := range items {
		rows = append(rows, []string{i.Label, formatCount(i.Count)})
	}
	return rows
}

// deliverabilityEntryView mirrors schema DeliverabilityEntry.
type deliverabilityEntryView struct {
	Domain          string  `json:"domain"`
	LinksCreated    int64   `json:"links_created"`
	LinksDownloaded int64   `json:"links_downloaded"`
	DownloadRate    float64 `json:"download_rate"`
}

func newStatsDeliverabilityCmd(env *appEnv) *cobra.Command {
	var from, to, sort, order string
	var limit int

	cmd := &cobra.Command{
		Use:   "deliverability",
		Short: "Link download-rate statistics broken down by recipient domain",
		Long:  "Surfaces which recipient domains are failing to retrieve their replaced attachments (ATR-231/ATR-274), sorted worst-performing first by default. Automatically walks every page of GET /stats/deliverability.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if from == "" || to == "" {
				return newCLIError(exitUsage, "stats deliverability: --from and --to are required (RFC3339)")
			}

			query := url.Values{"from": {from}, "to": {to}}
			setIfNonEmpty(query, "sort", sort)
			setIfNonEmpty(query, "order", order)
			if limit > 0 {
				query.Set("limit", strconv.Itoa(limit))
			}

			var rows [][]string
			err := env.client.fetchAllPages(cmd.Context(), "/stats/deliverability", query, func(raw json.RawMessage) error {
				if env.jsonOut {
					return printJSONLine(env.stdout, raw)
				}
				var d deliverabilityEntryView
				if err := json.Unmarshal(raw, &d); err != nil {
					return fmt.Errorf("decode deliverability entry: %w", err)
				}
				rows = append(rows, []string{
					d.Domain,
					formatCount(d.LinksCreated),
					formatCount(d.LinksDownloaded),
					strconv.FormatFloat(d.DownloadRate, 'f', 4, 64),
				})
				return nil
			})
			if err != nil {
				return err
			}
			if !env.jsonOut {
				printTable(env.stdout, []string{"DOMAIN", "LINKS_CREATED", "LINKS_DOWNLOADED", "DOWNLOAD_RATE"}, rows)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&from, "from", "", "inclusive lower bound of the window (RFC3339, required)")
	cmd.Flags().StringVar(&to, "to", "", "exclusive upper bound of the window (RFC3339, required)")
	cmd.Flags().StringVar(&sort, "sort", "", `sort key; only "download_rate" is supported`)
	cmd.Flags().StringVar(&order, "order", "", `sort order: "asc" (default, worst first) or "desc"`)
	cmd.Flags().IntVar(&limit, "limit", 0, "page size requested per API call (server default 50, max 200)")

	return cmd
}
