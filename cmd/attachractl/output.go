package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
)

// printTable renders headers and rows as an aligned, human-readable
// table using text/tabwriter (standard library — no third-party table
// dependency is warranted for this). It is the default rendering for
// every list/get command when --json is not given.
func printTable(w io.Writer, headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t")) //nolint:errcheck // best-effort table output
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t")) //nolint:errcheck // best-effort table output
	}
	_ = tw.Flush()
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no results)") //nolint:errcheck // best-effort table output
	}
}

// printJSONLine writes raw as a single compact JSON line, re-encoding
// it if the server's own output were ever to include insignificant
// whitespace (json.Compact is a cheap no-op on already-compact input).
// Used for every `--json` list command and for `audit list`/`audit
// tail`, matching the API's own /audit/export JSON Lines format
// (SR-128-3) so every --json list output attachractl produces is
// uniformly one JSON object per line.
func printJSONLine(w io.Writer, raw json.RawMessage) error {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return fmt.Errorf("compact JSON output: %w", err)
	}
	buf.WriteByte('\n')
	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write JSON output: %w", err)
	}
	return nil
}

// formatCount renders an int64 count as a plain decimal string —
// small helper so every table-building function does not need to
// import strconv itself.
func formatCount(n int64) string {
	return strconv.FormatInt(n, 10)
}

// orDash returns s, or "-" if s is empty — used for table cells that
// are optional/nullable on the wire (e.g. a link's hold_set_by).
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// orDashInt formats an *int64 as a decimal string, or "-" if nil.
func orDashInt(n *int64) string {
	if n == nil {
		return "-"
	}
	return strconv.FormatInt(*n, 10)
}
