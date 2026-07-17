package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
)

// Exit codes for `attachra audit export` (T-7.1.3).
const (
	auditExportOK    = 0
	auditExportError = 1
)

// runAuditCommand dispatches `attachra audit <subcommand> ...`.
// Subcommands: `export` (stream the log as JSON Lines) and `verify`
// (check the tamper-evidence hash chain, ATR-240).
func runAuditCommand(args []string, sink audit.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "attachra: usage: attachra audit (export|verify) ...") //nolint:errcheck // best-effort diagnostic on stderr
		return auditExportError
	}
	switch args[0] {
	case "export":
		return runAuditExport(args[1:], sink, stdout, stderr)
	case "verify":
		return runAuditVerify(args[1:], sink, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "attachra: usage: attachra audit (export|verify) ...") //nolint:errcheck // best-effort diagnostic on stderr
		return auditExportError
	}
}

// runAuditExport implements `attachra audit export` (T-7.1.3,
// SR-128-3): it streams every audit event matching the given filter to
// stdout as JSON Lines (one compact JSON object per line), for
// ingestion into an external immutable store/SIEM. Output is streamed
// via audit.ExportJSONL, so memory use is independent of how large the
// audit log has grown (the streaming invariant — no full-message buffering).
func runAuditExport(args []string, sink audit.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attachra audit export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "only include events at or after this RFC3339 timestamp")
	to := fs.String("to", "", "only include events strictly before this RFC3339 timestamp")
	typ := fs.String("type", "", "only include events of this type (e.g. download, revoke, error)")

	if err := fs.Parse(args); err != nil {
		return auditExportError
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "attachra: usage: attachra audit export [--from RFC3339] [--to RFC3339] [--type TYPE]") //nolint:errcheck // best-effort diagnostic on stderr
		return auditExportError
	}

	filter, err := parseAuditExportFilter(*from, *to, *typ)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: audit export: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return auditExportError
	}

	if err := audit.ExportJSONL(context.Background(), sink, stdout, filter); err != nil {
		fmt.Fprintf(stderr, "attachra: audit export: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return auditExportError
	}
	return auditExportOK
}

// parseAuditExportFilter parses the --from/--to/--type flag values
// into an audit.Filter, leaving From/To zero when the corresponding
// flag was not supplied (audit.Filter's own zero-value convention for
// "no bound").
func parseAuditExportFilter(from, to, typ string) (audit.Filter, error) {
	var filter audit.Filter

	if from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			return audit.Filter{}, fmt.Errorf("parse --from %q: %w", from, err)
		}
		filter.From = t
	}
	if to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			return audit.Filter{}, fmt.Errorf("parse --to %q: %w", to, err)
		}
		filter.To = t
	}
	if typ != "" {
		filter.Type = audit.Type(typ)
	}

	return filter, nil
}
