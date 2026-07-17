package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/302-digital/attachra/internal/core/audit"
)

// Exit codes for `attachra audit verify` (ATR-240). Distinct from an
// operational error so a caller (cron, CI, a compliance script) can tell
// "the chain is broken" (auditVerifyTampered) apart from "verification
// could not run" (auditVerifyError).
const (
	auditVerifyOK       = 0 // chain verified end-to-end
	auditVerifyTampered = 1 // a break was detected: altered/removed/reordered event, or an unestablished anchor
	auditVerifyError    = 2 // could not run: bad flags, unreadable input, store error
)

// runAuditVerify implements `attachra audit verify` (ATR-240): it walks
// the append-only audit log's per-row hash chain (SR-128-1) and reports
// whether it is intact, or the first point at which it breaks.
//
// It is strictly READ-ONLY with respect to the audit log: verification
// recomputes hashes from what is already stored and records nothing —
// were it to append its own event, running verify would perturb the very
// chain it checks (and recurse). By default it verifies the live log read
// from the metadata store; with --jsonl it instead verifies an offline
// segment previously produced by `attachra audit export` (a WORM/offsite
// archive), without touching the database.
//
// Honesty about scope (ADR-017 "Limitations"): a clean verdict proves the
// surviving chain has not been altered since its earliest trusted anchor.
// It does NOT prove that a truncation anchor is itself legitimate — an
// attacker with direct database write access can forge a
// retention_checkpoint. When any checkpoint is present the command says
// so explicitly, so nobody mistakes "the surviving chain verifies" for
// "nothing was ever removed". Two further, deliberate scope limits: a
// backward chain walk cannot detect deletion of the NEWEST events (the
// tail) — only an external high-water mark can (ADR-017 "Limitations");
// and --jsonl only proves the given file's own internal consistency, not
// that the file itself is genuine (see VerifyJSONL's doc comment).
func runAuditVerify(args []string, src audit.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attachra audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonlPath := fs.String("jsonl", "", "verify an exported JSON Lines segment at this path (\"-\" for stdin) instead of the live database")

	if err := fs.Parse(args); err != nil {
		return auditVerifyError
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "attachra: usage: attachra audit verify [--jsonl PATH]") //nolint:errcheck // best-effort diagnostic on stderr
		return auditVerifyError
	}

	report, err := runVerification(*jsonlPath, src)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: audit verify: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return auditVerifyError
	}

	writeVerifyReport(stdout, report, *jsonlPath)
	if report.OK {
		return auditVerifyOK
	}
	return auditVerifyTampered
}

// runVerification runs either the offline JSONL verification (when
// jsonlPath is set) or the live-database verification, returning the
// report and only an operational error (bad input / store failure); a
// detected tamper is a normal report with OK == false.
func runVerification(jsonlPath string, src audit.Reader) (audit.VerifyReport, error) {
	if jsonlPath == "" {
		return audit.Verify(context.Background(), src)
	}

	r, closeFn, err := openJSONLInput(jsonlPath)
	if err != nil {
		return audit.VerifyReport{}, err
	}
	defer closeFn()
	return audit.VerifyJSONL(r)
}

// openJSONLInput opens the JSONL segment to verify: stdin for "-", or the
// named file otherwise. The returned closeFn is always safe to call and is
// a no-op for stdin (the process does not own it).
func openJSONLInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path) //nolint:gosec // operator-supplied audit archive path, read-only.
	if err != nil {
		return nil, nil, fmt.Errorf("open jsonl segment %q: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// writeVerifyReport prints a human-readable verdict. On success it names
// the trusted start mode and, when the log has been truncated, states
// plainly that verification only covers history from the earliest anchor
// forward. On failure it prints the first break with its seq and the
// expected vs actual hash so an operator can locate the tampered row.
func writeVerifyReport(w io.Writer, r audit.VerifyReport, jsonlPath string) {
	source := "live audit log"
	if jsonlPath == "-" {
		source = "exported segment (stdin)"
	} else if jsonlPath != "" {
		source = fmt.Sprintf("exported segment %q", jsonlPath)
	}

	if !r.OK {
		fmt.Fprintf(w, "FAILED: %s tamper-evidence chain is broken.\n", source) //nolint:errcheck // best-effort report to stdout
		fmt.Fprintf(w, "  events checked: %d\n", r.EventsChecked)               //nolint:errcheck // best-effort report to stdout
		if r.Break != nil {
			fmt.Fprintf(w, "  first break at seq %d: %s\n", r.Break.Seq, r.Break.Reason) //nolint:errcheck // best-effort report to stdout
			if r.Break.ExpectedPrevHash != "" || r.Break.ActualPrevHash != "" {
				fmt.Fprintf(w, "    expected prev_hash: %s\n", hashOrNone(r.Break.ExpectedPrevHash)) //nolint:errcheck // best-effort report to stdout
				fmt.Fprintf(w, "    actual   prev_hash: %s\n", hashOrNone(r.Break.ActualPrevHash))   //nolint:errcheck // best-effort report to stdout
			}
		}
		return
	}

	if r.StartMode == audit.StartEmpty {
		fmt.Fprintf(w, "OK: %s is empty; nothing to verify.\n", source) //nolint:errcheck // best-effort report to stdout
		return
	}

	fmt.Fprintf(w, "OK: %s tamper-evidence chain verified.\n", source) //nolint:errcheck // best-effort report to stdout
	fmt.Fprintf(w, "  events checked: %d\n", r.EventsChecked)          //nolint:errcheck // best-effort report to stdout
	fmt.Fprintf(w, "  earliest surviving seq: %d\n", r.FirstSeq)       //nolint:errcheck // best-effort report to stdout
	fmt.Fprintf(w, "  trusted start: %s\n", r.StartMode)               //nolint:errcheck // best-effort report to stdout
	if r.CheckpointsPresent > 0 {
		fmt.Fprintf(w, "  note: %d truncation checkpoint(s) present; integrity verified from the earliest\n", r.CheckpointsPresent) //nolint:errcheck // best-effort report to stdout
		fmt.Fprintln(w, "        trusted anchor forward — pre-anchor history is not covered by this check.")                        //nolint:errcheck // best-effort report to stdout
		fmt.Fprintln(w, "        See docs/architecture/audit-retention.md and ADR-017 \"Limitations\".")                            //nolint:errcheck // best-effort report to stdout
	}
}

// hashOrNone renders an empty hash as "(none)" so a genesis/anchor
// boundary in a break report is unambiguous rather than a blank line.
func hashOrNone(h string) string {
	if h == "" {
		return "(none)"
	}
	return h
}
