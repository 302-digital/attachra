package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

// runMain contains the actual entrypoint logic and returns a process
// exit code, keeping main() itself trivial and testable indirectly
// (mirroring cmd/attachra/main.go's own run/main split).
func runMain(args []string, stdout, stderr io.Writer) int {
	// A signal-derived context lets `audit tail --follow` (the one
	// command that otherwise runs indefinitely) exit cleanly on
	// Ctrl+C/SIGTERM instead of being killed mid-request.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root, _ := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	if err := root.ExecuteContext(ctx); err != nil {
		printCLIError(stderr, err)
		return exitCodeForErr(err)
	}
	return exitOK
}

// printCLIError renders err to stderr. It never prints an *apiError's
// details unless they are the structured, non-sensitive
// ValidationIssue entries the API contract defines (policy
// validate/reload only) — no error path in this package ever wraps a
// value that could contain the bearer token.
func printCLIError(stderr io.Writer, err error) {
	fmt.Fprintln(stderr, "attachractl:", err) //nolint:errcheck // best-effort diagnostic on stderr

	var ae *apiError
	if errors.As(err, &ae) {
		for _, d := range ae.Details {
			fmt.Fprintf(stderr, "  - %s: %s\n", d.Path, d.Message) //nolint:errcheck // best-effort diagnostic on stderr
		}
	}
}
