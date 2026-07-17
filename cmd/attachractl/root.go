package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// appEnv carries per-invocation state shared by every subcommand: the
// output writers and the resolved API client, built once in
// PersistentPreRunE from whichever connection flags/env/config file
// resolveConnectConfig found. A command that needs a non-zero exit for
// an outcome that is not itself a Go error (e.g. `policy validate`
// finding errors in the submitted document — a successfully completed
// check, not a CLI failure) returns a *cliError (errors.go) from RunE
// rather than mutating shared state here, so main's single
// error-handling path covers every case uniformly.
type appEnv struct {
	stdout  io.Writer
	stderr  io.Writer
	client  *Client
	jsonOut bool
}

// newRootCmd builds the full attachractl command tree. stdout/stderr
// are injected rather than assumed to be os.Stdout/os.Stderr so tests
// can capture output and run entirely in-process, without a real
// subprocess.
func newRootCmd(stdout, stderr io.Writer) (*cobra.Command, *appEnv) {
	env := &appEnv{stdout: stdout, stderr: stderr}
	var flags connectFlags

	root := &cobra.Command{
		Use:           "attachractl",
		Short:         "Command-line client for the Attachra admin/automation REST API",
		Long:          "attachractl drives a running Attachra instance entirely over its /api/v1 REST API (api/openapi.yaml) — it never touches the metadata store or configuration directly.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// `attachractl version` needs no connection at all — every
			// other command does, so this is the one exception.
			if cmd.Name() == "version" {
				return nil
			}

			cfg, err := resolveConnectConfig(flags, os.Getenv)
			if err != nil {
				return err
			}
			if cfg.Insecure {
				fmt.Fprintln(stderr, "attachractl: WARNING: TLS certificate verification is disabled (--insecure); do not use this against an untrusted network") //nolint:errcheck // best-effort warning
			}
			for _, w := range cfg.Warnings {
				fmt.Fprintln(stderr, "attachractl: WARNING:", w) //nolint:errcheck // best-effort warning
			}

			client, err := newClient(cfg)
			if err != nil {
				return err
			}
			env.client = client
			env.jsonOut = flags.jsonOut
			return nil
		},
	}

	root.PersistentFlags().StringVar(&flags.configPath, "config", defaultConfigPath(), "path to the attachractl config file")
	root.PersistentFlags().StringVar(&flags.url, "url", "", "Attachra API base URL, e.g. https://attachra.example.com (env ATTACHRACTL_URL)")
	root.PersistentFlags().StringVar(&flags.tokenFile, "token-file", "", "path to a file containing the bearer token (env ATTACHRACTL_TOKEN for the raw value); the token is never accepted as a flag value")
	root.PersistentFlags().BoolVar(&flags.insecure, "insecure", false, "skip TLS certificate verification (INSECURE — testing only)")
	root.PersistentFlags().BoolVar(&flags.jsonOut, "json", false, "output machine-readable JSON instead of a human-readable table")
	root.PersistentFlags().DurationVar(&flags.timeout, "timeout", 30*time.Second, "request timeout")

	root.AddCommand(
		newPolicyCmd(env),
		newLinksCmd(env),
		newStatsCmd(env),
		newAuditCmd(env),
		newTokenCmd(env),
		newVersionCmd(env),
	)

	return root, env
}
