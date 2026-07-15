package main

import (
	"fmt"

	"github.com/302-digital/attachra/internal/version"
	"github.com/spf13/cobra"
)

// newVersionCmd builds `attachractl version`. It is the one command
// exempt from PersistentPreRunE's connection resolution (root.go) —
// printing the client's own build metadata needs no API endpoint or
// token at all.
func newVersionCmd(env *appEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the attachractl version and exit",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(env.stdout, "attachractl %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
			return err
		},
	}
}
