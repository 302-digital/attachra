package main

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

// newTokenCmd builds `attachractl token <subcommand>`, a thin client
// over the /api-tokens resource (api/openapi.yaml, ATR-201): create,
// list, revoke. All three are admin-only on the API.
func newTokenCmd(env *appEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage API tokens",
	}
	cmd.AddCommand(newTokenCreateCmd(env), newTokenListCmd(env), newTokenRevokeCmd(env))
	return cmd
}

// apiTokenView is the subset of schema ApiToken this CLI renders. It
// never carries a secret or hash (SR-130-2, CLAUDE.md invariant #5) —
// neither does the API response it is decoded from, for any operation
// except create.
type apiTokenView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"`
}

var tokenTableHeaders = []string{"ID", "NAME", "ROLE", "CREATED_AT", "LAST_USED_AT"}

func tokenRow(t apiTokenView) []string {
	return []string{t.ID, t.Name, t.Role, t.CreatedAt, orDash(t.LastUsedAt)}
}

// apiTokenCreateResponseView mirrors schema ApiTokenCreateResponse: the
// token metadata plus the one-time secret.
type apiTokenCreateResponseView struct {
	apiTokenView
	Secret string `json:"secret"`
}

func newTokenCreateCmd(env *appEnv) *cobra.Command {
	var name, role string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API token",
		Long:  "Calls POST /api-tokens (admin only). The response's secret is the only time the raw bearer token is ever shown — it is printed to stdout on its own line so scripts can capture it directly (e.g. `attachractl token create --name ci --role viewer > token.secret`); the id/name/role summary goes to stderr instead, and neither is ever logged.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return newCLIError(exitUsage, "token create: --name is required")
			}
			if role == "" {
				return newCLIError(exitUsage, "token create: --role is required (admin, viewer or auditor)")
			}

			raw, err := env.client.postJSON(cmd.Context(), "POST", "/api-tokens", nil, map[string]string{"name": name, "role": role})
			if err != nil {
				return err
			}

			if env.jsonOut {
				return printJSONLine(env.stdout, raw)
			}

			var resp apiTokenCreateResponseView
			if err := json.Unmarshal(raw, &resp); err != nil {
				return fmt.Errorf("decode token create response: %w", err)
			}
			fmt.Fprintf(env.stderr, "attachractl: created token %q (id %s, role %s) — the secret below is shown once and never persisted\n", resp.Name, resp.ID, resp.Role) //nolint:errcheck // best-effort info line, kept off stdout so it never pollutes a captured secret
			fmt.Fprintln(env.stdout, resp.Secret)                                                                                                                           //nolint:errcheck // best-effort output of the one-time secret
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "operator-chosen label for the token (required)")
	cmd.Flags().StringVar(&role, "role", "", "token role: admin, viewer or auditor (required)")

	return cmd
}

func newTokenListCmd(env *appEnv) *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API tokens",
		Long:  "Lists every token's metadata (never a secret or hash), automatically walking every page of GET /api-tokens.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			query := url.Values{}
			if limit > 0 {
				query.Set("limit", fmt.Sprintf("%d", limit))
			}

			var rows [][]string
			err := env.client.fetchAllPages(cmd.Context(), "/api-tokens", query, func(raw json.RawMessage) error {
				if env.jsonOut {
					return printJSONLine(env.stdout, raw)
				}
				var t apiTokenView
				if err := json.Unmarshal(raw, &t); err != nil {
					return fmt.Errorf("decode token: %w", err)
				}
				rows = append(rows, tokenRow(t))
				return nil
			})
			if err != nil {
				return err
			}
			if !env.jsonOut {
				printTable(env.stdout, tokenTableHeaders, rows)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 0, "page size requested per API call (server default 50, max 200)")

	return cmd
}

func newTokenRevokeCmd(env *appEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Revoke an API token",
		Long:  "Calls DELETE /api-tokens/{tokenId} (admin only). Takes effect immediately — the next request bearing that token's secret is rejected as 401.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := env.client.delete(cmd.Context(), "/api-tokens/"+url.PathEscape(args[0])); err != nil {
				return err
			}
			if !env.jsonOut {
				fmt.Fprintf(env.stdout, "token %s: revoked\n", args[0]) //nolint:errcheck // best-effort confirmation line
			}
			return nil
		},
	}
}
