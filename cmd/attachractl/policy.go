package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// newPolicyCmd builds `attachractl policy <subcommand>`, a thin client
// over the /policies resource (api/openapi.yaml, ATR-199): current,
// validate, reload, dry-run.
func newPolicyCmd(env *appEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and control the active policy",
	}
	cmd.AddCommand(
		newPolicyCurrentCmd(env),
		newPolicyValidateCmd(env),
		newPolicyReloadCmd(env),
		newPolicyDryRunCmd(env),
	)
	return cmd
}

// policyRuleView is the subset of schema Rule this CLI renders in a
// table; unknown/extra JSON fields (When, ttl_seconds, ...) are simply
// ignored by json.Unmarshal, so this stays forward-compatible with
// contract additions the table does not care about.
type policyRuleView struct {
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
	Then     struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	} `json:"then"`
}

// policyView is the subset of schema Policy this CLI renders.
type policyView struct {
	Version int              `json:"version"`
	Name    string           `json:"name"`
	Rules   []policyRuleView `json:"rules"`
	Default struct {
		Action string `json:"action"`
	} `json:"default"`
}

func newPolicyCurrentCmd(env *appEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the currently active policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := env.client.get(cmd.Context(), "/policies/current", nil)
			if err != nil {
				return err
			}
			if env.jsonOut {
				return printJSONLine(env.stdout, raw)
			}

			var p policyView
			if err := json.Unmarshal(raw, &p); err != nil {
				return fmt.Errorf("decode policy: %w", err)
			}
			fmt.Fprintf(env.stdout, "policy %q (version %d, %d rule(s), default action %s)\n", p.Name, p.Version, len(p.Rules), p.Default.Action) //nolint:errcheck // best-effort summary line
			rows := make([][]string, 0, len(p.Rules))
			for _, r := range p.Rules {
				rows = append(rows, []string{r.Name, r.Then.Action, strconv.FormatBool(r.Disabled), r.Then.Reason})
			}
			printTable(env.stdout, []string{"NAME", "ACTION", "DISABLED", "REASON"}, rows)
			return nil
		},
	}
}

// validateResponseView mirrors schema ValidateResponse.
type validateResponseView struct {
	Valid    bool             `json:"valid"`
	Errors   []apiErrorDetail `json:"errors"`
	Warnings []apiErrorDetail `json:"warnings"`
}

func newPolicyValidateCmd(env *appEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a candidate policy document without applying it",
		Long:  "Sends the given local YAML file to POST /policies/validate. Every error and warning found is printed; a document with errors exits non-zero (suitable for a CI gate).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data, err := os.ReadFile(path) //nolint:gosec // operator-supplied CLI argument, not untrusted input
			if err != nil {
				return newCLIError(exitUsage, "policy validate: %w", err)
			}

			raw, err := env.client.postRaw(cmd.Context(), "/policies/validate", data, "application/x-yaml")
			if err != nil {
				return err
			}

			var resp validateResponseView
			if err := json.Unmarshal(raw, &resp); err != nil {
				return fmt.Errorf("decode validate response: %w", err)
			}

			if env.jsonOut {
				if err := printJSONLine(env.stdout, raw); err != nil {
					return err
				}
			} else {
				printValidateResult(env.stdout, path, resp)
			}

			if !resp.Valid {
				return newCLIError(exitValidation, "policy %q has %d error(s)", path, len(resp.Errors))
			}
			return nil
		},
	}
}

func printValidateResult(w io.Writer, path string, resp validateResponseView) {
	status := "VALID"
	if !resp.Valid {
		status = "INVALID"
	}
	fmt.Fprintf(w, "policy %q: %s (%d error(s), %d warning(s))\n", path, status, len(resp.Errors), len(resp.Warnings)) //nolint:errcheck // best-effort summary line
	if len(resp.Errors) > 0 {
		fmt.Fprintln(w, "errors:") //nolint:errcheck // best-effort output
		printTable(w, []string{"PATH", "RULE", "MESSAGE"}, issueRows(resp.Errors))
	}
	if len(resp.Warnings) > 0 {
		fmt.Fprintln(w, "warnings:") //nolint:errcheck // best-effort output
		printTable(w, []string{"PATH", "RULE", "MESSAGE"}, issueRows(resp.Warnings))
	}
}

func issueRows(issues []apiErrorDetail) [][]string {
	rows := make([][]string, 0, len(issues))
	for _, i := range issues {
		rows = append(rows, []string{i.Path, orDash(i.RuleName), i.Message})
	}
	return rows
}

// reloadResponseView mirrors schema ReloadResponse.
type reloadResponseView struct {
	Policy struct {
		Name      string `json:"name"`
		Version   int    `json:"version"`
		RuleCount int    `json:"rule_count"`
	} `json:"policy"`
	Warnings []string `json:"warnings"`
}

func newPolicyReloadCmd(env *appEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Re-read and apply the configured policy file from disk",
		Long:  "Calls POST /policies/reload (admin only). If the file on disk fails to validate, the server rejects the reload with 409 and the previously active policy remains in effect.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := env.client.postJSON(cmd.Context(), "POST", "/policies/reload", nil, nil)
			if err != nil {
				return err
			}

			if env.jsonOut {
				return printJSONLine(env.stdout, raw)
			}

			var resp reloadResponseView
			if err := json.Unmarshal(raw, &resp); err != nil {
				return fmt.Errorf("decode reload response: %w", err)
			}
			fmt.Fprintf(env.stdout, "policy reloaded: %q (version %d, %d rule(s), %d warning(s))\n", resp.Policy.Name, resp.Policy.Version, resp.Policy.RuleCount, len(resp.Warnings)) //nolint:errcheck // best-effort summary line
			for _, w := range resp.Warnings {
				fmt.Fprintln(env.stdout, "  warning:", w) //nolint:errcheck // best-effort output
			}
			return nil
		},
	}
}

// dryRunAttachmentDecisionView mirrors schema DryRunAttachmentDecision.
type dryRunAttachmentDecisionView struct {
	Filename         string `json:"filename"`
	Action           string `json:"action"`
	RuleName         string `json:"rule_name"`
	Reason           string `json:"reason"`
	TTLSeconds       *int64 `json:"ttl_seconds"`
	MaxDownloads     *int   `json:"max_downloads"`
	RetentionSeconds *int64 `json:"retention_seconds"`
}

// dryRunResponseView mirrors schema DryRunResponse.
type dryRunResponseView struct {
	Action      string                         `json:"action"`
	Reason      string                         `json:"reason"`
	Attachments []dryRunAttachmentDecisionView `json:"attachments"`
}

// dryRunAttachmentRequest mirrors schema DryRunAttachment (the request
// side).
type dryRunAttachmentRequest struct {
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	DeclaredType string `json:"declared_type,omitempty"`
	DetectedType string `json:"detected_type"`
}

// dryRunRequest mirrors schema DryRunRequest.
type dryRunRequest struct {
	Sender      string                    `json:"sender"`
	Recipients  []string                  `json:"recipients"`
	Attachments []dryRunAttachmentRequest `json:"attachments"`
}

func newPolicyDryRunCmd(env *appEnv) *cobra.Command {
	var sender string
	var recipients []string
	var attachments []string
	var file string

	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Evaluate the active policy against a hypothetical message",
		Long: "Calls POST /policies/dry-run: a pure, side-effect-free simulation of what the active policy would decide, without creating a message, attachment, link or audit event.\n\n" +
			"Either pass --file/-f pointing at a JSON document matching the DryRunRequest schema (api/openapi.yaml) — use \"-\" for stdin — or build the request from flags: --sender, one or more --recipient, and one or more --attachment in \"filename:size[:mime_type[:detected_type]]\" form (mime_type is used as both declared_type and detected_type unless a fourth field overrides detected_type).\n\n" +
			"A filename containing a colon cannot be expressed in --attachment's \":\"-delimited form; use --file with a JSON document instead (its \"filename\" field takes any string verbatim).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, err := buildDryRunRequest(file, sender, recipients, attachments)
			if err != nil {
				return newCLIError(exitUsage, "policy dry-run: %w", err)
			}

			raw, err := env.client.postJSON(cmd.Context(), "POST", "/policies/dry-run", nil, req)
			if err != nil {
				return err
			}

			if env.jsonOut {
				return printJSONLine(env.stdout, raw)
			}

			var resp dryRunResponseView
			if err := json.Unmarshal(raw, &resp); err != nil {
				return fmt.Errorf("decode dry-run response: %w", err)
			}
			fmt.Fprintf(env.stdout, "message action: %s%s\n", resp.Action, formatReasonSuffix(resp.Reason)) //nolint:errcheck // best-effort summary line
			rows := make([][]string, 0, len(resp.Attachments))
			for _, a := range resp.Attachments {
				rows = append(rows, []string{a.Filename, a.Action, orDash(a.RuleName), orDash(a.Reason), orDashInt(a.TTLSeconds)})
			}
			printTable(env.stdout, []string{"FILENAME", "ACTION", "RULE", "REASON", "TTL_SECONDS"}, rows)
			return nil
		},
	}

	cmd.Flags().StringVar(&sender, "sender", "", "envelope sender address")
	cmd.Flags().StringArrayVar(&recipients, "recipient", nil, "recipient address (repeatable)")
	cmd.Flags().StringArrayVar(&attachments, "attachment", nil, `attachment in "filename:size[:mime_type[:detected_type]]" form (repeatable); a filename containing ":" is not expressible here, use --file instead`)
	cmd.Flags().StringVarP(&file, "file", "f", "", `read the full DryRunRequest JSON body from this file, or "-" for stdin, instead of --sender/--recipient/--attachment`)

	return cmd
}

func formatReasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

// buildDryRunRequest builds the request body either by reading a full
// JSON document (file != "") or by assembling one from the individual
// flags, validating the flag-based inputs are internally consistent
// before ever making a network call.
func buildDryRunRequest(file, sender string, recipients, attachments []string) (*dryRunRequest, error) {
	if file != "" {
		var r io.Reader
		if file == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(file) //nolint:gosec // operator-supplied CLI argument, not untrusted input
			if err != nil {
				return nil, fmt.Errorf("read dry-run request file %q: %w", file, err)
			}
			defer f.Close() //nolint:errcheck // read-only file, close error is not actionable
			r = f
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("read dry-run request: %w", err)
		}
		var req dryRunRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, fmt.Errorf("parse dry-run request JSON: %w", err)
		}
		return &req, nil
	}

	if sender == "" {
		return nil, fmt.Errorf("--sender is required (or use --file)")
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one --recipient is required (or use --file)")
	}
	if len(attachments) == 0 {
		return nil, fmt.Errorf("at least one --attachment is required (or use --file)")
	}

	req := &dryRunRequest{Sender: sender, Recipients: recipients}
	for _, spec := range attachments {
		att, err := parseAttachmentFlag(spec)
		if err != nil {
			return nil, err
		}
		req.Attachments = append(req.Attachments, att)
	}
	return req, nil
}

// parseAttachmentFlag parses one --attachment value in
// "filename:size[:mime_type[:detected_type]]" form: mime_type sets
// both declared_type and detected_type unless a distinct fourth field
// is given to override detected_type alone (the common case for
// testing "what if the declared and sniffed types disagree").
func parseAttachmentFlag(spec string) (dryRunAttachmentRequest, error) {
	parts := strings.SplitN(spec, ":", 4)
	if len(parts) < 2 {
		return dryRunAttachmentRequest{}, fmt.Errorf(`invalid --attachment %q, expected "filename:size[:mime_type[:detected_type]]"`, spec)
	}
	filename := parts[0]
	if filename == "" {
		return dryRunAttachmentRequest{}, fmt.Errorf("invalid --attachment %q: filename must not be empty", spec)
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || size < 0 {
		return dryRunAttachmentRequest{}, fmt.Errorf("invalid --attachment %q: size must be a non-negative integer", spec)
	}

	att := dryRunAttachmentRequest{Filename: filename, Size: size, DetectedType: "application/octet-stream"}
	if len(parts) >= 3 && parts[2] != "" {
		att.DeclaredType = parts[2]
		att.DetectedType = parts[2]
	}
	if len(parts) == 4 && parts[3] != "" {
		att.DetectedType = parts[3]
	}
	return att, nil
}
