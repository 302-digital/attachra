package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/302-digital/attachra/internal/core/policy"
)

// Exit codes for `attachra policy validate` (T-4.2.3):
//   - policyValidateOK: the policy is valid (--strict has no warnings
//     to escalate, or was not passed).
//   - policyValidateInvalid: the policy failed validation (errors
//     present) or the command was invoked incorrectly (missing/extra
//     arguments).
//   - policyValidateWarnings: the policy is valid but produced
//     warnings, and --strict was passed, so warnings are treated as a
//     failure for CI/pre-deploy gating purposes.
const (
	policyValidateOK       = 0
	policyValidateInvalid  = 1
	policyValidateWarnings = 2
)

// runPolicyCommand dispatches `attachra policy <subcommand> ...`.
// Currently the only subcommand is `validate`.
func runPolicyCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(stderr, "attachra: usage: attachra policy validate [--strict] <file>") //nolint:errcheck // best-effort diagnostic on stderr
		return policyValidateInvalid
	}

	return runPolicyValidate(args[1:], stdout, stderr)
}

// runPolicyValidate implements `attachra policy validate [--strict] <file>`
// (T-4.2.3): it loads and validates the policy file at the given
// path, printing every error/warning found in the same human-readable
// form policy.DocumentError/policy.Parse already produce
// (docs/architecture/policy-format-v1.md §3.5), then returns the
// process exit code:
//
//   - 0 if the policy is valid and (with --strict) has no warnings;
//   - 1 if the policy fails validation, or the command line is
//     malformed;
//   - 2 if the policy is valid but has warnings and --strict was
//     passed.
func runPolicyValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attachra policy validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strict := fs.Bool("strict", false, "treat warnings as failures (exit code 2)")

	if err := fs.Parse(args); err != nil {
		return policyValidateInvalid
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "attachra: usage: attachra policy validate [--strict] <file>") //nolint:errcheck // best-effort diagnostic on stderr
		return policyValidateInvalid
	}
	path := fs.Arg(0)

	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied CLI argument, not untrusted input
	if err != nil {
		fmt.Fprintf(stderr, "attachra: policy validate: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return policyValidateInvalid
	}

	p, warnings, err := policy.Parse(data, path)
	if err != nil {
		fmt.Fprintln(stderr, err) //nolint:errcheck // DocumentError already formats one line per validation error
		return policyValidateInvalid
	}

	fmt.Fprintf(stdout, "policy %q is valid: %d rule(s), %d warning(s)\n", path, len(p.Rules), len(warnings)) //nolint:errcheck // best-effort diagnostic on stdout
	for _, w := range warnings {
		fmt.Fprintln(stdout, w) //nolint:errcheck // best-effort diagnostic on stdout
	}

	if *strict && len(warnings) > 0 {
		return policyValidateWarnings
	}
	return policyValidateOK
}
