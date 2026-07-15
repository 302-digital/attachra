package policy

import (
	"fmt"
	"strings"
)

// ValidationError is a single validation problem found while
// validating a Policy (§3.5). Path is a JSON-pointer-like location
// such as "rules[2].then" or "default"; RuleName, when non-empty,
// names the offending rule so a business user can find it by name
// rather than by index (§3.5: "name the rule by `name`, not just by
// index").
type ValidationError struct {
	Path     string
	RuleName string
	Message  string
}

// Error implements the error interface, formatting the same way as
// the examples in §3.5: `error at <path>: <message>`, with the rule
// name prefixed when known.
func (e *ValidationError) Error() string {
	if e.RuleName != "" {
		return fmt.Sprintf("error at %s (rule %q): %s", e.Path, e.RuleName, e.Message)
	}
	return fmt.Sprintf("error at %s: %s", e.Path, e.Message)
}

// DocumentError aggregates every ValidationError found while
// validating a policy document (§3.5: "outputs all errors ... at
// once, not just the first"). It is returned by Parse/Load instead of
// the first error encountered.
type DocumentError struct {
	// Name identifies the document (e.g. a file name); may be empty.
	Name string
	// Errors lists every validation error found, in the order
	// encountered.
	Errors []*ValidationError
}

// Error implements the error interface, listing every contained
// error on its own line, prefixed with the document name as in the
// §3.5 examples (`policy "finance.yaml": error at ...`).
func (e *DocumentError) Error() string {
	prefix := "policy"
	if e.Name != "" {
		prefix = fmt.Sprintf("policy %q", e.Name)
	}

	lines := make([]string, len(e.Errors))
	for i, ve := range e.Errors {
		lines[i] = fmt.Sprintf("%s: %s", prefix, ve.Error())
	}
	return strings.Join(lines, "\n")
}

// policyError wraps a non-empty slice of ValidationErrors produced by
// validate into a *DocumentError for the named document.
func policyError(name string, errs []*ValidationError) *DocumentError {
	return &DocumentError{Name: name, Errors: errs}
}

// formatWarnings renders warning ValidationErrors as strings, in the
// same "policy <name>: warning at <path>: <message>" shape used for
// errors (§3.5), for callers (e.g. a future `attachractl policy
// validate`, T-4.2.3) that display them to the operator.
func formatWarnings(name string, warnings []*ValidationError) []string {
	prefix := "policy"
	if name != "" {
		prefix = fmt.Sprintf("policy %q", name)
	}

	out := make([]string, len(warnings))
	for i, w := range warnings {
		out[i] = fmt.Sprintf("%s: warning %s", prefix, strings.TrimPrefix(w.Error(), "error "))
	}
	return out
}
