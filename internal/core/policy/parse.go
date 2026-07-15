package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads a policy document from the file at path, parses it and
// validates it (see Parse and Validate). The returned error, if any,
// describes every validation error found (SR-119 / §3.5: "outputs all
// errors and warnings at once"); callers that want warnings
// separately from the fatal error should use Parse directly.
func Load(path string) (*Policy, error) {
	data, err := readPolicyFile(path)
	if err != nil {
		return nil, err
	}

	p, warnings, err := Parse(data, path)
	if err != nil {
		return nil, err
	}
	_ = warnings // Load callers that need warnings should call Parse directly.
	return p, nil
}

// readPolicyFile reads the raw bytes of the policy file at path,
// wrapping any error with context. Shared by Load and Store.Reload
// (store.go) so both go through the same file-reading path.
func readPolicyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied policy file path, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("policy: read %q: %w", path, err)
	}
	return data, nil
}

// Parse decodes and validates a single policy YAML document from
// data. name identifies the document in error and warning messages
// (typically a file name, e.g. "finance.yaml"); it may be empty.
//
// Parse uses strict decoding: any field not recognized by the schema
// (top-level or nested) is a validation error rather than being
// silently ignored, which protects against typos such as `rule:`
// instead of `rules:` (§2.1). A second YAML document in data is
// also rejected (§2.1: "multi-document is not supported in v1").
//
// On success, Parse returns the validated *Policy plus any non-fatal
// warnings (§3.5, e.g. unreachable rules after a catch-all). On
// failure, the returned error's message lists every validation error
// found, each naming the offending rule/field, and the *Policy return
// value is nil: an invalid policy must never be applied (SR-119-1,
// US-4.2).
func Parse(data []byte, name string) (*Policy, []string, error) {
	p, errs, warnings := parseIssues(data)
	if len(errs) > 0 {
		return nil, nil, policyError(name, errs)
	}
	return p, formatWarnings(name, warnings), nil
}

// ParseIssues is like Parse, but returns errors and warnings as
// structured *ValidationError values (path/rule_name/message) instead
// of Parse's human-formatted, document-name-prefixed strings — for
// callers that need machine-readable fields regardless of whether the
// document is valid (the HTTP API's POST /policies/validate, ATR-199,
// api/openapi.yaml schema ValidateResponse: both `errors` and
// `warnings` are arrays of ValidationIssue, not plain strings). Unlike
// Parse's *DocumentError, which only carries structured errors on the
// failure path, ParseIssues always returns warnings structured, on
// both outcomes.
//
// On success, p is the validated *Policy and errs is nil/empty; on
// failure, p is nil and errs lists every validation error found —
// there is no document name to prefix errors with here, since the
// caller (e.g. the HTTP API) reports path/rule_name/message as
// separate structured fields instead of a formatted string.
func ParseIssues(data []byte) (p *Policy, errs, warnings []*ValidationError) {
	return parseIssues(data)
}

// parseIssues is the shared implementation behind Parse and
// ParseIssues: decode (strict, single-document) and validate.
func parseIssues(data []byte) (p *Policy, errs, warnings []*ValidationError) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var pol Policy
	if err := dec.Decode(&pol); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, []*ValidationError{{Path: "document", Message: "policy document is empty"}}, nil
		}
		return nil, []*ValidationError{{Path: "document", Message: fmt.Sprintf("parse error: %v", err)}}, nil
	}

	// Reject a second YAML document in the same file (§2.1).
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, []*ValidationError{{Path: "document", Message: "only a single YAML document is supported, found more than one"}}, nil
	} else if !errors.Is(err, io.EOF) {
		return nil, []*ValidationError{{Path: "document", Message: fmt.Sprintf("parse error: %v", err)}}, nil
	}

	errs, warnings = validate(&pol)
	if len(errs) > 0 {
		return nil, errs, warnings
	}

	return &pol, nil, warnings
}
