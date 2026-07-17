package policy

import (
	"fmt"
	"strings"
)

// supportedVersion is the maximum policy format major version this
// build understands (§7.1). A policy requesting a higher version is
// rejected with a message telling the operator to upgrade, rather
// than risking silent misinterpretation.
const supportedVersion = 1

// validate checks p against every rule in §3.5, returning the fatal
// errors (if any, the policy must not be applied) and non-fatal
// warnings separately. It also compiles glob patterns and duration/
// size values are already parsed by the YAML unmarshalers by the time
// validate runs.
func validate(p *Policy) (errs, warnings []*ValidationError) {
	if p.Version == 0 {
		errs = append(errs, &ValidationError{Path: "version", Message: "version is required"})
	} else if p.Version > supportedVersion {
		errs = append(errs, &ValidationError{
			Path: "version",
			Message: fmt.Sprintf("policy requires format version %d, this build supports up to %d; upgrade Attachra",
				p.Version, supportedVersion),
		})
	} else if p.Version != supportedVersion {
		errs = append(errs, &ValidationError{
			Path:    "version",
			Message: fmt.Sprintf("unsupported version %d, this build supports version %d", p.Version, supportedVersion),
		})
	}

	if p.Name == "" {
		errs = append(errs, &ValidationError{Path: "name", Message: "name is required"})
	}

	for i, r := range p.Rules {
		re, rw := validateRule(i, r)
		errs = append(errs, re...)
		warnings = append(warnings, rw...)
	}

	// Default is required (§2.1, SR-119-1): a missing default must
	// never resolve to a silent pass.
	if p.Default.Action == "" {
		errs = append(errs, &ValidationError{Path: "default", Message: "default action is required and must not be omitted (a policy must never silently pass attachments by default)"})
	} else {
		aerrs, awarnings := validateActionBlock("default", "", p.Default)
		errs = append(errs, aerrs...)
		warnings = append(warnings, awarnings...)
	}

	warnings = append(warnings, unreachableRuleWarnings(p.Rules)...)

	return errs, warnings
}

// validateRule validates a single rules[i] entry, returning its
// errors and warnings.
func validateRule(i int, r Rule) (errs, warnings []*ValidationError) {
	path := fmt.Sprintf("rules[%d]", i)

	if r.Name == "" {
		errs = append(errs, &ValidationError{Path: path, Message: "rule name is required"})
	}

	if r.Then.Action == "" {
		errs = append(errs, &ValidationError{Path: path + ".then", RuleName: r.Name, Message: "then.action is required and must be one of: pass, replace, block"})
	} else {
		aerrs, awarnings := validateActionBlock(path+".then", r.Name, r.Then)
		errs = append(errs, aerrs...)
		warnings = append(warnings, awarnings...)
	}

	if r.When != nil {
		werrs, wwarnings := validateWhen(path+".when", r.Name, r.When)
		errs = append(errs, werrs...)
		warnings = append(warnings, wwarnings...)
	}

	return errs, warnings
}

// validateActionBlock enforces the `then`/`default` consistency rules
// in §2.4: ttl/max_downloads/retention/link only apply to `replace`;
// reason only applies to `block`. It also implements two §3.5
// warnings for `replace`:
//   - an explicit `ttl` but no `retention` is valid (retention falls
//     back to the global config, US-5.3) but worth flagging so the
//     author knows the object outlives the link by an implicit
//     amount;
//   - an explicit `retention` shorter than an explicit `ttl` is also
//     valid — link.Engine.CreateLinks silently raises it to match ttl
//     at runtime (T-5.3.1/ATR-178: a link must never outlive the
//     object it points to) — but this is exactly the case where the
//     policy's literal `retention:` value diverges from what storage
//     actually keeps, worth catching here with the rule name attached
//     rather than only learning about it from the runtime clamp
//     warning link.Engine.CreateLinks logs (ATR-294), which has no
//     rule-name context by the time it runs.
func validateActionBlock(path, ruleName string, a ActionSpec) (errs, warnings []*ValidationError) {
	switch a.Action {
	case ActionPass, ActionReplace, ActionBlock:
		// valid enum value
	default:
		errs = append(errs, &ValidationError{Path: path, RuleName: ruleName, Message: fmt.Sprintf("field %q has invalid value %q (want one of: pass, replace, block)", "action", a.Action)})
		return errs, warnings
	}

	if a.Action != ActionReplace {
		if a.TTL != nil {
			errs = append(errs, fieldOnlyValidFor(path, ruleName, "ttl", "replace", a.Action))
		}
		if a.MaxDownloads != nil {
			errs = append(errs, fieldOnlyValidFor(path, ruleName, "max_downloads", "replace", a.Action))
		}
		if a.Retention != nil {
			errs = append(errs, fieldOnlyValidFor(path, ruleName, "retention", "replace", a.Action))
		}
		if a.Link != nil {
			errs = append(errs, fieldOnlyValidFor(path, ruleName, "link", "replace", a.Action))
		}
	} else if a.TTL != nil && a.Retention == nil {
		warnings = append(warnings, &ValidationError{
			Path:     path,
			RuleName: ruleName,
			Message:  "replace has an explicit ttl but no retention; retention will fall back to the global config default",
		})
	} else if a.TTL != nil && a.Retention != nil && a.Retention.Duration() < a.TTL.Duration() {
		warnings = append(warnings, &ValidationError{
			Path:     path,
			RuleName: ruleName,
			Message:  fmt.Sprintf("retention (%s) is shorter than ttl (%s); retention will be raised to match ttl at run time (a link must never outlive the object it points to)", a.Retention.Duration(), a.TTL.Duration()),
		})
	}

	if a.Action != ActionBlock && a.Reason != "" {
		errs = append(errs, fieldOnlyValidFor(path, ruleName, "reason", "block", a.Action))
	}

	if a.MaxDownloads != nil && *a.MaxDownloads < 1 {
		errs = append(errs, &ValidationError{Path: path, RuleName: ruleName, Message: fmt.Sprintf("field %q must be >= 1, got %d", "max_downloads", *a.MaxDownloads)})
	}

	return errs, warnings
}

// fieldOnlyValidFor builds the standard "field is only valid for
// action X" ValidationError, matching the §3.5 example message shape
// exactly: `field "ttl" is only valid for action "replace" (found
// action "block")`.
func fieldOnlyValidFor(path, ruleName, field, wantAction string, gotAction Action) *ValidationError {
	return &ValidationError{
		Path:     path,
		RuleName: ruleName,
		Message:  fmt.Sprintf("field %q is only valid for action %q (found action %q)", field, wantAction, gotAction),
	}
}

// validateWhen checks a rule's `when` block: glob patterns must
// compile, and size ranges must not be inverted.
func validateWhen(path, ruleName string, w *When) (errs, warnings []*ValidationError) {
	if w.Sender != nil {
		errs = append(errs, validateAddressMatch(path+".sender", ruleName, w.Sender)...)
	}
	if w.Recipient != nil {
		errs = append(errs, validateAddressMatch(path+".recipient", ruleName, w.Recipient)...)
	}
	if w.Attachment != nil {
		aerrs, awarnings := validateAttachmentMatch(path+".attachment", ruleName, w.Attachment)
		errs = append(errs, aerrs...)
		warnings = append(warnings, awarnings...)
	}

	return errs, warnings
}

// validateAddressMatch checks that every glob in Pattern compiles.
func validateAddressMatch(path, ruleName string, a *AddressMatch) []*ValidationError {
	var errs []*ValidationError
	for _, pat := range a.Pattern {
		if _, err := compileGlob(pat); err != nil {
			errs = append(errs, &ValidationError{Path: path + ".pattern", RuleName: ruleName, Message: fmt.Sprintf("invalid glob pattern %q: %v", pat, err)})
		}
	}
	return errs
}

// validateAttachmentMatch checks glob patterns and size range
// ordering. Per §3.5, a malformed size string is already rejected at
// parse time (Bound.UnmarshalYAML); an empty size range (min > max,
// e.g. {min: "10MB", max: "1MB"}) is well-formed but can never match
// anything, which §3.5 classifies as a warning, not an error.
func validateAttachmentMatch(path, ruleName string, a *AttachmentMatch) (errs, warnings []*ValidationError) {
	for _, pat := range a.Filename {
		if _, err := compileGlob(pat); err != nil {
			errs = append(errs, &ValidationError{Path: path + ".filename", RuleName: ruleName, Message: fmt.Sprintf("invalid glob pattern %q: %v", pat, err)})
		}
	}
	for _, pat := range a.MimeType {
		if _, err := compileGlob(pat); err != nil {
			errs = append(errs, &ValidationError{Path: path + ".mime_type", RuleName: ruleName, Message: fmt.Sprintf("invalid glob pattern %q: %v", pat, err)})
		}
	}
	for _, pat := range a.ClaimedMimeType {
		if _, err := compileGlob(pat); err != nil {
			errs = append(errs, &ValidationError{Path: path + ".claimed_mime_type", RuleName: ruleName, Message: fmt.Sprintf("invalid glob pattern %q: %v", pat, err)})
		}
	}
	for _, d := range a.Disposition {
		if !strings.EqualFold(d, "inline") && !strings.EqualFold(d, "attachment") {
			errs = append(errs, &ValidationError{Path: path + ".disposition", RuleName: ruleName, Message: fmt.Sprintf("invalid value %q (want one of: inline, attachment)", d)})
		}
	}

	if a.Size != nil && a.Size.Min != nil && a.Size.Max != nil {
		if a.Size.Min.Bytes() > a.Size.Max.Bytes() {
			warnings = append(warnings, &ValidationError{Path: path + ".size", RuleName: ruleName, Message: fmt.Sprintf("size range is empty and can never match: min (%d bytes) is greater than max (%d bytes)", a.Size.Min.Bytes(), a.Size.Max.Bytes())})
		}
	}

	return errs, warnings
}

// unreachableRuleWarnings implements §3.3: warn when a catch-all rule
// (no `when`, or a `disabled: false` rule whose When is nil) is
// followed by further enabled rules, which can never be reached.
func unreachableRuleWarnings(rules []Rule) []*ValidationError {
	var warnings []*ValidationError

	catchAllIndex := -1
	for i, r := range rules {
		if r.Disabled {
			continue
		}
		if catchAllIndex >= 0 {
			warnings = append(warnings, &ValidationError{
				Path:     fmt.Sprintf("rules[%d]", i),
				RuleName: r.Name,
				Message:  fmt.Sprintf("rule is unreachable — preceding rule %q has no `when` and always matches", rules[catchAllIndex].Name),
			})
			continue
		}
		if r.When == nil {
			catchAllIndex = i
		}
	}

	return warnings
}
