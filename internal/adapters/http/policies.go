package http

import (
	"errors"
	"io"
	"net/http"

	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/store"
)

// policyDTO is the JSON representation of the currently active policy
// (api/openapi.yaml, schema Policy; GET /policies/current). Per the
// operation's own description, this is a read-only view reporting
// fully resolved values (durations in seconds, sizes in bytes) rather
// than the YAML file's convenience units, and is deliberately not
// round-trip compatible with the YAML document POST /policies/validate
// accepts — there is no export-then-edit-then-validate workflow through
// this API.
type policyDTO struct {
	Version     int               `json:"version"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Rules       []ruleDTO         `json:"rules"`
	Default     actionSpecDTO     `json:"default"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Defaults    *actionParamsDTO  `json:"defaults,omitempty"`
}

// ruleDTO mirrors schema Rule.
type ruleDTO struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	When        *whenDTO      `json:"when,omitempty"`
	Then        actionSpecDTO `json:"then"`
	Disabled    bool          `json:"disabled"`
}

// whenDTO mirrors schema When.
type whenDTO struct {
	Sender     *addressMatchDTO    `json:"sender,omitempty"`
	Recipient  *addressMatchDTO    `json:"recipient,omitempty"`
	Attachment *attachmentMatchDTO `json:"attachment,omitempty"`
}

// addressMatchDTO mirrors schema AddressMatch.
type addressMatchDTO struct {
	Address []string `json:"address,omitempty"`
	Domain  []string `json:"domain,omitempty"`
	Pattern []string `json:"pattern,omitempty"`
}

// sizeRangeDTO mirrors schema SizeRange, resolving policy.Bound to a
// plain byte count (schema SizeBytes).
type sizeRangeDTO struct {
	Min *int64 `json:"min"`
	Max *int64 `json:"max"`
}

// attachmentMatchDTO mirrors schema AttachmentMatch.
type attachmentMatchDTO struct {
	Size            *sizeRangeDTO `json:"size,omitempty"`
	MimeType        []string      `json:"mime_type,omitempty"`
	ClaimedMimeType []string      `json:"claimed_mime_type,omitempty"`
	Extension       []string      `json:"extension,omitempty"`
	Filename        []string      `json:"filename,omitempty"`
}

// actionParamsDTO mirrors schema ActionParams (Policy.defaults only;
// Rule.then/Policy.default use the richer actionSpecDTO instead).
type actionParamsDTO struct {
	TTLSeconds       *int64 `json:"ttl_seconds"`
	MaxDownloads     *int   `json:"max_downloads"`
	RetentionSeconds *int64 `json:"retention_seconds"`
}

// actionSpecDTO mirrors schema ActionSpec (Rule.then and Policy.default).
type actionSpecDTO struct {
	Action           string `json:"action"`
	TTLSeconds       *int64 `json:"ttl_seconds,omitempty"`
	MaxDownloads     *int   `json:"max_downloads,omitempty"`
	RetentionSeconds *int64 `json:"retention_seconds,omitempty"`
	Reason           string `json:"reason,omitempty"`
	DryRun           *bool  `json:"dry_run,omitempty"`
}

// reloadResponseDTO mirrors schema ReloadResponse.
type reloadResponseDTO struct {
	Policy   reloadPolicySummaryDTO `json:"policy"`
	Warnings []string               `json:"warnings"`
}

// reloadPolicySummaryDTO mirrors ReloadResponse's inline `policy` object.
type reloadPolicySummaryDTO struct {
	Name      string `json:"name"`
	Version   int    `json:"version"`
	RuleCount int    `json:"rule_count"`
}

// validateResponseDTO mirrors schema ValidateResponse. Errors and
// Warnings reuse apiErrorDetail (apierror.go) since its JSON shape is
// identical to the contract's ValidationIssue.
type validateResponseDTO struct {
	Valid    bool             `json:"valid"`
	Errors   []apiErrorDetail `json:"errors"`
	Warnings []apiErrorDetail `json:"warnings"`
}

// dryRunAttachmentRequestDTO mirrors schema DryRunAttachment.
type dryRunAttachmentRequestDTO struct {
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	DeclaredType string `json:"declared_type"`
	DetectedType string `json:"detected_type"`
}

// dryRunRequestDTO mirrors schema DryRunRequest.
type dryRunRequestDTO struct {
	Sender      string                       `json:"sender"`
	Recipients  []string                     `json:"recipients"`
	Attachments []dryRunAttachmentRequestDTO `json:"attachments"`
}

// dryRunAttachmentDecisionDTO mirrors schema DryRunAttachmentDecision.
type dryRunAttachmentDecisionDTO struct {
	Filename         string  `json:"filename"`
	Action           string  `json:"action"`
	RuleName         *string `json:"rule_name"`
	Reason           *string `json:"reason"`
	TTLSeconds       *int64  `json:"ttl_seconds"`
	MaxDownloads     *int    `json:"max_downloads"`
	RetentionSeconds *int64  `json:"retention_seconds"`
}

// dryRunResponseDTO mirrors schema DryRunResponse.
type dryRunResponseDTO struct {
	Action      string                        `json:"action"`
	Reason      *string                       `json:"reason"`
	Attachments []dryRunAttachmentDecisionDTO `json:"attachments"`
}

// handlePoliciesCurrent dispatches GET /api/v1/policies/current.
func (h *APIHandler) handlePoliciesCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w, "GET")
		return
	}
	h.getCurrentPolicy(w, r)
}

// handlePoliciesValidate dispatches POST /api/v1/policies/validate.
func (h *APIHandler) handlePoliciesValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, "POST")
		return
	}
	h.validatePolicy(w, r)
}

// handlePoliciesReload dispatches POST /api/v1/policies/reload.
func (h *APIHandler) handlePoliciesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, "POST")
		return
	}
	h.reloadPolicy(w, r)
}

// handlePoliciesDryRun dispatches POST /api/v1/policies/dry-run.
func (h *APIHandler) handlePoliciesDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, "POST")
		return
	}
	h.dryRunPolicy(w, r)
}

// noPolicyConfigured answers every /policies operation that needs an
// active policy.Store (current/reload/dry-run — validate does not, it
// only parses the submitted document) when this server was started
// without one configured (community-edition passthrough mode, empty
// config.Policy.Path — cmd/attachra/main.go). The contract's response
// set for these operations has no dedicated status for "feature not
// configured", so this resolves to 500 internal: a deliberate, narrow
// deviation from the literal spec, called out in ATR-199's review since
// it is a server configuration gap, not a client error, and no 4xx
// code in the schema fits it.
func (h *APIHandler) noPolicyConfigured(w http.ResponseWriter, r *http.Request, action string) {
	h.logger.Error("api: "+action+" requested but no policy engine is configured", "path", r.URL.Path)
	writeAPIError(w, h.logger, http.StatusInternalServerError, errCodeInternal, "an internal error occurred")
}

// getCurrentPolicy implements GET /api/v1/policies/current (admin,
// viewer): mirrors policy.Store.Current().
func (h *APIHandler) getCurrentPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}
	if h.policies == nil {
		h.noPolicyConfigured(w, r, "current policy")
		return
	}
	writeAPIJSON(w, h.logger, http.StatusOK, toPolicyDTO(h.policies.Current()))
}

// validatePolicy implements POST /api/v1/policies/validate (admin,
// viewer — SR-130-3 exempts it from the admin-only mutation set since
// it never touches the active policy, only parses/checks the submitted
// document, per api/openapi.yaml's own tag description). It mirrors
// policy.ParseIssues, returning every error and warning found rather
// than just the first (§3.5), and always answers 200 — an invalid
// document is a normal validation *result*, not an error response, so
// even `valid: false` is reported this way.
func (h *APIHandler) validatePolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeAPIError(w, h.logger, http.StatusRequestEntityTooLarge, errCodePayloadTooLarge, "request body exceeds the configured size limit")
			return
		}
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "invalid request body")
		return
	}

	_, errs, warnings := policy.ParseIssues(body)
	writeAPIJSON(w, h.logger, http.StatusOK, validateResponseDTO{
		Valid:    len(errs) == 0,
		Errors:   toIssueDetails(errs),
		Warnings: toIssueDetails(warnings),
	})
}

// reloadPolicy implements POST /api/v1/policies/reload (admin only,
// SR-130-3): mirrors policy.Store.Reload(). An invalid policy file is
// never applied (SR-119-1/§3.5) — Reload itself already guarantees
// this by leaving Current() untouched on failure; this handler only
// translates the outcome to HTTP, reporting the previous policy's
// details are unchanged via the 409 response.
func (h *APIHandler) reloadPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin); !ok {
		return
	}
	if h.policies == nil {
		h.noPolicyConfigured(w, r, "policy reload")
		return
	}

	p, warnings, err := h.policies.Reload()
	if err != nil {
		h.logger.Warn("api: policy reload failed, previous policy remains active", "path", h.policies.Path(), "error", err.Error())

		// message is always this fixed, generic string — never
		// docErr.Error()/err.Error(). DocumentError.Name is the
		// configured policy file's path (Store.Reload calls
		// Parse(data, s.path)), so formatting it into the response
		// would leak the server's absolute filesystem path to the
		// client (SR-130-1, this package's own apiError doc comment:
		// "no ... file path"). The structured, per-field details below
		// are safe: their Path values are policy-internal locations
		// like "rules[0].then", never a filesystem path.
		message := "the configured policy file is invalid; the previously active policy remains in effect"
		var details []apiErrorDetail
		var docErr *policy.DocumentError
		if errors.As(err, &docErr) {
			details = toIssueDetails(docErr.Errors)
		}
		writeAPIErrorWithDetails(w, h.logger, http.StatusConflict, errCodeInvalidPolicy, message, details)
		return
	}

	h.logger.Info("api: policy reloaded", "name", p.Name, "rules", len(p.Rules), "warnings", len(warnings))
	writeAPIJSON(w, h.logger, http.StatusOK, reloadResponseDTO{
		Policy: reloadPolicySummaryDTO{
			Name:      p.Name,
			Version:   p.Version,
			RuleCount: len(p.Rules),
		},
		Warnings: nonNilStrings(warnings),
	})
}

// dryRunPolicy implements POST /api/v1/policies/dry-run (admin,
// viewer): mirrors policy.Evaluate against the currently active
// policy, without creating any message, attachment, link or storage
// object, and without recording an audit event (a pure, side-effect-free
// simulation).
func (h *APIHandler) dryRunPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, store.RoleAdmin, store.RoleViewer); !ok {
		return
	}
	if h.policies == nil {
		h.noPolicyConfigured(w, r, "policy dry-run")
		return
	}

	var req dryRunRequestDTO
	if !decodeJSONBody(w, r, h.logger, &req) {
		return
	}

	if req.Sender == "" {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "sender is required")
		return
	}
	if len(req.Recipients) == 0 {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "recipients must not be empty")
		return
	}
	if len(req.Attachments) == 0 {
		writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "attachments must not be empty")
		return
	}

	atts := make([]message.Attachment, len(req.Attachments))
	for i, a := range req.Attachments {
		if a.Filename == "" {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "attachments[].filename is required")
			return
		}
		if a.DetectedType == "" {
			writeAPIError(w, h.logger, http.StatusBadRequest, errCodeBadRequest, "attachments[].detected_type is required")
			return
		}
		atts[i] = message.Attachment{
			Filename:     a.Filename,
			DeclaredType: a.DeclaredType,
			DetectedType: a.DetectedType,
			Size:         a.Size,
		}
	}

	env := policy.EnvelopeMeta{Sender: req.Sender, Recipients: req.Recipients}
	decision := policy.Evaluate(h.policies.Current(), env, atts)

	resp := dryRunResponseDTO{
		Action:      string(decision.Action),
		Attachments: make([]dryRunAttachmentDecisionDTO, len(decision.Attachments)),
	}
	if decision.Reason != "" {
		reason := decision.Reason
		resp.Reason = &reason
	}
	for i, d := range decision.Attachments {
		resp.Attachments[i] = toDryRunAttachmentDecisionDTO(atts[i].Filename, d)
	}

	writeAPIJSON(w, h.logger, http.StatusOK, resp)
}

// toDryRunAttachmentDecisionDTO maps one policy.AttachmentDecision to
// its wire shape. ttl_seconds/max_downloads/retention_seconds are only
// meaningful (and only rendered) when the decision's action is replace
// (api/openapi.yaml DryRunAttachmentDecision); reason only when the
// action is block.
func toDryRunAttachmentDecisionDTO(filename string, d policy.AttachmentDecision) dryRunAttachmentDecisionDTO {
	item := dryRunAttachmentDecisionDTO{
		Filename: filename,
		Action:   string(d.Action),
	}
	if d.RuleName != "" {
		ruleName := d.RuleName
		item.RuleName = &ruleName
	}
	if d.Action == policy.ActionBlock && d.Reason != "" {
		reason := d.Reason
		item.Reason = &reason
	}
	if d.Action == policy.ActionReplace {
		item.TTLSeconds = durationSecondsPtr(d.Params.TTL)
		item.MaxDownloads = d.Params.MaxDownloads
		item.RetentionSeconds = durationSecondsPtr(d.Params.Retention)
	}
	return item
}

// toPolicyDTO maps a *policy.Policy to its wire shape (schema Policy).
func toPolicyDTO(p *policy.Policy) policyDTO {
	dto := policyDTO{
		Version:     p.Version,
		Name:        p.Name,
		Description: p.Description,
		Rules:       make([]ruleDTO, 0, len(p.Rules)),
		Default:     toActionSpecDTO(p.Default),
		Metadata:    p.Metadata,
	}
	for _, r := range p.Rules {
		dto.Rules = append(dto.Rules, toRuleDTO(r))
	}
	if p.Defaults != nil {
		dto.Defaults = &actionParamsDTO{
			TTLSeconds:       durationSecondsPtr(p.Defaults.TTL),
			MaxDownloads:     p.Defaults.MaxDownloads,
			RetentionSeconds: durationSecondsPtr(p.Defaults.Retention),
		}
	}
	return dto
}

// toRuleDTO maps a policy.Rule to its wire shape (schema Rule).
func toRuleDTO(r policy.Rule) ruleDTO {
	dto := ruleDTO{
		Name:        r.Name,
		Description: r.Description,
		Then:        toActionSpecDTO(r.Then),
		Disabled:    r.Disabled,
	}
	if r.When != nil {
		w := toWhenDTO(*r.When)
		dto.When = &w
	}
	return dto
}

// toWhenDTO maps a policy.When to its wire shape (schema When).
func toWhenDTO(w policy.When) whenDTO {
	dto := whenDTO{}
	if w.Sender != nil {
		s := toAddressMatchDTO(*w.Sender)
		dto.Sender = &s
	}
	if w.Recipient != nil {
		r := toAddressMatchDTO(*w.Recipient)
		dto.Recipient = &r
	}
	if w.Attachment != nil {
		a := toAttachmentMatchDTO(*w.Attachment)
		dto.Attachment = &a
	}
	return dto
}

// toAddressMatchDTO maps a policy.AddressMatch to its wire shape.
func toAddressMatchDTO(m policy.AddressMatch) addressMatchDTO {
	return addressMatchDTO{Address: m.Address, Domain: m.Domain, Pattern: m.Pattern}
}

// toAttachmentMatchDTO maps a policy.AttachmentMatch to its wire shape.
func toAttachmentMatchDTO(m policy.AttachmentMatch) attachmentMatchDTO {
	dto := attachmentMatchDTO{
		MimeType:        m.MimeType,
		ClaimedMimeType: m.ClaimedMimeType,
		Extension:       m.Extension,
		Filename:        m.Filename,
	}
	if m.Size != nil {
		dto.Size = &sizeRangeDTO{Min: boundBytesPtr(m.Size.Min), Max: boundBytesPtr(m.Size.Max)}
	}
	return dto
}

// toActionSpecDTO maps a policy.ActionSpec (Rule.then/Policy.default)
// to its wire shape (schema ActionSpec).
func toActionSpecDTO(a policy.ActionSpec) actionSpecDTO {
	dto := actionSpecDTO{
		Action:           string(a.Action),
		TTLSeconds:       durationSecondsPtr(a.TTL),
		MaxDownloads:     a.MaxDownloads,
		RetentionSeconds: durationSecondsPtr(a.Retention),
		Reason:           a.Reason,
	}
	if a.DryRun != nil {
		dryRun := *a.DryRun
		dto.DryRun = &dryRun
	}
	return dto
}

// durationSecondsPtr resolves a *policy.Duration to a plain seconds
// count (schema Duration), or nil if d is nil.
func durationSecondsPtr(d *policy.Duration) *int64 {
	if d == nil {
		return nil
	}
	s := int64(d.Duration().Seconds())
	return &s
}

// boundBytesPtr resolves a *policy.Bound to a plain byte count (schema
// SizeBytes), or nil if b is nil.
func boundBytesPtr(b *policy.Bound) *int64 {
	if b == nil {
		return nil
	}
	n := b.Bytes()
	return &n
}

// toIssueDetails maps a slice of *policy.ValidationError to the
// contract's ValidationIssue wire shape (reusing apiErrorDetail, see
// its doc comment).
func toIssueDetails(errs []*policy.ValidationError) []apiErrorDetail {
	out := make([]apiErrorDetail, 0, len(errs))
	for _, e := range errs {
		out = append(out, apiErrorDetail{Path: e.Path, RuleName: e.RuleName, Message: e.Message})
	}
	return out
}

// nonNilStrings returns ss unchanged if non-nil, or an empty (but
// non-nil) slice otherwise, so ReloadResponse.warnings always renders
// as `[]` rather than `null` (matching this package's convention for
// required array fields, e.g. linkListDTO.Data).
func nonNilStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}
