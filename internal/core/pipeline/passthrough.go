package pipeline

import "context"

// PassthroughProcessor is a Processor that accepts every message
// unmodified. It exists as the current placeholder Core pipeline
// implementation until the real policy engine (MIME parsing, policy
// evaluation, attachment storage/rewrite) lands.
//
// TODO(US-3.x/US-4.x): replace with a Processor that parses the
// message (internal/core/message), evaluates policies
// (internal/core/policy), and produces VerdictRewrite/VerdictReject
// verdicts based on the result.
type PassthroughProcessor struct{}

var _ Processor = PassthroughProcessor{}

// Process always returns a VerdictAccept verdict.
func (PassthroughProcessor) Process(_ context.Context, _ *Envelope) (*Verdict, error) {
	return &Verdict{Action: VerdictAccept}, nil
}
