package pipeline

import (
	"context"
	"strings"
	"testing"
)

func TestPassthroughProcessor_AlwaysAccepts(t *testing.T) {
	p := PassthroughProcessor{}

	env := &Envelope{
		Sender:     "sender@example.com",
		Recipients: []string{"rcpt@example.com"},
		QueueID:    "ABC123",
		Body:       strings.NewReader("hello"),
	}

	verdict, err := p.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process() error = %v, want nil", err)
	}
	if verdict == nil {
		t.Fatal("Process() verdict = nil, want non-nil")
	}
	if verdict.Action != VerdictAccept {
		t.Errorf("verdict.Action = %v, want VerdictAccept", verdict.Action)
	}
}

func TestVerdictAction_String(t *testing.T) {
	tests := []struct {
		action VerdictAction
		want   string
	}{
		{VerdictAccept, "accept"},
		{VerdictRewrite, "rewrite"},
		{VerdictReject, "reject"},
		{VerdictTempFail, "tempfail"},
		{VerdictAction(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.action.String(); got != tt.want {
			t.Errorf("VerdictAction(%d).String() = %q, want %q", tt.action, got, tt.want)
		}
	}
}
