package audit_test

import (
	"context"
	"testing"

	"github.com/302-digital/attachra/internal/core/audit"
)

func TestNopSinkRecordReturnsEventUnchanged(t *testing.T) {
	ev := audit.Event{Type: audit.TypeError, Actor: "test"}

	rec, err := audit.NopSink{}.Record(context.Background(), ev)
	if err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}
	if rec.Type != ev.Type || rec.Actor != ev.Actor {
		t.Errorf("Record() = %+v, want event content preserved", rec)
	}
}
