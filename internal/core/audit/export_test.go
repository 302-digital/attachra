package audit_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/audit"
)

// fakeReader is an in-memory audit.Reader used to test ExportJSONL
// without depending on the sqlite implementation.
type fakeReader struct {
	events []audit.Recorded
}

func (f *fakeReader) StreamEvents(_ context.Context, filter audit.Filter, fn func(audit.Recorded) error) error {
	for _, e := range f.events {
		if filter.Type != "" && e.Type != filter.Type {
			continue
		}
		if !filter.From.IsZero() && e.Timestamp.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && !e.Timestamp.Before(filter.To) {
			continue
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func TestExportJSONLWritesOneLinePerEvent(t *testing.T) {
	base := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	reader := &fakeReader{events: []audit.Recorded{
		{
			Event: audit.Event{
				Timestamp: base,
				Type:      audit.TypeDownload,
				Actor:     "milter",
				MessageID: "msg-1",
				Recipient: "user@example.com",
				Details:   map[string]any{"filename": "report.pdf"},
			},
			ID:       "ev-1",
			Seq:      1,
			PrevHash: "",
		},
		{
			Event: audit.Event{
				Timestamp: base.Add(time.Second),
				Type:      audit.TypeRevoke,
				Actor:     "api:alice",
				MessageID: "msg-1",
			},
			ID:       "ev-2",
			Seq:      2,
			PrevHash: "deadbeef",
		},
	}}

	var buf bytes.Buffer
	if err := audit.ExportJSONL(context.Background(), reader, &buf, audit.Filter{}); err != nil {
		t.Fatalf("ExportJSONL() error = %v, want nil", err)
	}

	scanner := bufio.NewScanner(&buf)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error = %v, want nil", err)
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(lines), lines)
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal line 0 error = %v, want nil", err)
	}
	if first["id"] != "ev-1" {
		t.Errorf("line 0 id = %v, want ev-1", first["id"])
	}
	if first["type"] != string(audit.TypeDownload) {
		t.Errorf("line 0 type = %v, want %q", first["type"], audit.TypeDownload)
	}
	details, ok := first["details"].(map[string]any)
	if !ok {
		t.Fatalf("line 0 details = %#v, want a JSON object", first["details"])
	}
	if details["filename"] != "report.pdf" {
		t.Errorf("line 0 details.filename = %v, want report.pdf", details["filename"])
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("unmarshal line 1 error = %v, want nil", err)
	}
	if second["prev_hash"] != "deadbeef" {
		t.Errorf("line 1 prev_hash = %v, want deadbeef", second["prev_hash"])
	}
}

func TestExportJSONLAppliesTypeFilter(t *testing.T) {
	base := time.Now().UTC()
	reader := &fakeReader{events: []audit.Recorded{
		{Event: audit.Event{Timestamp: base, Type: audit.TypeDownload}, ID: "ev-1", Seq: 1},
		{Event: audit.Event{Timestamp: base, Type: audit.TypeRevoke}, ID: "ev-2", Seq: 2},
	}}

	var buf bytes.Buffer
	if err := audit.ExportJSONL(context.Background(), reader, &buf, audit.Filter{Type: audit.TypeRevoke}); err != nil {
		t.Fatalf("ExportJSONL() error = %v, want nil", err)
	}

	scanner := bufio.NewScanner(&buf)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %v", len(lines), lines)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal error = %v, want nil", err)
	}
	if got["id"] != "ev-2" {
		t.Errorf("id = %v, want ev-2", got["id"])
	}
}

func TestExportJSONLPropagatesReaderError(t *testing.T) {
	wantErr := errors.New("boom")
	reader := &erroringReader{err: wantErr}

	var buf bytes.Buffer
	err := audit.ExportJSONL(context.Background(), reader, &buf, audit.Filter{})
	if !errors.Is(err, wantErr) {
		t.Errorf("ExportJSONL() error = %v, want wrapping %v", err, wantErr)
	}
}

type erroringReader struct{ err error }

func (e *erroringReader) StreamEvents(_ context.Context, _ audit.Filter, _ func(audit.Recorded) error) error {
	return e.err
}

func TestExportJSONLNoEventsWritesNothing(t *testing.T) {
	reader := &fakeReader{}
	var buf bytes.Buffer
	if err := audit.ExportJSONL(context.Background(), reader, &buf, audit.Filter{}); err != nil {
		t.Fatalf("ExportJSONL() error = %v, want nil", err)
	}
	if buf.Len() != 0 {
		t.Errorf("buf = %q, want empty", buf.String())
	}
}
