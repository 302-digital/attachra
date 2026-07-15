package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/store"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
)

// newLinkTestEngine opens a fresh sqlite store under t.TempDir() and
// wraps it in a link.Engine, for the `attachra link` subcommand tests
// below (ATR-258).
func newLinkTestEngine(t *testing.T) (*sqlite.Store, *link.Engine) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "link-cli-test.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	e, err := link.NewEngine(st, link.Defaults{
		TTL:          time.Hour,
		MaxDownloads: 0,
		TokenBytes:   link.MinTokenBytes,
	}, st)
	if err != nil {
		t.Fatalf("link.NewEngine() error = %v, want nil", err)
	}
	return st, e
}

// seedLinkCLITestMessage creates one Message with one Attachment and
// one Link for it, via the engine's CreateLinks, returning the created
// link's store-assigned ID.
func seedLinkCLITestMessage(t *testing.T, e *link.Engine, messageID, sender string) string {
	t.Helper()
	ctx := context.Background()

	created, err := e.CreateLinks(ctx, link.CreateLinksParams{
		Message:     link.MessageInput{ID: messageID, QueueID: "queue-" + messageID, Sender: sender},
		Attachments: []link.AttachmentInput{{ID: messageID + "-att", PartRef: "1", Filename: "f", DeclaredType: "x", DetectedType: "x", Size: 1, StorageKey: "k"}},
		Recipients:  []string{"r@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateLinks() error = %v, want nil", err)
	}

	var tok string
	for _, c := range created {
		if c.AttachmentID != "" {
			tok = c.Token
		}
	}
	l, err := e.Resolve(ctx, tok)
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	return l.ID
}

func TestRunLinkCommand_MissingSubcommand(t *testing.T) {
	_, e := newLinkTestEngine(t)
	var stdout, stderr bytes.Buffer

	code := runLinkCommand(nil, nil, e, &stdout, &stderr)
	if code != linkError {
		t.Errorf("runLinkCommand() code = %d, want %d for missing subcommand", code, linkError)
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want usage diagnostic")
	}
}

func TestRunLinkCommand_UnknownSubcommand(t *testing.T) {
	_, e := newLinkTestEngine(t)
	var stdout, stderr bytes.Buffer

	code := runLinkCommand([]string{"bogus"}, nil, e, &stdout, &stderr)
	if code != linkError {
		t.Errorf("runLinkCommand() code = %d, want %d for unknown subcommand", code, linkError)
	}
}

func TestRunLinkHold_RequiresActor(t *testing.T) {
	st, e := newLinkTestEngine(t)
	linkID := seedLinkCLITestMessage(t, e, "msg-hold-noactor", "s@example.com")
	var stdout, stderr bytes.Buffer

	code := runLinkCommand([]string{"hold", linkID}, st, e, &stdout, &stderr)
	if code != linkError {
		t.Errorf("runLinkCommand(hold, no --actor) code = %d, want %d", code, linkError)
	}
	if !strings.Contains(stderr.String(), "--actor") {
		t.Errorf("stderr = %q, want a mention of --actor", stderr.String())
	}
}

func TestRunLinkHoldAndUnhold_HappyPath(t *testing.T) {
	st, e := newLinkTestEngine(t)
	linkID := seedLinkCLITestMessage(t, e, "msg-hold-happy", "s@example.com")

	var stdout, stderr bytes.Buffer
	code := runLinkCommand([]string{"hold", "--actor", "officer@example.com", linkID}, st, e, &stdout, &stderr)
	if code != linkOK {
		t.Fatalf("runLinkCommand(hold) code = %d, want %d; stderr=%s", code, linkOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), linkID) {
		t.Errorf("stdout = %q, want it to mention the link id", stdout.String())
	}

	got, err := st.GetLinkByID(context.Background(), linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if !got.Hold {
		t.Error("link Hold = false after `link hold`, want true")
	}

	stdout.Reset()
	stderr.Reset()
	code = runLinkCommand([]string{"unhold", "--actor", "officer@example.com", linkID}, st, e, &stdout, &stderr)
	if code != linkOK {
		t.Fatalf("runLinkCommand(unhold) code = %d, want %d; stderr=%s", code, linkOK, stderr.String())
	}

	got, err = st.GetLinkByID(context.Background(), linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Hold {
		t.Error("link Hold = true after `link unhold`, want false")
	}
}

func TestRunLinkHold_UnknownLink(t *testing.T) {
	st, e := newLinkTestEngine(t)
	var stdout, stderr bytes.Buffer

	code := runLinkCommand([]string{"hold", "--actor", "officer@example.com", "does-not-exist"}, st, e, &stdout, &stderr)
	if code != linkError {
		t.Errorf("runLinkCommand(hold, unknown link) code = %d, want %d", code, linkError)
	}
}

func TestRunLinkRevoke_RequiresActor(t *testing.T) {
	st, e := newLinkTestEngine(t)
	linkID := seedLinkCLITestMessage(t, e, "msg-revoke-noactor", "s@example.com")
	var stdout, stderr bytes.Buffer

	code := runLinkCommand([]string{"revoke", linkID}, st, e, &stdout, &stderr)
	if code != linkError {
		t.Errorf("runLinkCommand(revoke, no --actor) code = %d, want %d", code, linkError)
	}
}

func TestRunLinkRevoke_ModeExclusivity(t *testing.T) {
	st, e := newLinkTestEngine(t)
	linkID := seedLinkCLITestMessage(t, e, "msg-revoke-modes", "s@example.com")

	cases := [][]string{
		{"revoke", "--actor", "a"}, // no mode selected
		{"revoke", "--actor", "a", linkID, "--message-id", "msg-revoke-modes"},        // two modes
		{"revoke", "--actor", "a", linkID, "extra-positional-arg"},                    // extra positional
		{"revoke", "--actor", "a", "--message-id", "m1", "--sender", "s@example.com"}, // two flag modes
	}

	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := runLinkCommand(args, st, e, &stdout, &stderr)
		if code != linkError {
			t.Errorf("runLinkCommand(%v) code = %d, want %d", args, code, linkError)
		}
	}
}

func TestRunLinkRevoke_ByLinkID(t *testing.T) {
	st, e := newLinkTestEngine(t)
	linkID := seedLinkCLITestMessage(t, e, "msg-revoke-bylink", "s@example.com")
	var stdout, stderr bytes.Buffer

	code := runLinkCommand([]string{"revoke", "--actor", "officer@example.com", linkID}, st, e, &stdout, &stderr)
	if code != linkOK {
		t.Fatalf("runLinkCommand(revoke by link) code = %d, want %d; stderr=%s", code, linkOK, stderr.String())
	}

	got, err := st.GetLinkByID(context.Background(), linkID)
	if err != nil {
		t.Fatalf("GetLinkByID() error = %v, want nil", err)
	}
	if got.Status != store.LinkStatusRevoked {
		t.Errorf("link Status = %q after revoke, want %q", got.Status, store.LinkStatusRevoked)
	}
}

func TestRunLinkRevoke_ByMessageID(t *testing.T) {
	st, e := newLinkTestEngine(t)
	_ = seedLinkCLITestMessage(t, e, "msg-revoke-bymsg", "s@example.com")
	var stdout, stderr bytes.Buffer

	code := runLinkCommand([]string{"revoke", "--actor", "officer@example.com", "--message-id", "msg-revoke-bymsg"}, st, e, &stdout, &stderr)
	if code != linkOK {
		t.Fatalf("runLinkCommand(revoke by message) code = %d, want %d; stderr=%s", code, linkOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 link(s) revoked") {
		t.Errorf("stdout = %q, want it to report 1 link revoked", stdout.String())
	}

	links, err := st.ListLinksByMessage(context.Background(), "msg-revoke-bymsg")
	if err != nil {
		t.Fatalf("ListLinksByMessage() error = %v, want nil", err)
	}
	for _, l := range links {
		if l.Status != store.LinkStatusRevoked {
			t.Errorf("link %q Status = %q, want %q", l.ID, l.Status, store.LinkStatusRevoked)
		}
	}
}

func TestRunLinkRevoke_BySender(t *testing.T) {
	st, e := newLinkTestEngine(t)
	sender := "bulk-sender@example.com"
	_ = seedLinkCLITestMessage(t, e, "msg-revoke-bysender-1", sender)
	_ = seedLinkCLITestMessage(t, e, "msg-revoke-bysender-2", sender)
	_ = seedLinkCLITestMessage(t, e, "msg-revoke-bysender-other", "someone-else@example.com")

	var stdout, stderr bytes.Buffer
	code := runLinkCommand([]string{"revoke", "--actor", "officer@example.com", "--sender", sender}, st, e, &stdout, &stderr)
	if code != linkOK {
		t.Fatalf("runLinkCommand(revoke by sender) code = %d, want %d; stderr=%s", code, linkOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2 link(s) revoked across 2 message(s)") {
		t.Errorf("stdout = %q, want it to report 2 links revoked across 2 messages", stdout.String())
	}

	links, err := st.ListLinksByMessage(context.Background(), "msg-revoke-bysender-other")
	if err != nil {
		t.Fatalf("ListLinksByMessage() error = %v, want nil", err)
	}
	for _, l := range links {
		if l.Status != store.LinkStatusActive {
			t.Errorf("other-sender link %q Status = %q after revoke-by-sender, want still %q", l.ID, l.Status, store.LinkStatusActive)
		}
	}
}

func TestRunLinkRevoke_BySenderNoMessages(t *testing.T) {
	st, e := newLinkTestEngine(t)
	var stdout, stderr bytes.Buffer

	code := runLinkCommand([]string{"revoke", "--actor", "officer@example.com", "--sender", "nobody@example.com"}, st, e, &stdout, &stderr)
	if code != linkOK {
		t.Fatalf("runLinkCommand(revoke by unknown sender) code = %d, want %d; stderr=%s", code, linkOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "nothing to revoke") {
		t.Errorf("stdout = %q, want a nothing-to-revoke message", stdout.String())
	}
}

// TestRunLinkRevoke_HeldLinkRefusedWithClearMessage verifies the US-6.3/
// ATR-258 acceptance criterion that a hold blocks revoke with an
// understandable operator-facing message, for all three revoke modes.
func TestRunLinkRevoke_HeldLinkRefusedWithClearMessage(t *testing.T) {
	st, e := newLinkTestEngine(t)
	linkID := seedLinkCLITestMessage(t, e, "msg-revoke-held", "held-sender@example.com")

	holdCode := runLinkCommand([]string{"hold", "--actor", "officer@example.com", linkID}, st, e, new(bytes.Buffer), new(bytes.Buffer))
	if holdCode != linkOK {
		t.Fatalf("runLinkCommand(hold) code = %d, want %d", holdCode, linkOK)
	}

	t.Run("by link id", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runLinkCommand([]string{"revoke", "--actor", "officer@example.com", linkID}, st, e, &stdout, &stderr)
		if code != linkError {
			t.Errorf("code = %d, want %d", code, linkError)
		}
		if !strings.Contains(stderr.String(), "legal hold") {
			t.Errorf("stderr = %q, want a legal hold explanation", stderr.String())
		}

		got, err := st.GetLinkByID(context.Background(), linkID)
		if err != nil {
			t.Fatalf("GetLinkByID() error = %v, want nil", err)
		}
		if got.Status != store.LinkStatusActive {
			t.Errorf("held link Status = %q after refused revoke, want still %q", got.Status, store.LinkStatusActive)
		}
	})

	t.Run("by message id", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runLinkCommand([]string{"revoke", "--actor", "officer@example.com", "--message-id", "msg-revoke-held"}, st, e, &stdout, &stderr)
		if code != linkError {
			t.Errorf("code = %d, want %d", code, linkError)
		}
		if !strings.Contains(stderr.String(), "legal hold") {
			t.Errorf("stderr = %q, want a legal hold explanation", stderr.String())
		}
	})

	t.Run("by sender", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runLinkCommand([]string{"revoke", "--actor", "officer@example.com", "--sender", "held-sender@example.com"}, st, e, &stdout, &stderr)
		if code != linkError {
			t.Errorf("code = %d, want %d", code, linkError)
		}
		if !strings.Contains(stderr.String(), "legal hold") {
			t.Errorf("stderr = %q, want a legal hold explanation", stderr.String())
		}
	})
}
