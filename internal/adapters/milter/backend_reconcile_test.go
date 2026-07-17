package milter_test

import (
	"net/textproto"
	"sort"
	"strings"
	"testing"

	dmilter "github.com/d--j/go-milter"

	"github.com/302-digital/attachra/internal/core/pipeline"
)

// TestMilter_Rewrite_HeaderReconcile encodes the milter PROTOCOL
// semantics of replaceMessage's header reconciliation (ATR-290) against a
// hand-crafted NewBody, independent of the rewrite engine:
//   - a changed value becomes ChangeHeader in place;
//   - headers only in the original become deletes (ChangeHeader with an
//     empty value), applied highest-index-first so removing one
//     occurrence does not shift the 1-based index of another still
//     pending for the same name (the ModifyAction.HeaderIndex delete
//     contract);
//   - headers only in the rewritten block become AddHeader appends;
//   - an unchanged header is not touched.
//
// The three identical "X-Test" headers (three on the MTA side, one in
// NewBody) exercise the descending-index deletion order without depending
// on the relative order of same-name values as the test client delivers
// them (positional value comparison is a no-op when the values are equal,
// so only deletes are produced). In production this positional logic only
// ever fires for single-occurrence content headers (Content-Type on the
// promotion path); repeated headers like Received are preserved verbatim
// and in order by rewrite, so they compare equal and are left untouched.
func TestMilter_Rewrite_HeaderReconcile(t *testing.T) {
	origHeaders := []hdrKV{
		{"Subject", "keep me"},
		{"Content-Type", "text/plain"},
		{"X-Test", "dup"},
		{"X-Test", "dup"},
		{"X-Test", "dup"},
	}

	// NewBody: Subject unchanged, Content-Type changed, only one X-Test
	// kept, and a brand-new X-New added.
	newBody := "Subject: keep me\r\n" +
		"Content-Type: text/html\r\n" +
		"X-Test: dup\r\n" +
		"X-New: fresh\r\n" +
		"\r\n" +
		"replacement body\r\n"

	proc := &fakeProcessor{verdict: &pipeline.Verdict{
		Action:  pipeline.VerdictRewrite,
		NewBody: strings.NewReader(newBody),
	}}
	addr := startTestServer(t, proc, nil)

	modifyActs, act := runSessionWithHeaders(t, addr, "sender@example.com", "rcpt@example.com", origHeaders, []byte("original body\r\n"))
	requireAccept(t, act)

	var (
		ctChange     *dmilter.ModifyAction
		xTestDeletes []uint32
		xTestChanges int
		gotAddXNew   bool
		gotAddSubj   bool
		gotReplace   bool
	)
	for i := range modifyActs {
		ma := modifyActs[i]
		name := textproto.CanonicalMIMEHeaderKey(ma.HeaderName)
		switch ma.Type {
		case dmilter.ActionChangeHeader:
			switch name {
			case "Content-Type":
				ctChange = &modifyActs[i]
			case "X-Test":
				if ma.HeaderValue == "" {
					xTestDeletes = append(xTestDeletes, ma.HeaderIndex)
				} else {
					xTestChanges++
				}
			}
		case dmilter.ActionAddHeader:
			switch name {
			case "X-New":
				gotAddXNew = true
			case "Subject":
				gotAddSubj = true
			}
		case dmilter.ActionReplaceBody:
			gotReplace = true
		}
	}

	if ctChange == nil {
		t.Fatal("expected a ChangeHeader for Content-Type")
	}
	if ctChange.HeaderIndex != 1 || ctChange.HeaderValue != "text/html" {
		t.Errorf("Content-Type change = index %d value %q, want index 1 value text/html", ctChange.HeaderIndex, ctChange.HeaderValue)
	}
	// All three X-Test values are equal, so occurrence 1 is left untouched
	// and occurrences 2 and 3 are deleted, highest index first.
	if xTestChanges != 0 {
		t.Errorf("equal-valued X-Test occurrences must not be changed (%d spurious changes)", xTestChanges)
	}
	if len(xTestDeletes) != 2 {
		t.Fatalf("expected 2 X-Test deletes, got %d (%v)", len(xTestDeletes), xTestDeletes)
	}
	if !sort.SliceIsSorted(xTestDeletes, func(i, j int) bool { return xTestDeletes[i] > xTestDeletes[j] }) {
		t.Errorf("X-Test deletes not highest-index-first: %v", xTestDeletes)
	}
	if xTestDeletes[0] != 3 || xTestDeletes[1] != 2 {
		t.Errorf("X-Test delete indices = %v, want [3 2]", xTestDeletes)
	}
	if !gotAddXNew {
		t.Error("expected an AddHeader for the new X-New header")
	}
	if gotAddSubj {
		t.Error("Subject was unchanged and already on the MTA side; it must not be re-added")
	}
	if !gotReplace {
		t.Error("expected a ReplaceBody modify action")
	}

	// Net effect: applying the actions to the original headers must leave
	// exactly one X-Test (value "dup") and a text/html Content-Type.
	delivered := applyModifyActions(t, origHeaders, modifyActs, []byte("replacement body\r\n"))
	if n := strings.Count(string(delivered), "X-Test: dup\r\n"); n != 1 {
		t.Errorf("delivered message has %d X-Test headers, want 1:\n%s", n, delivered)
	}
	if !strings.Contains(string(delivered), "Content-Type: text/html\r\n") {
		t.Errorf("delivered Content-Type not changed to text/html:\n%s", delivered)
	}
}
