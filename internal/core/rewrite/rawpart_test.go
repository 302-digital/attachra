package rewrite

import (
	"io"
	"strings"
	"testing"
)

func TestRawMultipartReader_Basic(t *testing.T) {
	raw := "--B\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"hello\r\n" +
		"--B\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"world\r\n" +
		"--B--\r\n"

	rmr := newRawMultipartReader(strings.NewReader(raw), "B")

	var got []string
	for {
		part, err := rmr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		body, err := io.ReadAll(part.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		got = append(got, string(body))
	}

	want := []string{"hello", "world"}
	if len(got) != len(want) {
		t.Fatalf("got %d parts %q, want %d parts %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("part %d = %q, want %q", i, got[i], want[i])
		}
	}
}
