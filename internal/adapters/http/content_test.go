package http

import (
	"strings"
	"testing"
)

func TestResponseContentType(t *testing.T) {
	tests := []struct {
		detected string
		want     string
	}{
		{"application/pdf", octetStream}, // PDFs may carry embedded JS: always downgraded.
		{"text/html", octetStream},
		{"image/svg+xml", octetStream},
		{"application/javascript", octetStream},
		{"", octetStream},
		{"   ", octetStream},
		{"image/png", "image/png"},
		{"IMAGE/PNG", "image/png"},
		{"application/zip", "application/zip"},
	}

	for _, tt := range tests {
		t.Run(tt.detected, func(t *testing.T) {
			if got := responseContentType(tt.detected); got != tt.want {
				t.Errorf("responseContentType(%q) = %q, want %q", tt.detected, got, tt.want)
			}
		})
	}
}

func TestContentDispositionEscapesCRLF(t *testing.T) {
	got := contentDisposition("evil\r\nX-Injected: true.txt")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("contentDisposition() = %q, want no CR/LF", got)
	}
}

func TestContentDispositionAlwaysAttachment(t *testing.T) {
	got := contentDisposition("report.pdf")
	if !strings.HasPrefix(got, "attachment;") {
		t.Errorf("contentDisposition() = %q, want it to start with \"attachment;\"", got)
	}
	if !strings.Contains(got, `filename="report.pdf"`) {
		t.Errorf("contentDisposition() = %q, want an ASCII filename parameter", got)
	}
	if !strings.Contains(got, "filename*=UTF-8''report.pdf") {
		t.Errorf("contentDisposition() = %q, want an RFC 5987 filename* parameter", got)
	}
}

func TestContentDispositionNonASCIIName(t *testing.T) {
	got := contentDisposition("αναφορά.pdf")
	if !strings.Contains(got, "filename*=UTF-8''") {
		t.Errorf("contentDisposition() = %q, want an RFC 5987 filename* parameter", got)
	}
	// The legacy ASCII fallback parameter must not contain raw non-ASCII
	// bytes (they are replaced with '_' by asciiFallback).
	if strings.ContainsAny(got, "αναφορά") {
		t.Errorf("contentDisposition() = %q, want non-ASCII bytes absent from the legacy filename parameter", got)
	}
}

func TestContentDispositionQuoteAndBackslashEscaped(t *testing.T) {
	got := contentDisposition(`weird"name\here.txt`)
	// The ASCII-fallback parameter must not contain a raw unescaped
	// quote or backslash that could break out of the quoted-string.
	asciiParam := got[strings.Index(got, `filename="`)+len(`filename="`):]
	asciiParam = asciiParam[:strings.Index(asciiParam, `"`)]
	if strings.ContainsAny(asciiParam, `"\`) {
		t.Errorf("ascii filename parameter = %q, want no raw quote/backslash", asciiParam)
	}
}
