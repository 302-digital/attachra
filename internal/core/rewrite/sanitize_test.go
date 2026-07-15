package rewrite

import "testing"

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no control chars", "report.pdf", "report.pdf"},
		{"embedded CRLF", "evil\r\nX-Injected: yes", "evilX-Injected: yes"},
		{"embedded bare LF", "evil\ninjected", "evilinjected"},
		{"embedded bare CR", "evil\rinjected", "evilinjected"},
		{"multiple CRLF", "a\r\nb\r\nc", "abc"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeHeaderValue(tt.in); got != tt.want {
				t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestEncodeContentDispositionFilename(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ascii", "report.pdf", "UTF-8''report.pdf"},
		{"space", "my report.pdf", "UTF-8''my%20report.pdf"},
		{"greek", "αναφορά.pdf", "UTF-8''%CE%B1%CE%BD%CE%B1%CF%86%CE%BF%CF%81%CE%AC.pdf"},
		{"crlf injection attempt", "evil\r\nX-Injected: yes.txt", "UTF-8''evilX-Injected:%20yes.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeContentDispositionFilename(tt.in)
			if got != tt.want {
				t.Errorf("encodeContentDispositionFilename(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
