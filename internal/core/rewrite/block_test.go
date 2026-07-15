package rewrite

import (
	"strings"
	"testing"
)

func TestHumanSize(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1000, "1.0 kB"},
		{1500, "1.5 kB"},
		{1_000_000, "1.0 MB"},
		{25_000_000, "25.0 MB"},
		{1_000_000_000, "1.0 GB"},
	}
	for _, tt := range tests {
		if got := humanSize(tt.in); got != tt.want {
			t.Errorf("humanSize(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRenderBlock_SingleVsMultipleFileWording(t *testing.T) {
	tmpl, err := LoadTemplates(TemplateConfig{Locale: "en"})
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}

	single, _, err := renderBlock(tmpl, BlockData{
		Files:      []BlockFile{{Name: "a.pdf", Size: 10}},
		PackageURL: "https://dl.example.com/p/x",
	})
	if err != nil {
		t.Fatalf("renderBlock (single): %v", err)
	}
	if !strings.Contains(single, "An attachment was removed") {
		t.Errorf("singular wording missing: %q", single)
	}

	multi, _, err := renderBlock(tmpl, BlockData{
		Files: []BlockFile{
			{Name: "a.pdf", Size: 10},
			{Name: "b.pdf", Size: 20},
		},
		PackageURL: "https://dl.example.com/p/x",
	})
	if err != nil {
		t.Fatalf("renderBlock (multi): %v", err)
	}
	if !strings.Contains(multi, "2 attachments were removed") {
		t.Errorf("plural wording missing: %q", multi)
	}
}
