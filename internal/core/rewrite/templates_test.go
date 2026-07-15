package rewrite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTemplates_DefaultLocale(t *testing.T) {
	tmpl, err := LoadTemplates(TemplateConfig{})
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	plain, html, err := renderBlock(tmpl, BlockData{
		Files:      []BlockFile{{Name: "a.pdf", Size: 100}},
		PackageURL: "https://dl.example.com/p/x",
	})
	if err != nil {
		t.Fatalf("renderBlock: %v", err)
	}
	if !strings.Contains(plain, "available for download") {
		t.Errorf("default locale should be English, got plain text: %q", plain)
	}
	if !strings.Contains(html, "Download files") {
		t.Errorf("default locale should be English, got html: %q", html)
	}
}

func TestLoadTemplates_UnknownLocaleFallsBackToDefault(t *testing.T) {
	tmpl, err := LoadTemplates(TemplateConfig{Locale: "fr"})
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	plain, _, err := renderBlock(tmpl, BlockData{
		Files:      []BlockFile{{Name: "a.pdf", Size: 100}},
		PackageURL: "https://dl.example.com/p/x",
	})
	if err != nil {
		t.Fatalf("renderBlock: %v", err)
	}
	if !strings.Contains(plain, "available for download") {
		t.Errorf("unknown locale should fall back to English, got: %q", plain)
	}
}

func TestLoadTemplates_OverridePath(t *testing.T) {
	dir := t.TempDir()
	overridePath := filepath.Join(dir, "custom.txt.tmpl")
	if err := os.WriteFile(overridePath, []byte("CUSTOM: {{.PackageURL}}\n"), 0o600); err != nil {
		t.Fatalf("write override file: %v", err)
	}

	tmpl, err := LoadTemplates(TemplateConfig{TextTemplatePath: overridePath})
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	plain, _, err := renderBlock(tmpl, BlockData{PackageURL: "https://dl.example.com/p/x"})
	if err != nil {
		t.Fatalf("renderBlock: %v", err)
	}
	if !strings.Contains(plain, "CUSTOM: https://dl.example.com/p/x") {
		t.Errorf("override template not used, got: %q", plain)
	}
}

func TestLoadTemplates_OverridePathMissingFile(t *testing.T) {
	_, err := LoadTemplates(TemplateConfig{TextTemplatePath: "/nonexistent/path/template.tmpl"})
	if err == nil {
		t.Fatal("LoadTemplates with missing override file: want error, got nil")
	}
}

func TestLoadTemplates_InvalidTemplateSyntax(t *testing.T) {
	dir := t.TempDir()
	overridePath := filepath.Join(dir, "broken.html.tmpl")
	if err := os.WriteFile(overridePath, []byte("{{.Unclosed"), 0o600); err != nil {
		t.Fatalf("write override file: %v", err)
	}

	_, err := LoadTemplates(TemplateConfig{HTMLTemplatePath: overridePath})
	if err == nil {
		t.Fatal("LoadTemplates with invalid template syntax: want error, got nil")
	}
}
