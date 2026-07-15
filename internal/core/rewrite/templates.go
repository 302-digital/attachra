package rewrite

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	textTemplate "text/template"
)

//go:embed templates/en/block.txt.tmpl templates/en/block.html.tmpl
var defaultTemplateFS embed.FS

// DefaultLocale is used when TemplateConfig.Locale is empty or names
// a locale with no available templates (T-3.2.2: "default en").
const DefaultLocale = "en"

// TemplateConfig selects and optionally overrides the replacement
// block templates (T-3.2.2).
type TemplateConfig struct {
	// Locale selects which built-in template set to use. Only "en" is
	// built in; empty defaults to DefaultLocale, and unknown locales
	// also fall back to DefaultLocale rather than failing message
	// processing over a configuration typo. Additional locales can be
	// added via TextTemplatePath/HTMLTemplatePath overrides pointing
	// at custom templates on disk.
	Locale string

	// TextTemplatePath, if non-empty, overrides the built-in
	// text/plain template with the contents of the file at this
	// path, read once at load time. HTMLTemplatePath does the same
	// for the HTML template. Either, both, or neither may be set;
	// an unset path keeps the built-in template for that half of the
	// block.
	TextTemplatePath string
	HTMLTemplatePath string
}

// Templates holds the parsed text/plain and HTML templates used to
// render the replacement block for a single locale/override
// configuration. A *Templates is safe for concurrent use by multiple
// goroutines (per text/template and html/template's own guarantees
// for Execute once parsing is complete).
type Templates struct {
	text *textTemplate.Template
	html *template.Template
}

// LoadTemplates parses the replacement block templates selected by
// cfg, reading override files from disk (if configured) at call time
// so a config reload can pick up edited templates without a process
// restart. It returns an error if a configured override file cannot
// be read or if any template fails to parse; callers should treat
// that as a startup-time configuration error, not a per-message
// fail-open/fail-closed decision.
func LoadTemplates(cfg TemplateConfig) (*Templates, error) {
	locale := normalizeLocale(cfg.Locale)

	textSrc, err := loadTemplateSource(cfg.TextTemplatePath, defaultTemplatePath(locale, "txt"))
	if err != nil {
		return nil, fmt.Errorf("rewrite: load text template: %w", err)
	}
	htmlSrc, err := loadTemplateSource(cfg.HTMLTemplatePath, defaultTemplatePath(locale, "html"))
	if err != nil {
		return nil, fmt.Errorf("rewrite: load html template: %w", err)
	}

	textTmpl, err := textTemplate.New("block.txt").Parse(textSrc)
	if err != nil {
		return nil, fmt.Errorf("rewrite: parse text template: %w", err)
	}
	htmlTmpl, err := template.New("block.html").Parse(htmlSrc)
	if err != nil {
		return nil, fmt.Errorf("rewrite: parse html template: %w", err)
	}

	return &Templates{text: textTmpl, html: htmlTmpl}, nil
}

// normalizeLocale maps an arbitrary configured locale string to one
// of the built-in locales this package ships templates for, falling
// back to DefaultLocale for anything else. Only DefaultLocale ("en")
// is currently built in.
func normalizeLocale(_ string) string {
	return DefaultLocale
}

// defaultTemplatePath builds the embed.FS path for the built-in
// template of the given locale and kind ("txt" or "html").
func defaultTemplatePath(locale, kind string) string {
	return fmt.Sprintf("templates/%s/block.%s.tmpl", locale, kind)
}

// loadTemplateSource returns the contents of overridePath if
// non-empty, otherwise the embedded default at defaultPath.
func loadTemplateSource(overridePath, defaultPath string) (string, error) {
	if overridePath == "" {
		b, err := fs.ReadFile(defaultTemplateFS, defaultPath)
		if err != nil {
			return "", fmt.Errorf("read embedded default %q: %w", defaultPath, err)
		}
		return string(b), nil
	}

	b, err := os.ReadFile(overridePath) //nolint:gosec // operator-configured path from application config, not attacker-controlled
	if err != nil {
		return "", fmt.Errorf("read override file %q: %w", overridePath, err)
	}
	return string(b), nil
}
