package http

import (
	"html/template"
)

// Templates are parsed once at package init from Go string literals
// (not loaded from disk) so the binary stays single-file/static
// (CLAUDE.md invariant #2) and no external template file can be
// tampered with at runtime. html/template auto-escapes every
// interpolated value (SR-125-5/T1.5): file names and any other
// message-derived text are safe to interpolate directly.

// packagePageTemplate renders the step-1 landing page listing every
// replaced attachment of a message (docs/architecture/
// package-page-decision.md §4.1 item 3). Each available file is a
// same-origin POST form (no GET-triggered download, no query-string
// tokens, no external links); unavailable files render as inert list
// items with a neutral status label, never explaining why (SR-125-5).
var packagePageTemplate = template.Must(template.New("package").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attachra - Files from a message</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.25rem}
ul{list-style:none;padding:0}
li{display:flex;align-items:center;justify-content:space-between;padding:.75rem 0;border-bottom:1px solid #e2e2e2}
.name{overflow-wrap:anywhere}
.size{color:#666;font-size:.85em;margin-left:.5rem}
.status{color:#888;font-size:.85em}
button{padding:.4rem .9rem;border:1px solid #1a1a1a;background:#1a1a1a;color:#fff;border-radius:4px;cursor:pointer}
button:hover{opacity:.85}
</style>
</head>
<body>
<h1>Files from a message</h1>
<p>The files below were held by Attachra and replaced with this link. Click download on any file you want.</p>
<ul>
{{range .Files}}<li>
<span class="name">{{.Name}}{{if .Size}}<span class="size">({{.Size}})</span>{{end}}</span>
{{if .Available}}
<form method="post" action="{{$.PackagePath}}/d/{{.Ref}}">
<button type="submit">Download</button>
</form>
{{else}}
<span class="status">Not available</span>
{{end}}
</li>
{{end}}
</ul>
</body>
</html>
`))

// errorPageTemplate is the single generic response rendered for every
// negative outcome on this adapter's routes: unknown token, expired,
// revoked, exhausted, or any internal failure (SR-125-5). Content is
// static aside from nothing message-derived — no token, reason, or
// internal detail is ever interpolated into it, so there is nothing
// for html/template to need to escape, but the page still runs
// through the templating engine for consistency with packagePageTemplate.
var errorPageTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attachra - Not available</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:4rem auto;padding:0 1rem;color:#1a1a1a;text-align:center}
h1{font-size:1.25rem}
</style>
</head>
<body>
<h1>This link is not available</h1>
<p>It may have expired, been revoked, or already used up its download limit. If you were expecting this file, ask the sender to share it again.</p>
</body>
</html>
`))

// packagePageData is the render model for packagePageTemplate.
type packagePageData struct {
	PackagePath string // e.g. "/p/<token>", used as the POST form action prefix.
	Files       []packageFileView
}

// packageFileView is one row of the package page's file listing.
type packageFileView struct {
	Ref       string // attachment ID, used in the download form's action URL.
	Name      string
	Size      string // pre-formatted human-readable size, or "" if unknown.
	Available bool
}
