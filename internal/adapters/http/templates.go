package http

import (
	"html/template"
)

// Templates are parsed once at package init from Go string literals
// (not loaded from disk) so the binary stays single-file/static (the
// single-static-binary invariant, ADR-001) and no external template
// file can be tampered with at runtime. html/template auto-escapes every
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

// aboutPageTemplate renders GET /about, the second layer of the
// Recipient Trust Kit (ATR-230/ATR-271): a static, unauthenticated
// landing page on the same public download listener as /p/, aimed at
// the IT administrator of an email's recipient who does not recognize
// the download domain in a link they received and wants to verify it
// before whitelisting it or reporting it as suspicious.
//
// Content is entirely static (no template data, no configuration
// input): it explains what Attachra is, why the recipient is seeing a
// link on this domain, and how to verify the link's legitimacy, without
// ever naming this specific installation's operator, version, or any
// other installation-specific detail (SR-130-1-style "no leakage of
// installation details" — see Handler.serveAbout's doc comment). Like
// packagePageTemplate, it is parsed once from a Go string literal so
// the binary stays single-file/static (the single-static-binary
// invariant (ADR-001)) and carries no external resources, matching
// pageCSP's "default-src
// 'none'" policy (the two plain-text links to attachra.org/GitHub are
// page navigation, not a resource load, so they are unaffected by CSP).
var aboutPageTemplate = template.Must(template.New("about").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attachra - About this link</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:680px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;line-height:1.5}
h1{font-size:1.35rem}
h2{font-size:1.05rem;margin-top:1.75rem}
ul{padding-left:1.25rem}
li{margin:.4rem 0}
code{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px}
.footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #e2e2e2;color:#555;font-size:.9em}
</style>
</head>
<body>
<h1>About this link</h1>
<p>You received an email whose attachments were replaced with a link on
this domain. This page explains what that means and how to verify the
link is legitimate before you open it, whitelist the domain, or report
it as suspicious.</p>

<h2>What is Attachra?</h2>
<p>Attachra is a self-hosted attachment policy engine that mail servers
run to replace large or risky email attachments with secure, revocable
download links instead of sending the files inline. It is not a mail
provider: it is software the sending organization runs on its own
infrastructure. Learn more at
<a href="https://attachra.org">attachra.org</a> or on
<a href="https://github.com/302-digital/attachra">GitHub</a>.</p>

<h2>Why did I get this link?</h2>
<p>The organization that emailed you runs an Attachra instance that
replaced one or more attachments with a link before the message was
delivered. This is a routing decision made by the sender's own mail
system, not by the Attachra project.</p>

<h2>How to verify this link is legitimate</h2>
<ul>
<li>This domain is operated by the organization that sent you the
email — check that it matches (or is a recognizable subdomain of) the
sender's own domain, the same way you would verify any link.</li>
<li>Each link is single-purpose: it is revocable and time-limited, and
may also be limited to a fixed number of downloads. Once revoked,
expired, or exhausted, it stops working.</li>
<li>Every download is forced to save-as, not run: files are served
with a <code>Content-Disposition: attachment</code> header and
<code>X-Content-Type-Options: nosniff</code>, so nothing executes
inline in your browser and nothing redirects you elsewhere. The file
itself can still be of any type, so use the same judgment (scanning,
sender verification) you would for any email attachment before opening
it.</li>
<li>If you still have doubts, do not rely on this page alone — contact
the sender's IT or mail administrator directly, through a channel you
already trust, and ask them to confirm the link.</li>
</ul>

<div class="footer">
<p>This page is served by the Attachra software the sender's
organization operates. Questions about a specific email or link should
go to that organization's IT/mail administrator, not the Attachra
project — the project has no visibility into any installation's mail
traffic or recipients.</p>
</div>
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
	// Ref is the store-assigned, non-secret store.Link.ID (not the
	// attachment ID), used as the download form's action URL segment.
	// See Handler.fileView and link.Engine.RegisterPackageDownload's
	// doc comment for why a row ID — not a second bearer token or the
	// AttachmentID — is what belongs here.
	Ref       string
	Name      string
	Size      string // pre-formatted human-readable size, or "" if unknown.
	Available bool
}
