// Package http implements the public download adapter (US-6.2, ADR-002):
// an HTTP server exposing the two-step package-page download flow
// described in docs/architecture/package-page-decision.md §4.1.
//
//   - GET  /p/<message-link-token>                  — package page
//     (step 1, safe): resolves the message-link token via
//     internal/core/link, renders an HTML listing of the message's
//     replaced attachments. Never streams bytes and never decrements a
//     download counter (SR-125-3), so link-preview bots that fetch
//     this URL do not consume a recipient's download budget.
//   - POST /p/<message-link-token>/d/<link-id> — download (step 2,
//     explicit action): registers the download atomically against the
//     per-attachment Link identified by its store-assigned, non-secret
//     ID (see internal/core/link.Engine.RegisterPackageDownload for
//     why the package token, not a second bearer token, is what
//     authorizes this step) and streams the object from
//     storage.Driver without buffering the whole payload in memory
//     (CLAUDE.md invariant #4).
//
// This package depends only on internal/core (link, store, storage);
// it must never be imported by internal/core (ADR-002), matching the
// milter adapter's dependency direction.
//
// Every negative outcome (token not found, expired, revoked,
// download-limit exhausted) renders through the exact same generic
// error page and HTTP status (SR-125-5): the cause is never
// distinguishable to an anonymous caller, only to the audit log line
// this package writes.
package http
