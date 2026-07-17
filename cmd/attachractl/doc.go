// Command attachractl is the network client for the Attachra
// admin/automation REST API (US-9.1/E9, ATR-131/202..205). Unlike
// cmd/attachra's own `link`/`token`/`audit` subcommands — which talk
// directly to the metadata store from the same host the server runs on
// — attachractl never touches internal/core or the database: every
// operation goes over HTTP to a running Attachra instance's /api/v1
// surface (api/openapi.yaml is the source of truth for every request
// and response shape this package builds). This is deliberate
// "dogfooding" of the REST API contract: if attachractl can drive the
// system, so can any other automation client.
//
// # Connection configuration
//
// The API endpoint and Bearer token are resolved with the following
// precedence, highest first:
//
//  1. Command-line flags (--url, --token-file, --insecure).
//  2. Environment variables (ATTACHRACTL_URL, ATTACHRACTL_TOKEN).
//  3. The YAML config file (--config, default
//     ~/.config/attachractl/config.yaml).
//
// The token is never accepted as a plain --token flag value: a value
// passed on the command line is visible to every other local user via
// /proc/<pid>/cmdline or `ps`, so it may only come from a file (via
// --token-file or the config file's token/token_file field) or the
// ATTACHRACTL_TOKEN environment variable, and it is never logged or
// echoed back by this CLI.
//
// Whichever file the token lives in (--token-file, the config file's
// token_file, or an inline token: in the config file itself) should be
// chmod 0600 — readable and writable only by its owner. attachractl
// checks this on every invocation and prints a WARNING to stderr (it
// does not refuse to run, since an operator may have deliberate
// reasons, e.g. a read-only mount inside a container image with its
// own access controls) when the file grants group or other access
// (SR-130-2).
package main
