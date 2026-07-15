// Package version holds build-time metadata injected via -ldflags.
package version

// Version, Commit and Date are populated at build time via:
//
//	go build -ldflags "-X github.com/302-digital/attachra/internal/version.Version=... \
//	  -X github.com/302-digital/attachra/internal/version.Commit=... \
//	  -X github.com/302-digital/attachra/internal/version.Date=..."
//
// They default to "dev"/"none"/"unknown" for local `go run`/`go build`
// invocations that don't set ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a single-line human-readable representation, e.g.
// "attachra dev (commit none, built unknown)".
func String() string {
	return "attachra " + Version + " (commit " + Commit + ", built " + Date + ")"
}
