package main

import (
	"errors"
	"fmt"
	"net/http"
)

// Process exit codes. 0/1 follow the usual Unix convention (success /
// generic failure); the rest give scripts driving attachractl a way to
// distinguish common failure classes without parsing stderr text.
const (
	exitOK           = 0
	exitError        = 1 // unexpected/internal failure (network, decode, bug)
	exitUsage        = 2 // bad arguments, or the API rejected the request as malformed (400)
	exitUnauthorized = 3 // 401: missing/invalid bearer token
	exitForbidden    = 4 // 403: token's role may not perform this action
	exitNotFound     = 5 // 404: no such resource
	exitConflict     = 6 // 409: e.g. link under legal hold, invalid policy on reload
	exitValidation   = 7 // `policy validate` found errors in the submitted document
)

// cliError pairs an error with the specific process exit code it
// should produce, for outcomes that are not naturally derived from an
// *apiError's HTTP status (e.g. `policy validate` finding document
// errors, which is a 200 response, not an API error).
type cliError struct {
	code int
	err  error
}

func newCLIError(code int, format string, args ...any) *cliError {
	return &cliError{code: code, err: fmt.Errorf(format, args...)}
}

func (e *cliError) Error() string { return e.err.Error() }
func (e *cliError) Unwrap() error { return e.err }

// exitCodeForErr maps any error returned by a command's RunE to a
// process exit code: a *cliError's own code takes priority, then an
// *apiError's HTTP status is mapped to the closest matching exit code
// above, and anything else is the generic exitError.
func exitCodeForErr(err error) int {
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.code
	}

	var ae *apiError
	if errors.As(err, &ae) {
		switch ae.StatusCode {
		case http.StatusBadRequest:
			return exitUsage
		case http.StatusUnauthorized:
			return exitUnauthorized
		case http.StatusForbidden:
			return exitForbidden
		case http.StatusNotFound:
			return exitNotFound
		case http.StatusConflict:
			return exitConflict
		default:
			return exitError
		}
	}

	return exitError
}
