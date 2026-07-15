package http

import "strings"

// parsePackagePath parses a request path against the two fixed route
// shapes this adapter serves:
//
//	/p/<token>          -> token, "", true
//	/p/<token>/d/<ref>   -> token, ref, true
//
// Any other shape (wrong prefix, missing token, extra segments,
// malformed "/d/" marker) returns ok == false. Parsing is done with
// plain string splitting rather than a routing library or regex,
// since there are exactly two shapes to recognize and both token and
// ref are opaque path segments that must not be interpreted as
// containing further structure (in particular, a token or ref
// containing "/" is never valid — link.GenerateToken's base64
// URL-safe alphabet cannot produce one, but a malicious path must
// still not be silently reinterpreted).
func parsePackagePath(path string) (token, ref string, ok bool) {
	const prefix = "/p/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rest := path[len(prefix):]
	if rest == "" {
		return "", "", false
	}

	i := strings.IndexByte(rest, '/')
	if i < 0 {
		token = rest
		if !validSegment(token) {
			return "", "", false
		}
		return token, "", true
	}

	token = rest[:i]
	tail := rest[i+1:]
	const dMarker = "d/"
	if !strings.HasPrefix(tail, dMarker) {
		return "", "", false
	}
	ref = tail[len(dMarker):]
	if !validSegment(token) || !validSegment(ref) {
		return "", "", false
	}
	return token, ref, true
}

// validSegment reports whether s is a non-empty path segment with no
// further "/" and no empty sub-parts, rejecting anything that looks
// like it is trying to smuggle additional path structure.
func validSegment(s string) bool {
	return s != "" && !strings.Contains(s, "/")
}
