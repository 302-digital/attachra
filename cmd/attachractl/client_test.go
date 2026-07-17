package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDecodeAPIError_NonJSONBodyFalksBack exercises decodeAPIError's
// fallback path: a body that is not the expected apiErrorEnvelope
// (e.g. an intermediary proxy's own HTML error page, or a plain-text
// body from a component upstream of the API server) must still produce
// a usable *apiError carrying the raw body as its Message, rather than
// the caller getting no error information at all.
func TestDecodeAPIError_NonJSONBodyFallsBack(t *testing.T) {
	body := "<html><body>502 Bad Gateway</body></html>"
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     "502 Bad Gateway",
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	err := decodeAPIError(resp)
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("decodeAPIError() = %v (%T), want an *apiError", err, err)
	}
	if ae.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want %d", ae.StatusCode, http.StatusBadGateway)
	}
	if ae.Code != "unknown" {
		t.Errorf("Code = %q, want %q", ae.Code, "unknown")
	}
	if ae.Message != body {
		t.Errorf("Message = %q, want the raw body %q", ae.Message, body)
	}
}

// TestDecodeAPIError_EmptyBodyFallsBackToStatus covers the same
// fallback path with a completely empty body (e.g. a HEAD-like
// response, or a proxy that drops the body): the message must fall
// back to the HTTP status line rather than being blank.
func TestDecodeAPIError_EmptyBodyFallsBackToStatus(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Status:     "503 Service Unavailable",
		Body:       io.NopCloser(strings.NewReader("")),
	}

	err := decodeAPIError(resp)
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("decodeAPIError() = %v (%T), want an *apiError", err, err)
	}
	if ae.Message != "503 Service Unavailable" {
		t.Errorf("Message = %q, want the response status %q", ae.Message, "503 Service Unavailable")
	}
}

// TestDecodeAPIError_ValidEnvelopeIsParsed is the counterpart positive
// case: a well-formed apiErrorEnvelope body must populate Code/Message
// from it rather than taking the fallback path.
func TestDecodeAPIError_ValidEnvelopeIsParsed(t *testing.T) {
	body := `{"error":{"code":"not_found","message":"link not found"}}`
	resp := &http.Response{
		StatusCode: http.StatusNotFound,
		Status:     "404 Not Found",
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	err := decodeAPIError(resp)
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("decodeAPIError() = %v (%T), want an *apiError", err, err)
	}
	if ae.Code != "not_found" || ae.Message != "link not found" {
		t.Errorf("ae = %+v, want code=not_found message=%q", ae, "link not found")
	}
}

// TestStreamGet_TruncatedBodyReturnsError exercises streamGet's error
// path used by `audit export`: a response that is cut off mid-stream
// (the server declares a Content-Length larger than what it actually
// sends, then the connection is closed) must surface as an error from
// io.Copy rather than being silently treated as a complete,
// successfully streamed export. Whatever bytes did arrive before the
// truncation must still have reached the writer — audit export streams
// directly to stdout without buffering (the streaming invariant), so a
// caller piping this output has already seen the partial data by the
// time the error is reported.
func TestStreamGet_TruncatedBodyReturnsError(t *testing.T) {
	const partial = `{"seq":1,"type":"error"}` + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Promise far more bytes than are actually written, then rip the
		// connection out from under the client via Hijack — this is the
		// standard way to force net/http's client-side reader to observe
		// a truncated, Content-Length-framed body (io.ErrUnexpectedEOF).
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(partial)); err != nil {
			t.Errorf("write partial body: %v", err)
			return
		}
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("ResponseWriter does not support Hijack")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)
			return
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	client, err := newClient(connectConfig{URL: srv.URL, Token: "t", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newClient() error = %v", err)
	}

	var buf bytes.Buffer
	err = client.streamGet(context.Background(), "/audit/export", nil, &buf)
	if err == nil {
		t.Fatal("streamGet() error = nil, want an error for a body truncated mid-stream")
	}
	if !strings.Contains(buf.String(), `"seq":1`) {
		t.Errorf("buf = %q, want the bytes written before truncation to have reached the writer", buf.String())
	}
}
