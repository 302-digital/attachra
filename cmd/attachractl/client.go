package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// apiPrefix mirrors api/openapi.yaml's `servers: [{url: /api/v1}]`:
// every path this client builds is relative to it, so command code
// passes paths like "/links" or "/policies/reload", never the prefix
// itself.
const apiPrefix = "/api/v1"

// defaultTimeout is used when no --timeout is given (root.go sets a
// flag default too; this is only a defensive fallback for a *Client
// built with a zero connectConfig.Timeout, e.g. directly in a test).
const defaultTimeout = 30 * time.Second

// Client is attachractl's HTTP client for the Attachra REST API. It
// carries no knowledge of internal/core or the metadata store — every
// method it exposes issues one HTTP request and returns the raw
// response body (or an error), leaving JSON decoding to the caller.
// This mirrors api/openapi.yaml exactly: attachractl is a client of
// the contract, not a second implementation of it.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// newClient builds a *Client from a resolved connectConfig, validating
// that the URL is well-formed (a clear error here beats a confusing
// "unsupported protocol scheme" from the first request).
func newClient(cfg connectConfig) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid API URL %q (expected e.g. https://host:port)", cfg.URL)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		// Only reachable when the operator explicitly passed --insecure
		// or set insecure: true in the config file — root.go prints a
		// warning to stderr whenever this path is taken.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit operator opt-in
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &Client{
		baseURL: strings.TrimRight(cfg.URL, "/"),
		token:   cfg.Token,
		http:    &http.Client{Transport: transport, Timeout: timeout},
	}, nil
}

// apiErrorDetail mirrors api/openapi.yaml schema ValidationIssue, the
// shape of Error.details (populated only by policy validate/reload).
type apiErrorDetail struct {
	Path     string `json:"path"`
	RuleName string `json:"rule_name,omitempty"`
	Message  string `json:"message"`
}

// apiErrorEnvelope mirrors api/openapi.yaml schema Error, the body of
// every non-2xx /api/v1 response.
type apiErrorEnvelope struct {
	Error struct {
		Code    string           `json:"code"`
		Message string           `json:"message"`
		Details []apiErrorDetail `json:"details,omitempty"`
	} `json:"error"`
}

// apiError is returned by every Client method for a non-2xx response.
// Command code type-asserts it (via errors.As) to distinguish
// authentication/authorization failures from other errors for both
// the printed message and the process exit code (errors.go).
type apiError struct {
	StatusCode int
	Code       string
	Message    string
	Details    []apiErrorDetail
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s (HTTP %d, %s)", e.Message, e.StatusCode, e.Code)
}

// decodeAPIError reads and parses resp's body as apiErrorEnvelope. A
// body that is not the expected envelope (e.g. an intermediary proxy's
// own error page) still produces a usable *apiError, with the raw body
// as Message, rather than swallowing the failure.
func decodeAPIError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env apiErrorEnvelope
	if err := json.Unmarshal(data, &env); err != nil || env.Error.Code == "" {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return &apiError{StatusCode: resp.StatusCode, Code: "unknown", Message: msg}
	}
	return &apiError{
		StatusCode: resp.StatusCode,
		Code:       env.Error.Code,
		Message:    env.Error.Message,
		Details:    env.Error.Details,
	}
}

// newRequest builds an *http.Request for path (relative to apiPrefix)
// with the given query parameters and body, always attaching the
// Bearer token (SR-130-2: the only place this client ever sends it).
func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) (*http.Request, error) {
	full := c.baseURL + apiPrefix + path
	if len(query) > 0 {
		full += "?" + query.Encode()
	}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, full, rdr)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}

// roundtrip issues req and returns the response with a nil error only
// for a 2xx status; any other status is translated to *apiError with
// the body already consumed and closed, so every call site can treat
// "no error" as "safe to read resp.Body" uniformly.
func (c *Client) roundtrip(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", req.URL.Path, err)
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close() //nolint:errcheck // body already fully consumed by decodeAPIError
		return nil, decodeAPIError(resp)
	}
	return resp, nil
}

// get issues a GET request and returns the full response body. Used by
// every read-only, non-streaming endpoint (get-by-id, current policy,
// stats summary, a single list page).
func (c *Client) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, path, query, nil, "")
	if err != nil {
		return nil, err
	}
	resp, err := c.roundtrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only response, close error is not actionable
	return io.ReadAll(resp.Body)
}

// postJSON issues a POST (or, via method, another verb carrying a JSON
// body) with reqBody marshaled as application/json, or no body at all
// when reqBody is nil (e.g. POST /policies/reload, POST
// /links/{id}/revoke). It returns the raw response body.
func (c *Client) postJSON(ctx context.Context, method, path string, query url.Values, reqBody any) ([]byte, error) {
	var body []byte
	contentType := ""
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		body = b
		contentType = "application/json"
	}

	req, err := c.newRequest(ctx, method, path, query, body, contentType)
	if err != nil {
		return nil, err
	}
	resp, err := c.roundtrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only response, close error is not actionable
	return io.ReadAll(resp.Body)
}

// postRaw is postJSON's counterpart for a non-JSON request body — used
// only by POST /policies/validate, whose contract requires
// application/x-yaml (api/openapi.yaml).
func (c *Client) postRaw(ctx context.Context, path string, body []byte, contentType string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodPost, path, nil, body, contentType)
	if err != nil {
		return nil, err
	}
	resp, err := c.roundtrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only response, close error is not actionable
	return io.ReadAll(resp.Body)
}

// delete issues a DELETE request and returns the (possibly empty)
// response body, used by DELETE /api-tokens/{tokenId} (204 No
// Content).
func (c *Client) delete(ctx context.Context, path string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodDelete, path, nil, nil, "")
	if err != nil {
		return nil, err
	}
	resp, err := c.roundtrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only response, close error is not actionable
	return io.ReadAll(resp.Body)
}

// streamGet issues a GET request and copies the response body directly
// to w without buffering it in memory (CLAUDE.md invariant #4). Used
// only by GET /audit/export, whose response is itself an unbounded,
// streamed newline-delimited JSON document (audit.ExportJSONL).
func (c *Client) streamGet(ctx context.Context, path string, query url.Values, w io.Writer) error {
	req, err := c.newRequest(ctx, http.MethodGet, path, query, nil, "")
	if err != nil {
		return err
	}
	resp, err := c.roundtrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // streamed response, close error is not actionable

	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("stream response: %w", err)
	}
	return nil
}

// rawListEnvelope is the shape shared by every paginated list resource
// (api/openapi.yaml: MessageList/AttachmentList/LinkList/
// DeliverabilityList/AuditEventList/ApiTokenList all follow the same
// `{data: [...], next_cursor}` envelope over PageMeta). Decoding items
// as json.RawMessage rather than a concrete type lets fetchAllPages be
// shared by every resource regardless of its item shape — callers
// decode each item into their own resource-specific struct.
type rawListEnvelope struct {
	Data       []json.RawMessage `json:"data"`
	NextCursor *string           `json:"next_cursor"`
}

// fetchAllPages walks every page of a cursor-paginated list resource
// (starting with no cursor), invoking onItem for each item as soon as
// its page arrives — so a caller streams output incrementally instead
// of buffering the full, potentially unbounded result set. baseQuery's
// "cursor" key is overwritten on every call after the first; the
// caller's map is never mutated (a defensive copy is taken per page).
func (c *Client) fetchAllPages(ctx context.Context, path string, baseQuery url.Values, onItem func(json.RawMessage) error) error {
	cursor := ""
	for {
		q := cloneValues(baseQuery)
		if cursor != "" {
			q.Set("cursor", cursor)
		}

		raw, err := c.get(ctx, path, q)
		if err != nil {
			return err
		}

		var env rawListEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return fmt.Errorf("decode list response from %s: %w", path, err)
		}

		for _, item := range env.Data {
			if err := onItem(item); err != nil {
				return err
			}
		}

		if env.NextCursor == nil || *env.NextCursor == "" {
			return nil
		}
		cursor = *env.NextCursor
	}
}

// fetchOnePage issues a single list request (no auto-pagination),
// returning the decoded envelope. Used by commands that expose the
// API's own cursor to the caller instead of walking it to completion
// (e.g. `audit list`, unless --all is given).
func (c *Client) fetchOnePage(ctx context.Context, path string, query url.Values) (items []json.RawMessage, nextCursor string, err error) {
	raw, err := c.get(ctx, path, query)
	if err != nil {
		return nil, "", err
	}
	var env rawListEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, "", fmt.Errorf("decode list response from %s: %w", path, err)
	}
	if env.NextCursor != nil {
		nextCursor = *env.NextCursor
	}
	return env.Data, nextCursor, nil
}

// cloneValues returns a copy of v so callers may mutate the copy
// (e.g. setting "cursor") without affecting the caller's own map,
// which may be reused across pagination calls.
func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}
