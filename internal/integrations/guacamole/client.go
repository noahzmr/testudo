package guacamole

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client drives the Apache Guacamole REST API so a PAM grant can be a
// *brokered* session: Testudo creates a per-grant connection (credentials
// stay inside Guacamole, recording on), hands the user a launch URL, and at
// grant end kills the live session and deletes the connection. The API
// credential is a Guacamole account with permission to manage connections;
// Testudo never stores target credentials.
type Client struct {
	BaseURL  string // e.g. https://guac.example.com (installation root)
	Username string
	Password string
	HTTP     *http.Client

	mu         sync.Mutex
	token      string
	dataSource string
	tokenAt    time.Time
}

// tokenTTL is how long a token is reused before re-authenticating. Guacamole
// tokens live much longer, but a short reuse window keeps a revoked API user
// from working for hours.
const tokenTTL = 30 * time.Minute

// ErrNotConfigured is returned when the client has no base URL / credentials.
var ErrNotConfigured = errors.New("guacamole: API not configured")

// APIError carries the HTTP status Guacamole answered with.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("guacamole: HTTP %d: %s", e.Status, strings.TrimSpace(e.Body))
}

// Configured reports whether the client can talk to Guacamole at all.
func (c *Client) Configured() bool {
	return c != nil && c.BaseURL != "" && c.Username != "" && c.Password != ""
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// login obtains an auth token (POST /api/tokens, form-encoded).
func (c *Client) login(ctx context.Context) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	form := url.Values{"username": {c.Username}, "password": {c.Password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/api/tokens",
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("guacamole: login: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return &APIError{Status: resp.StatusCode, Body: redact(string(body))}
	}
	var tok struct {
		AuthToken  string `json:"authToken"`
		DataSource string `json:"dataSource"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AuthToken == "" {
		return errors.New("guacamole: login: malformed token response")
	}
	c.token, c.dataSource, c.tokenAt = tok.AuthToken, tok.DataSource, time.Now()
	return nil
}

// do performs an authenticated data-source request, logging in first when
// needed and once more if the token was rejected. out may be nil.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" || time.Since(c.tokenAt) > tokenTTL {
		if err := c.login(ctx); err != nil {
			return err
		}
	}
	for attempt := range 2 {
		status, resp, err := c.request(ctx, method, path, body)
		if err != nil {
			return err
		}
		if (status == http.StatusUnauthorized || status == http.StatusForbidden) && attempt == 0 {
			if err := c.login(ctx); err != nil {
				return err
			}
			continue
		}
		if status < 200 || status >= 300 {
			return &APIError{Status: status, Body: redact(string(resp))}
		}
		if out != nil && len(resp) > 0 {
			if err := json.Unmarshal(resp, out); err != nil {
				return fmt.Errorf("guacamole: decode %s: %w", path, err)
			}
		}
		return nil
	}
	return errors.New("guacamole: authentication failed")
}

// request issues one call to /api/session/data/{ds}{path} with the token.
func (c *Client) request(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	u := strings.TrimRight(c.BaseURL, "/") + "/api/session/data/" + url.PathEscape(c.dataSource) + path
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	u += sep + "token=" + url.QueryEscape(c.token)
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Guacamole-Token", c.token)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("guacamole: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, nil
}

// ConnectionSpec describes a connection to create.
type ConnectionSpec struct {
	Name       string
	Protocol   string            // ssh | rdp | vnc | telnet
	Parameters map[string]string // hostname, port, username, password, recording-path, ...
	Attributes map[string]string // max-connections etc.
	Parent     string            // connection group; "" = ROOT
}

// CreateConnection creates a connection and returns its identifier.
func (c *Client) CreateConnection(ctx context.Context, spec ConnectionSpec) (string, error) {
	if spec.Parent == "" {
		spec.Parent = "ROOT"
	}
	if spec.Attributes == nil {
		spec.Attributes = map[string]string{}
	}
	payload := map[string]any{
		"parentIdentifier": spec.Parent,
		"name":             spec.Name,
		"protocol":         spec.Protocol,
		"parameters":       spec.Parameters,
		"attributes":       spec.Attributes,
	}
	var out struct {
		Identifier string `json:"identifier"`
	}
	if err := c.do(ctx, http.MethodPost, "/connections", payload, &out); err != nil {
		return "", err
	}
	if out.Identifier == "" {
		return "", errors.New("guacamole: create connection: no identifier returned")
	}
	return out.Identifier, nil
}

// ConnectionParameters reads a connection's parameters (hostname, port,
// credentials...). Needs an API user with ADMINISTER on the connection; used
// to clone a template connection into a per-grant one.
func (c *Client) ConnectionParameters(ctx context.Context, id string) (map[string]string, error) {
	var out map[string]string
	if err := c.do(ctx, http.MethodGet, "/connections/"+url.PathEscape(id)+"/parameters", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Connection reads a connection's metadata (name, protocol).
func (c *Client) Connection(ctx context.Context, id string) (name, protocol string, err error) {
	var out struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
	}
	if err := c.do(ctx, http.MethodGet, "/connections/"+url.PathEscape(id), nil, &out); err != nil {
		return "", "", err
	}
	return out.Name, out.Protocol, nil
}

// DeleteConnection removes a connection. A 404 is treated as success.
func (c *Client) DeleteConnection(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// GrantUserRead lets a Guacamole user open the connection. The Guacamole user
// is expected to share the Testudo user name; a missing user is reported as
// *APIError 404 so callers can fall back to a launch URL only.
func (c *Client) GrantUserRead(ctx context.Context, user, connID string) error {
	patch := []map[string]string{{
		"op": "add", "path": "/connectionPermissions/" + connID, "value": "READ",
	}}
	return c.do(ctx, http.MethodPatch, "/users/"+url.PathEscape(user)+"/permissions", patch, nil)
}

// ActiveConnection is one live session.
type ActiveConnection struct {
	Identifier           string `json:"identifier"`
	ConnectionIdentifier string `json:"connectionIdentifier"`
	Username             string `json:"username"`
	RemoteHost           string `json:"remoteHost"`
	StartDate            int64  `json:"startDate"`
}

// ActiveConnections lists live sessions, optionally filtered to one connection.
func (c *Client) ActiveConnections(ctx context.Context, connID string) ([]ActiveConnection, error) {
	var out map[string]ActiveConnection
	if err := c.do(ctx, http.MethodGet, "/activeConnections", nil, &out); err != nil {
		return nil, err
	}
	var list []ActiveConnection
	for id, a := range out {
		if a.Identifier == "" {
			a.Identifier = id
		}
		if connID == "" || a.ConnectionIdentifier == connID {
			list = append(list, a)
		}
	}
	return list, nil
}

// KillActiveConnections terminates every live session of a connection and
// returns how many it killed.
func (c *Client) KillActiveConnections(ctx context.Context, connID string) (int, error) {
	active, err := c.ActiveConnections(ctx, connID)
	if err != nil {
		return 0, err
	}
	if len(active) == 0 {
		return 0, nil
	}
	patch := make([]map[string]string, 0, len(active))
	for _, a := range active {
		patch = append(patch, map[string]string{"op": "remove", "path": "/" + a.Identifier})
	}
	if err := c.do(ctx, http.MethodPatch, "/activeConnections", patch, nil); err != nil {
		return 0, err
	}
	return len(active), nil
}

// redact keeps error bodies from echoing credentials back into logs.
func redact(s string) string {
	for _, k := range []string{"password", "authToken"} {
		if before, _, found := strings.Cut(s, k); found {
			return before + k + "…[redacted]"
		}
	}
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
