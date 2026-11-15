// Package oidcauth is the OpenID Connect relying party: the authorization
// code flow with PKCE, strict validation of ID tokens, refresh, logout at
// the provider and logout by the provider (back-channel).
//
// Discovery and key handling come from github.com/coreos/go-oidc: the
// provider's keys are cached and fetched again when a token names a key
// that is not known, which is how key rotation is followed.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// DefaultAlgs are accepted when a provider's configuration names none.
// Symmetric algorithms and "none" are never accepted.
var DefaultAlgs = []string{"RS256", "ES256"}

// Config describes the provider and this client.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string // empty for a public client
	RedirectURL  string
	Scopes       []string // in addition to openid, profile, email
	// UsernameClaim and GroupsClaim name the claims to read; a dot walks
	// into nested objects ("realm_access.roles").
	UsernameClaim string
	GroupsClaim   string
	SigningAlgs   []string
	// HTTPClient is used for every request to the provider. Nil uses a
	// client with a 10 s timeout.
	HTTPClient *http.Client
	Now        func() time.Time
}

// Client talks to one provider.
type Client struct {
	cfg        Config
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth      oauth2.Config
	endSession string
	backchan   bool

	mu   sync.Mutex
	seen map[string]time.Time // logout token ids already used
}

func (c *Client) now() time.Time {
	if c.cfg.Now != nil {
		return c.cfg.Now()
	}
	return time.Now()
}

func (c *Client) ctx(ctx context.Context) context.Context {
	hc := c.cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return oidc.ClientContext(ctx, hc)
}

// New reads the provider's discovery document. The issuer in it has to be
// exactly the configured one.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: issuer, client id and redirect URL are required")
	}
	algs := cfg.SigningAlgs
	if len(algs) == 0 {
		algs = DefaultAlgs
	}
	for _, a := range algs {
		if a == "none" || strings.HasPrefix(a, "HS") {
			return nil, fmt.Errorf("oidc: signature algorithm %s is not accepted", a)
		}
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	c := &Client{cfg: cfg, seen: map[string]time.Time{}}
	provider, err := oidc.NewProvider(c.ctx(ctx), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
		Backchan   bool   `json:"backchannel_logout_supported"`
	}
	_ = provider.Claims(&extra)
	c.provider, c.endSession, c.backchan = provider, extra.EndSession, extra.Backchan
	c.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: algs, Now: c.now})
	c.oauth = oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: cfg.RedirectURL, Scopes: append([]string{oidc.ScopeOpenID, "profile", "email"}, cfg.Scopes...)}
	return c, nil
}

// Flow is the state of one login attempt between the redirect to the
// provider and the callback. It stays on the server.
type Flow struct {
	State    string
	Nonce    string
	Verifier string
	Created  time.Time
}

func random() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Start begins a login and returns where to send the browser.
func (c *Client) Start() (Flow, string) {
	f := Flow{State: random(), Nonce: random(), Verifier: random(), Created: c.now()}
	sum := sha256.Sum256([]byte(f.Verifier))
	return f, c.oauth.AuthCodeURL(f.State, oidc.Nonce(f.Nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
}

// Identity is who the provider says logged in.
type Identity struct {
	Subject  string
	Username string
	Email    string
	Groups   []string
	// SessionID is the provider's session ("sid"), used by back-channel
	// logout.
	SessionID string
}

// Tokens is what a session keeps to refresh itself and to log out.
type Tokens struct {
	IDToken string
	Refresh string
	// Expiry is when the session has to be refreshed.
	Expiry time.Time
}

func walk(claims map[string]any, path string) any {
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

func (c *Client) identity(tok *oidc.IDToken) (Identity, error) {
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return Identity{}, err
	}
	id := Identity{Subject: tok.Subject}
	if id.Subject == "" {
		return id, errors.New("oidc: the token has no subject")
	}
	id.Username, _ = walk(claims, c.cfg.UsernameClaim).(string)
	if id.Username == "" {
		id.Username = id.Subject
	}
	id.Email, _ = claims["email"].(string)
	id.SessionID, _ = claims["sid"].(string)
	switch g := walk(claims, c.cfg.GroupsClaim).(type) {
	case []any:
		for _, v := range g {
			if s, ok := v.(string); ok {
				id.Groups = append(id.Groups, s)
			}
		}
	case string:
		id.Groups = strings.Fields(g)
	}
	// With several audiences the token has to say which client it was
	// issued to.
	if len(tok.Audience) > 1 {
		if azp, _ := claims["azp"].(string); azp != c.cfg.ClientID {
			return id, errors.New("oidc: the token was issued to another client")
		}
	}
	return id, nil
}

func (c *Client) tokens(t *oauth2.Token, raw string, idExp time.Time, old Tokens) Tokens {
	out := Tokens{IDToken: raw, Refresh: t.RefreshToken, Expiry: idExp}
	if out.Refresh == "" {
		out.Refresh = old.Refresh // the provider did not rotate it
	}
	if !t.Expiry.IsZero() && t.Expiry.Before(out.Expiry) {
		out.Expiry = t.Expiry
	}
	return out
}

// Finish completes a login: it exchanges the code with the PKCE verifier
// and validates the ID token (signature with an accepted algorithm, issuer,
// audience, expiry, nonce).
func (c *Client) Finish(ctx context.Context, f Flow, code string) (Identity, Tokens, error) {
	t, err := c.oauth.Exchange(c.ctx(ctx), code, oauth2.SetAuthURLParam("code_verifier", f.Verifier))
	if err != nil {
		return Identity{}, Tokens{}, fmt.Errorf("oidc: code exchange: %w", err)
	}
	raw, _ := t.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, Tokens{}, errors.New("oidc: the provider returned no ID token")
	}
	tok, err := c.verifier.Verify(c.ctx(ctx), raw)
	if err != nil {
		return Identity{}, Tokens{}, fmt.Errorf("oidc: ID token: %w", err)
	}
	if tok.Nonce == "" || tok.Nonce != f.Nonce {
		return Identity{}, Tokens{}, errors.New("oidc: the ID token does not belong to this login (nonce)")
	}
	id, err := c.identity(tok)
	if err != nil {
		return Identity{}, Tokens{}, err
	}
	return id, c.tokens(t, raw, tok.Expiry, Tokens{}), nil
}

// ErrNoRefresh means the session cannot be extended and has to end.
var ErrNoRefresh = errors.New("oidc: the session cannot be refreshed")

// Refresh extends a session with its refresh token. The new ID token has to
// be for the same subject. The identity is read again, so a change of
// groups at the provider arrives here.
func (c *Client) Refresh(ctx context.Context, old Tokens, subject string) (Identity, Tokens, error) {
	if old.Refresh == "" {
		return Identity{}, Tokens{}, ErrNoRefresh
	}
	t, err := c.oauth.TokenSource(c.ctx(ctx), &oauth2.Token{RefreshToken: old.Refresh}).Token()
	if err != nil {
		return Identity{}, Tokens{}, fmt.Errorf("%w: %v", ErrNoRefresh, err)
	}
	raw, _ := t.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, Tokens{}, fmt.Errorf("%w: no ID token in the answer", ErrNoRefresh)
	}
	tok, err := c.verifier.Verify(c.ctx(ctx), raw)
	if err != nil {
		return Identity{}, Tokens{}, fmt.Errorf("%w: %v", ErrNoRefresh, err)
	}
	if tok.Subject != subject {
		return Identity{}, Tokens{}, fmt.Errorf("%w: the token is for another subject", ErrNoRefresh)
	}
	id, err := c.identity(tok)
	if err != nil {
		return Identity{}, Tokens{}, err
	}
	return id, c.tokens(t, raw, tok.Expiry, old), nil
}

// LogoutURL returns where to send the browser to end the provider's
// session too, or false when the provider has no such endpoint.
func (c *Client) LogoutURL(idToken, returnTo string) (string, bool) {
	if c.endSession == "" {
		return "", false
	}
	u, err := url.Parse(c.endSession)
	if err != nil {
		return "", false
	}
	q := u.Query()
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	q.Set("client_id", c.cfg.ClientID)
	if returnTo != "" {
		q.Set("post_logout_redirect_uri", returnTo)
	}
	u.RawQuery = q.Encode()
	return u.String(), true
}

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// VerifyLogoutToken validates a back-channel logout token and returns the
// subject and provider session it ends. A token is accepted once.
func (c *Client) VerifyLogoutToken(ctx context.Context, raw string) (subject, sessionID string, err error) {
	tok, err := c.verifier.Verify(c.ctx(ctx), raw)
	if err != nil {
		return "", "", fmt.Errorf("oidc: logout token: %w", err)
	}
	var claims struct {
		Events map[string]any `json:"events"`
		Nonce  *string        `json:"nonce"`
		SID    string         `json:"sid"`
		JTI    string         `json:"jti"`
	}
	if err := tok.Claims(&claims); err != nil {
		return "", "", err
	}
	if _, ok := claims.Events[backchannelEvent]; !ok {
		return "", "", errors.New("oidc: not a logout token")
	}
	if claims.Nonce != nil {
		return "", "", errors.New("oidc: a logout token must not carry a nonce")
	}
	if tok.Subject == "" && claims.SID == "" {
		return "", "", errors.New("oidc: the logout token names neither a subject nor a session")
	}
	if claims.JTI == "" {
		return "", "", errors.New("oidc: the logout token has no id")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for id, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, id)
		}
	}
	if _, used := c.seen[claims.JTI]; used {
		return "", "", errors.New("oidc: the logout token was already used")
	}
	c.seen[claims.JTI] = tok.Expiry
	return tok.Subject, claims.SID, nil
}
