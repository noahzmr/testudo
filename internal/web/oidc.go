package web

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/oidcauth"
)

// oidcSession is what a session that began at the identity provider keeps:
// the tokens to refresh it and to log out, and the provider's own session id
// so the provider can end it.
type oidcSession struct {
	tokens    oidcauth.Tokens
	subject   string
	sessionID string
}

// oidcState is the server's side of the provider integration.
type oidcState struct {
	mu      sync.Mutex
	client  *oidcauth.Client
	version int64  // version of the provider object the client was built for
	id      string // its id
	flows   map[string]oidcauth.Flow
}

const (
	oidcFlowTTL  = 10 * time.Minute
	oidcMaxFlows = 1000
)

// clientIP is the address a request came from, for audit rows.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// oidcProvider returns the enabled provider object, or nil.
func (s *Server) oidcProvider() *model.OIDCProvider {
	st := s.modelState()
	if st == nil {
		return nil
	}
	for _, e := range st.List(model.KindOIDCProvider) {
		if p := e.(*model.OIDCProvider); p.Enabled {
			return p
		}
	}
	return nil
}

// oidcClient returns a client for the enabled provider. It is built on
// first use and again when the provider object changes. A provider that
// cannot be reached is an error here and never a reason to refuse the other
// ways to log in.
func (s *Server) oidcClient(ctx context.Context) (*oidcauth.Client, *model.OIDCProvider, error) {
	p := s.oidcProvider()
	if p == nil {
		return nil, nil, errors.New("no identity provider is configured")
	}
	o := &s.oidc
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client != nil && o.id == p.ID && o.version == p.Version {
		return o.client, p, nil
	}
	secret := ""
	if p.ClientSecretRef != "" {
		raw, err := s.Engine.Secret(p.ClientSecretRef)
		if err != nil {
			return nil, p, fmt.Errorf("the client secret is not on this node: %w", err)
		}
		secret = strings.TrimSpace(string(raw))
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := oidcauth.New(ctx, oidcauth.Config{Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: secret,
		RedirectURL: p.RedirectURL, Scopes: p.Scopes, UsernameClaim: p.UsernameClaim, GroupsClaim: p.GroupsClaim,
		SigningAlgs: p.SigningAlgs, HTTPClient: s.OIDCHTTPClient})
	if err != nil {
		return nil, p, err
	}
	o.client, o.id, o.version = c, p.ID, p.Version
	return c, p, nil
}

// loginError shows the login page with a message; the local login on it
// keeps working whatever happened at the provider.
func (s *Server) loginError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = s.loginTmpl.Execute(w, s.loginView(loginView{Error: msg}))
}

// handleOIDCLogin sends the browser to the provider.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.oidcClient(r.Context())
	if err != nil {
		log.Printf("oidc: %v", err)
		s.loginError(w, http.StatusBadGateway, "The identity provider cannot be reached. Local accounts still work.")
		return
	}
	flow, to := c.Start()
	o := &s.oidc
	o.mu.Lock()
	if o.flows == nil {
		o.flows = map[string]oidcauth.Flow{}
	}
	for state, f := range o.flows {
		if time.Since(f.Created) > oidcFlowTTL {
			delete(o.flows, state)
		}
	}
	full := len(o.flows) >= oidcMaxFlows
	if !full {
		o.flows[flow.State] = flow
	}
	o.mu.Unlock()
	if full {
		http.Error(w, "too many logins in progress; try again in a moment", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, to, http.StatusFound)
}

// handleOIDCCallback finishes a login the provider redirected back.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	o := &s.oidc
	o.mu.Lock()
	flow, ok := o.flows[q.Get("state")]
	delete(o.flows, q.Get("state")) // a state is good once
	o.mu.Unlock()
	if !ok || time.Since(flow.Created) > oidcFlowTTL {
		s.loginError(w, http.StatusBadRequest, "That login attempt is unknown or too old. Start again.")
		return
	}
	if e := q.Get("error"); e != "" {
		s.Engine.Audit("", "login", fmt.Sprintf(`{"source":"oidc","result":"denied","from":%q}`, clientIP(r)), errors.New(e))
		s.loginError(w, http.StatusUnauthorized, "The identity provider did not complete the login.")
		return
	}
	c, _, err := s.oidcClient(r.Context())
	if err != nil {
		s.loginError(w, http.StatusBadGateway, "The identity provider cannot be reached. Local accounts still work.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	id, tokens, err := c.Finish(ctx, flow, q.Get("code"))
	if err != nil {
		log.Printf("oidc: %v", err)
		s.Engine.Audit("", "login", fmt.Sprintf(`{"source":"oidc","result":"denied","from":%q}`, clientIP(r)), err)
		s.loginError(w, http.StatusUnauthorized, "The login could not be verified.")
		return
	}
	login := identity.Login{Source: identity.SourceOIDC, Username: id.Username, Subject: id.Subject, Groups: id.Groups}
	p, err := identity.Resolve(s.modelState(), login)
	if err == nil && !consoleAccess(p) {
		err = identity.ErrNoRole
	}
	if err != nil {
		s.Engine.Audit(id.Username, "login", fmt.Sprintf(`{"source":"oidc","result":"denied","subject":%q,"from":%q}`, id.Subject, clientIP(r)), err)
		msg := "Your account has no role on this system. Ask an administrator."
		if errors.Is(err, identity.ErrDisabled) {
			msg = "Your account is disabled."
		}
		s.loginError(w, http.StatusForbidden, msg)
		return
	}
	s.startSession(w, p, &login, &oidcSession{tokens: tokens, subject: id.Subject, sessionID: id.SessionID})
	s.Engine.Audit(p.Name, "login", fmt.Sprintf(`{"source":"oidc","subject":%q,"role":%q,"from":%q}`, id.Subject, p.LegacyRole(), clientIP(r)), nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// oidcFresh extends a provider session whose tokens ran out. When the
// provider no longer vouches for it the session ends. Sessions that did not
// begin at the provider are always fresh.
func (s *Server) oidcFresh(ctx context.Context, sid string, rec *sessionRecord) bool {
	s.mu.RLock()
	o := rec.oidc
	due := o != nil && time.Now().After(o.tokens.Expiry)
	s.mu.RUnlock()
	if !due {
		return true
	}
	end := func(err error) bool {
		s.mu.Lock()
		delete(s.sessions, sid)
		s.mu.Unlock()
		s.Engine.Audit(rec.user, "session_end", `{"reason":"the identity provider did not renew the session"}`, err)
		return false
	}
	c, _, err := s.oidcClient(ctx)
	if err != nil {
		return end(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	id, tokens, err := c.Refresh(ctx, o.tokens, o.subject)
	if err != nil {
		return end(err)
	}
	login := identity.Login{Source: identity.SourceOIDC, Username: id.Username, Subject: id.Subject, Groups: id.Groups}
	p, err := identity.Resolve(s.modelState(), login)
	if err != nil || !consoleAccess(p) {
		return end(err)
	}
	s.mu.Lock()
	rec.oidc = &oidcSession{tokens: tokens, subject: id.Subject, sessionID: o.sessionID}
	rec.login, rec.principal, rec.role = &login, p, p.LegacyRole()
	s.mu.Unlock()
	return true
}

// oidcLogoutURL returns where the browser should go to end the provider's
// session after the local one is gone, or "".
func (s *Server) oidcLogoutURL(ctx context.Context, rec *sessionRecord) string {
	if rec == nil || rec.oidc == nil {
		return ""
	}
	c, p, err := s.oidcClient(ctx)
	if err != nil {
		return ""
	}
	back := ""
	if u, err := url.Parse(p.RedirectURL); err == nil {
		back = u.Scheme + "://" + u.Host + "/login"
	}
	to, _ := c.LogoutURL(rec.oidc.tokens.IDToken, back)
	return to
}

// handleOIDCBackchannelLogout ends the sessions a logout token from the
// provider names. The provider calls it server to server; the token's
// signature is the authentication.
func (s *Server) handleOIDCBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	c, _, err := s.oidcClient(r.Context())
	if err != nil {
		http.Error(w, "no identity provider", http.StatusBadRequest)
		return
	}
	sub, sid, err := c.VerifyLogoutToken(r.Context(), r.PostForm.Get("logout_token"))
	if err != nil {
		log.Printf("oidc: %v", err)
		http.Error(w, "invalid logout token", http.StatusBadRequest)
		return
	}
	n := s.dropSessions(func(rec *sessionRecord) bool {
		if rec.oidc == nil {
			return false
		}
		if sid != "" {
			return rec.oidc.sessionID == sid
		}
		return rec.oidc.subject == sub
	})
	s.Engine.Audit("", "logout", fmt.Sprintf(`{"source":"oidc","by":"provider","subject":%q,"sessions":%d}`, sub, n), nil)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}
