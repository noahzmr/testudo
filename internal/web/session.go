package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/confapi"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/identity"
)

// consoleAccess reports whether a principal may use the console at all.
// Someone whose only permissions concern themselves (a VPN user) may not.
func consoleAccess(p identity.Principal) bool {
	for _, perm := range p.Permissions {
		if len(perm) < 5 || perm[:5] != "self:" {
			return true
		}
	}
	return false
}

// modelState returns the current configuration, or nil without a model.
func (s *Server) modelState() *confstore.State {
	if st := s.Engine.ConfigStore(); st != nil {
		return st.Current()
	}
	return nil
}

// startSession records a login and sets the session cookie. login is nil
// for users of the built-in store, whose role is fixed for the session.
func (s *Server) startSession(w http.ResponseWriter, p identity.Principal, login *identity.Login, tokens *oidcSession) {
	rec := &sessionRecord{user: p.Name, role: p.LegacyRole(), principal: p, login: login, oidc: tokens,
		expiresAt: time.Now().Add(sessionTTL)}
	if st := s.modelState(); st != nil {
		rec.index = st.Index()
	}
	sid := newSessionID()
	s.mu.Lock()
	s.sessions[sid] = rec
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.TLS.Enabled(),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
	})
}

// dropSessions ends every session the predicate selects and returns how
// many there were.
func (s *Server) dropSessions(match func(*sessionRecord) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for sid, rec := range s.sessions {
		if match(rec) {
			delete(s.sessions, sid)
			n++
		}
	}
	return n
}

// current keeps a session in step with the model: when the configuration
// changed since the principal was worked out, it is worked out again, so
// removing a role or disabling a user takes effect on the next request and
// not at the next login. It returns false when the session has to end.
func (s *Server) current(sid string, rec *sessionRecord) bool {
	if rec.login == nil {
		return true
	}
	st := s.modelState()
	if st == nil || st.Index() == rec.index {
		return true
	}
	p, err := identity.Resolve(st, *rec.login)
	if err != nil || !consoleAccess(p) {
		s.mu.Lock()
		delete(s.sessions, sid)
		s.mu.Unlock()
		s.Engine.Audit(rec.user, "session_end", `{"reason":"access withdrawn"}`, err)
		return false
	}
	s.mu.Lock()
	rec.principal, rec.role, rec.index = p, p.LegacyRole(), st.Index()
	s.mu.Unlock()
	return true
}

// tokenSession recognises a request that carries an API token and returns
// a one-request session for it, or nil. The token's own permissions apply,
// whatever its owner may do today.
func (s *Server) tokenSession(r *http.Request) *sessionRecord {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return nil
	}
	t, ok := confapi.FindToken(s.modelState(), strings.TrimSpace(h[7:]), time.Now())
	if !ok {
		return nil
	}
	p := identity.Principal{Name: t.Owner + "/" + t.Name, Source: identity.SourceToken, Permissions: t.Permissions}
	return &sessionRecord{user: p.Name, role: p.LegacyRole(), principal: p, expiresAt: time.Now().Add(time.Minute)}
}
