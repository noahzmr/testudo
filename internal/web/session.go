package web

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/confapi"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/netops"
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
	if s.Engine == nil {
		return nil
	}
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
	if err := s.saveSession(sid, rec); err != nil {
		log.Printf("web: storing the session of %s: %v", p.Name, err)
	}
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
	n := 0
	s.eachSession(func(sid string, rec *sessionRecord) {
		if match(rec) {
			s.endSession(sid)
			n++
		}
	})
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
		s.endSession(sid)
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

// Failed logins are counted per address. After loginMaxFailures within
// loginWindow further attempts from that address are refused until the
// window has passed; this bounds password guessing through this page
// whatever the PAM stack itself does about it.
const (
	loginMaxFailures = 10
	loginWindow      = 5 * time.Minute
)

type loginLimiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func (l *loginLimiter) recent(addr string, now time.Time) []time.Time {
	kept := l.fails[addr][:0]
	for _, t := range l.fails[addr] {
		if now.Sub(t) < loginWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.fails, addr)
	} else {
		l.fails[addr] = kept
	}
	return kept
}

func (s *Server) loginAllowed(addr string) bool {
	l := &s.logins
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(addr, time.Now())) < loginMaxFailures
}

func (s *Server) loginFailed(addr string) {
	l := &s.logins
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		l.fails = map[string][]time.Time{}
	}
	// Bound the table itself: forget the oldest addresses first.
	if len(l.fails) > 10000 {
		for a := range l.fails {
			l.recent(a, time.Now())
		}
	}
	l.fails[addr] = append(l.fails[addr], time.Now())
}

// pamLogin authenticates against the host's PAM stack. Who someone is comes
// from the host; what they may do comes from the model, or from the
// break-glass group.
func (s *Server) pamLogin(w http.ResponseWriter, r *http.Request, user, pass, code string) {
	from := clientIP(r)
	deny := func(status int, view loginView, err error) {
		s.Engine.Audit(user, "login", fmt.Sprintf(`{"source":"pam","result":"denied","from":%q}`, from), err)
		w.WriteHeader(status)
		view.Username = user
		_ = s.loginTmpl.Execute(w, s.loginView(view))
	}
	res, err := s.Engine.PAMLogin(user, pass, code, from)
	if err != nil {
		deny(http.StatusBadGateway, loginView{Error: "the login service of this host cannot be reached"}, err)
		return
	}
	if !res.OK {
		switch res.Reason {
		case netops.PAMNeedCode:
			deny(http.StatusUnauthorized, loginView{Error: "enter your one-time code", NeedCode: true}, errors.New("one-time code required"))
		case netops.PAMAccount:
			s.loginFailed(from)
			deny(http.StatusForbidden, loginView{Error: "this account cannot log in: " + res.Detail}, errors.New(res.Detail))
		default:
			s.loginFailed(from)
			deny(http.StatusUnauthorized, loginView{Error: "invalid credentials"}, errors.New("invalid credentials"))
		}
		return
	}
	login := identity.Login{Source: identity.SourcePAM, Username: res.User, Groups: res.Groups}
	p, err := identity.Resolve(s.modelState(), login)
	if err == nil && !consoleAccess(p) {
		err = identity.ErrNoRole
	}
	if err != nil {
		msg := "your account has no role on this system; ask an administrator"
		if errors.Is(err, identity.ErrDisabled) {
			msg = "account disabled"
		}
		deny(http.StatusForbidden, loginView{Error: msg}, err)
		return
	}
	s.startSession(w, p, &login, nil)
	s.Engine.Audit(p.Name, "login", fmt.Sprintf(`{"source":"pam","role":%q,"break_glass":%v,"from":%q}`, p.LegacyRole(), p.BreakGlass, from), nil)
	http.Redirect(w, r, s.afterLogin(w, r), http.StatusSeeOther)
}
