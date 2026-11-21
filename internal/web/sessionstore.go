package web

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/oidcauth"
)

// Sessions, and the tickets and grants of published services, are kept in
// the node's secret store, which a cluster replicates (sealed with the
// cluster's key) to every member: a login on one member is good on all of
// them, and a logout or an ended session is over everywhere. The store keeps
// what was proven at the login, never a password; each member works out
// from the model what the session may do.

// kvStore is the part of the secret store the sessions use.
type kvStore interface {
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Delete(name string) error
	Has(name string) bool
	List() ([]string, error)
}

// Entry name prefixes in the secret store.
const (
	sessionEntry = "session-"
	ticketEntry  = "access-t-"
	grantEntry   = "access-g-"
)

// shared is a small key-value store on top of the secret store, or in
// memory when there is none.
type shared struct {
	sec kvStore
	// local takes a write the replicated store refused: a member cut off
	// from its cluster keeps working for whoever logs in on it.
	local kvStore

	mu  sync.Mutex
	mem map[string][]byte
}

func (s *shared) put(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if s.sec != nil {
		err := s.sec.Put(name, b)
		if err != nil && s.local != nil {
			err = s.local.Put(name, b)
		}
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mem == nil {
		s.mem = map[string][]byte{}
	}
	s.mem[name] = b
	return nil
}

func (s *shared) get(name string, out any) bool {
	var b []byte
	if s.sec != nil {
		var err error
		if b, err = s.sec.Get(name); err != nil {
			return false
		}
	} else {
		s.mu.Lock()
		b = s.mem[name]
		s.mu.Unlock()
		if b == nil {
			return false
		}
	}
	return json.Unmarshal(b, out) == nil
}

func (s *shared) has(name string) bool {
	if s.sec != nil {
		return s.sec.Has(name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.mem[name]
	return ok
}

func (s *shared) del(name string) {
	if s.sec != nil {
		if s.sec.Has(name) {
			if err := s.sec.Delete(name); err != nil && s.local != nil {
				_ = s.local.Delete(name)
			}
		}
		return
	}
	s.mu.Lock()
	delete(s.mem, name)
	s.mu.Unlock()
}

func (s *shared) names(prefix string) []string {
	var all []string
	if s.sec != nil {
		all, _ = s.sec.List()
	} else {
		s.mu.Lock()
		for n := range s.mem {
			all = append(all, n)
		}
		s.mu.Unlock()
	}
	var out []string
	for _, n := range all {
		if strings.HasPrefix(n, prefix) {
			out = append(out, n)
		}
	}
	return out
}

// sessionDoc is a session as it is stored.
type sessionDoc struct {
	User    string          `json:"user"`
	Expires time.Time       `json:"expires"`
	Login   *identity.Login `json:"login,omitempty"`
	OIDC    *oidcDoc        `json:"oidc,omitempty"`
}

type oidcDoc struct {
	Tokens    oidcauth.Tokens `json:"tokens"`
	Subject   string          `json:"subject"`
	SessionID string          `json:"session_id,omitempty"`
}

func docOf(rec *sessionRecord) sessionDoc {
	d := sessionDoc{User: rec.user, Expires: rec.expiresAt, Login: rec.login}
	if o := rec.oidc; o != nil {
		d.OIDC = &oidcDoc{Tokens: o.tokens, Subject: o.subject, SessionID: o.sessionID}
	}
	return d
}

// saveSession stores a session and keeps it in the member's cache.
func (s *Server) saveSession(sid string, rec *sessionRecord) error {
	s.mu.Lock()
	d := docOf(rec)
	s.sessions[sid] = rec
	s.mu.Unlock()
	return s.shared.put(sessionEntry+sid, d)
}

// loadSession returns a session that exists in the store, from the cache or
// worked out again from the stored login. A session another member ended
// is gone here too.
func (s *Server) loadSession(sid string) *sessionRecord {
	if !validEntryID(sid) {
		return nil
	}
	name := sessionEntry + sid
	if !s.shared.has(name) {
		s.mu.Lock()
		delete(s.sessions, sid)
		s.mu.Unlock()
		return nil
	}
	s.mu.RLock()
	rec, ok := s.sessions[sid]
	s.mu.RUnlock()
	if ok {
		return rec
	}
	var d sessionDoc
	if !s.shared.get(name, &d) || d.Login == nil || time.Now().After(d.Expires) {
		return nil
	}
	st := s.modelState()
	p, err := identity.Resolve(st, *d.Login)
	if err != nil || !consoleAccess(p) {
		return nil
	}
	rec = &sessionRecord{user: d.User, role: p.LegacyRole(), principal: p, login: d.Login, expiresAt: d.Expires}
	if st != nil {
		rec.index = st.Index()
	}
	if o := d.OIDC; o != nil {
		rec.oidc = &oidcSession{tokens: o.Tokens, subject: o.Subject, sessionID: o.SessionID}
	}
	s.mu.Lock()
	s.sessions[sid] = rec
	s.mu.Unlock()
	return rec
}

// endSession ends a session everywhere, with the grants that hang on it.
func (s *Server) endSession(sid string) {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
	s.shared.del(sessionEntry + sid)
	s.dropAccess(sid)
}

// eachSession calls fn for every stored session, loaded.
func (s *Server) eachSession(fn func(sid string, rec *sessionRecord)) {
	for _, name := range s.shared.names(sessionEntry) {
		sid := strings.TrimPrefix(name, sessionEntry)
		if rec := s.loadSession(sid); rec != nil {
			fn(sid, rec)
		}
	}
}

// gcShared removes expired sessions, tickets and grants. In a cluster one
// member does it for all (leads reports whether this one should).
func (s *Server) gcShared(leads bool) {
	now := time.Now()
	s.mu.Lock()
	for sid, rec := range s.sessions {
		if now.After(rec.expiresAt) {
			delete(s.sessions, sid)
		}
	}
	s.mu.Unlock()
	if !leads {
		return
	}
	for _, prefix := range []string{sessionEntry, ticketEntry, grantEntry} {
		for _, name := range s.shared.names(prefix) {
			var d struct {
				Expires time.Time `json:"expires"`
			}
			if !s.shared.get(name, &d) || now.After(d.Expires) {
				s.shared.del(name)
			}
		}
	}
}
