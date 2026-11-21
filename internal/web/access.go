package web

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/model"
)

// Access to published services. A load-balancer router can require a login
// and membership in a group. The proxy asks this program about every
// request to such a router (forward authentication, on loopback), and this
// file is the answer.
//
// A visitor without access is sent to the console to log in, by whichever
// way they normally do. The console then hands the browser a ticket for
// the service's host name; presenting it there sets a cookie for that host.
// The cookie is only a reference: what it refers to is the visitor's
// console session, so logging out, losing the group or being disabled
// closes the published service at the next request.

const (
	accessCookie = "testudo_access"
	ticketParam  = "testudo_ticket"
	ticketTTL    = time.Minute
	nextCookie   = "testudo_next"
)

// accessPass is a ticket (good once, for a minute) or a grant (the cookie
// of a published service, for as long as the console session lasts). Both
// are stored for every member: the console that hands out a ticket and the
// proxy that takes it may run on different members.
type accessPass struct {
	SID     string    `json:"sid"`
	Host    string    `json:"host"`
	Expires time.Time `json:"expires"`
}

// consoleURL is the address people reach this console at: the configured
// one, or the one the identity provider redirects back to.
func (s *Server) consoleURL() string {
	if s.PublicURL != "" {
		return strings.TrimRight(s.PublicURL, "/")
	}
	if p := s.oidcProvider(); p != nil {
		if u, err := url.Parse(p.RedirectURL); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

// protectedHost reports whether an enabled router that requires a login
// serves the host. Tickets are only made for such hosts, so the login page
// cannot be used to send a browser somewhere else.
func (s *Server) protectedHost(host string) bool {
	st := s.modelState()
	if st == nil {
		return false
	}
	host = hostOnly(host)
	for _, e := range st.List(model.KindLBRouter) {
		rt := e.(*model.LBRouter)
		if !rt.Enabled || len(rt.RequireGroups) == 0 {
			continue
		}
		for _, name := range rt.Hosts {
			name = strings.ToLower(name)
			if rest, ok := strings.CutPrefix(name, "*."); ok {
				if strings.HasSuffix(host, "."+rest) {
					return true
				}
			} else if name == host {
				return true
			}
		}
	}
	return false
}

// liveSession returns the console session with the given id when it is
// still good, brought up to date with the model and the provider.
func (s *Server) liveSession(r *http.Request, sid string) *sessionRecord {
	rec := s.loadSession(sid)
	if rec == nil || time.Now().After(rec.expiresAt) {
		return nil
	}
	if !s.current(sid, rec) || !s.oidcFresh(r.Context(), sid, rec) {
		return nil
	}
	return rec
}

// handleForwardAuth answers the proxy: 2xx lets the request through, and
// anything else is sent to the visitor as it is.
func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	proto := r.Header.Get("X-Forwarded-Proto")
	uri := r.Header.Get("X-Forwarded-Uri")
	if host == "" || !strings.HasPrefix(uri, "/") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if proto != "https" {
		proto = "http"
	}
	required := map[string]bool{}
	for _, g := range strings.Split(r.URL.Query().Get("groups"), ",") {
		if g != "" {
			required[g] = true
		}
	}
	// A visitor coming back from the console with a ticket.
	if u, err := url.ParseRequestURI(uri); err == nil && u.Query().Get(ticketParam) != "" {
		q := u.Query()
		ticket := q.Get(ticketParam)
		q.Del(ticketParam)
		u.RawQuery = q.Encode()
		var t accessPass
		ok := validEntryID(ticket) && s.shared.get(ticketEntry+ticket, &t)
		if ok {
			s.shared.del(ticketEntry + ticket) // a ticket is good once
		}
		if ok && time.Now().Before(t.Expires) && t.Host == hostOnly(host) {
			id := newSessionID()
			expires := time.Now().Add(sessionTTL)
			if rec := s.loadSession(t.SID); rec != nil {
				expires = rec.expiresAt
			}
			_ = s.shared.put(grantEntry+id, accessPass{SID: t.SID, Host: t.Host, Expires: expires})
			http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: id, Path: "/", HttpOnly: true,
				Secure: proto == "https", SameSite: http.SameSiteLaxMode})
			// Absolute: the proxy would resolve a relative address against
			// this listener's own.
			http.Redirect(w, r, proto+"://"+host+u.RequestURI(), http.StatusFound)
			return
		}
		uri = u.RequestURI() // fall through and ask for a login again
	}

	if c, err := r.Cookie(accessCookie); err == nil && validEntryID(c.Value) {
		var g accessPass
		if s.shared.get(grantEntry+c.Value, &g) && g.Host == hostOnly(host) {
			if rec := s.liveSession(r, g.SID); rec != nil {
				for _, id := range rec.principal.Groups {
					if required[id] {
						w.Header().Set("X-Forwarded-User", rec.user)
						w.WriteHeader(http.StatusOK)
						return
					}
				}
				s.Engine.Audit(rec.user, "access_denied", fmt.Sprintf(`{"host":%q,"reason":"not in a required group"}`, hostOnly(host)), nil)
				http.Error(w, "You are logged in as "+rec.user+", and this service is not open to you.", http.StatusForbidden)
				return
			}
			s.shared.del(grantEntry + c.Value)
		}
	}

	console := s.consoleURL()
	if console == "" || (r.Header.Get("X-Forwarded-Method") != "" && r.Header.Get("X-Forwarded-Method") != http.MethodGet) {
		// Nowhere to send the visitor, or not a page load: refuse plainly.
		http.Error(w, "This service requires a login.", http.StatusUnauthorized)
		return
	}
	to := console + "/access/login?" + url.Values{"host": {host}, "proto": {proto}, "rd": {uri}}.Encode()
	http.Redirect(w, r, to, http.StatusFound)
}

// handleAccessLogin runs on the console, with a session: it hands the
// browser a ticket for the service it came from.
func (s *Server) handleAccessLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host, proto, rd := q.Get("host"), q.Get("proto"), q.Get("rd")
	if proto != "https" {
		proto = "http"
	}
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || !s.protectedHost(host) {
		http.Error(w, "unknown service", http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil || s.liveSession(r, c.Value) == nil {
		// Log in first, then come back here.
		http.SetCookie(w, &http.Cookie{Name: nextCookie, Value: url.QueryEscape(r.URL.RequestURI()), Path: "/", HttpOnly: true,
			Secure: s.TLS.Enabled(), SameSite: http.SameSiteLaxMode, MaxAge: 600})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ticket := newSessionID()
	if err := s.shared.put(ticketEntry+ticket, accessPass{SID: c.Value, Host: hostOnly(host), Expires: time.Now().Add(ticketTTL)}); err != nil {
		http.Error(w, "the ticket could not be stored", http.StatusServiceUnavailable)
		return
	}
	u, err := url.ParseRequestURI(rd)
	if err != nil {
		http.Error(w, "unknown service", http.StatusBadRequest)
		return
	}
	qq := u.Query()
	qq.Set(ticketParam, ticket)
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, proto+"://"+host+u.RequestURI(), http.StatusFound)
}

// afterLogin is where a fresh login goes: back to the service that asked
// for it, or to the console.
func (s *Server) afterLogin(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(nextCookie)
	if err != nil {
		return "/"
	}
	http.SetCookie(w, &http.Cookie{Name: nextCookie, Value: "", Path: "/", MaxAge: -1})
	next, err := url.QueryUnescape(c.Value)
	if err != nil || !strings.HasPrefix(next, "/access/login?") {
		return "/"
	}
	return next
}

// dropAccess forgets the grants that hang on a console session.
func (s *Server) dropAccess(sid string) {
	for _, name := range s.shared.names(grantEntry) {
		var g accessPass
		if !s.shared.get(name, &g) || g.SID == sid {
			s.shared.del(name)
		}
	}
}

// validEntryID accepts what newSessionID makes, so a cookie or a ticket
// from a visitor cannot name anything else in the secret store.
func validEntryID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
