// Package web implements the optional HTTP UI. It mirrors the TUI views
// (Dashboard, Flows, Devices, Interfaces, Routes, Firewall, NAT, Alerts,
// Settings) as a single-page app served from embedded assets. Auth is
// session-cookie based; credentials live in the auth package.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/localauth"
	"github.com/noahzmr/testudo/internal/netops"
)

//go:embed assets
var assetsFS embed.FS

// Server is the HTTP UI. Build one per process and call ListenAndServe.
type Server struct {
	Engine *engine.Engine
	Addr   string
	// TLS selects HTTPS (operator cert or auto self-signed). Zero = plain HTTP.
	TLS TLSConfig
	// Issuer is the label authenticator apps show for TOTP enrollments.
	Issuer string

	loginTmpl *template.Template
	mux       *http.ServeMux
	static    *staticSet
	index     *staticAsset // index.html with versioned asset URLs

	mu sync.RWMutex
	// sessions caches the sessions this member has seen; shared holds them
	// for every member.
	sessions map[string]*sessionRecord
	shared   *shared

	// PublicURL is the address people reach this console at, for sending
	// visitors of published services here to log in. Empty uses the
	// address the identity provider redirects to.
	PublicURL string
	// ControlSocket is the path of the control socket for the command line;
	// "" serves none.
	ControlSocket string

	// logins counts failed logins per address.
	logins loginLimiter

	// oidc is the identity-provider integration; OIDCHTTPClient replaces
	// the HTTP client used towards the provider (tests, private CAs).
	oidc           oidcState
	OIDCHTTPClient *http.Client

	// stopping is closed when the server shuts down; long-lived responses
	// (the configuration event stream, the live views) end on it.
	stopping <-chan struct{}

	// live pushes the console's snapshot to every open console.
	live *liveHub
}

// sessionRecord is one logged-in browser. The role is captured at login so a
// demotion takes effect on the next login, not mid-session (the admin can
// disable the account to cut a live session).
type sessionRecord struct {
	user      string
	role      auth.Role
	expiresAt time.Time
	// principal is what the caller may do. For logins the model decides
	// about, login and index let it be worked out again when the model
	// changes; oidc holds the provider's tokens of such a session.
	principal identity.Principal
	login     *identity.Login
	index     int64
	oidc      *oidcSession
}

const (
	sessionCookieName = "testudo_sid"
	sessionTTL        = 8 * time.Hour
)

// ctxKey keys the session record in the request context.
type ctxKey int

const sessionCtxKey ctxKey = 1

// actorFrom returns the logged-in user name for audit rows ("" when unknown).
func actorFrom(r *http.Request) string {
	if rec, ok := r.Context().Value(sessionCtxKey).(*sessionRecord); ok && rec != nil {
		return rec.user
	}
	return ""
}

// roleFrom returns the logged-in user's role (viewer when unknown).
func roleFrom(r *http.Request) auth.Role {
	if rec, ok := r.Context().Value(sessionCtxKey).(*sessionRecord); ok && rec != nil {
		return rec.role
	}
	return auth.RoleViewer
}

// netops returns the engine's netops writer stamped with the request's actor
// so every kernel mutation this request triggers carries the human in its
// audit row. nil when netops is unavailable (callers check as before).
func (s *Server) netops(r *http.Request) *netops.Writer {
	return s.Engine.Netops().WithActor(actorFrom(r))
}

// New constructs an unstarted Server. Mux is built lazily on first ListenAndServe.
func New(eng *engine.Engine, addr string) *Server {
	srv := &Server{
		Engine: eng, Addr: addr, Issuer: "Testudo",
		sessions: make(map[string]*sessionRecord),
		shared:   &shared{},
	}
	srv.live = newLiveHub(srv)
	if eng != nil {
		if sec, ok := eng.SessionStore(); ok {
			srv.shared.sec, srv.shared.local = sec, sec.Local()
		}
	}
	return srv
}

func (s *Server) buildMux() error {
	mux := http.NewServeMux()

	staticFS, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return fmt.Errorf("sub assets: %w", err)
	}
	s.static, err = newStaticSet(staticFS)
	if err != nil {
		return fmt.Errorf("prepare assets: %w", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static", s.static))

	// The two pages reference assets by content hash (see staticSet).
	indexBytes, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		return fmt.Errorf("read index.html: %w", err)
	}
	s.index = &staticAsset{body: s.static.Version(indexBytes), ctype: "text/html; charset=utf-8"}
	sum := sha256.Sum256(s.index.body)
	s.index.hash = hex.EncodeToString(sum[:])[:12]
	if s.index.gz, err = gzipBytes(s.index.body); err != nil {
		return fmt.Errorf("gzip index.html: %w", err)
	}

	loginBytes, err := assetsFS.ReadFile("assets/login.html")
	if err != nil {
		return fmt.Errorf("read login.html: %w", err)
	}
	t, err := template.New("login").Parse(string(s.static.Version(loginBytes)))
	if err != nil {
		return fmt.Errorf("parse login.html: %w", err)
	}
	s.loginTmpl = t

	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/access/login", s.handleAccessLogin)
	s.Engine.SetForwardAuth(http.HandlerFunc(s.handleForwardAuth))
	mux.HandleFunc("/auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("/auth/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/auth/oidc/backchannel-logout", s.handleOIDCBackchannelLogout)
	mux.HandleFunc("/api/me", s.protect(s.handleMe))
	mux.HandleFunc("/api/me/passwd", s.protect(s.handleMePasswd))
	mux.HandleFunc("/api/me/totp/enroll", s.protect(s.handleMeTOTPEnroll))
	mux.HandleFunc("/api/me/totp/disable", s.protect(s.handleMeTOTPDisable))

	// User management (admin only - see adminOnly).

	// Privileged access: JIT grants compiled into firewall rules for the
	// requester's WireGuard peers. See internal/pam and docs/pam.md.
	mux.HandleFunc("/api/pam", s.protect(s.handlePAM))
	mux.HandleFunc("/api/pam/request", s.protect(s.handlePAMRequest))
	mux.HandleFunc("/api/pam/approve", s.protect(s.handlePAMApprove))
	mux.HandleFunc("/api/pam/deny", s.protect(s.handlePAMDeny))
	mux.HandleFunc("/api/pam/revoke", s.protect(s.handlePAMRevoke))
	mux.HandleFunc("/api/pam/breakglass", s.protect(s.handlePAMBreakGlass))
	mux.HandleFunc("/api/pam/ssh/cert", s.protect(s.handlePAMSSHCert))

	mux.HandleFunc("/api/snapshot", s.protect(s.handleSnapshot))
	mux.HandleFunc("/api/live", s.protect(s.handleLive))
	mux.HandleFunc("/api/settings", s.protect(s.handleSettings))
	mux.HandleFunc("/api/baseline/reset", s.protect(s.handleBaselineReset))
	mux.HandleFunc("/api/probe", s.protect(s.handleProbe))
	mux.HandleFunc("/api/sessions", s.protect(s.handleSessions))
	mux.HandleFunc("/api/session/detail", s.protect(s.handleSessionDetail))
	mux.HandleFunc("/api/session/snapshot", s.protect(s.handleSnapshotPayload))

	// Capture
	mux.HandleFunc("/api/capture/start", s.protect(s.handleCaptureStart))
	mux.HandleFunc("/api/capture/stop", s.protect(s.handleCaptureStop))
	mux.HandleFunc("/api/capture/clear", s.protect(s.handleCaptureClear))

	// Interfaces

	// Routes

	// Firewall / NAT: rules are model objects; these show the running state.
	mux.HandleFunc("/api/firewall/reset-counter", s.protect(s.handleFirewallResetCounter))
	mux.HandleFunc("/api/firewall/view", s.protect(s.handleFirewallView))
	mux.HandleFunc("/api/firewall/rendered", s.protect(s.handleFirewallRendered))
	mux.HandleFunc("/api/conntrack/flush", s.protect(s.handleConntrackFlush))

	// TCPDump
	mux.HandleFunc("/api/tcpdump/start", s.protect(s.handleTCPDumpStart))
	mux.HandleFunc("/api/tcpdump/stop", s.protect(s.handleTCPDumpStop))
	mux.HandleFunc("/api/tcpdump/remove", s.protect(s.handleTCPDumpRemove))

	// Device connect launchpad
	mux.HandleFunc("/api/device/scan", s.protect(s.handleDeviceScan))
	mux.HandleFunc("/api/device/nmap-scan", s.protect(s.handleDeviceNmapScan))
	mux.HandleFunc("/api/connect", s.protect(s.handleConnect))

	// MaxMind GeoIP enrichment lookup: GET /api/ip/{addr}
	mux.HandleFunc("/api/ip/", s.protect(s.handleIPLookup))

	if err := s.mountConfig(mux); err != nil {
		return err
	}

	mux.HandleFunc("/", s.protect(s.handleRoot))

	s.mux = mux
	return nil
}

// ListenAndServe blocks until ctx is cancelled or the server errors. With TLS
// configured it serves HTTPS (TLS 1.2+); a self-signed certificate is
// generated on first use when TLS.Auto is set and its fingerprint logged so
// the operator can pin it.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.stopping = ctx.Done()
	if err := s.buildMux(); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.Addr,
		Handler:           s.withTransport(s.mux),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	cert, key, err := s.TLS.resolve()
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	errCh := make(chan error, 1)
	if cert != "" {
		if fp := certFingerprint(cert); fp != "" {
			log.Printf("web: serving HTTPS on %s, certificate SHA-256 %s", s.Addr, fp)
		}
		go func() { errCh <- srv.ListenAndServeTLS(cert, key) }()
	} else {
		go func() { errCh <- srv.ListenAndServe() }()
	}

	go s.gcSessionsLoop(ctx)
	if s.ControlSocket != "" {
		go s.serveControl(ctx, s.ControlSocket)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// ---- auth helpers ----

// adminOnly lists the mutation endpoints that change who may do what or the
// security posture of the host itself; operators cannot touch them.
var adminOnly = []string{
	"/api/settings",
	"/api/pam/breakglass",
}

// approverOnly lists the endpoints that decide on access requests. They are
// open to approvers and admins - not to operators, even though operators
// outrank approvers for everything else (separation of duties).
var approverOnly = []string{"/api/pam/approve", "/api/pam/deny"}

// selfService lists the mutation endpoints every logged-in role may call about
// their own account.
var selfService = []string{"/api/me/passwd", "/api/me/totp/enroll", "/api/me/totp/disable"}

// protect authenticates the session, rejects cross-origin mutations, enforces
// the role the endpoint needs, and attaches the session to the request
// context so handlers can name the actor in audit rows.
//
// Role model: GET is open to every role (viewer+); mutations need operator+,
// the adminOnly paths need admin, the selfService paths need only a login.
func (s *Server) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := s.session(r)
		if rec == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !sameOrigin(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			if hasPrefixAny(r.URL.Path, approverOnly) {
				if !rec.role.CanApprove() {
					http.Error(w, fmt.Sprintf("requires role approver or admin (you are %s)", rec.role), http.StatusForbidden)
					return
				}
			} else {
				min := auth.RoleOperator
				switch {
				case hasPrefixAny(r.URL.Path, selfService):
					min = auth.RoleViewer
				case hasPrefixAny(r.URL.Path, adminOnly):
					min = auth.RoleAdmin
				}
				if !rec.role.AtLeast(min) {
					http.Error(w, fmt.Sprintf("requires role %s (you are %s)", min, rec.role), http.StatusForbidden)
					return
				}
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, rec)))
	}
}

func hasPrefixAny(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// sameOrigin is the CSRF guard for state-changing requests: browsers always
// send Origin (and Sec-Fetch-Site) on cross-site POSTs, so a mismatch means a
// foreign page is driving the session. Requests without either header (curl,
// scripts holding a session cookie) pass - the cookie is SameSite=Lax too.
func sameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		return false
	}
	return true
}

// session returns the live session for the request, or nil.
func (s *Server) session(r *http.Request) *sessionRecord {
	if rec := controlSession(r); rec != nil {
		return rec
	}
	if rec := s.tokenSession(r); rec != nil {
		return rec
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	rec := s.loadSession(c.Value)
	if rec == nil || time.Now().After(rec.expiresAt) {
		return nil
	}
	if !s.current(c.Value, rec) || !s.oidcFresh(r.Context(), c.Value, rec) {
		return nil
	}
	return rec
}

func (s *Server) authed(r *http.Request) bool { return s.session(r) != nil }

// loginView is the login template's data.
type loginView struct {
	Error    string
	Username string
	NeedCode bool
	// Provider is the name of the identity provider when one is enabled.
	Provider string
}

// loginView fills in what every rendering of the login page shows.
func (s *Server) loginView(v loginView) loginView {
	if p := s.oidcProvider(); p != nil {
		v.Provider = p.Name
	}
	return v
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = s.loginTmpl.Execute(w, s.loginView(loginView{}))
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		code := r.FormValue("code")
		from := clientIP(r)
		if !s.loginAllowed(from) {
			s.Engine.Audit(user, "login", fmt.Sprintf(`{"result":"throttled","from":%q}`, from), errors.New("too many failed logins"))
			w.WriteHeader(http.StatusTooManyRequests)
			_ = s.loginTmpl.Execute(w, s.loginView(loginView{Error: "too many failed attempts; wait a few minutes", Username: user}))
			return
		}
		// A local user of the model logs in with the password Testudo
		// keeps; every other name is the host's (PAM).
		st := s.modelState()
		if localauth.Find(st, user) == nil && netops.PAMAvailable() {
			s.pamLogin(w, r, user, pass, code)
			return
		}
		sec := s.Engine.LocalSecrets()
		u, err := localauth.Authenticate(st, sec, user, pass, code, time.Now())
		var p identity.Principal
		login := identity.Login{Source: identity.SourceLocal, Username: user}
		if err == nil {
			p, err = identity.Resolve(st, login)
			if err == nil && !consoleAccess(p) {
				err = identity.ErrNoRole
			}
		}
		if err != nil {
			if !errors.Is(err, localauth.ErrTOTPRequired) {
				s.loginFailed(from)
			}
			s.Engine.Audit(user, "login", fmt.Sprintf(`{"source":"local","result":"denied","from":%q}`, from), err)
			status, view := http.StatusUnauthorized, loginView{Error: "invalid credentials", Username: user}
			switch {
			case errors.Is(err, localauth.ErrTOTPRequired):
				view.Error, view.NeedCode = "enter the one-time code from your authenticator", true
			case errors.Is(err, localauth.ErrDisabled), errors.Is(err, identity.ErrDisabled):
				view.Error = "account disabled"
			case errors.Is(err, identity.ErrNoRole):
				status, view.Error = http.StatusForbidden, "your account has no role on this system; ask an administrator"
			}
			w.WriteHeader(status)
			_ = s.loginTmpl.Execute(w, s.loginView(view))
			return
		}
		s.startSession(w, p, &login, nil)
		s.Engine.Audit(u.Username, "login", fmt.Sprintf(`{"source":"local","role":%q,"mfa":%v,"from":%q}`, p.LegacyRole(), localauth.MFAEnrolled(sec, u.ID), from), nil)
		http.Redirect(w, r, s.afterLogin(w, r), http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMe tells the page who is logged in and what they may do.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	rec := r.Context().Value(sessionCtxKey).(*sessionRecord)
	mfa := false
	if rec.principal.Source == identity.SourceLocal {
		if u := localauth.Find(s.modelState(), rec.user); u != nil {
			mfa = localauth.MFAEnrolled(s.Engine.LocalSecrets(), u.ID)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user":         rec.user,
		"role":         rec.role,
		"source":       rec.principal.Source,
		"permissions":  rec.principal.Permissions,
		"break_glass":  rec.principal.BreakGlass,
		"mfa_enrolled": mfa,
		"can_approve":  rec.role.CanApprove(),
		"tls":          s.TLS.Enabled(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var rec *sessionRecord
	if c, err := r.Cookie(sessionCookieName); err == nil {
		rec = s.loadSession(c.Value)
		s.endSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", Expires: time.Unix(0, 0),
	})
	if rec != nil {
		s.Engine.Audit(rec.user, "logout", fmt.Sprintf(`{"source":%q}`, rec.principal.Source), nil)
	}
	// A session that began at the identity provider ends there too: the
	// page is told where to go next.
	if to := s.oidcLogoutURL(r.Context(), rec); to != "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"logout_url": to})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) gcSessionsLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.gcShared(s.Engine.LeadsCluster())
		}
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// private: the page sits behind the session cookie; no-cache: revalidate
	// by ETag so a new build's asset hashes are picked up on the next load.
	w.Header().Set("Cache-Control", "private, no-cache")
	s.index.write(w, r)
}

// ---- snapshot ----

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	snap := s.buildSnapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

// handleSettings sets what stays the node's own: whether it may write to
// the kernel. Thresholds and integrations are node settings of the model.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		AllowNetopsWrite bool `json:"allow_netops_write"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Engine.Settings().Update(func(t *config.Thresholds) { t.AllowNetopsWrite = body.AllowNetopsWrite }); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if nw := s.Engine.Netops(); nw != nil {
		nw.AllowWrites = body.AllowNetopsWrite
	}
	s.Engine.Audit(actorFrom(r), "settings_update",
		fmt.Sprintf(`{"allow_netops_write":%v}`, body.AllowNetopsWrite), nil)
	w.WriteHeader(http.StatusNoContent)
}

func newSessionID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
