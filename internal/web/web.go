// Package web implements the optional HTTP UI. It mirrors the TUI views
// (Dashboard, Flows, Devices, Interfaces, Routes, Firewall, NAT, Alerts,
// Settings) as a single-page app served from embedded assets. Auth is
// session-cookie based; credentials live in the auth package.
package web

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/base64"
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
	sentryx "github.com/noahzmr/testudo/internal/integrations/sentry"
	"github.com/noahzmr/testudo/internal/netops"
)

//go:embed assets
var assetsFS embed.FS

// Server is the HTTP UI. Build one per process and call ListenAndServe.
type Server struct {
	Engine *engine.Engine
	Users  *auth.Store
	Addr   string
	// TLS selects HTTPS (operator cert or auto self-signed). Zero = plain HTTP.
	TLS TLSConfig
	// Issuer is the label authenticator apps show for TOTP enrollments.
	Issuer string

	loginTmpl *template.Template
	mux       *http.ServeMux

	mu       sync.RWMutex
	sessions map[string]*sessionRecord
}

// sessionRecord is one logged-in browser. The role is captured at login so a
// demotion takes effect on the next login, not mid-session (the admin can
// disable the account to cut a live session).
type sessionRecord struct {
	user      string
	role      auth.Role
	expiresAt time.Time
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
func New(eng *engine.Engine, users *auth.Store, addr string) *Server {
	return &Server{
		Engine: eng, Users: users, Addr: addr, Issuer: "Testudo",
		sessions: make(map[string]*sessionRecord),
	}
}

func (s *Server) buildMux() error {
	mux := http.NewServeMux()

	staticFS, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return fmt.Errorf("sub assets: %w", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	loginBytes, err := assetsFS.ReadFile("assets/login.html")
	if err != nil {
		return fmt.Errorf("read login.html: %w", err)
	}
	t, err := template.New("login").Parse(string(loginBytes))
	if err != nil {
		return fmt.Errorf("parse login.html: %w", err)
	}
	s.loginTmpl = t

	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/me", s.protect(s.handleMe))
	mux.HandleFunc("/api/me/passwd", s.protect(s.handleMePasswd))
	mux.HandleFunc("/api/me/totp/enroll", s.protect(s.handleMeTOTPEnroll))
	mux.HandleFunc("/api/me/totp/disable", s.protect(s.handleMeTOTPDisable))

	// User management (admin only - see adminOnly).
	mux.HandleFunc("/api/users", s.protect(s.handleUsers))
	mux.HandleFunc("/api/users/add", s.protect(s.handleUserAdd))
	mux.HandleFunc("/api/users/del", s.protect(s.handleUserDel))
	mux.HandleFunc("/api/users/role", s.protect(s.handleUserRole))
	mux.HandleFunc("/api/users/disable", s.protect(s.handleUserDisable))
	mux.HandleFunc("/api/users/passwd", s.protect(s.handleUserPasswd))
	mux.HandleFunc("/api/users/totp/enroll", s.protect(s.handleUserTOTPEnroll))
	mux.HandleFunc("/api/users/totp/disable", s.protect(s.handleUserTOTPDisable))

	// Privileged access: JIT grants compiled into firewall rules for the
	// requester's WireGuard peers. See internal/pam and docs/pam.md.
	mux.HandleFunc("/api/pam", s.protect(s.handlePAM))
	mux.HandleFunc("/api/pam/request", s.protect(s.handlePAMRequest))
	mux.HandleFunc("/api/pam/approve", s.protect(s.handlePAMApprove))
	mux.HandleFunc("/api/pam/deny", s.protect(s.handlePAMDeny))
	mux.HandleFunc("/api/pam/revoke", s.protect(s.handlePAMRevoke))
	mux.HandleFunc("/api/pam/breakglass", s.protect(s.handlePAMBreakGlass))
	mux.HandleFunc("/api/pam/resource/add", s.protect(s.handlePAMResourceAdd))
	mux.HandleFunc("/api/pam/resource/del", s.protect(s.handlePAMResourceDel))
	mux.HandleFunc("/api/pam/policy/add", s.protect(s.handlePAMPolicyAdd))
	mux.HandleFunc("/api/pam/policy/del", s.protect(s.handlePAMPolicyDel))
	mux.HandleFunc("/api/pam/peer/bind", s.protect(s.handlePAMPeerBind))
	mux.HandleFunc("/api/pam/ssh/cert", s.protect(s.handlePAMSSHCert))

	mux.HandleFunc("/api/snapshot", s.protect(s.handleSnapshot))
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
	mux.HandleFunc("/api/iface/up", s.protect(s.handleIfaceUp))
	mux.HandleFunc("/api/iface/down", s.protect(s.handleIfaceDown))
	mux.HandleFunc("/api/iface/addr/add", s.protect(s.handleIfaceAddAddr))
	mux.HandleFunc("/api/iface/addr/del", s.protect(s.handleIfaceDelAddr))
	mux.HandleFunc("/api/iface/mtu", s.protect(s.handleIfaceMTU))
	mux.HandleFunc("/api/iface/dhcp", s.protect(s.handleIfaceDHCP))
	mux.HandleFunc("/api/iface/static", s.protect(s.handleIfaceStatic))

	// Routes
	mux.HandleFunc("/api/route/add", s.protect(s.handleRouteAdd))
	mux.HandleFunc("/api/route/del", s.protect(s.handleRouteDel))

	// Firewall / NAT: every mutation goes through the policy manager (desired
	// state in firewall.json, applied atomically, reconciled after reboot).
	// Enabling enforce (default-deny) is commit-confirm; see handleFirewallEnforce.
	mux.HandleFunc("/api/firewall/policy", s.protect(s.handleFirewallPolicy))
	mux.HandleFunc("/api/firewall/add", s.protect(s.handleFirewallAdd))
	mux.HandleFunc("/api/firewall/del", s.protect(s.handleFirewallDel))
	mux.HandleFunc("/api/firewall/reorder", s.protect(s.handleFirewallReorder))
	mux.HandleFunc("/api/firewall/enforce", s.protect(s.handleFirewallEnforce))
	mux.HandleFunc("/api/firewall/enforce/confirm", s.protect(s.handleFirewallConfirm))
	mux.HandleFunc("/api/firewall/baseline", s.protect(s.handleFirewallBaseline))
	mux.HandleFunc("/api/firewall/export", s.protect(s.handleFirewallExport))
	mux.HandleFunc("/api/firewall/import", s.protect(s.handleFirewallImport))
	mux.HandleFunc("/api/firewall/reset-counter", s.protect(s.handleFirewallResetCounter))
	mux.HandleFunc("/api/nat/add", s.protect(s.handleNATAdd))
	mux.HandleFunc("/api/nat/del", s.protect(s.handleNATDel))
	mux.HandleFunc("/api/nat/masquerade/add", s.protect(s.handleMasqueradeAdd))
	mux.HandleFunc("/api/nat/masquerade/del", s.protect(s.handleMasqueradeDel))
	mux.HandleFunc("/api/conntrack/flush", s.protect(s.handleConntrackFlush))

	// WireGuard: read via /api/snapshot; provision/deprovision here. Peer
	// provisioning is a write-gated, audit-logged transaction with rollback.
	mux.HandleFunc("/api/wireguard/interface", s.protect(s.handleWireGuardInterfaceCreate))
	mux.HandleFunc("/api/wireguard/interface/delete", s.protect(s.handleWireGuardInterfaceDelete))
	mux.HandleFunc("/api/wireguard/interface/name", s.protect(s.handleWireGuardInterfaceName))
	mux.HandleFunc("/api/wireguard/interface/restart", s.protect(s.handleWireGuardInterfaceRestart))
	mux.HandleFunc("/api/wireguard/interface/tune", s.protect(s.handleWireGuardInterfaceTune))
	mux.HandleFunc("/api/wireguard/peer", s.protect(s.handleWireGuardProvision))
	mux.HandleFunc("/api/wireguard/peer/update", s.protect(s.handleWireGuardUpdate))
	mux.HandleFunc("/api/wireguard/peer/deprovision", s.protect(s.handleWireGuardDeprovision))
	mux.HandleFunc("/api/wireguard/netplan/render", s.protect(s.handleWireGuardNetplanRender))
	mux.HandleFunc("/api/wireguard/netplan/write", s.protect(s.handleWireGuardNetplanWrite))
	mux.HandleFunc("/api/wireguard/netplan/list", s.protect(s.handleWireGuardNetplanList))
	mux.HandleFunc("/api/wireguard/netplan/save", s.protect(s.handleWireGuardNetplanSave))
	mux.HandleFunc("/api/wireguard/netplan/apply", s.protect(s.handleWireGuardNetplanApply))
	mux.HandleFunc("/api/wireguard/netplan/save-apply", s.protect(s.handleWireGuardNetplanSaveApply))

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

	mux.HandleFunc("/", s.protect(s.handleRoot))

	s.mux = mux
	return nil
}

// ListenAndServe blocks until ctx is cancelled or the server errors. With TLS
// configured it serves HTTPS (TLS 1.2+); a self-signed certificate is
// generated on first use when TLS.Auto is set and its fingerprint logged so
// the operator can pin it.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.buildMux(); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.Addr,
		Handler:           s.mux,
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
	"/api/users",
	"/api/firewall/import",
	"/api/firewall/enforce",
	"/api/firewall/baseline",
	"/api/pam/resource",
	"/api/pam/policy",
	"/api/pam/breakglass",
	"/api/pam/peer",
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
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.sessions[c.Value]
	if !ok || time.Now().After(rec.expiresAt) {
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
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = s.loginTmpl.Execute(w, loginView{})
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		code := r.FormValue("code")
		u, err := s.Users.Authenticate(user, pass, code)
		if err != nil {
			s.Engine.Audit(user, "login", `{"result":"denied"}`, err)
			w.WriteHeader(http.StatusUnauthorized)
			view := loginView{Error: "invalid credentials", Username: user}
			switch {
			case errors.Is(err, auth.ErrTOTPRequired):
				view.Error, view.NeedCode = "enter the one-time code from your authenticator", true
			case errors.Is(err, auth.ErrDisabled):
				view.Error = "account disabled"
			}
			_ = s.loginTmpl.Execute(w, view)
			return
		}
		sid := newSessionID()
		s.mu.Lock()
		s.sessions[sid] = &sessionRecord{user: u.Name, role: u.Role, expiresAt: time.Now().Add(sessionTTL)}
		s.mu.Unlock()
		s.Engine.Audit(u.Name, "login", fmt.Sprintf(`{"role":%q,"mfa":%v}`, u.Role, u.MFAEnrolled()), nil)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			Secure:   s.TLS.Enabled(),
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(sessionTTL),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMe tells the page who is logged in and what they may do.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	rec := r.Context().Value(sessionCtxKey).(*sessionRecord)
	u, _ := s.Users.Get(rec.user)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user":         rec.user,
		"role":         rec.role,
		"mfa_enrolled": u.MFAEnrolled(),
		"can_approve":  rec.role.CanApprove(),
		"tls":          s.TLS.Enabled(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", Expires: time.Unix(0, 0),
	})
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
			s.mu.Lock()
			now := time.Now()
			for k, v := range s.sessions {
				if now.After(v.expiresAt) {
					delete(s.sessions, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// ---- snapshot ----

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	snap := s.buildSnapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		PacketLossPct       float64 `json:"packet_loss_pct"`
		DNSLatencyMs        float64 `json:"dns_latency_ms"`
		JitterMs            float64 `json:"jitter_ms"`
		RTTMs               float64 `json:"rtt_ms"`
		RetransmissionsPct  float64 `json:"retransmissions_pct"`
		IncidentCooldownSec float64 `json:"incident_cooldown_sec"`
		AllowNetopsWrite    bool    `json:"allow_netops_write"`
		SentryDSN           string  `json:"sentry_dsn"`
		GuacamoleURL        string  `json:"guacamole_url"`
		GuacamoleConnID     string  `json:"guacamole_conn_id"`
		GuacamoleTemplate   string  `json:"guacamole_template"`
		GuacamoleAPIUser    string  `json:"guacamole_api_user"`
		GuacamoleAPIPass    *string `json:"guacamole_api_password"` // nil = keep current (never echoed to the page)
		GuacamoleRecording  string  `json:"guacamole_recording_path"`
		GuacamoleTypescript string  `json:"guacamole_typescript_path"`
		IPFIXEnabled        bool    `json:"ipfix_enabled"`
		IPFIXEndpoint       string  `json:"ipfix_endpoint"`
		IPFIXIntervalSec    int     `json:"ipfix_interval_sec"`
		IPFIXDomainID       uint32  `json:"ipfix_domain_id"`
		EBPFEnabled         bool    `json:"ebpf_enabled"`
		FlowRetransPct      float64 `json:"flow_retrans_pct"`
		ExpectedDownMbps    float64 `json:"expected_down_mbps"`
		ExpectedUpMbps      float64 `json:"expected_up_mbps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prev := s.Engine.Settings().Snapshot()
	err := s.Engine.Settings().Update(func(t *config.Thresholds) {
		t.PacketLossPct = body.PacketLossPct
		t.DNSLatencyMs = body.DNSLatencyMs
		t.JitterMs = body.JitterMs
		t.RTTMs = body.RTTMs
		t.RetransmissionsPct = body.RetransmissionsPct
		t.IncidentCooldown = time.Duration(body.IncidentCooldownSec * float64(time.Second))
		t.AllowNetopsWrite = body.AllowNetopsWrite
		t.SentryDSN = body.SentryDSN
		t.GuacamoleURL = body.GuacamoleURL
		t.GuacamoleConnID = body.GuacamoleConnID
		t.GuacamoleTemplate = body.GuacamoleTemplate
		t.GuacamoleAPIUser = body.GuacamoleAPIUser
		if body.GuacamoleAPIPass != nil && *body.GuacamoleAPIPass != "" {
			t.GuacamoleAPIPassword = *body.GuacamoleAPIPass
		}
		t.GuacamoleRecordingPath = body.GuacamoleRecording
		t.GuacamoleTypescriptPath = body.GuacamoleTypescript
		t.IPFIXEnabled = body.IPFIXEnabled
		t.IPFIXEndpoint = body.IPFIXEndpoint
		t.IPFIXIntervalSec = body.IPFIXIntervalSec
		t.IPFIXDomainID = body.IPFIXDomainID
		t.EBPFEnabled = body.EBPFEnabled
		t.FlowRetransPct = body.FlowRetransPct
		t.ExpectedDownMbps = body.ExpectedDownMbps
		t.ExpectedUpMbps = body.ExpectedUpMbps
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Mirror the runtime state changes the Settings TUI tab does.
	if nw := s.Engine.Netops(); nw != nil {
		nw.AllowWrites = body.AllowNetopsWrite
	}
	if body.SentryDSN != prev.SentryDSN {
		_ = sentryx.Init(body.SentryDSN, "testudo")
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
