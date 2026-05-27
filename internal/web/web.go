// Package web implements the optional HTTP UI. It mirrors the TUI views
// (Dashboard, Flows, Devices, Interfaces, Routes, Firewall, NAT, Alerts,
// Settings) as a single-page app served from embedded assets. Auth is
// session-cookie based; credentials live in the auth package.
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/engine"
	sentryx "github.com/noahzmr/testudo/internal/integrations/sentry"
)

//go:embed assets
var assetsFS embed.FS

// Server is the HTTP UI. Build one per process and call ListenAndServe.
type Server struct {
	Engine *engine.Engine
	Users  *auth.Store
	Addr   string

	loginTmpl *template.Template
	mux       *http.ServeMux

	mu       sync.RWMutex
	sessions map[string]*sessionRecord
}

type sessionRecord struct {
	user      string
	expiresAt time.Time
}

const (
	sessionCookieName = "testudo_sid"
	sessionTTL        = 8 * time.Hour
)

// New constructs an unstarted Server. Mux is built lazily on first ListenAndServe.
func New(eng *engine.Engine, users *auth.Store, addr string) *Server {
	return &Server{
		Engine: eng, Users: users, Addr: addr,
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

	// Routes / firewall / NAT
	mux.HandleFunc("/api/route/add", s.protect(s.handleRouteAdd))
	mux.HandleFunc("/api/route/del", s.protect(s.handleRouteDel))
	mux.HandleFunc("/api/firewall/add", s.protect(s.handleFirewallAdd))
	mux.HandleFunc("/api/firewall/del", s.protect(s.handleFirewallDel))
	mux.HandleFunc("/api/firewall/reset-counter", s.protect(s.handleFirewallResetCounter))
	mux.HandleFunc("/api/nat/add", s.protect(s.handleNATAdd))
	mux.HandleFunc("/api/nat/del", s.protect(s.handleNATDel))
	mux.HandleFunc("/api/conntrack/flush", s.protect(s.handleConntrackFlush))

	// TCPDump
	mux.HandleFunc("/api/tcpdump/start", s.protect(s.handleTCPDumpStart))
	mux.HandleFunc("/api/tcpdump/stop", s.protect(s.handleTCPDumpStop))
	mux.HandleFunc("/api/tcpdump/remove", s.protect(s.handleTCPDumpRemove))

	// Device connect launchpad
	mux.HandleFunc("/api/device/scan", s.protect(s.handleDeviceScan))
	mux.HandleFunc("/api/connect", s.protect(s.handleConnect))

	mux.HandleFunc("/", s.protect(s.handleRoot))

	s.mux = mux
	return nil
}

// ListenAndServe blocks until ctx is cancelled or the server errors.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.buildMux(); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.Addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

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

func (s *Server) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.sessions[c.Value]
	if !ok || time.Now().After(rec.expiresAt) {
		return false
	}
	return true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = s.loginTmpl.Execute(w, map[string]string{"Error": ""})
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		user := r.FormValue("username")
		pass := r.FormValue("password")
		if !s.Users.Verify(user, pass) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = s.loginTmpl.Execute(w, map[string]string{"Error": "invalid credentials"})
			return
		}
		sid := newSessionID()
		s.mu.Lock()
		s.sessions[sid] = &sessionRecord{user: user, expiresAt: time.Now().Add(sessionTTL)}
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(sessionTTL),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
		IPFIXEnabled        bool    `json:"ipfix_enabled"`
		IPFIXEndpoint       string  `json:"ipfix_endpoint"`
		IPFIXIntervalSec    int     `json:"ipfix_interval_sec"`
		IPFIXDomainID       uint32  `json:"ipfix_domain_id"`
		EBPFEnabled         bool    `json:"ebpf_enabled"`
		FlowRetransPct      float64 `json:"flow_retrans_pct"`
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
		t.IPFIXEnabled = body.IPFIXEnabled
		t.IPFIXEndpoint = body.IPFIXEndpoint
		t.IPFIXIntervalSec = body.IPFIXIntervalSec
		t.IPFIXDomainID = body.IPFIXDomainID
		t.EBPFEnabled = body.EBPFEnabled
		t.FlowRetransPct = body.FlowRetransPct
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
	w.WriteHeader(http.StatusNoContent)
}

func newSessionID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
