package web

import (
	"net/http"

	"github.com/noahzmr/testudo/internal/promtext"
)

// handleHealthz answers while the process serves requests: a liveness
// check for systemd or an orchestrator. It needs no login and says nothing
// else.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}

// handleReadyz answers 200 once the configuration model is open and has
// been applied, 503 with the reason before that. It needs no login.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.Engine.Ready(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(err.Error() + "\n"))
		return
	}
	_, _ = w.Write([]byte("ready\n"))
}

// handleMetrics serves the node's metrics in the Prometheus text format.
// It needs a session or an API token (Authorization: Bearer); a scraper
// gets a 401, not the login page, without one.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.session(r) == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="testudo"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", promtext.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	_ = promtext.Write(w, s.Engine.Metrics())
}
