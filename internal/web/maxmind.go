package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

// handleIPLookup serves GET /api/ip/{addr} - returns the cached MaxMind
// enrichment for the address, schedules a background lookup on a miss, and
// 404s when the address is unparseable. Always JSON so the SPA can render
// the result identically to the TUI detail pane.
func (s *Server) handleIPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	addr := strings.TrimPrefix(r.URL.Path, "/api/ip/")
	addr = strings.TrimSpace(addr)
	if addr == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	enricher := s.Engine.MaxMind()
	w.Header().Set("Content-Type", "application/json")
	if enricher == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ip":      addr,
			"status":  "disabled",
			"message": "maxmind enrichment not configured",
		})
		return
	}
	res, ok := enricher.Lookup(addr)
	if !ok {
		enricher.Enqueue(addr)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ip":      addr,
			"status":  "pending",
			"message": "no database loaded or lookup pending",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(res)
}
