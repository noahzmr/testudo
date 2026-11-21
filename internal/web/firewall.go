package web

import (
	"encoding/json"
	"net/http"
)

// The packet filter is the model's; these read-only views serve the command
// line (over the control socket) and anyone who wants the running state.

// handleFirewallView answers with the model's rules on this node, their
// counters, and whether the kernel holds the model's ruleset.
func (s *Server) handleFirewallView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.Engine.FirewallView())
}

// handleFirewallRendered answers with the ruleset as nft loads it.
func (s *Server) handleFirewallRendered(w http.ResponseWriter, r *http.Request) {
	text, err := s.Engine.RenderedFirewall()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(text))
}
