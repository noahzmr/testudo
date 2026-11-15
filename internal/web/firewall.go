package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/netops"
)

// The policy file is no longer edited from here. Rules, NAT, defaults and
// the baseline are model objects (/api/v1); this file serves the view of
// what the manager enforces, and lets an operator delete rules that were
// created by hand before the model existed and were not carried over.

// leftover reports whether an entry was created by hand; only those may be
// deleted here. Rules of WireGuard peers, access grants and the model belong
// to their subsystems.
func leftover(owner string) bool { return owner == "" || owner == netops.OwnerUser }

var errNotLeftover = errors.New("this entry belongs to a subsystem or to the configuration model; change it there")

// firewallManager returns the policy manager or writes a 503 explaining why
// firewall management is unavailable.
func (s *Server) firewallManager(w http.ResponseWriter) (*firewall.Manager, bool) {
	fw := s.Engine.Firewall()
	if fw == nil {
		msg := "firewall management unavailable: netops not initialized"
		if err := s.Engine.FirewallError(); err != nil {
			msg = "firewall management unavailable: " + err.Error()
		}
		http.Error(w, msg, http.StatusServiceUnavailable)
		return nil, false
	}
	return fw, true
}

// writeFirewallErr maps manager errors onto HTTP statuses: the write gate and
// a pending confirm are 403/409 (the request was fine, the state refused it),
// everything else is the usual 422.
func writeFirewallErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, firewall.ErrWritesDisabled):
		http.Error(w, "netops writes are disabled - enable \"allow netops writes\" in Settings", http.StatusForbidden)
	case errors.Is(err, firewall.ErrPendingConfirm):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, errNotLeftover):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, firewall.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		writeErr(w, err)
	}
}

// firewallPolicyView is the GET /api/firewall/policy response.
type firewallPolicyView struct {
	Status      firewall.Status          `json:"status"`
	Policy      firewall.Policy          `json:"policy"`
	Rules       []firewall.RuleStatus    `json:"rules"`
	Forwards    []firewall.ForwardStatus `json:"forwards"`
	Masquerades []firewall.MasqStatus    `json:"masquerades"`
	NFT         string                   `json:"nft"`
}

// handleFirewallPolicy returns the full policy, its status, and every rule
// joined with live counters.
func (s *Server) handleFirewallPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	view := firewallPolicyView{Status: fw.Status(), Policy: fw.Policy(), NFT: fw.RenderNFT()}
	view.Rules, _ = fw.Rules()
	view.Forwards, view.Masquerades, _ = fw.NAT()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// handleFirewallDel removes a hand-made rule by id.
func (s *Server) handleFirewallDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err := firewall.ErrNotFound
	for _, rule := range fw.Policy().Rules {
		if rule.ID() == b.ID && b.ID != "" {
			if err = errNotLeftover; leftover(rule.Owner) {
				err = fw.DelRule(b.ID)
			}
		}
	}
	s.Engine.AuditFirewall(actorFrom(r), "rule_del", jsonArgs(b), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

// handleFirewallExport downloads the policy file.
func (s *Server) handleFirewallExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	data, err := fw.Export()
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="testudo-firewall.json"`)
	_, _ = w.Write(data)
}

func (s *Server) handleNATDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err := firewall.ErrNotFound
	for _, pf := range fw.Policy().Forwards {
		if pf.ID() == b.ID && b.ID != "" {
			if err = errNotLeftover; leftover(pf.Owner) {
				err = fw.DelForward(b.ID)
			}
		}
	}
	s.Engine.AuditFirewall(actorFrom(r), "forward_del", jsonArgs(b), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleMasqueradeDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err := firewall.ErrNotFound
	for _, ms := range fw.Policy().Masquerades {
		if ms.ID() == b.ID && b.ID != "" {
			if err = errNotLeftover; leftover(ms.Owner) {
				err = fw.DelMasquerade(b.ID)
			}
		}
	}
	s.Engine.AuditFirewall(actorFrom(r), "masquerade_del", jsonArgs(b), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

// jsonArgs renders a request body for the audit log (never secret material).
func jsonArgs(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
