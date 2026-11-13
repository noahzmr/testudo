package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/netops"
)

// maxPolicyImport bounds an uploaded policy document.
const maxPolicyImport = 1 << 20

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

// handleFirewallAdd appends a filter rule to the policy (applied atomically,
// then persisted).
func (s *Server) handleFirewallAdd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		netops.FilterRule
		Index *int `json:"index"` // optional insert position
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	var err error
	if b.Index != nil {
		err = fw.InsertRule(*b.Index, b.FilterRule)
	} else {
		err = fw.AddRule(b.FilterRule)
	}
	s.Engine.AuditFirewall(actorFrom(r), "rule_add", jsonArgs(b.FilterRule), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

// handleFirewallDel removes a rule by id when given one, otherwise every rule
// matching the non-empty fields of the body (the pre-id wildcard contract).
func (s *Server) handleFirewallDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		netops.FilterRule
		ID string `json:"id"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	var err error
	if b.ID != "" {
		err = fw.DelRule(b.ID)
	} else {
		var n int
		n, err = fw.DelRulesMatching(b.FilterRule)
		if err == nil && n == 0 {
			err = firewall.ErrNotFound
		}
	}
	s.Engine.AuditFirewall(actorFrom(r), "rule_del", jsonArgs(b), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

// handleFirewallReorder sets the order of the user rules (ids = full new order).
func (s *Server) handleFirewallReorder(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []string `json:"ids"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err := fw.Reorder(b.IDs)
	s.Engine.AuditFirewall(actorFrom(r), "rules_reorder", jsonArgs(b), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

// handleFirewallEnforce toggles default-deny. Turning it on with confirm_sec
// > 0 is commit-confirm: the browser must POST /api/firewall/enforce/confirm
// within the window (it does so automatically once it can still reach the
// API) or the change reverts - the operator cannot lock themselves out.
func (s *Server) handleFirewallEnforce(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enforce    bool `json:"enforce"`
		ConfirmSec int  `json:"confirm_sec"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	window := time.Duration(b.ConfirmSec) * time.Second
	if b.Enforce && b.ConfirmSec == 0 {
		window = 90 * time.Second // never let a browser enable enforce without a safety net
	}
	err := fw.SetEnforce(b.Enforce, window)
	s.Engine.AuditFirewall(actorFrom(r), "enforce", fmt.Sprintf(`{"enforce":%v,"confirm_sec":%d}`, b.Enforce, int(window.Seconds())), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(fw.Status())
}

// handleFirewallConfirm keeps a pending enforce change.
func (s *Server) handleFirewallConfirm(w http.ResponseWriter, r *http.Request) {
	var b struct{}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err := fw.ConfirmEnforce()
	s.Engine.AuditFirewall(actorFrom(r), "enforce_confirm", "{}", err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(fw.Status())
}

// handleFirewallBaseline replaces the baseline (the always-on preamble).
func (s *Server) handleFirewallBaseline(w http.ResponseWriter, r *http.Request) {
	var b netops.FilterBaseline
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err := fw.SetBaseline(b)
	s.Engine.AuditFirewall(actorFrom(r), "baseline", jsonArgs(b), err)
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

// handleFirewallImport replaces the whole policy from an uploaded document.
func (s *Server) handleFirewallImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxPolicyImport+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(data) > maxPolicyImport {
		http.Error(w, "policy document too large", http.StatusRequestEntityTooLarge)
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err = fw.Import(data)
	s.Engine.AuditFirewall(actorFrom(r), "import", fmt.Sprintf(`{"bytes":%d}`, len(data)), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

// ---- NAT (port forwards + masquerades live in the same policy) -------

func (s *Server) handleNATAdd(w http.ResponseWriter, r *http.Request) {
	var b netops.PortForward
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err := fw.AddForward(b)
	s.Engine.AuditFirewall(actorFrom(r), "forward_add", jsonArgs(b), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleNATDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID      string `json:"id"`
		Proto   string `json:"proto"`
		WANPort uint16 `json:"wan_port"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	var err error
	if b.ID != "" {
		err = fw.DelForward(b.ID)
	} else {
		var n int
		n, err = fw.DelForwardsMatching(b.Proto, b.WANPort)
		if err == nil && n == 0 {
			err = firewall.ErrNotFound
		}
	}
	s.Engine.AuditFirewall(actorFrom(r), "forward_del", jsonArgs(b), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleMasqueradeAdd(w http.ResponseWriter, r *http.Request) {
	var b netops.Masquerade
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	err := fw.AddMasquerade(b)
	s.Engine.AuditFirewall(actorFrom(r), "masquerade_add", jsonArgs(b), err)
	if err != nil {
		writeFirewallErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleMasqueradeDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID       string `json:"id"`
		OutIface string `json:"out_iface"`
		SrcCIDR  string `json:"src"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	fw, ok := s.firewallManager(w)
	if !ok {
		return
	}
	var err error
	if b.ID != "" {
		err = fw.DelMasquerade(b.ID)
	} else {
		var n int
		n, err = fw.DelMasqueradesMatching(b.OutIface, b.SrcCIDR)
		if err == nil && n == 0 {
			err = firewall.ErrNotFound
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
