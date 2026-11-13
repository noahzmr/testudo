package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/pam"
	"github.com/noahzmr/testudo/internal/storage"
)

// Privileged access (PAM). Role gating lives in protect: requests and
// revocations need operator, approve/deny need an approver (approverOnly),
// resources / policies / break-glass / peer binding need admin (adminOnly).
// The manager re-checks the subject's role anyway - the HTTP layer is not the
// only guard.

// subjectFrom builds the PAM subject for the logged-in user.
func (s *Server) subjectFrom(r *http.Request) pam.Subject {
	rec, _ := r.Context().Value(sessionCtxKey).(*sessionRecord)
	if rec == nil {
		return pam.Subject{Role: auth.RoleViewer}
	}
	u, _ := s.Users.Get(rec.user)
	return pam.Subject{Name: rec.user, Role: rec.role, MFA: u.MFAEnrolled()}
}

func (s *Server) pamManager(w http.ResponseWriter) (*pam.Manager, bool) {
	m := s.Engine.PAM()
	if m == nil {
		http.Error(w, "privileged access unavailable: needs storage, netops and the firewall policy", http.StatusServiceUnavailable)
		return nil, false
	}
	return m, true
}

func writePAMErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pam.ErrForbidden), errors.Is(err, pam.ErrSelfApproval):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, pam.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, pam.ErrState):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		writeErr(w, err)
	}
}

// handlePAM returns the whole access picture for the Access tab.
func (s *Server) handlePAM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	ov, err := m.Overview(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	subj := s.subjectFrom(r)
	// Brokered sessions: launch URLs for the requester's own active grants.
	launch := map[string]string{}
	for _, g := range ov.Grants {
		if g.User == subj.Name {
			if u := m.LaunchURL(g); u != "" {
				launch[g.ID] = u
			}
		}
	}
	caPub, caFP := "", ""
	if ca, err := s.Engine.SSHCA(); err == nil {
		caPub, caFP = ca.PublicKey(), ca.Fingerprint()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"overview":     ov,
		"me":           subj.Name,
		"role":         subj.Role,
		"can_approve":  subj.Role.CanApprove(),
		"can_request":  subj.Role.AtLeast(auth.RoleOperator),
		"is_admin":     subj.Role == auth.RoleAdmin,
		"mfa":          subj.MFA,
		"now":          time.Now().Format(time.RFC3339),
		"launch_urls":  launch,
		"ssh_ca_key":   caPub,
		"ssh_ca_fp":    caFP,
		"broker_ready": s.Engine.Settings().Snapshot().GuacamoleAPIUser != "",
	})
}

// handlePAMSSHCert signs the caller's SSH public key for one of their active
// ssh grants (principal = resource login, validity = grant window,
// source-address = their peer addresses). The certificate contains no secret.
func (s *Server) handlePAMSSHCert(w http.ResponseWriter, r *http.Request) {
	var b struct {
		GrantID   string `json:"grant_id"`
		PublicKey string `json:"public_key"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	cert, principals, err := s.Engine.IssueSSHCert(r.Context(), actorFrom(r), b.GrantID, b.PublicKey)
	if err != nil {
		writePAMErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"certificate": cert,
		"principals":  principals,
		"hint":        "save as ~/.ssh/<key>-cert.pub next to your private key; ssh " + principals[0] + "@<target> then uses it automatically",
	})
}

func (s *Server) handlePAMRequest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ResourceID    string `json:"resource_id"`
		TTLSec        int    `json:"ttl_sec"`
		Justification string `json:"justification"`
		Ticket        string `json:"ticket"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	g, err := m.Request(r.Context(), s.subjectFrom(r), b.ResourceID, time.Duration(b.TTLSec)*time.Second, b.Justification, b.Ticket)
	if err != nil {
		writePAMErr(w, err)
		return
	}
	writeGrant(w, g)
}

func (s *Server) handlePAMApprove(w http.ResponseWriter, r *http.Request) {
	var b struct {
		GrantID string `json:"grant_id"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	g, err := m.Approve(r.Context(), s.subjectFrom(r), b.GrantID)
	if err != nil {
		writePAMErr(w, err)
		return
	}
	writeGrant(w, g)
}

func (s *Server) handlePAMDeny(w http.ResponseWriter, r *http.Request) {
	var b struct {
		GrantID string `json:"grant_id"`
		Reason  string `json:"reason"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	g, err := m.Deny(r.Context(), s.subjectFrom(r), b.GrantID, b.Reason)
	if err != nil {
		writePAMErr(w, err)
		return
	}
	writeGrant(w, g)
}

func (s *Server) handlePAMRevoke(w http.ResponseWriter, r *http.Request) {
	var b struct {
		GrantID string `json:"grant_id"`
		Reason  string `json:"reason"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	g, err := m.Revoke(r.Context(), s.subjectFrom(r), b.GrantID, b.Reason)
	if err != nil {
		writePAMErr(w, err)
		return
	}
	writeGrant(w, g)
}

func (s *Server) handlePAMBreakGlass(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ResourceID    string `json:"resource_id"`
		TTLSec        int    `json:"ttl_sec"`
		Justification string `json:"justification"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	g, err := m.BreakGlass(r.Context(), s.subjectFrom(r), b.ResourceID, time.Duration(b.TTLSec)*time.Second, b.Justification)
	if err != nil {
		writePAMErr(w, err)
		return
	}
	writeGrant(w, g)
}

func (s *Server) handlePAMResourceAdd(w http.ResponseWriter, r *http.Request) {
	var b storage.PAMResource
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	res, err := m.AddResource(r.Context(), s.subjectFrom(r), b)
	if err != nil {
		writePAMErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handlePAMResourceDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	if err := m.DeleteResource(r.Context(), s.subjectFrom(r), b.ID); err != nil {
		writePAMErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handlePAMPolicyAdd(w http.ResponseWriter, r *http.Request) {
	var b storage.PAMPolicy
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	pol, err := m.AddPolicy(r.Context(), s.subjectFrom(r), b)
	if err != nil {
		writePAMErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pol)
}

func (s *Server) handlePAMPolicyDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	if err := m.DeletePolicy(r.Context(), s.subjectFrom(r), b.ID); err != nil {
		writePAMErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handlePAMPeerBind(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PublicKey string `json:"public_key"`
		User      string `json:"user"` // "" unbinds
	}
	if !readJSON(w, r, &b) {
		return
	}
	m, ok := s.pamManager(w)
	if !ok {
		return
	}
	if b.User != "" {
		if _, exists := s.Users.Get(strings.TrimSpace(b.User)); !exists {
			http.Error(w, fmt.Sprintf("no such user %q", b.User), http.StatusNotFound)
			return
		}
	}
	if err := m.BindPeer(r.Context(), s.subjectFrom(r), b.PublicKey, b.User); err != nil {
		writePAMErr(w, err)
		return
	}
	writeOK(w)
}

func writeGrant(w http.ResponseWriter, g storage.PAMGrant) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(g)
}

// ensure the context import is used even if handlers change shape.
var _ = context.Background
