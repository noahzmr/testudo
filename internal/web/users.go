package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/noahzmr/testudo/internal/auth"
)

// User management lives behind adminOnly ("/api/users/..."); the /api/me/...
// endpoints are self-service for every logged-in role. Every change is
// audited with the acting admin as actor. Secrets never leave the server:
// listings carry no hashes, and a TOTP secret is returned exactly once, as
// the otpauth:// URI the authenticator app scans (QR rendered client-side).

func writeAuthErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, auth.ErrLastAdmin):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		writeErr(w, err)
	}
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type userView struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		MFA      bool   `json:"mfa_enrolled"`
		Disabled bool   `json:"disabled"`
		Created  string `json:"created_at"`
		Updated  string `json:"updated_at"`
	}
	var out []userView
	for _, u := range s.Users.List() {
		out = append(out, userView{
			Name: u.Name, Role: string(u.Role), MFA: u.MFAEnrolled(), Disabled: u.Disabled,
			Created: u.CreatedAt.Format("2006-01-02"), Updated: u.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"users": out, "roles": []string{
		string(auth.RoleViewer), string(auth.RoleApprover), string(auth.RoleOperator), string(auth.RoleAdmin),
	}})
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	role := auth.Role(strings.TrimSpace(b.Role))
	if role == "" {
		role = auth.RoleViewer
	}
	err := s.Users.Add(b.Name, b.Password, role)
	s.Engine.Audit(actorFrom(r), "user_add", fmt.Sprintf(`{"name":%q,"role":%q}`, b.Name, role), err)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleUserDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if b.Name == actorFrom(r) {
		http.Error(w, "you cannot delete your own account", http.StatusConflict)
		return
	}
	err := s.Users.Delete(b.Name)
	s.Engine.Audit(actorFrom(r), "user_del", fmt.Sprintf(`{"name":%q}`, b.Name), err)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	s.dropSessionsFor(b.Name)
	writeOK(w)
}

func (s *Server) handleUserRole(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	err := s.Users.SetRole(b.Name, auth.Role(strings.TrimSpace(b.Role)))
	s.Engine.Audit(actorFrom(r), "user_role", fmt.Sprintf(`{"name":%q,"role":%q}`, b.Name, b.Role), err)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	// A role change applies to the user's next login; cut live sessions so a
	// demotion is not deferred for up to the session TTL.
	s.dropSessionsFor(b.Name)
	writeOK(w)
}

func (s *Server) handleUserDisable(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name     string `json:"name"`
		Disabled bool   `json:"disabled"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if b.Disabled && b.Name == actorFrom(r) {
		http.Error(w, "you cannot disable your own account", http.StatusConflict)
		return
	}
	err := s.Users.SetDisabled(b.Name, b.Disabled)
	s.Engine.Audit(actorFrom(r), "user_disable", fmt.Sprintf(`{"name":%q,"disabled":%v}`, b.Name, b.Disabled), err)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	if b.Disabled {
		s.dropSessionsFor(b.Name)
	}
	writeOK(w)
}

func (s *Server) handleUserPasswd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if _, ok := s.Users.Get(b.Name); !ok {
		writeAuthErr(w, auth.ErrNotFound)
		return
	}
	err := s.Users.SetPassword(b.Name, b.Password)
	s.Engine.Audit(actorFrom(r), "user_passwd", fmt.Sprintf(`{"name":%q}`, b.Name), err)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleUserTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	uri, err := s.Users.EnrollTOTP(b.Name, s.Issuer)
	s.Engine.Audit(actorFrom(r), "user_totp_enroll", fmt.Sprintf(`{"name":%q}`, b.Name), err)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"otpauth": uri}) // shown once; never logged
}

func (s *Server) handleUserTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	err := s.Users.DisableTOTP(b.Name)
	s.Engine.Audit(actorFrom(r), "user_totp_disable", fmt.Sprintf(`{"name":%q}`, b.Name), err)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	writeOK(w)
}

// ---- self service ----------------------------------------------------

func (s *Server) handleMePasswd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	me := actorFrom(r)
	if !s.Users.Verify(me, b.Current) {
		http.Error(w, "current password is wrong", http.StatusForbidden)
		return
	}
	if len(b.New) < 8 {
		http.Error(w, "new password must be at least 8 characters", http.StatusUnprocessableEntity)
		return
	}
	err := s.Users.SetPassword(me, b.New)
	s.Engine.Audit(me, "me_passwd", "{}", err)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleMeTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	me := actorFrom(r)
	if !s.Users.Verify(me, b.Password) {
		http.Error(w, "password is wrong", http.StatusForbidden)
		return
	}
	uri, err := s.Users.EnrollTOTP(me, s.Issuer)
	s.Engine.Audit(me, "me_totp_enroll", "{}", err)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"otpauth": uri})
}

func (s *Server) handleMeTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	me := actorFrom(r)
	if !s.Users.Verify(me, b.Password) {
		http.Error(w, "password is wrong", http.StatusForbidden)
		return
	}
	err := s.Users.DisableTOTP(me)
	s.Engine.Audit(me, "me_totp_disable", "{}", err)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// dropSessionsFor logs a user out everywhere.
func (s *Server) dropSessionsFor(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid, rec := range s.sessions {
		if rec.user == name {
			delete(s.sessions, sid)
		}
	}
}
