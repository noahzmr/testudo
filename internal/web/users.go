package web

import (
	"encoding/json"
	"net/http"

	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/localauth"
	"github.com/noahzmr/testudo/internal/model"
)

// Local users are objects of the model (Settings → Users); administrators
// set their passwords and second factors through /api/v1/users/{id}/...
// Here are the self-service endpoints of a logged-in local user. A TOTP
// secret leaves the server exactly once, as the otpauth:// URI the
// authenticator app scans (the QR code is drawn in the browser).

// me returns the local user behind the request, or nil with an answer
// already written.
func (s *Server) me(w http.ResponseWriter, r *http.Request) *model.User {
	rec, _ := r.Context().Value(sessionCtxKey).(*sessionRecord)
	if rec == nil || rec.principal.Source != identity.SourceLocal {
		http.Error(w, "only local users keep a password here; change it where your account lives", http.StatusConflict)
		return nil
	}
	u := localauth.Find(s.modelState(), rec.user)
	if u == nil {
		http.Error(w, "no such local user", http.StatusNotFound)
		return nil
	}
	return u
}

func (s *Server) handleMePasswd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	u := s.me(w, r)
	if u == nil {
		return
	}
	sec := s.Engine.LocalSecrets()
	if !localauth.Verify(sec, u.ID, b.Current) {
		http.Error(w, "current password is wrong", http.StatusForbidden)
		return
	}
	err := localauth.SetPassword(sec, u.ID, b.New)
	s.Engine.Audit(u.Username, "me_passwd", "{}", err)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
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
	u := s.me(w, r)
	if u == nil {
		return
	}
	sec := s.Engine.LocalSecrets()
	if !localauth.Verify(sec, u.ID, b.Password) {
		http.Error(w, "password is wrong", http.StatusForbidden)
		return
	}
	uri, err := localauth.EnrollTOTP(sec, u, s.Issuer)
	s.Engine.Audit(u.Username, "me_totp_enroll", "{}", err)
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
	u := s.me(w, r)
	if u == nil {
		return
	}
	sec := s.Engine.LocalSecrets()
	if !localauth.Verify(sec, u.ID, b.Password) {
		http.Error(w, "password is wrong", http.StatusForbidden)
		return
	}
	err := localauth.DisableTOTP(sec, u.ID)
	s.Engine.Audit(u.Username, "me_totp_disable", "{}", err)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}
