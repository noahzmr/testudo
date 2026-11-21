package confapi

import (
	"encoding/json"
	"net/http"

	"github.com/noahzmr/testudo/internal/localauth"
	"github.com/noahzmr/testudo/internal/model"
)

// localUser finds the local user the path names, answering for the caller
// when it cannot.
func (s *Server) localUser(w http.ResponseWriter, r *http.Request, verb string) *model.User {
	if s.LocalSecrets == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "local users are not available on this node")
		return nil
	}
	if !who(r).Can(SystemArea, verb) {
		fail(w, http.StatusForbidden, "forbidden", "needs system:"+verb)
		return nil
	}
	obj, ok := s.Store.Current().Get(model.KindUser, r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such user")
		return nil
	}
	u := obj.(*model.User)
	if u.Source != "local" {
		fail(w, http.StatusConflict, "conflict", "only local users keep a password here; this one logs in through "+u.Source)
		return nil
	}
	return u
}

// userCredentials says whether a local user has a password and a second
// factor, without either.
func (s *Server) userCredentials(w http.ResponseWriter, r *http.Request) {
	u := s.localUser(w, r, "read")
	if u == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"password": localauth.HasPassword(s.LocalSecrets, u.ID),
		"mfa": localauth.MFAEnrolled(s.LocalSecrets, u.ID)})
}

// setUserPassword gives a local user a new password.
func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	u := s.localUser(w, r, "write")
	if u == nil {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	body, err := readBody(w, r, 1<<12)
	if err != nil || json.Unmarshal(body, &in) != nil {
		fail(w, http.StatusBadRequest, "bad_request", "give the password")
		return
	}
	err = localauth.SetPassword(s.LocalSecrets, u.ID, in.Password)
	s.auditCredential(r, "user_passwd", u.Username, err)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// enrollUserTOTP gives a local user a new second factor and returns the
// otpauth URI, once.
func (s *Server) enrollUserTOTP(w http.ResponseWriter, r *http.Request) {
	u := s.localUser(w, r, "write")
	if u == nil {
		return
	}
	uri, err := localauth.EnrollTOTP(s.LocalSecrets, u, s.Issuer)
	s.auditCredential(r, "user_totp_enroll", u.Username, err)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not store the second factor")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"otpauth": uri})
}

// disableUserTOTP removes a local user's second factor.
func (s *Server) disableUserTOTP(w http.ResponseWriter, r *http.Request) {
	u := s.localUser(w, r, "write")
	if u == nil {
		return
	}
	err := localauth.DisableTOTP(s.LocalSecrets, u.ID)
	s.auditCredential(r, "user_totp_disable", u.Username, err)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// audit records a credential change; nothing secret goes into the row.
func (s *Server) auditCredential(r *http.Request, op, subject string, err error) {
	if s.AuditWrite != nil {
		args, _ := json.Marshal(map[string]string{"user": subject})
		s.AuditWrite(who(r).Name, op, string(args), err)
	}
}
