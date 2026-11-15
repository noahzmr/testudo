package netops

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/noahzmr/testudo/internal/pamauth"
)

// PAM logins run on the privileged side: checking a local password means
// reading the shadow database, and the modules of a stack may start helper
// programs, which the request-handling process is forbidden to do.
//
// The request is a query, not a mutation. Queries are not written to the
// audit log, and that matters here: the request carries a password. The
// login itself is audited by the caller, without it.

// OpQueryPAMAuth asks the host's PAM stack whether a login is good (Op.PAM).
const OpQueryPAMAuth OpKind = "pam_auth"

// PAMRequest is one login attempt.
type PAMRequest struct {
	User       string `json:"user"`
	Password   string `json:"password"`
	Code       string `json:"code,omitempty"`
	RemoteHost string `json:"remote_host,omitempty"`
}

// Reasons a PAM login did not succeed.
const (
	PAMDenied      = "denied"
	PAMNeedCode    = "need_code"
	PAMAccount     = "account"
	PAMUnavailable = "unavailable"
)

// PAMResult is the answer to a login attempt.
type PAMResult struct {
	OK     bool     `json:"ok"`
	User   string   `json:"user,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Reason string   `json:"reason,omitempty"`
	// Detail says why the account phase refused; it is safe to show.
	Detail string `json:"detail,omitempty"`
}

// RunPAM performs the attempt in this process.
func RunPAM(req PAMRequest) NftResult {
	var out PAMResult
	res, err := pamauth.Authenticate(pamauth.Request{User: req.User, Password: req.Password, Code: req.Code, RemoteHost: req.RemoteHost})
	var acct *pamauth.AccountError
	switch {
	case err == nil:
		out = PAMResult{OK: true, User: res.User, Groups: res.Groups}
	case errors.Is(err, pamauth.ErrUnavailable):
		out.Reason = PAMUnavailable
	case errors.Is(err, pamauth.ErrNeedCode):
		out.Reason = PAMNeedCode
	case errors.As(err, &acct):
		out.Reason, out.Detail = PAMAccount, acct.Reason
	default:
		out.Reason = PAMDenied
	}
	js, _ := json.Marshal(out)
	return NftResult{Output: string(js)}
}

var (
	pamRunnerMu sync.RWMutex
	pamRunner   func(PAMRequest) NftResult
)

// SetPAMRunner routes every PAM login of this process through fn.
func SetPAMRunner(fn func(PAMRequest) NftResult) {
	pamRunnerMu.Lock()
	pamRunner = fn
	pamRunnerMu.Unlock()
}

func runPAM(req PAMRequest) (PAMResult, error) {
	pamRunnerMu.RLock()
	fn := pamRunner
	pamRunnerMu.RUnlock()
	if fn == nil {
		fn = RunPAM
	}
	res := fn(req)
	if res.Error != "" {
		return PAMResult{}, errors.New("pam: " + res.Error)
	}
	var out PAMResult
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		return PAMResult{}, errors.New("pam: unreadable answer")
	}
	return out, nil
}

// PAMLogin asks the host's PAM stack about a login.
func (w *Writer) PAMLogin(req PAMRequest) (PAMResult, error) {
	var out PAMResult
	err := w.queryInto(Op{Kind: OpQueryPAMAuth, PAM: &req}, &out)
	return out, err
}

// PAMAvailable reports whether this build can ask PAM at all.
func PAMAvailable() bool { return pamauth.Available() }
