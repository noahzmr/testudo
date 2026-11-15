// Package pamauth authenticates people through the host's PAM stack, the
// way login and sshd do. The service file /etc/pam.d/testudo decides what
// that means: local accounts, LDAP or SSSD, RADIUS, one-time codes,
// lock-out after failed attempts.
//
// All three phases run. Authentication proves who someone is; the account
// phase can still refuse them (expired, locked, not allowed at this hour);
// the session phase is opened and closed so that modules that record or
// limit logins see this one.
//
// The binding needs cgo and is compiled in with the build tag "pam". A
// binary built without it has no PAM logins and says so.
package pamauth

import (
	"errors"
	"os/user"
	"sort"
)

// Service is the PAM service name: /etc/pam.d/testudo.
const Service = "testudo"

// Request is one login attempt.
type Request struct {
	// Service defaults to Service. ConfDir, when set, replaces /etc/pam.d
	// as the place the service file is read from; it exists for tests.
	Service string
	ConfDir string
	User    string
	// Password answers the first hidden prompt of the stack, Code the
	// second (a one-time code, where the stack asks for one).
	Password string
	Code     string
	// RemoteHost is the address the person connects from, for modules
	// that log or restrict by it.
	RemoteHost string
}

// Result describes a successful login.
type Result struct {
	User string
	// Groups are the names of the host groups the user belongs to.
	Groups []string
}

var (
	// ErrUnavailable: this binary was built without PAM.
	ErrUnavailable = errors.New("PAM logins are not available in this build")
	// ErrDenied: the stack did not accept the credentials. The reason is
	// deliberately not more specific.
	ErrDenied = errors.New("invalid credentials")
	// ErrNeedCode: the stack asked for a second secret and none was given.
	ErrNeedCode = errors.New("one-time code required")
)

// AccountError means the credentials were right and the account phase
// refused the login anyway.
type AccountError struct{ Reason string }

func (e *AccountError) Error() string { return "account not usable: " + e.Reason }

// Available reports whether this binary can ask PAM.
func Available() bool { return available }

// Authenticate runs a login attempt through the stack.
func Authenticate(req Request) (Result, error) {
	if req.Service == "" {
		req.Service = Service
	}
	if req.User == "" || req.Password == "" {
		return Result{}, ErrDenied
	}
	name, err := authenticate(req)
	if err != nil {
		return Result{}, err
	}
	return Result{User: name, Groups: groupsOf(name)}, nil
}

// groupsOf returns the names of a user's host groups. An account PAM knows
// and the user database does not simply has none.
func groupsOf(name string) []string {
	u, err := user.Lookup(name)
	if err != nil {
		return nil
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil
	}
	var out []string
	for _, id := range ids {
		if g, err := user.LookupGroupId(id); err == nil {
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out
}
