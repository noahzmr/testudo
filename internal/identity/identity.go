// Package identity turns a successful login into what the caller may do.
// Whatever proved who someone is (the local user store, the host's PAM
// stack, the OIDC provider, an API token), the answer to "what are they
// allowed" comes from one place: the users, groups and roles of the
// configuration model.
package identity

import (
	"errors"
	"sort"
	"strings"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// Where a login was proven.
const (
	SourceLocal = "local" // the built-in user store
	SourcePAM   = "pam"   // the host's PAM stack
	SourceOIDC  = "oidc"  // the identity provider
	SourceToken = "token" // an API token
)

// BreakGlassGroup is the host group whose members are administrators no
// matter what the model says. It is how someone gets in when the identity
// provider is down or the model's users and roles are broken.
const BreakGlassGroup = "testudo-admin"

// The built-in roles. They exist as role objects in the model so they can
// be assigned like any other; the names are fixed.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleReadOnly = "read-only"
	RoleVPNUser  = "vpn-user"
)

// BuiltinRoles maps the built-in role names to their permissions.
var BuiltinRoles = map[string][]string{
	RoleAdmin: {"*:write"},
	RoleOperator: {"*:read", "firewall:write", "routing:write", "vpn:write", "loadbalancer:write",
		"interfaces:write", "access:write"},
	RoleReadOnly: {"*:read"},
	// A VPN user may use tunnels and published services, not the console.
	RoleVPNUser: {"self:read"},
}

var (
	// ErrDisabled: the model has the user, switched off.
	ErrDisabled = errors.New("the account is disabled")
	// ErrNoRole: the login is genuine but nothing gives it a role.
	ErrNoRole = errors.New("no role is assigned to this account")
)

// Principal is an authenticated caller.
type Principal struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Subject string `json:"subject,omitempty"`
	// Groups holds the ids of the model groups the caller belongs to.
	Groups      []string `json:"groups,omitempty"`
	Permissions []string `json:"permissions"`
	// BreakGlass is set when the permissions come from the host's
	// break-glass group and not from the model.
	BreakGlass bool `json:"break_glass,omitempty"`
}

// Can reports whether the caller may read or write an area. Write implies
// read; the area "*" covers every area.
func (p Principal) Can(area, verb string) bool {
	for _, perm := range p.Permissions {
		a, v, _ := strings.Cut(perm, ":")
		if (a == "*" || a == area) && (v == verb || v == "write") {
			return true
		}
	}
	return false
}

// LegacyRole maps the permissions onto the four ranks the endpoints from
// before the model check: admin for everything, approver for someone who
// decides on access but does not manage the network, operator for anyone
// who may change something, viewer otherwise.
func (p Principal) LegacyRole() auth.Role {
	switch {
	case p.Can("*", "write"):
		return auth.RoleAdmin
	case p.Can("firewall", "write"):
		return auth.RoleOperator
	case p.Can("access", "write"):
		return auth.RoleApprover
	case len(p.Permissions) > 0 && anyWrite(p.Permissions):
		return auth.RoleOperator
	}
	return auth.RoleViewer
}

func anyWrite(perms []string) bool {
	for _, p := range perms {
		if strings.HasSuffix(p, ":write") {
			return true
		}
	}
	return false
}

// LocalPermissions maps a role of the built-in user store to permissions.
func LocalPermissions(role auth.Role) []string {
	switch role {
	case auth.RoleAdmin:
		return BuiltinRoles[RoleAdmin]
	case auth.RoleOperator:
		return BuiltinRoles[RoleOperator]
	case auth.RoleApprover:
		return []string{"*:read", "access:write"}
	}
	return BuiltinRoles[RoleReadOnly]
}

// Local is the principal of a user of the built-in store.
func Local(u auth.User) Principal {
	return Principal{Name: u.Name, Source: SourceLocal, Permissions: LocalPermissions(u.Role)}
}

// Login describes a login that was proven outside the model.
type Login struct {
	Source   string
	Username string
	// Subject is the provider's stable identifier (OIDC "sub").
	Subject string
	// Groups are the names the source reports: values of the provider's
	// groups claim, or the host groups of a PAM user.
	Groups []string
}

// Resolve decides what a proven login may do.
//
// The user object, if there is one, is found by subject for OIDC and by
// user name otherwise, and only among users of the same kind of source. Its
// roles and groups count, and so does every group whose claim value is one
// of the names the source reported. A login nothing gives a role to is
// refused: being known to the provider is not enough.
//
// With st == nil only the break-glass group can give access.
func Resolve(st *confstore.State, in Login) (Principal, error) {
	p := Principal{Name: in.Username, Source: in.Source, Subject: in.Subject}
	if in.Source == SourcePAM {
		for _, g := range in.Groups {
			if g == BreakGlassGroup {
				p.Permissions, p.BreakGlass = BuiltinRoles[RoleAdmin], true
				return p, nil
			}
		}
	}
	if st == nil {
		return p, ErrNoRole
	}
	want := "host"
	if in.Source == SourceOIDC {
		want = "oidc"
	}
	var user *model.User
	for _, e := range st.List(model.KindUser) {
		u := e.(*model.User)
		if u.Source != want {
			continue
		}
		bySubject := in.Source == SourceOIDC && u.Subject != "" && u.Subject == in.Subject
		// A user object without a subject is matched by name until the
		// first login; whoever maintains the object can pin the subject.
		byName := u.Username == in.Username && (in.Source != SourceOIDC || u.Subject == "")
		if bySubject || byName {
			user = u
			if bySubject {
				break
			}
		}
	}
	if user != nil && user.Disabled {
		return p, ErrDisabled
	}
	reported := map[string]bool{}
	for _, g := range in.Groups {
		reported[g] = true
	}
	groups, roles := map[string]bool{}, map[string]bool{}
	if user != nil {
		for _, g := range user.Groups {
			groups[g.ID] = true
		}
		for _, r := range user.Roles {
			roles[r.ID] = true
		}
	}
	for _, e := range st.List(model.KindGroup) {
		g := e.(*model.Group)
		if g.Claim != "" && reported[g.Claim] {
			groups[g.ID] = true
		}
		if groups[g.ID] {
			for _, r := range g.Roles {
				roles[r.ID] = true
			}
		}
	}
	perms := map[string]bool{}
	for id := range roles {
		if e, ok := st.Get(model.KindRole, id); ok {
			for _, perm := range e.(*model.Role).Permissions {
				perms[perm] = true
			}
		}
	}
	if len(perms) == 0 {
		return p, ErrNoRole
	}
	for g := range groups {
		p.Groups = append(p.Groups, g)
	}
	for perm := range perms {
		p.Permissions = append(p.Permissions, perm)
	}
	sort.Strings(p.Groups)
	sort.Strings(p.Permissions)
	return p, nil
}

// ModelGroups returns the ids of the groups a user object puts a user of
// the built-in store or of the host in. Permissions of built-in users come
// from their role there; their groups, which decide about published
// services, come from here.
func ModelGroups(st *confstore.State, username string) []string {
	if st == nil {
		return nil
	}
	var out []string
	for _, e := range st.List(model.KindUser) {
		if u := e.(*model.User); u.Source == "host" && u.Username == username && !u.Disabled {
			for _, g := range u.Groups {
				out = append(out, g.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Cap returns the permissions of want that the holder of have also has, so
// nobody can hand out more than they hold.
func Cap(have Principal, want []string) (granted []string, refused []string) {
	for _, perm := range want {
		area, verb, _ := strings.Cut(perm, ":")
		if have.Can(area, verb) {
			granted = append(granted, perm)
		} else {
			refused = append(refused, perm)
		}
	}
	return granted, refused
}

// MissingBuiltinRoles returns the built-in roles the model does not have
// yet, ready to be created.
func MissingBuiltinRoles(st *confstore.State) []*model.Role {
	have := map[string]bool{}
	for _, e := range st.List(model.KindRole) {
		have[e.GetMeta().Name] = true
	}
	var out []*model.Role
	for _, name := range []string{RoleAdmin, RoleOperator, RoleReadOnly, RoleVPNUser} {
		if !have[name] {
			out = append(out, &model.Role{Meta: model.Meta{Name: name, Description: "Built-in role"}, Permissions: BuiltinRoles[name]})
		}
	}
	return out
}
