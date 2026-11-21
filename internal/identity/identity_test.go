package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

func fixture(t *testing.T) (*confstore.Store, map[string]string) {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ids := map[string]string{}
	add := func(e model.Entity) {
		t.Helper()
		out, err := s.Create(context.Background(), "test", e)
		if err != nil {
			t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
		ids[out.GetMeta().Name] = out.GetMeta().ID
	}
	for _, r := range MissingBuiltinRoles(s.Current()) {
		add(r)
	}
	role := func(n string) []model.Ref[model.Role] { return []model.Ref[model.Role]{{ID: ids[n]}} }
	add(&model.Group{Meta: model.Meta{Name: "netops"}, Claim: "/network/operators", Roles: role(RoleOperator)})
	add(&model.Group{Meta: model.Meta{Name: "staff"}, Claim: "staff", Roles: role(RoleVPNUser)})
	add(&model.Group{Meta: model.Meta{Name: "auditors"}, Roles: role(RoleReadOnly)})
	add(&model.User{Meta: model.Meta{Name: "alice"}, Username: "alice", Source: "oidc", Subject: "sub-alice", Roles: role(RoleAdmin)})
	add(&model.User{Meta: model.Meta{Name: "bob"}, Username: "bob", Source: "oidc", Groups: []model.Ref[model.Group]{{ID: ids["auditors"]}}})
	add(&model.User{Meta: model.Meta{Name: "carol"}, Username: "carol", Source: "host", Roles: role(RoleOperator)})
	add(&model.User{Meta: model.Meta{Name: "dave"}, Username: "dave", Source: "oidc", Subject: "sub-dave", Roles: role(RoleAdmin), Disabled: true})
	return s, ids
}

func TestResolve(t *testing.T) {
	s, ids := fixture(t)
	st := s.Current()
	cases := []struct {
		name  string
		in    Login
		err   error
		role  auth.Role
		can   []string // "area:verb" that must be allowed
		cant  []string
		group string
	}{
		{name: "a user object by subject, whatever the name says",
			in: Login{Source: SourceOIDC, Username: "renamed", Subject: "sub-alice"}, role: auth.RoleAdmin, can: []string{"system:write"}},
		{name: "a user object without a subject is matched by name",
			in: Login{Source: SourceOIDC, Username: "bob", Subject: "sub-bob"}, role: auth.RoleViewer, can: []string{"firewall:read"}, cant: []string{"firewall:write"}, group: "auditors"},
		{name: "a name does not match a user pinned to another subject",
			in: Login{Source: SourceOIDC, Username: "alice", Subject: "someone-else"}, err: ErrNoRole},
		{name: "no user object, but a group claim that maps to a role",
			in:   Login{Source: SourceOIDC, Username: "erin", Subject: "sub-erin", Groups: []string{"/network/operators", "unknown"}},
			role: auth.RoleOperator, can: []string{"firewall:write", "system:read"}, cant: []string{"system:write"}, group: "netops"},
		{name: "known to the provider and nothing else",
			in: Login{Source: SourceOIDC, Username: "mallory", Subject: "sub-m", Groups: []string{"unknown"}}, err: ErrNoRole},
		{name: "a disabled user stays out even with a group that would let them in",
			in: Login{Source: SourceOIDC, Username: "dave", Subject: "sub-dave", Groups: []string{"/network/operators"}}, err: ErrDisabled},
		{name: "a vpn user may not use the console",
			in: Login{Source: SourceOIDC, Username: "frank", Subject: "sub-f", Groups: []string{"staff"}}, role: auth.RoleViewer, cant: []string{"firewall:read", "system:read"}, group: "staff"},
		{name: "a host user object is not an OIDC user",
			in: Login{Source: SourceOIDC, Username: "carol", Subject: "sub-c"}, err: ErrNoRole},
		{name: "a host user through PAM",
			in: Login{Source: SourcePAM, Username: "carol", Groups: []string{"users"}}, role: auth.RoleOperator, can: []string{"vpn:write"}},
		{name: "an OIDC user object is not a host user",
			in: Login{Source: SourcePAM, Username: "alice"}, err: ErrNoRole},
		{name: "host groups map like claims",
			in: Login{Source: SourcePAM, Username: "grace", Groups: []string{"staff"}}, role: auth.RoleViewer, group: "staff"},
	}
	for _, c := range cases {
		p, err := Resolve(st, c.in)
		if !errors.Is(err, c.err) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.err)
			continue
		}
		if err != nil {
			if len(p.Permissions) != 0 {
				t.Errorf("%s: a refused login carries permissions %v", c.name, p.Permissions)
			}
			continue
		}
		if p.LegacyRole() != c.role {
			t.Errorf("%s: role %s, want %s (%v)", c.name, p.LegacyRole(), c.role, p.Permissions)
		}
		for _, perm := range c.can {
			if a, v, _ := cut(perm); !p.Can(a, v) {
				t.Errorf("%s: may not %s", c.name, perm)
			}
		}
		for _, perm := range c.cant {
			if a, v, _ := cut(perm); p.Can(a, v) {
				t.Errorf("%s: may %s", c.name, perm)
			}
		}
		if c.group != "" && !reflect.DeepEqual(p.Groups, []string{ids[c.group]}) {
			t.Errorf("%s: groups %v, want %s", c.name, p.Groups, c.group)
		}
	}
}

func cut(perm string) (string, string, bool) {
	for i := range perm {
		if perm[i] == ':' {
			return perm[:i], perm[i+1:], true
		}
	}
	return perm, "", false
}

func TestBreakGlassNeedsNoModel(t *testing.T) {
	in := Login{Source: SourcePAM, Username: "root", Groups: []string{"adm", BreakGlassGroup}}
	p, err := Resolve(nil, in)
	if err != nil || !p.BreakGlass || p.LegacyRole() != auth.RoleAdmin {
		t.Fatalf("break-glass without a model: %+v, %v", p, err)
	}
	// The group name means nothing coming from the identity provider.
	in.Source = SourceOIDC
	if _, err := Resolve(nil, in); !errors.Is(err, ErrNoRole) {
		t.Errorf("the break-glass group as an OIDC claim: %v", err)
	}
	s, _ := fixture(t)
	if p, err := Resolve(s.Current(), in); !errors.Is(err, ErrNoRole) || p.BreakGlass {
		t.Errorf("the break-glass group as an OIDC claim, with a model: %+v, %v", p, err)
	}
}

func TestCapAndLegacyRoles(t *testing.T) {
	op := Principal{Name: "o", Source: SourceLocal, Permissions: BuiltinRoles[RoleOperator]}
	granted, refused := Cap(op, []string{"firewall:write", "routing:read", "system:write", "*:write"}, nil)
	if !reflect.DeepEqual(granted, []string{"firewall:write", "routing:read"}) || !reflect.DeepEqual(refused, []string{"system:write", "*:write"}) {
		t.Errorf("cap: granted %v refused %v", granted, refused)
	}
	// The built-in roles of the model map onto the old role names the
	// access manager still uses.
	for role, want := range map[string]auth.Role{RoleAdmin: auth.RoleAdmin, RoleOperator: auth.RoleOperator,
		RoleApprover: auth.RoleApprover, RoleReadOnly: auth.RoleViewer} {
		if got := (Principal{Permissions: BuiltinRoles[role]}).LegacyRole(); got != want {
			t.Errorf("role %s maps back to %s", role, got)
		}
	}
	s, _ := fixture(t)
	if left := MissingBuiltinRoles(s.Current()); len(left) != 0 {
		t.Errorf("built-in roles missing after seeding: %d", len(left))
	}
}
