package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/localauth"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/secrets"
)

// LocalSecrets is where local users' password hashes and second factors
// are kept: the node's secret store, which a cluster replicates.
func (e *Engine) LocalSecrets() localauth.Secrets { return e.conf.secrets }

// SessionStore is where console sessions are kept: the secret store, which
// a cluster replicates. ok is false without a configuration model.
func (e *Engine) SessionStore() (secrets.Store, bool) {
	return e.conf.secrets, e.conf.secrets.Dir != ""
}

// LeadsCluster reports whether this node does the cluster-wide chores: it
// leads its cluster, or it has none.
func (e *Engine) LeadsCluster() bool {
	m := e.cluster.mgr
	return m == nil || !m.Member() || (m.Node() != nil && m.Node().IsLeader())
}

// FirstRunPassword is the password of the administrator this start created,
// or "". It is shown once.
func (e *Engine) FirstRunPassword() string { return e.firstPassword }

// legacyRoles maps the roles of the old user store to built-in roles.
var legacyRoles = map[auth.Role]string{auth.RoleAdmin: identity.RoleAdmin, auth.RoleOperator: identity.RoleOperator,
	auth.RoleApprover: identity.RoleApprover, auth.RoleViewer: identity.RoleReadOnly}

var objName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// prepareLocalUsers moves the accounts of the old user store (users.json)
// into the model, once, and gives a node without any local user its first
// administrator. Both are changes of the system, like the built-in roles,
// so a fresh node can still join a cluster.
func (e *Engine) prepareLocalUsers(ctx context.Context) {
	c := &e.conf
	if c.apply == nil {
		return
	}
	if _, pending := c.apply.Pending(); pending {
		return
	}
	path := filepath.Join(e.cfg.StorageDir, "users.json")
	if _, err := os.Stat(path); err == nil {
		if err := e.migrateUserFile(ctx, path); err != nil {
			log.Printf("config: moving %s into the model: %v", path, err)
		}
	}
	if e.cluster.mgr != nil && e.cluster.mgr.Member() {
		return // the cluster's model has its users
	}
	st := c.store.Current()
	for _, obj := range st.List(model.KindUser) {
		if obj.(*model.User).Source == "local" {
			return
		}
	}
	pw, err := localauth.NewPassword()
	if err != nil {
		log.Printf("config: first administrator: %v", err)
		return
	}
	u := &model.User{Meta: model.Meta{ID: confstore.NewID(), Name: "testudo", Description: "First administrator"},
		Username: "testudo", Source: "local", Roles: roleRefs(st, identity.RoleAdmin)}
	if err := localauth.SetPassword(c.secrets, u.ID, pw); err != nil {
		log.Printf("config: first administrator: %v", err)
		return
	}
	if err := e.systemCreate(ctx, "first administrator", u); err != nil {
		log.Printf("config: first administrator: %v", err)
		localauth.Forget(c.secrets, u.ID)
		return
	}
	e.firstPassword = pw
}

func roleRefs(st *confstore.State, names ...string) []model.Ref[model.Role] {
	var out []model.Ref[model.Role]
	for _, n := range names {
		for _, obj := range st.List(model.KindRole) {
			if obj.GetMeta().Name == n {
				out = append(out, model.Ref[model.Role]{ID: obj.GetMeta().ID})
			}
		}
	}
	return out
}

// migrateUserFile creates a local user for every account of users.json the
// model does not have yet, with its password hash and second factor, and
// keeps the file as users.json.migrated.
func (e *Engine) migrateUserFile(ctx context.Context, path string) error {
	old, err := auth.ReadFile(path)
	if err != nil {
		return err
	}
	st := e.conf.store.Current()
	var created []model.Entity
	type creds struct{ hash, totp string }
	secrets := map[string]creds{}
	for _, u := range old {
		if localauth.Find(st, u.Name) != nil {
			continue
		}
		if u.Hash == "" {
			return fmt.Errorf("user %q has no password hash; %s is left as it is", u.Name, path)
		}
		if !objName.MatchString(u.Name) {
			log.Printf("config: user %q from %s has a name the model does not take; create it again", u.Name, path)
			continue
		}
		role := legacyRoles[u.Role]
		if role == "" {
			role = identity.RoleReadOnly
		}
		m := &model.User{Meta: model.Meta{ID: confstore.NewID(), Name: u.Name, Description: "Moved from users.json"},
			Username: u.Name, Source: "local", Roles: roleRefs(st, role), Disabled: u.Disabled}
		created = append(created, m)
		secrets[m.ID] = creds{u.Hash, u.TOTPSecret}
	}
	// The secrets go first, so the accounts work as soon as they exist.
	for id, c := range secrets {
		if c.hash != "" {
			if err := localauth.SetHash(e.conf.secrets, id, c.hash); err != nil {
				return err
			}
		}
		if c.totp != "" {
			if err := localauth.SetTOTPSecret(e.conf.secrets, id, c.totp); err != nil {
				return err
			}
		}
	}
	if len(created) > 0 {
		if err := e.systemCreate(ctx, "users moved from users.json", created...); err != nil {
			for id := range secrets {
				localauth.Forget(e.conf.secrets, id)
			}
			return err
		}
		log.Printf("config: moved %d user(s) from %s into the model", len(created), path)
	}
	return os.Rename(path, path+".migrated")
}

// systemCreate applies and confirms objects as the system.
func (e *Engine) systemCreate(ctx context.Context, reason string, objs ...model.Entity) error {
	var ops []confstore.Op
	for _, o := range objs {
		raw, err := json.Marshal(o)
		if err != nil {
			return err
		}
		ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: o.Kind(), ID: o.GetMeta().ID, Object: raw})
	}
	if e.conf.apply == nil {
		return errors.New("the configuration model is unavailable")
	}
	if _, err := e.conf.apply.Apply(ctx, "system", reason, ops); err != nil {
		return err
	}
	return e.conf.apply.Confirm("system")
}

// forgetDeletedUsers removes the password hashes and second factors of
// local users that are no longer in the model. In a cluster the leader does
// it, once for everyone.
func (e *Engine) forgetDeletedUsers() {
	if e.conf.store == nil {
		return
	}
	if m := e.cluster.mgr; m != nil && m.Member() && (m.Node() == nil || !m.Node().IsLeader()) {
		return
	}
	names, err := e.conf.secrets.List()
	if err != nil {
		return
	}
	st := e.conf.store.Current()
	for _, n := range names {
		id, ok := userOfEntry(n)
		if !ok {
			continue
		}
		if _, exists := st.Get(model.KindUser, id); !exists {
			_ = e.conf.secrets.Delete(n)
		}
	}
}

// userOfEntry returns the user id in a secret's name ("user-<id>-password").
func userOfEntry(name string) (string, bool) {
	for _, suffix := range []string{"-password", "-totp"} {
		if len(name) == len("user-")+36+len(suffix) && name[:5] == "user-" && name[len(name)-len(suffix):] == suffix {
			return name[5 : 5+36], true
		}
	}
	return "", false
}
