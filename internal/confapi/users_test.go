package confapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/localauth"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/secrets"
)

func TestLocalUserCredentials(t *testing.T) {
	r := newRig(t)
	api := r.srv.Config.Handler.(*Server)
	sec := secrets.Store{Dir: t.TempDir()}
	api.LocalSecrets = sec
	var audited []string
	api.AuditWrite = func(actor, op, args string, err error) { audited = append(audited, actor+" "+op+" "+args) }
	local, err := r.store.Create(context.Background(), "a", &model.User{Meta: model.Meta{Name: "carol"}, Username: "carol", Source: "local"})
	if err != nil {
		t.Fatal(err)
	}
	host, err := r.store.Create(context.Background(), "a", &model.User{Meta: model.Meta{Name: "dave"}, Username: "dave", Source: "host"})
	if err != nil {
		t.Fatal(err)
	}
	id := local.GetMeta().ID
	if res := r.do("viewer", "POST", "/api/v1/users/"+id+"/password", map[string]string{"password": "a long password"}); res.status != 403 {
		t.Errorf("viewer sets a password: %d", res.status)
	}
	if res := r.do("admin", "POST", "/api/v1/users/"+id+"/password", map[string]string{"password": "short"}); res.status != 422 {
		t.Errorf("short password: %d %s", res.status, res.body)
	}
	if res := r.do("admin", "POST", "/api/v1/users/"+host.GetMeta().ID+"/password", map[string]string{"password": "a long password"}); res.status != 409 {
		t.Errorf("password for a host user: %d", res.status)
	}
	if res := r.do("admin", "POST", "/api/v1/users/"+id+"/password", map[string]string{"password": "a long password"}); res.status != 204 {
		t.Fatalf("set password: %d %s", res.status, res.body)
	}
	if _, err := localauth.Authenticate(r.store.Current(), sec, "carol", "a long password", "", time.Now()); err != nil {
		t.Errorf("the new password does not work: %v", err)
	}
	res := r.do("admin", "POST", "/api/v1/users/"+id+"/totp", nil)
	if res.status != 201 || !strings.HasPrefix(res.json(t)["otpauth"].(string), "otpauth://totp/") {
		t.Fatalf("enroll: %d %s", res.status, res.body)
	}
	cred := r.do("viewer", "GET", "/api/v1/users/"+id+"/credentials", nil).json(t)
	if cred["password"] != true || cred["mfa"] != true {
		t.Errorf("credentials: %v", cred)
	}
	if res := r.do("admin", "DELETE", "/api/v1/users/"+id+"/totp", nil); res.status != 204 || localauth.MFAEnrolled(sec, id) {
		t.Errorf("disable: %d", res.status)
	}
	// Nothing secret in the audit rows or in the model.
	for _, a := range audited {
		if strings.Contains(a, "long password") || strings.Contains(a, "$2a$") {
			t.Errorf("audit row carries a secret: %s", a)
		}
	}
	// The refused short password is audited too.
	if len(audited) != 4 {
		t.Errorf("audit rows: %v", audited)
	}
	snap := r.do("admin", "GET", "/api/v1/users/"+id, nil)
	if strings.Contains(string(snap.body), "$2a$") {
		t.Error("the model carries the hash")
	}
}
