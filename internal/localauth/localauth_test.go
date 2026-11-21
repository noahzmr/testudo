package localauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/secrets"
)

func setup(t *testing.T) (*confstore.State, secrets.Store, *model.User) {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	role, err := s.Create(context.Background(), "a", &model.Role{Meta: model.Meta{Name: "admin"}, Permissions: []string{"*:write"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []*model.User{
		{Meta: model.Meta{Name: "alice"}, Username: "alice", Source: "local", Roles: []model.Ref[model.Role]{{ID: role.GetMeta().ID}}},
		{Meta: model.Meta{Name: "alice-host"}, Username: "bob", Source: "host"},
	} {
		if _, err := s.Create(context.Background(), "a", u); err != nil {
			t.Fatal(err)
		}
	}
	u := Find(s.Current(), "alice")
	if u == nil || Find(s.Current(), "bob") != nil {
		t.Fatal("Find returns only local users by name")
	}
	return s.Current(), secrets.Store{Dir: t.TempDir()}, u
}

func TestPasswordAndCode(t *testing.T) {
	st, sec, u := setup(t)
	now := time.Now()
	if _, err := Authenticate(st, sec, "alice", "anything", "", now); !errors.Is(err, ErrInvalid) {
		t.Errorf("without a password set: %v", err)
	}
	if err := SetPassword(sec, u.ID, "short"); err == nil {
		t.Error("a short password was accepted")
	}
	if err := SetPassword(sec, u.ID, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(st, sec, "alice", "correct horse battery", "", now); err != nil {
		t.Errorf("right password: %v", err)
	}
	for _, tc := range []struct{ name, pw string }{{"alice", "wrong"}, {"nobody", "correct horse battery"}, {"bob", "correct horse battery"}} {
		if _, err := Authenticate(st, sec, tc.name, tc.pw, "", now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s/%s: %v", tc.name, tc.pw, err)
		}
	}
	if _, err := EnrollTOTP(sec, u, "Testudo"); err != nil {
		t.Fatal(err)
	}
	if !MFAEnrolled(sec, u.ID) {
		t.Fatal("not enrolled")
	}
	if _, err := Authenticate(st, sec, "alice", "correct horse battery", "", now); !errors.Is(err, ErrTOTPRequired) {
		t.Errorf("no code: %v", err)
	}
	secret, _ := sec.Get(TOTPEntry(u.ID))
	code, _ := auth.TOTPCode(string(secret), now)
	if _, err := Authenticate(st, sec, "alice", "correct horse battery", code, now); err != nil {
		t.Errorf("right code: %v", err)
	}
	if _, err := Authenticate(st, sec, "alice", "correct horse battery", "000000", now); !errors.Is(err, ErrInvalid) && code != "000000" {
		t.Errorf("wrong code: %v", err)
	}
	if err := DisableTOTP(sec, u.ID); err != nil || MFAEnrolled(sec, u.ID) {
		t.Errorf("disable: %v", err)
	}
	Forget(sec, u.ID)
	if HasPassword(sec, u.ID) {
		t.Error("secrets left after Forget")
	}
}

func TestDisabledUser(t *testing.T) {
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.Create(context.Background(), "a", &model.User{Meta: model.Meta{Name: "carol"}, Username: "carol", Source: "local", Disabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sec := secrets.Store{Dir: t.TempDir()}
	_ = SetPassword(sec, u.GetMeta().ID, "correct horse battery")
	if _, err := Authenticate(s.Current(), sec, "carol", "correct horse battery", "", time.Now()); !errors.Is(err, ErrDisabled) {
		t.Errorf("disabled, right password: %v", err)
	}
	if _, err := Authenticate(s.Current(), sec, "carol", "wrong password", "", time.Now()); !errors.Is(err, ErrInvalid) {
		t.Errorf("disabled, wrong password: %v", err)
	}
	if err := SetHash(sec, "x", "not-a-hash"); err == nil {
		t.Error("a non-bcrypt hash was accepted")
	}
}

func TestNewPassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := NewPassword()
		if err != nil || len(p) != 16 || seen[p] {
			t.Fatalf("%q %v", p, err)
		}
		seen[p] = true
	}
}
