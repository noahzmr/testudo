package web

import (
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/secrets"
)

// member is a web server on top of a secret store; two members on the same
// directory stand in for two cluster members whose stores are replicated.
func member(dir string) *Server {
	return &Server{sessions: map[string]*sessionRecord{}, shared: &shared{sec: secrets.Store{Dir: dir}}}
}

func TestSessionsAreSharedByMembers(t *testing.T) {
	dir := t.TempDir()
	a, b := member(dir), member(dir)
	// A login whose principal needs no model: the host's break-glass group.
	login := &identity.Login{Source: identity.SourcePAM, Username: "root", Groups: []string{identity.BreakGlassGroup}}
	rec := &sessionRecord{user: "root", login: login, expiresAt: time.Now().Add(time.Hour)}
	sid := newSessionID()
	if err := a.saveSession(sid, rec); err != nil {
		t.Fatal(err)
	}
	got := b.loadSession(sid)
	if got == nil || !got.principal.BreakGlass || got.user != "root" {
		t.Fatalf("the other member: %+v", got)
	}
	// Grants hang on the session and go with it.
	_ = a.shared.put(grantEntry+newSessionID(), accessPass{SID: sid, Host: "app.example.com", Expires: time.Now().Add(time.Hour)})
	other := newSessionID()
	_ = a.shared.put(grantEntry+newSessionID(), accessPass{SID: other, Host: "app.example.com", Expires: time.Now().Add(time.Hour)})
	a.endSession(sid)
	if b.loadSession(sid) != nil {
		t.Error("a session ended on one member lives on on the other")
	}
	if n := len(b.shared.names(grantEntry)); n != 1 {
		t.Errorf("grants left: %d, want the other session's only", n)
	}
	// What a visitor sends cannot name another entry.
	for _, bad := range []string{"", "../../etc/passwd", "short", sid + "x"} {
		if b.loadSession(bad) != nil {
			t.Errorf("session %q", bad)
		}
	}
}

func TestExpiredEntriesAreCollected(t *testing.T) {
	dir := t.TempDir()
	a := member(dir)
	old, fresh := newSessionID(), newSessionID()
	login := &identity.Login{Source: identity.SourcePAM, Username: "root", Groups: []string{identity.BreakGlassGroup}}
	_ = a.saveSession(old, &sessionRecord{user: "root", login: login, expiresAt: time.Now().Add(-time.Minute)})
	_ = a.saveSession(fresh, &sessionRecord{user: "root", login: login, expiresAt: time.Now().Add(time.Hour)})
	_ = a.shared.put(ticketEntry+newSessionID(), accessPass{Expires: time.Now().Add(-time.Second)})
	a.gcShared(false)
	if len(a.shared.names(sessionEntry)) != 2 {
		t.Error("a member that does not lead removed shared entries")
	}
	a.gcShared(true)
	if names := a.shared.names(""); len(names) != 1 || names[0] != sessionEntry+fresh {
		t.Errorf("after collection: %v", names)
	}
}
