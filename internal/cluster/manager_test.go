package cluster

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/secrets"
)

// box is a node as the daemon sets it up: store, secrets, manager.
type box struct {
	id    string
	dir   string
	store *confstore.Store
	sec   secrets.Store
	mgr   *Manager
	cfg   Config
	// forwarded records what reached this node as the leader.
	forwarded []string
}

func newBox(t *testing.T, id string, tune ...func(*Config)) *box {
	t.Helper()
	b := &box{id: id, dir: t.TempDir()}
	b.cfg = Config{ID: id, Name: "node-" + id, Dir: filepath.Join(b.dir, "cluster"), RaftBind: freeAddr(t), APIBind: freeAddr(t),
		Build: "test", Heartbeat: 150 * time.Millisecond, Election: 150 * time.Millisecond, LeaderLease: 100 * time.Millisecond}
	for _, f := range tune {
		f(&b.cfg)
	}
	b.up(t)
	return b
}

// up opens the node's store and manager (again, after down).
func (b *box) up(t *testing.T) {
	t.Helper()
	store, err := confstore.Open(filepath.Join(b.dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	b.store, b.sec = store, secrets.Store{Dir: filepath.Join(b.dir, "secrets")}
	cfg := b.cfg
	cfg.Store, cfg.Secrets = store, b.sec
	cfg.Forwarded = func(w http.ResponseWriter, r *http.Request, identity string) {
		b.forwarded = append(b.forwarded, r.Method+" "+r.URL.RequestURI()+" as "+identity)
		fmt.Fprintf(w, "served by %s", b.id)
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatal(err)
	}
	b.mgr = mgr
	t.Cleanup(b.down)
}

func (b *box) down() {
	if b.mgr != nil {
		b.mgr.Close()
		b.store.Close()
		b.mgr = nil
	}
}

func wait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("never: %s", what)
}

func leaderOf(t *testing.T, boxes ...*box) *box {
	t.Helper()
	var l *box
	wait(t, "a leader", func() bool {
		for _, b := range boxes {
			if n := b.mgr.Node(); n != nil && n.IsLeader() {
				l = b
				return true
			}
		}
		return false
	})
	return l
}

func voters(b *box) int {
	servers, _ := b.mgr.Node().Servers()
	n := 0
	for _, s := range servers {
		if s.Voter {
			n++
		}
	}
	return n
}

// trio forms a cluster of three voters over TLS, the way an operator does:
// init on one node, a token for each of the others.
func trio(t *testing.T, tune ...func(*Config)) (a, b, c *box) {
	t.Helper()
	a, b, c = newBox(t, "a", tune...), newBox(t, "b", tune...), newBox(t, "c", tune...)
	if err := a.mgr.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*box{b, c} {
		tok, err := a.mgr.NewToken(time.Minute, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.mgr.Join(ctx, tok); err != nil {
			t.Fatalf("join %s: %v", n.id, err)
		}
	}
	wait(t, "three voters", func() bool { return voters(a) == 3 })
	return a, b, c
}

func TestJoinWithTokenAndMutualTLS(t *testing.T) {
	a, b, c := trio(t)
	// A model made on the first node is on the others.
	if _, err := a.store.Create(ctx, "alice", alias("one")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*box{b, c} {
		wait(t, n.id+" has the model", func() bool { return n.store.Current().Index() == 1 })
	}
	// Each member has its own key and certificate, the cluster key, and
	// the authority (sealed in the log, opened locally).
	for _, n := range []*box{a, b, c} {
		for _, e := range []string{entryNodeKey, entryNodeCert, entryKey, entryCACert, entryCAKey} {
			n := n
			wait(t, n.id+" has "+e, func() bool { return n.sec.Has(e) })
		}
	}
	ka, _ := a.sec.Get(entryNodeKey)
	kb, _ := b.sec.Get(entryNodeKey)
	if string(ka) == string(kb) {
		t.Error("two members share a private key")
	}
	st := a.mgr.Node().State()
	for _, id := range []string{"a", "b", "c"} {
		m := st.Members[id]
		if m.API == "" || m.Serial == "" || m.Commands[CmdRecord] != 1 || m.Schema != model.SchemaVersion {
			t.Errorf("member %s is announced as %+v", id, m)
		}
	}
	if len(st.Tokens) != 0 {
		t.Errorf("used tokens are still there: %v", st.Tokens)
	}

	// A token works once.
	tok, _ := a.mgr.NewToken(time.Minute, false)
	d := newBox(t, "d")
	if err := d.mgr.Join(ctx, tok); err != nil {
		t.Fatal(err)
	}
	e := newBox(t, "e")
	if err := e.mgr.Join(ctx, tok); err == nil || !strings.Contains(err.Error(), "used or expired") {
		t.Errorf("second use of a token: %v", err)
	}
	// It was for a non-voter: the member gets the model and no vote.
	wait(t, "d has the model", func() bool { return d.store.Current().Index() == 1 })
	time.Sleep(3 * time.Second) // longer than the promotion loop
	if voters(a) != 3 {
		t.Errorf("a non-voter token made a voter: %d voters", voters(a))
	}
	// An expired token, a made-up one, and one that is not a token.
	old, _ := a.mgr.NewToken(-time.Second, true)
	for name, bad := range map[string]string{"expired": old, "garbage": "tdj1.AAAA", "not a token": "hello"} {
		if err := e.mgr.Join(ctx, bad); err == nil {
			t.Errorf("join with a token that is %s succeeded", name)
		}
	}
	if e.mgr.Member() || e.sec.Has(entryKey) {
		t.Error("a refused node holds cluster material")
	}
	// A node with a model of its own does not join.
	f := newBox(t, "f")
	f.store.Create(ctx, "x", alias("mine"))
	tok2, _ := a.mgr.NewToken(time.Minute, true)
	if err := f.mgr.Join(ctx, tok2); err == nil || !strings.Contains(err.Error(), "joins empty") {
		t.Errorf("join with an existing model: %v", err)
	}
}

func TestJoinerChecksWhoItTalksTo(t *testing.T) {
	a := newBox(t, "a")
	if err := a.mgr.Init(ctx); err != nil {
		t.Fatal(err)
	}
	other := newBox(t, "other")
	if err := other.mgr.Init(ctx); err != nil {
		t.Fatal(err)
	}
	// A token for cluster a, pointed at another cluster's member: the
	// joiner must notice before it sends its token.
	tok, _ := a.mgr.NewToken(time.Minute, true)
	body, _ := parseToken(tok)
	body.API = other.cfg.APIBind
	forged := forgeToken(body)
	j := newBox(t, "j")
	err := j.mgr.Join(ctx, forged)
	if err == nil || !strings.Contains(err.Error(), "not the cluster this token is for") {
		t.Fatalf("join against the wrong cluster: %v", err)
	}
	// The real token still works: it never left.
	if err := j.mgr.Join(ctx, tok); err != nil {
		t.Fatalf("join after the detour: %v", err)
	}
}

func TestOnlyMembersGetIn(t *testing.T) {
	a, b, c := trio(t)
	l := leaderOf(t, a, b, c)
	// Without a certificate the member API answers nothing but join.
	anon := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for _, path := range []string{"/cluster/v1/propose", "/cluster/v1/renew", "/cluster/v1/forward/api/v1/zones"} {
		res, err := anon.Post("https://"+l.cfg.APIBind+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a certificate: %d", path, res.StatusCode)
		}
	}
	// The consensus transport does not even finish the handshake.
	conn, err := tls.Dial("tcp", l.cfg.RaftBind, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, werr := conn.Write([]byte{0})
		buf := make([]byte, 1)
		_, rerr := conn.Read(buf)
		conn.Close()
		if werr == nil && rerr == nil {
			t.Error("the consensus transport talks to a stranger")
		}
	}
	// A certificate from another cluster's authority is a stranger's.
	other := newBox(t, "z")
	if err := other.mgr.Init(ctx); err != nil {
		t.Fatal(err)
	}
	foreign := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: other.mgr.clientTLS()}}
	if res, err := foreign.Post("https://"+l.cfg.APIBind+"/cluster/v1/propose", "application/json", strings.NewReader("{}")); err == nil {
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("a member of another cluster got %d", res.StatusCode)
		}
	}

	// A member may report for itself and for nobody else.
	var follower *box
	for _, n := range []*box{a, b, c} {
		if n != l {
			follower = n
			break
		}
	}
	if err := follower.mgr.SendResult(Result{Node: follower.id, Index: 1, OK: true}); err != nil {
		t.Errorf("a member's own report: %v", err)
	}
	if err := follower.mgr.SendResult(Result{Node: l.id, Index: 1, OK: false, Error: "made up"}); err == nil {
		t.Error("a member reported for another")
	}
	rec, _ := command(CmdRecord, "", RecordEntry{})
	if err := follower.mgr.send(ctx, "/cluster/v1/propose", rec, nil); err == nil {
		t.Error("a follower proposed a record through the member API")
	}
}

func TestRemovedMemberIsLockedOut(t *testing.T) {
	a, b, c := trio(t)
	l := leaderOf(t, a, b, c)
	var gone *box
	for _, n := range []*box{a, b, c} {
		if n != l {
			gone = n
			break
		}
	}
	serial := l.mgr.Node().State().Members[gone.id].Serial
	if err := l.mgr.Remove(gone.id); err != nil {
		t.Fatal(err)
	}
	wait(t, "the certificate is revoked", func() bool {
		_, ok := l.mgr.Node().State().Revoked[serial]
		return ok
	})
	// The removed node still has its key and certificate. They open
	// nothing any more.
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: gone.mgr.clientTLS()}}
	res, err := hc.Post("https://"+l.cfg.APIBind+"/cluster/v1/propose", "application/json", strings.NewReader("{}"))
	if err == nil {
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("a removed member's certificate got %d", res.StatusCode)
		}
	}
	// The cluster goes on with two.
	if _, err := l.store.Create(ctx, "alice", alias("after")); err != nil {
		t.Fatalf("write after the removal: %v", err)
	}
	if n := gone.store.Current().Index(); n != 0 {
		// It may have received earlier records; it must not get new ones.
		time.Sleep(500 * time.Millisecond)
		if gone.store.Current().Index() != n {
			t.Error("the removed member still receives the model")
		}
	}
}

func TestWritesAreForwardedToTheLeader(t *testing.T) {
	a, b, c := trio(t)
	l := leaderOf(t, a, b, c)
	var follower *box
	for _, n := range []*box{a, b, c} {
		if n != l {
			follower = n
			break
		}
	}
	req := httptest.NewRequest("POST", "/api/v1/zones?changeset=x", strings.NewReader(`{"name":"wan"}`))
	req.Header.Set("Cookie", "testudo_sid=secret-session")
	req.Header.Set("Authorization", "Bearer tdo_secret")
	rec := httptest.NewRecorder()
	follower.mgr.Forward(rec, req, `{"name":"alice","permissions":["firewall:write"]}`)
	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != 200 || string(body) != "served by "+l.id {
		t.Fatalf("forwarded request: %d %q", rec.Code, body)
	}
	want := `POST /api/v1/zones?changeset=x as {"name":"alice","permissions":["firewall:write"]}`
	if len(l.forwarded) != 1 || l.forwarded[0] != want {
		t.Fatalf("the leader saw %q", l.forwarded)
	}
	// The identity cannot be claimed from outside the cluster, and the
	// session's own credentials do not travel.
	anon := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	r2, _ := http.NewRequest("POST", "https://"+l.cfg.APIBind+"/cluster/v1/forward/api/v1/zones", strings.NewReader("{}"))
	r2.Header.Set("X-Testudo-Identity", `{"name":"root","permissions":["*:write"]}`)
	if res, err := anon.Do(r2); err == nil {
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized || len(l.forwarded) != 1 {
			t.Errorf("identity claimed without a member certificate: %d", res.StatusCode)
		}
	}
	// A secret made on a follower reaches every member.
	if err := follower.mgr.PutSecret("oidc-9", []byte("s3cret"), false); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*box{a, b, c} {
		n := n
		wait(t, n.id+" has the secret", func() bool { v, _ := n.sec.Get("oidc-9"); return string(v) == "s3cret" })
	}
	// With the leader gone and no majority left, the member says so.
	for _, n := range []*box{a, b, c} {
		if n != follower {
			n.down()
		}
	}
	wait(t, "the member notices it is alone", func() bool { return follower.mgr.LeaderAPI() == "" })
	rec = httptest.NewRecorder()
	follower.mgr.Forward(rec, httptest.NewRequest("POST", "/api/v1/zones", strings.NewReader("{}")), "{}")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "read-only") {
		t.Errorf("forward without a leader: %d %s", rec.Code, rec.Body)
	}
}

func TestRenewalAndRestart(t *testing.T) {
	a, b, c := trio(t)
	l := leaderOf(t, a, b, c)
	var follower *box
	for _, n := range []*box{a, b, c} {
		if n != l {
			follower = n
			break
		}
	}
	for _, n := range []*box{follower, l} {
		before, _ := n.sec.Get(entryNodeCert)
		oldSerial := l.mgr.Node().State().Members[n.id].Serial
		if err := n.mgr.Renew(ctx); err != nil {
			t.Fatalf("renew on %s: %v", n.id, err)
		}
		after, _ := n.sec.Get(entryNodeCert)
		if string(before) == string(after) {
			t.Errorf("%s has the same certificate after renewing", n.id)
		}
		n := n
		wait(t, n.id+"'s new serial is announced", func() bool {
			s := l.mgr.Node().State().Members[n.id].Serial
			return s != "" && s != oldSerial
		})
	}
	// Everything still talks to everything.
	if _, err := l.store.Create(ctx, "alice", alias("after-renewal")); err != nil {
		t.Fatal(err)
	}
	wait(t, "the follower has it", func() bool { return follower.store.Current().Index() == 1 })
	// A member that restarts finds its place again without a token.
	follower.down()
	if _, err := l.store.Create(ctx, "alice", alias("while-away")); err != nil {
		t.Fatal(err)
	}
	follower.up(t)
	wait(t, "the restarted member caught up", func() bool { return follower.store.Current().Index() == 2 })
	// Whoever leads next can admit a member: the authority is everywhere.
	l.down()
	rest := []*box{a, b, c}
	for i, n := range rest {
		if n == l {
			rest = append(rest[:i], rest[i+1:]...)
			break
		}
	}
	next := leaderOf(t, rest...)
	tok, err := next.mgr.NewToken(time.Minute, false)
	if err != nil {
		t.Fatalf("token from the new leader: %v", err)
	}
	d := newBox(t, "d")
	if err := d.mgr.Join(ctx, tok); err != nil {
		t.Fatalf("join through the new leader: %v", err)
	}
	wait(t, "the new member has the model", func() bool { return d.store.Current().Index() == 2 })
}

// TestPartnerTakesTheVoteOfADeadVoter: three sites vote; the third site is
// an HA pair whose second node is a non-voter. When the pair's voter stays
// away, the leader hands the site's vote to the partner; when the old voter
// returns it stays a non-voter (ADR 0004).
func TestPartnerTakesTheVoteOfADeadVoter(t *testing.T) {
	var mu sync.Mutex
	var events []string
	tune := func(c *Config) {
		c.Partner = func(id string) string { return map[string]string{"c": "d", "d": "c"}[id] }
		c.FailoverAfter = time.Second
		c.FailedOver = func(dead, partner string) {
			mu.Lock()
			events = append(events, dead+"->"+partner)
			mu.Unlock()
		}
	}
	a, b, c := trio(t, tune)
	d := newBox(t, "d", tune)
	tok, err := a.mgr.NewToken(time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.mgr.Join(ctx, tok); err != nil {
		t.Fatal(err)
	}
	isVoter := func(from *box, id string) bool {
		servers, _ := from.mgr.Node().Servers()
		for _, s := range servers {
			if s.ID == id {
				return s.Voter
			}
		}
		return false
	}
	wait(t, "d announced as a non-voter", func() bool {
		m, ok := a.mgr.Node().State().Members["d"]
		return ok && m.Commands != nil && !isVoter(a, "d")
	})
	// The voter that fails must not be the leader itself.
	if l := leaderOf(t, a, b, c); l == c {
		if err := c.mgr.Node().TransferLeadership(); err != nil {
			t.Fatal(err)
		}
	}
	wait(t, "a leader other than c", func() bool {
		l := leaderOf(t, a, b, c)
		return l != c
	})
	c.down()
	l := leaderOf(t, a, b)
	wait(t, "d votes in c's place", func() bool { return isVoter(l, "d") && !isVoter(l, "c") && voters(l) == 3 })
	mu.Lock()
	if len(events) != 1 || events[0] != "c->d" {
		t.Errorf("failover events: %v", events)
	}
	mu.Unlock()
	if m := l.mgr.Node().State().Members; m["c"].Voter || !m["d"].Voter {
		t.Errorf("member list: c voter %v, d voter %v", m["c"].Voter, m["d"].Voter)
	}
	// The cluster still takes changes.
	if _, err := l.store.Create(ctx, "a", &model.Site{Meta: model.Meta{Name: "after-failover"}}); err != nil {
		t.Fatalf("write after failover: %v", err)
	}
	// c returns and catches up as a non-voter.
	c.up(t)
	want := l.store.Current().Index()
	wait(t, "c caught up", func() bool { return c.store.Current().Index() >= want })
	time.Sleep(time.Second)
	if isVoter(leaderOf(t, a, b, c, d), "c") {
		t.Errorf("the returning voter took its vote back")
	}
}
