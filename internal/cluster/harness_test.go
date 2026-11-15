package cluster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/secrets"
)

var ctx = context.Background()

// net is the test network: every connection between members goes through
// it, so links can be cut and restored.
type network struct {
	mu      sync.Mutex
	owner   map[string]string          // transport address -> member id
	blocked map[string]map[string]bool // from id -> to id
	conns   map[*tracked]struct{}
}

type tracked struct {
	net.Conn
	n *network
}

func (c *tracked) Close() error {
	c.n.mu.Lock()
	delete(c.n.conns, c)
	c.n.mu.Unlock()
	return c.Conn.Close()
}

func newNetwork() *network {
	return &network{owner: map[string]string{}, blocked: map[string]map[string]bool{}, conns: map[*tracked]struct{}{}}
}

func (n *network) track(c net.Conn) net.Conn {
	t := &tracked{Conn: c, n: n}
	n.mu.Lock()
	n.conns[t] = struct{}{}
	n.mu.Unlock()
	return t
}

func (n *network) dialer(from string) func(string, time.Duration) (net.Conn, error) {
	return func(addr string, timeout time.Duration) (net.Conn, error) {
		n.mu.Lock()
		cut := n.blocked[from][n.owner[addr]]
		n.mu.Unlock()
		if cut {
			return nil, errors.New("link is cut")
		}
		c, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return nil, err
		}
		return n.track(c), nil
	}
}

// partition splits the members into groups that cannot reach each other.
// Existing connections are closed; within a group they are made again.
func (n *network) partition(groups ...[]string) {
	side := map[string]int{}
	for i, g := range groups {
		for _, id := range g {
			side[id] = i
		}
	}
	n.mu.Lock()
	n.blocked = map[string]map[string]bool{}
	for a, sa := range side {
		n.blocked[a] = map[string]bool{}
		for b, sb := range side {
			if sa != sb {
				n.blocked[a][b] = true
			}
		}
	}
	conns := make([]*tracked, 0, len(n.conns))
	for c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func (n *network) heal() { n.partition() }

// member is a node with everything it owns.
type member struct {
	id    string
	dir   string
	addr  string
	node  *Node
	store *confstore.Store
	sec   secrets.Store
	key   []byte
}

type cluster struct {
	t   *testing.T
	net *network
	// mu guards members and each member's node and store, which a test's
	// background writer reads while the test starts and stops members.
	mu      sync.Mutex
	members map[string]*member
	key     []byte
	// opts lets a test change a member's options before it is opened.
	opts func(id string, o *Options)
}

func newCluster(t *testing.T) *cluster {
	key, _ := NewKey()
	return &cluster{t: t, net: newNetwork(), members: map[string]*member{}, key: key}
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// start opens (or reopens) a member.
func (c *cluster) start(id string) *member {
	c.t.Helper()
	c.mu.Lock()
	m := c.members[id]
	if m == nil {
		m = &member{id: id, dir: c.t.TempDir(), addr: freeAddr(c.t), key: c.key}
		c.members[id] = m
	}
	c.mu.Unlock()
	{
		c.net.mu.Lock()
		c.net.owner[m.addr] = id
		c.net.mu.Unlock()
	}
	store, err := confstore.Open(filepath.Join(m.dir, "config"))
	if err != nil {
		c.t.Fatal(err)
	}
	sec := secrets.Store{Dir: filepath.Join(m.dir, "secrets")}
	opt := Options{ID: id, Dir: filepath.Join(m.dir, "raft"), Bind: m.addr, Store: store, Secrets: sec,
		Key:       func() []byte { return m.key },
		Heartbeat: 150 * time.Millisecond, Election: 150 * time.Millisecond, LeaderLease: 100 * time.Millisecond,
		dial: c.net.dialer(id), wrap: c.net.track}
	if c.opts != nil {
		c.opts(id, &opt)
	}
	node, err := Open(opt)
	if err != nil {
		c.t.Fatal(err)
	}
	store.SetReplicator(node)
	c.mu.Lock()
	m.store, m.sec, m.node = store, sec, node
	c.mu.Unlock()
	c.t.Cleanup(func() { c.stop(id) })
	return m
}

func (c *cluster) stop(id string) {
	c.mu.Lock()
	m := c.members[id]
	if m == nil || m.node == nil {
		c.mu.Unlock()
		return
	}
	node, store := m.node, m.store
	m.node = nil
	c.mu.Unlock()
	node.Shutdown()
	store.Close()
}

// running returns the members that are up, as copies that stay valid
// while the test goes on starting and stopping members.
func (c *cluster) running() []member {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []member
	for _, m := range c.members {
		if m.node != nil {
			out = append(out, *m)
		}
	}
	return out
}

// leader waits for a leader among the given members (all running ones when
// none are named) and returns it.
func (c *cluster) leader(among ...string) *member {
	c.t.Helper()
	want := map[string]bool{}
	for _, id := range among {
		want[id] = true
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		for _, m := range c.running() {
			if (len(want) == 0 || want[m.id]) && m.node.IsLeader() {
				c.mu.Lock()
				real := c.members[m.id]
				c.mu.Unlock()
				return real
			}
		}
	}
	c.t.Fatalf("no leader among %v", among)
	return nil
}

// form starts n members and makes them one cluster of voters.
func (c *cluster) form(ids ...string) {
	c.t.Helper()
	first := c.start(ids[0])
	if err := first.node.Bootstrap(ctx); err != nil {
		c.t.Fatal(err)
	}
	if err := first.node.Announce(Member{Voter: true}); err != nil {
		c.t.Fatal(err)
	}
	for _, id := range ids[1:] {
		c.join(id, true)
	}
}

// join starts a member and admits it; voter also promotes it.
func (c *cluster) join(id string, voter bool) *member {
	c.t.Helper()
	m := c.start(id)
	l := c.leader()
	if err := l.node.Add(id, m.addr); err != nil {
		c.t.Fatalf("add %s: %v", id, err)
	}
	c.announce(m, voter)
	if voter {
		if err := c.leader().node.Promote(id); err != nil {
			c.t.Fatalf("promote %s: %v", id, err)
		}
	}
	return m
}

// announce has the leader publish a member's build: in the daemon the
// member asks the leader to, over the member API.
func (c *cluster) announce(m *member, voter bool) {
	c.t.Helper()
	cmd, _ := command(CmdMember, "", Member{ID: m.id, Schema: model.SchemaVersion, Raft: m.addr, Voter: voter, Commands: Supported})
	if err := c.leader().node.Propose(ctx, cmd); err != nil {
		c.t.Fatalf("announce %s: %v", m.id, err)
	}
}

func alias(name string) *model.Alias {
	return &model.Alias{Meta: model.Meta{Name: name}, Type: "host", Entries: []string{"192.0.2.1"}}
}

// write creates an alias through a member's store.
func (m *member) write(name string) error {
	_, err := m.store.Create(ctx, "test", alias(name))
	return err
}

// names returns the alias names a member holds, as a set.
func (m *member) names() map[string]bool {
	out := map[string]bool{}
	for _, e := range m.store.Current().List(model.KindAlias) {
		out[e.GetMeta().Name] = true
	}
	return out
}

// converge waits until the named members hold the same model at index.
func (c *cluster) converge(index int64, ids ...string) {
	c.t.Helper()
	var got []string
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		got = got[:0]
		ok := true
		for _, id := range ids {
			i := c.members[id].store.Current().Index()
			got = append(got, fmt.Sprintf("%s=%d", id, i))
			ok = ok && i == index
		}
		if ok {
			return
		}
	}
	c.t.Fatalf("members did not reach record %d: %v", index, got)
}

// same fails unless the named members hold exactly the same objects in the
// same versions.
func (c *cluster) same(ids ...string) {
	c.t.Helper()
	ref := c.members[ids[0]].store.Snapshot()
	for _, id := range ids[1:] {
		got := c.members[id].store.Snapshot()
		if got.Index != ref.Index || fmt.Sprint(got.Objects) != fmt.Sprint(ref.Objects) {
			c.t.Fatalf("%s and %s differ: index %d vs %d", ids[0], id, ref.Index, got.Index)
		}
	}
}

// leaderErr returns the current leader without waiting.
func (c *cluster) leaderErr() (*member, error) {
	for _, m := range c.running() {
		if m.node.IsLeader() {
			c.mu.Lock()
			real := c.members[m.id]
			c.mu.Unlock()
			return real, nil
		}
	}
	return nil, ErrNoQuorum
}

// forgeToken encodes a token body, for tests that tamper with one.
func forgeToken(b tokenBody) string {
	body, _ := json.Marshal(b)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(body)
}
