package cluster

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

func TestWritesReachEveryMember(t *testing.T) {
	c := newCluster(t)
	c.form("a", "b", "c")
	l := c.leader()
	for i := 0; i < 5; i++ {
		if err := l.write(fmt.Sprintf("alias-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	c.converge(5, "a", "b", "c")
	c.same("a", "b", "c")
	// An object's version is the same number on every member.
	for _, id := range []string{"a", "b", "c"} {
		for _, e := range c.members[id].store.Current().List(model.KindAlias) {
			var n int64
			fmt.Sscanf(e.GetMeta().Name, "alias-%d", &n)
			if e.GetMeta().Version != n+1 {
				t.Errorf("%s: %s has version %d", id, e.GetMeta().Name, e.GetMeta().Version)
			}
		}
	}
	// A member that does not lead refuses to decide.
	for _, id := range []string{"a", "b", "c"} {
		if m := c.members[id]; m != l {
			if err := m.write("from-a-follower"); !errors.Is(err, ErrNotLeader) {
				t.Errorf("write on follower %s: %v", id, err)
			}
		}
	}
	// A change the model refuses is never proposed.
	if err := l.write("alias-0"); err == nil || l.store.Current().Index() != 5 {
		t.Errorf("duplicate name: %v", err)
	}
}

func TestLeaderLossLosesNothing(t *testing.T) {
	c := newCluster(t)
	c.form("a", "b", "c")
	old := c.leader()
	for i := 0; i < 3; i++ {
		if err := old.write(fmt.Sprintf("before-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	c.stop(old.id)
	var rest []string
	for id := range c.members {
		if id != old.id {
			rest = append(rest, id)
		}
	}
	next := c.leader(rest...)
	if err := next.write("after"); err != nil {
		t.Fatalf("write after the leader was lost: %v", err)
	}
	c.converge(4, rest...)
	c.same(rest...)
	// The old leader comes back as a follower and catches up.
	c.start(old.id)
	c.converge(4, old.id)
	c.same("a", "b", "c")
	if got := c.members[old.id].names(); !got["after"] || len(got) != 4 {
		t.Errorf("the returned member holds %v", got)
	}
}

func TestPartitionTwoToOne(t *testing.T) {
	c := newCluster(t)
	c.form("a", "b", "c")
	l := c.leader()
	if err := l.write("before"); err != nil {
		t.Fatal(err)
	}
	c.converge(1, "a", "b", "c")
	// Cut the leader off: it is the minority.
	var majority []string
	for id := range c.members {
		if id != l.id {
			majority = append(majority, id)
		}
	}
	c.net.partition([]string{l.id}, majority)
	next := c.leader(majority...)
	if err := next.write("majority"); err != nil {
		t.Fatalf("the majority cannot write: %v", err)
	}
	// The cut-off member, which was leader a moment ago, accepts nothing:
	// neither while it still thinks it leads nor after it noticed.
	for i := 0; i < 20; i++ {
		if err := l.write(fmt.Sprintf("minority-%d", i)); err == nil {
			t.Fatal("the minority accepted a write")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// It still has, and serves, what it had.
	if got := l.names(); !got["before"] || got["majority"] || len(got) != 1 {
		t.Errorf("the minority holds %v", got)
	}
	c.net.heal()
	c.converge(2, "a", "b", "c")
	c.same("a", "b", "c")
	for id, m := range c.members {
		for name := range m.names() {
			if strings.HasPrefix(name, "minority") {
				t.Errorf("%s holds %s, which nobody agreed on", id, name)
			}
		}
	}
	if err := c.leader().write("after-heal"); err != nil {
		t.Errorf("write after the partition healed: %v", err)
	}
}

func TestPartitionOneOneOne(t *testing.T) {
	c := newCluster(t)
	c.form("a", "b", "c")
	if err := c.leader().write("before"); err != nil {
		t.Fatal(err)
	}
	c.converge(1, "a", "b", "c")
	c.net.partition([]string{"a"}, []string{"b"}, []string{"c"})
	// Nobody has a majority, so nobody decides.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for id, m := range c.members {
			if err := m.write("alone-" + id); err == nil {
				t.Fatalf("%s accepted a write on its own", id)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	for id, m := range c.members {
		if got := m.names(); len(got) != 1 || !got["before"] {
			t.Errorf("%s holds %v", id, got)
		}
	}
	c.net.heal()
	l := c.leader()
	if err := l.write("after-heal"); err != nil {
		t.Fatalf("write after the partition healed: %v", err)
	}
	c.converge(l.store.Current().Index(), "a", "b", "c")
	c.same("a", "b", "c")
	// A write that was refused during the partition may still have been in
	// the old leader's log, and is agreed on once there is a majority
	// again: its outcome was unknown, not negative. What must hold is that
	// at most the old leader's own attempt surfaces, once, and on every
	// member alike (checked by same above). The apply engine rolls such a
	// change back, because its confirmation deadline has passed.
	late := 0
	for name := range l.names() {
		if strings.HasPrefix(name, "alone-") {
			late++
		}
	}
	if late > 1 {
		t.Errorf("%d refused writes surfaced after the partition", late)
	}
}

func TestSnapshotBringsALateMemberUp(t *testing.T) {
	c := newCluster(t)
	c.opts = func(_ string, o *Options) {
		o.SnapshotThreshold, o.TrailingLogs, o.SnapshotInterval = 8, 2, 50*time.Millisecond
	}
	c.form("a", "b", "c")
	l := c.leader()
	for i := 0; i < 30; i++ {
		if err := l.write(fmt.Sprintf("alias-%02d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.node.PutSecret("shared", []byte("s3cret"), false); err != nil {
		t.Fatal(err)
	}
	if err := l.node.Snapshot(); err != nil {
		t.Fatal(err)
	}
	// The log from before the snapshot is gone; a new member can only get
	// the state.
	d := c.join("d", false)
	c.converge(30, "d")
	c.same("a", "d")
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && !d.sec.Has("shared"); time.Sleep(20 * time.Millisecond) {
	}
	if v, err := d.sec.Get("shared"); err != nil || string(v) != "s3cret" {
		t.Errorf("the secret on the late member: %q %v", v, err)
	}
	// A member restarted from its own disk is where it was.
	c.stop("b")
	c.start("b")
	c.converge(30, "b")
	if err := c.leader().write("after-restart"); err != nil {
		t.Fatal(err)
	}
	c.converge(31, "a", "b", "c", "d")
	c.same("a", "b", "c", "d")
}

func TestMembersJoinAndLeaveUnderLoad(t *testing.T) {
	c := newCluster(t)
	c.form("a", "b", "c")
	var mu sync.Mutex
	acked := map[string]bool{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			name := fmt.Sprintf("load-%04d", i)
			// Whoever leads right now; a refusal is simply tried again
			// under the next name.
			for _, m := range c.running() {
				if !m.node.IsLeader() {
					continue
				}
				if err := m.write(name); err == nil {
					mu.Lock()
					acked[name] = true
					mu.Unlock()
				}
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	time.Sleep(300 * time.Millisecond)
	c.join("d", true)
	time.Sleep(300 * time.Millisecond)
	// A voter leaves, and it is the leader of all members.
	gone := c.leader()
	var rest []string
	for id := range c.members {
		if id != gone.id {
			rest = append(rest, id)
		}
	}
	if err := gone.node.TransferLeadership(); err != nil {
		t.Fatalf("hand over leadership: %v", err)
	}
	if err := c.leader(rest...).node.Remove(gone.id); err != nil {
		t.Fatalf("remove %s: %v", gone.id, err)
	}
	c.stop(gone.id)
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()

	l := c.leader(rest...)
	if err := l.write("last"); err != nil {
		t.Fatal(err)
	}
	c.converge(l.store.Current().Index(), rest...)
	c.same(rest...)
	// Everything that was acknowledged is there, on every remaining member.
	mu.Lock()
	defer mu.Unlock()
	if len(acked) < 20 {
		t.Fatalf("only %d writes went through; the test proves little", len(acked))
	}
	for _, id := range rest {
		have := c.members[id].names()
		for name := range acked {
			if !have[name] {
				t.Errorf("%s lost acknowledged write %s", id, name)
			}
		}
	}
	servers, _ := l.node.Servers()
	if len(servers) != 3 {
		t.Errorf("members after one joined and one left: %v", servers)
	}
	if _, still := l.node.State().Members[gone.id]; still {
		t.Error("the removed member is still announced")
	}
}

func TestMixedBuilds(t *testing.T) {
	c := newCluster(t)
	c.form("a", "b", "c")
	l := c.leader()
	if err := l.write("before"); err != nil {
		t.Fatal(err)
	}
	c.converge(1, "a", "b", "c")
	// One voter runs an older build: it knows the model up to the previous
	// schema and no command beyond version 1.
	var old *member
	for _, m := range c.members {
		if m != l {
			old = m
			break
		}
	}
	lower := map[string]int{}
	for k, v := range Supported {
		lower[k] = v
	}
	cmd, _ := command(CmdMember, "", Member{ID: old.id, Schema: model.SchemaVersion - 1, Raft: old.addr, Voter: true, Commands: lower})
	if err := l.node.Propose(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	// The leader does not propose what that voter could not apply.
	if err := l.write("needs-the-new-schema"); !errors.Is(err, ErrGate) {
		t.Fatalf("write while a voter is on an older schema: %v", err)
	}
	if err := l.node.Propose(ctx, Command{Type: CmdRollout, Version: 2}); !errors.Is(err, ErrGate) {
		t.Errorf("a command in a newer version: %v", err)
	}
	// Reads and the rest of the cluster are unaffected.
	if got := l.names(); len(got) != 1 {
		t.Errorf("the refused write left traces: %v", got)
	}
	// After the upgrade the voter announces the current build and the
	// change goes through.
	c.announce(old, true)
	if err := l.write("needs-the-new-schema"); err != nil {
		t.Fatalf("write after the upgrade: %v", err)
	}
	c.converge(2, "a", "b", "c")

	// Should a command it cannot read reach a member all the same, the
	// member stops there. It does not skip it and carry on differently.
	if err := l.node.propose(Command{Type: "from-the-future", Version: 1}); !errors.Is(err, ErrHalted) {
		t.Fatalf("unknown command on the leader: %v", err)
	}
	for id, m := range c.members {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && m.node.Halted() == ""; time.Sleep(20 * time.Millisecond) {
		}
		if !strings.Contains(m.node.Halted(), "from-the-future") {
			t.Errorf("%s did not stop at the unknown command: %q", id, m.node.Halted())
		}
		if m.store.Current().Index() != 2 {
			t.Errorf("%s moved on to record %d", id, m.store.Current().Index())
		}
	}
}

func TestClusterFromAnExistingNode(t *testing.T) {
	c := newCluster(t)
	a := c.start("a")
	// The node has a life before the cluster.
	a.store.SetReplicator(nil)
	for _, n := range []string{"one", "two", "three"} {
		if err := a.write(n); err != nil {
			t.Fatal(err)
		}
	}
	a.store.SetReplicator(a.node)
	if err := a.node.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	c.announce(a, true)
	c.join("b", true)
	c.join("c", true)
	c.converge(3, "a", "b", "c")
	c.same("a", "b", "c")
	if err := c.leader().write("four"); err != nil {
		t.Fatal(err)
	}
	c.converge(4, "a", "b", "c")
	c.same("a", "b", "c")
}

func TestSecretsAreSealedInTheLog(t *testing.T) {
	c := newCluster(t)
	c.form("a", "b", "c")
	l := c.leader()
	// One member never got the cluster key.
	var keyless *member
	for _, m := range c.members {
		if m != l {
			keyless = m
			break
		}
	}
	keyless.key = nil
	if err := l.node.PutSecret("oidc-1", []byte("the client secret"), false); err != nil {
		t.Fatal(err)
	}
	for id, m := range c.members {
		var v []byte
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if v, _ = m.sec.Get("oidc-1"); v != nil || m == keyless {
				break
			}
		}
		if m == keyless {
			time.Sleep(200 * time.Millisecond)
			if m.sec.Has("oidc-1") {
				t.Errorf("%s has the secret without the key", id)
			}
			continue
		}
		if string(v) != "the client secret" {
			t.Errorf("%s holds %q", id, v)
		}
	}
	// What is replicated is not the secret.
	sealed := l.node.State().Secrets["oidc-1"]
	if len(sealed) == 0 || strings.Contains(string(sealed), "client secret") {
		t.Errorf("the replicated form: %q", sealed)
	}
	if _, err := unseal(c.key, "another-name", sealed); err == nil {
		t.Error("a sealed secret opens under another name")
	}
	if err := l.node.PutSecret("oidc-1", nil, true); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && l.sec.Has("oidc-1"); time.Sleep(20 * time.Millisecond) {
	}
	if l.sec.Has("oidc-1") {
		t.Error("the secret was not removed")
	}
	_ = confstore.ErrStale
}
