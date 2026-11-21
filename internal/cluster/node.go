package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/secrets"
)

// Timing defaults. They are chosen for members that talk over a WAN: a
// heartbeat that survives a slow link, an election that does not start
// because one packet was late. Pre-vote is on (the library's default), so a
// member that was cut off does not disturb the others when it comes back.
const (
	DefaultHeartbeat   = 1500 * time.Millisecond
	DefaultElection    = 3 * time.Second
	DefaultLeaderLease = 1 * time.Second
	proposeTimeout     = 10 * time.Second
)

// Options configure a member.
type Options struct {
	// ID is the member's stable identifier: the id of its cluster_node
	// object, or any unique name before there is one.
	ID string
	// Dir holds the consensus log, the stable store and snapshots.
	Dir string
	// Bind is where the consensus transport listens; Advertise is the
	// address the other members reach it at (default: Bind).
	Bind      string
	Advertise string

	Store   *confstore.Store
	Secrets secrets.Store
	// Key returns the cluster key, or nil while the member has none.
	Key func() []byte

	// ServerTLS and ClientTLS protect the transport. Both nil means plain
	// TCP, which is for tests only.
	ServerTLS, ClientTLS *tls.Config

	Heartbeat, Election, LeaderLease time.Duration
	// SnapshotThreshold is how many entries may accumulate before a
	// snapshot is taken; TrailingLogs how many are kept after one.
	SnapshotThreshold, TrailingLogs uint64
	SnapshotInterval                time.Duration

	// Changed is called after every applied entry and leadership change.
	Changed func()
	// LogOutput receives the consensus library's log; nil discards it.
	LogOutput io.Writer

	// dial replaces how the transport connects (tests cut links with it).
	dial func(addr string, timeout time.Duration) (net.Conn, error)
	// wrap is applied to every accepted connection (tests).
	wrap func(net.Conn) net.Conn
}

// Node is one member of the cluster.
type Node struct {
	opt   Options
	raft  *raft.Raft
	fsm   *fsm
	trans *raft.NetworkTransport
	logs  *raftboltdb.BoltStore
	snaps raft.SnapshotStore

	closeOnce sync.Once

	attachMu sync.Mutex
	attach   *RecordEntry // what the next record carries with it

	// While leading, the members the leader cannot reach and since when.
	hbMu   sync.Mutex
	hbLost map[string]time.Time
	hbObs  *raft.Observer
}

// Attach makes the next record this member proposes carry a pending
// confirmation and a rollout, in the same log entry. It is used up by that
// record, whether the record is agreed on or refused.
func (n *Node) Attach(pending *Pending, setPending bool, rollout *Rollout, setRollout bool) {
	n.attachMu.Lock()
	n.attach = &RecordEntry{Pending: pending, SetPending: setPending, Rollout: rollout, SetRollout: setRollout}
	n.attachMu.Unlock()
}

var (
	// ErrNotLeader means the request has to go to the leader.
	ErrNotLeader = errors.New("cluster: this member is not the leader")
	// ErrNoQuorum means no leader is known: the cluster cannot accept
	// writes right now.
	ErrNoQuorum = errors.New("cluster: no leader; the cluster has no quorum")
	// ErrGate means a voter runs a build that cannot apply the command.
	ErrGate = errors.New("cluster: not every voter can apply this yet; finish the upgrade first")
)

// stream is the transport's connection layer.
type stream struct {
	net.Listener
	advertise net.Addr
	opt       *Options
}

func (s *stream) Addr() net.Addr { return s.advertise }

func (s *stream) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err == nil && s.opt.wrap != nil {
		c = s.opt.wrap(c)
	}
	return c, err
}

func (s *stream) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	if s.opt.dial != nil {
		return s.opt.dial(string(address), timeout)
	}
	d := &net.Dialer{Timeout: timeout}
	if s.opt.ClientTLS != nil {
		return tls.DialWithDialer(d, "tcp", string(address), s.opt.ClientTLS)
	}
	return d.Dial("tcp", string(address))
}

// Open starts a member. A member that was part of a cluster before finds
// its place again from Dir; a new one waits to be bootstrapped or joined.
func Open(opt Options) (*Node, error) {
	if opt.ID == "" || opt.Dir == "" || opt.Bind == "" || opt.Store == nil {
		return nil, errors.New("cluster: id, directory, bind address and store are required")
	}
	if (opt.ServerTLS == nil) != (opt.ClientTLS == nil) {
		return nil, errors.New("cluster: both TLS configurations or neither")
	}
	if opt.Advertise == "" {
		opt.Advertise = opt.Bind
	}
	if opt.Key == nil {
		opt.Key = func() []byte { return nil }
	}
	if err := os.MkdirAll(opt.Dir, 0o700); err != nil {
		return nil, err
	}
	n := &Node{opt: opt}
	n.fsm = &fsm{store: opt.Store, secrets: opt.Secrets.Local(), key: opt.Key, state: newState(), changed: opt.Changed}

	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(opt.ID)
	conf.HeartbeatTimeout = pick(opt.Heartbeat, DefaultHeartbeat)
	conf.ElectionTimeout = pick(opt.Election, DefaultElection)
	conf.LeaderLeaseTimeout = pick(opt.LeaderLease, DefaultLeaderLease)
	if conf.LeaderLeaseTimeout > conf.HeartbeatTimeout {
		conf.LeaderLeaseTimeout = conf.HeartbeatTimeout
	}
	conf.CommitTimeout = 50 * time.Millisecond
	if opt.SnapshotThreshold > 0 {
		conf.SnapshotThreshold = opt.SnapshotThreshold
	}
	if opt.TrailingLogs > 0 {
		conf.TrailingLogs = opt.TrailingLogs
	}
	if opt.SnapshotInterval > 0 {
		conf.SnapshotInterval = opt.SnapshotInterval
	}
	out := opt.LogOutput
	if out == nil {
		out = io.Discard
	}
	conf.Logger = hclog.New(&hclog.LoggerOptions{Name: "raft", Output: out, Level: hclog.Warn})

	ln, err := net.Listen("tcp", opt.Bind)
	if err != nil {
		return nil, fmt.Errorf("cluster: listen: %w", err)
	}
	if opt.ServerTLS != nil {
		ln = tls.NewListener(ln, opt.ServerTLS)
	}
	adv, err := net.ResolveTCPAddr("tcp", opt.Advertise)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("cluster: advertise address: %w", err)
	}
	n.trans = raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{
		Stream: &stream{Listener: ln, advertise: adv, opt: &n.opt}, MaxPool: 3, Timeout: 10 * time.Second, Logger: conf.Logger})

	if n.logs, err = raftboltdb.New(raftboltdb.Options{Path: filepath.Join(opt.Dir, "raft.db")}); err != nil {
		n.trans.Close()
		return nil, fmt.Errorf("cluster: log store: %w", err)
	}
	if n.snaps, err = raft.NewFileSnapshotStoreWithLogger(opt.Dir, 3, conf.Logger); err != nil {
		n.close()
		return nil, fmt.Errorf("cluster: snapshot store: %w", err)
	}
	if n.raft, err = raft.NewRaft(conf, n.fsm, n.logs, n.logs, n.snaps, n.trans); err != nil {
		n.close()
		return nil, fmt.Errorf("cluster: %w", err)
	}
	n.watchHeartbeats()
	if opt.Changed != nil {
		ch := make(chan raft.Observation, 16)
		n.raft.RegisterObserver(raft.NewObserver(ch, false, func(o *raft.Observation) bool {
			_, leader := o.Data.(raft.LeaderObservation)
			return leader
		}))
		go func() {
			for range ch {
				opt.Changed()
			}
		}()
	}
	return n, nil
}

func pick(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

func (n *Node) close() {
	if n.trans != nil {
		n.trans.Close()
	}
	if n.logs != nil {
		n.logs.Close()
	}
}

// watchHeartbeats records which members the leader fails to reach. A new
// term starts with a clean slate: what an earlier leadership saw is stale.
func (n *Node) watchHeartbeats() {
	n.hbLost = map[string]time.Time{}
	ch := make(chan raft.Observation, 64)
	n.hbObs = raft.NewObserver(ch, false, func(o *raft.Observation) bool {
		switch o.Data.(type) {
		case raft.FailedHeartbeatObservation, raft.ResumedHeartbeatObservation, raft.LeaderObservation:
			return true
		}
		return false
	})
	n.raft.RegisterObserver(n.hbObs)
	go func() {
		for o := range ch {
			n.hbMu.Lock()
			switch d := o.Data.(type) {
			case raft.FailedHeartbeatObservation:
				if _, ok := n.hbLost[string(d.PeerID)]; !ok {
					since := d.LastContact
					if since.IsZero() {
						since = time.Now()
					}
					n.hbLost[string(d.PeerID)] = since
				}
			case raft.ResumedHeartbeatObservation:
				delete(n.hbLost, string(d.PeerID))
			case raft.LeaderObservation:
				n.hbLost = map[string]time.Time{}
			}
			n.hbMu.Unlock()
		}
	}()
}

// Unreachable returns, on the leader, how long each member it cannot reach
// has been silent. Elsewhere it is empty.
func (n *Node) Unreachable() map[string]time.Duration {
	out := map[string]time.Duration{}
	if n.raft.State() != raft.Leader {
		return out
	}
	n.hbMu.Lock()
	defer n.hbMu.Unlock()
	for id, since := range n.hbLost {
		out[id] = time.Since(since)
	}
	return out
}

// Shutdown stops the member. The cluster goes on without it.
func (n *Node) Shutdown() error {
	var err error
	n.closeOnce.Do(func() {
		if n.hbObs != nil {
			n.raft.DeregisterObserver(n.hbObs)
		}
		err = n.raft.Shutdown().Error()
		n.close()
	})
	return err
}

// ID returns the member's identifier.
func (n *Node) ID() string { return n.opt.ID }

// Initialized reports whether the member belongs to a cluster already.
func (n *Node) Initialized() bool {
	f := n.raft.GetConfiguration()
	return f.Error() == nil && len(f.Configuration().Servers) > 0
}

// Bootstrap makes this member a cluster of one. If the store already holds
// a model, the model becomes the first thing in the log, so that members
// joining later receive it.
func (n *Node) Bootstrap(ctx context.Context) error {
	if n.Initialized() {
		return errors.New("cluster: this member already belongs to a cluster")
	}
	f := n.raft.BootstrapCluster(raft.Configuration{Servers: []raft.Server{
		{ID: raft.ServerID(n.opt.ID), Address: raft.ServerAddress(n.opt.Advertise), Suffrage: raft.Voter}}})
	if err := f.Error(); err != nil {
		return fmt.Errorf("cluster: bootstrap: %w", err)
	}
	if err := n.WaitLeader(ctx); err != nil {
		return err
	}
	if snap := n.opt.Store.Snapshot(); snap.Index > 0 {
		c, err := command(CmdSeed, "", snap)
		if err != nil {
			return err
		}
		return n.propose(c)
	}
	return nil
}

// WaitLeader blocks until some member leads, or ctx ends.
func (n *Node) WaitLeader(ctx context.Context) error {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		if addr, _ := n.raft.LeaderWithID(); addr != "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrNoQuorum
		case <-t.C:
		}
	}
}

// IsLeader reports whether this member leads and still holds its lease.
func (n *Node) IsLeader() bool { return n.raft.VerifyLeader().Error() == nil }

// Leader returns the leader's id and transport address; both are empty
// when none is known.
func (n *Node) Leader() (id, addr string) {
	a, i := n.raft.LeaderWithID()
	return string(i), string(a)
}

// State returns a copy of the replicated state next to the model.
func (n *Node) State() *State { return n.fsm.State() }

// Halted says why this member stopped applying the log, or "".
func (n *Node) Halted() string { return n.fsm.Halted() }

func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, raft.ErrNotLeader), errors.Is(err, raft.ErrLeadershipLost), errors.Is(err, raft.ErrLeadershipTransferInProgress):
		return ErrNotLeader
	case errors.Is(err, raft.ErrEnqueueTimeout), errors.Is(err, raft.ErrRaftShutdown):
		return ErrNoQuorum
	}
	return err
}

// gate refuses a command some voter could not apply.
func (n *Node) gate(c Command, schema int) error {
	f := n.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return err
	}
	st := n.fsm.State()
	for _, srv := range f.Configuration().Servers {
		if srv.Suffrage != raft.Voter {
			continue
		}
		m, announced := st.Members[string(srv.ID)]
		if !announced {
			continue // a voter is promoted only after it announced itself
		}
		if m.Commands[c.Type] < c.Version {
			return fmt.Errorf("%w (member %s cannot apply %s in version %d)", ErrGate, m.ID, c.Type, c.Version)
		}
		if schema > m.Schema {
			return fmt.Errorf("%w (member %s knows the model up to schema %d, this change needs %d)", ErrGate, m.ID, m.Schema, schema)
		}
	}
	return nil
}

func (n *Node) propose(c Command) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f := n.raft.Apply(data, proposeTimeout)
	if err := f.Error(); err != nil {
		if _, leader := n.Leader(); leader == "" {
			return ErrNoQuorum
		}
		return translate(err)
	}
	if err, ok := f.Response().(error); ok && err != nil {
		return err
	}
	return nil
}

// Propose gets a command agreed on and applied. Only the leader can.
func (n *Node) Propose(_ context.Context, c Command) error {
	if c.Version == 0 {
		c.Version = Supported[c.Type]
	}
	if err := n.gate(c, 0); err != nil {
		return err
	}
	return n.propose(c)
}

// Replicate implements confstore.Replicator.
func (n *Node) Replicate(_ context.Context, r confstore.Record) error {
	entry := RecordEntry{Record: r}
	n.attachMu.Lock()
	if a := n.attach; a != nil {
		entry.Pending, entry.SetPending, entry.Rollout, entry.SetRollout = a.Pending, a.SetPending, a.Rollout, a.SetRollout
		if entry.Pending != nil {
			p := *entry.Pending
			p.Index = r.Index
			entry.Pending = &p
		}
		if entry.Rollout != nil {
			ro := *entry.Rollout
			ro.Index = r.Index
			entry.Rollout = &ro
		}
	}
	n.attachMu.Unlock()
	c, err := command(CmdRecord, r.Actor, entry)
	if err != nil {
		return err
	}
	if err := n.gate(c, r.Schema); err != nil {
		return err
	}
	err = n.propose(c)
	if !errors.Is(err, confstore.ErrDuplicate) {
		// Used up, unless the record lost the race for its index: then the
		// store prepares it again and the attachments go with that one.
		n.attachMu.Lock()
		n.attach = nil
		n.attachMu.Unlock()
	}
	return err
}

// PutSecret replicates a secret, sealed with the cluster key.
func (n *Node) PutSecret(name string, value []byte, remove bool) error {
	op := SecretOp{Name: name, Remove: remove}
	if !remove {
		key := n.opt.Key()
		if key == nil {
			return errors.New("cluster: this member has no cluster key")
		}
		sealed, err := seal(key, name, value)
		if err != nil {
			return err
		}
		op.Sealed = sealed
	}
	c, err := command(CmdSecret, "", op)
	if err != nil {
		return err
	}
	return n.Propose(context.Background(), c)
}

// Announce publishes what this member is and can do.
func (n *Node) Announce(m Member) error {
	m.ID, m.Schema, m.Commands = n.opt.ID, model.SchemaVersion, Supported
	if m.Raft == "" {
		m.Raft = n.opt.Advertise
	}
	c, err := command(CmdMember, "", m)
	if err != nil {
		return err
	}
	return n.Propose(context.Background(), c)
}

// Server is one member as the consensus layer sees it.
type Server struct {
	ID    string `json:"id"`
	Addr  string `json:"addr"`
	Voter bool   `json:"voter"`
}

// Servers lists the members of the consensus group.
func (n *Node) Servers() ([]Server, error) {
	f := n.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, err
	}
	var out []Server
	for _, s := range f.Configuration().Servers {
		out = append(out, Server{ID: string(s.ID), Addr: string(s.Address), Voter: s.Suffrage == raft.Voter})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Add admits a member. Everyone starts as a non-voter: it receives the log
// and does not count for quorum. Promote makes it a voter.
func (n *Node) Add(id, addr string) error {
	return translate(n.raft.AddNonvoter(raft.ServerID(id), raft.ServerAddress(addr), 0, proposeTimeout).Error())
}

// Promote makes a member a voter. Voters decide; keep their number odd and
// at three or five.
func (n *Node) Promote(id string) error {
	servers, err := n.Servers()
	if err != nil {
		return err
	}
	for _, s := range servers {
		if s.ID == id {
			return translate(n.raft.AddVoter(raft.ServerID(id), raft.ServerAddress(s.Addr), 0, proposeTimeout).Error())
		}
	}
	return fmt.Errorf("cluster: %s is not a member", id)
}

// Demote takes a member's vote away without removing it.
func (n *Node) Demote(id string) error {
	return translate(n.raft.DemoteVoter(raft.ServerID(id), 0, proposeTimeout).Error())
}

// Remove takes a member out of the cluster and revokes its certificate.
func (n *Node) Remove(id string) error {
	st := n.fsm.State()
	if err := translate(n.raft.RemoveServer(raft.ServerID(id), 0, proposeTimeout).Error()); err != nil {
		return err
	}
	if m, ok := st.Members[id]; ok {
		if m.Serial != "" {
			if c, err := command(CmdRevoke, "", []string{m.Serial}); err == nil {
				if err := n.propose(c); err != nil {
					return err
				}
			}
		}
		c, err := command(CmdMember, "", Member{ID: id})
		if err != nil {
			return err
		}
		return n.propose(c)
	}
	return nil
}

// TransferLeadership hands leadership to another voter, for maintenance.
func (n *Node) TransferLeadership() error {
	return translate(n.raft.LeadershipTransfer().Error())
}

// Snapshot takes a snapshot now, which also lets the log be shortened.
func (n *Node) Snapshot() error { return n.raft.Snapshot().Error() }

// Barrier returns once every entry committed before the call is applied
// here; a leader uses it before it trusts its own state.
func (n *Node) Barrier(timeout time.Duration) error {
	return translate(n.raft.Barrier(timeout).Error())
}

// Stats describes the member for monitoring.
type Stats struct {
	ID          string        `json:"id"`
	State       string        `json:"state"` // Leader, Follower, Candidate, Shutdown
	LeaderID    string        `json:"leader_id"`
	Term        uint64        `json:"term"`
	CommitIndex uint64        `json:"commit_index"`
	Applied     uint64        `json:"applied_index"`
	LastLog     uint64        `json:"last_log_index"`
	LastContact time.Duration `json:"last_contact_ns"` // since the leader was last heard; 0 on the leader
	ModelIndex  int64         `json:"model_index"`
	Halted      string        `json:"halted,omitempty"`
}

// Stats returns the member's current numbers.
func (n *Node) Stats() Stats {
	raw := n.raft.Stats()
	num := func(k string) uint64 { v, _ := strconv.ParseUint(raw[k], 10, 64); return v }
	id, _ := n.Leader()
	s := Stats{ID: n.opt.ID, State: n.raft.State().String(), LeaderID: id, Term: num("term"), CommitIndex: num("commit_index"),
		Applied: num("applied_index"), LastLog: num("last_log_index"), ModelIndex: n.opt.Store.Current().Index(), Halted: n.fsm.Halted()}
	if s.State != "Leader" {
		if last := n.raft.LastContact(); !last.IsZero() {
			s.LastContact = time.Since(last)
		}
	}
	return s
}

func schemaVersion() int { return model.SchemaVersion }

// Recover rewrites a member's consensus state so that it is a cluster of
// one. It is the way out when the majority of voters is lost for good and
// nothing can be decided any more. It is unsafe by nature: whatever the
// lost members had agreed on and this one never received is gone, and if
// the others come back they must not be let in again as they are. The
// member must be stopped while this runs.
func Recover(opt Options) error {
	if opt.ID == "" || opt.Dir == "" || opt.Store == nil {
		return errors.New("cluster: id, directory and store are required")
	}
	if opt.Advertise == "" {
		opt.Advertise = opt.Bind
	}
	if opt.Key == nil {
		opt.Key = func() []byte { return nil }
	}
	logs, err := raftboltdb.New(raftboltdb.Options{Path: filepath.Join(opt.Dir, "raft.db")})
	if err != nil {
		return fmt.Errorf("cluster: log store: %w", err)
	}
	defer logs.Close()
	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(opt.ID)
	conf.Logger = hclog.New(&hclog.LoggerOptions{Name: "raft", Output: io.Discard})
	snaps, err := raft.NewFileSnapshotStoreWithLogger(opt.Dir, 3, conf.Logger)
	if err != nil {
		return err
	}
	_, trans := raft.NewInmemTransport(raft.ServerAddress(opt.Advertise))
	f := &fsm{store: opt.Store, secrets: opt.Secrets.Local(), key: opt.Key, state: newState()}
	return raft.RecoverCluster(conf, f, logs, logs, snaps, trans, raft.Configuration{Servers: []raft.Server{
		{ID: raft.ServerID(opt.ID), Address: raft.ServerAddress(opt.Advertise), Suffrage: raft.Voter}}})
}
