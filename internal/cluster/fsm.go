package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/hashicorp/raft"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/secrets"
)

// fsm applies agreed commands: records go to the configuration store, the
// rest to the state next to it.
type fsm struct {
	store   *confstore.Store
	secrets secrets.Store // without replication
	key     func() []byte

	mu     sync.RWMutex
	state  *State
	halted string // why this member stopped applying; empty when it has not
	// applied is the index of the last Raft entry applied here.
	applied uint64
	// seen is the highest record index met in the log so far. The model is
	// on disk and survives a restart; the state next to it is rebuilt from
	// the log. So a record the model already has is either a replay, whose
	// attachments have to take effect again, or a proposal that lost the
	// race for its index, whose attachments never did. The first entry for
	// an index is the record; any later one lost.
	seen int64

	changed func() // called, without locks, after every applied entry
}

// ErrHalted is returned for every entry after one this build cannot apply.
// The member stops there and has to be upgraded; it does not skip the entry
// and go on with a state that differs from everyone else's.
var ErrHalted = errors.New("cluster: this member cannot apply the log; it runs an older build than the cluster needs")

func (f *fsm) State() *State {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.state.clone()
}

func (f *fsm) Halted() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.halted
}

func (f *fsm) halt(format string, a ...any) error {
	f.halted = fmt.Sprintf(format, a...)
	return fmt.Errorf("%w: %s", ErrHalted, f.halted)
}

// Apply implements raft.FSM. Its return value is what the proposer gets
// back: nil or an error.
func (f *fsm) Apply(l *raft.Log) any {
	err := f.apply(l)
	if f.changed != nil {
		f.changed()
	}
	return err
}

func (f *fsm) apply(l *raft.Log) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = l.Index
	if f.halted != "" {
		return fmt.Errorf("%w: %s", ErrHalted, f.halted)
	}
	var c Command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		return f.halt("entry %d is not a command: %v", l.Index, err)
	}
	if max, known := Supported[c.Type]; !known || c.Version > max {
		return f.halt("entry %d is a %q command in version %d", l.Index, c.Type, c.Version)
	}
	decode := func(into any) error {
		if err := json.Unmarshal(c.Payload, into); err != nil {
			return f.halt("entry %d (%s) cannot be read: %v", l.Index, c.Type, err)
		}
		return nil
	}
	switch c.Type {
	case CmdRecord:
		var e RecordEntry
		if err := decode(&e); err != nil {
			return err
		}
		first := e.Record.Index > f.seen
		err := f.store.ApplyReplicated(e.Record)
		if err != nil && !errors.Is(err, confstore.ErrDuplicate) {
			return f.halt("record %d: %v", e.Record.Index, err)
		}
		if first {
			f.seen = e.Record.Index
			f.setAttached(e)
			return nil // also for a replay: the record is in the model
		}
		return confstore.ErrDuplicate
	case CmdSeed:
		var snap confstore.Snapshot
		if err := decode(&snap); err != nil {
			return err
		}
		if err := f.store.RestoreSnapshot(snap); err != nil {
			return f.halt("seed: %v", err)
		}
		if snap.Index > f.seen {
			f.seen = snap.Index
		}
	case CmdResult:
		var r Result
		if err := decode(&r); err != nil {
			return err
		}
		f.state.Results[r.Node] = r
	case CmdPending:
		var p *Pending
		if err := decode(&p); err != nil {
			return err
		}
		f.state.Pending = p
		if p == nil {
			f.state.Rollout = nil
		}
	case CmdRollout:
		var r *Rollout
		if err := decode(&r); err != nil {
			return err
		}
		f.state.Rollout = r
	case CmdMember:
		var m Member
		if err := decode(&m); err != nil {
			return err
		}
		if m.Raft == "" {
			delete(f.state.Members, m.ID) // the member left
			delete(f.state.Results, m.ID)
		} else {
			f.state.Members[m.ID] = m
		}
	case CmdRevoke:
		var serials []string
		if err := decode(&serials); err != nil {
			return err
		}
		for _, s := range serials {
			f.state.Revoked[s] = l.AppendedAt
		}
	case CmdToken:
		var t Token
		if err := decode(&t); err != nil {
			return err
		}
		if t.Remove {
			delete(f.state.Tokens, t.Hash)
		} else {
			f.state.Tokens[t.Hash] = t
		}
		// Forget what expired; the entry's own time is the same everywhere.
		for h, old := range f.state.Tokens {
			if l.AppendedAt.After(old.Expires) {
				delete(f.state.Tokens, h)
			}
		}
	case CmdSecret:
		var op SecretOp
		if err := decode(&op); err != nil {
			return err
		}
		if op.Remove {
			delete(f.state.Secrets, op.Name)
			return f.secrets.Delete(op.Name)
		}
		f.state.Secrets[op.Name] = op.Sealed
		return f.materialize(op.Name, op.Sealed)
	}
	return nil
}

func (f *fsm) setAttached(e RecordEntry) {
	if e.SetPending {
		f.state.Pending = e.Pending
		if e.Pending == nil {
			f.state.Rollout = nil
		}
	}
	if e.SetRollout {
		f.state.Rollout = e.Rollout
	}
}

// materialize writes a sealed secret into this member's own secret store,
// where the rest of the program reads it.
func (f *fsm) materialize(name string, sealed []byte) error {
	value, err := unseal(f.key(), name, sealed)
	if err != nil {
		// Without the key the member keeps the sealed form and goes on; it
		// can still take part in consensus.
		return fmt.Errorf("cluster: secret %q cannot be opened here: %w", name, err)
	}
	return f.secrets.Put(name, value)
}

// Snapshot implements raft.FSM.
func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.halted != "" {
		return nil, fmt.Errorf("%w: %s", ErrHalted, f.halted)
	}
	data, err := json.Marshal(snapshot{Model: f.store.Snapshot(), Cluster: f.state.clone()})
	if err != nil {
		return nil, err
	}
	return fsmSnapshot(data), nil
}

// Restore implements raft.FSM. It is used when this member starts from a
// snapshot and when it is so far behind that the leader sends one.
func (f *fsm) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	var snap snapshot
	if err := json.NewDecoder(rc).Decode(&snap); err != nil {
		return err
	}
	if err := f.store.RestoreSnapshot(snap.Model); err != nil {
		return err
	}
	if snap.Cluster == nil {
		snap.Cluster = newState()
	}
	fresh := newState()
	// Fill the maps a snapshot written without them leaves nil.
	for k, v := range snap.Cluster.Members {
		fresh.Members[k] = v
	}
	for k, v := range snap.Cluster.Results {
		fresh.Results[k] = v
	}
	for k, v := range snap.Cluster.Revoked {
		fresh.Revoked[k] = v
	}
	for k, v := range snap.Cluster.Secrets {
		fresh.Secrets[k] = v
	}
	for k, v := range snap.Cluster.Tokens {
		fresh.Tokens[k] = v
	}
	fresh.Pending, fresh.Rollout = snap.Cluster.Pending, snap.Cluster.Rollout
	f.mu.Lock()
	f.state, f.seen = fresh, snap.Model.Index
	f.mu.Unlock()
	for name, sealed := range fresh.Secrets {
		_ = f.materialize(name, sealed)
	}
	if f.changed != nil {
		f.changed()
	}
	return nil
}

type fsmSnapshot []byte

func (s fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (fsmSnapshot) Release() {}
