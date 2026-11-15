package confstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/noahzmr/testudo/internal/model"
)

// A store can be one member of a replicated group. Then a write is not
// applied where it is made: the store prepares the record (validation,
// index, the resolved changes) and hands it to a Replicator, which gets it
// agreed on by the group. Every member, the one that prepared it included,
// applies an agreed record through ApplyReplicated. A record is complete,
// so applying it is the same computation everywhere.

// Replicator gets a prepared record agreed on. It returns nil once the
// record was applied to this store, and an error when the group refused it
// or this member cannot propose (it is not the leader, there is no quorum).
type Replicator interface {
	Replicate(ctx context.Context, r Record) error
}

// ErrStale means the store moved on between preparing a record and the
// group agreeing on it; the caller prepares again.
var ErrStale = errors.New("confstore: the model changed while the change was being agreed on; try again")

// ErrDuplicate means the store already has a record with that index. When
// the group's log is replayed after a restart that is expected and
// harmless; for a record that was just proposed it means another one got
// there first.
var ErrDuplicate = errors.New("confstore: a record with this index is already applied")

// ErrAhead means a record cannot be applied because records before it are
// missing here.
var ErrAhead = errors.New("confstore: records are missing before this one")

// SetReplicator makes the store a member of a group. Nil returns it to
// applying its own writes.
func (s *Store) SetReplicator(r Replicator) {
	s.mu.Lock()
	s.repl = r
	s.mu.Unlock()
}

// ApplyReplicated applies a record the group agreed on. For a record this
// store already has it returns ErrDuplicate and changes nothing. A record written with a newer schema than this build
// knows is refused: the member has to be upgraded first.
func (s *Store) ApplyReplicated(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.Current()
	switch {
	case r.Index <= cur.index:
		return ErrDuplicate
	case r.Index != cur.index+1:
		return fmt.Errorf("%w: have %d, got %d", ErrAhead, cur.index, r.Index)
	case r.Schema > model.SchemaVersion:
		return fmt.Errorf("confstore: record %d was written by a newer version (schema %d, this build knows %d)",
			r.Index, r.Schema, model.SchemaVersion)
	}
	next, err := cur.apply(r)
	if err != nil {
		return err
	}
	return s.appendLocked(r, next)
}

// appendLocked makes a record durable and current. The caller holds s.mu.
func (s *Store) appendLocked(r Record, next *State) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := s.log.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("confstore: append: %w", err)
	}
	if err := s.log.Sync(); err != nil {
		return fmt.Errorf("confstore: sync: %w", err)
	}
	s.state.Store(next)
	s.publish(r)
	return nil
}

// Snapshot returns the whole current state, for the group's own snapshots.
func (s *Store) Snapshot() Snapshot { return s.Current().Export() }

// RestoreSnapshot replaces the store's content with a snapshot: what a
// member does when it is so far behind that the group sends it the state
// instead of the records. History before the snapshot is gone here.
func (s *Store) RestoreSnapshot(snap Snapshot) error {
	if snap.Schema > model.SchemaVersion {
		return fmt.Errorf("confstore: snapshot has schema %d, this build knows %d", snap.Schema, model.SchemaVersion)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Index <= s.Current().index {
		return nil // nothing in it that is not here already
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	// Same order as compaction: the snapshot first, then the log, so an
	// interruption leaves a store that opens.
	path := filepath.Join(s.dir, snapshotFile)
	if err := writeFileSync(path, data); err != nil {
		return err
	}
	st, err := loadSnapshot(path)
	if err != nil {
		return err
	}
	if err := writeFileSync(s.path, nil); err != nil {
		return err
	}
	nf, err := os.OpenFile(s.path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if err := lockFile(nf); err != nil {
		nf.Close()
		return err
	}
	s.log.Close()
	s.log = nf
	s.state.Store(st)
	s.publish(Record{Index: st.index, Time: s.now().UTC(), Actor: "cluster", Type: "restore"})
	return nil
}
