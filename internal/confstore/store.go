package confstore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noahzmr/testudo/internal/model"
)

// Event tells subscribers that the model changed. It carries no secrets.
type Event struct {
	Index   int64    `json:"index"`
	Time    string   `json:"time"`
	Actor   string   `json:"actor"`
	Type    string   `json:"type"`
	Changes []Change `json:"changes,omitempty"` // Before/After stripped
	// Resync is set when earlier events were dropped because the subscriber
	// was slow; it should reload instead of patching its view.
	Resync bool `json:"resync,omitempty"`
}

// Store is the node-local implementation: an append-only JSON-lines log
// (mode 0600, fsynced per record) that is replayed on open.
type Store struct {
	mu sync.Mutex // serialises writers
	// repl, when set, gets records agreed on by a group before they are
	// applied; propose serialises the writes of this member meanwhile.
	repl    Replicator
	propose sync.Mutex
	state   atomic.Pointer[State]
	log     *os.File
	dir     string
	path    string
	now     func() time.Time

	subMu sync.Mutex
	subs  map[*subscriber]struct{}
}

type subscriber struct {
	ch      chan Event
	dropped bool
}

// Open replays the log in dir (created with mode 0700 when missing). It
// fails with ErrLocked at once when another process has the store open.
func Open(dir string) (*Store, error) { return OpenWait(dir, 0) }

// OpenWait is Open, but waits up to wait for another process to release the
// store. A daemon restarting right after its predecessor uses this so the
// handover does not leave it without a configuration model.
func OpenWait(dir string, wait time.Duration) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, path: filepath.Join(dir, "config.log"), now: time.Now, subs: map[*subscriber]struct{}{}}
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	// One writer per log. A second process (a CLI command while the daemon
	// runs) is refused instead of interleaving records.
	for deadline := time.Now().Add(wait); ; time.Sleep(50 * time.Millisecond) {
		if err := lockFile(f); err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, fmt.Errorf("%w: %s", ErrLocked, s.path)
		}
	}
	st, err := loadSnapshot(filepath.Join(dir, snapshotFile))
	if err != nil {
		f.Close()
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var good, skipped int64
	for sc.Scan() {
		var r Record
		err := json.Unmarshal(sc.Bytes(), &r)
		if err == nil && r.Index <= st.index && good == 0 && r.Index > 0 {
			// Already covered by the snapshot (compaction was interrupted
			// between writing the snapshot and trimming the log).
			skipped += int64(len(sc.Bytes())) + 1
			continue
		}
		if err == nil && r.Schema > model.SchemaVersion {
			f.Close()
			return nil, fmt.Errorf("confstore: record %d was written by a newer version (schema %d, this build knows %d)",
				r.Index, r.Schema, model.SchemaVersion)
		}
		if err != nil || r.Index != st.index+1 {
			// A torn final line after a crash is expected and dropped;
			// anything else in the middle of the log is corruption.
			rest := sc.Scan()
			if rest || err == nil {
				f.Close()
				return nil, fmt.Errorf("confstore: %s is corrupt after record %d", s.path, st.index)
			}
			break
		}
		if st, err = st.apply(r); err != nil {
			f.Close()
			return nil, err
		}
		good += int64(len(sc.Bytes())) + 1
	}
	if err := sc.Err(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Truncate(skipped + good); err != nil {
		f.Close()
		return nil, err
	}
	s.log = f
	s.state.Store(st)
	return s, nil
}

// ErrLocked means another process has the store open for writing.
var ErrLocked = errors.New("confstore: the configuration store is in use by another process")

// ReadState replays the store in dir without locking or modifying it, for
// read-only tools that may run next to the daemon.
func ReadState(dir string) (*State, error) {
	st, err := loadSnapshot(filepath.Join(dir, snapshotFile))
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, "config.log"))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			break // a record being written right now
		}
		if r.Index != st.index+1 {
			continue
		}
		if st, err = st.apply(r); err != nil {
			return nil, err
		}
	}
	return st, sc.Err()
}

// Close releases the log file.
func (s *Store) Close() error { return s.log.Close() }

// Current returns the current immutable state.
func (s *Store) Current() *State { return s.state.Load() }

// Preview validates ops against the current state and returns the state they
// would produce and the resulting changes, without committing anything. The
// apply pipeline renders and dry-runs from this candidate.
func (s *Store) Preview(actor string, ops []Op) (*State, []Change, error) {
	cur := s.Current()
	return cur.prepare(cur.index+1, actor, s.now().UTC(), fillIDs(ops))
}

// Commit applies ops as one transaction. removeChangeSets are deleted in the
// same record, which is how applying change sets consumes them.
func (s *Store) Commit(ctx context.Context, actor, note string, ops []Op, removeChangeSets ...string) (Record, error) {
	return s.commit(ctx, Record{Actor: actor, Type: "commit", Note: note, DeleteChangeSets: removeChangeSets}, ops, 0)
}

// commit is the only writer. csVersion is the change-set version an edit of
// r.PutChangeSet is based on.
func (s *Store) commit(ctx context.Context, r Record, ops []Op, csVersion int64) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.propose.Lock()
	defer s.propose.Unlock()
	// In a group, another record can take the index while ours is being
	// agreed on (a new leader finishing what the old one began). Then the
	// change is prepared again against the state that includes it: all of
	// the validation, and the version check that turns a real conflict
	// into a conflict.
	orig := r.PutChangeSet
	for attempt := 0; ; attempt++ {
		rec, err := s.commitOnce(ctx, r, ops, csVersion)
		if errors.Is(err, ErrStale) && attempt < 3 {
			continue
		}
		if err == nil && orig != nil {
			*orig = *rec.PutChangeSet // callers read owner and version back
			rec.PutChangeSet = orig
		}
		return rec, err
	}
}

func (s *Store) commitOnce(ctx context.Context, r Record, ops []Op, csVersion int64) (Record, error) {
	if cs := r.PutChangeSet; cs != nil {
		c := *cs // an attempt must not see what the one before wrote into it
		r.PutChangeSet = &c
	}
	s.mu.Lock()
	// Unlocked by hand: a replicated record is applied by the group's
	// state machine, which takes the lock itself.
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	cur := s.Current()
	r.Index, r.Time, r.Schema = cur.index+1, s.now().UTC(), model.SchemaVersion
	if cs := r.PutChangeSet; cs != nil {
		if old, ok := cur.changesets[cs.ID]; ok {
			if old.Version != csVersion {
				return Record{}, &ConflictError{Kind: "changeset", ID: cs.ID, YourVersion: csVersion,
					CurrentVersion: old.Version, CurrentBy: old.Owner}
			}
			cs.Owner = old.Owner
		} else {
			cs.Owner = r.Actor
		}
		cs.Version, cs.UpdatedAt = r.Index, r.Time
	}
	_, changes, err := cur.prepare(r.Index, r.Actor, r.Time, fillIDs(ops))
	if err != nil {
		return Record{}, err
	}
	r.Changes = changes
	next, err := cur.apply(r)
	if err != nil {
		return Record{}, err
	}
	if repl := s.repl; repl != nil {
		s.mu.Unlock()
		locked = false
		// Had another record taken this index first, applying ours fails
		// as a duplicate on every member alike.
		if err := repl.Replicate(ctx, r); errors.Is(err, ErrDuplicate) {
			return Record{}, ErrStale
		} else if err != nil {
			return Record{}, err
		}
		return r, nil
	}
	if err := s.appendLocked(r, next); err != nil {
		return Record{}, err
	}
	return r, nil
}

// fillIDs gives creates without an id a fresh one, outside the deterministic
// state machine.
func fillIDs(ops []Op) []Op {
	out := make([]Op, len(ops))
	copy(out, ops)
	for i, op := range out {
		if op.Type == OpCreate && op.ID == "" {
			var probe struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(op.Object, &probe)
			if probe.ID == "" {
				out[i].ID = NewID()
			} else {
				out[i].ID = probe.ID
			}
		}
	}
	return out
}

// Revert undoes the record at index with a new record. It only succeeds when
// nothing has touched the affected objects since.
func (s *Store) Revert(ctx context.Context, actor string, index int64, note string) (Record, error) {
	ops, err := s.InverseOps(index)
	if err != nil {
		return Record{}, err
	}
	return s.commit(ctx, Record{Actor: actor, Type: "revert", Note: note, Reverts: index}, ops, 0)
}

// InverseOps returns the ops that undo the record at index. They carry the
// record's index as their base version, so they only apply while nothing has
// touched the affected objects since.
func (s *Store) InverseOps(index int64) ([]Op, error) {
	target, err := s.RecordAt(index)
	if err != nil {
		return nil, err
	}
	var ops []Op
	for i := len(target.Changes) - 1; i >= 0; i-- {
		c := target.Changes[i]
		switch c.Type {
		case OpCreate:
			ops = append(ops, Op{Type: OpDelete, Kind: c.Kind, ID: c.ID, IfMatch: index})
		case OpUpdate:
			ops = append(ops, Op{Type: OpUpdate, Kind: c.Kind, ID: c.ID, Object: c.Before, IfMatch: index})
		case OpDelete:
			ops = append(ops, Op{Type: OpCreate, Kind: c.Kind, ID: c.ID, Object: c.Before})
		}
	}
	return ops, nil
}

// PutChangeSet creates or replaces a change set. version is the change set
// version the edit is based on (0 to create).
func (s *Store) PutChangeSet(ctx context.Context, actor string, cs ChangeSet, version int64) (ChangeSet, error) {
	if cs.ID == "" {
		cs.ID = NewID()
	}
	cs.Ops = fillIDs(cs.Ops)
	if _, err := s.commit(ctx, Record{Actor: actor, Type: "changeset", PutChangeSet: &cs}, nil, version); err != nil {
		return ChangeSet{}, err
	}
	return cs, nil
}

// DeleteChangeSet discards a change set.
func (s *Store) DeleteChangeSet(ctx context.Context, actor, id string) error {
	if _, ok := s.Current().ChangeSet(id); !ok {
		return ErrNotFound
	}
	_, err := s.commit(ctx, Record{Actor: actor, Type: "changeset", DeleteChangeSets: []string{id}}, nil, 0)
	return err
}

// Combine returns the ops of several change sets in order, ready for Preview
// (the combined diff) or Commit (applying them as one transaction).
func (s *Store) Combine(ids ...string) ([]Op, error) {
	st := s.Current()
	var ops []Op
	for _, id := range ids {
		cs, ok := st.ChangeSet(id)
		if !ok {
			return nil, fmt.Errorf("%w: change set %s", ErrNotFound, id)
		}
		ops = append(ops, cs.Ops...)
	}
	return ops, nil
}

// History returns up to limit records, newest first, starting below before
// (0 means from the end). Secrets are still present; mask before output.
func (s *Store) History(before int64, limit int) ([]Record, error) {
	var out []Record
	err := s.scan(func(r Record) bool {
		if before == 0 || r.Index < before {
			out = append(out, r)
		}
		return true
	})
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, err
}

// RecordAt returns one record of the log.
func (s *Store) RecordAt(index int64) (Record, error) {
	var found *Record
	err := s.scan(func(r Record) bool {
		if r.Index == index {
			found = &r
			return false
		}
		return true
	})
	if err != nil {
		return Record{}, err
	}
	if found == nil {
		return Record{}, fmt.Errorf("%w: record %d", ErrNotFound, index)
	}
	return *found, nil
}

func (s *Store) scan(fn func(Record) bool) error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()
	last := s.Current().index
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return err
		}
		if r.Index > last || !fn(r) {
			break
		}
	}
	return sc.Err()
}

// Subscribe delivers an Event for every committed record until cancel is
// called. A subscriber that falls more than buf events behind loses events
// and gets Resync on the next one it receives.
func (s *Store) Subscribe(buf int) (<-chan Event, func()) {
	sub := &subscriber{ch: make(chan Event, buf)}
	s.subMu.Lock()
	s.subs[sub] = struct{}{}
	s.subMu.Unlock()
	var once sync.Once
	return sub.ch, func() {
		once.Do(func() {
			s.subMu.Lock()
			delete(s.subs, sub)
			s.subMu.Unlock()
		})
	}
}

func (s *Store) publish(r Record) {
	ev := Event{Index: r.Index, Time: r.Time.Format(time.RFC3339Nano), Actor: r.Actor, Type: r.Type}
	for _, c := range r.Changes {
		ev.Changes = append(ev.Changes, Change{Type: c.Type, Kind: c.Kind, ID: c.ID, Name: c.Name})
	}
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for sub := range s.subs {
		e := ev
		e.Resync = sub.dropped
		select {
		case sub.ch <- e:
			sub.dropped = false
		default:
			sub.dropped = true
		}
	}
}

// Create, Update and Delete are single-op conveniences over Commit.

func (s *Store) Create(ctx context.Context, actor string, e model.Entity) (model.Entity, error) {
	if e.GetMeta().ID == "" {
		e.GetMeta().ID = NewID()
	}
	_, err := s.Commit(ctx, actor, "", []Op{{Type: OpCreate, Kind: e.Kind(), ID: e.GetMeta().ID, Object: mustJSON(e)}})
	if err != nil {
		return nil, err
	}
	out, _ := s.Current().Get(e.Kind(), e.GetMeta().ID)
	return out, nil
}

func (s *Store) Update(ctx context.Context, actor string, e model.Entity, ifMatch int64) (model.Entity, error) {
	_, err := s.Commit(ctx, actor, "", []Op{{Type: OpUpdate, Kind: e.Kind(), ID: e.GetMeta().ID,
		Object: mustJSON(e), IfMatch: ifMatch}})
	if err != nil {
		return nil, err
	}
	out, _ := s.Current().Get(e.Kind(), e.GetMeta().ID)
	return out, nil
}

func (s *Store) Delete(ctx context.Context, actor string, kind model.Kind, id string, ifMatch int64) error {
	_, err := s.Commit(ctx, actor, "", []Op{{Type: OpDelete, Kind: kind, ID: id, IfMatch: ifMatch}})
	return err
}

// IsRejection reports whether err means the request was refused because of
// its content (validation, conflict, integrity, reference), as opposed to an
// internal failure.
func IsRejection(err error) bool {
	var (
		v *model.ValidationError
		c *ConflictError
		r *ReferencedError
		i *IntegrityError
	)
	return errors.As(err, &v) || errors.As(err, &c) || errors.As(err, &r) || errors.As(err, &i) ||
		errors.Is(err, ErrIfMatchNeeded) || errors.Is(err, ErrNotFound)
}
