package confstore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/noahzmr/testudo/internal/model"
)

const snapshotFile = "config.snapshot"

// Migration upgrades the JSON form of one object by one schema version.
type Migration func(kind model.Kind, object json.RawMessage) (json.RawMessage, error)

var migrations = map[int]Migration{}

// RegisterMigration installs the step from schema version `from` to from+1.
// Every version below model.SchemaVersion needs one; a test enforces it.
func RegisterMigration(from int, m Migration) { migrations[from] = m }

// migrate brings an object written with an older schema up to date. Version
// 0 marks records from before versions were recorded and equals version 1.
func migrate(from int, kind model.Kind, object json.RawMessage) (json.RawMessage, error) {
	if from == 0 {
		from = 1
	}
	for v := from; v < model.SchemaVersion; v++ {
		m, ok := migrations[v]
		if !ok {
			return nil, fmt.Errorf("no migration from schema %d to %d", v, v+1)
		}
		var err error
		if object, err = m(kind, object); err != nil {
			return nil, fmt.Errorf("migrate %s from schema %d: %w", kind, v, err)
		}
	}
	return object, nil
}

// Snapshot is the whole model in one document: the backup format, the input
// of Import, and the base a compacted log starts from. It contains secrets.
type Snapshot struct {
	Schema     int                              `json:"schema"`
	Index      int64                            `json:"index"`
	Objects    map[model.Kind][]json.RawMessage `json:"objects"`
	ChangeSets []ChangeSet                      `json:"changesets,omitempty"`
	// Hash is the chain hash of the record at Index; the log after the
	// snapshot chains on from it.
	Hash string `json:"hash,omitempty"`
}

// Export returns the state as a snapshot, objects ordered by name.
func (s *State) Export() Snapshot {
	snap := Snapshot{Schema: model.SchemaVersion, Index: s.index, Objects: map[model.Kind][]json.RawMessage{},
		ChangeSets: s.ChangeSets(), Hash: s.hash}
	for kind, objs := range s.objects {
		for _, e := range sortedByName(objs) {
			snap.Objects[kind] = append(snap.Objects[kind], mustJSON(e))
		}
	}
	return snap
}

// ImportOps returns the ops that turn the current model into the one in the
// snapshot: objects are matched by id, created, updated when they differ and
// deleted when absent. The result goes through the normal validation and
// apply path like any other change. Change sets in the snapshot are ignored.
func (s *State) ImportOps(snap Snapshot) ([]Op, error) {
	if snap.Schema > model.SchemaVersion {
		return nil, fmt.Errorf("confstore: snapshot has schema %d, this build knows %d", snap.Schema, model.SchemaVersion)
	}
	var ops []Op
	wanted := map[string]bool{}
	for _, info := range model.Kinds() {
		for _, raw := range snap.Objects[info.Kind] {
			raw, err := migrate(snap.Schema, info.Kind, raw)
			if err != nil {
				return nil, err
			}
			e, err := model.Decode(info.Kind, raw)
			if err != nil {
				return nil, err
			}
			id := e.GetMeta().ID
			wanted[string(info.Kind)+"/"+id] = true
			cur := s.peek(info.Kind, id)
			switch {
			case cur == nil:
				ops = append(ops, Op{Type: OpCreate, Kind: info.Kind, ID: id, Object: raw})
			case len(diffFieldsRaw(e, cur)) > 0:
				ops = append(ops, Op{Type: OpUpdate, Kind: info.Kind, ID: id, Object: raw, IfMatch: cur.GetMeta().Version})
			}
		}
	}
	for kind := range snap.Objects {
		if _, ok := model.Lookup(string(kind)); !ok {
			return nil, fmt.Errorf("confstore: snapshot contains unknown kind %q", kind)
		}
	}
	for _, info := range model.Kinds() {
		for _, e := range sortedByName(s.objects[info.Kind]) {
			if !wanted[string(info.Kind)+"/"+e.GetMeta().ID] {
				ops = append(ops, Op{Type: OpDelete, Kind: info.Kind, ID: e.GetMeta().ID, IfMatch: e.GetMeta().Version})
			}
		}
	}
	return ops, nil
}

// diffFieldsRaw is diffFields without masking, so a changed secret counts.
func diffFieldsRaw(a, b model.Entity) []string {
	var ma, mb map[string]any
	_ = json.Unmarshal(mustJSON(a), &ma)
	_ = json.Unmarshal(mustJSON(b), &mb)
	var out []string
	for k := range mergeKeys(ma, mb) {
		if contains(bookkeeping, k) {
			continue
		}
		x, _ := json.Marshal(ma[k])
		y, _ := json.Marshal(mb[k])
		if !bytes.Equal(x, y) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func loadSnapshot(path string) (*State, error) {
	st := newState()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("confstore: %s: %w", path, err)
	}
	if snap.Schema > model.SchemaVersion {
		return nil, fmt.Errorf("confstore: %s was written by a newer version (schema %d)", path, snap.Schema)
	}
	st.index, st.hash = snap.Index, snap.Hash
	for kind, objs := range snap.Objects {
		st.objects[kind] = map[string]model.Entity{}
		for _, raw := range objs {
			raw, err := migrate(snap.Schema, kind, raw)
			if err != nil {
				return nil, err
			}
			e, err := model.Decode(kind, raw)
			if err != nil {
				return nil, fmt.Errorf("confstore: %s: %w", path, err)
			}
			st.objects[kind][e.GetMeta().ID] = e
		}
	}
	for i := range snap.ChangeSets {
		st.changesets[snap.ChangeSets[i].ID] = &snap.ChangeSets[i]
	}
	return st, nil
}

// Compact folds all but the newest keep records into the snapshot file and
// trims the log. History and Revert reach only the records that remain.
// The snapshot is written and synced before the log is replaced, and Open
// skips log records the snapshot already covers, so an interruption at any
// point loses nothing.
func (s *Store) Compact(keep int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.Current().index - int64(keep)
	base, err := loadSnapshot(filepath.Join(s.dir, snapshotFile))
	if err != nil {
		return err
	}
	if cut <= base.index {
		return nil
	}
	var tail bytes.Buffer
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			f.Close()
			return err
		}
		switch {
		case r.Index <= base.index:
		case r.Index <= cut:
			if base, err = base.apply(r); err != nil {
				f.Close()
				return err
			}
		default:
			tail.Write(sc.Bytes())
			tail.WriteByte('\n')
		}
	}
	f.Close()
	if err := sc.Err(); err != nil {
		return err
	}
	snap, err := json.Marshal(base.Export())
	if err != nil {
		return err
	}
	if err := writeFileSync(filepath.Join(s.dir, snapshotFile), snap); err != nil {
		return err
	}
	if err := writeFileSync(s.path, tail.Bytes()); err != nil {
		return err
	}
	nf, err := os.OpenFile(s.path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.log.Close()
	s.log = nf
	return nil
}

// writeFileSync replaces path atomically with mode 0600.
func writeFileSync(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// VerifyLog walks the store's log from its snapshot and checks the hash
// chain. It returns how many chained records it checked and the index of
// the first one that does not match (0: intact). Records from before the
// chain carry no hash; the first chained record after them still covers
// them. It only reads, so it works while the daemon has the store open.
func VerifyLog(dir string) (checked int, brokenAt int64, err error) {
	hash := ""
	if data, err := os.ReadFile(filepath.Join(dir, snapshotFile)); err == nil {
		var snap Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return 0, 0, err
		}
		hash = snap.Hash
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, 0, err
	}
	f, err := os.Open(filepath.Join(dir, "config.log"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil // no configuration yet
	}
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			break // a torn last line
		}
		want := chainHash(hash, r)
		if r.Hash != "" {
			checked++
			if r.Prev != hash || r.Hash != want {
				return checked, r.Index, nil
			}
		}
		hash = want
	}
	return checked, 0, sc.Err()
}

// Verify checks the store's own log; see VerifyLog.
func (s *Store) Verify() (checked int, brokenAt int64, err error) { return VerifyLog(s.dir) }
