// Package confstore is the versioned store behind the configuration model.
//
// It is built as a deterministic state machine fed by a log of records, so
// the single-node file log used today can be replaced by a replicated log
// without changing callers: an object's version is the index of the log
// record that last wrote it, which makes optimistic concurrency (If-Match)
// mean the same thing on every node.
package confstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/noahzmr/testudo/internal/model"
)

// OpType is what a change does to one object.
type OpType string

const (
	OpCreate OpType = "create"
	OpUpdate OpType = "update"
	OpDelete OpType = "delete"
)

// Op is one requested change. IfMatch is the version the change is based on;
// it is required for update and delete.
type Op struct {
	Type    OpType          `json:"type"`
	Kind    model.Kind      `json:"kind"`
	ID      string          `json:"id,omitempty"`
	Object  json.RawMessage `json:"object,omitempty"`
	IfMatch int64           `json:"if_match,omitempty"`
}

// Change is what one op did, with the object before and after. Secrets are
// present; use Masked before a Change leaves the process.
type Change struct {
	Type   OpType          `json:"type"`
	Kind   model.Kind      `json:"kind"`
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

// Record is one committed transaction: the unit of the log, of history and
// of the audit trail.
type Record struct {
	Index   int64     `json:"index"`
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Type    string    `json:"type"` // "commit", "revert", "changeset"
	Note    string    `json:"note,omitempty"`
	Reverts int64     `json:"reverts,omitempty"`
	Changes []Change  `json:"changes,omitempty"`
	// Change-set bookkeeping travels in the same log.
	PutChangeSet     *ChangeSet `json:"put_changeset,omitempty"`
	DeleteChangeSets []string   `json:"delete_changesets,omitempty"`
}

// ChangeSet is a named draft: changes one user prepares and applies later,
// alone or together with other change sets.
type ChangeSet struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	Ops       []Op      `json:"ops"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FieldDiff is one differing top-level field in a version conflict.
type FieldDiff struct {
	Field   string `json:"field"`
	Yours   any    `json:"yours"`
	Current any    `json:"current"`
}

// ConflictError reports a write based on a stale version.
type ConflictError struct {
	Kind           model.Kind  `json:"kind"`
	ID             string      `json:"id"`
	YourVersion    int64       `json:"your_version"`
	CurrentVersion int64       `json:"current_version"` // 0 when the object is gone
	CurrentBy      string      `json:"current_by,omitempty"`
	Diff           []FieldDiff `json:"diff,omitempty"`
	Reason         string      `json:"reason,omitempty"`
}

func (e *ConflictError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("conflict on %s %s: %s", e.Kind, e.ID, e.Reason)
	}
	return fmt.Sprintf("conflict on %s %s: based on version %d, current is %d (changed by %s)",
		e.Kind, e.ID, e.YourVersion, e.CurrentVersion, e.CurrentBy)
}

// Use is one object that references another.
type Use struct {
	Kind  model.Kind `json:"kind"`
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Field string     `json:"field"`
}

// ReferencedError blocks the deletion of an object that is still in use.
type ReferencedError struct {
	Kind   model.Kind `json:"kind"`
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	UsedBy []Use      `json:"used_by"`
}

func (e *ReferencedError) Error() string {
	users := make([]string, len(e.UsedBy))
	for i, u := range e.UsedBy {
		users[i] = fmt.Sprintf("%s %q (%s)", u.Kind, u.Name, u.Field)
	}
	return fmt.Sprintf("%s %q is still used by: %s", e.Kind, e.Name, strings.Join(users, ", "))
}

// Problem is one failed cross-object check.
type Problem struct {
	Kind    model.Kind `json:"kind"`
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Field   string     `json:"field,omitempty"`
	Message string     `json:"message"`
}

// IntegrityError collects every cross-object problem of a candidate model.
type IntegrityError struct {
	Problems []Problem `json:"problems"`
}

func (e *IntegrityError) Error() string {
	parts := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		parts[i] = fmt.Sprintf("%s %q %s: %s", p.Kind, p.Name, p.Field, p.Message)
	}
	return "model is inconsistent: " + strings.Join(parts, "; ")
}

var (
	ErrNotFound      = errors.New("confstore: not found")
	ErrIfMatchNeeded = errors.New("confstore: update and delete need the version they are based on")
)

// State is one immutable version of the whole model. Readers may keep a
// State for as long as they like; commits build a new one.
type State struct {
	index      int64
	objects    map[model.Kind]map[string]model.Entity
	changesets map[string]*ChangeSet
}

func newState() *State {
	return &State{objects: map[model.Kind]map[string]model.Entity{}, changesets: map[string]*ChangeSet{}}
}

// Index is the log index this state reflects.
func (s *State) Index() int64 { return s.index }

// Get returns a copy of one object.
func (s *State) Get(kind model.Kind, id string) (model.Entity, bool) {
	e, ok := s.objects[kind][id]
	if !ok {
		return nil, false
	}
	return model.Clone(e), true
}

// peek returns the stored object without copying; callers must not modify it.
func (s *State) peek(kind model.Kind, id string) model.Entity { return s.objects[kind][id] }

// List returns copies of every object of a kind, ordered by name.
func (s *State) List(kind model.Kind) []model.Entity {
	out := make([]model.Entity, 0, len(s.objects[kind]))
	for _, e := range s.objects[kind] {
		out = append(out, model.Clone(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetMeta().Name < out[j].GetMeta().Name })
	return out
}

// UsedBy lists the objects that reference the given one.
func (s *State) UsedBy(kind model.Kind, id string) []Use {
	var out []Use
	for _, info := range model.Kinds() {
		for _, e := range s.objects[info.Kind] {
			for _, r := range model.Refs(e) {
				if r.Target == kind && r.ID == id {
					out = append(out, Use{Kind: e.Kind(), ID: e.GetMeta().ID, Name: e.GetMeta().Name, Field: r.Field})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return string(out[i].Kind)+out[i].Name+out[i].Field < string(out[j].Kind)+out[j].Name+out[j].Field
	})
	return out
}

// ChangeSets returns every change set, ordered by name.
func (s *State) ChangeSets() []ChangeSet {
	out := make([]ChangeSet, 0, len(s.changesets))
	for _, c := range s.changesets {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].ID < out[j].Name+out[j].ID })
	return out
}

// ChangeSet returns one change set.
func (s *State) ChangeSet(id string) (ChangeSet, bool) {
	c, ok := s.changesets[id]
	if !ok {
		return ChangeSet{}, false
	}
	return *c, true
}

// with returns a copy of the state in which the given kinds can be modified
// without affecting s.
func (s *State) with(index int64, kinds ...model.Kind) *State {
	n := &State{index: index, objects: maps.Clone(s.objects), changesets: s.changesets}
	for _, k := range kinds {
		n.objects[k] = maps.Clone(s.objects[k])
		if n.objects[k] == nil {
			n.objects[k] = map[string]model.Entity{}
		}
	}
	return n
}

// prepare validates ops against s and returns the resulting state and the
// changes, without side effects. It is deterministic: everything that varies
// (time, actor, new IDs) comes in through the arguments or the ops.
func (s *State) prepare(index int64, actor string, now time.Time, ops []Op) (*State, []Change, error) {
	kinds := make([]model.Kind, 0, len(ops))
	seen := map[string]bool{}
	for _, op := range ops {
		if _, ok := model.Lookup(string(op.Kind)); !ok {
			return nil, nil, fmt.Errorf("confstore: unknown kind %q", op.Kind)
		}
		kinds = append(kinds, op.Kind)
		if op.ID != "" {
			key := string(op.Kind) + "/" + op.ID
			if seen[key] {
				return nil, nil, &ConflictError{Kind: op.Kind, ID: op.ID,
					Reason: "the object is changed more than once in this transaction (overlapping change sets)"}
			}
			seen[key] = true
		}
	}
	next := s.with(index, kinds...)
	var changes []Change
	var touched []model.Entity
	var deleted []model.Entity

	for _, op := range ops {
		cur := s.peek(op.Kind, op.ID)
		switch op.Type {
		case OpCreate:
			e, err := model.Decode(op.Kind, op.Object)
			if err != nil {
				return nil, nil, err
			}
			m := e.GetMeta()
			if m.ID == "" {
				m.ID = op.ID
			}
			if m.ID == "" {
				return nil, nil, fmt.Errorf("confstore: create %s without an id", op.Kind)
			}
			if s.peek(op.Kind, m.ID) != nil || next.objects[op.Kind][m.ID] != nil {
				return nil, nil, &ConflictError{Kind: op.Kind, ID: m.ID, Reason: "an object with this id already exists"}
			}
			if m.Scope == "" {
				m.Scope = model.ScopeGlobal
			}
			m.Version, m.CreatedAt, m.CreatedBy, m.UpdatedAt, m.UpdatedBy = index, now, actor, now, actor
			if err := model.Validate(e); err != nil {
				return nil, nil, err
			}
			next.objects[op.Kind][m.ID] = e
			touched = append(touched, e)
			changes = append(changes, Change{Type: OpCreate, Kind: op.Kind, ID: m.ID, Name: m.Name, After: mustJSON(e)})

		case OpUpdate:
			e, err := model.Decode(op.Kind, op.Object)
			if err != nil {
				return nil, nil, err
			}
			if err := checkVersion(op, cur, e); err != nil {
				return nil, nil, err
			}
			model.KeepMaskedSecrets(e, cur)
			m, cm := e.GetMeta(), cur.GetMeta()
			m.ID, m.CreatedAt, m.CreatedBy = cm.ID, cm.CreatedAt, cm.CreatedBy
			m.Version, m.UpdatedAt, m.UpdatedBy = index, now, actor
			if err := model.Validate(e); err != nil {
				return nil, nil, err
			}
			next.objects[op.Kind][m.ID] = e
			touched = append(touched, e)
			changes = append(changes, Change{Type: OpUpdate, Kind: op.Kind, ID: m.ID, Name: m.Name,
				Before: mustJSON(cur), After: mustJSON(e)})

		case OpDelete:
			if err := checkVersion(op, cur, nil); err != nil {
				return nil, nil, err
			}
			delete(next.objects[op.Kind], op.ID)
			deleted = append(deleted, cur)
			changes = append(changes, Change{Type: OpDelete, Kind: op.Kind, ID: op.ID,
				Name: cur.GetMeta().Name, Before: mustJSON(cur)})

		default:
			return nil, nil, fmt.Errorf("confstore: unknown op type %q", op.Type)
		}
	}

	// Names are unique per kind.
	for _, k := range kinds {
		names := map[string]string{}
		for id, e := range next.objects[k] {
			if other, dup := names[e.GetMeta().Name]; dup {
				first, second := other, id
				if first > second {
					first, second = second, first
				}
				return nil, nil, &model.ValidationError{Kind: k, ID: second, Fields: []model.FieldError{{
					Field: "name", Rule: "unique", Message: fmt.Sprintf("another %s is already named %q", k, e.GetMeta().Name)}}}
			}
			names[e.GetMeta().Name] = id
		}
	}
	// Deleting something that is still referenced is refused, with the list
	// of referrers. Deleting referrer and target together is fine.
	for _, d := range deleted {
		if users := next.UsedBy(d.Kind(), d.GetMeta().ID); len(users) > 0 {
			return nil, nil, &ReferencedError{Kind: d.Kind(), ID: d.GetMeta().ID, Name: d.GetMeta().Name, UsedBy: users}
		}
	}
	var problems []Problem
	for _, e := range touched {
		for _, r := range model.Refs(e) {
			if next.peek(r.Target, r.ID) == nil {
				problems = append(problems, Problem{Kind: e.Kind(), ID: e.GetMeta().ID, Name: e.GetMeta().Name,
					Field: r.Field, Message: fmt.Sprintf("references %s %s, which does not exist", r.Target, r.ID)})
			}
		}
	}
	if len(problems) == 0 {
		problems = runChecks(next)
	}
	if len(problems) > 0 {
		return nil, nil, &IntegrityError{Problems: problems}
	}
	return next, changes, nil
}

func checkVersion(op Op, cur, yours model.Entity) error {
	if cur == nil {
		return &ConflictError{Kind: op.Kind, ID: op.ID, YourVersion: op.IfMatch,
			Reason: "the object does not exist (it may have been deleted)"}
	}
	if op.IfMatch == 0 {
		return ErrIfMatchNeeded
	}
	if cm := cur.GetMeta(); cm.Version != op.IfMatch {
		return &ConflictError{Kind: op.Kind, ID: op.ID, YourVersion: op.IfMatch,
			CurrentVersion: cm.Version, CurrentBy: cm.UpdatedBy, Diff: diffFields(yours, cur)}
	}
	return nil
}

// bookkeeping fields never show up in a conflict diff.
var bookkeeping = []string{"version", "created_at", "created_by", "updated_at", "updated_by"}

// diffFields compares two objects field by field. Secrets are masked first.
func diffFields(yours, current model.Entity) []FieldDiff {
	if yours == nil || current == nil {
		return nil
	}
	var a, b map[string]any
	_ = json.Unmarshal(mustJSON(model.Mask(yours)), &a)
	_ = json.Unmarshal(mustJSON(model.Mask(current)), &b)
	var out []FieldDiff
	for k := range mergeKeys(a, b) {
		if slices.Contains(bookkeeping, k) || reflect.DeepEqual(a[k], b[k]) {
			continue
		}
		out = append(out, FieldDiff{Field: k, Yours: a[k], Current: b[k]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func mergeKeys(a, b map[string]any) map[string]struct{} {
	keys := map[string]struct{}{}
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range b {
		keys[k] = struct{}{}
	}
	return keys
}

func mustJSON(e model.Entity) json.RawMessage {
	b, err := json.Marshal(e)
	if err != nil {
		panic(fmt.Sprintf("confstore: marshal %s: %v", e.Kind(), err))
	}
	return b
}

// apply folds a committed record into the state without re-validating it:
// the log is trusted, and validation rules may have changed since.
func (s *State) apply(r Record) (*State, error) {
	kinds := make([]model.Kind, 0, len(r.Changes))
	for _, c := range r.Changes {
		kinds = append(kinds, c.Kind)
	}
	next := s.with(r.Index, kinds...)
	for _, c := range r.Changes {
		if c.Type == OpDelete {
			delete(next.objects[c.Kind], c.ID)
			continue
		}
		e, err := model.Decode(c.Kind, c.After)
		if err != nil {
			return nil, fmt.Errorf("confstore: record %d: %w", r.Index, err)
		}
		next.objects[c.Kind][c.ID] = e
	}
	if r.PutChangeSet != nil || len(r.DeleteChangeSets) > 0 {
		next.changesets = maps.Clone(s.changesets)
		for _, id := range r.DeleteChangeSets {
			delete(next.changesets, id)
		}
		if cs := r.PutChangeSet; cs != nil {
			c := *cs
			next.changesets[c.ID] = &c
		}
	}
	return next, nil
}

// Masked returns the change with secrets replaced, for audit output, events
// and API responses.
func (c Change) Masked() Change {
	mask := func(raw json.RawMessage) json.RawMessage {
		if len(raw) == 0 {
			return nil
		}
		e, err := model.Decode(c.Kind, raw)
		if err != nil {
			return nil
		}
		return mustJSON(model.Mask(e))
	}
	c.Before, c.After = mask(c.Before), mask(c.After)
	return c
}

// NewID returns a fresh object identifier.
func NewID() string { return uuid.NewString() }
