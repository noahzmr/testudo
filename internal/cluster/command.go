// Package cluster replicates the control plane between nodes with Raft:
// the configuration model, change sets, the state of a rollout, secrets
// (sealed), and who the members are. Packets, sessions and flow records
// never go through it.
//
// The configuration store is the state machine. A write is prepared on the
// leader, agreed on, and applied by every member; an object's version is
// the same number everywhere.
package cluster

import (
	"encoding/json"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
)

// Command is one entry of the replicated log. Every entry says what it is
// and in which version of its format, so that members running different
// builds during an upgrade never guess.
type Command struct {
	Type    string          `json:"type"`
	Version int             `json:"v"`
	Actor   string          `json:"actor,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Command types.
const (
	CmdRecord  = "record"       // a configuration record and what travels with it (RecordEntry)
	CmdSeed    = "seed"         // the whole model, for a cluster started from an existing node
	CmdResult  = "apply_result" // a member reports how applying a record went
	CmdPending = "pending"      // a change waits for confirmation, or no longer does
	CmdRollout = "rollout"      // a rollout moves from the canary to everyone
	CmdMember  = "member"       // a member announces its build and addresses
	CmdSecret  = "secret"       // a sealed secret is stored or removed
	CmdRevoke  = "revoke"       // a member's certificate is no longer accepted
)

// Supported lists the command types this build can apply and the highest
// format version of each. A member announces this map; the leader proposes
// a command only when every voter can apply it.
var Supported = map[string]int{
	CmdRecord: 1, CmdSeed: 1, CmdResult: 1, CmdPending: 1, CmdRollout: 1, CmdMember: 1, CmdSecret: 1, CmdRevoke: 1,
}

// Member is what a node announces about itself.
type Member struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Build  string `json:"build,omitempty"`
	Schema int    `json:"schema"`
	Raft   string `json:"raft"` // address of the consensus transport
	API    string `json:"api"`  // address of the member API
	Serial string `json:"serial,omitempty"`
	Voter  bool   `json:"voter"`
	// Commands is the member's Supported map.
	Commands map[string]int `json:"commands"`
}

// Result is a member's report on applying the model up to Index.
type Result struct {
	Node  string    `json:"node"`
	Index int64     `json:"index"`
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
	// Drift says what the running system differs in from the model, as
	// last seen; empty when it matches.
	Drift string `json:"drift,omitempty"`
}

// Pending is a change that is live and waits to be confirmed.
type Pending struct {
	Index    int64     `json:"index"`
	Actor    string    `json:"actor"`
	Note     string    `json:"note,omitempty"`
	Deadline time.Time `json:"deadline"`
}

// Rollout phases.
const (
	PhaseCanary = "canary" // only the canary applies
	PhaseAll    = "all"    // every member applies
)

// Rollout says how far a change may spread. While the phase is canary,
// only the canary member applies records up to Index; the others keep what
// they run.
type Rollout struct {
	Index  int64  `json:"index"`
	Canary string `json:"canary"`
	Phase  string `json:"phase"`
}

// RecordEntry is a configuration record together with the state of its
// rollout. They are one log entry on purpose: a record must never become
// effective without the deadline by which someone has to confirm it. That
// includes a record whose proposal failed on a leader that was cut off and
// which is agreed on later after all; it arrives with a deadline that has
// passed, and is rolled back.
type RecordEntry struct {
	Record confstore.Record `json:"record"`
	// Pending and Rollout replace the current ones when SetPending or
	// SetRollout is set; a nil value then clears.
	Pending    *Pending `json:"pending,omitempty"`
	SetPending bool     `json:"set_pending,omitempty"`
	Rollout    *Rollout `json:"rollout,omitempty"`
	SetRollout bool     `json:"set_rollout,omitempty"`
}

// SecretOp stores or removes one sealed secret.
type SecretOp struct {
	Name   string `json:"name"`
	Sealed []byte `json:"sealed,omitempty"`
	Remove bool   `json:"remove,omitempty"`
}

// State is the replicated state next to the model.
type State struct {
	Members map[string]Member `json:"members"`
	Results map[string]Result `json:"results"`
	Pending *Pending          `json:"pending,omitempty"`
	Rollout *Rollout          `json:"rollout,omitempty"`
	// Revoked maps certificate serials to when they were revoked.
	Revoked map[string]time.Time `json:"revoked,omitempty"`
	// Secrets holds sealed secrets by name.
	Secrets map[string][]byte `json:"secrets,omitempty"`
}

func newState() *State {
	return &State{Members: map[string]Member{}, Results: map[string]Result{}, Revoked: map[string]time.Time{}, Secrets: map[string][]byte{}}
}

func (s *State) clone() *State {
	c := newState()
	for k, v := range s.Members {
		c.Members[k] = v
	}
	for k, v := range s.Results {
		c.Results[k] = v
	}
	for k, v := range s.Revoked {
		c.Revoked[k] = v
	}
	for k, v := range s.Secrets {
		c.Secrets[k] = v
	}
	if s.Pending != nil {
		p := *s.Pending
		c.Pending = &p
	}
	if s.Rollout != nil {
		r := *s.Rollout
		c.Rollout = &r
	}
	return c
}

// MayApply reports whether a member may apply the model at index now.
func (s *State) MayApply(node string, index int64) bool {
	r := s.Rollout
	return r == nil || r.Phase == PhaseAll || r.Canary == node || index < r.Index
}

// snapshot is what a Raft snapshot holds: the model and the state next to
// it.
type snapshot struct {
	Model   confstore.Snapshot `json:"model"`
	Cluster *State             `json:"cluster"`
}

func command(typ string, actor string, payload any) (Command, error) {
	raw, err := json.Marshal(payload)
	return Command{Type: typ, Version: Supported[typ], Actor: actor, Payload: raw}, err
}
