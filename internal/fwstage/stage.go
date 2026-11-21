// Package fwstage applies the nftables ruleset that internal/fwrender
// produces from the model: the policy and baseline, the rules, NAT, kernel
// load balancing, access grants. It loads the whole table in one nft
// transaction, checks that the kernel still holds what it loaded, and loads
// it again when something else changed it.
package fwstage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/fwrender"
	"github.com/noahzmr/testudo/internal/netops"
)

// Runner loads and inspects rulesets. *netops.Writer implements it.
type Runner interface {
	WritesAllowed() bool
	NftCheck(ruleset string) error
	NftApply(ruleset string) error
	NftListTable(family, table string) ([]byte, error)
}

// Stage implements confapply.Stage.
type Stage struct {
	Runner Runner
	// ProtectedTCPPorts stay open on the input chain whatever the policy
	// says: SSH and the console, the ways back in.
	ProtectedTCPPorts []int
	// Locate finds this node in the model; nil means only global objects.
	Locate func(*confstore.State) (siteID, nodeID string)
	// Elements returns the current content of run-time aliases by alias id.
	Elements func() map[string][]string
	// BackendDown returns the backends of kernel-mode load balancing that
	// failed their health check.
	BackendDown func() map[string]bool

	mu      sync.Mutex
	frags   fwrender.Fragments
	loaded  bool   // the fragments are what the model wants, applied once
	applied string // the ruleset the kernel is believed to hold
}

func (s *Stage) Name() string { return "packet-filter" }

type artifact struct {
	Fragments fwrender.Fragments `json:"fragments"`
}

// Render builds the model's fragments. The result does not depend on the
// running side, so the same state always renders to the same artifact.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	opt := fwrender.Options{ProtectedTCPPorts: s.ProtectedTCPPorts}
	if s.Locate != nil {
		opt.SiteID, opt.NodeID = s.Locate(st)
	}
	if s.Elements != nil {
		opt.Elements = s.Elements()
	}
	if s.BackendDown != nil {
		opt.BackendDown = s.BackendDown()
	}
	frags, err := fwrender.Build(st, opt)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(artifact{Fragments: frags}, "", " ")
}

func decode(raw []byte) (artifact, error) {
	var a artifact
	err := json.Unmarshal(raw, &a)
	return a, err
}

// assemble is the ruleset; it removes the old firewall manager's tables in
// the same transaction.
func assemble(f fwrender.Fragments) string {
	return fwrender.Assemble(f, &fwrender.Running{DropLegacyTables: true})
}

// Check assembles the ruleset the change would produce and has nft validate
// it. Nothing is loaded.
func (s *Stage) Check(_ context.Context, raw []byte) error {
	a, err := decode(raw)
	if err != nil {
		return err
	}
	err = s.Runner.NftCheck(assemble(a.Fragments))
	if err != nil && !a.Fragments.HasPolicy && s.outOfReach(err) {
		return nil // nothing to enforce, and nothing to enforce it with
	}
	return err
}

// outOfReach reports whether err means this process cannot change the packet
// filter at all: no privileged side, or writes turned off. A model without
// a firewall policy asks nothing of the kernel, so such a node still takes
// the rest of the model.
func (s *Stage) outOfReach(err error) bool {
	if !s.Runner.WritesAllowed() || errors.Is(err, os.ErrPermission) {
		return true
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "operation not permitted") || strings.Contains(m, "permission denied")
}

// Apply loads the ruleset the artifact describes.
func (s *Stage) Apply(_ context.Context, raw []byte) error {
	a, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, prevLoaded := s.frags, s.loaded
	s.frags, s.loaded = a.Fragments, true
	if err := s.loadLocked(); err != nil {
		if !a.Fragments.HasPolicy && s.outOfReach(err) {
			return nil
		}
		s.frags, s.loaded = prev, prevLoaded
		return err
	}
	return nil
}

// Refresh renders the model again and loads the result if it differs. It is
// for content that changes without a model change: the elements of run-time
// aliases. Nothing is committed and there is no confirmation window, because
// the rules are the same ones the operator already confirmed.
func (s *Stage) Refresh(st *confstore.State) error {
	raw, err := s.Render(st)
	if err != nil {
		return err
	}
	a, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.frags
	s.frags = a.Fragments
	if err := s.loadLocked(); err != nil {
		s.frags = prev
		return err
	}
	return nil
}

// Healthy reports whether the kernel holds the ruleset that was loaded.
func (s *Stage) Healthy(context.Context) error {
	st, err := s.read()
	if err != nil {
		if !s.hasPolicy() && s.outOfReach(err) {
			return nil
		}
		return err
	}
	if !s.hasPolicy() && !s.Runner.WritesAllowed() {
		return nil // a table left behind is reported by the reconciler
	}
	if !s.hasPolicy() {
		// Without a firewall policy the model filters nothing and loads no
		// table.
		if st.exists {
			return errors.New("a table of Testudo is in the kernel although the model has no firewall policy")
		}
		return nil
	}
	if !st.current {
		return errors.New("the kernel does not hold the ruleset that was just loaded")
	}
	return nil
}

// Drift is what a reconcile found.
type Drift struct {
	// InSync: the kernel holds the ruleset the model wants.
	InSync bool `json:"in_sync"`
	// Reloaded: it did not, and the ruleset was loaded again.
	Reloaded bool   `json:"reloaded,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Reconcile checks that the kernel still holds the model's ruleset and
// loads it again when it does not (a reboot, someone's nft flush). Before
// the first apply there is nothing to compare with.
func (s *Stage) Reconcile() Drift {
	s.mu.Lock()
	loaded := s.loaded
	s.mu.Unlock()
	if !loaded {
		return Drift{InSync: true}
	}
	st, err := s.read()
	if err != nil {
		return Drift{Error: err.Error()}
	}
	if (st.exists || s.hasPolicy()) && !st.current {
		if !s.Runner.WritesAllowed() {
			return Drift{Error: "the kernel's ruleset differs from the model's, and writes are disabled"}
		}
		s.mu.Lock()
		s.applied = ""
		err := s.loadLocked()
		s.mu.Unlock()
		if err != nil {
			return Drift{Error: "reloading the ruleset: " + err.Error()}
		}
		return Drift{InSync: true, Reloaded: true}
	}
	return Drift{InSync: true}
}

func (s *Stage) hasPolicy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frags.HasPolicy
}

// Status is the running packet filter as the UIs show it.
type Status struct {
	Loaded      bool   `json:"loaded"`
	HasPolicy   bool   `json:"has_policy"`
	DefaultDeny bool   `json:"default_deny"`
	InSync      bool   `json:"in_sync"`
	Error       string `json:"error,omitempty"`
}

// Status reads the kernel and says whether it holds the model's ruleset.
func (s *Stage) Status() Status {
	s.mu.Lock()
	out := Status{Loaded: s.loaded, HasPolicy: s.frags.HasPolicy, DefaultDeny: s.frags.Policy.DefaultDeny}
	s.mu.Unlock()
	st, err := s.read()
	switch {
	case err != nil:
		out.Error = err.Error()
	case !out.HasPolicy:
		out.InSync = !st.exists || st.current
	default:
		out.InSync = st.current
	}
	return out
}

// loadLocked loads the assembled ruleset unless the kernel already has it.
func (s *Stage) loadLocked() error {
	text := assemble(s.frags)
	if text == s.applied {
		return nil
	}
	if err := s.Runner.NftApply(text); err != nil {
		return err
	}
	s.applied = text
	return nil
}

// Counter is the traffic one object has matched.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type kernelRule struct {
	chain   string
	handle  uint64
	comment string
	Counter
	hasCounter bool
}

type kernelState struct {
	exists   bool
	current  bool // the generation marker matches what was loaded
	policies map[string]string
	rules    []kernelRule
}

var genRe = regexp.MustCompile(`^gen_[0-9a-f]{16}$`)

// read lists the table and decodes the generation marker and the counters.
func (s *Stage) read() (kernelState, error) {
	st := kernelState{policies: map[string]string{}}
	raw, err := s.Runner.NftListTable("inet", fwrender.Table)
	if errors.Is(err, netops.ErrNftTableMissing) {
		s.forget()
		return st, nil
	}
	if err != nil {
		return st, err
	}
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Name   string `json:"name"`
				Policy string `json:"policy"`
			} `json:"chain"`
			Set *struct {
				Name string `json:"name"`
			} `json:"set"`
			Rule *struct {
				Chain   string            `json:"chain"`
				Handle  uint64            `json:"handle"`
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return st, fmt.Errorf("decode nft listing: %w", err)
	}
	st.exists = true
	s.mu.Lock()
	want := fwrender.Generation(s.frags)
	s.mu.Unlock()
	for _, o := range doc.Nftables {
		switch {
		case o.Chain != nil && o.Chain.Policy != "":
			st.policies[o.Chain.Name] = o.Chain.Policy
		case o.Set != nil && genRe.MatchString(o.Set.Name):
			st.current = o.Set.Name == want
		case o.Rule != nil:
			r := kernelRule{chain: o.Rule.Chain, handle: o.Rule.Handle, comment: o.Rule.Comment}
			for _, e := range o.Rule.Expr {
				var c struct {
					Counter *Counter `json:"counter"`
				}
				if json.Unmarshal(e, &c) == nil && c.Counter != nil {
					r.Counter, r.hasCounter = *c.Counter, true
				}
			}
			st.rules = append(st.rules, r)
		}
	}
	if !st.current {
		s.forget()
	}
	return st, nil
}

// forget makes the next load unconditional: the kernel no longer holds what
// was loaded last.
func (s *Stage) forget() {
	s.mu.Lock()
	s.applied = ""
	s.mu.Unlock()
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Counters returns what each model object has matched, by object id. A model
// rule can be several kernel rules; their counters are added up.
func (s *Stage) Counters() (map[string]Counter, error) {
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	out := map[string]Counter{}
	for _, r := range st.rules {
		if uuidRe.MatchString(r.comment) {
			c := out[r.comment]
			c.Packets += r.Packets
			c.Bytes += r.Bytes
			out[r.comment] = c
		}
	}
	return out, nil
}
