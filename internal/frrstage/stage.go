// Package frrstage applies the routing setup that internal/frrender
// produces: the routing daemon's configuration through FRR's own reload
// tool, and VRF devices and policy rules in the kernel.
package frrstage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/frrender"
	"github.com/noahzmr/testudo/internal/netops"
)

// Runner is the privileged side. *netops.Writer implements it.
type Runner interface {
	WritesAllowed() bool
	FrrAvailable() bool
	FrrCheck(conf string) error
	FrrReload(conf string) error
	FrrShow(view string) (string, error)
	SyncRouting(spec netops.RoutingSpec) error
}

// Stage implements confapply.Stage.
type Stage struct {
	// Runner may be nil on a node without network privileges; then only a
	// model without routing objects can be applied.
	Runner Runner
	Locate func(*confstore.State) (siteID, nodeID string)
	// Down returns the gateways whose monitor currently fails.
	Down func() map[string]bool
	// StateDir holds the marker that says this program manages the routing
	// daemon's configuration.
	StateDir string

	mu      sync.Mutex
	applied string
}

func (s *Stage) Name() string { return "routing" }

// Render builds the routing setup for this node.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	var opt frrender.Options
	if s.Locate != nil {
		opt.SiteID, opt.NodeID = s.Locate(st)
	}
	if s.Down != nil {
		opt.Down = s.Down()
	}
	res, err := frrender.Render(st, opt)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(res, "", " ")
}

var passwordRe = regexp.MustCompile(`(?m)^( neighbor \S+ password ).*$`)

// Redact hides session passwords in an artifact that is shown to a person.
func (s *Stage) Redact(artifact []byte) []byte {
	var res frrender.Result
	if json.Unmarshal(artifact, &res) != nil {
		return nil
	}
	return []byte(passwordRe.ReplaceAllString(res.Conf, "${1}********"))
}

func (s *Stage) marker() string { return filepath.Join(s.StateDir, "routing-managed") }

// managed reports whether this program has taken over the routing daemon's
// configuration. Until the model has routing objects it has not, and an
// existing configuration is left exactly as it is.
func (s *Stage) managed() bool {
	_, err := os.Stat(s.marker())
	return err == nil
}

func decode(raw []byte) (frrender.Result, error) {
	var res frrender.Result
	err := json.Unmarshal(raw, &res)
	return res, err
}

// Check has FRR's parser validate the configuration. Nothing is applied.
func (s *Stage) Check(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil || res.Empty {
		return err
	}
	if s.Runner == nil {
		return errors.New("routing is not available on this node (no network privileges)")
	}
	if !res.NeedsDaemon {
		return nil
	}
	if !s.Runner.FrrAvailable() {
		return errors.New("the routing daemon (FRR) is not installed or not running on this node")
	}
	return s.Runner.FrrCheck(res.Conf)
}

// Apply brings kernel and routing daemon in line with the artifact.
func (s *Stage) Apply(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	managed := s.managed()
	if res.Empty && !managed {
		return nil
	}
	if s.Runner == nil {
		return errors.New("routing is not available on this node (no network privileges)")
	}
	spec := netops.RoutingSpec{RulePriorityLow: frrender.RulePriorityBase, RulePriorityHigh: frrender.RulePriorityBase + 999}
	for _, v := range res.VRFs {
		spec.VRFs = append(spec.VRFs, netops.RoutingVRF{Name: v.Name, Table: v.Table, Members: v.Members})
	}
	for _, r := range res.Rules {
		spec.Rules = append(spec.Rules, netops.RoutingRule{Priority: r.Priority, Mark: r.Mark, Table: r.Table})
	}
	// VRF devices first: the daemon needs them to exist.
	if err := s.Runner.SyncRouting(spec); err != nil {
		return err
	}
	if res.NeedsDaemon || managed {
		if err := s.Runner.FrrReload(res.Conf); err != nil {
			return err
		}
	}
	s.applied = string(raw)
	if res.Empty {
		_ = os.Remove(s.marker())
		return nil
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.marker(), []byte("the routing daemon's configuration is managed by testudo\n"), 0o600)
}

// Healthy reports whether the daemons the configuration needs are running.
func (s *Stage) Healthy(context.Context) error {
	s.mu.Lock()
	raw := s.applied
	s.mu.Unlock()
	res, err := decode([]byte(raw))
	if raw == "" || err != nil || !res.NeedsDaemon {
		return nil
	}
	out, err := s.Runner.FrrShow("daemons")
	if err != nil {
		return err
	}
	running := map[string]bool{}
	for _, d := range strings.Fields(out) {
		running[d] = true
	}
	var missing []string
	for _, d := range append([]string{"zebra", "staticd"}, res.Daemons...) {
		if !running[d] {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("FRR daemons not running: %s (enable them in /etc/frr/daemons)", strings.Join(missing, ", "))
	}
	return nil
}

// Refresh renders again and applies the result if it differs. It is for
// changes of gateway health: the routes move without a model change and
// without a confirmation window.
func (s *Stage) Refresh(ctx context.Context, st *confstore.State) error {
	raw, err := s.Render(st)
	if err != nil {
		return err
	}
	s.mu.Lock()
	same := string(raw) == s.applied
	s.mu.Unlock()
	if same {
		return nil
	}
	return s.Apply(ctx, raw)
}
