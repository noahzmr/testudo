// Package hastage applies an HA pair on a node: it writes the files that
// internal/harender produces and keeps keepalived and conntrackd running
// through the privileged side.
package hastage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/harender"
	"github.com/noahzmr/testudo/internal/netops"
)

// Runner is the privileged side. *netops.Writer implements it.
type Runner interface {
	DaemonControl(req netops.DaemonRequest) error
	DaemonState(name, runDir string) (string, error)
}

// Stage implements confapply.Stage.
type Stage struct {
	Runner Runner
	Locate func(*confstore.State) (siteID, nodeID string)
	// Dir holds configuration and scripts (root only); RunDir pid files,
	// lock and control socket (a short path).
	Dir, RunDir string

	mu      sync.Mutex
	applied map[string]string
}

func (s *Stage) Name() string { return "ha" }

func (s *Stage) options(st *confstore.State) harender.Options {
	o := harender.Options{Dir: s.Dir, RunDir: s.RunDir}
	if s.Locate != nil {
		o.SiteID, o.NodeID = s.Locate(st)
	}
	return o
}

// Render builds the node's HA setup.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	res, err := harender.Render(st, s.options(st))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(res, "", " ")
}

func decode(raw []byte) (harender.Result, error) {
	var r harender.Result
	err := json.Unmarshal(raw, &r)
	return r, err
}

var daemonsUsed = []string{"conntrackd", "keepalived"}

// Check makes sure the daemons can run here.
func (s *Stage) Check(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil || !res.Enabled {
		return err
	}
	if s.Runner == nil {
		return errors.New("HA is not available on this node (no privileges)")
	}
	for _, d := range daemonsUsed {
		state, err := s.Runner.DaemonState(d, s.RunDir)
		if err != nil {
			return err
		}
		if state == "missing" {
			return fmt.Errorf("%s is not installed on this node", d)
		}
	}
	return nil
}

func (s *Stage) req(name string, mode netops.DaemonMode, conf string) netops.DaemonRequest {
	return netops.DaemonRequest{Name: name, Mode: mode, ConfigFile: filepath.Join(s.Dir, conf), RunDir: s.RunDir,
		LogFile: filepath.Join(s.Dir, name+".log")}
}

// Apply writes the files and makes the daemons run with them.
func (s *Stage) Apply(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !res.Enabled {
		// Stop what this program started; leave a node that never had HA
		// alone.
		if _, err := os.Stat(filepath.Join(s.Dir, harender.KeepalivedConf)); err != nil || s.Runner == nil {
			s.applied = nil
			return nil
		}
		// keepalived first: it gives the virtual addresses up.
		for _, d := range []string{"keepalived", "conntrackd"} {
			if err := s.Runner.DaemonControl(netops.DaemonRequest{Name: d, Mode: netops.DaemonStop, RunDir: s.RunDir}); err != nil {
				return err
			}
		}
		for name := range map[string]bool{harender.KeepalivedConf: true, harender.ConntrackdConf: true, harender.MasterScript: true, harender.BackupScript: true} {
			_ = os.Remove(filepath.Join(s.Dir, name))
		}
		s.applied = nil
		return nil
	}
	if s.Runner == nil {
		return errors.New("HA is not available on this node (no privileges)")
	}
	// keepalived runs the scripts as root and refuses ones that others
	// could change.
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	names := make([]string, 0, len(res.Files))
	for n := range res.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	changed := map[string]bool{}
	for _, n := range names {
		mode := os.FileMode(0o600)
		if n == harender.MasterScript || n == harender.BackupScript {
			mode = 0o700
		}
		path := filepath.Join(s.Dir, n)
		if old, err := os.ReadFile(path); err == nil && string(old) == res.Files[n] {
			continue
		}
		changed[n] = true
		if err := os.WriteFile(path+".tmp", []byte(res.Files[n]), mode); err != nil {
			return err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return err
		}
	}
	// conntrackd first, so the scripts keepalived runs find it.
	ct := netops.DaemonEnsure
	if changed[harender.ConntrackdConf] {
		ct = netops.DaemonRestart
	}
	if err := s.Runner.DaemonControl(s.req("conntrackd", ct, harender.ConntrackdConf)); err != nil {
		return err
	}
	ka := netops.DaemonEnsure
	if changed[harender.KeepalivedConf] {
		ka = netops.DaemonReload
	}
	if err := s.Runner.DaemonControl(s.req("keepalived", ka, harender.KeepalivedConf)); err != nil {
		return err
	}
	s.applied = res.Files
	return nil
}

// Healthy checks that both daemons stayed up.
func (s *Stage) Healthy(ctx context.Context) error {
	s.mu.Lock()
	on := s.applied != nil
	s.mu.Unlock()
	if !on {
		return nil
	}
	time.Sleep(200 * time.Millisecond)
	for _, d := range daemonsUsed {
		state, err := s.Runner.DaemonState(d, s.RunDir)
		if err != nil {
			return err
		}
		if state != "running" {
			return fmt.Errorf("%s is not running (%s); see %s", d, state, filepath.Join(s.Dir, d+".log"))
		}
	}
	return nil
}

// Active reports whether this node holds the pair's virtual addresses
// now, and which of them it holds.
func Active(virtualIPs []string) (bool, []string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, nil
	}
	have := map[string]bool{}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			have[n.IP.String()] = true
		}
	}
	var held []string
	for _, v := range virtualIPs {
		ip, _, err := net.ParseCIDR(v)
		if err == nil && have[ip.String()] {
			held = append(held, v)
		}
	}
	return len(held) > 0 && len(held) == len(virtualIPs), held
}
