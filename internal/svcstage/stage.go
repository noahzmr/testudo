// Package svcstage applies the node's network services: it writes what
// internal/svcrender produces, checks it with each daemon's own checker,
// and keeps Kea, Unbound, chronyd and radvd running through the
// privileged side. It also reads the leases and keeps the names of DHCP
// clients in the resolver (names.go).
package svcstage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/svcrender"
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
	// Dir holds leases and logs (root only). RunDir holds the
	// configuration, which daemons that drop privileges read again on a
	// reload, pid files and control sockets.
	Dir, RunDir, HooksDir string

	mu      sync.Mutex
	applied *svcrender.Result
}

func (s *Stage) Name() string { return "services" }

func (s *Stage) options(st *confstore.State) svcrender.Options {
	o := svcrender.Options{Dir: s.Dir, RunDir: s.RunDir, HooksDir: s.HooksDir}
	if s.Locate != nil {
		o.SiteID, o.NodeID = s.Locate(st)
	}
	return o
}

// Render builds the node's services.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	res, err := svcrender.Render(st, s.options(st))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(res, "", " ")
}

func decode(raw []byte) (svcrender.Result, error) {
	var r svcrender.Result
	err := json.Unmarshal(raw, &r)
	return r, err
}

// checkers run each daemon's own configuration check on a file.
var checkers = map[string]func(file string) *exec.Cmd{
	svcrender.DaemonKea4:    func(f string) *exec.Cmd { return exec.Command("kea-dhcp4", "-t", f) },
	svcrender.DaemonKea6:    func(f string) *exec.Cmd { return exec.Command("kea-dhcp6", "-t", f) },
	svcrender.DaemonUnbound: func(f string) *exec.Cmd { return exec.Command("unbound-checkconf", f) },
	svcrender.DaemonRadvd:   func(f string) *exec.Cmd { return exec.Command("radvd", "-c", "-C", f) },
	svcrender.DaemonChrony:  func(f string) *exec.Cmd { return exec.Command("chronyd", "-p", "-f", f) },
}

// Check makes sure every daemon is installed and accepts its configuration,
// and that no other program sets the clock when chronyd is to.
func (s *Stage) Check(ctx context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil || !res.Enabled() {
		return err
	}
	if s.Runner == nil {
		return errors.New("network services are not available on this node (no privileges)")
	}
	tmp, err := os.MkdirTemp("", "testudo-svc-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	// Unbound's check opens the include file.
	if err := s.ensureLeaseNames(); err != nil {
		return err
	}
	for _, d := range res.Daemons {
		state, err := s.Runner.DaemonState(d, s.RunDir)
		if err != nil {
			return err
		}
		if state == "missing" {
			return fmt.Errorf("%s is not installed on this node", d)
		}
		file := filepath.Join(tmp, svcrender.ConfOf[d])
		if err := os.WriteFile(file, []byte(res.Files[svcrender.ConfOf[d]]), 0o644); err != nil {
			return err
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		cmd := checkers[d](file)
		cmd = exec.CommandContext(cctx, cmd.Path, cmd.Args[1:]...)
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("%s refuses its configuration: %s", d, firstLines(string(out), 6))
		}
	}
	if contains(res.Daemons, svcrender.DaemonChrony) && !res.ServeOnly {
		if other := clockDaemons(filepath.Join(s.RunDir, "chronyd.pid")); len(other) > 0 {
			return fmt.Errorf("%s sets the clock already; stop it (for example: systemctl disable --now chrony systemd-timesyncd) or let the NTP service leave the clock alone",
				strings.Join(other, ", "))
		}
	}
	return nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// clockDaemons lists other processes that discipline the clock, apart
// from the chronyd whose pid file is ownPid.
func clockDaemons(ownPid string) []string {
	own := 0
	if b, err := os.ReadFile(ownPid); err == nil {
		own, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	names := map[string]bool{"chronyd": true, "ntpd": true, "systemd-timesyn": true, "openntpd": true, "ntpsec": true}
	entries, _ := os.ReadDir("/proc")
	var out []string
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == own {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		if c := strings.TrimSpace(string(comm)); names[c] {
			out = append(out, fmt.Sprintf("%s (pid %d)", c, pid))
		}
	}
	sort.Strings(out)
	return out
}

func (s *Stage) ensureLeaseNames() error {
	if err := os.MkdirAll(s.RunDir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(s.RunDir, 0o755); err != nil {
		return err
	}
	p := filepath.Join(s.RunDir, svcrender.LeaseNames)
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(p, nil, 0o644)
	}
	return nil
}

func (s *Stage) req(name string, mode netops.DaemonMode, res svcrender.Result) netops.DaemonRequest {
	r := netops.DaemonRequest{Name: name, Mode: mode, ConfigFile: filepath.Join(s.RunDir, svcrender.ConfOf[name]),
		RunDir: s.RunDir, LogFile: filepath.Join(s.Dir, name+".log")}
	if name == svcrender.DaemonChrony && res.ServeOnly {
		r.Options = []string{"serve-only"}
	}
	return r
}

// hups lists the daemons that read their configuration again on SIGHUP;
// the others restart on a change.
var hups = map[string]bool{svcrender.DaemonKea4: true, svcrender.DaemonKea6: true, svcrender.DaemonUnbound: true, svcrender.DaemonRadvd: true}

// Apply writes the files and makes the daemons run with them.
func (s *Stage) Apply(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.applied
	if !res.Enabled() {
		if s.Runner != nil {
			for i := len(svcrender.AllDaemons) - 1; i >= 0; i-- {
				d := svcrender.AllDaemons[i]
				if err := s.Runner.DaemonControl(netops.DaemonRequest{Name: d, Mode: netops.DaemonStop, RunDir: s.RunDir}); err != nil {
					return err
				}
				_ = os.Remove(filepath.Join(s.RunDir, svcrender.ConfOf[d]))
			}
		}
		s.applied = &res
		return nil
	}
	if s.Runner == nil {
		return errors.New("network services are not available on this node (no privileges)")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := s.ensureLeaseNames(); err != nil {
		return err
	}
	changed := map[string]bool{}
	for name, body := range res.Files {
		path := filepath.Join(s.RunDir, name)
		if old, err := os.ReadFile(path); err == nil && string(old) == body {
			continue
		}
		changed[name] = true
		if err := os.WriteFile(path+".tmp", []byte(body), 0o644); err != nil {
			return err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return err
		}
	}
	// Stop what is no longer wanted, last started first.
	for i := len(svcrender.AllDaemons) - 1; i >= 0; i-- {
		d := svcrender.AllDaemons[i]
		if contains(res.Daemons, d) {
			continue
		}
		if err := s.Runner.DaemonControl(netops.DaemonRequest{Name: d, Mode: netops.DaemonStop, RunDir: s.RunDir}); err != nil {
			return err
		}
		_ = os.Remove(filepath.Join(s.RunDir, svcrender.ConfOf[d]))
	}
	for _, d := range res.Daemons {
		mode := netops.DaemonEnsure
		switch {
		case d == svcrender.DaemonChrony && prev != nil && prev.ServeOnly != res.ServeOnly:
			mode = netops.DaemonRestart
		case changed[svcrender.ConfOf[d]] && hups[d]:
			mode = netops.DaemonReload
		case changed[svcrender.ConfOf[d]]:
			mode = netops.DaemonRestart
		}
		if err := s.Runner.DaemonControl(s.req(d, mode, res)); err != nil {
			return err
		}
	}
	s.applied = &res
	return nil
}

// Healthy checks that every daemon stayed up.
func (s *Stage) Healthy(context.Context) error {
	s.mu.Lock()
	res := s.applied
	s.mu.Unlock()
	if res == nil || !res.Enabled() {
		return nil
	}
	time.Sleep(500 * time.Millisecond)
	for _, d := range res.Daemons {
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

// Applied returns what was applied last, or nil.
func (s *Stage) Applied() *svcrender.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied
}
