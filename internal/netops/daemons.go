package netops

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Managed daemons other than the proxy: keepalived (VRRP between the two
// nodes of a site), conntrackd (their connection-state sync), and the
// network services: Kea for DHCPv4 and DHCPv6, Unbound, chronyd and radvd.
// The privileged runner starts them with fixed command lines; a request
// only names the daemon, what to do, where its configuration is, and
// options from the daemon's own short list.

const (
	// OpDaemonControl starts, restarts, reloads or stops a daemon (Op.Daemon).
	OpDaemonControl OpKind = "daemon_control"
	// OpQueryDaemonStatus reports "running", "stopped" or "missing".
	OpQueryDaemonStatus OpKind = "daemon_status"
)

// DaemonMode selects what happens to a daemon.
type DaemonMode string

const (
	DaemonEnsure  DaemonMode = "ensure"  // start it unless it runs
	DaemonRestart DaemonMode = "restart" // stop and start
	DaemonReload  DaemonMode = "reload"  // read the configuration again (keepalived: SIGHUP; others restart)
	DaemonStop    DaemonMode = "stop"
	DaemonStatus  DaemonMode = "status"
)

// DaemonRequest is one job for the daemon supervisor.
type DaemonRequest struct {
	Name string     `json:"name"` // "keepalived" or "conntrackd"
	Mode DaemonMode `json:"mode"`
	// ConfigFile is the daemon's configuration, an absolute path with the
	// daemon's usual file name. RunDir holds its pid files. LogFile gets its
	// output.
	ConfigFile string `json:"config_file,omitempty"`
	RunDir     string `json:"run_dir,omitempty"`
	LogFile    string `json:"log_file,omitempty"`
	// Options are named switches the daemon's spec knows (chronyd:
	// "serve-only").
	Options []string `json:"options,omitempty"`
}

func (r DaemonRequest) has(option string) bool {
	for _, o := range r.Options {
		if o == option {
			return true
		}
	}
	return false
}

type daemonSpec struct {
	paths []string
	conf  string // the configuration's file name
	args  func(req DaemonRequest) []string
	// env adds to the daemon's environment.
	env func(req DaemonRequest) []string
	// options are the switches a request may set.
	options []string
	// hup says the daemon reads its configuration again on SIGHUP.
	hup bool
}

// keaEnv keeps Kea's pid and lock files in the run directory instead of
// the distribution's.
func keaEnv(r DaemonRequest) []string {
	return []string{"KEA_PIDFILE_DIR=" + r.RunDir, "KEA_LOCKFILE_DIR=" + r.RunDir}
}

var daemonSpecs = map[string]daemonSpec{
	"keepalived": {paths: []string{"/usr/sbin/keepalived", "/sbin/keepalived"}, conf: "keepalived.conf", hup: true,
		args: func(r DaemonRequest) []string {
			return []string{"--dont-fork", "--log-console", "--log-detail", "--use-file=" + r.ConfigFile,
				"--pid=" + filepath.Join(r.RunDir, "keepalived.pid"), "--vrrp_pid=" + filepath.Join(r.RunDir, "vrrp.pid"),
				"--checkers_pid=" + filepath.Join(r.RunDir, "checkers.pid")}
		}},
	"conntrackd": {paths: []string{"/usr/sbin/conntrackd", "/sbin/conntrackd"}, conf: "conntrackd.conf",
		args: func(r DaemonRequest) []string { return []string{"-C", r.ConfigFile} }},
	"kea-dhcp4": {paths: []string{"/usr/sbin/kea-dhcp4"}, conf: "kea-dhcp4.conf", hup: true, env: keaEnv,
		args: func(r DaemonRequest) []string { return []string{"-c", r.ConfigFile} }},
	"kea-dhcp6": {paths: []string{"/usr/sbin/kea-dhcp6"}, conf: "kea-dhcp6.conf", hup: true, env: keaEnv,
		args: func(r DaemonRequest) []string { return []string{"-c", r.ConfigFile} }},
	// Unbound drops to its own user; its configuration lives where that
	// user can read it again on SIGHUP.
	"unbound": {paths: []string{"/usr/sbin/unbound"}, conf: "unbound.conf", hup: true,
		args: func(r DaemonRequest) []string { return []string{"-d", "-p", "-c", r.ConfigFile} }},
	// chronyd has no reload; a change restarts it. serve-only keeps its
	// hands off the system clock.
	"chronyd": {paths: []string{"/usr/sbin/chronyd"}, conf: "chrony.conf", options: []string{"serve-only"},
		args: func(r DaemonRequest) []string {
			args := []string{"-d", "-f", r.ConfigFile}
			if r.has("serve-only") {
				args = append(args, "-x")
			}
			return args
		}},
	"radvd": {paths: []string{"/usr/sbin/radvd"}, conf: "radvd.conf", hup: true,
		args: func(r DaemonRequest) []string {
			return []string{"-n", "-m", "stderr", "-u", "radvd", "-p", filepath.Join(r.RunDir, "radvd.pid"), "-C", r.ConfigFile}
		}},
}

// DaemonBinary returns where a managed daemon is installed.
func DaemonBinary(name string) (string, error) {
	spec, ok := daemonSpecs[name]
	if !ok {
		return "", fmt.Errorf("unknown daemon %q", name)
	}
	for _, p := range spec.paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return exec.LookPath(name)
}

type daemonProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *daemonProc) running() bool {
	if p == nil || p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

var daemons = struct {
	mu    sync.Mutex
	procs map[string]*daemonProc
}{procs: map[string]*daemonProc{}}

func cleanPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\n\x00")
}

// procKey tells instances apart: one per daemon and run directory, so a
// test can run two nodes' daemons in one process.
func procKey(req DaemonRequest) string { return req.Name + "@" + req.RunDir }

func stopDaemon(key string) {
	p := daemons.procs[key]
	if p.running() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	}
	delete(daemons.procs, key)
}

func startDaemon(req DaemonRequest, spec daemonSpec, bin string) error {
	if !cleanPath(req.ConfigFile) || filepath.Base(req.ConfigFile) != spec.conf || !cleanPath(req.RunDir) {
		return fmt.Errorf("%s: bad configuration or run directory path", req.Name)
	}
	if err := os.MkdirAll(req.RunDir, 0o700); err != nil {
		return err
	}
	for _, o := range req.Options {
		known := false
		for _, k := range spec.options {
			known = known || o == k
		}
		if !known {
			return fmt.Errorf("%s: unknown option %q", req.Name, o)
		}
	}
	cmd := exec.Command(bin, spec.args(req)...)
	if spec.env != nil {
		cmd.Env = append(os.Environ(), spec.env(req)...)
	}
	if req.LogFile != "" && cleanPath(req.LogFile) {
		if f, err := os.OpenFile(req.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
			cmd.Stdout, cmd.Stderr = f, f
			defer f.Close()
		}
	}
	// The daemon goes down with its supervisor.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", req.Name, err)
	}
	p := &daemonProc{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	daemons.procs[procKey(req)] = p
	select {
	case <-p.done:
		delete(daemons.procs, procKey(req))
		return fmt.Errorf("%s exited right after starting; see its log", req.Name)
	case <-time.After(300 * time.Millisecond):
		return nil
	}
}

// RunDaemon executes one request against this process's daemon supervisor.
func RunDaemon(req DaemonRequest) NftResult {
	spec, ok := daemonSpecs[req.Name]
	if !ok {
		return NftResult{Error: fmt.Sprintf("unknown daemon %q", req.Name)}
	}
	daemons.mu.Lock()
	defer daemons.mu.Unlock()
	bin, berr := DaemonBinary(req.Name)
	key := procKey(req)
	var err error
	switch req.Mode {
	case DaemonStatus:
		switch {
		case berr != nil:
			return NftResult{Output: "missing"}
		case daemons.procs[key].running():
			return NftResult{Output: "running"}
		}
		return NftResult{Output: "stopped"}
	case DaemonEnsure:
		if !daemons.procs[key].running() {
			if berr != nil {
				return NftResult{Error: req.Name + " is not installed"}
			}
			err = startDaemon(req, spec, bin)
		}
	case DaemonReload:
		if p := daemons.procs[key]; spec.hup && p.running() {
			err = p.cmd.Process.Signal(syscall.SIGHUP)
			break
		}
		fallthrough
	case DaemonRestart:
		stopDaemon(key)
		if berr != nil {
			return NftResult{Error: req.Name + " is not installed"}
		}
		err = startDaemon(req, spec, bin)
	case DaemonStop:
		stopDaemon(key)
	default:
		err = fmt.Errorf("unknown mode %q", req.Mode)
	}
	if err != nil {
		return NftResult{Error: err.Error()}
	}
	return NftResult{Output: "ok"}
}

var (
	daemonRunnerMu sync.RWMutex
	daemonRunner   func(DaemonRequest) NftResult
)

// SetDaemonRunner routes every daemon request of this process through fn.
func SetDaemonRunner(fn func(DaemonRequest) NftResult) {
	daemonRunnerMu.Lock()
	daemonRunner = fn
	daemonRunnerMu.Unlock()
}

func runDaemon(req DaemonRequest) (string, error) {
	daemonRunnerMu.RLock()
	fn := daemonRunner
	daemonRunnerMu.RUnlock()
	if fn == nil {
		fn = RunDaemon
	}
	res := fn(req)
	if res.Error != "" {
		return "", errors.New(res.Error)
	}
	return res.Output, nil
}

// DaemonControl starts, restarts, reloads or stops a managed daemon. It is
// a mutation.
func (w *Writer) DaemonControl(req DaemonRequest) error {
	if !w.AllowWrites {
		return fmt.Errorf("%s control: writes are disabled", req.Name)
	}
	if req.Mode == DaemonStatus {
		return errors.New("daemon control: status is a query")
	}
	return w.mutate(Op{Kind: OpDaemonControl, Daemon: &req})
}

// DaemonState reports "running", "stopped" or "missing" (not installed)
// for the daemon with that run directory.
func (w *Writer) DaemonState(name, runDir string) (string, error) {
	var out string
	err := w.queryInto(Op{Kind: OpQueryDaemonStatus, Daemon: &DaemonRequest{Name: name, Mode: DaemonStatus, RunDir: runDir}}, &out)
	return out, err
}
