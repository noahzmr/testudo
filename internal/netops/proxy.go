package netops

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// The managed proxy (Traefik) is a child of the privileged side: it has to
// bind listener ports, and it must not die when the engine restarts a
// request. Four requests exist: make sure it runs, restart it, stop it, and
// say whether it runs.

const (
	// OpProxyControl starts, restarts or stops the proxy (Op.Proxy).
	OpProxyControl OpKind = "proxy_control"
	// OpQueryProxyStatus reports "running", "stopped" or "missing".
	OpQueryProxyStatus OpKind = "proxy_status"
)

// ProxyMode selects what happens to the proxy process.
type ProxyMode string

const (
	ProxyEnsure  ProxyMode = "ensure"  // start it unless it runs
	ProxyRestart ProxyMode = "restart" // stop and start: the static configuration changed
	ProxyStop    ProxyMode = "stop"
	ProxyStatus  ProxyMode = "status"
)

// ProxyRequest is one job for the proxy supervisor.
type ProxyRequest struct {
	Mode ProxyMode `json:"mode"`
	// ConfigFile is the static configuration, an absolute path.
	ConfigFile string `json:"config_file,omitempty"`
	// LogFile receives the proxy's own output.
	LogFile string `json:"log_file,omitempty"`
}

// ProxyWrapper, when set, is put in front of the proxy's command line. The
// daemon sets it to a re-execution of itself that sheds every capability
// the proxy has no use for before it becomes the proxy.
var ProxyWrapper []string

var proxyPaths = []string{"/usr/local/bin/traefik", "/usr/bin/traefik"}

func proxyBinary() (string, error) {
	for _, p := range proxyPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return exec.LookPath("traefik")
}

type proxySupervisor struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
}

var proxySup proxySupervisor

func (s *proxySupervisor) running() bool {
	if s.cmd == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *proxySupervisor) stop() {
	if !s.running() {
		s.cmd = nil
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
	s.cmd = nil
}

func (s *proxySupervisor) start(req ProxyRequest) error {
	bin, err := proxyBinary()
	if err != nil {
		return errors.New("the proxy (traefik) is not installed")
	}
	if !filepath.IsAbs(req.ConfigFile) || filepath.Base(req.ConfigFile) != "traefik.yml" {
		return errors.New("bad proxy configuration path")
	}
	args := append(append([]string{}, ProxyWrapper...), bin, "--configFile="+req.ConfigFile)
	cmd := exec.Command(args[0], args[1:]...)
	if req.LogFile != "" && filepath.IsAbs(req.LogFile) {
		if f, err := os.OpenFile(req.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
			cmd.Stdout, cmd.Stderr = f, f
			defer f.Close()
		}
	}
	// The proxy goes down with its supervisor.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the proxy: %w", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	s.cmd, s.done = cmd, done
	// A proxy that cannot bind its ports or read its configuration exits at
	// once; say so instead of reporting a start.
	select {
	case <-done:
		s.cmd = nil
		return errors.New("the proxy exited right after starting; see its log")
	case <-time.After(300 * time.Millisecond):
		return nil
	}
}

// RunProxy executes one request against this process's proxy supervisor.
func RunProxy(req ProxyRequest) NftResult {
	s := &proxySup
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	switch req.Mode {
	case ProxyStatus:
		if _, berr := proxyBinary(); berr != nil {
			return NftResult{Output: "missing"}
		}
		if s.running() {
			return NftResult{Output: "running"}
		}
		return NftResult{Output: "stopped"}
	case ProxyEnsure:
		if !s.running() {
			err = s.start(req)
		}
	case ProxyRestart:
		s.stop()
		err = s.start(req)
	case ProxyStop:
		s.stop()
	default:
		err = fmt.Errorf("unknown proxy mode %q", req.Mode)
	}
	if err != nil {
		return NftResult{Error: err.Error()}
	}
	return NftResult{Output: "ok"}
}

var (
	proxyRunnerMu sync.RWMutex
	proxyRunner   func(ProxyRequest) NftResult
)

// SetProxyRunner routes every proxy request of this process through fn.
func SetProxyRunner(fn func(ProxyRequest) NftResult) {
	proxyRunnerMu.Lock()
	proxyRunner = fn
	proxyRunnerMu.Unlock()
}

func runProxy(req ProxyRequest) (string, error) {
	proxyRunnerMu.RLock()
	fn := proxyRunner
	proxyRunnerMu.RUnlock()
	if fn == nil {
		fn = RunProxy
	}
	res := fn(req)
	if res.Error != "" {
		return "", errors.New("proxy: " + res.Error)
	}
	return res.Output, nil
}

// ProxyControl starts, restarts or stops the proxy. It is a mutation.
func (w *Writer) ProxyControl(mode ProxyMode, configFile, logFile string) error {
	if !w.AllowWrites {
		return fmt.Errorf("proxy control: writes are disabled")
	}
	return w.mutate(Op{Kind: OpProxyControl, Proxy: &ProxyRequest{Mode: mode, ConfigFile: configFile, LogFile: logFile}})
}

// ProxyState reports "running", "stopped" or "missing" (not installed).
func (w *Writer) ProxyState() (string, error) {
	var out string
	err := w.queryInto(Op{Kind: OpQueryProxyStatus}, &out)
	return out, err
}
