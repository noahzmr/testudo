package netops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FRRouting is driven the way nft is: a fixed set of requests, executed by
// the runner on the privileged side. Check a configuration, reload the
// daemons from a configuration, or read one of a fixed list of state views.

const (
	// OpFrrReload makes the running daemons match a configuration (Op.Frr).
	OpFrrReload OpKind = "frr_reload"
	// OpQueryFrrCheck has FRR's parser validate a configuration (Op.Frr).
	OpQueryFrrCheck OpKind = "frr_check"
	// OpQueryFrrShow returns one state view (Op.Name) as JSON.
	OpQueryFrrShow OpKind = "frr_show"
	// OpQueryFrrAvailable reports whether FRR is installed and reachable.
	OpQueryFrrAvailable OpKind = "frr_available"
)

// FrrMode selects what the runner does with FRR.
type FrrMode string

const (
	FrrCheck  FrrMode = "check"
	FrrReload FrrMode = "reload"
	FrrShow   FrrMode = "show"
)

// FrrRequest is one job for the runner.
type FrrRequest struct {
	Mode FrrMode `json:"mode"`
	Conf string  `json:"conf,omitempty"`
	View string  `json:"view,omitempty"`
}

// FrrViews are the state views that can be read, and the command each one
// runs. Nothing else is ever passed to vtysh.
var FrrViews = map[string]string{
	"daemons":        "show daemons",
	"routes":         "show ip route json",
	"routes6":        "show ipv6 route json",
	"bgp":            "show bgp summary json",
	"ospf-neighbors": "show ip ospf neighbor json",
	"bfd":            "show bfd peers json",
	"running-config": "show running-config",
}

const (
	frrConfDir    = "/etc/frr"
	frrReloadTool = "/usr/lib/frr/frr-reload.py"
)

// RunFrr executes one request with FRR's own tools.
func RunFrr(req FrrRequest) NftResult {
	vtysh, err := exec.LookPath("vtysh")
	if err != nil {
		return NftResult{Error: "FRR is not installed (vtysh not found)"}
	}
	run := func(timeout time.Duration, name string, args ...string) NftResult {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			msg := strings.TrimSpace(stderr.String() + "\n" + out.String())
			if msg == "" {
				msg = err.Error()
			}
			return NftResult{Error: msg}
		}
		return NftResult{Output: out.String()}
	}
	switch req.Mode {
	case FrrShow:
		cmd, ok := FrrViews[req.View]
		if !ok {
			return NftResult{Error: fmt.Sprintf("unknown view %q", req.View)}
		}
		return run(20*time.Second, vtysh, "-c", cmd)
	case FrrCheck, FrrReload:
		// The configuration is written next to FRR's own, readable by its
		// daemons' group only: it can contain session passwords.
		dir := frrConfDir
		if req.Mode == FrrCheck {
			dir = os.TempDir()
		}
		f, err := os.CreateTemp(dir, "testudo-frr-*.conf")
		if err != nil {
			return NftResult{Error: err.Error()}
		}
		defer os.Remove(f.Name())
		_, werr := f.WriteString(req.Conf)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return NftResult{Error: werr.Error()}
		}
		if req.Mode == FrrCheck {
			return run(20*time.Second, vtysh, "-C", "-f", f.Name())
		}
		_ = os.Chmod(f.Name(), 0o640)
		if _, err := os.Stat(frrReloadTool); err != nil {
			return NftResult{Error: "frr-reload.py is not installed (package frr-pythontools)"}
		}
		return run(90*time.Second, frrReloadTool, "--reload", "--overwrite", "--stdout",
			"--bindir", filepath.Dir(vtysh), "--confdir", frrConfDir, f.Name())
	}
	return NftResult{Error: fmt.Sprintf("unknown frr mode %q", req.Mode)}
}

var (
	frrRunnerMu sync.RWMutex
	frrRunner   func(FrrRequest) NftResult
)

// SetFrrRunner routes every FRR request of this process through fn.
func SetFrrRunner(fn func(FrrRequest) NftResult) {
	frrRunnerMu.Lock()
	frrRunner = fn
	frrRunnerMu.Unlock()
}

func runFrr(req FrrRequest) (string, error) {
	frrRunnerMu.RLock()
	fn := frrRunner
	frrRunnerMu.RUnlock()
	if fn == nil {
		fn = RunFrr
	}
	res := fn(req)
	if res.Error != "" {
		return "", errors.New("frr: " + res.Error)
	}
	return res.Output, nil
}

// FrrAvailable reports whether FRR's daemons can be reached from the
// privileged side.
func (w *Writer) FrrAvailable() bool {
	var ok bool
	return w.queryInto(Op{Kind: OpQueryFrrAvailable}, &ok) == nil && ok
}

// FrrCheck has FRR's parser validate a configuration without applying it.
func (w *Writer) FrrCheck(conf string) error {
	var res string
	return w.queryInto(Op{Kind: OpQueryFrrCheck, Frr: conf}, &res)
}

// FrrReload makes the running daemons match conf. It is a mutation.
func (w *Writer) FrrReload(conf string) error {
	if !w.AllowWrites {
		return fmt.Errorf("frr reload: writes are disabled")
	}
	return w.mutate(Op{Kind: OpFrrReload, Frr: conf})
}

// FrrShow returns one of the FrrViews.
func (w *Writer) FrrShow(view string) (string, error) {
	var out string
	err := w.queryInto(Op{Kind: OpQueryFrrShow, Name: view}, &out)
	return out, err
}

func frrQueryDirect(op Op) ([]byte, error) {
	switch op.Kind {
	case OpQueryFrrAvailable:
		_, err := runFrr(FrrRequest{Mode: FrrShow, View: "daemons"})
		return json.Marshal(err == nil)
	case OpQueryFrrCheck:
		_, err := runFrr(FrrRequest{Mode: FrrCheck, Conf: op.Frr})
		return marshalResult("ok", err)
	default:
		return marshalResult(runFrr(FrrRequest{Mode: FrrShow, View: op.Name}))
	}
}
