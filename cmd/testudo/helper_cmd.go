package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/health"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/privsep"
	"github.com/noahzmr/testudo/internal/storage"
)

// helperReport captures the outcome of the privilege-separation handshake so
// the engine can surface it in the self-status surface and the one-line header.
type helperReport struct {
	enabled bool   // --privsep was on
	ok      bool   // helper spawned, handshook, and caps dropped
	pid     int    // helper pid when ok
	err     string // why the helper is unavailable
	dropErr string // non-fatal: caps could not be fully dropped
}

// report records the privilege-separation posture into the engine's health
// registry and one-line status string.
func (r helperReport) report(eng *engine.Engine) {
	switch {
	case !r.enabled:
		eng.SetPrivsepInfo("privilege separation disabled (--privsep=false); running in a single privileged process")
		eng.MarkSubsystem("priv-helper", false, health.StateDegraded,
			"privsep disabled", "start without --privsep=false to isolate privileged ops")
	case r.ok:
		info := fmt.Sprintf("running unprivileged; privileged ops via helper (pid %d)", r.pid)
		if r.dropErr != "" {
			info += " - note: " + r.dropErr
		}
		eng.SetPrivsepInfo(info)
		eng.MarkSubsystem("priv-helper", false, health.StateOK, "", "")
	default:
		eng.SetPrivsepInfo("privileged helper unavailable - falling back to in-process netops: " + r.err)
		eng.MarkSubsystem("priv-helper", false, health.StateDegraded, r.err,
			"privileged ops run in-process; check helper spawn / capabilities")
	}
}

// setupNetops wires the netops Writer to either the privileged helper (default)
// or the legacy in-process path. When privsep is on it spawns the helper, hands
// it the capabilities, drops the engine's own, and forwards mutations over the
// socket. Any failure degrades gracefully to the in-process writer so the tool
// still runs.
func setupNetops(ctx context.Context, cfg config.Config, allowWrites, usePrivsep bool) (*netops.Writer, *privsep.Client, helperReport) {
	if !usePrivsep {
		return &netops.Writer{AllowWrites: allowWrites}, nil, helperReport{enabled: false}
	}
	// Let the privileged helper find the audit DB.
	_ = os.Setenv(envAuditDB, cfg.SQLitePath)

	client, cmd, err := privsep.Spawn(ctx)
	if err != nil {
		return &netops.Writer{AllowWrites: allowWrites}, nil, helperReport{enabled: true, err: err.Error()}
	}
	if err := client.Ping(); err != nil {
		_ = client.Close()
		return &netops.Writer{AllowWrites: allowWrites}, nil, helperReport{enabled: true, err: "handshake: " + err.Error()}
	}

	report := helperReport{enabled: true, ok: true, pid: cmd.Process.Pid}
	// Capabilities now live with the helper; drop ours so the engine, web
	// server, and TUI run unprivileged. A failure here is non-fatal - we still
	// route mutations through the helper.
	if derr := privsep.DropPrivileges(); derr != nil {
		report.dropErr = derr.Error()
	}
	return netops.NewHelperWriter(allowWrites, client), client, report
}

// envAuditDB names the env var the engine sets before spawning the helper so
// the privileged side can append to the same audit log the UIs read.
const envAuditDB = "TESTUDO_AUDIT_DB"

// runHelper is the privileged-helper entry point (testudo __helper). It is
// re-exec'd by privsep.Spawn with the SEQPACKET socket on fd 3 and inherits the
// binary's file capabilities. It holds the caps, applies a seccomp denylist,
// and performs the narrow set of privileged operations the unprivileged engine
// requests, auditing every mutation.
func runHelper() error {
	// We hold the capabilities here. A direct (in-process) Writer executes the
	// netlink/nftables mutations against the kernel.
	nw := &netops.Writer{AllowWrites: true}

	var store *storage.Store
	if p := os.Getenv(envAuditDB); p != "" {
		if s, err := storage.Open(p); err == nil {
			store = s
			defer s.Close()
		} else {
			fmt.Fprintf(os.Stderr, "helper: audit log unavailable: %v\n", err)
		}
	}

	captures := newCaptureReg()

	handler := func(op byte, body []byte) ([]byte, int, error) {
		switch op {
		case privsep.OpMutate:
			o, err := netops.DecodeOp(body)
			if err != nil {
				return nil, -1, fmt.Errorf("decode op: %w", err)
			}
			return nil, -1, nw.ApplyOp(o)
		case privsep.OpQuery:
			o, err := netops.DecodeOp(body)
			if err != nil {
				return nil, -1, fmt.Errorf("decode query: %w", err)
			}
			resp, err := nw.QueryOp(o)
			return resp, -1, err
		case privsep.OpOpenSocket:
			return openPrivilegedSocket(body)
		case privsep.OpCaptureStart:
			return captures.handleStart(body)
		case privsep.OpCaptureStop:
			return captures.handleStop(body)
		case privsep.OpCaptureStatus:
			return captures.handleStatus(body)
		default:
			return nil, -1, fmt.Errorf("helper: unknown op %#x", op)
		}
	}

	audit := func(op byte, body []byte, peerUID uint32, err error) {
		if store == nil {
			return
		}
		result := "ok"
		if err != nil {
			result = err.Error()
		}
		switch op {
		case privsep.OpMutate:
			o, _ := netops.DecodeOp(body)
			_ = store.InsertAudit(context.Background(), storage.AuditEntry{
				Op:      string(o.Kind),
				Args:    string(body),
				PeerUID: peerUID,
				Result:  result,
			})
		case privsep.OpCaptureStart:
			// Launching tcpdump as root is privileged - record the argv.
			_ = store.InsertAudit(context.Background(), storage.AuditEntry{
				Op:      "capture.start",
				Args:    string(body),
				PeerUID: peerUID,
				Result:  result,
			})
		}
	}

	return privsep.RunHelper(handler, audit)
}

// socketReq is the body of an OpOpenSocket request.
type socketReq struct {
	Type  string `json:"type"`  // "icmp" | "afpacket"
	Iface string `json:"iface"` // for afpacket bind
}

// openPrivilegedSocket opens a capability-requiring socket and returns its fd
// for SCM_RIGHTS transfer to the engine. This is the seam capture/probing can
// adopt to run fully unprivileged; the mechanism is exercised end-to-end here
// even though the live capture pipeline does not yet consume it.
func openPrivilegedSocket(body []byte) ([]byte, int, error) {
	var req socketReq
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, -1, fmt.Errorf("decode socket req: %w", err)
	}
	switch req.Type {
	case "icmp":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
		if err != nil {
			return nil, -1, fmt.Errorf("open icmp socket: %w", err)
		}
		return nil, fd, nil
	case "afpacket":
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
		if err != nil {
			return nil, -1, fmt.Errorf("open af_packet socket: %w", err)
		}
		if req.Iface != "" {
			if ifi, err := net.InterfaceByName(req.Iface); err == nil {
				_ = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index})
			}
		}
		return nil, fd, nil
	default:
		return nil, -1, fmt.Errorf("helper: unknown socket type %q", req.Type)
	}
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

// --- Capture process management (privileged side) ---------------------------
//
// The helper owns the tcpdump children. Because the helper runs as uid 0 with
// an intact capability bounding set, a tcpdump it execs acquires CAP_NET_RAW
// via the kernel's root-exception - something the capability-stripped engine
// cannot do for its own children. The engine drives start/stop/status over the
// privsep RPC.

// Capture RPC message bodies (JSON).
type captureStartReq struct {
	Args []string `json:"args"`
}
type captureStartResp struct {
	PID int `json:"pid"`
}
type capturePIDReq struct {
	PID int `json:"pid"`
}
type captureStatusResp struct {
	State   string `json:"state"`
	ExitErr string `json:"exitErr"`
	Done    bool   `json:"done"`
}

// helperCapture tracks one running/finished tcpdump child.
type helperCapture struct {
	cmd    *exec.Cmd
	stderr *boundedBuf

	mu      sync.Mutex
	state   string // "running" / "stopped" / "failed"
	exitErr string
	done    bool
}

// captureReg is the helper's table of capture children, keyed by pid.
type captureReg struct {
	mu sync.Mutex
	m  map[int]*helperCapture
}

func newCaptureReg() *captureReg { return &captureReg{m: map[int]*helperCapture{}} }

func (r *captureReg) handleStart(body []byte) ([]byte, int, error) {
	var req captureStartReq
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, -1, fmt.Errorf("decode capture start: %w", err)
	}
	if len(req.Args) == 0 {
		return nil, -1, errors.New("capture start: empty args")
	}
	stderr := &boundedBuf{limit: 4096}
	cmd := exec.Command("tcpdump", req.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, -1, fmt.Errorf("start tcpdump: %w", err)
	}
	hc := &helperCapture{cmd: cmd, stderr: stderr, state: "running"}
	pid := cmd.Process.Pid
	r.mu.Lock()
	r.m[pid] = hc
	r.mu.Unlock()
	go r.reap(hc)

	resp, _ := json.Marshal(captureStartResp{PID: pid})
	return resp, -1, nil
}

// reap waits for the child and records its terminal state. Mirrors the
// in-process TCPDumpManager.wait logic, including surfacing tcpdump's stderr.
func (r *captureReg) reap(hc *helperCapture) {
	err := hc.cmd.Wait()
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.done = true
	switch {
	case err == nil:
		hc.state = "stopped"
	case isSignalExit(err):
		// We stop captures with SIGINT; a signalled exit is a clean stop.
		hc.state = "stopped"
	default:
		hc.state = "failed"
		hc.exitErr = err.Error()
		if msg := hc.stderr.String(); msg != "" {
			hc.exitErr = err.Error() + ": " + msg
		}
	}
}

func (r *captureReg) handleStop(body []byte) ([]byte, int, error) {
	var req capturePIDReq
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, -1, fmt.Errorf("decode capture stop: %w", err)
	}
	r.mu.Lock()
	_, ok := r.m[req.PID]
	r.mu.Unlock()
	if !ok {
		return nil, -1, nil // unknown/already-reaped pid: no-op
	}
	// SIGINT to the whole process group (Setpgid above); tcpdump flushes the
	// pcap and exits cleanly.
	_ = syscall.Kill(-req.PID, syscall.SIGINT)
	return nil, -1, nil
}

func (r *captureReg) handleStatus(body []byte) ([]byte, int, error) {
	var req capturePIDReq
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, -1, fmt.Errorf("decode capture status: %w", err)
	}
	r.mu.Lock()
	hc, ok := r.m[req.PID]
	r.mu.Unlock()
	var out captureStatusResp
	if !ok {
		// Unknown pid - treat as a finished job so the engine stops polling.
		out = captureStatusResp{State: "stopped", Done: true}
	} else {
		hc.mu.Lock()
		out = captureStatusResp{State: hc.state, ExitErr: hc.exitErr, Done: hc.done}
		hc.mu.Unlock()
	}
	resp, _ := json.Marshal(out)
	return resp, -1, nil
}

// isSignalExit reports whether err is an ExitError from a signal (vs a non-zero
// exit code), so a SIGINT-terminated capture reads as "stopped", not "failed".
func isSignalExit(err error) bool {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			return ws.Signaled()
		}
	}
	return false
}

// boundedBuf is an io.Writer retaining at most `limit` bytes (the head, where
// tcpdump prints its error). Concurrency-safe.
type boundedBuf struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (b *boundedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n := b.limit - len(b.buf); n > 0 {
		if n > len(p) {
			n = len(p)
		}
		b.buf = append(b.buf, p[:n]...)
	}
	return len(p), nil
}

func (b *boundedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.buf))
}

// --- Capture spawner (engine side) ------------------------------------------

// helperCaptureSpawner implements capture.CaptureSpawner by forwarding launches
// to the privileged helper over the privsep RPC.
type helperCaptureSpawner struct{ client *privsep.Client }

func (s helperCaptureSpawner) StartCapture(args []string) (int, error) {
	body, _ := json.Marshal(captureStartReq{Args: args})
	resp, _, err := s.client.Call(privsep.OpCaptureStart, body)
	if err != nil {
		return 0, err
	}
	var r captureStartResp
	if err := json.Unmarshal(resp, &r); err != nil {
		return 0, fmt.Errorf("decode capture start resp: %w", err)
	}
	return r.PID, nil
}

func (s helperCaptureSpawner) StopCapture(pid int) error {
	body, _ := json.Marshal(capturePIDReq{PID: pid})
	_, _, err := s.client.Call(privsep.OpCaptureStop, body)
	return err
}

func (s helperCaptureSpawner) CaptureStatus(pid int) (capture.CaptureStatus, error) {
	body, _ := json.Marshal(capturePIDReq{PID: pid})
	resp, _, err := s.client.Call(privsep.OpCaptureStatus, body)
	if err != nil {
		return capture.CaptureStatus{}, err
	}
	var r captureStatusResp
	if err := json.Unmarshal(resp, &r); err != nil {
		return capture.CaptureStatus{}, fmt.Errorf("decode capture status resp: %w", err)
	}
	return capture.CaptureStatus{State: r.State, ExitErr: r.ExitErr, Done: r.Done}, nil
}
