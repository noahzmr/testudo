package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"

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
func setupNetops(ctx context.Context, cfg config.Config, allowWrites, usePrivsep bool) (*netops.Writer, helperReport) {
	if !usePrivsep {
		return &netops.Writer{AllowWrites: allowWrites}, helperReport{enabled: false}
	}
	// Let the privileged helper find the audit DB.
	_ = os.Setenv(envAuditDB, cfg.SQLitePath)

	client, cmd, err := privsep.Spawn(ctx)
	if err != nil {
		return &netops.Writer{AllowWrites: allowWrites}, helperReport{enabled: true, err: err.Error()}
	}
	if err := client.Ping(); err != nil {
		_ = client.Close()
		return &netops.Writer{AllowWrites: allowWrites}, helperReport{enabled: true, err: "handshake: " + err.Error()}
	}

	report := helperReport{enabled: true, ok: true, pid: cmd.Process.Pid}
	// Capabilities now live with the helper; drop ours so the engine, web
	// server, and TUI run unprivileged. A failure here is non-fatal - we still
	// route mutations through the helper.
	if derr := privsep.DropPrivileges(); derr != nil {
		report.dropErr = derr.Error()
	}
	return netops.NewHelperWriter(allowWrites, client), report
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

	handler := func(op byte, body []byte) ([]byte, int, error) {
		switch op {
		case privsep.OpMutate:
			o, err := netops.DecodeOp(body)
			if err != nil {
				return nil, -1, fmt.Errorf("decode op: %w", err)
			}
			return nil, -1, nw.ApplyOp(o)
		case privsep.OpOpenSocket:
			return openPrivilegedSocket(body)
		default:
			return nil, -1, fmt.Errorf("helper: unknown op %#x", op)
		}
	}

	audit := func(op byte, body []byte, peerUID uint32, err error) {
		if store == nil || op != privsep.OpMutate {
			return
		}
		o, _ := netops.DecodeOp(body)
		result := "ok"
		if err != nil {
			result = err.Error()
		}
		_ = store.InsertAudit(context.Background(), storage.AuditEntry{
			Op:      string(o.Kind),
			Args:    string(body),
			PeerUID: peerUID,
			Result:  result,
		})
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
