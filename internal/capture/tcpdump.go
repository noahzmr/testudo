package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// FilterSpec is the structured form a BPF expression. Every field is
// optional - empty fields are skipped. Build() renders the canonical
// "<clause> and <clause> ..." string accepted by tcpdump and libpcap.
type FilterSpec struct {
	Proto     string // "tcp" / "udp" / "icmp" / "" (any)
	SrcHost   string // hostname or IP
	DstHost   string
	SrcPort   string // numeric; kept as string so the form can validate
	DstPort   string
	RawAppend string // extra raw BPF appended in parentheses
}

// Build assembles the BPF expression. Returns "" when no clauses are set
// (which tcpdump interprets as "capture everything").
func (f FilterSpec) Build() string {
	var parts []string
	if f.Proto != "" {
		parts = append(parts, f.Proto)
	}
	if f.SrcHost != "" {
		parts = append(parts, "src host "+f.SrcHost)
	}
	if f.DstHost != "" {
		parts = append(parts, "dst host "+f.DstHost)
	}
	if f.SrcPort != "" {
		parts = append(parts, "src port "+f.SrcPort)
	}
	if f.DstPort != "" {
		parts = append(parts, "dst port "+f.DstPort)
	}
	if f.RawAppend != "" {
		parts = append(parts, "("+f.RawAppend+")")
	}
	return strings.Join(parts, " and ")
}

// TCPDumpJob is the public snapshot of one capture - running or completed.
// Safe to copy.
type TCPDumpJob struct {
	ID         string
	Iface      string
	Filter     string
	OutputPath string
	Name       string
	State      string // "running" / "stopped" / "failed"
	ExitErr    string
	StartedAt  time.Time
	EndedAt    time.Time
	Bytes      int64
}

// CaptureStatus is the helper's view of one out-of-process tcpdump child.
type CaptureStatus struct {
	State   string // "running" / "stopped" / "failed"
	ExitErr string // populated when State == "failed"
	Done    bool   // the process has exited and been reaped
}

// CaptureSpawner runs tcpdump out-of-process in a context that still holds
// CAP_NET_RAW - in practice the privileged privsep helper. When a manager has
// one, it delegates the whole process lifecycle to it instead of forking
// tcpdump itself (which, post-DropPrivileges, would lack the capability). A nil
// spawner keeps the legacy single-process path (--privsep=false).
type CaptureSpawner interface {
	StartCapture(args []string) (pid int, err error)
	StopCapture(pid int) error
	CaptureStatus(pid int) (CaptureStatus, error)
}

// runningJob carries the parts of a job that mustn't be copied.
type runningJob struct {
	pub    TCPDumpJob
	cancel context.CancelFunc
	cmd    *exec.Cmd  // nil for helper-spawned jobs
	pid    int        // helper-spawned process pid (0 in-process)
	stderr *capWriter // captures tcpdump's diagnostics for failure reporting
}

// capWriter is an io.Writer that retains at most `limit` bytes. tcpdump prints
// its error on the first line, so keeping the head is what we want.
type capWriter struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if n := w.limit - len(w.buf); n > 0 {
		if n > len(p) {
			n = len(p)
		}
		w.buf = append(w.buf, p[:n]...)
	}
	return len(p), nil
}

func (w *capWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.TrimSpace(string(w.buf))
}

// TCPDumpManager orchestrates tcpdump subprocesses. Safe for concurrent use.
// Each TCPDump session is a child process - Testudo doesn't link libpcap, it
// drives the standard tcpdump binary. That keeps us portable, capability-
// agnostic, and lets operators reuse the resulting .pcap with any tool.
type TCPDumpManager struct {
	captureDir string
	sessionID  string

	spawner CaptureSpawner // when set, tcpdump runs in the privileged helper

	mu      sync.Mutex
	jobs    map[string]*runningJob // active processes
	history []TCPDumpJob           // completed snapshots
	next    int
}

func NewTCPDumpManager(captureDir, sessionID string) *TCPDumpManager {
	return &TCPDumpManager{
		captureDir: captureDir,
		sessionID:  sessionID,
		jobs:       map[string]*runningJob{},
	}
}

// SetSpawner routes tcpdump launches through s (the privileged helper) instead
// of forking in-process. Call once at wiring time, before any Start.
func (m *TCPDumpManager) SetSpawner(s CaptureSpawner) { m.spawner = s }

// TCPDumpAvailable returns true iff the tcpdump binary is on PATH.
func TCPDumpAvailable() bool {
	_, err := exec.LookPath("tcpdump")
	return err == nil
}

// Start launches a tcpdump process. Returns the job snapshot once the
// process is running, or the error that prevented it from starting.
func (m *TCPDumpManager) Start(iface, name, filter string, maxSizeMB int, duration time.Duration) (TCPDumpJob, error) {
	if !TCPDumpAvailable() {
		return TCPDumpJob{}, errors.New(
			"tcpdump not on PATH - install it (apt install tcpdump) or run testudo as a user that can see it")
	}
	if strings.TrimSpace(iface) == "" {
		return TCPDumpJob{}, errors.New("interface required")
	}
	dir := filepath.Join(m.captureDir, m.sessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return TCPDumpJob{}, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	m.mu.Lock()
	m.next++
	id := fmt.Sprintf("td-%03d", m.next)
	m.mu.Unlock()

	safeName := strings.NewReplacer(" ", "_", "/", "_").Replace(strings.TrimSpace(name))
	if safeName == "" {
		safeName = "capture"
	}
	outFile := filepath.Join(dir, fmt.Sprintf(
		"tcpdump-%s-%s-%s.pcap",
		id, safeName, time.Now().UTC().Format("20060102-150405"),
	))

	args := []string{"-i", iface, "-w", outFile, "-s", "0", "-n", "-U"}
	// Distro tcpdump builds (Debian/Ubuntu: --with-user=tcpdump) drop privileges
	// to an unprivileged user AFTER opening the device but BEFORE opening the
	// -w savefile. That user can't write into root-owned capture dirs, which
	// surfaces as "Permission denied" on the .pcap. -Z root keeps root for the
	// file write. Only meaningful (and only valid) when we're actually root.
	if os.Geteuid() == 0 {
		args = append(args, "-Z", "root")
	}
	if maxSizeMB > 0 {
		args = append(args, "-C", strconv.Itoa(maxSizeMB))
	}
	if f := strings.TrimSpace(filter); f != "" {
		// tcpdump treats trailing tokens as the BPF expression.
		args = append(args, f)
	}

	// Privileged-helper path: the engine has dropped CAP_NET_RAW, so a tcpdump
	// it forks itself would fail with "socket: Operation not permitted". Hand
	// the launch to the helper, which still holds the capability.
	if m.spawner != nil {
		pid, err := m.spawner.StartCapture(args)
		if err != nil {
			return TCPDumpJob{}, fmt.Errorf("start tcpdump (helper): %w", err)
		}
		job := &runningJob{
			pub: TCPDumpJob{
				ID: id, Iface: iface, Filter: filter, OutputPath: outFile,
				Name: name, StartedAt: time.Now(), State: "running",
			},
			pid: pid,
			// Stop/Remove call cancel(); route it through the helper RPC.
			cancel: func() { _ = m.spawner.StopCapture(pid) },
		}
		m.mu.Lock()
		m.jobs[id] = job
		m.mu.Unlock()
		if duration > 0 {
			// The helper owns the process, so enforce duration by asking it to
			// stop after the window (mirrors the in-process context timeout).
			go func() {
				t := time.NewTimer(duration)
				defer t.Stop()
				<-t.C
				_ = m.spawner.StopCapture(pid)
			}()
		}
		go m.pollHelper(id, job)
		return job.pub, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	if duration > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), duration)
	}

	stderr := &capWriter{limit: 4096}
	cmd := exec.CommandContext(ctx, "tcpdump", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return TCPDumpJob{}, fmt.Errorf("start tcpdump: %w", err)
	}

	job := &runningJob{
		pub: TCPDumpJob{
			ID: id, Iface: iface, Filter: filter, OutputPath: outFile,
			Name: name, StartedAt: time.Now(), State: "running",
		},
		cancel: cancel,
		cmd:    cmd,
		stderr: stderr,
	}
	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()
	go m.wait(id, job)
	return job.pub, nil
}

// pollHelper reaps a helper-spawned job: it polls the helper for terminal
// status and, once the process has exited, moves the job into history with the
// final state. Mirrors wait() for the in-process path.
func (m *TCPDumpManager) pollHelper(id string, job *runningJob) {
	for {
		time.Sleep(500 * time.Millisecond)
		st, err := m.spawner.CaptureStatus(job.pid)
		if err != nil {
			m.finishHelper(id, job, "failed", "helper status: "+err.Error())
			return
		}
		if st.Done {
			state := st.State
			if state == "" {
				state = "stopped"
			}
			m.finishHelper(id, job, state, st.ExitErr)
			return
		}
	}
}

func (m *TCPDumpManager) finishHelper(id string, job *runningJob, state, exitErr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job.pub.EndedAt = time.Now()
	job.pub.State = state
	job.pub.ExitErr = exitErr
	if st, err := os.Stat(job.pub.OutputPath); err == nil {
		job.pub.Bytes = st.Size()
	}
	m.history = append(m.history, job.pub)
	delete(m.jobs, id)
}

// wait reaps the child process and moves the job from `jobs` => `history`
// with the final state.
func (m *TCPDumpManager) wait(id string, job *runningJob) {
	err := job.cmd.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()

	job.pub.EndedAt = time.Now()
	switch {
	case err == nil:
		job.pub.State = "stopped"
	case ctxCancelled(err):
		job.pub.State = "stopped"
	default:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == -1 {
			job.pub.State = "stopped"
		} else {
			job.pub.State = "failed"
			job.pub.ExitErr = err.Error()
			// tcpdump's own diagnostic (permission denied, no such device,
			// bad filter, ...) is far more useful than "exit status 1".
			if msg := job.stderr.String(); msg != "" {
				job.pub.ExitErr = fmt.Sprintf("%s: %s", err.Error(), msg)
			}
		}
	}
	if st, statErr := os.Stat(job.pub.OutputPath); statErr == nil {
		job.pub.Bytes = st.Size()
	}
	m.history = append(m.history, job.pub)
	delete(m.jobs, id)
}

func ctxCancelled(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "context canceled") ||
		strings.Contains(err.Error(), "killed") ||
		strings.Contains(err.Error(), "signal: terminated")
}

// Stop signals the named job. Idempotent; returns nil for already-stopped
// jobs.
func (m *TCPDumpManager) Stop(id string) error {
	m.mu.Lock()
	job, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	job.cancel()
	return nil
}

// List returns a chronological snapshot: history first (oldest=>newest),
// then currently-running jobs. Each entry is a value copy - safe to render
// without locking.
func (m *TCPDumpManager) List() []TCPDumpJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TCPDumpJob, 0, len(m.history)+len(m.jobs))
	out = append(out, m.history...)
	for _, j := range m.jobs {
		snap := j.pub
		if st, err := os.Stat(snap.OutputPath); err == nil {
			snap.Bytes = st.Size()
		}
		out = append(out, snap)
	}
	return out
}

// Remove deletes a stopped job's pcap file and removes the history entry.
// Running jobs are stopped first.
func (m *TCPDumpManager) Remove(id string) error {
	m.mu.Lock()
	if job, ok := m.jobs[id]; ok {
		cancel := job.cancel
		m.mu.Unlock()
		cancel()
		// Brief wait for the reaper goroutine. 2s is enough on any sane
		// system; if tcpdump hangs longer than that the operator can
		// retry the Remove.
		for i := 0; i < 20; i++ {
			m.mu.Lock()
			_, still := m.jobs[id]
			m.mu.Unlock()
			if !still {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		m.mu.Lock()
	}
	defer m.mu.Unlock()
	for i, h := range m.history {
		if h.ID != id {
			continue
		}
		if h.OutputPath != "" {
			_ = os.Remove(h.OutputPath)
		}
		m.history = append(m.history[:i], m.history[i+1:]...)
		return nil
	}
	return fmt.Errorf("no such job: %s", id)
}
