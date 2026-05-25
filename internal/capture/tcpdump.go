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

// runningJob carries the parts of a job that mustn't be copied.
type runningJob struct {
	pub    TCPDumpJob
	cancel context.CancelFunc
	cmd    *exec.Cmd
}

// TCPDumpManager orchestrates tcpdump subprocesses. Safe for concurrent use.
// Each TCPDump session is a child process - Testudo doesn't link libpcap, it
// drives the standard tcpdump binary. That keeps us portable, capability-
// agnostic, and lets operators reuse the resulting .pcap with any tool.
type TCPDumpManager struct {
	captureDir string
	sessionID  string

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
	if maxSizeMB > 0 {
		args = append(args, "-C", strconv.Itoa(maxSizeMB))
	}
	if f := strings.TrimSpace(filter); f != "" {
		// tcpdump treats trailing tokens as the BPF expression.
		args = append(args, f)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if duration > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), duration)
	}

	cmd := exec.CommandContext(ctx, "tcpdump", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
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
	}
	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()
	go m.wait(id, job)
	return job.pub, nil
}

// wait reaps the child process and moves the job from `jobs` → `history`
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

// List returns a chronological snapshot: history first (oldest→newest),
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
