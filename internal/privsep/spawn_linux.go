//go:build linux

package privsep

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// HelperArg is the argv[0] subcommand that re-execs this binary as the
// privileged helper. cmd/testudo dispatches on it before any normal startup.
const HelperArg = "__helper"

// helperFD is the fixed descriptor the SEQPACKET socket is passed to the child
// on. fd 0/1/2 are stdio; ExtraFiles starts at fd 3.
const helperFD = 3

// Spawn forks a privileged helper by re-executing this binary with the
// HelperArg subcommand, connected over an anonymous SOCK_SEQPACKET socketpair.
// The child inherits the binary's file capabilities (granted via setcap); the
// returned Client talks to it. The caller drops its own capabilities after a
// successful Spawn (see DropPrivileges) so only the helper retains them.
//
// The helper's stderr is wired to the parent's so its diagnostics surface.
func Spawn(ctx context.Context) (*Client, *exec.Cmd, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("privsep: socketpair: %w", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "privsep-parent")
	childFile := os.NewFile(uintptr(fds[1]), "privsep-child")
	defer childFile.Close()

	exe, err := os.Executable()
	if err != nil {
		parentFile.Close()
		return nil, nil, fmt.Errorf("privsep: executable: %w", err)
	}

	cmd := exec.CommandContext(ctx, exe, HelperArg)
	cmd.Stdout = os.Stderr // keep stdout clean for the TUI
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{childFile} // becomes helperFD in the child
	if err := cmd.Start(); err != nil {
		parentFile.Close()
		return nil, nil, fmt.Errorf("privsep: start helper: %w", err)
	}

	conn, err := net.FileConn(parentFile)
	parentFile.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, nil, fmt.Errorf("privsep: fileconn: %w", err)
	}
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = cmd.Process.Kill()
		return nil, nil, fmt.Errorf("privsep: unexpected conn type %T", conn)
	}
	return NewClient(uconn), cmd, nil
}

// RunHelper is the helper-process entry point. It claims the inherited socket,
// applies the seccomp allowlist (NO_NEW_PRIVS lets an unprivileged process
// install it), and serves requests with the supplied handler until the parent
// disconnects. It restricts itself to the parent's uid via SO_PEERCRED.
func RunHelper(h Handler, audit AuditFunc) error {
	f := os.NewFile(helperFD, "privsep-socket")
	if f == nil {
		return fmt.Errorf("privsep: helper socket fd %d not inherited", helperFD)
	}
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("privsep: helper fileconn: %w", err)
	}
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("privsep: helper unexpected conn type %T", conn)
	}

	// Narrow the syscall surface before handling any request. A failure here is
	// non-fatal (older kernels) but logged by the caller via the returned error
	// of InstallSeccomp when it chooses to surface it.
	_ = InstallSeccomp()

	srv := NewServer(uconn, h)
	if audit != nil {
		srv.SetAudit(audit)
	}
	// Only serve the user that launched us.
	srv.RestrictPeer(uint32(os.Getuid()))
	return srv.Serve(context.Background())
}
