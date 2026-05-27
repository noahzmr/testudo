//go:build linux && !amd64

package privsep

import "golang.org/x/sys/unix"

// InstallSeccomp on non-amd64 Linux sets NO_NEW_PRIVS but skips the BPF filter:
// the denylist's syscall numbers are arch-specific and only encoded for amd64.
// NO_NEW_PRIVS still meaningfully prevents privilege escalation via exec.
func InstallSeccomp() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
