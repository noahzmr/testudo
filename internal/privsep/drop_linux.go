//go:build linux

package privsep

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// maxCapValue is an upper bound for the capability index when clearing the
// bounding set. CAP_LAST_CAP grows over kernel releases; iterating a bit past
// the current known last cap is harmless (PR_CAPBSET_DROP on an unknown cap
// returns EINVAL, which we ignore).
const maxCapValue = 64

// DropPrivileges makes the current process unprivileged and unable to regain
// privilege:
//
//   - PR_SET_NO_NEW_PRIVS prevents any future execve from gaining privilege
//     (and is the precondition for installing seccomp unprivileged).
//   - The capability bounding set is cleared so even a setuid/file-cap binary
//     execed later can't acquire caps (best-effort: needs CAP_SETPCAP).
//   - All capabilities are dropped from the effective, permitted, and
//     inheritable sets via capset.
//
// It is safe to call when the process already holds no capabilities - the
// result is simply a hardened, no-caps process. Call this in the engine after
// Spawn has handed the caps to the helper.
func DropPrivileges() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("privsep: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	// Clear the bounding set. Ignore EPERM/EINVAL so a process that lacks
	// CAP_SETPCAP (the common unprivileged case) still proceeds - NO_NEW_PRIVS
	// already blocks privilege escalation via exec.
	for c := 0; c <= maxCapValue; c++ {
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
	}
	// Drop every capability set to empty.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData // 64-bit cap set spans two 32-bit words
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("privsep: capset(empty): %w", err)
	}
	return nil
}

// NoNewPrivs reports whether the calling thread has the no-new-privs bit set,
// read from /proc/self/status. Used by the integration test that verifies the
// engine actually dropped privilege.
func NoNewPrivs() (bool, error) {
	v, err := procStatusField("NoNewPrivs")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(v) == "1", nil
}

// EffectiveCaps returns the CapEff bitmask from /proc/self/status. Zero means
// the process holds no effective capabilities.
func EffectiveCaps() (uint64, error) {
	v, err := procStatusField("CapEff")
	if err != nil {
		return 0, err
	}
	var caps uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%x", &caps); err != nil {
		return 0, fmt.Errorf("privsep: parse CapEff %q: %w", v, err)
	}
	return caps, nil
}

func procStatusField(name string) (string, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	prefix := name + ":"
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix)), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("privsep: field %q not found in /proc/self/status", name)
}
