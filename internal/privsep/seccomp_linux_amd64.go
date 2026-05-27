//go:build linux && amd64

package privsep

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// blockedSyscalls is the seccomp denylist applied to the helper. The helper
// makes a small, well-understood set of calls (socket/netlink I/O, the netlink
// mutations, sqlite audit writes, and the Go runtime's own syscalls), so rather
// than risk killing the Go runtime with an over-tight allowlist, we deny the
// syscalls a compromised helper would reach for - process execution, tracing,
// module loading, namespace and mount manipulation, raw memory injection - and
// allow everything else. Denied calls fail with EPERM rather than killing the
// process, so a bug degrades the helper instead of crashing the engine's view
// of it.
var blockedSyscalls = []int{
	unix.SYS_EXECVE,
	unix.SYS_EXECVEAT,
	unix.SYS_PTRACE,
	unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_MOUNT,
	unix.SYS_UMOUNT2,
	unix.SYS_PIVOT_ROOT,
	unix.SYS_CHROOT,
	unix.SYS_SETNS,
	unix.SYS_UNSHARE,
	unix.SYS_INIT_MODULE,
	unix.SYS_FINIT_MODULE,
	unix.SYS_DELETE_MODULE,
	unix.SYS_KEXEC_LOAD,
	unix.SYS_KEXEC_FILE_LOAD,
}

// seccomp_data field offsets (struct seccomp_data in <linux/seccomp.h>).
const (
	offsetNR   = 0 // int   nr
	offsetArch = 4 // __u32 arch
)

// InstallSeccomp sets NO_NEW_PRIVS (so an unprivileged-style install is allowed
// even though the helper holds only CAP_NET_* and not CAP_SYS_ADMIN) and then
// applies the denylist BPF filter. Returns an error if the kernel rejects the
// filter; the caller decides whether that is fatal.
func InstallSeccomp() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("privsep: NO_NEW_PRIVS: %w", err)
	}

	retErrno := uint32(unix.SECCOMP_RET_ERRNO) | (uint32(unix.EPERM) & 0xffff)

	// Program layout:
	//   load arch; if != x86_64 -> KILL (block ABI-confusion bypass)
	//   load nr;   for each blocked nr -> jump to RET ERRNO
	//   RET ALLOW
	//   RET ERRNO
	filter := []unix.SockFilter{
		// [0] A = arch
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offsetArch),
		// [1] if A == AUDIT_ARCH_X86_64 skip the kill (jt=1), else fall through
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(unix.AUDIT_ARCH_X86_64), 1, 0),
		// [2] arch mismatch -> kill the whole process
		bpfStmt(unix.BPF_RET|unix.BPF_K, uint32(unix.SECCOMP_RET_KILL_PROCESS)),
		// [3] A = nr
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offsetNR),
	}
	// The RET ERRNO instruction sits at the very end. base is the index of the
	// first syscall check; the RET ALLOW / RET ERRNO statements follow the
	// checks. For a JEQ at absolute index `cur`, the jump-true distance to the
	// RET ERRNO is (errnoIdx - cur - 1).
	base := len(filter)
	allowIdx := base + len(blockedSyscalls) // index of RET ALLOW
	errnoIdx := allowIdx + 1                // index of RET ERRNO
	for i, nr := range blockedSyscalls {
		cur := base + i
		jt := uint8(errnoIdx - cur - 1)
		filter = append(filter, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(nr), jt, 0))
	}
	filter = append(filter,
		bpfStmt(unix.BPF_RET|unix.BPF_K, uint32(unix.SECCOMP_RET_ALLOW)), // allowIdx
		bpfStmt(unix.BPF_RET|unix.BPF_K, retErrno),                       // errnoIdx
	)

	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	if err := unix.Prctl(unix.PR_SET_SECCOMP,
		uintptr(unix.SECCOMP_MODE_FILTER),
		uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
		return fmt.Errorf("privsep: PR_SET_SECCOMP: %w", err)
	}
	return nil
}

func bpfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}
