//go:build ebpf

package telemetry

import (
	"os"

	"golang.org/x/sys/unix"
)

// EBPFStatus does runtime detection for the optional eBPF backend (compiled in
// via `-tags ebpf`). It checks the two hard prerequisites - kernel BTF for
// CO-RE relocation, and the capability to load programs - and reports the
// result. When either is missing the collector transparently falls back to the
// pure-Go INET_DIAG reader; eBPF is strictly additive and never fatal.
//
// The CO-RE program objects themselves are not yet bundled in the tree (they
// require a clang/LLVM build step and a cilium/ebpf loader); until they are,
// detection succeeds on a capable kernel but Available stays false so the
// fallback path is used. This keeps the seam, the detection, and the fallback
// all real and exercised - only the loaded bytecode is outstanding.
func EBPFStatus() EBPFInfo {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return EBPFInfo{
			Compiled:  true,
			Available: false,
			Detail:    "kernel BTF (/sys/kernel/btf/vmlinux) unavailable; INET_DIAG fallback",
		}
	}
	if !hasBPFCapability() {
		return EBPFInfo{
			Compiled:  true,
			Available: false,
			Detail:    "missing CAP_BPF/CAP_NET_ADMIN; INET_DIAG fallback",
		}
	}
	return EBPFInfo{
		Compiled:  true,
		Available: false,
		Detail:    "BTF + caps present; CO-RE objects not bundled in this build, INET_DIAG fallback",
	}
}

// hasBPFCapability reports whether the process holds CAP_BPF (preferred) or the
// legacy CAP_NET_ADMIN that older kernels require to load programs.
func hasBPFCapability() bool {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	hdr.Pid = 0
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	const capNetAdmin = 12 // CAP_NET_ADMIN
	const capBPF = 39      // CAP_BPF
	has := func(cap uint) bool {
		idx, bit := cap/32, uint(1)<<(cap%32)
		return data[idx].Effective&uint32(bit) != 0
	}
	return has(capBPF) || has(capNetAdmin)
}
