//go:build !ebpf

package telemetry

// EBPFStatus reports that this is the default, cgo-free build with no eBPF
// support compiled in. Per-flow TCP stats come from the pure-Go INET_DIAG
// reader (Stage A). Rebuild with `-tags ebpf` to compile the optional eBPF
// path (Stage B), which then does its own runtime kernel/BTF detection.
func EBPFStatus() EBPFInfo {
	return EBPFInfo{
		Compiled:  false,
		Available: false,
		Detail:    "eBPF not compiled in; using INET_DIAG (build with -tags ebpf to enable)",
	}
}
