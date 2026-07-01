package netops

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
)

// SetTxQLen sets an interface's transmit queue length. A larger queue lets the
// kernel absorb bursts before dropping - one of the levers for WireGuard
// throughput and fewer tx drops under load.
func (w *Writer) SetTxQLen(iface string, qlen int) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpSetTxQLen, Iface: iface, TxQLen: qlen})
}

func (w *Writer) setTxQLenDirect(iface string, qlen int) error {
	if qlen < 0 {
		return fmt.Errorf("txqueuelen must be >= 0")
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", iface, err)
	}
	if err := netlink.LinkSetTxQLen(link, qlen); err != nil {
		return fmt.Errorf("set txqueuelen on %s: %w", iface, err)
	}
	log.Printf("netops audit: set txqueuelen %s = %d", iface, qlen)
	return nil
}

// sysctlAllow is the performance-tuning allowlist for OpSetSysctl. Only these
// keys can be written, so the op can never touch an arbitrary /proc/sys value.
// These are the socket-buffer / backlog knobs that matter for UDP-based
// WireGuard throughput and drop avoidance.
var sysctlAllow = map[string]struct{}{
	"net.core.rmem_max":           {},
	"net.core.wmem_max":           {},
	"net.core.rmem_default":       {},
	"net.core.wmem_default":       {},
	"net.core.optmem_max":         {},
	"net.core.netdev_max_backlog": {},
	"net.ipv4.udp_rmem_min":       {},
	"net.ipv4.udp_wmem_min":       {},
}

// SetSysctl writes a single allowlisted performance sysctl.
func (w *Writer) SetSysctl(key, val string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpSetSysctl, SysctlKey: key, SysctlVal: val})
}

func (w *Writer) setSysctlDirect(key, val string) error {
	if _, ok := sysctlAllow[key]; !ok {
		return fmt.Errorf("sysctl %q not in the performance allowlist", key)
	}
	if strings.TrimSpace(val) == "" {
		return fmt.Errorf("empty sysctl value for %s", key)
	}
	// Map net.core.rmem_max -> /proc/sys/net/core/rmem_max.
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	// Defence in depth: the resolved path must still live under /proc/sys/net.
	if !strings.HasPrefix(filepath.Clean(path), "/proc/sys/net/") {
		return fmt.Errorf("refusing sysctl path %q", path)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(val)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write sysctl %s: %w", key, err)
	}
	log.Printf("netops audit: sysctl %s = %s", key, val)
	return nil
}
