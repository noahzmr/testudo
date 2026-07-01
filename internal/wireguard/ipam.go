package wireguard

import (
	"fmt"
	"net/netip"
)

// AllocateIP hands out the next free host address in the tunnel subnet. The
// tunnel itself is the source of truth: taken addresses are read from the live
// AllowedIPs of the device's existing peers plus the reserved server address, so
// no extra allocation state has to be persisted (matches the "tunnel is source
// of truth" rule in G1).
//
//   - subnetCIDR: the tunnel pool, e.g. "10.8.0.0/24"
//   - serverAddr: the server's own tunnel address to reserve, e.g. "10.8.0.1"
//     (may be empty to reserve nothing beyond taken peer IPs)
//   - takenAllowedIPs: every AllowedIP currently configured across peers
//
// It returns a host address as "10.8.0.2/32" ready to use as a peer AllowedIP.
// The network and broadcast addresses are skipped. Errors when the pool is
// exhausted or the inputs are malformed.
func AllocateIP(subnetCIDR, serverAddr string, takenAllowedIPs []string) (string, error) {
	prefix, err := netip.ParsePrefix(subnetCIDR)
	if err != nil {
		return "", fmt.Errorf("parse tunnel subnet %q: %w", subnetCIDR, err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("tunnel subnet must be IPv4: %q", subnetCIDR)
	}

	taken := map[netip.Addr]struct{}{}
	// Reserve the network address itself.
	taken[prefix.Addr()] = struct{}{}
	// Reserve the server address.
	if serverAddr != "" {
		if a, err := parseHost(serverAddr); err == nil {
			taken[a] = struct{}{}
		}
	}
	// Reserve every address already routed to a peer.
	for _, aip := range takenAllowedIPs {
		if a, err := parseHost(aip); err == nil {
			taken[a] = struct{}{}
		}
	}

	// The broadcast address (all-ones host) is reserved by walking to it and
	// never handing it out below.
	broadcast := lastAddr(prefix)

	for addr := prefix.Addr().Next(); prefix.Contains(addr); addr = addr.Next() {
		if addr == broadcast {
			break
		}
		if _, used := taken[addr]; used {
			continue
		}
		return addr.String() + "/32", nil
	}
	return "", fmt.Errorf("tunnel subnet %s is exhausted", subnetCIDR)
}

// parseHost accepts a bare address ("10.8.0.2") or a CIDR ("10.8.0.2/32") and
// returns the host address.
func parseHost(s string) (netip.Addr, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return a, nil
}

// lastAddr returns the highest address (broadcast) in an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	ip := p.Masked().Addr().As4()
	bits := p.Bits()
	// Set all host bits.
	for i := bits; i < 32; i++ {
		ip[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom4(ip)
}

// ServerSubnetContains reports whether addr (bare or CIDR) falls inside the
// tunnel subnet - a guard for a caller-supplied fixed IP.
func ServerSubnetContains(subnetCIDR, addr string) bool {
	prefix, err := netip.ParsePrefix(subnetCIDR)
	if err != nil {
		return false
	}
	a, err := parseHost(addr)
	if err != nil {
		return false
	}
	return prefix.Masked().Contains(a)
}

// DefaultServerAddr returns the conventional server address (first host) of a
// subnet, e.g. "10.8.0.0/24" -> "10.8.0.1". Used to seed settings defaults.
func DefaultServerAddr(subnetCIDR string) string {
	prefix, err := netip.ParsePrefix(subnetCIDR)
	if err != nil {
		return ""
	}
	a := prefix.Masked().Addr().Next()
	if !prefix.Contains(a) {
		return ""
	}
	return a.String()
}
