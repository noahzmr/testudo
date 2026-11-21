package netops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// PortForward describes a destination-NAT rule managed by Testudo: traffic
// arriving on WANPort (optionally only via InIface) is rewritten to
// LANIP:LANPort. IPv4 only.
type PortForward struct {
	Proto   string `json:"proto"`              // "tcp" or "udp"
	WANPort uint16 `json:"wan_port"`           // port reachable from the outside
	LANIP   string `json:"lan_ip"`             // internal target IP
	LANPort uint16 `json:"lan_port"`           // internal target port (defaults to WANPort if 0)
	InIface string `json:"in_iface,omitempty"` // restrict to this ingress interface; "" = any
	Comment string `json:"comment,omitempty"`
	Owner   string `json:"owner,omitempty"`
}

// Normalize returns the canonical form (lower-cased proto, defaulted LAN port
// and owner). ID is computed over it.
func (pf PortForward) Normalize() PortForward {
	n := pf
	n.Proto = strings.ToLower(strings.TrimSpace(n.Proto))
	n.LANIP = strings.TrimSpace(n.LANIP)
	if ip := net.ParseIP(n.LANIP); ip != nil {
		n.LANIP = ip.String()
	}
	if n.LANPort == 0 {
		n.LANPort = n.WANPort
	}
	n.InIface = strings.TrimSpace(n.InIface)
	n.Comment = strings.TrimSpace(n.Comment)
	n.Owner = strings.TrimSpace(n.Owner)
	if n.Owner == "" {
		n.Owner = OwnerUser
	}
	return n
}

// Validate guards the forward before anything touches netlink.
func (pf PortForward) Validate() error {
	n := pf.Normalize()
	if n.Proto != "tcp" && n.Proto != "udp" {
		return fmt.Errorf("proto must be tcp or udp, got %q", pf.Proto)
	}
	if n.WANPort == 0 {
		return fmt.Errorf("wan_port is required")
	}
	lan := net.ParseIP(n.LANIP)
	if lan == nil || lan.To4() == nil {
		return fmt.Errorf("lan ip must be IPv4, got %q", pf.LANIP)
	}
	if len(n.InIface) > 15 {
		return fmt.Errorf("interface names are at most 15 characters")
	}
	if len(n.Comment) > 200 {
		return fmt.Errorf("comment is at most 200 characters")
	}
	return nil
}

// ID is a stable content hash of the normalized forward (12 hex chars).
func (pf PortForward) ID() string {
	n := pf.Normalize()
	h := sha256.Sum256([]byte(strings.Join([]string{
		tagForward, n.Proto, strconv.Itoa(int(n.WANPort)), n.LANIP,
		strconv.Itoa(int(n.LANPort)), n.InIface, n.Owner,
	}, "\x00")))
	return hex.EncodeToString(h[:6])
}

// String renders the forward nft-style.
func (pf PortForward) String() string {
	n := pf.Normalize()
	var b strings.Builder
	b.WriteString("prerouting")
	if n.InIface != "" {
		b.WriteString(" iifname " + n.InIface)
	}
	fmt.Fprintf(&b, " %s dport %d dnat to %s:%d", n.Proto, n.WANPort, n.LANIP, n.LANPort)
	return b.String()
}

// Masquerade is a source-NAT rule: packets from SrcCIDR leaving via OutIface
// are rewritten to the interface's address. Used by the WireGuard full-tunnel
// preset and by operators sharing a WAN uplink. IPv4 only.
type Masquerade struct {
	OutIface string `json:"out_iface"`
	SrcCIDR  string `json:"src"`
	Comment  string `json:"comment,omitempty"`
	Owner    string `json:"owner,omitempty"`
}

// Normalize returns the canonical form (network-address CIDR, defaulted owner).
func (m Masquerade) Normalize() Masquerade {
	n := m
	n.OutIface = strings.TrimSpace(n.OutIface)
	n.SrcCIDR = canonicalCIDR(n.SrcCIDR)
	n.Comment = strings.TrimSpace(n.Comment)
	n.Owner = strings.TrimSpace(n.Owner)
	if n.Owner == "" {
		n.Owner = OwnerUser
	}
	return n
}

// Validate guards the masquerade before anything touches netlink.
func (m Masquerade) Validate() error {
	n := m.Normalize()
	if n.OutIface == "" {
		return fmt.Errorf("masquerade out interface required")
	}
	if len(n.OutIface) > 15 {
		return fmt.Errorf("interface names are at most 15 characters")
	}
	ip, _, err := parseCIDROrIP(n.SrcCIDR)
	if err != nil {
		return fmt.Errorf("masquerade src: %w", err)
	}
	if len(ip) != net.IPv4len {
		return fmt.Errorf("masquerade src must be IPv4")
	}
	if len(n.Comment) > 200 {
		return fmt.Errorf("comment is at most 200 characters")
	}
	return nil
}

// ID is a stable content hash of the normalized masquerade (12 hex chars).
func (m Masquerade) ID() string {
	n := m.Normalize()
	h := sha256.Sum256([]byte(strings.Join([]string{tagMasquerade, n.SrcCIDR, n.OutIface, n.Owner}, "\x00")))
	return hex.EncodeToString(h[:6])
}

// String renders the masquerade nft-style.
func (m Masquerade) String() string {
	n := m.Normalize()
	return fmt.Sprintf("postrouting ip saddr %s oifname %s masquerade", n.SrcCIDR, n.OutIface)
}

// NATSpec is the complete desired content of the testudo_nat table.
type NATSpec struct {
	Forwards    []PortForward `json:"forwards"`
	Masquerades []Masquerade  `json:"masquerades"`
}
