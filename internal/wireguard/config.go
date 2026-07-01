package wireguard

import (
	"fmt"
	"strings"
)

// FirewallPreset is a fixed-degrees-of-freedom routing policy for a peer. Presets
// (not free-form rules) keep the footguns away - the firewall is where mistakes
// cost the most.
type FirewallPreset string

const (
	// PresetFullTunnel: peer reaches everything; the server masquerades the
	// peer's traffic out the WAN interface. (AllowedIPs 0.0.0.0/0 client-side.)
	PresetFullTunnel FirewallPreset = "full"
	// PresetSplit: peer reaches only the specified LAN subnets (plus the tunnel);
	// everything else it tries to forward is dropped.
	PresetSplit FirewallPreset = "split"
	// PresetIsolated: peer reaches only the server itself; no LAN, no internet,
	// no peer-to-peer.
	PresetIsolated FirewallPreset = "isolated"
)

// Valid reports whether p is a known preset.
func (p FirewallPreset) Valid() bool {
	switch p {
	case PresetFullTunnel, PresetSplit, PresetIsolated:
		return true
	}
	return false
}

// clientAllowedIPs computes the AllowedIPs line for the *client* config given
// the preset. Full tunnel routes everything; split routes the LAN subnets plus
// the tunnel pool; isolated routes only the server's tunnel address.
func clientAllowedIPs(preset FirewallPreset, tunnelSubnet, serverAddr string, lanSubnets []string) string {
	switch preset {
	case PresetFullTunnel:
		return "0.0.0.0/0, ::/0"
	case PresetSplit:
		parts := append([]string(nil), lanSubnets...)
		if tunnelSubnet != "" {
			parts = append(parts, tunnelSubnet)
		}
		if len(parts) == 0 {
			return tunnelSubnet
		}
		return strings.Join(parts, ", ")
	case PresetIsolated:
		if serverAddr != "" {
			return hostCIDR(serverAddr)
		}
		return tunnelSubnet
	}
	return tunnelSubnet
}

// RenderClientConfig builds a complete WireGuard client config. It contains the
// client's PRIVATE key, so it is produced exactly once (server-side keygen mode)
// and the caller must drop it after handing it to the user - never log or
// persist it (secrets rule). QR encoding happens client-side in the browser.
func RenderClientConfig(req ProvisionRequest, clientPrivateKey, assignedIP string) string {
	keepalive := req.Keepalive
	if keepalive <= 0 {
		keepalive = 25 // required to keep NAT holes open for mobile clients
	}
	var b strings.Builder
	if req.Name != "" {
		fmt.Fprintf(&b, "# %s\n", req.Name)
	}
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", clientPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", ensureCIDR(assignedIP))
	if req.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", req.DNS)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", req.ServerPublicKey)
	if req.Endpoint != "" {
		fmt.Fprintf(&b, "Endpoint = %s\n", req.Endpoint)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n",
		clientAllowedIPs(req.Preset, req.TunnelSubnet, req.ServerAddr, req.LANSubnets))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)
	return b.String()
}

// InterfaceConfig describes a WireGuard interface for netplan rendering. On
// Ubuntu/Debian the wg interface can be declared natively in netplan
// (mode: wireguard). PrivateKey is write-only: it is embedded in the rendered
// file (which Testudo writes 0600) but never persisted to settings/DB/logs.
type InterfaceConfig struct {
	Name       string        // "wg0"
	Address    string        // CIDR, e.g. "10.8.0.1/24"
	ListenPort int           // e.g. 51820
	PrivateKey string        // write-only; omitted from the render when empty
	Peers      []NetplanPeer // current peers (public keys only)
}

// NetplanPeer is one peer entry in a netplan wireguard tunnel (public only).
type NetplanPeer struct {
	PublicKey  string
	AllowedIPs []string
	Endpoint   string
	Keepalive  int
}

// RenderNetplan produces a netplan YAML document declaring the wg interface as a
// wireguard tunnel. It is hand-rendered (no YAML dependency) with two-space
// indentation. The private key is included only when set; peers carry public
// keys only. The caller writes this via the write-gated netplan file op.
func RenderNetplan(cfg InterfaceConfig) (string, error) {
	if cfg.Name == "" {
		return "", fmt.Errorf("interface name required")
	}
	if cfg.Address == "" {
		return "", fmt.Errorf("interface address (CIDR) required")
	}
	var b strings.Builder
	b.WriteString("# Managed by Testudo - WireGuard interface config.\n")
	b.WriteString("network:\n")
	b.WriteString("  version: 2\n")
	b.WriteString("  tunnels:\n")
	fmt.Fprintf(&b, "    %s:\n", cfg.Name)
	b.WriteString("      mode: wireguard\n")
	fmt.Fprintf(&b, "      addresses: [%s]\n", cfg.Address)
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&b, "      port: %d\n", cfg.ListenPort)
	}
	if strings.TrimSpace(cfg.PrivateKey) != "" {
		fmt.Fprintf(&b, "      key: %s\n", cfg.PrivateKey)
	}
	if len(cfg.Peers) > 0 {
		b.WriteString("      peers:\n")
		for _, p := range cfg.Peers {
			b.WriteString("        - keys:\n")
			fmt.Fprintf(&b, "            public: %s\n", p.PublicKey)
			if len(p.AllowedIPs) > 0 {
				fmt.Fprintf(&b, "          allowed-ips: [%s]\n", strings.Join(p.AllowedIPs, ", "))
			}
			if strings.TrimSpace(p.Endpoint) != "" {
				fmt.Fprintf(&b, "          endpoint: %s\n", p.Endpoint)
			}
			if p.Keepalive > 0 {
				fmt.Fprintf(&b, "          keepalive: %d\n", p.Keepalive)
			}
		}
	}
	return b.String(), nil
}

// hostCIDR turns a bare address into a /32, leaving an existing CIDR untouched.
func hostCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	return s + "/32"
}

// ensureCIDR is hostCIDR for the client Address line.
func ensureCIDR(s string) string { return hostCIDR(s) }
