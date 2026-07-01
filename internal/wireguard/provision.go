package wireguard

import (
	"fmt"
	"strings"

	"github.com/noahzmr/testudo/internal/netops"
)

// NetopsBackend is the privileged surface the provisioner drives. Every method
// is already write-gated and audit-logged inside netops and, when the engine is
// helper-backed, executes in the privileged helper. *netops.Writer satisfies it;
// tests substitute a fake to assert the transaction + rollback ordering.
type NetopsBackend interface {
	ListWGDevices() ([]netops.WGDeviceInfo, error)
	ConfigureWGPeer(device, peerPubKey string, allowedIPs []string, endpoint string, keepalive int) error
	RemoveWGPeer(device, peerPubKey string) error
	AddRoute(cidr, gateway, iface string) error
	DelRoute(cidr string) error
	AddFilterRule(fr netops.FilterRule) error
	DelFilterRule(fr netops.FilterRule) error
	AddMasquerade(outIface, srcCIDR string) error
	DelMasquerade(outIface, srcCIDR string) error
	WriteNetplan(path, content string) error
}

// ProvisionRequest fully describes a peer to provision. The IPAM + preset inputs
// (TunnelSubnet, ServerAddr, WANIface, LANSubnets) come from settings, not the
// end user, so an operator can't fat-finger the routing policy.
type ProvisionRequest struct {
	Device string         // wg device, e.g. "wg0"
	Name   string         // human label; used only in the returned config comment
	Preset FirewallPreset // routing policy

	// ServerSideKeygen=true means the server generates the keypair and returns a
	// one-shot client config (with the private key). Default (false) means the
	// client generated its keypair in the browser and submits only PeerPublicKey.
	ServerSideKeygen bool
	PeerPublicKey    string // required unless ServerSideKeygen

	// IPAM.
	TunnelSubnet string // "10.8.0.0/24"
	ServerAddr   string // "10.8.0.1"
	FixedIP      string // optional caller-chosen peer IP; validated against pool

	// Firewall preset inputs.
	WANIface   string   // masquerade egress iface for full tunnel, e.g. "eth0"
	LANSubnets []string // reachable subnets for the split preset

	// Client-config rendering (server-side keygen only, G6).
	ServerPublicKey string
	Endpoint        string
	DNS             string
	Keepalive       int
}

// ProvisionResult is returned once. ClientConfig is non-empty only in
// server-side keygen mode and must be shown once then dropped (secrets rule).
type ProvisionResult struct {
	Device        string
	PeerPublicKey string
	AssignedIP    string // "10.8.0.5/32"
	Preset        FirewallPreset
	ClientConfig  string // server-side keygen only; contains a private key
}

// Provision runs the whole peer-creation transaction as a unit with rollback.
// On any step failure every already-applied step is undone in reverse order, so
// a half-provisioned peer never lingers. The steps mirror G2:
//
//  1. resolve/generate the peer keypair
//  2. allocate an IP from the tunnel pool (collision-free)
//  3. configure the peer via ConfigureDevice (pubkey + AllowedIPs)
//  4. set the route over the wg device
//  5. apply the firewall preset
//  6. render the client config (server-side keygen only)
func Provision(be NetopsBackend, req ProvisionRequest) (ProvisionResult, error) {
	if req.Device == "" {
		return ProvisionResult{}, fmt.Errorf("wg device required")
	}
	if !req.Preset.Valid() {
		return ProvisionResult{}, fmt.Errorf("invalid firewall preset %q", req.Preset)
	}
	if req.TunnelSubnet == "" {
		return ProvisionResult{}, fmt.Errorf("tunnel subnet required for IPAM")
	}
	if req.Preset == PresetFullTunnel && req.WANIface == "" {
		return ProvisionResult{}, fmt.Errorf("full-tunnel preset requires a WAN interface for masquerade")
	}

	// Step 1: resolve the peer public key (and keep the private key locally for a
	// one-shot config render in server-side mode - it is never persisted/logged).
	var clientPrivateKey string
	peerPub := strings.TrimSpace(req.PeerPublicKey)
	if req.ServerSideKeygen {
		kp, err := GenerateKeypair()
		if err != nil {
			return ProvisionResult{}, err
		}
		clientPrivateKey = kp.PrivateKey
		peerPub = kp.PublicKey
	}
	if peerPub == "" {
		return ProvisionResult{}, fmt.Errorf("peer public key required (or enable server-side keygen)")
	}

	// Read the live device to feed IPAM and detect duplicates.
	devs, err := be.ListWGDevices()
	if err != nil {
		return ProvisionResult{}, fmt.Errorf("read wg devices: %w", err)
	}
	dev, ok := findDevice(devs, req.Device)
	if !ok {
		return ProvisionResult{}, fmt.Errorf("wg device %q not found", req.Device)
	}
	for _, p := range dev.Peers {
		if p.PublicKey == peerPub {
			return ProvisionResult{}, fmt.Errorf("peer %s already exists on %s", ShortKey(peerPub), req.Device)
		}
	}

	// Step 2: allocate the IP.
	taken := allAllowedIPs(dev)
	var assignedIP string
	if req.FixedIP != "" {
		if !ServerSubnetContains(req.TunnelSubnet, req.FixedIP) {
			return ProvisionResult{}, fmt.Errorf("fixed IP %s is outside tunnel subnet %s", req.FixedIP, req.TunnelSubnet)
		}
		if ipTaken(taken, req.FixedIP) {
			return ProvisionResult{}, fmt.Errorf("fixed IP %s is already allocated", req.FixedIP)
		}
		assignedIP = hostCIDR(req.FixedIP)
	} else {
		assignedIP, err = AllocateIP(req.TunnelSubnet, req.ServerAddr, taken)
		if err != nil {
			return ProvisionResult{}, err
		}
	}

	// Transaction: accumulate undo steps, unwind on the first failure.
	var undo []func()
	rollback := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	fail := func(err error) (ProvisionResult, error) {
		rollback()
		return ProvisionResult{}, err
	}

	// Step 3: configure the peer. Endpoint is left unset on provision - the
	// client roams and its endpoint is learned on first handshake. keepalive -1
	// leaves it unset server-side (the client sets its own keepalive).
	if err := be.ConfigureWGPeer(req.Device, peerPub, []string{assignedIP}, "", -1); err != nil {
		return fail(fmt.Errorf("configure peer: %w", err))
	}
	undo = append(undo, func() { _ = be.RemoveWGPeer(req.Device, peerPub) })

	// Step 4: route the peer's address over the wg device.
	if err := be.AddRoute(assignedIP, "", req.Device); err != nil {
		return fail(fmt.Errorf("add route: %w", err))
	}
	undo = append(undo, func() { _ = be.DelRoute(assignedIP) })

	// Step 5: apply the firewall preset.
	rules, masq := presetRules(req.Preset, req.Device, assignedIP, req.WANIface, req.LANSubnets)
	for _, fr := range rules {
		if err := be.AddFilterRule(fr); err != nil {
			return fail(fmt.Errorf("apply firewall rule: %w", err))
		}
		undo = append(undo, func() { _ = be.DelFilterRule(fr) })
	}
	if masq != nil {
		if err := be.AddMasquerade(masq.outIface, masq.srcCIDR); err != nil {
			return fail(fmt.Errorf("apply masquerade: %w", err))
		}
		m := *masq
		undo = append(undo, func() { _ = be.DelMasquerade(m.outIface, m.srcCIDR) })
	}

	res := ProvisionResult{
		Device:        req.Device,
		PeerPublicKey: peerPub,
		AssignedIP:    assignedIP,
		Preset:        req.Preset,
	}
	// Step 6: one-shot client config (server-side keygen only).
	if req.ServerSideKeygen {
		res.ClientConfig = RenderClientConfig(req, clientPrivateKey, assignedIP)
	}
	// Drop the private key reference; it lives only in res.ClientConfig now.
	clientPrivateKey = "" //nolint:ineffassign // explicit secret drop
	_ = clientPrivateKey
	return res, nil
}

// DeprovisionRequest reverses a Provision. It reconstructs the deterministic set
// of routes/firewall rules for the peer and removes them, then removes the peer.
// The preset inputs are supplied again (from settings) so every candidate rule
// can be torn down; DelFilterRule/DelMasquerade are no-ops for rules that don't
// exist, so passing the union across presets is safe.
type DeprovisionRequest struct {
	Device        string
	PeerPublicKey string
	WANIface      string
	LANSubnets    []string
}

// Deprovision removes a peer and every artifact Provision created for it: the
// route, all firewall-preset rules, the masquerade, and the peer itself. The
// peer's IP is freed implicitly because IPAM reads live AllowedIPs.
func Deprovision(be NetopsBackend, req DeprovisionRequest) error {
	if req.Device == "" || req.PeerPublicKey == "" {
		return fmt.Errorf("device and peer public key required")
	}
	devs, err := be.ListWGDevices()
	if err != nil {
		return fmt.Errorf("read wg devices: %w", err)
	}
	dev, ok := findDevice(devs, req.Device)
	if !ok {
		return fmt.Errorf("wg device %q not found", req.Device)
	}
	var peer *netops.WGPeerInfo
	for i := range dev.Peers {
		if dev.Peers[i].PublicKey == req.PeerPublicKey {
			peer = &dev.Peers[i]
			break
		}
	}
	if peer == nil {
		return fmt.Errorf("peer %s not found on %s", ShortKey(req.PeerPublicKey), req.Device)
	}

	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Remove every route + firewall rule for each address routed to the peer.
	for _, aip := range peer.AllowedIPs {
		peerIP := hostCIDR(strings.TrimSpace(aip))
		note(be.DelRoute(peerIP))
		// Remove candidate rules across every preset (idempotent).
		for _, preset := range []FirewallPreset{PresetFullTunnel, PresetSplit, PresetIsolated} {
			rules, masq := presetRules(preset, req.Device, peerIP, req.WANIface, req.LANSubnets)
			for _, fr := range rules {
				note(be.DelFilterRule(fr))
			}
			if masq != nil {
				note(be.DelMasquerade(masq.outIface, masq.srcCIDR))
			}
		}
	}
	// Finally remove the peer.
	note(be.RemoveWGPeer(req.Device, req.PeerPublicKey))
	return firstErr
}

// UpdateRequest is a full edit of an existing peer: its endpoint, its
// server-side AllowedIPs (the addresses routed to it), and its firewall preset.
// The keypair is never touched. Empty AllowedIPs means "keep the current set";
// Endpoint is applied as given (empty clears it). Preset inputs come from
// settings.
type UpdateRequest struct {
	Device        string
	PeerPublicKey string
	Endpoint      string   // "host:port"; "" clears the stored endpoint
	AllowedIPs    []string // nil/empty = keep current
	Keepalive     int      // persistent-keepalive seconds: -1 leave, 0 clear, >0 set
	Preset        FirewallPreset
	WANIface      string
	LANSubnets    []string
}

// UpdatePeer applies a full edit to an existing peer. It reconfigures the peer's
// AllowedIPs + endpoint, reconciles the wg-device routes (adds for new IPs,
// removes for dropped ones), and swaps the firewall preset (tears down every old
// candidate rule for the old IPs, applies the new preset for the current IPs).
// The peer's keypair is preserved throughout.
func UpdatePeer(be NetopsBackend, req UpdateRequest) error {
	if req.Device == "" || req.PeerPublicKey == "" {
		return fmt.Errorf("device and peer public key required")
	}
	if !req.Preset.Valid() {
		return fmt.Errorf("invalid firewall preset %q", req.Preset)
	}
	if req.Preset == PresetFullTunnel && req.WANIface == "" {
		return fmt.Errorf("full-tunnel preset requires a WAN interface for masquerade")
	}
	devs, err := be.ListWGDevices()
	if err != nil {
		return fmt.Errorf("read wg devices: %w", err)
	}
	dev, ok := findDevice(devs, req.Device)
	if !ok {
		return fmt.Errorf("wg device %q not found", req.Device)
	}
	var peer *netops.WGPeerInfo
	for i := range dev.Peers {
		if dev.Peers[i].PublicKey == req.PeerPublicKey {
			peer = &dev.Peers[i]
			break
		}
	}
	if peer == nil {
		return fmt.Errorf("peer %s not found on %s", ShortKey(req.PeerPublicKey), req.Device)
	}

	oldIPs := normalizeIPs(peer.AllowedIPs)
	newIPs := oldIPs
	if len(req.AllowedIPs) > 0 {
		newIPs = normalizeIPs(req.AllowedIPs)
		if len(newIPs) == 0 {
			return fmt.Errorf("no valid allowed IPs supplied")
		}
	}

	// Reconfigure the peer (AllowedIPs replaced, endpoint + keepalive set).
	if err := be.ConfigureWGPeer(req.Device, req.PeerPublicKey, newIPs, req.Endpoint, req.Keepalive); err != nil {
		return fmt.Errorf("reconfigure peer: %w", err)
	}

	// Reconcile routes: add routes for newly-added IPs, drop routes for removed
	// IPs. Best-effort so a stale route can't block the edit.
	for _, ip := range newIPs {
		if !containsIP(oldIPs, ip) {
			_ = be.AddRoute(ip, "", req.Device)
		}
	}
	for _, ip := range oldIPs {
		if !containsIP(newIPs, ip) {
			_ = be.DelRoute(ip)
		}
	}

	// Firewall: tear down every candidate rule for the OLD IPs across all
	// presets, then apply the new preset for the CURRENT IPs.
	for _, ip := range oldIPs {
		for _, preset := range []FirewallPreset{PresetFullTunnel, PresetSplit, PresetIsolated} {
			rules, masq := presetRules(preset, req.Device, ip, req.WANIface, req.LANSubnets)
			for _, fr := range rules {
				_ = be.DelFilterRule(fr)
			}
			if masq != nil {
				_ = be.DelMasquerade(masq.outIface, masq.srcCIDR)
			}
		}
	}
	for _, ip := range newIPs {
		rules, masq := presetRules(req.Preset, req.Device, ip, req.WANIface, req.LANSubnets)
		for _, fr := range rules {
			if err := be.AddFilterRule(fr); err != nil {
				return fmt.Errorf("apply firewall rule: %w", err)
			}
		}
		if masq != nil {
			if err := be.AddMasquerade(masq.outIface, masq.srcCIDR); err != nil {
				return fmt.Errorf("apply masquerade: %w", err)
			}
		}
	}
	return nil
}

// normalizeIPs trims, host-CIDRs, and de-dupes a list of allowed IPs.
func normalizeIPs(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		c := hostCIDR(s)
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func containsIP(list []string, ip string) bool {
	for _, v := range list {
		if v == ip {
			return true
		}
	}
	return false
}

// masqSpec is an internal description of a masquerade rule for a preset.
type masqSpec struct {
	outIface string
	srcCIDR  string
}

// presetRules builds the deterministic firewall rule set (and optional
// masquerade) for a peer under a preset. Rules are ordered so that ACCEPTs
// precede any catch-all DROP - nftables evaluates in insertion order and
// AddFilterRule appends. Forwarding is always scoped to the wg device and
// direction (never a blanket FORWARD ACCEPT), per WireGuard best practice.
func presetRules(preset FirewallPreset, device, peerIP, wanIface string, lanSubnets []string) ([]netops.FilterRule, *masqSpec) {
	peerCIDR := hostCIDR(peerIP)
	// Return path is identical for every preset that allows any forwarding:
	// let replies flow back out the tunnel to the peer.
	returnRule := netops.FilterRule{Chain: "forward", Action: "accept", OutIface: device, DstCIDR: peerCIDR}

	switch preset {
	case PresetFullTunnel:
		rules := []netops.FilterRule{
			{Chain: "forward", Action: "accept", InIface: device, SrcCIDR: peerCIDR},
			returnRule,
		}
		return rules, &masqSpec{outIface: wanIface, srcCIDR: peerCIDR}

	case PresetSplit:
		var rules []netops.FilterRule
		for _, sub := range lanSubnets {
			sub = strings.TrimSpace(sub)
			if sub == "" {
				continue
			}
			rules = append(rules, netops.FilterRule{
				Chain: "forward", Action: "accept", InIface: device,
				SrcCIDR: peerCIDR, DstCIDR: sub,
			})
		}
		rules = append(rules, returnRule)
		// Catch-all DROP for anything else the peer tries to forward. MUST be
		// last so the accepts above win.
		rules = append(rules, netops.FilterRule{
			Chain: "forward", Action: "drop", InIface: device, SrcCIDR: peerCIDR,
		})
		return rules, nil

	case PresetIsolated:
		// Block all forwarding from the peer. Traffic to the server itself is
		// INPUT (not FORWARD) and stays reachable; peer-to-peer and LAN/internet
		// are dropped.
		return []netops.FilterRule{
			{Chain: "forward", Action: "drop", InIface: device, SrcCIDR: peerCIDR},
		}, nil
	}
	return nil, nil
}

func findDevice(devs []netops.WGDeviceInfo, name string) (netops.WGDeviceInfo, bool) {
	for _, d := range devs {
		if d.Name == name {
			return d, true
		}
	}
	return netops.WGDeviceInfo{}, false
}

func allAllowedIPs(dev netops.WGDeviceInfo) []string {
	var out []string
	for _, p := range dev.Peers {
		out = append(out, p.AllowedIPs...)
	}
	return out
}

func ipTaken(taken []string, ip string) bool {
	want := hostCIDR(strings.TrimSpace(ip))
	for _, t := range taken {
		if hostCIDR(strings.TrimSpace(t)) == want {
			return true
		}
	}
	return false
}
