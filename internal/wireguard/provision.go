package wireguard

import (
	"fmt"
	"strings"

	"github.com/noahzmr/testudo/internal/netops"
)

// NetopsBackend is the privileged surface the provisioner drives. Peer, route
// and netplan ops are write-gated and audit-logged inside netops and, when the
// engine is helper-backed, execute in the privileged helper. Firewall and NAT
// ops go through the firewall policy manager (the engine adapts it) so preset
// rules are persisted and survive a reboot. Tests substitute a fake to assert
// the transaction + rollback ordering.
type NetopsBackend interface {
	ListWGDevices() ([]netops.WGDeviceInfo, error)
	ConfigureWGPeer(device, peerPubKey string, allowedIPs []string, endpoint string, keepalive int) error
	RemoveWGPeer(device, peerPubKey string) error
	AddRoute(cidr, gateway, iface string) error
	DelRoute(cidr string) error
	AddFilterRule(fr netops.FilterRule) error
	// DelFilterRulesMatching removes rules whose non-empty fields match target
	// (used to tear down pre-ownership rules imported from older builds).
	DelFilterRulesMatching(target netops.FilterRule) error
	// DelFilterRulesByOwner removes every rule tagged with owner (OwnerForPeer).
	DelFilterRulesByOwner(owner string) error
	AddMasquerade(ms netops.Masquerade) error
	DelMasqueradesMatching(outIface, srcCIDR string) error
	DelMasqueradesByOwner(owner string) error
	WriteNetplan(path, content string) error
}

// ownerPrefix tags every firewall/NAT entry provisioned for a peer.
const ownerPrefix = "wg-peer:"

// OwnerForPeer is the firewall ownership tag for everything Testudo provisions
// for a peer, so deprovisioning removes exactly those entries - no matter how
// the preset inputs (LAN subnets, WAN interface) changed in the meantime.
func OwnerForPeer(peerPublicKey string) string { return ownerPrefix + peerPublicKey }

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

	// Step 5: apply the firewall preset. Every entry carries the peer's owner
	// tag; one owner-scoped delete undoes all of them.
	owner := OwnerForPeer(peerPub)
	rules, masq := presetRules(req.Preset, req.Device, assignedIP, req.WANIface, req.LANSubnets, owner)
	if len(rules) > 0 {
		undo = append(undo, func() { _ = be.DelFilterRulesByOwner(owner) })
	}
	for _, fr := range rules {
		if err := be.AddFilterRule(fr); err != nil {
			return fail(fmt.Errorf("apply firewall rule: %w", err))
		}
	}
	if masq != nil {
		undo = append(undo, func() { _ = be.DelMasqueradesByOwner(owner) })
		if err := be.AddMasquerade(*masq); err != nil {
			return fail(fmt.Errorf("apply masquerade: %w", err))
		}
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

// DeprovisionRequest reverses a Provision: routes for the peer's addresses, every
// firewall/NAT entry tagged with the peer's owner, and the peer itself. The
// preset inputs are still accepted so rules provisioned by older builds (before
// ownership tags) can be torn down by reconstructing them.
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

	// Routes for every address routed to the peer, plus legacy (pre-ownership)
	// preset rules reconstructed from the current inputs.
	for _, aip := range peer.AllowedIPs {
		peerIP := hostCIDR(strings.TrimSpace(aip))
		note(be.DelRoute(peerIP))
		teardownLegacyPresetRules(be, req.Device, peerIP, req.WANIface, req.LANSubnets, note)
	}
	// Everything tagged for this peer, whatever the inputs were at the time.
	owner := OwnerForPeer(req.PeerPublicKey)
	note(be.DelFilterRulesByOwner(owner))
	note(be.DelMasqueradesByOwner(owner))
	// Finally remove the peer.
	note(be.RemoveWGPeer(req.Device, req.PeerPublicKey))
	return firstErr
}

// teardownLegacyPresetRules removes preset rules written by builds that did
// not tag ownership, by reconstructing every preset's candidate rules for the
// peer IP and deleting whatever matches. Idempotent; a no-op on fresh hosts.
func teardownLegacyPresetRules(be NetopsBackend, device, peerIP, wanIface string, lanSubnets []string, note func(error)) {
	for _, preset := range []FirewallPreset{PresetFullTunnel, PresetSplit, PresetIsolated} {
		rules, masq := presetRules(preset, device, peerIP, wanIface, lanSubnets, "")
		for _, fr := range rules {
			fr.Owner, fr.Comment = "", ""
			note(be.DelFilterRulesMatching(fr))
		}
		if masq != nil {
			note(be.DelMasqueradesMatching(masq.OutIface, masq.SrcCIDR))
		}
	}
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

	// Firewall: tear down everything tagged for the peer (plus legacy untagged
	// rules for the OLD IPs), then apply the new preset for the CURRENT IPs.
	owner := OwnerForPeer(req.PeerPublicKey)
	ignore := func(error) {}
	for _, ip := range oldIPs {
		teardownLegacyPresetRules(be, req.Device, ip, req.WANIface, req.LANSubnets, ignore)
	}
	_ = be.DelFilterRulesByOwner(owner)
	_ = be.DelMasqueradesByOwner(owner)
	for _, ip := range newIPs {
		rules, masq := presetRules(req.Preset, req.Device, ip, req.WANIface, req.LANSubnets, owner)
		for _, fr := range rules {
			if err := be.AddFilterRule(fr); err != nil {
				return fmt.Errorf("apply firewall rule: %w", err)
			}
		}
		if masq != nil {
			if err := be.AddMasquerade(*masq); err != nil {
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

// presetRules builds the deterministic firewall rule set (and optional
// masquerade) for a peer under a preset, every entry tagged with owner. Rules
// are ordered so that ACCEPTs precede the catch-all DROP - the policy manager
// installs them in order. Forwarding is always scoped to the wg device and the
// peer's address (never a blanket FORWARD ACCEPT), per WireGuard best practice.
//
// Return traffic needs no rule here: the firewall baseline's
// `ct state established,related accept` covers replies to the peer. The old
// per-peer return rule (`oif wg0 daddr peer accept`) let any LAN host *initiate*
// connections to the peer and is gone.
func presetRules(preset FirewallPreset, device, peerIP, wanIface string, lanSubnets []string, owner string) ([]netops.FilterRule, *netops.Masquerade) {
	peerCIDR := hostCIDR(peerIP)
	comment := "wg " + string(preset) + " preset"

	switch preset {
	case PresetFullTunnel:
		rules := []netops.FilterRule{
			{Chain: "forward", Action: "accept", InIface: device, SrcCIDR: peerCIDR, Owner: owner, Comment: comment},
		}
		return rules, &netops.Masquerade{OutIface: wanIface, SrcCIDR: peerCIDR, Owner: owner, Comment: comment}

	case PresetSplit:
		var rules []netops.FilterRule
		for _, sub := range lanSubnets {
			sub = strings.TrimSpace(sub)
			if sub == "" {
				continue
			}
			rules = append(rules, netops.FilterRule{
				Chain: "forward", Action: "accept", InIface: device,
				SrcCIDR: peerCIDR, DstCIDR: sub, Owner: owner, Comment: comment,
			})
		}
		// Catch-all DROP for anything else the peer tries to forward. MUST be
		// last so the accepts above win.
		rules = append(rules, netops.FilterRule{
			Chain: "forward", Action: "drop", InIface: device, SrcCIDR: peerCIDR, Owner: owner, Comment: comment,
		})
		return rules, nil

	case PresetIsolated:
		// Block all forwarding from the peer. Traffic to the server itself is
		// INPUT (not FORWARD) and stays reachable; peer-to-peer and LAN/internet
		// are dropped.
		return []netops.FilterRule{
			{Chain: "forward", Action: "drop", InIface: device, SrcCIDR: peerCIDR, Owner: owner, Comment: comment},
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
