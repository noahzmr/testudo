package engine

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/health"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/storage"
	"github.com/noahzmr/testudo/internal/wireguard"
)

// wgUnprivilegedHint is the actionable remediation surfaced when WireGuard state
// can't be read (needs CAP_NET_ADMIN via generic-netlink).
const wgUnprivilegedHint = "grant CAP_NET_ADMIN (sudo setcap cap_net_admin+ep ./testudo) or run with the privileged helper"

// errWireGuardNoNetops is returned by the management helpers when netops is
// unavailable (privileged mutations have nowhere to go).
var errWireGuardNoNetops = errors.New("wireguard management unavailable: netops not initialized")

// startWireGuardPersister consumes the WireGuard snapshot stream and (a) writes
// per-tick peer samples to SQLite for replay (public keys only) and (b) refines
// the "wireguard" subsystem health row: OK while snapshots flow, unprivileged/
// soft-fail when reads error, and a benign "no device" note when the tunnel is
// simply absent. It is a no-op when WireGuard monitoring is disabled.
func (e *Engine) startWireGuardPersister(ctx context.Context) {
	if e.wg0 == nil {
		return
	}
	sub := e.bus.SubscribeKinds(events.KindWireGuardSnapshot)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer sub.Close()
		// A slow ticker independently checks read availability, because a failed
		// read publishes no snapshot event - without this the health row would
		// never leave OK.
		healthTick := time.NewTicker(10 * time.Second)
		defer healthTick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-sub.C():
				if !ok {
					return
				}
				snap, ok := ev.Payload.(wireguard.Snapshot)
				if !ok {
					continue
				}
				e.persistWireGuardSnapshot(ctx, snap)
				e.reportWireGuardHealth()
			case <-healthTick.C:
				e.reportWireGuardHealth()
			}
		}
	}()
}

// persistWireGuardSnapshot writes one sample row per peer. HandshakeAgeSec is -1
// for a never-established peer so replay can tell "stale" from "never".
func (e *Engine) persistWireGuardSnapshot(ctx context.Context, snap wireguard.Snapshot) {
	var samples []storage.WireGuardSample
	for _, d := range snap.Devices {
		for _, p := range d.Peers {
			age := int64(-1)
			if !p.Never {
				age = int64(p.HandshakeAge.Seconds())
			}
			samples = append(samples, storage.WireGuardSample{
				TS:              snap.Time,
				Device:          d.Name,
				PeerPublicKey:   p.PublicKey,
				HandshakeAgeSec: age,
				RxBytes:         p.ReceiveBytes,
				TxBytes:         p.TransmitBytes,
			})
		}
	}
	_ = e.store.InsertWireGuardSamples(ctx, e.sessionID, snap.Time, samples)
}

// ProvisionWireGuardPeer builds a ProvisionRequest from persisted settings plus
// the per-peer options and runs the transactional provision (G2). It centralises
// the settings->request mapping so the TUI and Web UI stay thin and identical.
// The returned ClientConfig is non-empty only in server-side keygen mode and
// must be shown once then dropped (secrets rule). A summary is written to the
// audit log with public keys only.
func (e *Engine) ProvisionWireGuardPeer(name string, preset wireguard.FirewallPreset, serverSideKeygen bool, peerPub, fixedIP string) (wireguard.ProvisionResult, error) {
	if e.netops == nil {
		return wireguard.ProvisionResult{}, errWireGuardNoNetops
	}
	th := e.settings.Snapshot()
	req := wireguard.ProvisionRequest{
		Device:           firstNonEmpty(th.WireGuardDevice, "wg0"),
		Name:             name,
		Preset:           preset,
		ServerSideKeygen: serverSideKeygen,
		PeerPublicKey:    peerPub,
		FixedIP:          fixedIP,
		TunnelSubnet:     th.WireGuardTunnelSubnet,
		ServerAddr:       th.WireGuardServerAddr,
		WANIface:         th.WireGuardWANIface,
		LANSubnets:       splitCSVList(th.WireGuardLANSubnets),
		ServerPublicKey:  th.WireGuardServerPublicKey,
		Endpoint:         th.WireGuardEndpoint,
		DNS:              th.WireGuardDNS,
	}
	res, err := wireguard.Provision(e.netops, req)
	e.auditWireGuard(context.Background(), "wg_provision_peer", res.Device, res.PeerPublicKey, err)
	if err == nil {
		// Persist the peer name (SQLite) - neither netplan nor the kernel stores it.
		if e.store != nil && res.PeerPublicKey != "" {
			_ = e.store.UpsertWGPeerMeta(context.Background(), res.PeerPublicKey, name, "")
		}
		e.syncWireGuardNetplan(req.Device)
	}
	return res, err
}

// DeprovisionWireGuardPeer reverses a provision for the peer with peerPub (G5):
// removes the peer, its route, all preset firewall rules, and the masquerade,
// then frees the IP. Preset inputs come from settings so every candidate rule
// is torn down.
func (e *Engine) DeprovisionWireGuardPeer(peerPub string) error {
	if e.netops == nil {
		return errWireGuardNoNetops
	}
	th := e.settings.Snapshot()
	device := firstNonEmpty(th.WireGuardDevice, "wg0")
	err := wireguard.Deprovision(e.netops, wireguard.DeprovisionRequest{
		Device:        device,
		PeerPublicKey: peerPub,
		WANIface:      th.WireGuardWANIface,
		LANSubnets:    splitCSVList(th.WireGuardLANSubnets),
	})
	e.auditWireGuard(context.Background(), "wg_deprovision_peer", device, peerPub, err)
	if err == nil {
		if e.store != nil {
			_ = e.store.DeleteWGPeerMeta(context.Background(), peerPub)
		}
		e.syncWireGuardNetplan(device)
	}
	return err
}

// UpdateWireGuardPeer applies a full edit to an existing peer - endpoint,
// server-side AllowedIPs, and firewall preset - keeping the keypair. Empty
// allowedIPs keeps the current set; the WAN interface and LAN subnets come from
// settings.
func (e *Engine) UpdateWireGuardPeer(peerPub, endpoint string, allowedIPs []string, keepalive int, preset wireguard.FirewallPreset) error {
	if e.netops == nil {
		return errWireGuardNoNetops
	}
	th := e.settings.Snapshot()
	device := firstNonEmpty(th.WireGuardDevice, "wg0")
	err := wireguard.UpdatePeer(e.netops, wireguard.UpdateRequest{
		Device:        device,
		PeerPublicKey: peerPub,
		Endpoint:      endpoint,
		AllowedIPs:    allowedIPs,
		Keepalive:     keepalive,
		Preset:        preset,
		WANIface:      th.WireGuardWANIface,
		LANSubnets:    splitCSVList(th.WireGuardLANSubnets),
	})
	e.auditWireGuard(context.Background(), "wg_update_peer", device, peerPub, err)
	if err == nil {
		e.syncWireGuardNetplan(device)
	}
	return err
}

// wireguardInterfaceConfig builds the netplan InterfaceConfig from settings plus
// the live peer list (public keys only). privateKey is caller-supplied and used
// only for the render/write - it is never persisted or logged by Testudo.
func (e *Engine) wireguardInterfaceConfig(privateKey string) wireguard.InterfaceConfig {
	th := e.settings.Snapshot()
	cfg := wireguard.InterfaceConfig{
		Name:       firstNonEmpty(th.WireGuardDevice, "wg0"),
		Address:    th.WireGuardServerAddr,
		ListenPort: th.WireGuardListenPort,
		PrivateKey: privateKey,
	}
	// Give the server address a prefix if it's bare, matching the tunnel subnet.
	if cfg.Address != "" && !strings.Contains(cfg.Address, "/") {
		if _, bits, ok := splitCIDR(th.WireGuardTunnelSubnet); ok {
			cfg.Address = cfg.Address + "/" + bits
		} else {
			cfg.Address = cfg.Address + "/24"
		}
	}
	if e.wg0 != nil {
		if snap, ok := e.wg0.Snapshot(); ok {
			for _, d := range snap.Devices {
				if d.Name != cfg.Name {
					continue
				}
				for _, p := range d.Peers {
					cfg.Peers = append(cfg.Peers, wireguard.NetplanPeer{
						PublicKey:  p.PublicKey,
						AllowedIPs: p.AllowedIPs,
						Endpoint:   p.Endpoint,
						Keepalive:  int(p.PersistentKeepalive.Seconds()),
					})
				}
			}
		}
	}
	return cfg
}

// RenderWireGuardNetplan returns the netplan YAML for the wg interface without
// writing anything. privateKey is optional (omitted from the render when empty)
// and never persisted. Read-only - safe without netops writes.
func (e *Engine) RenderWireGuardNetplan(privateKey string) (string, error) {
	return wireguard.RenderNetplan(e.wireguardInterfaceConfig(privateKey))
}

// WriteWireGuardNetplan renders and writes the wg-interface netplan file
// (write-gated). The operator then applies it with `sudo netplan apply` - the
// privileged helper cannot exec (seccomp denies execve), so Testudo writes the
// declarative config but does not run netplan itself. Returns the path written.
func (e *Engine) WriteWireGuardNetplan(privateKey string) (string, error) {
	if e.netops == nil {
		return "", errWireGuardNoNetops
	}
	content, err := e.RenderWireGuardNetplan(privateKey)
	if err != nil {
		return "", err
	}
	th := e.settings.Snapshot()
	path := firstNonEmpty(th.WireGuardNetplanPath, "/etc/netplan/60-testudo-wg.yaml")
	err = e.netops.WriteNetplan(path, content)
	// Audit the path only - never the content (it may hold the private key).
	e.auditWireGuard(context.Background(), "wg_write_netplan", firstNonEmpty(th.WireGuardDevice, "wg0"), path, err)
	return path, err
}

// splitCIDR returns the network address and prefix-length string of a CIDR.
func splitCIDR(cidr string) (network, bits string, ok bool) {
	i := strings.LastIndex(cidr, "/")
	if i < 0 {
		return "", "", false
	}
	return cidr[:i], cidr[i+1:], true
}

// wireguardPeerNames returns the peer public-key -> display-name map from
// wg_peer_meta, feeding the collector's merged read. Never blocks the collector
// on a DB error - it just yields no names.
func (e *Engine) wireguardPeerNames() map[string]string {
	if e.store == nil {
		return nil
	}
	meta, err := e.store.WGPeerMetaMap(context.Background())
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(meta))
	for k, m := range meta {
		if m.Name != "" {
			out[k] = m.Name
		}
	}
	return out
}

// wireguardIfaceNames returns the device -> label map from wg_iface_meta.
func (e *Engine) wireguardIfaceNames() map[string]string {
	if e.store == nil {
		return nil
	}
	m, err := e.store.WGIfaceMetaMap(context.Background())
	if err != nil {
		return nil
	}
	return m
}

// interfaceNetplanPath is the conventional netplan file Testudo writes for a wg
// interface it created, so create/delete can find it deterministically.
func interfaceNetplanPath(device string) string {
	return "/etc/netplan/60-testudo-" + device + ".yaml"
}

// CreateWireGuardInterface writes a netplan tunnel for a new wg device and
// applies it (§2 safe-apply). When privateKey is empty a keypair is generated;
// the private key lands only in the 0600 netplan file, never in SQLite/logs. The
// returned public key lets the operator note the server key. Write-gated.
func (e *Engine) CreateWireGuardInterface(device, address string, listenPort int, privateKey string) (string, error) {
	if e.netops == nil {
		return "", errWireGuardNoNetops
	}
	if device == "" || address == "" {
		return "", errors.New("device and address (CIDR) required")
	}
	pub := ""
	if privateKey == "" {
		kp, err := wireguard.GenerateKeypair()
		if err != nil {
			return "", err
		}
		privateKey, pub = kp.PrivateKey, kp.PublicKey
	} else if p, err := wireguard.PublicKeyFor(privateKey); err == nil {
		pub = p
	}
	content, err := wireguard.RenderNetplan(wireguard.InterfaceConfig{
		Name: device, Address: address, ListenPort: listenPort, PrivateKey: privateKey,
	})
	if err != nil {
		return "", err
	}
	path := interfaceNetplanPath(device)
	err = e.netops.SafeApplyNetplan(path, content)
	// Audit the public key only - never the private key that went into the file.
	e.auditWireGuard(context.Background(), "wg_iface_create", device, pub, err)
	return pub, err
}

// DeleteWireGuardInterface removes the Testudo-managed netplan file for the
// device, applies, and cleans up SQLite metadata. Write-gated.
func (e *Engine) DeleteWireGuardInterface(device string) error {
	if e.netops == nil {
		return errWireGuardNoNetops
	}
	if device == "" {
		return errors.New("device required")
	}
	err := e.netops.RemoveNetplan(interfaceNetplanPath(device))
	e.auditWireGuard(context.Background(), "wg_iface_delete", device, "", err)
	if err == nil && e.store != nil {
		_ = e.store.UpsertWGIfaceMeta(context.Background(), device, "", "") // clear label row content
	}
	return err
}

// SetWireGuardInterfaceName stores a human label for a wg device (SQLite only -
// neither netplan nor the kernel keeps it). Not a privileged mutation.
func (e *Engine) SetWireGuardInterfaceName(device, name string) error {
	if e.store == nil {
		return errWireGuardNoNetops
	}
	err := e.store.UpsertWGIfaceMeta(context.Background(), device, name, "")
	e.auditWireGuard(context.Background(), "wg_iface_name", device, "", err)
	return err
}

// TuneParams describes a WireGuard interface performance tweak. Zero/false
// fields are skipped, so callers can apply just the knobs they want.
type TuneParams struct {
	MTU           int  // 0 = leave; e.g. 1420 default, 1380/1280 to avoid frag
	TxQueueLen    int  // 0 = leave; larger absorbs bursts (e.g. 1000-2000)
	SocketBuffers bool // apply the recommended UDP socket-buffer sysctls
}

// RecommendedTune is the "max performance" profile Testudo applies on one click:
// the WireGuard default MTU, a generous tx queue, and enlarged socket buffers.
// If tx/rx errors persist after this, the MTU is usually still too high for the
// path (try 1380, then 1280).
func RecommendedTune() TuneParams {
	return TuneParams{MTU: 1420, TxQueueLen: 1000, SocketBuffers: true}
}

// wgPerfSysctls is the recommended UDP socket-buffer profile (bytes). ~25 MiB
// max buffers and a deeper backlog markedly reduce drops on a busy tunnel.
var wgPerfSysctls = [][2]string{
	{"net.core.rmem_max", "26214400"},
	{"net.core.wmem_max", "26214400"},
	{"net.core.rmem_default", "1048576"},
	{"net.core.wmem_default", "1048576"},
	{"net.core.netdev_max_backlog", "5000"},
	{"net.core.optmem_max", "65536"},
}

// TuneWireGuardInterface applies the requested performance tweaks to a wg device
// (MTU, tx queue length, and recommended socket-buffer sysctls). Write-gated;
// audited. Best-effort per knob - it applies what it can and returns the first
// error so a partial tune is still visible.
func (e *Engine) TuneWireGuardInterface(device string, p TuneParams) error {
	if e.netops == nil {
		return errWireGuardNoNetops
	}
	if device == "" {
		return errors.New("device required")
	}
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if p.MTU > 0 {
		note(e.netops.SetMTU(device, p.MTU))
	}
	if p.TxQueueLen > 0 {
		note(e.netops.SetTxQLen(device, p.TxQueueLen))
	}
	if p.SocketBuffers {
		for _, kv := range wgPerfSysctls {
			note(e.netops.SetSysctl(kv[0], kv[1]))
		}
	}
	e.auditWireGuard(context.Background(), "wg_iface_tune", device, "", firstErr)
	return firstErr
}

// RestartWireGuardInterface bounces the wg link (down then up) via netlink -
// a quick way to reset a wedged tunnel without a full netplan apply. Write-gated
// (SetIface* enforce --allow-netops-write).
func (e *Engine) RestartWireGuardInterface(device string) error {
	if e.netops == nil {
		return errWireGuardNoNetops
	}
	if err := e.netops.SetIfaceDown(device); err != nil {
		e.auditWireGuard(context.Background(), "wg_iface_restart", device, "", err)
		return err
	}
	err := e.netops.SetIfaceUp(device)
	e.auditWireGuard(context.Background(), "wg_iface_restart", device, "", err)
	return err
}

// ListNetplan returns every netplan file under /etc/netplan (privileged read).
func (e *Engine) ListNetplan() ([]netops.NetplanFile, error) {
	if e.netops == nil {
		return nil, errWireGuardNoNetops
	}
	return e.netops.ListNetplan()
}

// SaveNetplan writes edited content to a netplan file (write-gated, path
// validated under /etc/netplan). Audited by path only - content may hold a key.
func (e *Engine) SaveNetplan(path, content string) error {
	if e.netops == nil {
		return errWireGuardNoNetops
	}
	err := e.netops.WriteNetplan(path, content)
	e.auditWireGuard(context.Background(), "netplan_save", "", path, err)
	return err
}

// ApplyNetplan runs `netplan apply` (write-gated; validates with generate first).
func (e *Engine) ApplyNetplan() error {
	if e.netops == nil {
		return errWireGuardNoNetops
	}
	err := e.netops.NetplanApply()
	e.auditWireGuard(context.Background(), "netplan_apply", "", "", err)
	return err
}

// SafeApplyNetplan writes edited content and applies it as one transaction with
// backup + validate + rollback (§2). Write-gated; audited by path only.
func (e *Engine) SafeApplyNetplan(path, content string) error {
	if e.netops == nil {
		return errWireGuardNoNetops
	}
	err := e.netops.SafeApplyNetplan(path, content)
	e.auditWireGuard(context.Background(), "netplan_safe_apply", "", path, err)
	return err
}

// syncWireGuardNetplan keeps a Testudo-managed netplan file in step with the
// live peer set after a mutation, so the change survives a reboot / netplan
// apply. Best-effort: a no-op when no netplan path is configured, and it does
// nothing to a file Testudo didn't create (the netops layer marker-gates it).
// Called after a successful provision / update / deprovision.
func (e *Engine) syncWireGuardNetplan(device string) {
	if e.netops == nil {
		return
	}
	th := e.settings.Snapshot()
	path := th.WireGuardNetplanPath
	if path == "" {
		return
	}
	peers := e.wireguardNetplanPeers(device)
	if err := e.netops.SyncNetplan(path, peers); err != nil {
		log.Printf("wireguard: netplan sync failed: %v", err)
	}
}

// wireguardNetplanPeers returns the current peer set for device as netplan wire
// peers (public only). It prefers a fresh netops read (accurate right after a
// change) and falls back to the collector's cached snapshot when the read is
// unavailable (e.g. unprivileged engine without CAP_NET_ADMIN).
func (e *Engine) wireguardNetplanPeers(device string) []netops.NetplanPeerWire {
	if devs, err := e.netops.ListWGDevices(); err == nil {
		for _, d := range devs {
			if d.Name != device {
				continue
			}
			var out []netops.NetplanPeerWire
			for _, p := range d.Peers {
				out = append(out, netops.NetplanPeerWire{
					PublicKey: p.PublicKey, AllowedIPs: p.AllowedIPs,
					Endpoint: p.Endpoint, Keepalive: int(p.PersistentKeepalive.Seconds()),
				})
			}
			return out
		}
	}
	if e.wg0 != nil {
		if snap, ok := e.wg0.Snapshot(); ok {
			for _, d := range snap.Devices {
				if d.Name != device {
					continue
				}
				var out []netops.NetplanPeerWire
				for _, p := range d.Peers {
					out = append(out, netops.NetplanPeerWire{
						PublicKey: p.PublicKey, AllowedIPs: p.AllowedIPs,
						Endpoint: p.Endpoint, Keepalive: int(p.PersistentKeepalive.Seconds()),
					})
				}
				return out
			}
		}
	}
	return nil
}

// auditWireGuard records a provisioning op to the audit log. Public keys only -
// never a private or preshared key.
func (e *Engine) auditWireGuard(ctx context.Context, op, device, peerPub string, opErr error) {
	if e.store == nil {
		return
	}
	result := "ok"
	if opErr != nil {
		result = opErr.Error()
	}
	args := `{"device":"` + device + `","peer_public_key":"` + peerPub + `"}`
	_ = e.store.InsertAudit(ctx, storage.AuditEntry{
		Op: op, Args: args, Result: result,
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitCSVList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// WireGuardGrade returns the WireGuard sub-score for the Network Quality grade
// and whether it carries data. hasData=false (neutral 100) when WireGuard is
// disabled, unread, or has no device - the grade excludes it entirely so a host
// without WireGuard is never penalised.
func (e *Engine) WireGuardGrade() (score int, hasData bool) {
	if e.wg0 == nil {
		return 100, false
	}
	snap, ok := e.wg0.Snapshot()
	if !ok {
		return 100, false
	}
	return snap.SubScore()
}

// reportWireGuardHealth maps the collector's read state onto the subsystem
// registry. When reads fail (missing CAP_NET_ADMIN) the row goes "unprivileged"
// with a setcap hint; when reads succeed it is "ok" (even with zero devices -
// having no WireGuard is not a fault). Not marked core: a missing tunnel must
// never drag down the headline connectivity grade.
func (e *Engine) reportWireGuardHealth() {
	if e.wg0 == nil {
		return
	}
	if e.wg0.Available() {
		e.MarkSubsystem("wireguard", false, health.StateOK, "", "")
		return
	}
	if err := e.wg0.LastErr(); err != nil {
		e.MarkSubsystem("wireguard", false, health.StateUnprivileged, err.Error(), wgUnprivilegedHint)
	}
}
