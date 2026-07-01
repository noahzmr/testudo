package netops

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGDeviceInfo is a denormalised, secrets-free view of one WireGuard device.
// The private key is deliberately omitted - only the public key is ever
// surfaced or persisted (secrets rule).
type WGDeviceInfo struct {
	Name         string
	PublicKey    string // base64 public key (public material)
	ListenPort   int
	FirewallMark int
	Peers        []WGPeerInfo
}

// WGPeerInfo is a denormalised, secrets-free view of one WireGuard peer. The
// preshared key is never included.
type WGPeerInfo struct {
	PublicKey           string // base64 public key (public material)
	Endpoint            string // host:port or "" when unknown
	AllowedIPs          []string
	LastHandshake       time.Time // zero when never established
	ReceiveBytes        int64
	TransmitBytes       int64
	PersistentKeepalive time.Duration
}

// ListWGDevices returns every WireGuard device known to the kernel, sorted by
// name, carrying public keys only. It runs in-process via wgctrl's
// generic-netlink client. Reading device state needs CAP_NET_ADMIN, so an
// unprivileged process gets a permission error here - callers treat that as a
// soft "not available" rather than a hard failure.
func (w *Writer) ListWGDevices() ([]WGDeviceInfo, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl new: %w", err)
	}
	defer c.Close()

	devs, err := c.Devices()
	if err != nil {
		return nil, fmt.Errorf("wg devices: %w", err)
	}
	out := make([]WGDeviceInfo, 0, len(devs))
	for _, d := range devs {
		di := WGDeviceInfo{
			Name:         d.Name,
			PublicKey:    d.PublicKey.String(),
			ListenPort:   d.ListenPort,
			FirewallMark: d.FirewallMark,
		}
		for _, p := range d.Peers {
			pi := WGPeerInfo{
				PublicKey:           p.PublicKey.String(),
				LastHandshake:       p.LastHandshakeTime,
				ReceiveBytes:        p.ReceiveBytes,
				TransmitBytes:       p.TransmitBytes,
				PersistentKeepalive: p.PersistentKeepaliveInterval,
			}
			if p.Endpoint != nil {
				pi.Endpoint = p.Endpoint.String()
			}
			for _, aip := range p.AllowedIPs {
				pi.AllowedIPs = append(pi.AllowedIPs, aip.String())
			}
			di.Peers = append(di.Peers, pi)
		}
		out = append(out, di)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ConfigureWGPeer adds or updates a peer on the named device. peerPubKey is the
// peer's base64 public key; allowedIPs is the list of CIDRs routed to the peer;
// endpoint ("host:port", or "" to leave unset) sets the peer's reachable
// address. No private or preshared key is accepted here - the peer's private key
// stays on the client, and PSKs are out of scope for the managed flow.
func (w *Writer) ConfigureWGPeer(device, peerPubKey string, allowedIPs []string, endpoint string, keepalive int) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{
		Kind:         OpWGConfigurePeer,
		WGDevice:     device,
		WGPeerKey:    peerPubKey,
		WGAllowedIPs: allowedIPs,
		WGEndpoint:   endpoint,
		WGKeepalive:  keepalive,
	})
}

func (w *Writer) wgConfigurePeerDirect(device, peerPubKey string, allowedIPs []string, endpoint string, keepalive int) error {
	if device == "" {
		return fmt.Errorf("wg device name required")
	}
	key, err := wgtypes.ParseKey(peerPubKey)
	if err != nil {
		return fmt.Errorf("parse peer public key: %w", err)
	}
	nets, err := parseAllowedIPs(allowedIPs)
	if err != nil {
		return err
	}
	pc := wgtypes.PeerConfig{
		PublicKey:         key,
		ReplaceAllowedIPs: true,
		AllowedIPs:        nets,
	}
	if strings.TrimSpace(endpoint) != "" {
		ep, err := net.ResolveUDPAddr("udp", strings.TrimSpace(endpoint))
		if err != nil {
			return fmt.Errorf("resolve endpoint %q: %w", endpoint, err)
		}
		pc.Endpoint = ep
	}
	// keepalive: -1 leaves it unchanged, 0 clears, >0 sets N seconds.
	if keepalive >= 0 {
		d := time.Duration(keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &d
	}
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl new: %w", err)
	}
	defer c.Close()

	if err := c.ConfigureDevice(device, wgtypes.Config{Peers: []wgtypes.PeerConfig{pc}}); err != nil {
		return fmt.Errorf("configure %s: %w", device, err)
	}
	// Audit trail (public key only - never the private/preshared key).
	log.Printf("netops audit: wg configure peer dev=%s pub=%s allowed=%s endpoint=%s",
		device, shortKey(peerPubKey), strings.Join(allowedIPs, ","), endpoint)
	return nil
}

// netplanDir is the only directory the netplan ops will write into. It is a var
// (not a const) solely so tests can point it at a temp directory.
var netplanDir = "/etc/netplan"

// netplanMarker identifies a Testudo-rendered netplan file. RenderNetplan (in the
// wireguard package) emits this on the first line; SyncNetplan refuses to touch
// any file that lacks it, so an operator's own netplan is never clobbered.
const netplanMarker = "Managed by Testudo"

// WriteNetplan writes a netplan YAML file describing a WireGuard interface. The
// path must live under /etc/netplan and end in .yaml; the file is written 0600
// because it may contain the interface private key.
func (w *Writer) WriteNetplan(path, content string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpWriteNetplan, NetplanPath: path, NetplanContent: content})
}

func (w *Writer) writeNetplanDirect(path, content string) error {
	clean := filepath.Clean(path)
	if clean != filepath.Join(netplanDir, filepath.Base(clean)) || !strings.HasSuffix(clean, ".yaml") {
		return fmt.Errorf("netplan path must be a *.yaml file directly under %s, got %q", netplanDir, path)
	}
	if content == "" {
		return fmt.Errorf("empty netplan content")
	}
	if err := os.WriteFile(clean, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write netplan %s: %w", clean, err)
	}
	// Audit trail: the path only - never the content (it may hold a private key).
	log.Printf("netops audit: wrote netplan %s (%d bytes)", clean, len(content))
	return nil
}

// NetplanFile is one netplan YAML file under /etc/netplan. Content may hold
// secrets (interface private keys), so it is never logged and is only surfaced
// to an authenticated operator viewing/editing their own config.
type NetplanFile struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Managed bool   `json:"managed"` // carries the Testudo marker
}

// ListNetplan reads every *.yaml under /etc/netplan and returns them, sorted by
// name. It is a privileged READ (netplan files are often 0600) routed through
// the query seam, so it works from the unprivileged engine via the helper. Not
// write-gated - viewing config is not a mutation.
func (w *Writer) ListNetplan() ([]NetplanFile, error) {
	body, err := w.be().Query(Op{Kind: OpListNetplan})
	if err != nil {
		return nil, err
	}
	var out []NetplanFile
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode netplan list: %w", err)
	}
	return out, nil
}

func (w *Writer) listNetplanDirect() ([]byte, error) {
	entries, err := os.ReadDir(netplanDir)
	if err != nil {
		if os.IsNotExist(err) {
			return json.Marshal([]NetplanFile{})
		}
		return nil, fmt.Errorf("read %s: %w", netplanDir, err)
	}
	var files []NetplanFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		p := filepath.Join(netplanDir, e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			continue // unreadable entry - skip rather than fail the whole list
		}
		files = append(files, NetplanFile{
			Name:    e.Name(),
			Path:    p,
			Content: string(data),
			Managed: strings.Contains(string(data), netplanMarker),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return json.Marshal(files)
}

// NetplanApply runs `netplan apply` in the privileged helper (exec, like the
// capture path). Write-gated. Returns the command's stderr on failure.
func (w *Writer) NetplanApply() error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpNetplanApply})
}

func (w *Writer) netplanApplyDirect() error {
	// Validate first - never apply a YAML that doesn't render.
	if err := netplanGenerate(); err != nil {
		return err
	}
	if err := netplanRun("apply"); err != nil {
		return err
	}
	log.Printf("netops audit: netplan apply ok")
	return nil
}

// SafeApplyNetplan is the §2 transactional write+apply: back up the target file,
// write new content, validate with `netplan generate`, `netplan apply`, and on
// any failure restore the backup and re-apply (rollback). Write-gated. Only the
// path is auditable - content may hold a private key.
func (w *Writer) SafeApplyNetplan(path, content string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpSafeApplyNetplan, NetplanPath: path, NetplanContent: content})
}

func (w *Writer) safeApplyNetplanDirect(path, content string) error {
	clean := filepath.Clean(path)
	if clean != filepath.Join(netplanDir, filepath.Base(clean)) || !strings.HasSuffix(clean, ".yaml") {
		return fmt.Errorf("netplan path must be a *.yaml file directly under %s, got %q", netplanDir, path)
	}
	if content == "" {
		return fmt.Errorf("empty netplan content")
	}

	// Back up the existing file (if any) to a sibling non-.yaml file netplan
	// ignores, so we can roll back. Missing file => no backup, restore = delete.
	backup := clean + ".testudo.bak"
	prev, readErr := os.ReadFile(clean)
	hadPrev := readErr == nil
	if hadPrev {
		if err := os.WriteFile(backup, prev, 0o600); err != nil {
			return fmt.Errorf("backup %s: %w", clean, err)
		}
	}

	restore := func() {
		if hadPrev {
			_ = os.WriteFile(clean, prev, 0o600)
		} else {
			_ = os.Remove(clean)
		}
		_ = netplanRun("apply") // best-effort rollback to the known-good state
	}

	if err := os.WriteFile(clean, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write netplan %s: %w", clean, err)
	}
	if err := netplanGenerate(); err != nil {
		restore()
		return fmt.Errorf("validation failed, rolled back: %w", err)
	}
	if err := netplanRun("apply"); err != nil {
		restore()
		return fmt.Errorf("apply failed, rolled back: %w", err)
	}
	log.Printf("netops audit: netplan safe-apply ok %s", clean)
	return nil
}

// netplanGenerate runs `netplan generate` as a dry-run validation of the YAML.
func netplanGenerate() error { return netplanRun("generate") }

// netplanRun execs `netplan <sub>` with a timeout and surfaces its output.
func netplanRun(sub string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netplan", sub).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("netplan %s: %s", sub, msg)
	}
	return nil
}

// RemoveNetplan deletes a Testudo-managed netplan file and runs `netplan apply`
// (to tear down the interface it defined). Marker-gated: refuses files that lack
// the Testudo marker, so an operator's own netplan is never deleted. Write-gated.
func (w *Writer) RemoveNetplan(path string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpRemoveNetplan, NetplanPath: path})
}

func (w *Writer) removeNetplanDirect(path string) error {
	clean := filepath.Clean(path)
	if clean != filepath.Join(netplanDir, filepath.Base(clean)) || !strings.HasSuffix(clean, ".yaml") {
		return fmt.Errorf("netplan path must be a *.yaml file directly under %s, got %q", netplanDir, path)
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already gone
		}
		return fmt.Errorf("read netplan %s: %w", clean, err)
	}
	if !strings.Contains(string(data), netplanMarker) {
		return fmt.Errorf("refusing to delete non-Testudo netplan %s", clean)
	}
	// Keep a backup so the delete is recoverable, then remove and apply.
	_ = os.WriteFile(clean+".testudo.bak", data, 0o600)
	if err := os.Remove(clean); err != nil {
		return fmt.Errorf("remove netplan %s: %w", clean, err)
	}
	if err := netplanRun("apply"); err != nil {
		// Roll back the delete so we don't leave the system half-changed.
		_ = os.WriteFile(clean, data, 0o600)
		_ = netplanRun("apply")
		return fmt.Errorf("apply after remove failed, restored: %w", err)
	}
	log.Printf("netops audit: removed netplan %s", clean)
	return nil
}

// SyncNetplan rewrites the peers: block of a Testudo-managed netplan file so a
// live peer change persists across reboots / `netplan apply`. It is a no-op when
// the file does not exist or lacks the Testudo marker (an operator's own netplan
// is never touched). The interface block - crucially the private key - is
// preserved verbatim because only the peers section is replaced. Public keys only.
func (w *Writer) SyncNetplan(path string, peers []NetplanPeerWire) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpSyncNetplan, NetplanPath: path, NetplanPeers: peers})
}

func (w *Writer) syncNetplanDirect(path string, peers []NetplanPeerWire) error {
	clean := filepath.Clean(path)
	if clean != filepath.Join(netplanDir, filepath.Base(clean)) || !strings.HasSuffix(clean, ".yaml") {
		return fmt.Errorf("netplan path must be a *.yaml file directly under %s, got %q", netplanDir, path)
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no managed netplan to update
		}
		return fmt.Errorf("read netplan %s: %w", clean, err)
	}
	content := string(data)
	if !strings.Contains(content, netplanMarker) {
		return nil // not a Testudo-managed file - never clobber operator config
	}

	// Keep everything up to the tunnel's `peers:` key (the interface block,
	// including the private key); replace the peers section wholesale. In a
	// Testudo-rendered file the peers block is last, so this is a clean splice.
	lines := strings.Split(content, "\n")
	head := lines
	for i, ln := range lines {
		if strings.TrimRight(ln, " \t") == "      peers:" {
			head = lines[:i]
			break
		}
	}
	for len(head) > 0 && strings.TrimSpace(head[len(head)-1]) == "" {
		head = head[:len(head)-1]
	}

	var b strings.Builder
	b.WriteString(strings.Join(head, "\n"))
	b.WriteString("\n")
	b.WriteString(renderNetplanPeersBlock(peers))
	if err := os.WriteFile(clean, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("write netplan %s: %w", clean, err)
	}
	log.Printf("netops audit: synced netplan peers %s (%d peers)", clean, len(peers))
	return nil
}

// renderNetplanPeersBlock renders the `peers:` YAML subtree (public data only)
// at the indentation Testudo's netplan renderer uses.
func renderNetplanPeersBlock(peers []NetplanPeerWire) string {
	if len(peers) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("      peers:\n")
	for _, p := range peers {
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
	return b.String()
}

// RemoveWGPeer removes the peer with the given public key from the device.
func (w *Writer) RemoveWGPeer(device, peerPubKey string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpWGRemovePeer, WGDevice: device, WGPeerKey: peerPubKey})
}

func (w *Writer) wgRemovePeerDirect(device, peerPubKey string) error {
	if device == "" {
		return fmt.Errorf("wg device name required")
	}
	key, err := wgtypes.ParseKey(peerPubKey)
	if err != nil {
		return fmt.Errorf("parse peer public key: %w", err)
	}
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl new: %w", err)
	}
	defer c.Close()

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}},
	}
	if err := c.ConfigureDevice(device, cfg); err != nil {
		return fmt.Errorf("remove peer on %s: %w", device, err)
	}
	log.Printf("netops audit: wg remove peer dev=%s pub=%s", device, shortKey(peerPubKey))
	return nil
}

// parseAllowedIPs turns "10.0.0.5/32" style strings into net.IPNet, accepting a
// bare address as a host route.
func parseAllowedIPs(cidrs []string) ([]net.IPNet, error) {
	out := make([]net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid allowed-ip %q", s)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed-ip %q: %w", s, err)
		}
		out = append(out, *ipnet)
	}
	return out, nil
}

// shortKey truncates a base64 key for logging so full material never dominates a
// log line (still public, but keeps logs tidy and mirrors the UI's truncation).
func shortKey(k string) string {
	if len(k) <= 10 {
		return k
	}
	return k[:10] + "…"
}

// masqTableName is a dedicated nftables table for Testudo-managed masquerade
// (source-NAT) rules, kept separate from testudo_nat (DNAT) so the two never
// collide and either can be listed/torn down independently.
const masqTableName = "testudo_masq"

// masqKey is the UserData tag round-tripped on each masquerade rule so list and
// delete can match without decoding the expression list.
func masqKey(outIface, srcCIDR string) string {
	return "masq|" + srcCIDR + "|" + outIface
}

// AddMasquerade installs a POSTROUTING masquerade for packets sourced from
// srcCIDR leaving on outIface. This is the source-NAT half of the "Full tunnel"
// WireGuard preset: tunnel peers reach the internet behind the server's WAN IP.
func (w *Writer) AddMasquerade(outIface, srcCIDR string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpAddMasquerade, MasqOutIface: outIface, MasqSrcCIDR: srcCIDR})
}

func (w *Writer) addMasqueradeDirect(outIface, srcCIDR string) error {
	if outIface == "" {
		return fmt.Errorf("masquerade out interface required")
	}
	ip, mask, err := parseCIDROrIP(srcCIDR)
	if err != nil {
		return fmt.Errorf("masquerade src: %w", err)
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   masqTableName,
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	var exprs []expr.Any
	// ip saddr {srcCIDR}
	exprs = append(exprs, &expr.Payload{
		DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4,
	})
	if mask != nil {
		exprs = append(exprs, &expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: mask, Xor: []byte{0, 0, 0, 0},
		})
	}
	exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip})
	// oifname == outIface
	exprs = append(exprs, ifaceMatchExprs(expr.MetaKeyOIFNAME, outIface)...)
	// masquerade
	exprs = append(exprs, &expr.Masq{})

	conn.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    exprs,
		UserData: []byte(masqKey(outIface, srcCIDR)),
	})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush nft: %w", err)
	}
	log.Printf("netops audit: add masquerade src=%s out=%s", srcCIDR, outIface)
	return nil
}

// DelMasquerade removes the masquerade rule matching (outIface, srcCIDR).
func (w *Writer) DelMasquerade(outIface, srcCIDR string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	return w.be().Mutate(Op{Kind: OpDelMasquerade, MasqOutIface: outIface, MasqSrcCIDR: srcCIDR})
}

func (w *Writer) delMasqueradeDirect(outIface, srcCIDR string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	var ours *nftables.Table
	for _, t := range tables {
		if t.Name == masqTableName && t.Family == nftables.TableFamilyIPv4 {
			ours = t
			break
		}
	}
	if ours == nil {
		return nil
	}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	want := masqKey(outIface, srcCIDR)
	for _, c := range chains {
		if c.Table.Name != ours.Name || c.Table.Family != ours.Family {
			continue
		}
		rules, err := conn.GetRules(ours, c)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if string(r.UserData) == want {
				_ = conn.DelRule(r)
				log.Printf("netops audit: del masquerade src=%s out=%s", srcCIDR, outIface)
			}
		}
	}
	return conn.Flush()
}
