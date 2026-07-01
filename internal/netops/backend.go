package netops

import (
	"encoding/json"
	"fmt"

	"github.com/noahzmr/testudo/internal/privsep"
)

// Backend executes the privileged netlink/nftables mutations behind the Writer.
// Two implementations exist:
//
//   - directBackend runs the operation in-process against the kernel. It is
//     used by the privileged helper (and by legacy single-process / CLI paths
//     that still hold capabilities).
//   - helperBackend forwards the operation to the privileged helper over the
//     privsep socket. It is used by the unprivileged engine/web/TUI.
//
// The whole point of the seam is that Writer's public methods - ListIfaces,
// AddRoute, AddPortForward, etc. - keep their exact signatures. Only the
// backend swaps, so no call site in the TUI, Web UI, collectors, or CLI changes.
type Backend interface {
	Mutate(op Op) error
	// Query performs a privileged READ and returns a JSON result body. Reads that
	// need capabilities/root (e.g. listing 0600 netplan files) route here so the
	// unprivileged engine can reach them via the helper.
	Query(op Op) ([]byte, error)
}

// OpKind names a privileged mutation. The value travels on the wire, so the
// strings are part of the helper protocol and must stay stable.
type OpKind string

const (
	OpSetIfaceUp       OpKind = "iface_up"
	OpSetIfaceDown     OpKind = "iface_down"
	OpAddAddr          OpKind = "addr_add"
	OpDelAddr          OpKind = "addr_del"
	OpFlushAddrs       OpKind = "addr_flush"
	OpSetMTU           OpKind = "mtu_set"
	OpAddRoute         OpKind = "route_add"
	OpAddDefaultRoute  OpKind = "route_add_default"
	OpDelRoute         OpKind = "route_del"
	OpFlushConntrack   OpKind = "ct_flush"
	OpResetRuleCounter OpKind = "fw_reset_counter"
	OpAddFilterRule    OpKind = "filter_add"
	OpDelFilterRule    OpKind = "filter_del"
	OpAddPortForward   OpKind = "nat_add"
	OpDelPortForward   OpKind = "nat_del"

	// WireGuard peer mutations. Only public keys travel on the wire - private
	// and preshared keys never reach the helper protocol (secrets rule).
	OpWGConfigurePeer OpKind = "wg_peer_config"
	OpWGRemovePeer    OpKind = "wg_peer_remove"

	// Masquerade (source NAT) for a WireGuard tunnel pool egressing a WAN
	// interface. Used by the "Full tunnel" firewall preset.
	OpAddMasquerade OpKind = "masq_add"
	OpDelMasquerade OpKind = "masq_del"

	// OpWriteNetplan writes a netplan YAML file for a WireGuard interface. The
	// path is validated to live under /etc/netplan and end in .yaml, and the
	// file is written 0600 (it may contain the interface private key).
	OpWriteNetplan OpKind = "netplan_write"

	// OpSyncNetplan rewrites only the peers: block of a Testudo-managed netplan
	// file so a live peer change persists across reboots. It preserves the
	// interface block (including the private key) and refuses files that lack the
	// Testudo marker, so it can never clobber an operator's own netplan.
	OpSyncNetplan OpKind = "netplan_sync"

	// OpNetplanApply runs `netplan apply` (privileged exec in the helper, like
	// the capture path). A mutation. It runs `netplan generate` first and refuses
	// to apply a YAML that does not render.
	OpNetplanApply OpKind = "netplan_apply"

	// OpSafeApplyNetplan is the transactional write+apply of §2: back up the
	// target file, write the new content, `netplan generate` (validate), `netplan
	// apply`, and on any failure restore the backup and re-apply (rollback).
	OpSafeApplyNetplan OpKind = "netplan_safe_apply"

	// OpRemoveNetplan deletes a Testudo-managed netplan file (marker-gated) and
	// runs `netplan apply`. Used to delete a wg interface Testudo created.
	OpRemoveNetplan OpKind = "netplan_remove"

	// OpSetTxQLen sets an interface's transmit queue length (performance tuning).
	OpSetTxQLen OpKind = "txqlen_set"

	// OpSetSysctl writes a single kernel sysctl. The key is validated against a
	// performance allowlist (net.core.* / net.ipv4.udp_* buffers) so it can never
	// write an arbitrary /proc/sys value.
	OpSetSysctl OpKind = "sysctl_set"

	// OpListNetplan is a QUERY (not a mutation): it reads every *.yaml under
	// /etc/netplan and returns them. Routed through Backend.Query / OpQuery so it
	// works from the unprivileged engine via the helper.
	OpListNetplan OpKind = "netplan_list"
)

// Op is a serializable description of one privileged mutation. It is the unit
// the helper protocol carries; the union of fields is small enough to keep in
// one flat struct rather than per-op message types.
type Op struct {
	Kind    OpKind `json:"kind"`
	Name    string `json:"name,omitempty"`    // interface name
	CIDR    string `json:"cidr,omitempty"`    // address / route destination
	Gateway string `json:"gateway,omitempty"` // route gateway
	Iface   string `json:"iface,omitempty"`   // route outgoing interface
	MTU     int    `json:"mtu,omitempty"`
	TxQLen  int    `json:"txqlen,omitempty"` // interface transmit queue length

	// Sysctl write (performance tuning; key allowlisted).
	SysctlKey string `json:"sysctl_key,omitempty"`
	SysctlVal string `json:"sysctl_val,omitempty"`

	// Firewall counter reset.
	Family string `json:"family,omitempty"`
	Table  string `json:"table,omitempty"`
	Chain  string `json:"chain,omitempty"`
	Handle uint64 `json:"handle,omitempty"`

	// Struct-carrying ops.
	Filter    *FilterRule    `json:"filter,omitempty"`
	PortFwd   *PortForward   `json:"port_forward,omitempty"`
	Conntrack *ConntrackFlow `json:"conntrack,omitempty"`

	// WireGuard peer mutation (public key only).
	WGDevice     string   `json:"wg_device,omitempty"`
	WGPeerKey    string   `json:"wg_peer_key,omitempty"`
	WGAllowedIPs []string `json:"wg_allowed_ips,omitempty"`
	WGEndpoint   string   `json:"wg_endpoint,omitempty"` // host:port; "" leaves it unset
	// WGKeepalive is the persistent-keepalive in seconds: -1 leaves it unchanged,
	// 0 clears it, >0 sets it. Not omitempty so 0 (clear) survives the wire.
	WGKeepalive int `json:"wg_keepalive"`

	// Masquerade source-NAT rule.
	MasqOutIface string `json:"masq_out_iface,omitempty"`
	MasqSrcCIDR  string `json:"masq_src_cidr,omitempty"`

	// Netplan file write (WireGuard interface config). NetplanContent may hold a
	// private key, so it is written 0600 and never echoed to the audit args.
	NetplanPath    string `json:"netplan_path,omitempty"`
	NetplanContent string `json:"netplan_content,omitempty"`

	// Netplan peer-sync (public material only).
	NetplanPeers []NetplanPeerWire `json:"netplan_peers,omitempty"`
}

// NetplanPeerWire is one peer for OpSyncNetplan - public material only.
type NetplanPeerWire struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	Endpoint   string   `json:"endpoint,omitempty"`
	Keepalive  int      `json:"keepalive,omitempty"`
}

// EncodeOp serialises an Op for the helper wire.
func EncodeOp(op Op) ([]byte, error) { return json.Marshal(op) }

// DecodeOp parses an Op from the helper wire.
func DecodeOp(b []byte) (Op, error) {
	var op Op
	err := json.Unmarshal(b, &op)
	return op, err
}

// directBackend runs ops in-process against the kernel.
type directBackend struct{ w *Writer }

func (d directBackend) Mutate(op Op) error          { return d.w.applyDirect(op) }
func (d directBackend) Query(op Op) ([]byte, error) { return d.w.queryDirect(op) }

// helperBackend forwards ops to the privileged helper over the privsep socket.
type helperBackend struct{ client *privsep.Client }

func (h *helperBackend) Mutate(op Op) error {
	body, err := EncodeOp(op)
	if err != nil {
		return fmt.Errorf("encode op: %w", err)
	}
	_, _, err = h.client.Call(privsep.OpMutate, body)
	return err
}

func (h *helperBackend) Query(op Op) ([]byte, error) {
	body, err := EncodeOp(op)
	if err != nil {
		return nil, fmt.Errorf("encode op: %w", err)
	}
	resp, _, err := h.client.Call(privsep.OpQuery, body)
	return resp, err
}

// be returns the Writer's backend, defaulting to a direct one bound to this
// Writer. Defaulting here is what lets existing `&netops.Writer{AllowWrites: x}`
// literals keep working unchanged.
func (w *Writer) be() Backend {
	if w.backend != nil {
		return w.backend
	}
	return directBackend{w}
}

// NewHelperWriter builds a Writer whose mutations are forwarded to the
// privileged helper via client. Reads still run in-process (they need no
// capabilities). allowWrites mirrors the --allow-netops-write gate.
func NewHelperWriter(allowWrites bool, client *privsep.Client) *Writer {
	return &Writer{AllowWrites: allowWrites, backend: &helperBackend{client: client}}
}

// ApplyOp runs op directly against the kernel. The privileged helper calls this
// for each request it receives from the engine.
func (w *Writer) ApplyOp(op Op) error { return w.applyDirect(op) }

// QueryOp runs a read op in-process and returns its JSON result. The privileged
// helper calls this for each OpQuery request it receives.
func (w *Writer) QueryOp(op Op) ([]byte, error) { return w.queryDirect(op) }

// queryDirect dispatches a read Op to the matching in-process implementation.
func (w *Writer) queryDirect(op Op) ([]byte, error) {
	switch op.Kind {
	case OpListNetplan:
		return w.listNetplanDirect()
	default:
		return nil, fmt.Errorf("unknown query kind %q", op.Kind)
	}
}

// applyDirect dispatches an Op to the matching in-process implementation.
func (w *Writer) applyDirect(op Op) error {
	switch op.Kind {
	case OpSetIfaceUp:
		return w.setIfaceUpDirect(op.Name)
	case OpSetIfaceDown:
		return w.setIfaceDownDirect(op.Name)
	case OpAddAddr:
		return w.addAddrDirect(op.Iface, op.CIDR)
	case OpDelAddr:
		return w.delAddrDirect(op.Iface, op.CIDR)
	case OpFlushAddrs:
		return w.flushAddrsDirect(op.Iface)
	case OpSetMTU:
		return w.setMTUDirect(op.Iface, op.MTU)
	case OpAddRoute:
		return w.addRouteDirect(op.CIDR, op.Gateway, op.Iface)
	case OpAddDefaultRoute:
		return w.addDefaultRouteDirect(op.Iface, op.Gateway)
	case OpDelRoute:
		return w.delRouteDirect(op.CIDR)
	case OpFlushConntrack:
		if op.Conntrack == nil {
			return fmt.Errorf("conntrack op missing flow")
		}
		return w.flushConntrackDirect(*op.Conntrack)
	case OpResetRuleCounter:
		return w.resetRuleCounterDirect(op.Family, op.Table, op.Chain, op.Handle)
	case OpAddFilterRule:
		if op.Filter == nil {
			return fmt.Errorf("filter op missing rule")
		}
		return w.addFilterRuleDirect(*op.Filter)
	case OpDelFilterRule:
		if op.Filter == nil {
			return fmt.Errorf("filter op missing rule")
		}
		return w.delFilterRuleDirect(*op.Filter)
	case OpAddPortForward:
		if op.PortFwd == nil {
			return fmt.Errorf("nat op missing port forward")
		}
		return w.addPortForwardDirect(*op.PortFwd)
	case OpDelPortForward:
		return w.delPortForwardDirect(op.Proto(), op.WANPort())
	case OpWGConfigurePeer:
		return w.wgConfigurePeerDirect(op.WGDevice, op.WGPeerKey, op.WGAllowedIPs, op.WGEndpoint, op.WGKeepalive)
	case OpWriteNetplan:
		return w.writeNetplanDirect(op.NetplanPath, op.NetplanContent)
	case OpSyncNetplan:
		return w.syncNetplanDirect(op.NetplanPath, op.NetplanPeers)
	case OpNetplanApply:
		return w.netplanApplyDirect()
	case OpSafeApplyNetplan:
		return w.safeApplyNetplanDirect(op.NetplanPath, op.NetplanContent)
	case OpRemoveNetplan:
		return w.removeNetplanDirect(op.NetplanPath)
	case OpSetTxQLen:
		return w.setTxQLenDirect(op.Iface, op.TxQLen)
	case OpSetSysctl:
		return w.setSysctlDirect(op.SysctlKey, op.SysctlVal)
	case OpWGRemovePeer:
		return w.wgRemovePeerDirect(op.WGDevice, op.WGPeerKey)
	case OpAddMasquerade:
		return w.addMasqueradeDirect(op.MasqOutIface, op.MasqSrcCIDR)
	case OpDelMasquerade:
		return w.delMasqueradeDirect(op.MasqOutIface, op.MasqSrcCIDR)
	default:
		return fmt.Errorf("unknown op kind %q", op.Kind)
	}
}

// Proto / WANPort decode the DelPortForward arguments carried in PortFwd to
// avoid widening the flat Op struct with two more single-use fields.
func (op Op) Proto() string {
	if op.PortFwd != nil {
		return op.PortFwd.Proto
	}
	return ""
}

func (op Op) WANPort() uint16 {
	if op.PortFwd != nil {
		return op.PortFwd.WANPort
	}
	return 0
}
