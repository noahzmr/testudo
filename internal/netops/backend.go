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

	// OpApplyFilterTable / OpApplyNATTable replace the whole testudo_filter /
	// testudo_nat table with the carried spec in one atomic netlink batch. They
	// are the only firewall/NAT mutations: the policy manager (internal/firewall)
	// owns the desired state and re-applies it, so rules are never added or
	// removed one at a time behind its back.
	OpApplyFilterTable OpKind = "filter_apply"
	OpApplyNATTable    OpKind = "nat_apply"

	// WireGuard peer mutations. Only public keys travel on the wire - private
	// and preshared keys never reach the helper protocol (secrets rule).
	OpWGConfigurePeer OpKind = "wg_peer_config"
	OpWGRemovePeer    OpKind = "wg_peer_remove"

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

	// Privileged READS. nf_tables, conntrack and WireGuard netlink dumps all
	// need CAP_NET_ADMIN, which the engine drops after spawning the helper, so
	// every one of these is routed through Backend.Query like netplan_list.
	// Results are JSON; large ones (rule dumps, conntrack tables) span several
	// privsep frames.
	OpQueryFirewallSummary OpKind = "fw_summary"   // -> FirewallSummary
	OpQueryFirewallRules   OpKind = "fw_rules"     // -> []RuleInfo
	OpQueryFilterState     OpKind = "filter_state" // -> FilterTableState
	OpQueryNATState        OpKind = "nat_state"    // -> NATTableState
	OpQueryWGDevices       OpKind = "wg_devices"   // -> []WGDeviceInfo
	OpQueryConntrack       OpKind = "ct_list"      // CtQuery -> ConntrackResult
)

// Op is a serializable description of one privileged mutation. It is the unit
// the helper protocol carries; the union of fields is small enough to keep in
// one flat struct rather than per-op message types.
type Op struct {
	Kind OpKind `json:"kind"`
	// Actor is the human behind the request (Web UI session user, TUI/CLI
	// login), stamped by Writer.WithActor so the helper's audit row names a
	// person next to the process uid. Never secret material.
	Actor   string `json:"actor,omitempty"`
	Name    string `json:"name,omitempty"`    // interface name
	CIDR    string `json:"cidr,omitempty"`    // address / route destination
	Gateway string `json:"gateway,omitempty"` // route gateway
	Iface   string `json:"iface,omitempty"`   // route outgoing interface
	MTU     int    `json:"mtu,omitempty"`
	// Nft is an nftables ruleset for the nft_* operations. It is large and
	// not secret; audit rows record its size and hash, not the text.
	Nft string `json:"nft,omitempty"`
	// Frr is an FRRouting configuration for the frr_* operations. It can
	// contain session passwords; audit rows record size and hash only.
	Frr     string       `json:"frr,omitempty"`
	Routing *RoutingSpec `json:"routing,omitempty"`
	TxQLen  int          `json:"txqlen,omitempty"` // interface transmit queue length

	// Sysctl write (performance tuning; key allowlisted).
	SysctlKey string `json:"sysctl_key,omitempty"`
	SysctlVal string `json:"sysctl_val,omitempty"`

	// Firewall counter reset.
	Family string `json:"family,omitempty"`
	Table  string `json:"table,omitempty"`
	Chain  string `json:"chain,omitempty"`
	Handle uint64 `json:"handle,omitempty"`

	// Struct-carrying ops. The table specs carry the complete desired table;
	// a policy that does not fit privsep.MaxFrame is rejected by the manager.
	FilterSpec *FilterTableSpec `json:"filter_spec,omitempty"`
	NATSpec    *NATSpec         `json:"nat_spec,omitempty"`
	Conntrack  *ConntrackFlow   `json:"conntrack,omitempty"`
	CtQuery    *ConntrackQuery  `json:"ct_query,omitempty"` // filter for OpQueryConntrack

	// WireGuard peer mutation (public key only).
	WGDevice     string   `json:"wg_device,omitempty"`
	WGPeerKey    string   `json:"wg_peer_key,omitempty"`
	WGAllowedIPs []string `json:"wg_allowed_ips,omitempty"`
	WGEndpoint   string   `json:"wg_endpoint,omitempty"` // host:port; "" leaves it unset
	// WGKeepalive is the persistent-keepalive in seconds: -1 leaves it unchanged,
	// 0 clears it, >0 sets it. Not omitempty so 0 (clear) survives the wire.
	WGKeepalive int `json:"wg_keepalive"`

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

// mutate stamps the writer's actor onto op and dispatches it. Every Writer
// mutation goes through here so the audit trail is uniform.
func (w *Writer) mutate(op Op) error {
	op.Actor = w.actor
	return w.be().Mutate(op)
}

// WithActor returns a per-request copy of the writer whose mutations carry the
// given human actor into the helper's audit log. The copy shares the backend
// and the current write gate; it is cheap and meant to be made per request.
func (w *Writer) WithActor(actor string) *Writer {
	if w == nil {
		return nil
	}
	c := *w
	c.actor = actor
	return &c
}

// Actor returns the actor this writer stamps onto mutations ("" = none).
func (w *Writer) Actor() string { return w.actor }

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

// queryDirect dispatches a read Op to the matching in-process implementation
// and returns its JSON encoding.
func (w *Writer) queryDirect(op Op) ([]byte, error) {
	switch op.Kind {
	case OpListNetplan:
		return w.listNetplanDirect()
	case OpQueryNftAvailable, OpQueryNftCheck, OpQueryNftList:
		return nftQueryDirect(op)
	case OpQueryFrrAvailable, OpQueryFrrCheck, OpQueryFrrShow:
		return frrQueryDirect(op)
	case OpQueryFirewallSummary:
		return marshalResult(w.listFirewallDirect())
	case OpQueryFirewallRules:
		return marshalResult(w.listFirewallRulesDirect())
	case OpQueryFilterState:
		return marshalResult(w.filterTableStateDirect())
	case OpQueryNATState:
		return marshalResult(w.natTableStateDirect())
	case OpQueryWGDevices:
		return marshalResult(w.listWGDevicesDirect())
	case OpQueryConntrack:
		var q ConntrackQuery
		if op.CtQuery != nil {
			q = *op.CtQuery
		}
		return marshalResult(w.listConntrackDirect(q))
	default:
		return nil, fmt.Errorf("unknown query kind %q", op.Kind)
	}
}

// marshalResult JSON-encodes a direct read's result unless it failed.
func marshalResult(v any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// queryInto runs a privileged read through the query seam (helper when the
// engine is unprivileged, in-process otherwise) and decodes the result.
func (w *Writer) queryInto(op Op, out any) error {
	body, err := w.be().Query(op)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s result: %w", op.Kind, err)
	}
	return nil
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
	case OpFrrReload:
		_, err := runFrr(FrrRequest{Mode: FrrReload, Conf: op.Frr})
		return err
	case OpSyncRouting:
		if op.Routing == nil {
			return fmt.Errorf("routing sync missing spec")
		}
		return w.syncRoutingDirect(*op.Routing)
	case OpNftApply:
		_, err := runNft(NftRequest{Mode: NftLoad, Ruleset: op.Nft})
		return err
	case OpApplyFilterTable:
		if op.FilterSpec == nil {
			return fmt.Errorf("filter apply missing spec")
		}
		return w.applyFilterTableDirect(*op.FilterSpec)
	case OpApplyNATTable:
		if op.NATSpec == nil {
			return fmt.Errorf("nat apply missing spec")
		}
		return w.applyNATTableDirect(*op.NATSpec)
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
	default:
		return fmt.Errorf("unknown op kind %q", op.Kind)
	}
}
