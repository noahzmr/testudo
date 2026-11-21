package netops

import (
	"encoding/json"
	"fmt"

	"github.com/noahzmr/testudo/internal/nflog"
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
	OpSetMTU           OpKind = "mtu_set"
	OpFlushConntrack   OpKind = "ct_flush"
	OpResetRuleCounter OpKind = "fw_reset_counter"

	// OpListNetplan is a QUERY (not a mutation): it reads every *.yaml under
	// /etc/netplan and returns them. Routed through Backend.Query / OpQuery so it
	// works from the unprivileged engine via the helper.
	OpListNetplan OpKind = "netplan_list"

	// Privileged READS. nf_tables, conntrack and WireGuard netlink dumps all
	// need CAP_NET_ADMIN, which the engine drops after spawning the helper, so
	// every one of these is routed through Backend.Query like netplan_list.
	// Results are JSON; large ones (rule dumps, conntrack tables) span several
	// privsep frames.
	OpQueryFirewallSummary OpKind = "fw_summary" // -> FirewallSummary
	OpQueryFirewallRules   OpKind = "fw_rules"   // -> []RuleInfo
	OpQueryWGDevices       OpKind = "wg_devices" // -> []WGDeviceInfo
	OpQueryConntrack       OpKind = "ct_list"    // CtQuery -> ConntrackResult
)

// Op is a serializable description of one privileged mutation. It is the unit
// the helper protocol carries; the union of fields is small enough to keep in
// one flat struct rather than per-op message types.
type Op struct {
	Kind OpKind `json:"kind"`
	// Actor is the human behind the request (Web UI session user, TUI/CLI
	// login), stamped by Writer.WithActor so the helper's audit row names a
	// person next to the process uid. Never secret material.
	Actor string `json:"actor,omitempty"`
	Name  string `json:"name,omitempty"`  // interface name
	CIDR  string `json:"cidr,omitempty"`  // address
	Iface string `json:"iface,omitempty"` // interface of an address or MTU change
	MTU   int    `json:"mtu,omitempty"`
	// Nft is an nftables ruleset for the nft_* operations. It is large and
	// not secret; audit rows record its size and hash, not the text.
	Nft string `json:"nft,omitempty"`
	// Frr is an FRRouting configuration for the frr_* operations. It can
	// contain session passwords; audit rows record size and hash only.
	Frr     string         `json:"frr,omitempty"`
	Routing *RoutingSpec   `json:"routing,omitempty"`
	WG      *WGSpec        `json:"wg,omitempty"`
	Links   *LinksSpec     `json:"links,omitempty"`
	Proxy   *ProxyRequest  `json:"proxy,omitempty"`
	PAM     *PAMRequest    `json:"pam,omitempty"`
	Daemon  *DaemonRequest `json:"daemon,omitempty"`

	// Firewall counter reset.
	Family string `json:"family,omitempty"`
	Table  string `json:"table,omitempty"`
	Chain  string `json:"chain,omitempty"`
	Handle uint64 `json:"handle,omitempty"`

	Conntrack *ConntrackFlow  `json:"conntrack,omitempty"`
	CtQuery   *ConntrackQuery `json:"ct_query,omitempty"` // filter for OpQueryConntrack

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
	case OpQueryProxyStatus:
		return marshalResult(runProxy(ProxyRequest{Mode: ProxyStatus}))
	case OpQueryDaemonStatus:
		if op.Daemon == nil {
			return nil, fmt.Errorf("daemon status missing request")
		}
		return marshalResult(runDaemon(DaemonRequest{Name: op.Daemon.Name, Mode: DaemonStatus, RunDir: op.Daemon.RunDir, Interface: op.Daemon.Interface}))
	case OpQueryPAMAuth:
		if op.PAM == nil {
			return nil, fmt.Errorf("pam login missing request")
		}
		return marshalResult(runPAM(*op.PAM))
	case OpQueryFirewallSummary:
		return marshalResult(w.listFirewallDirect())
	case OpQueryFirewallRules:
		return marshalResult(w.listFirewallRulesDirect())
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
	case OpSetMTU:
		return w.setMTUDirect(op.Iface, op.MTU)
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
	case OpDaemonControl:
		if op.Daemon == nil || op.Daemon.Mode == DaemonStatus {
			return fmt.Errorf("daemon control missing request")
		}
		_, err := runDaemon(*op.Daemon)
		return err
	case OpProxyControl:
		if op.Proxy == nil || op.Proxy.Mode == ProxyStatus {
			return fmt.Errorf("proxy control missing request")
		}
		_, err := runProxy(*op.Proxy)
		return err
	case OpSyncWG:
		if op.WG == nil {
			return fmt.Errorf("wireguard sync missing spec")
		}
		return w.syncWGDirect(*op.WG)
	case OpSyncLinks:
		if op.Links == nil {
			return fmt.Errorf("links sync missing spec")
		}
		return w.syncLinksDirect(*op.Links)
	case OpSyncRouting:
		if op.Routing == nil {
			return fmt.Errorf("routing sync missing spec")
		}
		return w.syncRoutingDirect(*op.Routing)
	case OpNftApply:
		_, err := runNft(NftRequest{Mode: NftLoad, Ruleset: op.Nft})
		return err
	default:
		return fmt.Errorf("unknown op kind %q", op.Kind)
	}
}

// OpenNFLOG returns a socket bound to the firewall's log group: opened by
// the privileged helper when there is one, in this process otherwise.
func (w *Writer) OpenNFLOG() (int, error) {
	if h, ok := w.be().(*helperBackend); ok {
		_, fd, err := h.client.Call(privsep.OpOpenSocket, []byte(`{"type":"nflog"}`))
		if err == nil && fd < 0 {
			err = fmt.Errorf("the helper returned no socket")
		}
		return fd, err
	}
	return nflog.Open(nflog.Group)
}
