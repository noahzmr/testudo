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

	// Firewall counter reset.
	Family string `json:"family,omitempty"`
	Table  string `json:"table,omitempty"`
	Chain  string `json:"chain,omitempty"`
	Handle uint64 `json:"handle,omitempty"`

	// Struct-carrying ops.
	Filter    *FilterRule    `json:"filter,omitempty"`
	PortFwd   *PortForward   `json:"port_forward,omitempty"`
	Conntrack *ConntrackFlow `json:"conntrack,omitempty"`
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

func (d directBackend) Mutate(op Op) error { return d.w.applyDirect(op) }

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
