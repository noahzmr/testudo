package netops

import (
	"testing"
)

// TestOpCodecRoundTrip checks that every op kind survives encode/decode so the
// helper protocol stays in lockstep with the Writer methods that emit ops.
func TestOpCodecRoundTrip(t *testing.T) {
	cases := []Op{
		{Kind: OpSetIfaceUp, Name: "eth0"},
		{Kind: OpSetIfaceDown, Name: "wg0"},
		{Kind: OpAddAddr, Iface: "eth0", CIDR: "192.168.1.5/24"},
		{Kind: OpDelAddr, Iface: "eth0", CIDR: "192.168.1.5/24"},
		{Kind: OpFlushAddrs, Iface: "eth0"},
		{Kind: OpSetMTU, Iface: "eth0", MTU: 1400},
		{Kind: OpAddRoute, CIDR: "10.0.0.0/24", Gateway: "192.168.1.1", Iface: "eth0"},
		{Kind: OpAddDefaultRoute, Iface: "eth0", Gateway: "192.168.1.1"},
		{Kind: OpDelRoute, CIDR: "10.0.0.0/24"},
		{Kind: OpResetRuleCounter, Family: "inet", Table: "filter", Chain: "input", Handle: 42},
		{Kind: OpFlushConntrack, Conntrack: &ConntrackFlow{Proto: "tcp", OrigSrc: "1.2.3.4", OrigDst: "5.6.7.8", OrigSport: 1000, OrigDport: 443}},
		{Kind: OpAddFilterRule, Filter: &FilterRule{Chain: "input", Action: "drop", Proto: "tcp", Port: 22}},
		{Kind: OpDelFilterRule, Filter: &FilterRule{Chain: "input", Action: "drop", Proto: "tcp", Port: 22}},
		{Kind: OpAddPortForward, PortFwd: &PortForward{Proto: "tcp", WANPort: 443, LANIP: "192.168.1.10", LANPort: 443}},
		{Kind: OpDelPortForward, PortFwd: &PortForward{Proto: "tcp", WANPort: 443}},
	}
	for _, op := range cases {
		t.Run(string(op.Kind), func(t *testing.T) {
			b, err := EncodeOp(op)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := DecodeOp(b)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.Kind != op.Kind {
				t.Fatalf("kind = %q, want %q", got.Kind, op.Kind)
			}
			// Spot-check the struct-carrying ops survived intact.
			switch op.Kind {
			case OpAddPortForward:
				if got.PortFwd == nil || got.PortFwd.LANIP != "192.168.1.10" {
					t.Fatalf("port forward lost: %+v", got.PortFwd)
				}
			case OpFlushConntrack:
				if got.Conntrack == nil || got.Conntrack.OrigDport != 443 {
					t.Fatalf("conntrack lost: %+v", got.Conntrack)
				}
			case OpAddFilterRule:
				if got.Filter == nil || got.Filter.Port != 22 {
					t.Fatalf("filter lost: %+v", got.Filter)
				}
			case OpDelPortForward:
				if got.Proto() != "tcp" || got.WANPort() != 443 {
					t.Fatalf("del-pf args lost: proto=%q wan=%d", got.Proto(), got.WANPort())
				}
			}
		})
	}
}

// TestDefaultBackendIsDirect verifies a zero-value Writer (the common literal
// `&netops.Writer{AllowWrites: x}`) resolves to a direct backend so existing
// call sites keep running in-process.
func TestDefaultBackendIsDirect(t *testing.T) {
	w := &Writer{AllowWrites: true}
	if _, ok := w.be().(directBackend); !ok {
		t.Fatalf("default backend = %T, want directBackend", w.be())
	}
}

// TestWritesGateBeforeBackend confirms the AllowWrites gate short-circuits
// before any backend dispatch, so a writes-disabled Writer never forwards.
func TestWritesGateBeforeBackend(t *testing.T) {
	w := &Writer{AllowWrites: false, backend: panicBackend{}}
	if err := w.AddRoute("10.0.0.0/24", "", "eth0"); err != ErrWritesDisabled {
		t.Fatalf("err = %v, want ErrWritesDisabled", err)
	}
}

type panicBackend struct{}

func (panicBackend) Mutate(Op) error { panic("backend must not be reached when writes are disabled") }
