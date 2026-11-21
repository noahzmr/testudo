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
		{Kind: OpSetMTU, Iface: "eth0", MTU: 1400},
		{Kind: OpResetRuleCounter, Family: "inet", Table: "filter", Chain: "input", Handle: 42},
		{Kind: OpFlushConntrack, Conntrack: &ConntrackFlow{Proto: "tcp", OrigSrc: "1.2.3.4", OrigDst: "5.6.7.8", OrigSport: 1000, OrigDport: 443}},
		{Kind: OpNftApply, Nft: "table inet testudo {}\n"},
		{Kind: OpQueryFirewallSummary},
		{Kind: OpQueryFirewallRules},
		{Kind: OpQueryWGDevices},
		{Kind: OpQueryConntrack, CtQuery: &ConntrackQuery{SrcIPs: []string{"10.8.0.2"}, DstCIDR: "10.1.0.0/24", Limit: 50}},
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
			case OpNftApply:
				if got.Nft != op.Nft {
					t.Fatalf("ruleset lost: %q", got.Nft)
				}
			case OpFlushConntrack:
				if got.Conntrack == nil || got.Conntrack.OrigDport != 443 {
					t.Fatalf("conntrack lost: %+v", got.Conntrack)
				}
			case OpQueryConntrack:
				if got.CtQuery == nil || got.CtQuery.Limit != 50 || got.CtQuery.DstCIDR != "10.1.0.0/24" || len(got.CtQuery.SrcIPs) != 1 {
					t.Fatalf("conntrack query lost: %+v", got.CtQuery)
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
	if err := w.SetMTU("eth0", 1400); err != ErrWritesDisabled {
		t.Fatalf("err = %v, want ErrWritesDisabled", err)
	}
}

type panicBackend struct{}

func (panicBackend) Mutate(Op) error { panic("backend must not be reached when writes are disabled") }
func (panicBackend) Query(Op) ([]byte, error) {
	panic("backend must not be reached when writes are disabled")
}
