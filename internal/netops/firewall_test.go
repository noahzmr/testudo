package netops

import (
	"testing"

	"github.com/google/nftables/expr"
)

// ifaceBuf builds the 16-byte zero-padded interface-name buffer nftables
// compares iifname/oifname against.
func ifaceBuf(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

func TestDecodeRule(t *testing.T) {
	tests := []struct {
		name        string
		exprs       []expr.Any
		wantMatch   string
		wantVerdict string
	}{
		{
			name: "tcp dport drop",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(22)},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
			wantMatch:   "tcp dport 22",
			wantVerdict: "DROP",
		},
		{
			name: "iif accept",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBuf("eth0")},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			wantMatch:   "iif eth0",
			wantVerdict: "ACCEPT",
		},
		{
			name: "jump",
			exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictJump, Chain: "custom"},
			},
			wantMatch:   "",
			wantVerdict: "JUMP custom",
		},
		{
			name: "reject with icmp",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
				&expr.Reject{Type: 0, Code: 3},
			},
			wantMatch:   "udp",
			wantVerdict: "REJECT",
		},
		{
			name: "log",
			exprs: []expr.Any{
				&expr.Log{},
			},
			wantMatch:   "",
			wantVerdict: "LOG",
		},
		{
			name: "saddr cidr with family gate",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}}, // NFPROTO_IPV4
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 255, 255, 0}, Xor: []byte{0, 0, 0, 0}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 0}},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			wantMatch:   "saddr 10.0.0.0/24",
			wantVerdict: "ACCEPT",
		},
		{
			name: "daddr host and dport",
			exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{192, 168, 1, 10}},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(443)},
				&expr.Verdict{Kind: expr.VerdictReturn},
			},
			wantMatch:   "daddr 192.168.1.10 tcp dport 443",
			wantVerdict: "RETURN",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, verdict := decodeRule(tc.exprs)
			if match != tc.wantMatch {
				t.Errorf("match = %q, want %q", match, tc.wantMatch)
			}
			if verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q", verdict, tc.wantVerdict)
			}
		})
	}
}

func TestRuleCounter(t *testing.T) {
	withCounter := []expr.Any{
		&expr.Counter{Packets: 42, Bytes: 4096},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
	pkts, bytes, ok := ruleCounter(withCounter)
	if !ok || pkts != 42 || bytes != 4096 {
		t.Errorf("ruleCounter = (%d, %d, %v), want (42, 4096, true)", pkts, bytes, ok)
	}

	noCounter := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	if _, _, ok := ruleCounter(noCounter); ok {
		t.Error("ruleCounter on counterless rule = ok, want !ok")
	}
}

func TestSortChainRules(t *testing.T) {
	rules := []RuleInfo{
		{Handle: 1, Verdict: "ACCEPT", HasCounter: true, Packets: 9},  // non-blocking
		{Handle: 2, Verdict: "DROP", HasCounter: true, Packets: 5},    // blocking, low
		{Handle: 3, Verdict: "DROP", HasCounter: true, Packets: 100},  // blocking, high
		{Handle: 4, Verdict: "ACCEPT", HasCounter: true, Packets: 0},  // non-blocking
		{Handle: 5, Verdict: "REJECT", HasCounter: true, Packets: 50}, // blocking, mid
	}
	sortChainRules(rules)

	wantOrder := []uint64{3, 5, 2, 1, 4}
	for i, want := range wantOrder {
		if rules[i].Handle != want {
			t.Errorf("position %d: handle = %d, want %d (full order: %v)", i, rules[i].Handle, want, handles(rules))
		}
	}
}

func handles(rs []RuleInfo) []uint64 {
	out := make([]uint64, len(rs))
	for i, r := range rs {
		out[i] = r.Handle
	}
	return out
}

// TestRuleInfoLegacyRendering documents the contract the UIs rely on: a rule
// without a counter (predates counter attachment, or a foreign rule) reports
// HasCounter=false so renderers can show "—" instead of a misleading 0.
func TestRuleInfoLegacyRendering(t *testing.T) {
	legacy := RuleInfo{Verdict: "DROP", HasCounter: false}
	if legacy.HasCounter {
		t.Fatal("legacy rule should have HasCounter=false")
	}
	if !legacy.IsBlocking() {
		t.Error("DROP rule should be blocking regardless of counter presence")
	}
	if (RuleInfo{Verdict: "ACCEPT"}).IsBlocking() {
		t.Error("ACCEPT must not be blocking")
	}
}

func TestRuleComment(t *testing.T) {
	// A clean TLV: type=0 (comment), len=6, "block\x00".
	ud := []byte{nftRuleCommentType, 6, 'b', 'l', 'o', 'c', 'k', 0}
	if got := ruleComment(ud); got != "block" {
		t.Errorf("ruleComment = %q, want %q", got, "block")
	}
	// Testudo's own pipe-delimited round-trip key is not a TLV comment.
	if got := ruleComment([]byte("input|drop|tcp|22|||")); got != "" {
		t.Errorf("ruleComment on non-TLV userdata = %q, want empty", got)
	}
	if got := ruleComment(nil); got != "" {
		t.Errorf("ruleComment(nil) = %q, want empty", got)
	}
}
