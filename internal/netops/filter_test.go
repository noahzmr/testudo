package netops

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestFilterRuleValidate(t *testing.T) {
	ok := []FilterRule{
		{Chain: "input", Action: "accept"},
		{Chain: "input", Action: "drop", Proto: "tcp", Port: 22},
		{Chain: "input", Action: "reject", Proto: "udp", Port: 1000, PortEnd: 2000},
		{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.2/32", DstCIDR: "192.168.1.0/24", CtState: "new"},
		{Chain: "input", Action: "drop", SrcCIDR: "2001:db8::/32", Proto: "icmpv6"},
		{Chain: "input", Action: "accept", Proto: "icmp"},
		{Chain: "input", Action: "log", RateLimit: "10/minute"},
		{Chain: "input", Action: "drop", Proto: "tcp", Port: 22, CtState: "new", RateLimit: "5/minute", RateOver: true},
		{Chain: "INPUT", Action: "ACCEPT", Proto: "TCP", Port: 80}, // normalised
		{Chain: "input", Action: "accept", CtState: "established, related"},
	}
	for _, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: unexpected error %v", r, err)
		}
	}
	bad := []struct {
		r    FilterRule
		want string
	}{
		{FilterRule{Chain: "prerouting", Action: "accept"}, "chain"},
		{FilterRule{Chain: "input", Action: "allow"}, "action"},
		{FilterRule{Chain: "input", Action: "accept", Proto: "sctp"}, "proto"},
		{FilterRule{Chain: "input", Action: "accept", Port: 22}, "port requires"},
		{FilterRule{Chain: "input", Action: "accept", Proto: "icmp", Port: 22}, "port requires"},
		{FilterRule{Chain: "input", Action: "accept", Proto: "tcp", PortEnd: 22}, "port_end requires"},
		{FilterRule{Chain: "input", Action: "accept", Proto: "tcp", Port: 50, PortEnd: 22}, "below"},
		{FilterRule{Chain: "output", Action: "accept", InIface: "eth0"}, "in_iface"},
		{FilterRule{Chain: "input", Action: "accept", OutIface: "eth0"}, "out_iface"},
		{FilterRule{Chain: "input", Action: "accept", SrcCIDR: "nope"}, "src"},
		{FilterRule{Chain: "input", Action: "accept", SrcCIDR: "10.0.0.1", DstCIDR: "2001:db8::1"}, "family"},
		{FilterRule{Chain: "input", Action: "accept", Proto: "icmp", SrcCIDR: "2001:db8::1"}, "icmp is IPv4"},
		{FilterRule{Chain: "input", Action: "accept", Proto: "icmpv6", SrcCIDR: "10.0.0.1"}, "icmpv6 is IPv6"},
		{FilterRule{Chain: "input", Action: "accept", CtState: "bogus"}, "ct_state"},
		{FilterRule{Chain: "input", Action: "accept", RateLimit: "fast"}, "rate_limit"},
		{FilterRule{Chain: "input", Action: "accept", RateLimit: "0/second"}, "rate_limit"},
		{FilterRule{Chain: "input", Action: "accept", RateOver: true}, "rate_over"},
		{FilterRule{Chain: "input", Action: "accept", InIface: "averyveryverylongname"}, "15 characters"},
	}
	for _, tc := range bad {
		err := tc.r.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err = %v, want containing %q", tc.r, err, tc.want)
		}
	}
}

func TestFilterRuleIDStable(t *testing.T) {
	a := FilterRule{Chain: "forward", Action: "accept", SrcCIDR: "10.8.0.5/24", Proto: "TCP", Port: 443, Comment: "x"}
	b := FilterRule{Chain: "FORWARD", Action: "ACCEPT", SrcCIDR: "10.8.0.0/24", Proto: "tcp", Port: 443, Comment: "different comment", Owner: "user"}
	if a.ID() != b.ID() {
		t.Fatalf("normalisation-equivalent rules must share an ID: %s vs %s", a.ID(), b.ID())
	}
	if len(a.ID()) != 12 {
		t.Fatalf("id length = %d, want 12", len(a.ID()))
	}
	c := a
	c.Owner = "wg-peer:abc"
	if c.ID() == a.ID() {
		t.Fatal("owner must be part of the ID")
	}
	d := a
	d.Port = 444
	if d.ID() == a.ID() {
		t.Fatal("match fields must be part of the ID")
	}
	// Normalize drops a redundant PortEnd and sorts ct states.
	n := FilterRule{Chain: "input", Action: "accept", Proto: "tcp", Port: 22, PortEnd: 22, CtState: "related,established"}.Normalize()
	if n.PortEnd != 0 || n.CtState != "established,related" {
		t.Fatalf("normalize: %+v", n)
	}
}

func TestBuildFilterExprsShapes(t *testing.T) {
	// IPv6 source + destination: family gate must be IPv6 and offsets 8/24 len 16.
	ex, err := buildFilterExprs(FilterRule{Chain: "input", Action: "drop", SrcCIDR: "2001:db8::/32", DstCIDR: "2001:db8::1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	gate := ex[1].(*expr.Cmp)
	if gate.Data[0] != unix.NFPROTO_IPV6 {
		t.Fatalf("family gate = %v, want IPv6", gate.Data)
	}
	var offsets []uint32
	for _, e := range ex {
		if p, ok := e.(*expr.Payload); ok {
			offsets = append(offsets, p.Offset)
			if p.Len != 16 {
				t.Fatalf("v6 payload len = %d", p.Len)
			}
		}
	}
	if len(offsets) != 2 || offsets[0] != 8 || offsets[1] != 24 {
		t.Fatalf("v6 offsets = %v", offsets)
	}
	// The CIDR gets a 16-byte mask; the bare address does not.
	masks := 0
	for _, e := range ex {
		if b, ok := e.(*expr.Bitwise); ok {
			masks++
			if b.Len != 16 || len(b.Mask) != 16 {
				t.Fatalf("v6 mask len = %d/%d", b.Len, len(b.Mask))
			}
		}
	}
	if masks != 1 {
		t.Fatalf("masks = %d, want 1", masks)
	}

	// ct state + range + rate limit + log + verdict ordering.
	ex, err = buildFilterExprs(FilterRule{Chain: "input", Action: "drop", Proto: "tcp", Port: 1000, PortEnd: 2000,
		CtState: "new", RateLimit: "5/minute", RateOver: true, Log: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	kinds := exprKinds(ex)
	want := "Ct Bitwise Cmp Meta Cmp Payload Range Limit Counter Log Verdict"
	if kinds != want {
		t.Fatalf("kinds = %q\nwant    %q", kinds, want)
	}
	ct := ex[2].(*expr.Cmp)
	if ct.Op != expr.CmpOpNeq {
		t.Fatal("ct state compare must be != 0")
	}
	rng := ex[6].(*expr.Range)
	if string(rng.FromData) != string(be16(1000)) || string(rng.ToData) != string(be16(2000)) {
		t.Fatalf("range = %v..%v", rng.FromData, rng.ToData)
	}
	lim := ex[7].(*expr.Limit)
	if lim.Rate != 5 || lim.Unit != expr.LimitTimeMinute || !lim.Over {
		t.Fatalf("limit = %+v", lim)
	}
	if v := ex[10].(*expr.Verdict); v.Kind != expr.VerdictDrop {
		t.Fatalf("verdict = %v", v.Kind)
	}

	// reject on tcp -> TCP RST; otherwise ICMPX port-unreachable.
	ex, _ = buildFilterExprs(FilterRule{Chain: "input", Action: "reject", Proto: "tcp", Port: 25}, "")
	if rj := ex[len(ex)-1].(*expr.Reject); rj.Type != unix.NFT_REJECT_TCP_RST {
		t.Fatalf("tcp reject type = %d", rj.Type)
	}
	ex, _ = buildFilterExprs(FilterRule{Chain: "input", Action: "reject", Proto: "udp", Port: 53}, "")
	if rj := ex[len(ex)-1].(*expr.Reject); rj.Type != unix.NFT_REJECT_ICMPX_UNREACH || rj.Code != unix.NFT_REJECT_ICMPX_PORT_UNREACH {
		t.Fatalf("udp reject = %+v", rj)
	}

	// "log" action: limit + counter + log, no verdict; baseline prefix honoured.
	ex, _ = buildFilterExprs(FilterRule{Chain: "forward", Action: "log", RateLimit: "10/minute"}, "fw-drop: ")
	if kinds := exprKinds(ex); kinds != "Limit Counter Log" {
		t.Fatalf("log kinds = %q", kinds)
	}
	if lg := ex[2].(*expr.Log); string(lg.Data) != "fw-drop: " || lg.Key != 1<<unix.NFTA_LOG_PREFIX {
		t.Fatalf("log = %+v", lg)
	}

	// IPv4 with a /24: nfproto gate IPv4, offset 12, 4-byte mask.
	ex, _ = buildFilterExprs(FilterRule{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.0/24"}, "")
	if kinds := exprKinds(ex); kinds != "Meta Cmp Meta Cmp Payload Bitwise Cmp Counter Verdict" {
		t.Fatalf("v4 kinds = %q", kinds)
	}
	if gate := ex[1].(*expr.Cmp); gate.Data[0] != unix.NFPROTO_IPV4 {
		t.Fatal("v4 gate")
	}
	if p := ex[4].(*expr.Payload); p.Offset != 12 || p.Len != 4 {
		t.Fatalf("v4 payload = %+v", p)
	}
}

func exprKinds(ex []expr.Any) string {
	var parts []string
	for _, e := range ex {
		name := strings.TrimPrefix(strings.TrimPrefix(strings.Split(strings.TrimPrefix(
			strings.TrimPrefix(typeName(e), "*"), "expr."), "{")[0], "*"), "expr.")
		parts = append(parts, name)
	}
	return strings.Join(parts, " ")
}

func typeName(v any) string {
	switch v.(type) {
	case *expr.Meta:
		return "Meta"
	case *expr.Cmp:
		return "Cmp"
	case *expr.Payload:
		return "Payload"
	case *expr.Bitwise:
		return "Bitwise"
	case *expr.Ct:
		return "Ct"
	case *expr.Range:
		return "Range"
	case *expr.Limit:
		return "Limit"
	case *expr.Counter:
		return "Counter"
	case *expr.Log:
		return "Log"
	case *expr.Reject:
		return "Reject"
	case *expr.Verdict:
		return "Verdict"
	case *expr.Immediate:
		return "Immediate"
	case *expr.NAT:
		return "NAT"
	case *expr.Masq:
		return "Masq"
	}
	return "?"
}

func TestBaselineAndRenderOrdering(t *testing.T) {
	b := DefaultBaseline()
	b.AllowTCPPorts = []uint16{8080, 22, 22}
	b.AllowUDPPorts = []uint16{51820}
	rules := BaselineRules(b)
	// input: est, invalid, lo, icmp, icmpv6, tcp 22, tcp 8080, udp 51820 ; forward: est, invalid
	var input, forward []FilterRule
	for _, r := range rules {
		if r.Owner != OwnerBaseline {
			t.Fatalf("baseline rule without baseline owner: %+v", r)
		}
		switch r.Chain {
		case "input":
			input = append(input, r)
		case "forward":
			forward = append(forward, r)
		}
	}
	if len(input) != 8 || len(forward) != 2 {
		t.Fatalf("baseline input=%d forward=%d", len(input), len(forward))
	}
	if input[0].CtState != "established,related" || input[5].Port != 22 || input[6].Port != 8080 || input[7].Proto != "udp" {
		t.Fatalf("baseline input order: %v", input)
	}

	user := FilterRule{Chain: "input", Action: "drop", Proto: "tcp", Port: 23}
	spec := FilterTableSpec{Enforce: true, Baseline: b, Rules: []FilterRule{user}}
	all := RenderFilterRules(spec)
	var inputIDs []string
	for _, r := range all {
		if r.Chain == "input" {
			inputIDs = append(inputIDs, r.Action+"/"+r.Owner)
		}
	}
	// baseline x8, then user, then the trailing log rule
	if len(inputIDs) != 10 || inputIDs[8] != "drop/user" || inputIDs[9] != "log/baseline" {
		t.Fatalf("render order: %v", inputIDs)
	}
	pol := ChainPolicies(spec)
	if pol["input"] != "drop" || pol["forward"] != "drop" || pol["output"] != "accept" {
		t.Fatalf("policies = %v", pol)
	}
	spec.Enforce = false
	if n := len(RenderFilterRules(spec)); n != len(rules)+1 {
		t.Fatalf("non-enforce render adds log rules: %d", n)
	}
	if pol := ChainPolicies(spec); pol["input"] != "accept" {
		t.Fatalf("non-enforce policy = %v", pol)
	}
}

func TestManagedUserDataRoundTrip(t *testing.T) {
	r := FilterRule{Chain: "input", Action: "drop", Proto: "tcp", Port: 22, Comment: "no ssh from outside"}
	ud := managedUserData(tagFilter, r.ID(), r.Comment)
	tag, id, comment, ok := parseManagedUserData(ud)
	if !ok || tag != tagFilter || id != r.ID() || comment != r.Comment {
		t.Fatalf("roundtrip: ok=%v tag=%q id=%q comment=%q", ok, tag, id, comment)
	}
	// nft sees a plain comment.
	if c := ruleComment(ud); !strings.HasPrefix(c, "tf1:"+r.ID()) {
		t.Fatalf("ruleComment = %q", c)
	}
	// Overlong comments are truncated to the nftables UserData cap.
	long := managedUserData(tagFilter, r.ID(), strings.Repeat("x", 400))
	if len(long) > maxUserData+2 {
		t.Fatalf("userdata len = %d", len(long))
	}
	if _, id2, _, ok := parseManagedUserData(long); !ok || id2 != r.ID() {
		t.Fatal("truncated userdata must still carry the id")
	}
	// Legacy pipe keys and foreign data are rejected by the managed parser but
	// recovered by the legacy parser.
	if _, _, _, ok := parseManagedUserData([]byte("input|drop|tcp|22||||")); ok {
		t.Fatal("legacy key parsed as managed")
	}
	legacy, ok := parseLegacyRuleKey("forward|accept||0|wg0||10.8.0.2/32|192.168.1.0/24")
	if !ok || legacy.Chain != "forward" || legacy.InIface != "wg0" || legacy.DstCIDR != "192.168.1.0/24" || legacy.Owner != OwnerUser {
		t.Fatalf("legacy = %+v ok=%v", legacy, ok)
	}
	if _, ok := parseLegacyRuleKey("masq|10.8.0.0/24|eth0"); ok {
		t.Fatal("masq key must not parse as a filter rule")
	}
	if _, _, _, ok := parseManagedUserData(nil); ok {
		t.Fatal("empty userdata")
	}
}

func TestNATRoundTrips(t *testing.T) {
	pf := PortForward{Proto: "udp", WANPort: 51820, LANIP: "192.168.1.10", InIface: "eth0"}.Normalize()
	if pf.LANPort != 51820 || pf.Owner != OwnerUser {
		t.Fatalf("normalize: %+v", pf)
	}
	if err := pf.Validate(); err != nil {
		t.Fatal(err)
	}
	got, ok := decodePortForward(&nftables.Rule{Exprs: buildForwardExprs(pf)})
	if !ok || got.Proto != "udp" || got.WANPort != 51820 || got.LANIP != "192.168.1.10" || got.LANPort != 51820 || got.InIface != "eth0" {
		t.Fatalf("forward roundtrip = %+v ok=%v", got, ok)
	}
	if got.Normalize().ID() != pf.ID() {
		t.Fatal("decoded forward must hash to the same ID")
	}
	if err := (PortForward{Proto: "tcp", WANPort: 80, LANIP: "2001:db8::1"}).Validate(); err == nil {
		t.Fatal("IPv6 LAN target must be rejected (v4-only NAT)")
	}
	if err := (PortForward{Proto: "tcp", LANIP: "10.0.0.1"}).Validate(); err == nil {
		t.Fatal("wan_port 0 must be rejected")
	}

	ms := Masquerade{OutIface: "eth0", SrcCIDR: "10.8.0.5/24"}.Normalize()
	if ms.SrcCIDR != "10.8.0.0/24" {
		t.Fatalf("masq normalize = %+v", ms)
	}
	ex, err := buildMasqueradeExprs(ms)
	if err != nil {
		t.Fatal(err)
	}
	if kinds := exprKinds(ex); kinds != "Payload Bitwise Cmp Meta Cmp Counter Masq" {
		t.Fatalf("masq kinds = %q", kinds)
	}
	gotM, ok := decodeMasquerade(&nftables.Rule{Exprs: ex})
	if !ok || gotM.OutIface != "eth0" || gotM.SrcCIDR != "10.8.0.0/24" {
		t.Fatalf("masq roundtrip = %+v ok=%v", gotM, ok)
	}
	if gotM.ID() != ms.ID() {
		t.Fatal("decoded masquerade must hash to the same ID")
	}
	// A DNAT rule is not mistaken for a masquerade and vice versa.
	if _, ok := decodeMasquerade(&nftables.Rule{Exprs: buildForwardExprs(pf)}); ok {
		t.Fatal("forward decoded as masquerade")
	}
	if _, ok := decodePortForward(&nftables.Rule{Exprs: ex}); ok {
		t.Fatal("masquerade decoded as forward")
	}
}

func TestParseRateLimit(t *testing.T) {
	cases := map[string]struct {
		n    uint64
		unit expr.LimitTime
	}{
		"10/second": {10, expr.LimitTimeSecond},
		"5/min":     {5, expr.LimitTimeMinute},
		"100/hour":  {100, expr.LimitTimeHour},
		"3/d":       {3, expr.LimitTimeDay},
	}
	for in, want := range cases {
		n, unit, err := parseRateLimit(in)
		if err != nil || n != want.n || unit != want.unit {
			t.Errorf("%s: %d %d %v", in, n, unit, err)
		}
	}
	for _, bad := range []string{"", "10", "/second", "x/second", "10/fortnight", "0/second"} {
		if _, _, err := parseRateLimit(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestFilterRuleString(t *testing.T) {
	r := FilterRule{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.2/32", DstCIDR: "192.168.1.0/24", Proto: "tcp", Port: 22, CtState: "new"}
	want := "forward ct state new iifname wg0 ip saddr 10.8.0.2/32 ip daddr 192.168.1.0/24 meta l4proto tcp th dport 22 accept"
	if got := r.String(); got != want {
		t.Fatalf("String() = %q\nwant      %q", got, want)
	}
	r6 := FilterRule{Chain: "input", Action: "drop", SrcCIDR: "2001:db8::/32", RateLimit: "5/minute", RateOver: true, Log: true}
	if got := r6.String(); got != "input ip6 saddr 2001:db8::/32 limit rate over 5/minute log drop" {
		t.Fatalf("String() v6 = %q", got)
	}
}
