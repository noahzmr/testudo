package netops

import (
	"strings"
	"testing"

	"github.com/google/nftables/expr"
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
