package netops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables/expr"
)

// Rule ownership tags. Owner lets a subsystem tear down exactly the rules it
// created (WireGuard peer presets, PAM grants) without re-deriving them from
// current settings. Rules the operator adds by hand carry OwnerUser; rules the
// baseline renders carry OwnerBaseline and are never persisted as user rules.
const (
	OwnerUser     = "user"
	OwnerBaseline = "baseline"
)

// FilterRule is one rule of the old firewall policy file, read once to move
// it into the model.
//
// Every field except Chain and Action is optional - empty means "any".
// Chain is one of "input", "output", "forward". Action is "accept", "drop",
// "reject" or "log" (log matching packets and continue). IP fields accept a
// bare address or a CIDR in either family; a rule may not mix families.
// CtState is a comma-separated subset of new / established / related /
// invalid / untracked. RateLimit is "N/second|minute|hour|day"; with RateOver
// the rule matches only packets *above* the rate (brute-force style).
type FilterRule struct {
	Chain     string `json:"chain"`
	Action    string `json:"action"`
	Proto     string `json:"proto"`              // "" / tcp / udp / icmp / icmpv6
	Port      uint16 `json:"port"`               // destination port, 0 = any
	PortEnd   uint16 `json:"port_end,omitempty"` // inclusive range end, 0 = single port
	InIface   string `json:"in_iface"`           // iifname (input / forward only)
	OutIface  string `json:"out_iface"`          // oifname (output / forward only)
	SrcCIDR   string `json:"src"`                // source IPv4/IPv6 address or CIDR
	DstCIDR   string `json:"dst"`                // destination IPv4/IPv6 address or CIDR
	CtState   string `json:"ct_state,omitempty"`
	Log       bool   `json:"log,omitempty"`        // log before the verdict (rate-limited by RateLimit if set)
	RateLimit string `json:"rate_limit,omitempty"` // "10/minute"
	RateOver  bool   `json:"rate_over,omitempty"`  // match packets over the rate instead of under it
	Comment   string `json:"comment,omitempty"`
	Owner     string `json:"owner,omitempty"` // ownership tag, see OwnerUser
}

// Normalize returns a canonical copy: lower-cased keywords, trimmed fields,
// CIDRs reduced to their network address, a defaulted owner. Rule identity
// (ID) is computed over the normalized form so "10.0.0.5/24" and
// "10.0.0.0/24" are the same rule.
func (fr FilterRule) Normalize() FilterRule {
	n := fr
	n.Chain = strings.ToLower(strings.TrimSpace(n.Chain))
	n.Action = strings.ToLower(strings.TrimSpace(n.Action))
	n.Proto = strings.ToLower(strings.TrimSpace(n.Proto))
	n.InIface = strings.TrimSpace(n.InIface)
	n.OutIface = strings.TrimSpace(n.OutIface)
	n.SrcCIDR = canonicalCIDR(n.SrcCIDR)
	n.DstCIDR = canonicalCIDR(n.DstCIDR)
	n.CtState = canonicalCtState(n.CtState)
	n.RateLimit = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(n.RateLimit), " ", ""))
	n.Comment = strings.TrimSpace(n.Comment)
	n.Owner = strings.TrimSpace(n.Owner)
	if n.Owner == "" {
		n.Owner = OwnerUser
	}
	if n.PortEnd == n.Port {
		n.PortEnd = 0
	}
	return n
}

// ID is a stable content hash of the normalized rule (12 hex chars). It is the
// join key between the persisted policy and the live kernel table: the kernel
// rule carries only the ID in its UserData, never the full rule.
func (fr FilterRule) ID() string {
	n := fr.Normalize()
	h := sha256.Sum256([]byte(strings.Join([]string{
		"tf1", n.Chain, n.Action, n.Proto,
		strconv.Itoa(int(n.Port)), strconv.Itoa(int(n.PortEnd)),
		n.InIface, n.OutIface, n.SrcCIDR, n.DstCIDR, n.CtState,
		strconv.FormatBool(n.Log), n.RateLimit, strconv.FormatBool(n.RateOver),
		n.Owner,
	}, "\x00")))
	return hex.EncodeToString(h[:6])
}

// String renders the rule nft-style on one line, e.g.
// "forward iifname wg0 ip saddr 10.8.0.2/32 ct state new accept".
func (fr FilterRule) String() string {
	n := fr.Normalize()
	var b strings.Builder
	b.WriteString(n.Chain)
	if n.CtState != "" {
		b.WriteString(" ct state " + n.CtState)
	}
	if n.InIface != "" {
		b.WriteString(" iifname " + n.InIface)
	}
	if n.OutIface != "" {
		b.WriteString(" oifname " + n.OutIface)
	}
	fam := n.family()
	if n.SrcCIDR != "" {
		b.WriteString(" " + fam + " saddr " + n.SrcCIDR)
	}
	if n.DstCIDR != "" {
		b.WriteString(" " + fam + " daddr " + n.DstCIDR)
	}
	if n.Proto != "" {
		b.WriteString(" meta l4proto " + n.Proto)
	}
	if n.Port != 0 {
		if n.PortEnd != 0 {
			fmt.Fprintf(&b, " th dport %d-%d", n.Port, n.PortEnd)
		} else {
			fmt.Fprintf(&b, " th dport %d", n.Port)
		}
	}
	if n.RateLimit != "" {
		b.WriteString(" limit rate ")
		if n.RateOver {
			b.WriteString("over ")
		}
		b.WriteString(n.RateLimit)
	}
	if n.Log && n.Action != "log" {
		b.WriteString(" log")
	}
	b.WriteString(" " + n.Action)
	return b.String()
}

// family returns "ip" or "ip6" from the address fields ("ip" when none set).
func (fr FilterRule) family() string {
	for _, s := range []string{fr.SrcCIDR, fr.DstCIDR} {
		if s == "" {
			continue
		}
		if ip, _, err := parseCIDROrIP(s); err == nil && len(ip) == net.IPv6len {
			return "ip6"
		}
	}
	return "ip"
}

// Validate guards against wrong combinations before anything touches netlink.
func (fr FilterRule) Validate() error {
	n := fr.Normalize()
	switch n.Chain {
	case "input", "output", "forward":
	default:
		return fmt.Errorf("chain must be input / output / forward, got %q", fr.Chain)
	}
	switch n.Action {
	case "accept", "drop", "reject", "log":
	default:
		return fmt.Errorf("action must be accept / drop / reject / log, got %q", fr.Action)
	}
	switch n.Proto {
	case "", "tcp", "udp", "icmp", "icmpv6":
	default:
		return fmt.Errorf("proto must be tcp / udp / icmp / icmpv6 / empty, got %q", fr.Proto)
	}
	if n.Port != 0 && n.Proto != "tcp" && n.Proto != "udp" {
		return fmt.Errorf("port requires a proto (tcp or udp)")
	}
	if n.PortEnd != 0 && n.Port == 0 {
		return fmt.Errorf("port_end requires port")
	}
	if n.PortEnd != 0 && n.PortEnd < n.Port {
		return fmt.Errorf("port_end %d is below port %d", n.PortEnd, n.Port)
	}
	if n.InIface != "" && n.Chain == "output" {
		return fmt.Errorf("in_iface has no effect on the output chain")
	}
	if n.OutIface != "" && n.Chain == "input" {
		return fmt.Errorf("out_iface has no effect on the input chain")
	}
	if len(n.InIface) > 15 || len(n.OutIface) > 15 {
		return fmt.Errorf("interface names are at most 15 characters")
	}
	var srcV6, dstV6, haveSrc, haveDst bool
	if n.SrcCIDR != "" {
		ip, _, err := parseCIDROrIP(n.SrcCIDR)
		if err != nil {
			return fmt.Errorf("src: %w", err)
		}
		haveSrc, srcV6 = true, len(ip) == net.IPv6len
	}
	if n.DstCIDR != "" {
		ip, _, err := parseCIDROrIP(n.DstCIDR)
		if err != nil {
			return fmt.Errorf("dst: %w", err)
		}
		haveDst, dstV6 = true, len(ip) == net.IPv6len
	}
	if haveSrc && haveDst && srcV6 != dstV6 {
		return fmt.Errorf("src and dst must be the same address family")
	}
	v6 := (haveSrc && srcV6) || (haveDst && dstV6)
	v4 := (haveSrc && !srcV6) || (haveDst && !dstV6)
	if n.Proto == "icmp" && v6 {
		return fmt.Errorf("icmp is IPv4-only; use icmpv6 with IPv6 addresses")
	}
	if n.Proto == "icmpv6" && v4 {
		return fmt.Errorf("icmpv6 is IPv6-only; use icmp with IPv4 addresses")
	}
	if n.CtState != "" {
		for _, tok := range strings.Split(n.CtState, ",") {
			switch tok {
			case "new", "established", "related", "invalid", "untracked":
			default:
				return fmt.Errorf("ct_state: unknown state %q", tok)
			}
		}
	}
	if n.RateLimit != "" {
		if _, _, err := parseRateLimit(n.RateLimit); err != nil {
			return fmt.Errorf("rate_limit: %w", err)
		}
	}
	if n.RateOver && n.RateLimit == "" {
		return fmt.Errorf("rate_over requires rate_limit")
	}
	if len(n.Comment) > 200 {
		return fmt.Errorf("comment is at most 200 characters")
	}
	if strings.ContainsAny(n.Owner, " \t\n") {
		return fmt.Errorf("owner must not contain whitespace")
	}
	return nil
}

// FilterBaseline is the set of always-on rules a default-deny firewall needs
// to stay reachable and stateful. Rendered first in each chain, before user
// rules, whenever ApplyFilterTable runs. The manager merges the ports it knows
// it must protect (Web UI listen port, SSH) into AllowTCPPorts so enabling
// Enforce can never cut the operator's own session.
type FilterBaseline struct {
	AllowEstablished bool     `json:"allow_established"` // ct state established,related accept (input + forward)
	DropInvalid      bool     `json:"drop_invalid"`      // ct state invalid drop (input + forward)
	AllowLoopback    bool     `json:"allow_loopback"`    // iifname lo accept
	AllowICMP        bool     `json:"allow_icmp"`        // icmp + icmpv6 accept on input
	AllowTCPPorts    []uint16 `json:"allow_tcp_ports,omitempty"`
	AllowUDPPorts    []uint16 `json:"allow_udp_ports,omitempty"`
	LogDrops         bool     `json:"log_drops"`            // rate-limited log before the chain policy drop
	LogPrefix        string   `json:"log_prefix,omitempty"` // kernel log prefix; default "testudo-drop: "
}

// DefaultBaseline is the baseline a fresh policy starts with. It is the
// textbook stateful-firewall preamble; SSH is included because losing the
// box is the one firewall mistake that cannot be fixed remotely.
func DefaultBaseline() FilterBaseline {
	return FilterBaseline{
		AllowEstablished: true,
		DropInvalid:      true,
		AllowLoopback:    true,
		AllowICMP:        true,
		AllowTCPPorts:    []uint16{22},
		LogDrops:         true,
	}
}

// FilterTableSpec is the complete desired content of the testudo_filter table.
// ApplyFilterTable rebuilds the table from it atomically; nothing is ever
// added or removed incrementally.
type FilterTableSpec struct {
	// Enforce sets the input and forward chain policies to drop (output stays
	// accept). With Enforce false the chains are default-accept and the table
	// behaves like a plain allow/deny list.
	Enforce  bool           `json:"enforce"`
	Baseline FilterBaseline `json:"baseline"`
	Rules    []FilterRule   `json:"rules"` // ordered; per chain, rendered after the baseline
}

// BaselineRules renders the baseline into ordinary rules (Owner =
// OwnerBaseline) so the kernel table, the drift check and the UI all see the
// same thing. Deterministic: same baseline, same rules, same IDs.
func BaselineRules(b FilterBaseline) []FilterRule {
	var out []FilterRule
	for _, chain := range []string{"input", "forward"} {
		if b.AllowEstablished {
			out = append(out, FilterRule{Chain: chain, Action: "accept", CtState: "established,related",
				Comment: "baseline: established/related", Owner: OwnerBaseline})
		}
		if b.DropInvalid {
			out = append(out, FilterRule{Chain: chain, Action: "drop", CtState: "invalid",
				Comment: "baseline: invalid", Owner: OwnerBaseline})
		}
	}
	if b.AllowLoopback {
		out = append(out, FilterRule{Chain: "input", Action: "accept", InIface: "lo",
			Comment: "baseline: loopback", Owner: OwnerBaseline})
	}
	if b.AllowICMP {
		out = append(out,
			FilterRule{Chain: "input", Action: "accept", Proto: "icmp", Comment: "baseline: icmp", Owner: OwnerBaseline},
			FilterRule{Chain: "input", Action: "accept", Proto: "icmpv6", Comment: "baseline: icmpv6", Owner: OwnerBaseline},
		)
	}
	for _, p := range sortedPorts(b.AllowTCPPorts) {
		out = append(out, FilterRule{Chain: "input", Action: "accept", Proto: "tcp", Port: p,
			Comment: "baseline: management port", Owner: OwnerBaseline})
	}
	for _, p := range sortedPorts(b.AllowUDPPorts) {
		out = append(out, FilterRule{Chain: "input", Action: "accept", Proto: "udp", Port: p,
			Comment: "baseline: management port", Owner: OwnerBaseline})
	}
	return out
}

// WritesAllowed reports the --allow-netops-write gate, so policy-layer callers
// can tell "refused" from "failed" without attempting a mutation.
func (w *Writer) WritesAllowed() bool { return w.AllowWrites }

// Tags of the IDs of the old policy's NAT entries.
const (
	tagForward    = "tn1"
	tagMasquerade = "tm1"
)

// ---- expression building ----------------------------------------------

// ifaceMatchExprs returns the nftables expressions that compare iifname or
// oifname (depending on key) to a 16-byte zero-padded name buffer.
func ifaceMatchExprs(key expr.MetaKey, name string) []expr.Any {
	buf := make([]byte, 16)
	copy(buf, []byte(name))
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: buf},
	}
}

// addrMatchExprs matches the source (src=true) or destination address in
// either family. The network-header offsets are 12/16 (IPv4) and 8/24 (IPv6);
// a CIDR inserts a Bitwise mask between the Payload load and the Cmp.
func addrMatchExprs(src bool, addr string) ([]expr.Any, error) {
	ip, mask, err := parseCIDROrIP(addr)
	if err != nil {
		return nil, err
	}
	var offset uint32
	switch {
	case len(ip) == net.IPv4len && src:
		offset = 12
	case len(ip) == net.IPv4len:
		offset = 16
	case src:
		offset = 8
	default:
		offset = 24
	}
	out := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(ip))},
	}
	if mask != nil {
		out = append(out, &expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: uint32(len(ip)),
			Mask: mask, Xor: make([]byte, len(ip)),
		})
	}
	out = append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip})
	return out, nil
}

// parseCIDROrIP accepts a bare address or a CIDR in either family and returns
// the address bytes (4 or 16) plus the mask (nil for a bare address).
func parseCIDROrIP(s string) (ip []byte, mask []byte, err error) {
	if strings.Contains(s, "/") {
		_, ipnet, perr := net.ParseCIDR(s)
		if perr != nil {
			return nil, nil, perr
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil {
			return []byte(ip4), []byte(ipnet.Mask), nil
		}
		return []byte(ipnet.IP.To16()), []byte(ipnet.Mask), nil
	}
	raw := net.ParseIP(s)
	if raw == nil {
		return nil, nil, fmt.Errorf("not an IP address: %s", s)
	}
	if ip4 := raw.To4(); ip4 != nil {
		return []byte(ip4), nil, nil
	}
	return []byte(raw.To16()), nil, nil
}

// canonicalCIDR reduces "10.0.0.5/24" to "10.0.0.0/24" and lower-cases IPv6;
// bare addresses are returned in their canonical textual form. Unparseable
// input is returned trimmed so Validate can report it.
func canonicalCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "/") {
		if _, ipnet, err := net.ParseCIDR(s); err == nil {
			return ipnet.String()
		}
		return s
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// canonicalCtState lower-cases, de-dupes and sorts the state list.
func canonicalCtState(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, " ", ""))
	if s == "" {
		return ""
	}
	seen := map[string]bool{}
	var toks []string
	for _, t := range strings.Split(s, ",") {
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		toks = append(toks, t)
	}
	sort.Strings(toks)
	return strings.Join(toks, ",")
}

// parseRateLimit parses "N/unit" into a packet rate and nftables time unit.
func parseRateLimit(s string) (uint64, expr.LimitTime, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("want N/second|minute|hour|day, got %q", s)
	}
	n, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || n == 0 {
		return 0, 0, fmt.Errorf("rate must be a positive integer, got %q", parts[0])
	}
	switch parts[1] {
	case "s", "sec", "second":
		return n, expr.LimitTimeSecond, nil
	case "m", "min", "minute":
		return n, expr.LimitTimeMinute, nil
	case "h", "hour":
		return n, expr.LimitTimeHour, nil
	case "d", "day":
		return n, expr.LimitTimeDay, nil
	}
	return 0, 0, fmt.Errorf("unknown unit %q (second / minute / hour / day)", parts[1])
}

func sortedPorts(ps []uint16) []uint16 {
	out := make([]uint16, 0, len(ps))
	seen := map[uint16]bool{}
	for _, p := range ps {
		if p == 0 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
