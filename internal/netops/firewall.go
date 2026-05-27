package netops

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// FirewallSummary describes one nftables table/chain pair, plus a per-rule
// hit/byte counter snapshot. We don't attempt to fully render nftables
// expressions - that's an entire DSL - just the operational telemetry that
// matters to most operators (rule counters and chain hook info).
type FirewallSummary struct {
	Tables []TableInfo
}

type TableInfo struct {
	Family string // ip / ip6 / inet / arp / bridge / netdev
	Name   string
	Chains []ChainInfo
}

type ChainInfo struct {
	Name     string
	Hook     string
	Priority string
	Type     string
	Rules    int
	Packets  uint64
	Bytes    uint64
}

// ListFirewall enumerates nftables tables and chains, tallying rules and
// summed counter packets/bytes per chain. Returns an empty summary on
// systems without nftables loaded.
func (w *Writer) ListFirewall() (FirewallSummary, error) {
	conn, err := nftables.New()
	if err != nil {
		return FirewallSummary{}, fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	tables, err := conn.ListTables()
	if err != nil {
		return FirewallSummary{}, fmt.Errorf("list tables: %w", err)
	}
	out := FirewallSummary{}
	for _, t := range tables {
		tinfo := TableInfo{
			Family: familyName(t.Family),
			Name:   t.Name,
		}
		chains, err := conn.ListChains()
		if err != nil {
			continue
		}
		for _, c := range chains {
			if c.Table.Name != t.Name || c.Table.Family != t.Family {
				continue
			}
			cinfo := ChainInfo{Name: c.Name}
			if c.Hooknum != nil {
				cinfo.Hook = hookName(*c.Hooknum)
			}
			if c.Priority != nil {
				cinfo.Priority = fmt.Sprintf("%d", *c.Priority)
			}
			cinfo.Type = string(c.Type)
			rules, err := conn.GetRules(t, c)
			if err == nil {
				cinfo.Rules = len(rules)
			}
			tinfo.Chains = append(tinfo.Chains, cinfo)
		}
		out.Tables = append(out.Tables, tinfo)
	}
	return out, nil
}

// RuleInfo is one decoded firewall rule with live counters. It turns the
// firewall view from "chain totals" into "which rule fired" - the operator
// can see the exact rule dropping traffic, not just that a chain dropped
// something.
type RuleInfo struct {
	Family     string // ip / ip6 / inet
	Table      string
	Chain      string
	Handle     uint64 // nftables rule handle (stable id for reset/delete)
	Match      string // decoded: "tcp dport 22 iif eth0"
	Verdict    string // ACCEPT / DROP / REJECT / LOG / JUMP <chain> / RETURN
	Comment    string // nft comment expr, if present
	Packets    uint64
	Bytes      uint64
	HasCounter bool // false = rule predates counter attachment
}

// IsBlocking reports whether the rule's verdict actively denies traffic.
// DROP / REJECT velocity is the "what's blocking me" signal that floats
// these rules to the top of the diagnostic view and feeds Network Quality.
func (r RuleInfo) IsBlocking() bool {
	switch r.Verdict {
	case "DROP", "REJECT":
		return true
	}
	return false
}

// ListFirewallRules walks every table/chain and decodes each rule into a
// RuleInfo with per-rule packet/byte counters. Rules within a chain are
// ordered diagnostically: the highest-hit DROP/REJECT rules float to the
// top (see sortChainRules). Returns an empty slice on systems without
// nftables loaded; soft-fails per-table like ListFirewall.
func (w *Writer) ListFirewallRules() ([]RuleInfo, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("list chains: %w", err)
	}

	var out []RuleInfo
	for _, t := range tables {
		for _, c := range chains {
			if c.Table.Name != t.Name || c.Table.Family != t.Family {
				continue
			}
			rules, err := conn.GetRules(t, c)
			if err != nil {
				continue // soft-fail per chain
			}
			chainRules := make([]RuleInfo, 0, len(rules))
			for _, r := range rules {
				ri := RuleInfo{
					Family: familyName(t.Family),
					Table:  t.Name,
					Chain:  c.Name,
					Handle: r.Handle,
				}
				ri.Match, ri.Verdict = decodeRule(r.Exprs)
				if pkts, bytes, ok := ruleCounter(r.Exprs); ok {
					ri.Packets, ri.Bytes, ri.HasCounter = pkts, bytes, true
				}
				ri.Comment = ruleComment(r.UserData)
				chainRules = append(chainRules, ri)
			}
			sortChainRules(chainRules)
			out = append(out, chainRules...)
		}
	}
	return out, nil
}

// ResetRuleCounter zeroes the packet/byte counter on a single rule,
// identified by its (family, table, chain, handle) tuple. nftables has no
// in-place counter-zero, so we replace the rule's counter expression with a
// fresh zeroed one via NLM_F_REPLACE - which preserves the rule's position
// and handle, unlike a delete+re-add. Gated by AllowWrites and audit-logged
// (handle + before/after counters), same as every other netops mutation.
func (w *Writer) ResetRuleCounter(family, table, chain string, handle uint64) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	fam, ok := parseFamily(family)
	if !ok {
		return fmt.Errorf("unknown family %q", family)
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables new: %w", err)
	}
	defer conn.CloseLasting()

	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	var tbl *nftables.Table
	for _, t := range tables {
		if t.Name == table && t.Family == fam {
			tbl = t
			break
		}
	}
	if tbl == nil {
		return fmt.Errorf("table %s/%s not found", family, table)
	}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	for _, c := range chains {
		if c.Table.Name != tbl.Name || c.Table.Family != tbl.Family || c.Name != chain {
			continue
		}
		rules, err := conn.GetRules(tbl, c)
		if err != nil {
			return err
		}
		for _, r := range rules {
			if r.Handle != handle {
				continue
			}
			before, _, had := ruleCounter(r.Exprs)
			if !had {
				return fmt.Errorf("rule %d in %s/%s/%s has no counter to reset", handle, family, table, chain)
			}
			newExprs := make([]expr.Any, 0, len(r.Exprs))
			for _, e := range r.Exprs {
				if _, isCounter := e.(*expr.Counter); isCounter {
					newExprs = append(newExprs, &expr.Counter{})
					continue
				}
				newExprs = append(newExprs, e)
			}
			conn.ReplaceRule(&nftables.Rule{
				Table:    tbl,
				Chain:    c,
				Handle:   handle,
				Exprs:    newExprs,
				UserData: r.UserData,
			})
			if err := conn.Flush(); err != nil {
				return fmt.Errorf("flush nft: %w", err)
			}
			log.Printf("netops audit: reset firewall counter family=%s table=%s chain=%s handle=%d before_pkts=%d after_pkts=0",
				family, table, chain, handle, before)
			return nil
		}
	}
	return fmt.Errorf("rule %d not found in %s/%s/%s", handle, family, table, chain)
}

// parseFamily maps the string family names exposed by RuleInfo back to the
// nftables enum. Only the families Testudo surfaces are accepted.
func parseFamily(s string) (nftables.TableFamily, bool) {
	switch s {
	case "ip":
		return nftables.TableFamilyIPv4, true
	case "ip6":
		return nftables.TableFamilyIPv6, true
	case "inet":
		return nftables.TableFamilyINet, true
	case "arp":
		return nftables.TableFamilyARP, true
	case "bridge":
		return nftables.TableFamilyBridge, true
	case "netdev":
		return nftables.TableFamilyNetdev, true
	}
	return 0, false
}

// sortChainRules orders one chain's rules for the diagnostic "what's
// blocking me" view: DROP/REJECT rules carrying counters float to the top,
// ordered by packet hits descending; every other rule keeps its kernel
// order. Stable so equal-weight rules don't shuffle between refreshes.
func sortChainRules(rules []RuleInfo) {
	sort.SliceStable(rules, func(i, j int) bool {
		bi, bj := rules[i].IsBlocking(), rules[j].IsBlocking()
		if bi != bj {
			return bi // blocking rules first
		}
		if bi && bj {
			return rules[i].Packets > rules[j].Packets
		}
		return false // preserve original order for non-blocking rules
	})
}

// ruleCounter scans a rule's expression list for an expr.Counter and
// returns its packet/byte tallies. ok=false means the rule has no counter
// (a legacy rule added before Testudo attached counters, or a foreign rule).
func ruleCounter(exprs []expr.Any) (packets, bytes uint64, ok bool) {
	for _, e := range exprs {
		if c, isCounter := e.(*expr.Counter); isCounter {
			return c.Packets, c.Bytes, true
		}
	}
	return 0, 0, false
}

// decodeRule renders an nftables expression list into a one-line human match
// summary ("tcp dport 22 iif eth0") plus a verdict string. It is a pure
// function - no kernel, no Conn - so it is unit-testable against captured
// expression fixtures.
func decodeRule(exprs []expr.Any) (match, verdict string) {
	var tokens []string
	var (
		metaKey     expr.MetaKey
		haveMeta    bool
		payload     *expr.Payload
		havePayload bool
		mask        []byte // pending CIDR mask from a Bitwise before the Cmp
	)
	for _, e := range exprs {
		switch v := e.(type) {
		case *expr.Meta:
			metaKey, haveMeta = v.Key, true
			havePayload, mask = false, nil
		case *expr.Payload:
			payload, havePayload = v, true
			haveMeta, mask = false, nil
		case *expr.Bitwise:
			mask = v.Mask
		case *expr.Cmp:
			switch {
			case haveMeta:
				if tok := decodeMetaCmp(metaKey, v.Data); tok != "" {
					tokens = append(tokens, tok)
				}
				haveMeta = false
			case havePayload:
				if tok := decodePayloadCmp(payload, mask, v.Data); tok != "" {
					tokens = append(tokens, tok)
				}
				havePayload, mask = false, nil
			}
		case *expr.Counter:
			// Counters carry no match semantics; see ruleCounter.
		case *expr.Reject:
			verdict = "REJECT"
		case *expr.Log:
			if verdict == "" {
				verdict = "LOG"
			}
		case *expr.Verdict:
			verdict = verdictString(v)
		}
	}
	return strings.Join(tokens, " "), verdict
}

// decodeMetaCmp turns a meta-key comparison into a match token. The NFPROTO
// family gate is intentionally elided - it only ever accompanies an
// saddr/daddr match and would just clutter the line.
func decodeMetaCmp(key expr.MetaKey, data []byte) string {
	switch key {
	case expr.MetaKeyNFPROTO:
		return "" // family gate; redundant with the saddr/daddr token
	case expr.MetaKeyIIFNAME:
		return "iif " + trimIface(data)
	case expr.MetaKeyOIFNAME:
		return "oif " + trimIface(data)
	case expr.MetaKeyIIF:
		return fmt.Sprintf("iif %d", leUint32(data))
	case expr.MetaKeyOIF:
		return fmt.Sprintf("oif %d", leUint32(data))
	case expr.MetaKeyL4PROTO:
		if len(data) == 1 {
			return protoName(data[0])
		}
	}
	return ""
}

// decodePayloadCmp turns a payload comparison into a match token. It
// recognises the IPv4/IPv6 source/dest address offsets and the transport
// sport/dport offsets that cover the overwhelming majority of real rules.
func decodePayloadCmp(p *expr.Payload, mask, data []byte) string {
	if p == nil {
		return ""
	}
	switch p.Base {
	case expr.PayloadBaseNetworkHeader:
		switch {
		case p.Offset == 12 && p.Len == 4:
			return "saddr " + ipMaskString(data, mask)
		case p.Offset == 16 && p.Len == 4:
			return "daddr " + ipMaskString(data, mask)
		case p.Offset == 8 && p.Len == 16:
			return "saddr " + ipMaskString(data, mask)
		case p.Offset == 24 && p.Len == 16:
			return "daddr " + ipMaskString(data, mask)
		}
	case expr.PayloadBaseTransportHeader:
		if p.Len == 2 {
			port := beUint16(data)
			switch p.Offset {
			case 0:
				return fmt.Sprintf("sport %d", port)
			case 2:
				return fmt.Sprintf("dport %d", port)
			}
		}
	}
	return ""
}

// nftRuleCommentType is the libnftnl udata TLV type that carries an nft rule
// comment (NFTNL_UDATA_RULE_COMMENT).
const nftRuleCommentType = 0

// ruleComment best-effort decodes an nft `comment "..."` annotation from a
// rule's UserData. UserData is a sequence of {type, len, data} TLVs; we only
// extract the comment type and return "" for anything that doesn't parse as
// clean TLVs (e.g. Testudo's own pipe-delimited round-trip key).
func ruleComment(ud []byte) string {
	for len(ud) >= 2 {
		typ, length := ud[0], int(ud[1])
		ud = ud[2:]
		if length > len(ud) {
			return "" // malformed / not TLV-encoded
		}
		val := ud[:length]
		ud = ud[length:]
		if typ == nftRuleCommentType {
			return strings.TrimRight(string(val), "\x00")
		}
	}
	return ""
}

func verdictString(v *expr.Verdict) string {
	switch v.Kind {
	case expr.VerdictAccept:
		return "ACCEPT"
	case expr.VerdictDrop:
		return "DROP"
	case expr.VerdictReturn:
		return "RETURN"
	case expr.VerdictJump:
		return "JUMP " + v.Chain
	case expr.VerdictGoto:
		return "GOTO " + v.Chain
	case expr.VerdictQueue:
		return "QUEUE"
	}
	return "CONTINUE"
}

func protoName(p byte) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	}
	return fmt.Sprintf("proto %d", p)
}

// trimIface decodes a fixed 16-byte zero-padded interface name buffer.
func trimIface(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

func leUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func beUint16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// ipMaskString renders a raw IPv4/IPv6 address, appending the CIDR prefix
// length when a Bitwise mask preceded the comparison.
func ipMaskString(data, mask []byte) string {
	ip := net.IP(data).String()
	if len(mask) == len(data) {
		ones, bits := net.IPMask(mask).Size()
		if ones != bits { // bits==0 means a non-canonical mask; skip suffix
			return fmt.Sprintf("%s/%d", ip, ones)
		}
	}
	return ip
}

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	}
	return fmt.Sprintf("?%d", f)
}

func hookName(h nftables.ChainHook) string {
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	case *nftables.ChainHookIngress:
		return "ingress"
	}
	return "-"
}
