package fwrender

import (
	"fmt"
	"strings"

	"github.com/noahzmr/testudo/internal/netops"
)

// Comment prefixes that tie a kernel rule back to the firewall manager's
// rule, port forward or masquerade with that id. The manager's drift check
// and its counters depend on them.
const (
	RuleTag       = "tf1:"
	ForwardTag    = "tn1:"
	MasqueradeTag = "tm1:"
)

func famMatch(dir, addr string) string {
	if addr == "" {
		return ""
	}
	if isV6(addr) {
		return "ip6 " + dir + " " + addr
	}
	return "ip " + dir + " " + addr
}

// runningRule renders one rule in the firewall manager's format.
func runningRule(r netops.FilterRule) string {
	var p []string
	add := func(s string) {
		if s != "" {
			p = append(p, s)
		}
	}
	if r.InIface != "" {
		add("iifname " + quote(r.InIface))
	}
	if r.OutIface != "" {
		add("oifname " + quote(r.OutIface))
	}
	add(famMatch("saddr", r.SrcCIDR))
	add(famMatch("daddr", r.DstCIDR))
	switch proto := strings.ToLower(r.Proto); {
	case proto == "icmpv6":
		add("meta l4proto icmpv6")
	case proto != "" && r.Port == 0:
		add("meta l4proto " + proto)
	case proto != "" && r.PortEnd > r.Port:
		add(fmt.Sprintf("%s dport %d-%d", proto, r.Port, r.PortEnd))
	case proto != "":
		add(fmt.Sprintf("%s dport %d", proto, r.Port))
	}
	if r.CtState != "" {
		add("ct state " + strings.ReplaceAll(r.CtState, " ", ""))
	}
	if r.RateLimit != "" {
		if r.RateOver {
			add("limit rate over " + r.RateLimit)
		} else {
			add("limit rate " + r.RateLimit)
		}
	}
	action := strings.ToLower(r.Action)
	if r.Log || action == "log" {
		add(`log prefix "testudo: "`)
	}
	add("counter")
	if action != "log" {
		add(action)
	}
	add("comment " + quote(RuleTag+r.ID()))
	return strings.Join(p, " ")
}

// runningLines splits the manager's rendered rules per chain into the
// baseline (ahead of everything), the rules of other owners, and the
// baseline's final log rule (behind everything).
func runningLines(spec netops.FilterTableSpec) (head, foreign, logTail map[string][]string) {
	head, foreign, logTail = map[string][]string{}, map[string][]string{}, map[string][]string{}
	for _, r := range netops.RenderFilterRules(spec) {
		line := runningRule(r)
		switch {
		case r.Owner == netops.OwnerBaseline && strings.EqualFold(r.Action, "log"):
			logTail[r.Chain] = append(logTail[r.Chain], line)
		case r.Owner == netops.OwnerBaseline:
			head[r.Chain] = append(head[r.Chain], line)
		default:
			foreign[r.Chain] = append(foreign[r.Chain], line)
		}
	}
	return
}

func runningNAT(spec netops.NATSpec) (pre, post []string) {
	for _, f := range spec.Forwards {
		lan := f.LANPort
		if lan == 0 {
			lan = f.WANPort
		}
		var p []string
		if f.InIface != "" {
			p = append(p, "iifname "+quote(f.InIface))
		}
		p = append(p, fmt.Sprintf("%s dport %d counter dnat ip to %s:%d", strings.ToLower(f.Proto), f.WANPort, f.LANIP, lan),
			"comment "+quote(ForwardTag+f.ID()))
		pre = append(pre, strings.Join(p, " "))
	}
	for _, m := range spec.Masquerades {
		var p []string
		if m.OutIface != "" {
			p = append(p, "oifname "+quote(m.OutIface))
		}
		if m.SrcCIDR != "" {
			p = append(p, famMatch("saddr", m.SrcCIDR))
		}
		p = append(p, "counter masquerade", "comment "+quote(MasqueradeTag+m.ID()))
		post = append(post, strings.Join(p, " "))
	}
	return
}
