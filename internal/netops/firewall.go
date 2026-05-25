package netops

import (
	"fmt"

	"github.com/google/nftables"
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
