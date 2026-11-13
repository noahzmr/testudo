package firewall

import (
	"fmt"
	"strings"

	"github.com/noahzmr/testudo/internal/netops"
)

// RenderNFT renders the policy the way `nft list ruleset` would show the
// Testudo tables, for humans: review before enabling enforce, paste into a
// ticket, diff two exports. It is documentation, not an input format - the
// JSON export is what Import reads.
func (m *Manager) RenderNFT() string {
	m.mu.Lock()
	pol := m.pol.Clone()
	spec := pol.filterSpec(m.opts.ProtectedTCPPorts)
	m.mu.Unlock()
	return RenderNFT(pol, spec)
}

// RenderNFT renders a policy (with the filter spec the manager would apply).
func RenderNFT(pol Policy, spec netops.FilterTableSpec) string {
	var b strings.Builder
	mode := "default-accept"
	if pol.Enforce {
		mode = "default-deny (enforce)"
	}
	fmt.Fprintf(&b, "# Testudo firewall policy v%d - %s\n", PolicyVersion, mode)
	if !pol.UpdatedAt.IsZero() {
		fmt.Fprintf(&b, "# updated %s\n", pol.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	b.WriteString("table inet testudo_filter {\n")
	policies := netops.ChainPolicies(spec)
	rules := netops.RenderFilterRules(spec)
	hooks := map[string]string{"input": "input", "forward": "forward", "output": "output"}
	for _, chain := range []string{"input", "forward", "output"} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority filter; policy %s;\n", chain, hooks[chain], policies[chain])
		for _, r := range rules {
			if r.Chain != chain {
				continue
			}
			line := strings.TrimPrefix(r.String(), chain+" ")
			fmt.Fprintf(&b, "\t\t%s comment \"%s\"\n", line, commentFor(r.ID(), r.Comment, r.Owner))
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	if len(pol.Forwards) > 0 || len(pol.Masquerades) > 0 {
		b.WriteString("table ip testudo_nat {\n")
		b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
		for _, f := range pol.Forwards {
			fmt.Fprintf(&b, "\t\t%s comment \"%s\"\n", strings.TrimPrefix(f.String(), "prerouting "), commentFor(f.ID(), f.Comment, f.Owner))
		}
		b.WriteString("\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
		for _, ms := range pol.Masquerades {
			fmt.Fprintf(&b, "\t\t%s comment \"%s\"\n", strings.TrimPrefix(ms.String(), "postrouting "), commentFor(ms.ID(), ms.Comment, ms.Owner))
		}
		b.WriteString("\t}\n}\n")
	}
	return b.String()
}

func commentFor(id, comment, owner string) string {
	parts := []string{id}
	if owner != "" && owner != netops.OwnerUser {
		parts = append(parts, owner)
	}
	if comment != "" {
		parts = append(parts, comment)
	}
	return strings.ReplaceAll(strings.Join(parts, " "), `"`, "'")
}
