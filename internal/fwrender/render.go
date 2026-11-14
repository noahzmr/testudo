// Package fwrender turns the configuration model into one nftables ruleset
// for one node: zones as interface sets, aliases as address and port sets,
// ordered filter rules, the lock-out baseline, and NAT.
//
// Render is pure: the same state and options always give the same text,
// which is what the golden files pin down. Applying the text is the job of
// internal/fwstage.
package fwrender

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// Table is the nftables table this package owns, in the inet family so IPv4
// and IPv6 share every rule.
const Table = "testudo"

// Options are the node-local facts the model does not hold.
type Options struct {
	SiteID, NodeID string
	// ProtectedTCPPorts stay open on the input chain whatever the model
	// says (SSH, the web UI). They are the last line against a lock-out.
	ProtectedTCPPorts []int
}

type renderer struct {
	st   *confstore.State
	opt  Options
	b    strings.Builder
	errs []string

	zones   map[string]*model.Zone
	aliases map[string]*model.Alias
	zoneIfs map[string][]string // zone id -> device names
}

// effective returns the objects of one kind that apply to the node, with
// site and node overrides resolved, ordered by name.
func effective[T model.Entity](r *renderer, kind model.Kind) []T {
	var out []T
	for _, e := range r.st.List(kind) {
		if !model.AppliesTo(e, r.opt.SiteID, r.opt.NodeID) {
			continue
		}
		eff, _, err := model.Effective(e, r.opt.SiteID, r.opt.NodeID)
		if err != nil {
			r.errs = append(r.errs, fmt.Sprintf("%s %q: %v", kind, e.GetMeta().Name, err))
			continue
		}
		out = append(out, eff.(T))
	}
	return out
}

// ident builds an nftables identifier that is readable and cannot collide:
// the sanitised name plus the start of the object's UUID.
func ident(prefix string, m *model.Meta) string {
	var sb strings.Builder
	for _, c := range m.Name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			sb.WriteRune(c)
		default:
			sb.WriteByte('_')
		}
	}
	name := sb.String()
	if len(name) > 40 {
		name = name[:40]
	}
	return prefix + "_" + name + "_" + strings.ReplaceAll(m.ID, "-", "")[:6]
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, ``, `"`, ``, "\n", " ").Replace(s) + `"`
}

func isV6(s string) bool {
	host := s
	if i := strings.IndexByte(s, '/'); i >= 0 {
		host = s[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

// Render returns the complete ruleset for the node. A model without a
// firewall policy for this node renders to a ruleset that only removes the
// table, so the stage is inert until the operator defines a policy.
func Render(st *confstore.State, opt Options) ([]byte, error) {
	r := &renderer{st: st, opt: opt, zones: map[string]*model.Zone{}, aliases: map[string]*model.Alias{},
		zoneIfs: map[string][]string{}}

	// Replace-the-table idiom: create (no-op if present), delete, define.
	// nft applies one file as a single transaction.
	fmt.Fprintf(&r.b, "table inet %s\ndelete table inet %s\n", Table, Table)

	policy := r.policy()
	if policy == nil {
		return []byte(r.b.String()), r.err()
	}
	for _, z := range effective[*model.Zone](r, model.KindZone) {
		r.zones[z.ID] = z
	}
	for _, a := range effective[*model.Alias](r, model.KindAlias) {
		r.aliases[a.ID] = a
	}
	for _, i := range effective[*model.Interface](r, model.KindInterface) {
		if i.Enabled && i.Zone.ID != "" {
			r.zoneIfs[i.Zone.ID] = append(r.zoneIfs[i.Zone.ID], i.Device)
		}
	}
	for _, t := range effective[*model.WGTunnel](r, model.KindWGTunnel) {
		if t.Enabled {
			r.zoneIfs[t.Zone.ID] = append(r.zoneIfs[t.Zone.ID], t.Device)
		}
	}

	fmt.Fprintf(&r.b, "table inet %s {\n", Table)
	r.sets()
	rules := effective[*model.FilterRule](r, model.KindFilterRule)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Sequence < rules[j].Sequence })
	nat := effective[*model.NATRule](r, model.KindNATRule)
	sort.SliceStable(nat, func(i, j int) bool { return nat[i].Sequence < nat[j].Sequence })

	r.filterChain("input", "in", policy, rules)
	r.filterChain("forward", "forward", policy, rules)
	r.filterChain("output", "out", policy, rules)
	r.natChains(nat)
	r.b.WriteString("}\n")
	return []byte(r.b.String()), r.err()
}

func (r *renderer) err() error {
	if len(r.errs) == 0 {
		return nil
	}
	return fmt.Errorf("fwrender: %s", strings.Join(r.errs, "; "))
}

// policy picks the most specific firewall policy: node, then site, then
// global. The store guarantees at most one per scope.
func (r *renderer) policy() *model.FirewallPolicy {
	var best *model.FirewallPolicy
	rank := map[string]int{"global": 1, "site": 2, "node": 3}
	for _, p := range effective[*model.FirewallPolicy](r, model.KindFirewallPolicy) {
		if best == nil || rank[p.Scope.Level()] > rank[best.Scope.Level()] {
			best = p
		}
	}
	return best
}

func sortedKeys[V any](m map[string]V, name func(string) string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return name(keys[i]) < name(keys[j]) })
	return keys
}

// aliasContent flattens an alias and its nested aliases.
func (r *renderer) aliasContent(a *model.Alias, seen map[string]bool) (v4, v6, ports []string) {
	if a == nil || seen[a.ID] {
		return
	}
	seen[a.ID] = true
	for _, e := range a.Entries {
		switch {
		case a.Type == "port":
			ports = append(ports, e)
		case a.Type == "host" || a.Type == "network":
			if isV6(e) {
				v6 = append(v6, e)
			} else if net.ParseIP(strings.SplitN(e, "/", 2)[0]) != nil {
				v4 = append(v4, e)
			} else {
				r.errs = append(r.errs, fmt.Sprintf("alias %q: %q is not an address or network", a.Name, e))
			}
		}
	}
	for _, m := range a.Members {
		a4, a6, p := r.aliasContent(r.aliases[m.ID], seen)
		v4, v6, ports = append(v4, a4...), append(v6, a6...), append(ports, p...)
	}
	return
}

// dynamic reports whether an alias is filled at run time (URL table, GeoIP)
// and therefore has to stay a named set that rules reference.
func dynamic(a *model.Alias) bool { return a.Type == "url_table" || a.Type == "geoip" }

func uniq(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func (r *renderer) set(name, typ string, interval bool, elems []string, quoteElems bool) {
	fmt.Fprintf(&r.b, "\tset %s {\n\t\ttype %s\n", name, typ)
	if interval {
		r.b.WriteString("\t\tflags interval\n\t\tauto-merge\n")
	}
	if elems = uniq(elems); len(elems) > 0 {
		if quoteElems {
			for i := range elems {
				elems[i] = quote(elems[i])
			}
		}
		fmt.Fprintf(&r.b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	r.b.WriteString("\t}\n")
}

func (r *renderer) sets() {
	for _, id := range sortedKeys(r.zones, func(id string) string { return r.zones[id].Name }) {
		r.set(ident("z", &r.zones[id].Meta), "ifname", false, append([]string(nil), r.zoneIfs[id]...), true)
	}
	for _, id := range sortedKeys(r.aliases, func(id string) string { return r.aliases[id].Name }) {
		a := r.aliases[id]
		v4, v6, ports := r.aliasContent(a, map[string]bool{})
		if a.Type == "port" {
			r.set(ident("p", &a.Meta), "inet_service", true, ports, false)
			continue
		}
		r.set(ident("a4", &a.Meta), "ipv4_addr", true, v4, false)
		r.set(ident("a6", &a.Meta), "ipv6_addr", true, v6, false)
	}
}

// addrTerms returns, per address family, the alternative match expressions
// for one side of a rule. Static aliases and literal networks merge into one
// anonymous set; each dynamic alias stays a reference to its named set. A
// nil slice for a family means the rule cannot match that family.
func (r *renderer) addrTerms(dir string, refs []model.Ref[model.Alias], nets []string) (t4, t6 []string, constrained bool) {
	var s4, s6 []string
	for _, n := range nets {
		if isV6(n) {
			s6 = append(s6, n)
		} else {
			s4 = append(s4, n)
		}
	}
	for _, ref := range refs {
		a := r.aliases[ref.ID]
		if a == nil {
			continue // not in effect on this node
		}
		if dynamic(a) {
			t4 = append(t4, fmt.Sprintf("ip %s @%s", dir, ident("a4", &a.Meta)))
			t6 = append(t6, fmt.Sprintf("ip6 %s @%s", dir, ident("a6", &a.Meta)))
			continue
		}
		a4, a6, _ := r.aliasContent(a, map[string]bool{})
		s4, s6 = append(s4, a4...), append(s6, a6...)
	}
	constrained = len(refs) > 0 || len(nets) > 0
	if s4 = uniq(s4); len(s4) > 0 {
		t4 = append(t4, fmt.Sprintf("ip %s { %s }", dir, strings.Join(s4, ", ")))
	}
	if s6 = uniq(s6); len(s6) > 0 {
		t6 = append(t6, fmt.Sprintf("ip6 %s { %s }", dir, strings.Join(s6, ", ")))
	}
	return t4, t6, constrained
}

func (r *renderer) zoneMatch(dir string, z model.Ref[model.Zone]) string {
	if zone := r.zones[z.ID]; zone != nil {
		return fmt.Sprintf("%s @%s", dir, ident("z", &zone.Meta))
	}
	return ""
}

func protoMatch(proto string, hasPorts bool) string {
	switch proto {
	case "tcp", "udp", "icmp":
		return "meta l4proto " + proto
	case "icmpv6":
		return "meta l4proto ipv6-icmp"
	}
	if hasPorts {
		return "meta l4proto { tcp, udp }"
	}
	return ""
}

// rule writes one filter rule. A rule that constrains addresses is written
// once per address family and per combination of source and destination
// terms, because one nftables rule matches one family.
func (r *renderer) rule(fr *model.FilterRule, chain string) {
	var head []string
	if chain != "output" {
		if m := r.zoneMatch("iifname", fr.SourceZone); m != "" {
			head = append(head, m)
		}
	}
	if chain != "input" {
		if m := r.zoneMatch("oifname", fr.DestinationZone); m != "" {
			head = append(head, m)
		}
	}
	if fr.Tunnel.ID != "" {
		for _, t := range effective[*model.WGTunnel](r, model.KindWGTunnel) {
			if t.ID == fr.Tunnel.ID {
				head = append(head, "iifname "+quote(t.Device))
			}
		}
	}
	ports := append([]string(nil), fr.Ports...)
	for _, pa := range fr.PortAliases {
		_, _, p := r.aliasContent(r.aliases[pa.ID], map[string]bool{})
		ports = append(ports, p...)
	}
	ports = uniq(ports)

	var tail []string
	if p := protoMatch(fr.Protocol, len(ports) > 0); p != "" {
		tail = append(tail, p)
	}
	if len(ports) > 0 {
		tail = append(tail, "th dport { "+strings.Join(ports, ", ")+" }")
	}
	if len(fr.States) > 0 {
		tail = append(tail, "ct state { "+strings.Join(fr.States, ", ")+" }")
	}
	if fr.RateLimit != "" {
		tail = append(tail, "limit rate "+fr.RateLimit)
	}
	if fr.Mark != 0 {
		tail = append(tail, fmt.Sprintf("meta mark set 0x%x", fr.Mark))
	}
	if fr.Log {
		tail = append(tail, "log prefix "+quote("testudo "+fr.Name+": "))
	}
	tail = append(tail, "counter", fr.Action, "comment "+quote(fr.ID))

	s4, s6, sc := r.addrTerms("saddr", fr.Source, fr.SourceNets)
	d4, d6, dc := r.addrTerms("daddr", fr.Destination, fr.DestinationNets)
	emit := func(addr ...string) {
		parts := append(append(append([]string(nil), head...), addr...), tail...)
		fmt.Fprintf(&r.b, "\t\t%s\n", strings.Join(parts, " "))
	}
	if !sc && !dc {
		emit()
		return
	}
	for _, fam := range []struct{ src, dst []string }{{s4, d4}, {s6, d6}} {
		src, dst := fam.src, fam.dst
		if (sc && len(src) == 0) || (dc && len(dst) == 0) {
			continue // the rule has no address of this family on a constrained side
		}
		if !sc {
			src = []string{""}
		}
		if !dc {
			dst = []string{""}
		}
		for _, s := range src {
			for _, d := range dst {
				var addr []string
				for _, t := range []string{s, d} {
					if t != "" {
						addr = append(addr, t)
					}
				}
				emit(addr...)
			}
		}
	}
}

func intList(ports []int) []string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(p)
	}
	return out
}

func (r *renderer) filterChain(chain, direction string, p *model.FirewallPolicy, rules []*model.FilterRule) {
	verdict := "accept"
	if p.DefaultDeny && chain != "output" {
		verdict = "drop"
	}
	fmt.Fprintf(&r.b, "\tchain %s {\n\t\ttype filter hook %s priority filter; policy %s;\n", chain, chain, verdict)
	w := func(format string, a ...any) { fmt.Fprintf(&r.b, "\t\t"+format+"\n", a...) }

	if chain != "output" {
		// Baseline: what must keep working whatever the rules say.
		if p.AllowEstablished {
			w("ct state established,related accept")
		}
		if p.DropInvalid {
			w("ct state invalid drop")
		}
	}
	if chain == "input" {
		if p.AllowLoopback {
			w(`iifname "lo" accept`)
		}
		for _, id := range sortedKeys(r.zones, func(id string) string { return r.zones[id].Name }) {
			if z := r.zones[id]; z.AntiSpoof {
				w("iifname @%s fib saddr . iif oif missing counter drop", ident("z", &z.Meta))
			}
		}
		if p.SynFloodGuard {
			w("tcp flags & (fin | syn | rst | ack) == syn limit rate over 200/second burst 400 packets counter drop")
		}
		if p.AllowICMP {
			w("meta l4proto { icmp, ipv6-icmp } accept")
		}
		if tcp := uniq(append(intList(r.opt.ProtectedTCPPorts), p.AllowTCPPorts...)); len(tcp) > 0 {
			w("tcp dport { %s } accept", strings.Join(tcp, ", "))
		}
		if udp := uniq(append([]string(nil), p.AllowUDPPorts...)); len(udp) > 0 {
			w("udp dport { %s } accept", strings.Join(udp, ", "))
		}
	}
	if chain == "forward" {
		for _, id := range sortedKeys(r.zones, func(id string) string { return r.zones[id].Name }) {
			if z := r.zones[id]; z.AntiSpoof {
				w("iifname @%s fib saddr . iif oif missing counter drop", ident("z", &z.Meta))
			}
		}
		// Connections a destination NAT rule accepted are forwarded.
		w("ct status dnat accept")
	}

	for _, fr := range rules {
		if fr.Enabled && fr.Direction == direction {
			r.rule(fr, chain)
		}
	}

	if chain != "output" {
		for _, id := range sortedKeys(r.zones, func(id string) string { return r.zones[id].Name }) {
			z := r.zones[id]
			set := ident("z", &z.Meta)
			if chain == "forward" && z.IntraZone {
				w("iifname @%s oifname @%s accept", set, set)
			}
			// Without default deny, a zone's own default still applies to
			// what enters through it.
			if !p.DefaultDeny && z.DefaultAction != "accept" {
				w("iifname @%s counter %s", set, z.DefaultAction)
			}
		}
		if p.LogDrops && p.DefaultDeny {
			prefix := p.LogPrefix
			if prefix == "" {
				prefix = "testudo drop"
			}
			w("limit rate 10/second log prefix %s", quote(prefix+" "+chain+": "))
		}
	}
	r.b.WriteString("\t}\n")
}

// natAddr renders "ip to X" or "ip6 to X" with an optional port.
func natTarget(addr, port string) string {
	fam := "ip"
	if isV6(addr) {
		fam = "ip6"
		if port != "" {
			addr = "[" + addr + "]"
		}
	}
	if port != "" {
		addr += ":" + port
	}
	return fam + " to " + addr
}

func famAddr(dir, addr string) string {
	if addr == "" {
		return ""
	}
	if isV6(addr) {
		return "ip6 " + dir + " " + addr
	}
	return "ip " + dir + " " + addr
}

func (r *renderer) natChains(rules []*model.NATRule) {
	var pre, post []string
	add := func(list *[]string, n *model.NATRule, parts ...string) {
		var keep []string
		for _, p := range parts {
			if p != "" {
				keep = append(keep, p)
			}
		}
		*list = append(*list, strings.Join(append(keep, "comment "+quote(n.ID)), " "))
	}
	for _, n := range rules {
		if !n.Enabled {
			continue
		}
		proto := protoMatch(n.Protocol, n.Port != "")
		dport := ""
		if n.Port != "" {
			dport = "th dport " + n.Port
		}
		// A translation is written for the family of its target; source
		// networks of the other family cannot match it.
		var srcs []string
		for _, s := range n.SourceNets {
			if n.TranslateTo == "" || isV6(s) == isV6(n.TranslateTo) {
				srcs = append(srcs, s)
			}
		}
		src := ""
		if len(n.SourceNets) > 0 {
			if len(srcs) == 0 {
				continue
			}
			fam := "ip"
			if isV6(srcs[0]) {
				fam = "ip6"
			}
			src = fmt.Sprintf("%s saddr { %s }", fam, strings.Join(uniq(srcs), ", "))
		}
		switch n.Type {
		case "dnat":
			target := "dnat " + natTarget(n.TranslateTo, n.TranslatePort)
			add(&pre, n, r.zoneMatch("iifname", n.Zone), src, famAddr("daddr", n.Destination), proto, dport, "counter", target)
			if n.Reflection && n.Destination != "" && r.zones[n.Zone.ID] != nil {
				// Clients behind the firewall reach the forward through its
				// outside address; the reply has to come back through us.
				inside := "iifname != @" + ident("z", &r.zones[n.Zone.ID].Meta)
				add(&pre, n, inside, famAddr("daddr", n.Destination), proto, dport, "counter", target)
				tport := n.TranslatePort
				if tport == "" {
					tport = n.Port
				}
				tp := ""
				if tport != "" {
					tp = "th dport " + tport
				}
				add(&post, n, inside, "ct status dnat", famAddr("daddr", n.TranslateTo), proto, tp, "counter masquerade")
			}
		case "snat":
			add(&post, n, r.zoneMatch("oifname", n.Zone), src, famAddr("daddr", n.Destination), proto, dport, "counter",
				"snat "+natTarget(n.TranslateTo, n.TranslatePort))
		case "masquerade":
			add(&post, n, r.zoneMatch("oifname", n.Zone), src, famAddr("daddr", n.Destination), proto, dport, "counter masquerade")
		case "one_to_one":
			if n.Destination == "" {
				r.errs = append(r.errs, fmt.Sprintf("nat_rule %q: one-to-one needs the outside address in destination", n.Name))
				continue
			}
			add(&pre, n, famAddr("daddr", n.Destination), "counter", "dnat "+natTarget(n.TranslateTo, ""))
			add(&post, n, r.zoneMatch("oifname", n.Zone), famAddr("saddr", n.TranslateTo), "counter", "snat "+natTarget(n.Destination, ""))
		}
	}
	fmt.Fprintf(&r.b, "\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	for _, l := range pre {
		fmt.Fprintf(&r.b, "\t\t%s\n", l)
	}
	fmt.Fprintf(&r.b, "\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	for _, l := range post {
		fmt.Fprintf(&r.b, "\t\t%s\n", l)
	}
	r.b.WriteString("\t}\n")
}
