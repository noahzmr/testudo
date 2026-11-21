// Package fwrender turns the configuration model into one nftables ruleset
// for one node: zones as interface sets, aliases as address and port sets,
// ordered filter rules, the lock-out baseline, and NAT.
//
// Render is pure: the same state and options always give the same text,
// which is what the golden files pin down. Applying the text is the job of
// internal/fwstage.
package fwrender

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/harender"
	"github.com/noahzmr/testudo/internal/mesh"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/svcrender"
)

// Table is the nftables table this package owns, in the inet family so IPv4
// and IPv6 share every rule.
const Table = "testudo"

// Options are the node-local facts the model does not hold.
type Options struct {
	SiteID, NodeID string
	// ProtectedTCPPorts stay open on the input chain whatever the model
	// says (SSH, the web UI). They are the last line against a lock-out.
	// With Running set, the running policy already contains them.
	ProtectedTCPPorts []int
	// Elements holds the current content of aliases that are filled at run
	// time (URL tables, GeoIP), by alias id. They are rendered into the sets
	// so that a full reload does not empty them.
	Elements map[string][]string
	// BackendDown names the backends ("host:port") of kernel-mode load
	// balancing that failed their health check; they get no new connections.
	BackendDown map[string]bool
}

// Running is the part of the ruleset that does not come from the model: the
// firewall manager's defaults, its baseline, and the rules owned by the
// operator's direct edits, WireGuard peers and access grants. When it is
// given, those rules are rendered ahead of the model's in the same chains,
// and the manager's defaults decide the chain policies.
type Running struct {
	// DropLegacyTables removes the tables the old firewall manager used to
	// own, in the same transaction that installs this one.
	DropLegacyTables bool
}

// Fragments is the model's contribution to the ruleset, rendered but not yet
// combined with anything else. It is what the apply stage keeps, so that the
// ruleset can be assembled again when the running side changes.
type Fragments struct {
	// HasPolicy says whether the model defines a firewall policy for this
	// node. Without one, and without a running side, there is nothing to do.
	HasPolicy bool             `json:"has_policy"`
	Policy    PolicyFragment   `json:"policy"`
	Sets      string           `json:"sets"`
	Chains    map[string]Chain `json:"chains"`
	Pre       []string         `json:"prerouting"`
	Post      []string         `json:"postrouting"`
}

// PolicyFragment is the model's firewall policy in rendered form.
type PolicyFragment struct {
	DefaultDeny bool     `json:"default_deny"`
	Baseline    []string `json:"baseline_input"` // input-chain baseline lines
	Stateful    []string `json:"stateful"`       // established / invalid lines
	LogPrefix   string   `json:"log_prefix"`     // empty: dropped packets are not logged
	// Timeouts holds the connection-tracking timeout objects and Tracking
	// the rules that attach them; both are empty for kernel defaults.
	Timeouts string   `json:"ct_timeouts"`
	Tracking []string `json:"ct_tracking"`
	SynFlood bool     `json:"syn_flood_guard"`
}

// Chain is the model's part of one filter chain.
type Chain struct {
	Guards   []string `json:"guards"`    // anti-spoofing, ahead of every rule
	Rules    []string `json:"rules"`     // the ordered filter rules
	Tail     []string `json:"tail"`      // always at the end (traffic inside a zone)
	TailOpen []string `json:"tail_open"` // zone defaults, used when the chain policy is accept
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

// Render returns the complete ruleset for the node from the model alone. A
// model without a firewall policy for this node renders to a ruleset that
// only removes the table, so the stage is inert until one is defined.
func Render(st *confstore.State, opt Options) ([]byte, error) {
	f, err := Build(st, opt)
	if err != nil {
		return nil, err
	}
	return []byte(Assemble(f, nil)), nil
}

// Build renders the model's fragments for one node.
func Build(st *confstore.State, opt Options) (Fragments, error) {
	r := &renderer{st: st, opt: opt, zones: map[string]*model.Zone{}, aliases: map[string]*model.Alias{},
		zoneIfs: map[string][]string{}}
	f := Fragments{Chains: map[string]Chain{}}
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
	// The fabric's tunnels are in the fabric's zone, so rules about traffic
	// between the sites are written against that zone.
	plan, perr := mesh.Build(r.st, opt.SiteID, opt.NodeID)
	if perr != nil {
		r.errs = append(r.errs, perr.Error())
	}
	if plan.Enabled {
		r.zoneIfs[plan.Fabric.Zone.ID] = append(r.zoneIfs[plan.Fabric.Zone.ID], plan.Devices()...)
	}
	// An HA pair needs VRRP on its interfaces and the partner's state sync.
	// A pair that does not render opens nothing; the HA stage reports why.
	ha, _ := harender.Render(r.st, harender.Options{SiteID: opt.SiteID, NodeID: opt.NodeID})
	// The services answer on their interfaces whatever the policy says;
	// a service that does not render opens nothing.
	svc, _ := svcrender.Render(r.st, svcrender.Options{SiteID: opt.SiteID, NodeID: opt.NodeID})
	r.sets()
	f.Sets = r.take()

	if p := r.policy(); p != nil {
		f.HasPolicy = true
		f.Policy = r.policyFragment(p)
	}
	rules := effective[*model.FilterRule](r, model.KindFilterRule)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Sequence < rules[j].Sequence })
	zoneIDs := sortedKeys(r.zones, func(id string) string { return r.zones[id].Name })
	for chain, direction := range map[string]string{"input": "in", "forward": "forward", "output": "out"} {
		var c Chain
		for _, fr := range rules {
			if fr.Enabled && fr.Direction == direction {
				r.rule(fr, chain)
			}
		}
		c.Rules = r.takeLines()
		if chain == "forward" {
			c.Rules = append(c.Rules, r.access()...)
		}
		if chain == "input" && plan.Enabled && len(plan.Tunnels) > 0 {
			// What the fabric itself needs, ahead of the operator's rules
			// so that a default-deny policy cannot cut the sites apart:
			// the tunnels from anywhere (WireGuard answers only to the
			// keys it knows), BGP and BFD inside the tunnels only.
			ports := make([]string, 0, len(plan.Tunnels))
			for _, p := range plan.Ports() {
				ports = append(ports, fmt.Sprint(p))
			}
			devs := make([]string, 0, len(plan.Tunnels))
			for _, d := range plan.Devices() {
				devs = append(devs, quote(d))
			}
			c.Rules = append([]string{
				fmt.Sprintf("udp dport { %s } counter accept comment \"fabric: tunnels\"", strings.Join(ports, ", ")),
				fmt.Sprintf("iifname { %s } tcp dport 179 counter accept comment \"fabric: bgp\"", strings.Join(devs, ", ")),
				fmt.Sprintf("iifname { %s } udp dport { 3784, 3785, 4784 } counter accept comment \"fabric: bfd\"", strings.Join(devs, ", ")),
			}, c.Rules...)
		}
		if chain == "input" && ha.Enabled {
			c.Rules = append(haInput(ha), c.Rules...)
		}
		if chain == "input" {
			c.Rules = append(serviceInput(svc.Open), c.Rules...)
			c.Rules = append(r.dhcpv6ClientInput(), c.Rules...)
		}
		if chain != "output" {
			for _, id := range zoneIDs {
				z := r.zones[id]
				set := ident("z", &z.Meta)
				if z.AntiSpoof {
					c.Guards = append(c.Guards, fmt.Sprintf("iifname @%s fib saddr . iif oif missing counter drop", set))
				}
				if chain == "forward" && z.IntraZone {
					c.Tail = append(c.Tail, fmt.Sprintf("iifname @%s oifname @%s accept", set, set))
				}
				if z.DefaultAction != "accept" {
					c.TailOpen = append(c.TailOpen, fmt.Sprintf("iifname @%s counter %s", set, z.DefaultAction))
				}
			}
		}
		f.Chains[chain] = c
	}
	nat := effective[*model.NATRule](r, model.KindNATRule)
	sort.SliceStable(nat, func(i, j int) bool { return nat[i].Sequence < nat[j].Sequence })
	f.Pre, f.Post = r.nat(nat)
	f.Pre = append(f.Pre, r.balance()...)
	return f, r.err()
}

// haInput is what an HA pair member accepts ahead of the operator's rules,
// so that a default-deny policy cannot split the pair: VRRP adverts on the
// pair's interfaces and conntrackd's sync from the partner's sync address.
func haInput(ha harender.Result) []string {
	devs := make([]string, 0, len(ha.Interfaces))
	for _, d := range ha.Interfaces {
		devs = append(devs, quote(d))
	}
	fam := "ip"
	if isV6(ha.Peer) {
		fam = "ip6"
	}
	var out []string
	if len(devs) > 0 {
		out = append(out, fmt.Sprintf("iifname { %s } meta l4proto 112 counter accept comment \"ha: vrrp\"", strings.Join(devs, ", ")))
	}
	return append(out, fmt.Sprintf("iifname %s %s saddr %s udp dport %d counter accept comment \"ha: state sync\"",
		quote(ha.SyncInterface), fam, ha.Peer, harender.SyncPort))
}

// serviceInput lets clients reach the node's services on the interfaces
// each one serves, and from the extra networks the resolver and the NTP
// service name.
func serviceInput(o svcrender.Openings) []string {
	var out []string
	set := func(ifaces []string) string {
		q := make([]string, len(ifaces))
		for i, d := range ifaces {
			q[i] = quote(d)
		}
		return "{ " + strings.Join(q, ", ") + " }"
	}
	on := func(ifaces []string, match, what string) {
		if len(ifaces) > 0 {
			out = append(out, fmt.Sprintf("iifname %s %s counter accept comment \"service: %s\"", set(ifaces), match, what))
		}
	}
	from := func(nets []string, match, what string) {
		var v4, v6 []string
		for _, n := range nets {
			if isV6(n) {
				v6 = append(v6, n)
			} else {
				v4 = append(v4, n)
			}
		}
		for _, f := range []struct {
			fam  string
			list []string
		}{{"ip", v4}, {"ip6", v6}} {
			if len(f.list) > 0 {
				out = append(out, fmt.Sprintf("%s saddr { %s } %s counter accept comment \"service: %s\"", f.fam, strings.Join(f.list, ", "), match, what))
			}
		}
	}
	on(o.DHCP4, "udp dport 67", "dhcp")
	on(o.DHCP6, "udp dport 547", "dhcpv6")
	// SNMP on the agent's interfaces, from the monitoring networks only.
	if len(o.SNMP) > 0 {
		var v4, v6 []string
		for _, n := range o.SNMPFrom {
			if isV6(n) {
				v6 = append(v6, n)
			} else {
				v4 = append(v4, n)
			}
		}
		for _, f := range []struct {
			fam  string
			list []string
		}{{"ip", v4}, {"ip6", v6}} {
			if len(f.list) > 0 {
				out = append(out, fmt.Sprintf("iifname %s %s saddr { %s } udp dport 161 counter accept comment \"service: snmp\"",
					set(o.SNMP), f.fam, strings.Join(f.list, ", ")))
			}
		}
	}
	// The answers of the servers a relay passes requests to.
	var relay4, relay6 []string
	for _, srv := range o.RelayFrom {
		if isV6(srv) {
			relay6 = append(relay6, srv)
		} else {
			relay4 = append(relay4, srv)
		}
	}
	from(relay4, "udp dport 67", "dhcp relay")
	from(relay6, "udp dport 547", "dhcpv6 relay")
	// Neighbour discovery and router solicitations, without which the
	// advertised prefixes are useless.
	on(o.RA, "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }", "ipv6 neighbour discovery")
	on(o.DNS, "meta l4proto { tcp, udp } th dport 53", "dns")
	from(o.DNSFrom, "meta l4proto { tcp, udp } th dport 53", "dns")
	on(o.NTP, "udp dport 123", "ntp")
	from(o.NTPFrom, "udp dport 123", "ntp")
	if h := o.HA; h != nil && len(h.Ports) > 0 {
		fam := "ip"
		if isV6(h.Peer) {
			fam = "ip6"
		}
		ports := make([]string, len(h.Ports))
		for i, p := range h.Ports {
			ports[i] = fmt.Sprint(p)
		}
		out = append(out, fmt.Sprintf("iifname %s %s saddr %s tcp dport { %s } counter accept comment \"service: dhcp failover\"",
			quote(h.Interface), fam, h.Peer, strings.Join(ports, ", ")))
	}
	return out
}

// Policy returns the firewall policy in effect on the node, or nil.
func Policy(st *confstore.State, opt Options) *model.FirewallPolicy {
	return (&renderer{st: st, opt: opt}).policy()
}

func (r *renderer) take() string {
	out := r.b.String()
	r.b.Reset()
	return out
}

func (r *renderer) takeLines() []string {
	var out []string
	for _, l := range strings.Split(r.take(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (r *renderer) policyFragment(p *model.FirewallPolicy) PolicyFragment {
	pf := PolicyFragment{DefaultDeny: p.DefaultDeny, SynFlood: p.SynFloodGuard}
	if p.AllowEstablished {
		pf.Stateful = append(pf.Stateful, "ct state established,related accept")
	}
	if p.DropInvalid {
		pf.Stateful = append(pf.Stateful, "ct state invalid drop")
	}
	if p.AllowLoopback {
		pf.Baseline = append(pf.Baseline, `iifname "lo" accept`)
	}
	if p.AllowICMP {
		pf.Baseline = append(pf.Baseline, "meta l4proto { icmp, icmpv6 } accept")
	}
	if tcp := uniq(append(intList(r.opt.ProtectedTCPPorts), p.AllowTCPPorts...)); len(tcp) > 0 {
		pf.Baseline = append(pf.Baseline, fmt.Sprintf("tcp dport { %s } accept", strings.Join(tcp, ", ")))
	}
	if udp := uniq(append([]string(nil), p.AllowUDPPorts...)); len(udp) > 0 {
		pf.Baseline = append(pf.Baseline, fmt.Sprintf("udp dport { %s } accept", strings.Join(udp, ", ")))
	}
	// One timeout object per address family: an inet table needs the layer 3
	// protocol spelled out.
	timeout := func(name, proto, state, value string) {
		d, err := time.ParseDuration(value)
		if err != nil || d < time.Second {
			return
		}
		for _, fam := range [][2]string{{"ip", "ipv4"}, {"ip6", "ipv6"}} {
			obj := fmt.Sprintf("%s_%s", name, fam[1])
			pf.Timeouts += fmt.Sprintf("\tct timeout %s {\n\t\tprotocol %s\n\t\tl3proto %s\n\t\tpolicy = { %s : %d }\n\t}\n",
				obj, proto, fam[0], state, int(d.Seconds()))
			pf.Tracking = append(pf.Tracking, fmt.Sprintf("meta nfproto %s meta l4proto %s ct timeout set %s", fam[1], proto, quote(obj)))
		}
	}
	timeout("tcp_established", "tcp", "established", p.TCPEstablished)
	timeout("udp_stream", "udp", "replied", p.UDPTimeout)
	if p.LogDrops && p.DefaultDeny {
		pf.LogPrefix = p.LogPrefix
		if pf.LogPrefix == "" {
			pf.LogPrefix = "testudo drop"
		}
	}
	return pf
}

// Logged packets go to a netfilter log group, which the engine reads and
// exports, not to the kernel log. The prefix names the rule that logged.
const (
	LogGroup      = 7 // nflog.Group
	LogRulePrefix = "t:"
	LogDropPrefix = "t:drop:"
)

const synFloodLine = "tcp flags & (fin | syn | rst | ack) == syn limit rate over 200/second burst 400 packets counter drop"

// Assemble combines the model's fragments with the running side into the
// text nft loads. With run == nil the model's own firewall policy decides
// defaults and baseline; with it, the running policy does.
func Assemble(f Fragments, run *Running) string {
	var b strings.Builder
	if run != nil && run.DropLegacyTables {
		b.WriteString("table inet testudo_filter\ndelete table inet testudo_filter\n")
		b.WriteString("table ip testudo_nat\ndelete table ip testudo_nat\n")
	}
	// Replace-the-table idiom: create (no-op if present), delete, define.
	// nft applies one file as a single transaction.
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", Table, Table)
	if !f.HasPolicy {
		return b.String()
	}
	body := assembleBody(f)
	sum := sha256.Sum256([]byte(body))
	// The generation set carries a hash of the content, which is how a later
	// check tells whether the kernel still holds exactly this ruleset.
	fmt.Fprintf(&b, "table inet %s {\n\tset %s {\n\t\ttype ifname\n\t}\n%s}\n", Table, GenerationSet(sum), body)
	return b.String()
}

// GenerationSet names the marker set for a body hash.
func GenerationSet(sum [32]byte) string { return "gen_" + hex.EncodeToString(sum[:])[:16] }

// Generation returns the marker set name Assemble would use.
func Generation(f Fragments) string {
	return GenerationSet(sha256.Sum256([]byte(assembleBody(f))))
}

func assembleBody(f Fragments) string {
	var b strings.Builder
	b.WriteString(f.Sets)
	b.WriteString(f.Policy.Timeouts)
	deny := f.Policy.DefaultDeny
	for _, chain := range []string{"input", "forward", "output"} {
		verdict := "accept"
		if deny && chain != "output" {
			verdict = "drop"
		}
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority filter; policy %s;\n", chain, chain, verdict)
		w := func(lines ...string) {
			for _, l := range lines {
				fmt.Fprintf(&b, "\t\t%s\n", l)
			}
		}
		c := f.Chains[chain]
		// Timeouts are attached before anything accepts the packet.
		w(f.Policy.Tracking...)
		if chain != "output" {
			w(f.Policy.Stateful...)
			if chain == "input" {
				// Loopback first, then the guards, then the rest of the
				// baseline, so anti-spoofing sees traffic before ICMP and
				// the open ports accept it.
				var rest []string
				for _, l := range f.Policy.Baseline {
					if strings.HasPrefix(l, `iifname "lo"`) {
						w(l)
					} else {
						rest = append(rest, l)
					}
				}
				w(c.Guards...)
				if f.Policy.SynFlood {
					w(synFloodLine)
				}
				w(rest...)
				c.Guards = nil
			}
			w(c.Guards...)
		}
		if chain == "forward" {
			// Connections a destination NAT rule accepted are forwarded.
			w("ct status dnat accept")
		}
		w(c.Rules...)
		if chain != "output" {
			w(c.Tail...)
			if !deny {
				w(c.TailOpen...)
			}
			if f.Policy.LogPrefix != "" {
				w(fmt.Sprintf("limit rate 10/second log prefix %s group %d", quote(LogDropPrefix+chain), LogGroup))
			}
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	for _, l := range f.Pre {
		fmt.Fprintf(&b, "\t\t%s\n", l)
	}
	b.WriteString("\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	for _, l := range f.Post {
		fmt.Fprintf(&b, "\t\t%s\n", l)
	}
	b.WriteString("\t}\n")
	return b.String()
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
		for _, e := range r.opt.Elements[a.ID] {
			if isV6(e) {
				v6 = append(v6, e)
			} else {
				v4 = append(v4, e)
			}
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
		return "meta l4proto icmpv6"
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
		tail = append(tail, fmt.Sprintf("log prefix %s group %d", quote(LogRulePrefix+fr.ID), LogGroup))
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

func (r *renderer) nat(rules []*model.NATRule) (pre, post []string) {
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
	return pre, post
}

// KernelBackends lists, per pool id, the backends of services balanced in
// the packet filter on this node, for the health monitor.
func KernelBackends(st *confstore.State, opt Options) map[string]*model.LBBackendPool {
	r := &renderer{st: st, opt: opt}
	pools := map[string]*model.LBBackendPool{}
	for _, p := range effective[*model.LBBackendPool](r, model.KindLBBackendPool) {
		pools[p.ID] = p
	}
	out := map[string]*model.LBBackendPool{}
	for _, s := range effective[*model.LBService](r, model.KindLBService) {
		if p := pools[s.DefaultPool.ID]; s.Enabled && s.Mode == "kernel" && p != nil {
			out[p.ID] = p
		}
	}
	return out
}

// balance renders the services that are balanced in the packet filter: one
// destination NAT rule per service and address family that spreads new
// connections over the pool's backends by weight. A sticky pool hashes the
// client address instead of counting, so a client keeps its backend as long
// as the set of backends does not change. Draining and unhealthy backends
// are left out; connections they already have continue, because an
// established connection keeps its translation.
//
// Replies have to come back through this node: the client's address is
// preserved, so the backends need a route to it via the firewall.
func (r *renderer) balance() []string {
	pools := map[string]*model.LBBackendPool{}
	for _, p := range effective[*model.LBBackendPool](r, model.KindLBBackendPool) {
		pools[p.ID] = p
	}
	var out []string
	for _, s := range effective[*model.LBService](r, model.KindLBService) {
		if !s.Enabled || s.Mode != "kernel" {
			continue
		}
		fail := func(format string, a ...any) {
			r.errs = append(r.errs, fmt.Sprintf("lb_service %q: ", s.Name)+fmt.Sprintf(format, a...))
		}
		if s.Protocol != "tcp" && s.Protocol != "udp" {
			fail("kernel mode balances tcp and udp; %s needs the proxy", s.Protocol)
			continue
		}
		p := pools[s.DefaultPool.ID]
		if p == nil {
			fail("kernel mode needs a fallback pool that is in effect on this node")
			continue
		}
		if p.Algorithm != "weighted_round_robin" {
			fail("pool %q: %s is not available; use weighted round robin", p.Name, strings.ReplaceAll(p.Algorithm, "_", " "))
			continue
		}
		if p.ProxyProtocol != "" {
			fail("pool %q: the PROXY protocol needs the proxy; kernel mode preserves the client address by itself", p.Name)
			continue
		}
		type target struct {
			addr, port string
			weight     int
		}
		byFam := map[bool][]target{}
		for _, b := range p.Backends {
			host, port, err := net.SplitHostPort(b.Address)
			if err != nil || net.ParseIP(host) == nil {
				fail("pool %q: kernel mode needs backends by IP address, %q is not one", p.Name, b.Address)
				continue
			}
			if b.Drain || r.opt.BackendDown[b.Address] {
				continue
			}
			w := b.Weight
			if w == 0 {
				w = 1
			}
			byFam[isV6(host)] = append(byFam[isV6(host)], target{host, port, w})
		}
		for _, v6 := range []bool{false, true} {
			targets := byFam[v6]
			if len(targets) == 0 || (s.Address != "" && isV6(s.Address) != v6) {
				continue
			}
			fam := "ip"
			if v6 {
				fam = "ip6"
			}
			total, slots := 0, make([]string, 0, len(targets))
			for _, t := range targets {
				key := strconv.Itoa(total)
				if t.weight > 1 {
					key += "-" + strconv.Itoa(total+t.weight-1)
				}
				slots = append(slots, fmt.Sprintf("%s : %s . %s", key, t.addr, t.port))
				total += t.weight
			}
			pick := fmt.Sprintf("numgen inc mod %d", total)
			if p.Sticky {
				pick = fmt.Sprintf("jhash %s saddr mod %d", fam, total)
			}
			match := "meta nfproto ipv4"
			if v6 {
				match = "meta nfproto ipv6"
			}
			if s.Address != "" {
				match = famAddr("daddr", s.Address)
			}
			parts := []string{r.zoneMatch("iifname", s.Zone), match, fmt.Sprintf("%s dport %d", s.Protocol, s.Port), "counter",
				fmt.Sprintf("dnat %s addr . port to %s map { %s }", fam, pick, strings.Join(slots, ", ")), "comment " + quote(s.ID)}
			if parts[0] == "" {
				parts = parts[1:]
			}
			out = append(out, strings.Join(parts, " "))
		}
	}
	return out
}

// access renders the standing access policies: a peer bound to a user may
// reach a resource when a policy names that user, one of the user's or the
// peer's groups, or everyone. The source is the peer's own tunnel address,
// so the permission follows the identity, not a network.
//
// Policies that need an approval or a second factor grant nothing by
// themselves; access under them is given for a limited time by the access
// manager when a request is approved.
func (r *renderer) access() []string {
	resources := map[string]*model.AccessResource{}
	for _, res := range effective[*model.AccessResource](r, model.KindAccessResource) {
		resources[res.ID] = res
	}
	userGroups := map[string]map[string]bool{}
	for _, u := range effective[*model.User](r, model.KindUser) {
		if u.Disabled {
			continue
		}
		userGroups[u.ID] = map[string]bool{}
		for _, g := range u.Groups {
			userGroups[u.ID][g.ID] = true
		}
	}
	devices := map[string]string{}
	for _, t := range effective[*model.WGTunnel](r, model.KindWGTunnel) {
		if t.Enabled {
			devices[t.ID] = t.Device
		}
	}
	peers := effective[*model.WGPeer](r, model.KindWGPeer)
	policies := effective[*model.AccessPolicy](r, model.KindAccessPolicy)
	sort.SliceStable(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })

	var out []string
	// emit lets the peers allowed reach the resource: one rule per tunnel
	// device, matching the peers' own tunnel addresses.
	emit := func(res *model.AccessResource, allowed func(p *model.WGPeer, groups map[string]bool) bool, comment string) {
		// device -> family -> source addresses
		src := map[string]map[bool][]string{}
		for _, p := range peers {
			dev := devices[p.Tunnel.ID]
			member, known := userGroups[p.User.ID]
			if !p.Enabled || dev == "" || !known {
				continue // no identity, no access: an unbound peer matches nothing
			}
			if !allowed(p, member) {
				continue
			}
			for _, a := range p.AllowedIPs {
				ip, n, err := net.ParseCIDR(a)
				if err != nil {
					continue
				}
				if ones, bits := n.Mask.Size(); ones != bits {
					continue // only the peer's own addresses identify it
				}
				if src[dev] == nil {
					src[dev] = map[bool][]string{}
				}
				src[dev][isV6(a)] = append(src[dev][isV6(a)], ip.String())
			}
		}
		var tail []string
		if res.Protocol != "any" {
			tail = append(tail, "meta l4proto "+res.Protocol)
		} else if res.Ports != "" {
			tail = append(tail, "meta l4proto { tcp, udp }")
		}
		if res.Ports != "" {
			tail = append(tail, "th dport { "+res.Ports+" }")
		}
		tail = append(tail, "counter accept", "comment "+quote(comment))
		v6 := isV6(res.Target)
		fam := "ip"
		if v6 {
			fam = "ip6"
		}
		for _, dev := range sortedKeys(src, func(s string) string { return s }) {
			addrs := uniq(src[dev][v6])
			if len(addrs) == 0 {
				continue
			}
			out = append(out, strings.Join(append([]string{"iifname " + quote(dev),
				fmt.Sprintf("%s saddr { %s }", fam, strings.Join(addrs, ", ")), fam + " daddr " + res.Target}, tail...), " "))
		}
	}
	for _, pol := range policies {
		res := resources[pol.Resource.ID]
		if res == nil || pol.RequiresApproval || pol.RequiresMFA {
			continue
		}
		named := map[string]bool{}
		for _, u := range pol.Users {
			named[u.ID] = true
		}
		groups := map[string]bool{}
		for _, g := range pol.Groups {
			groups[g.ID] = true
		}
		emit(res, func(p *model.WGPeer, member map[string]bool) bool {
			allowed := pol.Everyone || named[p.User.ID]
			for g := range member {
				allowed = allowed || groups[g]
			}
			for _, g := range p.Groups {
				allowed = allowed || groups[g.ID]
			}
			return allowed
		}, pol.ID)
	}
	// Grants: what a request was given, for one user, until it ends. The
	// grant is removed when it ends; until then it is a rule like any other.
	grants := effective[*model.AccessGrant](r, model.KindAccessGrant)
	sort.SliceStable(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
	for _, g := range grants {
		res := resources[g.Resource.ID]
		if res == nil {
			continue
		}
		emit(res, func(p *model.WGPeer, _ map[string]bool) bool { return p.User.ID == g.User.ID }, g.ID)
	}
	return out
}

// dhcpv6ClientInput lets the answers of a provider's DHCPv6 server in on
// the upstream interfaces of the node's DHCPv6 clients: they come from the
// server's link-local address to the client's, which connection tracking
// cannot match to the multicast request.
func (r *renderer) dhcpv6ClientInput() []string {
	var devs []string
	for _, c := range effective[*model.DHCPv6Client](r, model.KindDHCPv6Client) {
		if c.Enabled {
			devs = append(devs, quote(c.Interface))
		}
	}
	if len(devs) == 0 {
		return nil
	}
	sort.Strings(devs)
	return []string{fmt.Sprintf("iifname { %s } ip6 saddr fe80::/10 udp sport 547 udp dport 546 counter accept comment \"dhcpv6 client\"",
		strings.Join(devs, ", "))}
}
