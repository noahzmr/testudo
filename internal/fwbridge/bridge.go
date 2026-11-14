// Package fwbridge enforces the configuration model's packet-filter objects
// through the existing firewall manager. It is the apply stage that makes
// the model the place where firewall rules are edited, while the manager
// keeps doing what it already does well: atomic netlink applies through the
// privileged helper, drift repair, counters, and the rules owned by
// WireGuard peers and access grants.
//
// The manager's rule format is narrower than the model (one interface, one
// network and one port range per rule), so one model rule expands into
// several. What cannot be expressed at all is refused in the dry run with a
// message naming the object, never dropped silently. internal/fwrender is
// the renderer without those limits; it takes over once nft can be driven
// from the privileged side.
package fwbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

// maxExpansion bounds how many kernel rules one model rule may become.
const maxExpansion = 256

// Manager is the part of the firewall manager the bridge needs.
type Manager interface {
	ReplaceOwned(owner string, set firewall.OwnedSet, dryRun bool) error
	Reconcile() firewall.Drift
}

// Stage implements confapply.Stage.
type Stage struct {
	Manager Manager
	// SiteID and NodeID select which objects apply here. Empty values match
	// only global objects.
	SiteID, NodeID string

	// Locate, when set, finds the site and node for the state being rendered
	// and replaces SiteID and NodeID. It lets the stage pick up the node's
	// own record as soon as it is created.
	Locate func(*confstore.State) (siteID, nodeID string)

	// enforced is set once the stage has put model rules into the policy;
	// only then does a failed kernel check concern the model.
	enforced bool
}

func (s *Stage) Name() string { return "packet-filter" }

type unsupported struct{ msgs []string }

func (u *unsupported) add(e model.Entity, format string, a ...any) {
	u.msgs = append(u.msgs, fmt.Sprintf("%s %q: %s", e.Kind(), e.GetMeta().Name, fmt.Sprintf(format, a...)))
}

type view struct {
	st      *confstore.State
	s       *Stage
	zoneIfs map[string][]string
	aliases map[string]*model.Alias
	tunnels map[string]*model.WGTunnel
	zones   map[string]*model.Zone
	bad     unsupported
}

func each[T model.Entity](v *view, kind model.Kind, fn func(T)) {
	for _, e := range v.st.List(kind) {
		if !model.AppliesTo(e, v.s.SiteID, v.s.NodeID) {
			continue
		}
		eff, _, err := model.Effective(e, v.s.SiteID, v.s.NodeID)
		if err != nil {
			v.bad.add(e, "%v", err)
			continue
		}
		fn(eff.(T))
	}
}

func isV6(s string) bool {
	ip := net.ParseIP(strings.SplitN(s, "/", 2)[0])
	return ip != nil && ip.To4() == nil
}

// content flattens an alias. ok is false for aliases filled at run time.
func (v *view) content(a *model.Alias, seen map[string]bool) (out []string, ok bool) {
	if a == nil || seen[a.ID] {
		return nil, true
	}
	seen[a.ID] = true
	if a.Type == "url_table" || a.Type == "geoip" {
		return nil, false
	}
	out = append(out, a.Entries...)
	for _, m := range a.Members {
		sub, subOK := v.content(v.aliases[m.ID], seen)
		if !subOK {
			return nil, false
		}
		out = append(out, sub...)
	}
	return out, true
}

func (v *view) addrs(e model.Entity, refs []model.Ref[model.Alias], nets []string) []string {
	out := append([]string(nil), nets...)
	for _, r := range refs {
		a := v.aliases[r.ID]
		if a == nil {
			continue
		}
		c, ok := v.content(a, map[string]bool{})
		if !ok {
			v.bad.add(e, "alias %q is filled at run time (%s), which the running packet filter cannot match yet", a.Name, a.Type)
		}
		out = append(out, c...)
	}
	if len(refs)+len(nets) > 0 && len(out) == 0 {
		v.bad.add(e, "its address aliases are empty, so it would match nothing")
	}
	if len(out) == 0 {
		return []string{""}
	}
	sort.Strings(out)
	return out
}

func (v *view) ifaces(e model.Entity, z model.Ref[model.Zone]) []string {
	if z.ID == "" {
		return []string{""}
	}
	ifs := v.zoneIfs[z.ID]
	if len(ifs) == 0 {
		name := z.ID
		if zone := v.zones[z.ID]; zone != nil {
			name = zone.Name
		}
		v.bad.add(e, "zone %q has no interface on this node", name)
		return nil
	}
	return ifs
}

func portRange(e model.Entity, v *view, p string) (lo, hi uint16) {
	a, b, isRange := strings.Cut(p, "-")
	x, err := strconv.Atoi(a)
	if err != nil {
		v.bad.add(e, "bad port %q", p)
		return 0, 0
	}
	lo = uint16(x)
	if isRange {
		y, _ := strconv.Atoi(b)
		hi = uint16(y)
	}
	return lo, hi
}

// Render translates the model into the manager's terms. The artifact is the
// JSON of a firewall.OwnedSet.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	if s.Locate != nil {
		s.SiteID, s.NodeID = s.Locate(st)
	}
	v := &view{st: st, s: s, zoneIfs: map[string][]string{}, aliases: map[string]*model.Alias{},
		tunnels: map[string]*model.WGTunnel{}, zones: map[string]*model.Zone{}}
	each(v, model.KindZone, func(z *model.Zone) { v.zones[z.ID] = z })
	each(v, model.KindAlias, func(a *model.Alias) { v.aliases[a.ID] = a })
	each(v, model.KindInterface, func(i *model.Interface) {
		if i.Enabled && i.Zone.ID != "" {
			v.zoneIfs[i.Zone.ID] = append(v.zoneIfs[i.Zone.ID], i.Device)
		}
	})
	each(v, model.KindWGTunnel, func(t *model.WGTunnel) {
		v.tunnels[t.ID] = t
		if t.Enabled {
			v.zoneIfs[t.Zone.ID] = append(v.zoneIfs[t.Zone.ID], t.Device)
		}
	})
	for _, ifs := range v.zoneIfs {
		sort.Strings(ifs)
	}

	var set firewall.OwnedSet

	// The most specific firewall policy decides the defaults.
	var policy *model.FirewallPolicy
	rank := map[string]int{"global": 1, "site": 2, "node": 3}
	each(v, model.KindFirewallPolicy, func(p *model.FirewallPolicy) {
		if policy == nil || rank[p.Scope.Level()] > rank[policy.Scope.Level()] {
			policy = p
		}
	})
	if policy != nil {
		if policy.SynFloodGuard {
			v.bad.add(policy, "the SYN flood guard is not available in the running packet filter yet")
		}
		toPorts := func(in []string) []uint16 {
			var out []uint16
			for _, p := range in {
				lo, hi := portRange(policy, v, p)
				if hi != 0 {
					v.bad.add(policy, "always-open port %q is a range; list single ports", p)
				}
				out = append(out, lo)
			}
			return out
		}
		enforce := policy.DefaultDeny
		set.Enforce = &enforce
		set.Baseline = &netops.FilterBaseline{AllowEstablished: policy.AllowEstablished, DropInvalid: policy.DropInvalid,
			AllowLoopback: policy.AllowLoopback, AllowICMP: policy.AllowICMP, AllowTCPPorts: toPorts(policy.AllowTCPPorts),
			AllowUDPPorts: toPorts(policy.AllowUDPPorts), LogDrops: policy.LogDrops, LogPrefix: policy.LogPrefix}
	}
	for _, id := range sortedIDs(v.zones) {
		z := v.zones[id]
		if z.AntiSpoof {
			v.bad.add(z, "the reverse-path check is not available in the running packet filter yet")
		}
		if z.IntraZone {
			for _, a := range v.zoneIfs[id] {
				for _, b := range v.zoneIfs[id] {
					set.Rules = append(set.Rules, netops.FilterRule{Chain: "forward", Action: "accept", InIface: a, OutIface: b,
						Comment: "model:" + z.ID + " traffic inside zone " + z.Name})
				}
			}
		}
	}

	var rules []*model.FilterRule
	each(v, model.KindFilterRule, func(r *model.FilterRule) {
		if r.Enabled {
			rules = append(rules, r)
		}
	})
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Sequence < rules[j].Sequence })
	chains := map[string]string{"in": "input", "out": "output", "forward": "forward"}
	for _, r := range rules {
		chain := chains[r.Direction]
		if r.Mark != 0 {
			v.bad.add(r, "setting a firewall mark is not available in the running packet filter yet")
		}
		in, out := []string{""}, []string{""}
		if chain != "output" {
			in = v.ifaces(r, r.SourceZone)
		}
		if chain != "input" {
			out = v.ifaces(r, r.DestinationZone)
		}
		if t := v.tunnels[r.Tunnel.ID]; t != nil {
			in = []string{t.Device}
		}
		ports := append([]string(nil), r.Ports...)
		for _, pa := range r.PortAliases {
			c, _ := v.content(v.aliases[pa.ID], map[string]bool{})
			ports = append(ports, c...)
		}
		if len(ports) == 0 {
			ports = []string{""}
		}
		protos := []string{r.Protocol}
		switch {
		case r.Protocol == "any" && ports[0] != "":
			protos = []string{"tcp", "udp"}
		case r.Protocol == "any":
			protos = []string{""}
		case ports[0] != "" && r.Protocol != "tcp" && r.Protocol != "udp":
			v.bad.add(r, "ports need protocol tcp, udp or any")
		}
		srcs := v.addrs(r, r.Source, r.SourceNets)
		dsts := v.addrs(r, r.Destination, r.DestinationNets)
		n := len(in) * len(out) * len(srcs) * len(dsts) * len(ports) * len(protos)
		if n > maxExpansion {
			v.bad.add(r, "expands to %d kernel rules (limit %d); split it or narrow its aliases", n, maxExpansion)
			continue
		}
		for _, i := range in {
			for _, o := range out {
				for _, src := range srcs {
					for _, dst := range dsts {
						// One kernel rule matches one address family.
						if src != "" && dst != "" && isV6(src) != isV6(dst) {
							continue
						}
						for _, proto := range protos {
							for _, p := range ports {
								fr := netops.FilterRule{Chain: chain, Action: r.Action, Proto: proto, InIface: i, OutIface: o,
									SrcCIDR: src, DstCIDR: dst, CtState: strings.Join(r.States, ","), Log: r.Log,
									RateLimit: r.RateLimit, Comment: "model:" + r.ID + " " + r.Name}
								if p != "" {
									fr.Port, fr.PortEnd = portRange(r, v, p)
								}
								set.Rules = append(set.Rules, fr)
							}
						}
					}
				}
			}
		}
	}

	var nat []*model.NATRule
	each(v, model.KindNATRule, func(n *model.NATRule) {
		if n.Enabled {
			nat = append(nat, n)
		}
	})
	sort.SliceStable(nat, func(i, j int) bool { return nat[i].Sequence < nat[j].Sequence })
	for _, n := range nat {
		switch n.Type {
		case "dnat":
			switch {
			case isV6(n.TranslateTo) || strings.Contains(n.TranslateTo, "/"):
				v.bad.add(n, "the running packet filter forwards to a single IPv4 address only")
			case n.Protocol == "any" || n.Port == "" || strings.Contains(n.Port, "-") || strings.Contains(n.TranslatePort, "-"):
				v.bad.add(n, "a port forward needs protocol tcp or udp and single ports")
			case n.Reflection || n.Destination != "" || len(n.SourceNets) > 0:
				v.bad.add(n, "reflection and matching on source or original destination are not available in the running packet filter yet")
			default:
				wan, _ := portRange(n, v, n.Port)
				lan := wan
				if n.TranslatePort != "" {
					lan, _ = portRange(n, v, n.TranslatePort)
				}
				for _, i := range v.ifaces(n, n.Zone) {
					set.Forwards = append(set.Forwards, netops.PortForward{Proto: n.Protocol, WANPort: wan, LANIP: n.TranslateTo,
						LANPort: lan, InIface: i, Comment: "model:" + n.ID + " " + n.Name})
					// A forward is useless if the filter then drops the
					// translated connection, so the matching accept comes
					// with it and goes with it.
					set.Rules = append(set.Rules, netops.FilterRule{Chain: "forward", Action: "accept", Proto: n.Protocol,
						Port: lan, InIface: i, DstCIDR: n.TranslateTo, Comment: "model:" + n.ID + " forwarded by " + n.Name})
				}
			}
		case "masquerade":
			if n.Zone.ID == "" || n.Destination != "" || n.Port != "" || n.Protocol != "any" {
				v.bad.add(n, "masquerade needs an outgoing zone and matches by source network only")
				continue
			}
			srcs := n.SourceNets
			if len(srcs) == 0 {
				v.bad.add(n, "masquerade needs at least one source network")
			}
			for _, i := range v.ifaces(n, n.Zone) {
				for _, src := range srcs {
					if isV6(src) {
						v.bad.add(n, "IPv6 masquerade is not available in the running packet filter yet")
						continue
					}
					set.Masquerades = append(set.Masquerades, netops.Masquerade{OutIface: i, SrcCIDR: src,
						Comment: "model:" + n.ID + " " + n.Name})
				}
			}
		default:
			v.bad.add(n, "%s is not available in the running packet filter yet", strings.ReplaceAll(n.Type, "_", "-"))
		}
	}

	if len(v.bad.msgs) > 0 {
		return nil, errors.New(strings.Join(v.bad.msgs, "; "))
	}
	return json.MarshalIndent(set, "", " ")
}

func sortedIDs[V any](m map[string]V) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *Stage) do(artifact []byte, dryRun bool) error {
	var set firewall.OwnedSet
	if err := json.Unmarshal(artifact, &set); err != nil {
		return err
	}
	empty := len(set.Rules)+len(set.Forwards)+len(set.Masquerades) == 0 && set.Enforce == nil
	if s.Manager == nil {
		if empty {
			return nil // nothing to enforce, and nothing to enforce it with
		}
		return errors.New("the packet filter is not available on this node (no network privileges)")
	}
	err := s.Manager.ReplaceOwned(firewall.OwnerModel, set, dryRun)
	if empty && errors.Is(err, firewall.ErrWritesDisabled) {
		return nil // read-only node without model rules: nothing to do
	}
	if err == nil && !dryRun {
		s.enforced = !empty
	}
	return err
}

// Check validates the resulting policy without touching the kernel.
func (s *Stage) Check(_ context.Context, artifact []byte) error { return s.do(artifact, true) }

// Apply replaces the model's rules in the running policy in one atomic step.
func (s *Stage) Apply(_ context.Context, artifact []byte) error { return s.do(artifact, false) }

// Healthy reports whether the kernel matches the policy after the apply.
func (s *Stage) Healthy(context.Context) error {
	if s.Manager == nil || !s.enforced {
		return nil
	}
	if d := s.Manager.Reconcile(); d.Error != "" {
		return errors.New(d.Error)
	}
	return nil
}
