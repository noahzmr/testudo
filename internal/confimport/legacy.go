// Package confimport translates the state Testudo kept before the
// configuration model existed (firewall.json, live WireGuard devices) into
// model objects. Users of users.json move by themselves when the daemon
// starts (internal/engine), with their credentials. The translation is one-way and produces
// ordinary ops, so the result goes through validation, review and apply like
// any other change.
package confimport

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

// Tunnel is a live WireGuard device with the addresses of its interface.
type Tunnel struct {
	netops.WGDeviceInfo
	Addresses []string
	// PeerNames maps a peer public key to its stored display name.
	PeerNames map[string]string
}

// Legacy is everything the import reads. Nil or empty parts are skipped.
type Legacy struct {
	Hostname    string
	NodeAddress string // address of this node for the cluster record
	Firewall    *firewall.Policy
	Tunnels     []Tunnel
}

// Result is the outcome of a translation.
type Result struct {
	Ops []confstore.Op
	// Notes lists what could not be carried over and why. Nothing is
	// dropped silently.
	Notes []string
	// Remaining is the firewall policy without the rules that are now model
	// objects: what could not be translated, and everything owned by
	// WireGuard peers and access grants. Writing it back in place of the
	// original keeps a rule from existing twice. Nil without a policy.
	Remaining *firewall.Policy
}

var (
	rateRe   = regexp.MustCompile(`^[1-9][0-9]{0,8}/(second|minute|hour|day)$`)
	nameSafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
)

type builder struct {
	res   Result
	newID func() string
	names map[string]bool
	zones map[string]string // interface name -> zone id
	site  string
	node  string
}

func (b *builder) add(e model.Entity) string {
	m := e.GetMeta()
	m.ID = b.newID()
	if m.Scope == "" {
		m.Scope = model.ScopeGlobal
	}
	// Names must be unique per kind; disambiguate instead of failing.
	base, key := m.Name, string(e.Kind())+"/"+m.Name
	for i := 2; b.names[key]; i++ {
		m.Name = fmt.Sprintf("%s-%d", base, i)
		key = string(e.Kind()) + "/" + m.Name
	}
	b.names[key] = true
	obj, _ := json.Marshal(e)
	b.res.Ops = append(b.res.Ops, confstore.Op{Type: confstore.OpCreate, Kind: e.Kind(), ID: m.ID, Object: obj})
	return m.ID
}

func (b *builder) note(format string, a ...any) {
	b.res.Notes = append(b.res.Notes, fmt.Sprintf(format, a...))
}

func safeName(s string) string {
	s = strings.Trim(nameSafe.ReplaceAllString(s, "-"), "-._")
	if s == "" {
		s = "unnamed"
	}
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

// zone returns the zone standing in for a legacy interface match, creating
// the zone and the node's interface record on first use. The old rules match
// interface names directly; the model matches zones.
func (b *builder) zone(iface string) model.Ref[model.Zone] {
	if iface == "" {
		return model.Ref[model.Zone]{}
	}
	if id, ok := b.zones[iface]; ok {
		return model.Ref[model.Zone]{ID: id}
	}
	id := b.add(&model.Zone{Meta: model.Meta{Name: safeName("zone-" + iface),
		Description: "Imported: stands for interface " + iface}, DefaultAction: "drop"})
	b.zones[iface] = id
	if len(iface) <= 15 {
		b.add(&model.Interface{Meta: model.Meta{Name: safeName(iface), Scope: model.NodeScope(b.node)},
			Device: iface, Zone: model.Ref[model.Zone]{ID: id}, Enabled: true})
	}
	return model.Ref[model.Zone]{ID: id}
}

func ports(lo, hi uint16) []string {
	switch {
	case lo == 0:
		return nil
	case hi > lo:
		return []string{fmt.Sprintf("%d-%d", lo, hi)}
	}
	return []string{strconv.Itoa(int(lo))}
}

func portList(in []uint16) []string {
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = strconv.Itoa(int(p))
	}
	return out
}

func nets(cidr string) []string {
	if cidr == "" {
		return nil
	}
	return []string{cidr}
}

// Translate builds the ops. newID may be nil (random UUIDs).
func Translate(in Legacy, newID func() string) Result {
	if newID == nil {
		newID = confstore.NewID
	}
	b := &builder{newID: newID, names: map[string]bool{}, zones: map[string]string{}}

	// A single node is a cluster of one: one site, one node.
	host := in.Hostname
	if host == "" {
		host = "testudo"
	}
	addr := in.NodeAddress
	if net.ParseIP(addr) == nil {
		addr = "127.0.0.1"
	}
	b.site, b.node = newID(), newID()
	site := &model.Site{Meta: model.Meta{ID: b.site, Name: "default", Scope: model.ScopeGlobal,
		Description: "Imported: the site this node was installed at"}, Voter: model.Ref[model.ClusterNode]{ID: b.node}}
	node := &model.ClusterNode{Meta: model.Meta{ID: b.node, Name: safeName(host), Scope: model.ScopeGlobal},
		Site: model.Ref[model.Site]{ID: b.site}, Hostname: strings.ToLower(safeName(host)), Address: addr}
	for _, e := range []model.Entity{site, node} {
		obj, _ := json.Marshal(e)
		b.names[string(e.Kind())+"/"+e.GetMeta().Name] = true
		b.res.Ops = append(b.res.Ops, confstore.Op{Type: confstore.OpCreate, Kind: e.Kind(), ID: e.GetMeta().ID, Object: obj})
	}

	if in.Firewall != nil {
		b.firewall(in.Firewall)
	}
	for _, t := range in.Tunnels {
		b.tunnel(t)
	}
	return b.res
}

func (b *builder) firewall(p *firewall.Policy) {
	rest := p.Clone()
	rest.Rules, rest.Forwards, rest.Masquerades = nil, nil, nil
	defer func() { b.res.Remaining = &rest }()
	// Only what the operator made directly moves into the model. Rules of
	// other owners belong to the subsystems that will remove them again.
	direct := func(owner string) bool { return owner == "" || owner == "user" }
	bl := p.Baseline
	b.add(&model.FirewallPolicy{Meta: model.Meta{Name: "default", Description: "Imported from firewall.json"},
		DefaultDeny: p.Enforce, AllowEstablished: bl.AllowEstablished, DropInvalid: bl.DropInvalid,
		AllowLoopback: bl.AllowLoopback, AllowICMP: bl.AllowICMP, AllowTCPPorts: portList(bl.AllowTCPPorts),
		AllowUDPPorts: portList(bl.AllowUDPPorts), LogDrops: bl.LogDrops, LogPrefix: strings.TrimSpace(bl.LogPrefix)})

	for i, r := range p.Rules {
		label := fmt.Sprintf("rule %d (%s)", i+1, r.ID())
		if !direct(r.Owner) {
			rest.Rules = append(rest.Rules, r)
			continue
		}
		// A rule that is not translated stays in the policy and keeps working.
		keep := func() { rest.Rules = append(rest.Rules, r) }
		dir, ok := map[string]string{"input": "in", "output": "out", "forward": "forward"}[strings.ToLower(r.Chain)]
		if !ok {
			b.note("%s: unknown chain %q, not imported", label, r.Chain)
			keep()
			continue
		}
		action := strings.ToLower(r.Action)
		if action != "accept" && action != "drop" && action != "reject" {
			b.note("%s: action %q has no equivalent (a rule must decide); not imported", label, r.Action)
			keep()
			continue
		}
		proto := strings.ToLower(r.Proto)
		if proto == "" {
			proto = "any"
		}
		fr := &model.FilterRule{
			Meta:     model.Meta{Name: fmt.Sprintf("rule-%03d", i+1), Description: r.Comment},
			Sequence: (i + 1) * 10, Enabled: true, Action: action, Direction: dir, Protocol: proto,
			SourceZone: b.zone(r.InIface), DestinationZone: b.zone(r.OutIface),
			SourceNets: nets(r.SrcCIDR), DestinationNets: nets(r.DstCIDR),
			Ports: ports(r.Port, r.PortEnd), Log: r.Log, Owner: r.Owner,
		}
		for _, st := range strings.Split(r.CtState, ",") {
			if st = strings.TrimSpace(st); st != "" {
				fr.States = append(fr.States, st)
			}
		}
		switch {
		case r.RateLimit == "":
		case r.RateOver:
			// Without its threshold an "over" rule would match everything,
			// turning a brute-force guard into a blanket block.
			b.note("%s: matches traffic over the rate %q, which is not modelled yet; not imported, because without the threshold it would match all traffic", label, r.RateLimit)
			keep()
			continue
		case rateRe.MatchString(r.RateLimit):
			fr.RateLimit = r.RateLimit
		default:
			b.note("%s: rate limit %q has an unsupported form; not imported, because without the limit it would match more than intended", label, r.RateLimit)
			keep()
			continue
		}
		b.add(fr)
	}
	for i, f := range p.Forwards {
		if !direct(f.Owner) {
			rest.Forwards = append(rest.Forwards, f)
			continue
		}
		lan := f.LANPort
		if lan == 0 {
			lan = f.WANPort
		}
		b.add(&model.NATRule{Meta: model.Meta{Name: fmt.Sprintf("forward-%03d", i+1), Description: f.Comment},
			Enabled: true, Sequence: (i + 1) * 10, Type: "dnat", Zone: b.zone(f.InIface), Protocol: strings.ToLower(f.Proto),
			Port: strconv.Itoa(int(f.WANPort)), TranslateTo: f.LANIP, TranslatePort: strconv.Itoa(int(lan))})
	}
	for i, m := range p.Masquerades {
		if !direct(m.Owner) {
			rest.Masquerades = append(rest.Masquerades, m)
			continue
		}
		b.add(&model.NATRule{Meta: model.Meta{Name: fmt.Sprintf("masquerade-%03d", i+1), Description: m.Comment},
			Enabled: true, Sequence: 1000 + (i+1)*10, Type: "masquerade", Zone: b.zone(m.OutIface), Protocol: "any",
			SourceNets: nets(m.SrcCIDR)})
	}
}

func (b *builder) tunnel(t Tunnel) {
	if len(t.Addresses) == 0 {
		b.note("tunnel %s: the interface has no address; not imported", t.Name)
		return
	}
	if t.ListenPort == 0 {
		b.note("tunnel %s: no listen port (client-only device); not imported", t.Name)
		return
	}
	id := b.add(&model.WGTunnel{Meta: model.Meta{Name: safeName(t.Name), Scope: model.NodeScope(b.node)},
		Enabled: true, Device: t.Name, Mode: "road_warrior", ListenPort: t.ListenPort, Addresses: t.Addresses,
		PublicKey: t.PublicKey, Zone: b.zone(t.Name)})
	b.note("tunnel %s: the private key stays on the node; the model only references it", t.Name)
	for i, p := range t.Peers {
		name := t.PeerNames[p.PublicKey]
		if name == "" {
			name = fmt.Sprintf("%s-peer-%02d", t.Name, i+1)
		}
		if len(p.AllowedIPs) == 0 {
			b.note("tunnel %s: peer %q has no allowed IPs; not imported", t.Name, name)
			continue
		}
		full := false
		for _, a := range p.AllowedIPs {
			if a == "0.0.0.0/0" || a == "::/0" {
				full = true
			}
		}
		b.add(&model.WGPeer{Meta: model.Meta{Name: safeName(name)}, Enabled: true,
			Tunnel: model.Ref[model.WGTunnel]{ID: id}, PublicKey: p.PublicKey, AllowedIPs: p.AllowedIPs,
			Endpoint: p.Endpoint, Keepalive: int(p.PersistentKeepalive.Seconds()), FullTunnel: full})
	}
}
