// Package svcrender renders the network services a node offers on its
// interfaces: DHCPv4 and DHCPv6 (Kea), router advertisements (radvd), a
// caching DNS resolver (Unbound) and NTP (chrony). Every service is bound
// to the interfaces the model names; the packet filter opens its port on
// those interfaces only (internal/fwrender reads Openings).
package svcrender

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// File names. Configuration goes to RunDir, which the daemons that drop
// privileges must be able to read again on a reload; leases go to Dir.
const (
	Kea4Conf    = "kea-dhcp4.conf"
	Kea6Conf    = "kea-dhcp6.conf"
	UnboundConf = "unbound.conf"
	ChronyConf  = "chrony.conf"
	RadvdConf   = "radvd.conf"
	// LeaseNames is the include file with the names of DHCP clients; the
	// engine keeps it current, the renderer only refers to it.
	LeaseNames = "dns-leases.conf"
	Kea4Socket = "kea4.sock"
	Kea6Socket = "kea6.sock"
	UnboundCtl = "unbound.ctl"
	Leases4    = "kea-leases4.csv"
	Leases6    = "kea-leases6.csv"

	// HAPort4 and HAPort6 are where the Kea servers of an HA pair talk to
	// each other, on the sync link.
	HAPort4 = 8000
	HAPort6 = 8001
	// NCRPort is the loopback port Kea sends name changes to.
	NCRPort = 53001

	// DefaultLocalDomain is the local domain when the resolver names none
	// (RFC 8375).
	DefaultLocalDomain = "home.arpa"
	// RootKey is the DNSSEC trust anchor Debian's dns-root-data keeps current.
	RootKey = "/usr/share/dns/root.key"
)

// Daemon names, in the order they start.
const (
	DaemonUnbound = "unbound"
	DaemonChrony  = "chronyd"
	DaemonKea4    = "kea-dhcp4"
	DaemonKea6    = "kea-dhcp6"
	DaemonRadvd   = "radvd"
)

// AllDaemons lists every daemon the services may run, in start order.
var AllDaemons = []string{DaemonUnbound, DaemonChrony, DaemonKea4, DaemonKea6, DaemonRadvd}

// ConfOf names each daemon's configuration file.
var ConfOf = map[string]string{DaemonUnbound: UnboundConf, DaemonChrony: ChronyConf, DaemonKea4: Kea4Conf,
	DaemonKea6: Kea6Conf, DaemonRadvd: RadvdConf}

// Options are the node-local facts.
type Options struct {
	SiteID, NodeID string
	// Dir holds leases (root only); RunDir configuration, pid files and
	// control sockets.
	Dir, RunDir string
	// HooksDir holds Kea's hook libraries.
	HooksDir string
}

// Openings are the ports the packet filter opens for the services.
type Openings struct {
	DHCP4, DHCP6, DNS, NTP []string // interfaces
	// DNSFrom and NTPFrom are networks served through other interfaces.
	DNSFrom, NTPFrom []string
	// HA is set on an HA pair whose Kea servers talk over the sync link.
	HA *HAOpening `json:"ha,omitempty"`
}

// HAOpening lets the partner's Kea reach this one.
type HAOpening struct {
	Interface string `json:"interface"`
	Peer      string `json:"peer"`
	Ports     []int  `json:"ports"`
}

// Scope describes one rendered DHCP scope, for the lease view and the
// registration of client names.
type Scope struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SubnetID  uint32 `json:"subnet_id"`
	Interface string `json:"interface"`
	Subnet    string `json:"subnet"`
	V6        bool   `json:"v6"`
	Domain    string `json:"domain,omitempty"`
	Register  bool   `json:"register,omitempty"`
}

// Result is what the services stage applies on the node.
type Result struct {
	// Files are written to RunDir.
	Files map[string]string `json:"files,omitempty"`
	// Daemons are the daemons to run, in start order; the others stop.
	Daemons []string `json:"daemons,omitempty"`
	// ServeOnly runs chronyd without control of the system clock.
	ServeOnly bool     `json:"serve_only,omitempty"`
	Open      Openings `json:"open"`
	Scopes    []Scope  `json:"scopes,omitempty"`
	// LocalDomain is the resolver's local domain; "" without a resolver.
	LocalDomain string `json:"local_domain,omitempty"`
	// StaticNames are names the model gives (records, reservations); a
	// client cannot take one of them over with its lease.
	StaticNames []string `json:"static_names,omitempty"`
}

// Enabled reports whether any service runs.
func (r Result) Enabled() bool { return len(r.Daemons) > 0 }

type renderer struct {
	st   *confstore.State
	opt  Options
	errs []string

	ifNets map[string][]*net.IPNet // the node's addresses by device, from the model
	vips   map[string][]*net.IPNet // HA virtual addresses by device
	pair   *pair

	resolver *model.DNSResolver
	ntp      *model.NTPService
	scopes   []*model.DHCPScope
	ras      []*model.RouterAdvert
	records  []*model.DNSRecord
}

type pair struct {
	me, peer  *model.ClusterNode
	first     bool
	sync      string
	partnerID string
}

func (r *renderer) fail(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

// effective returns the objects of one kind that apply to the node, with
// overrides resolved, ordered by name.
func effective[T model.Entity](r *renderer, kind model.Kind) []T {
	var out []T
	for _, e := range r.st.List(kind) {
		if !model.AppliesTo(e, r.opt.SiteID, r.opt.NodeID) {
			continue
		}
		eff, _, err := model.Effective(e, r.opt.SiteID, r.opt.NodeID)
		if err != nil {
			r.fail("%s %q: %v", kind, e.GetMeta().Name, err)
			continue
		}
		out = append(out, eff.(T))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].GetMeta().Name < out[j].GetMeta().Name })
	return out
}

var rank = map[string]int{"global": 1, "site": 2, "node": 3}

// mostSpecific picks the enabled object with the narrowest scope.
func mostSpecific[T model.Entity](objs []T, enabled func(T) bool) T {
	var best T
	found := false
	for _, o := range objs {
		if !enabled(o) {
			continue
		}
		if !found || rank[o.GetMeta().Scope.Level()] > rank[best.GetMeta().Scope.Level()] {
			best, found = o, true
		}
	}
	return best
}

// Render builds the node's services.
func Render(st *confstore.State, opt Options) (Result, error) {
	r := &renderer{st: st, opt: opt, ifNets: map[string][]*net.IPNet{}, vips: map[string][]*net.IPNet{}}
	r.gather()
	res := Result{Files: map[string]string{}}
	if r.resolver != nil {
		res.LocalDomain = r.localDomain()
		res.Files[UnboundConf] = r.unbound(&res)
		res.Daemons = append(res.Daemons, DaemonUnbound)
		res.Open.DNS = sortedUnique(r.resolver.Interfaces)
		res.Open.DNSFrom = r.resolver.AllowFrom
	}
	if r.ntp != nil {
		res.Files[ChronyConf] = r.chrony()
		res.Daemons = append(res.Daemons, DaemonChrony)
		res.ServeOnly = r.ntp.ServeOnly
		res.Open.NTP = sortedUnique(r.ntp.Interfaces)
		res.Open.NTPFrom = r.ntp.AllowFrom
	}
	for _, v6 := range []bool{false, true} {
		var scopes []*model.DHCPScope
		for _, s := range r.scopes {
			if isV6(s.Subnet) == v6 {
				scopes = append(scopes, s)
			}
		}
		if len(scopes) == 0 {
			continue
		}
		conf, ifaces, ha := r.kea(scopes, v6, &res)
		name, daemon := Kea4Conf, DaemonKea4
		if v6 {
			name, daemon = Kea6Conf, DaemonKea6
			res.Open.DHCP6 = ifaces
		} else {
			res.Open.DHCP4 = ifaces
		}
		res.Files[name] = conf
		res.Daemons = append(res.Daemons, daemon)
		if ha {
			if res.Open.HA == nil {
				res.Open.HA = &HAOpening{Interface: r.pair.sync, Peer: r.pair.peer.SyncAddress}
			}
			port := HAPort4
			if v6 {
				port = HAPort6
			}
			res.Open.HA.Ports = append(res.Open.HA.Ports, port)
		}
	}
	if len(r.ras) > 0 {
		res.Files[RadvdConf] = r.radvd()
		res.Daemons = append(res.Daemons, DaemonRadvd)
	}
	res.StaticNames = r.staticNames()
	if len(r.errs) > 0 {
		return Result{}, errors.New("svcrender: " + strings.Join(r.errs, "; "))
	}
	return res, nil
}

// gather collects what applies to the node.
func (r *renderer) gather() {
	for _, i := range effective[*model.Interface](r, model.KindInterface) {
		if !i.Enabled {
			continue
		}
		for _, a := range i.Addresses {
			if ip, n, err := net.ParseCIDR(a); err == nil {
				r.ifNets[i.Device] = append(r.ifNets[i.Device], &net.IPNet{IP: ip, Mask: n.Mask})
			}
		}
	}
	for _, e := range r.st.List(model.KindHAPair) {
		p := e.(*model.HAPair)
		if !p.Enabled || !model.AppliesTo(p, r.opt.SiteID, r.opt.NodeID) || len(p.Nodes) != 2 {
			continue
		}
		idx := -1
		for i, n := range p.Nodes {
			if n.ID == r.opt.NodeID {
				idx = i
			}
		}
		if idx < 0 {
			continue
		}
		me, ok1 := r.st.Get(model.KindClusterNode, p.Nodes[idx].ID)
		peer, ok2 := r.st.Get(model.KindClusterNode, p.Nodes[1-idx].ID)
		if !ok1 || !ok2 {
			continue
		}
		r.pair = &pair{me: me.(*model.ClusterNode), peer: peer.(*model.ClusterNode), first: idx == 0, sync: p.SyncInterface,
			partnerID: p.Nodes[1-idx].ID}
		for _, in := range p.Instances {
			for _, v := range in.VirtualIPs {
				if ip, n, err := net.ParseCIDR(v); err == nil {
					r.vips[in.Interface] = append(r.vips[in.Interface], &net.IPNet{IP: ip, Mask: n.Mask})
				}
			}
		}
	}
	r.resolver = mostSpecific(effective[*model.DNSResolver](r, model.KindDNSResolver), func(d *model.DNSResolver) bool { return d.Enabled })
	r.ntp = mostSpecific(effective[*model.NTPService](r, model.KindNTPService), func(n *model.NTPService) bool { return n.Enabled })
	for _, s := range effective[*model.DHCPScope](r, model.KindDHCPScope) {
		if s.Enabled {
			r.scopes = append(r.scopes, s)
		}
	}
	for _, a := range effective[*model.RouterAdvert](r, model.KindRouterAdvert) {
		if a.Enabled {
			r.ras = append(r.ras, a)
		}
	}
	r.records = effective[*model.DNSRecord](r, model.KindDNSRecord)
}

func isV6(cidrOrIP string) bool {
	s, _, _ := strings.Cut(cidrOrIP, "/")
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

// addrOn returns the address clients on iface should use for this node:
// a virtual address of the pair first, then the node's own, of the given
// family and, when within is set, inside it.
func (r *renderer) addrOn(iface string, v6 bool, within *net.IPNet) string {
	for _, list := range [][]*net.IPNet{r.vips[iface], r.ifNets[iface]} {
		for _, n := range list {
			if (n.IP.To4() == nil) != v6 || n.IP.IsLinkLocalUnicast() {
				continue
			}
			if within != nil && !within.Contains(n.IP) {
				continue
			}
			return n.IP.String()
		}
	}
	return ""
}

// networksOn lists the networks on an interface: the node's addresses,
// the pair's virtual addresses and the DHCP scopes there.
func (r *renderer) networksOn(iface string) []string {
	var out []string
	for _, list := range [][]*net.IPNet{r.ifNets[iface], r.vips[iface]} {
		for _, n := range list {
			out = append(out, (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String())
		}
	}
	for _, s := range r.scopes {
		if s.Interface == iface {
			if _, n, err := net.ParseCIDR(s.Subnet); err == nil {
				out = append(out, n.String())
			}
		}
	}
	return sortedUnique(out)
}

func (r *renderer) serves(list []string, iface string) bool {
	for _, i := range list {
		if i == iface {
			return true
		}
	}
	return false
}

func (r *renderer) localDomain() string {
	if r.resolver != nil && r.resolver.LocalDomain != "" {
		return strings.TrimSuffix(strings.ToLower(r.resolver.LocalDomain), ".")
	}
	return DefaultLocalDomain
}

// qualify makes a reservation's host name a full name under the domain.
func qualify(host, domain string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || strings.Contains(host, ".") || domain == "" {
		return host
	}
	return host + "." + strings.TrimSuffix(strings.ToLower(domain), ".")
}

func (r *renderer) staticNames() []string {
	var out []string
	for _, rec := range r.records {
		out = append(out, strings.TrimSuffix(strings.ToLower(rec.Host), "."))
	}
	for _, s := range r.scopes {
		for _, res := range s.Reservations {
			if n := qualify(res.Hostname, r.scopeDomain(s)); n != "" {
				out = append(out, n)
			}
		}
	}
	return sortedUnique(out)
}

// scopeDomain is the domain a scope's clients are named under.
func (r *renderer) scopeDomain(s *model.DHCPScope) string {
	if s.Domain != "" {
		return strings.TrimSuffix(strings.ToLower(s.Domain), ".")
	}
	if r.resolver != nil {
		return r.localDomain()
	}
	return ""
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
