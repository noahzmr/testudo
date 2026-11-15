// Package wgrender turns the configuration model into the WireGuard devices
// of one node, and into the configuration a client needs to connect.
//
// Render is pure: the current time is an input, because a peer past its
// expiry is left out.
package wgrender

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

// Options are the node-local facts the model does not hold.
type Options struct {
	SiteID, NodeID string
	Now            time.Time
}

// Result is the desired WireGuard state of the node.
type Result struct {
	Devices []netops.WGDeviceSpec `json:"devices"`
	// NextExpiry is when the next peer expires and the result has to be
	// rendered again; zero when no peer has an expiry ahead.
	NextExpiry time.Time `json:"next_expiry,omitzero"`
	// Expired names the peers that were left out because they expired.
	Expired []string `json:"expired,omitempty"`
}

func effective[T model.Entity](st *confstore.State, opt Options, kind model.Kind, errs *[]string) []T {
	var out []T
	for _, e := range st.List(kind) {
		if !model.AppliesTo(e, opt.SiteID, opt.NodeID) {
			continue
		}
		eff, _, err := model.Effective(e, opt.SiteID, opt.NodeID)
		if err != nil {
			*errs = append(*errs, fmt.Sprintf("%s %q: %v", kind, e.GetMeta().Name, err))
			continue
		}
		out = append(out, eff.(T))
	}
	return out
}

// Render builds the devices for the node.
func Render(st *confstore.State, opt Options) (Result, error) {
	var res Result
	var errs []string
	fail := func(e model.Entity, format string, a ...any) {
		errs = append(errs, fmt.Sprintf("%s %q: %s", e.Kind(), e.GetMeta().Name, fmt.Sprintf(format, a...)))
	}
	tunnels := map[string]int{} // tunnel id -> index in res.Devices
	names := map[string]string{}
	ports := map[int]string{}
	for _, t := range effective[*model.WGTunnel](st, opt, model.KindWGTunnel, &errs) {
		if !t.Enabled {
			continue
		}
		if other, dup := names[t.Device]; dup {
			fail(t, "device %s is already used by tunnel %q", t.Device, other)
			continue
		}
		if other, dup := ports[t.ListenPort]; dup {
			fail(t, "port %d is already used by tunnel %q", t.ListenPort, other)
			continue
		}
		names[t.Device], ports[t.ListenPort] = t.Name, t.Name
		addrs := append([]string(nil), t.Addresses...)
		sort.Strings(addrs)
		res.Devices = append(res.Devices, netops.WGDeviceSpec{Name: t.Device, ListenPort: t.ListenPort, MTU: t.MTU,
			Addresses: addrs, KeyRef: t.KeyRef, Peers: []netops.WGPeerSpec{}})
		tunnels[t.ID] = len(res.Devices) - 1
	}
	type claim struct {
		net  *net.IPNet
		peer string
	}
	claims := map[string][]claim{}
	keys := map[string]string{}
	peers := effective[*model.WGPeer](st, opt, model.KindWGPeer, &errs)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	for _, p := range peers {
		i, ok := tunnels[p.Tunnel.ID]
		if !p.Enabled || !ok {
			continue
		}
		dev := &res.Devices[i]
		if p.ExpiresAt != nil {
			if !p.ExpiresAt.After(opt.Now) {
				res.Expired = append(res.Expired, p.Name)
				continue
			}
			if res.NextExpiry.IsZero() || p.ExpiresAt.Before(res.NextExpiry) {
				res.NextExpiry = *p.ExpiresAt
			}
		}
		if other, dup := keys[dev.Name+"/"+p.PublicKey]; dup {
			fail(p, "has the same public key as peer %q on this tunnel", other)
			continue
		}
		keys[dev.Name+"/"+p.PublicKey] = p.Name
		allowed := append([]string(nil), p.AllowedIPs...)
		sort.Strings(allowed)
		// WireGuard routes by allowed IPs: two peers of one device cannot
		// both claim an address.
		overlap := false
		for _, a := range allowed {
			_, n, err := net.ParseCIDR(a)
			if err != nil {
				continue
			}
			for _, c := range claims[dev.Name] {
				if c.net.Contains(n.IP) || n.Contains(c.net.IP) {
					fail(p, "allowed IP %s overlaps with peer %q on this tunnel", a, c.peer)
					overlap = true
				}
			}
			claims[dev.Name] = append(claims[dev.Name], claim{n, p.Name})
		}
		if overlap {
			continue
		}
		dev.Peers = append(dev.Peers, netops.WGPeerSpec{PublicKey: p.PublicKey, PresharedRef: p.PresharedRef,
			AllowedIPs: allowed, Endpoint: p.Endpoint, Keepalive: p.Keepalive})
	}
	sort.Slice(res.Devices, func(i, j int) bool { return res.Devices[i].Name < res.Devices[j].Name })
	if len(errs) > 0 {
		return res, fmt.Errorf("wgrender: %s", strings.Join(errs, "; "))
	}
	return res, nil
}

// Placeholders stand in for the two secrets the server does not have or
// does not show again: the client's private key and the preshared key.
const (
	PrivateKeyPlaceholder   = "<the private key generated on the device>"
	PresharedKeyPlaceholder = "<the preshared key shown when it was created>"
)

// ClientConfig renders the configuration a peer's device needs. It contains
// placeholders instead of secrets; the caller fills them in from what it
// holds in memory.
func ClientConfig(st *confstore.State, peerID string) (string, error) {
	e, ok := st.Get(model.KindWGPeer, peerID)
	if !ok {
		return "", confstore.ErrNotFound
	}
	p := e.(*model.WGPeer)
	te, ok := st.Get(model.KindWGTunnel, p.Tunnel.ID)
	if !ok {
		return "", fmt.Errorf("wgrender: the peer's tunnel does not exist")
	}
	t := te.(*model.WGTunnel)
	if t.Endpoint == "" {
		return "", fmt.Errorf("tunnel %q has no public endpoint; set one so clients know where to connect", t.Name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n# %s\nPrivateKey = %s\n", p.Name, PrivateKeyPlaceholder)
	// The client's own addresses are the host routes it is allowed to use.
	var own []string
	for _, a := range p.AllowedIPs {
		if ip, n, err := net.ParseCIDR(a); err == nil {
			if ones, bits := n.Mask.Size(); ones == bits {
				own = append(own, ip.String()+fmt.Sprintf("/%d", bits))
			}
		}
	}
	if len(own) == 0 {
		return "", fmt.Errorf("peer %q has no single address among its allowed IPs to use as its own", p.Name)
	}
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(own, ", "))
	if len(t.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(t.DNS, ", "))
	}
	if t.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", t.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\n# %s\nPublicKey = %s\n", t.Name, t.PublicKey)
	if p.PresharedRef != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", PresharedKeyPlaceholder)
	}
	routes := []string{"0.0.0.0/0", "::/0"}
	if !p.FullTunnel {
		routes = nil
		for _, a := range t.Addresses {
			if _, n, err := net.ParseCIDR(a); err == nil {
				routes = append(routes, n.String())
			}
		}
		routes = append(routes, t.ClientRoutes...)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\nEndpoint = %s\n", strings.Join(routes, ", "), t.Endpoint)
	if p.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
	}
	return b.String(), nil
}
