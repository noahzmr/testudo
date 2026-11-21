package svcrender

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net"
	"path/filepath"
	"strings"

	"github.com/noahzmr/testudo/internal/model"
)

// SubnetID derives Kea's numeric subnet id from the scope's UUID, so the
// id, and with it every lease, survives a re-render.
func SubnetID(scopeID string) uint32 { return crc32.ChecksumIEEE([]byte(scopeID))%4294967294 + 1 }

type obj = map[string]any

// kea renders one Kea server (DHCPv4 or DHCPv6) for the scopes of that
// family. It returns the configuration, the interfaces it serves and
// whether it runs as half of an HA pair.
func (r *renderer) kea(scopes []*model.DHCPScope, v6 bool, res *Result) (string, []string, bool) {
	fam, root, subnets, leases, sock, port := "4", "Dhcp4", "subnet4", Leases4, Kea4Socket, HAPort4
	if v6 {
		fam, root, subnets, leases, sock, port = "6", "Dhcp6", "subnet6", Leases6, Kea6Socket, HAPort6
	}
	var ifaces []string
	var list []any
	ids := map[uint32]string{}
	register := false
	for _, s := range scopes {
		_, subnet, err := net.ParseCIDR(s.Subnet)
		if err != nil {
			continue
		}
		id := SubnetID(s.ID)
		if other, dup := ids[id]; dup {
			r.fail("DHCP scopes %q and %q map to the same subnet id; rename one", other, s.Name)
		}
		ids[id] = s.Name
		ifaces = append(ifaces, s.Interface)
		domain := r.scopeDomain(s)
		reg := s.RegisterDNS && domain != ""
		register = register || reg
		res.Scopes = append(res.Scopes, Scope{ID: s.ID, Name: s.Name, SubnetID: id, Interface: s.Interface, Subnet: subnet.String(),
			V6: v6, Domain: domain, Register: reg})

		lease := s.LeaseSeconds
		if lease == 0 {
			lease = 3600
		}
		sub := obj{"id": id, "subnet": subnet.String(), "interface": s.Interface, "valid-lifetime": lease,
			"ddns-send-updates": reg}
		if reg {
			sub["ddns-qualifying-suffix"] = domain + "."
		}
		if v6 {
			sub["preferred-lifetime"] = lease * 3 / 4
		}
		var pools []any
		for _, p := range s.Pools {
			if a, b, ok := strings.Cut(p, "-"); ok {
				p = strings.TrimSpace(a) + " - " + strings.TrimSpace(b)
			}
			pools = append(pools, obj{"pool": p})
		}
		if len(pools) > 0 {
			sub["pools"] = pools
		}

		var opts []any
		opt := func(name string, values []string) {
			if len(values) > 0 {
				opts = append(opts, obj{"name": name, "data": strings.Join(values, ", ")})
			}
		}
		dns := s.DNSServers
		if len(dns) == 0 && r.resolver != nil && r.serves(r.resolver.Interfaces, s.Interface) {
			if a := r.addrOn(s.Interface, v6, nil); a != "" {
				dns = []string{a}
			}
		}
		ntp := s.NTPServers
		if len(ntp) == 0 && r.ntp != nil && r.serves(r.ntp.Interfaces, s.Interface) {
			if a := r.addrOn(s.Interface, v6, nil); a != "" {
				ntp = []string{a}
			}
		}
		if v6 {
			opt("dns-servers", dns)
			opt("sntp-servers", ntp)
		} else {
			router := s.Router
			if router == "" {
				router = r.addrOn(s.Interface, false, subnet)
			}
			if router == "" {
				r.fail("DHCP scope %q: this node has no address in %s on %s; give the default gateway", s.Name, subnet, s.Interface)
			}
			opt("routers", []string{router})
			opt("domain-name-servers", dns)
			opt("ntp-servers", ntp)
			if domain != "" {
				opt("domain-name", []string{domain})
			}
		}
		if domain != "" {
			opt("domain-search", []string{domain})
		}
		if len(opts) > 0 {
			sub["option-data"] = opts
		}

		var resv []any
		for _, h := range s.Reservations {
			e := obj{}
			if v6 {
				e["ip-addresses"] = []string{h.Address}
				if h.DUID != "" {
					e["duid"] = strings.ToLower(h.DUID)
				} else {
					e["hw-address"] = strings.ToLower(h.MAC)
				}
			} else {
				e["ip-address"] = h.Address
				e["hw-address"] = strings.ToLower(h.MAC)
			}
			if h.Hostname != "" {
				e["hostname"] = qualify(h.Hostname, domain)
			}
			resv = append(resv, e)
		}
		if len(resv) > 0 {
			sub["reservations"] = resv
		}
		list = append(list, sub)
	}
	ifaces = sortedUnique(ifaces)

	hooks := []any{obj{"library": filepath.Join(r.opt.HooksDir, "libdhcp_lease_cmds.so")}}
	conf := obj{
		"interfaces-config": obj{"interfaces": ifaces, "service-sockets-max-retries": 30, "service-sockets-retry-wait-time": 2000},
		"control-socket":    obj{"socket-type": "unix", "socket-name": filepath.Join(r.opt.RunDir, sock)},
		"lease-database":    obj{"type": "memfile", "persist": true, "name": filepath.Join(r.opt.Dir, leases), "lfc-interval": 3600},
		subnets:             list,
		"loggers": []any{obj{"name": "kea-dhcp" + fam, "output_options": []any{obj{"output": "stdout"}}, "severity": "INFO"}},
		// Client names are kept with the lease only when name updates are
		// on; they go to the engine on the loopback, which enters them in
		// the resolver.
		"dhcp-ddns": obj{"enable-updates": register, "server-ip": "127.0.0.1", "server-port": NCRPort,
			"sender-ip": "127.0.0.1", "sender-port": 0, "ncr-protocol": "UDP", "ncr-format": "JSON"},
		"ddns-replace-client-name":  "never",
		"hostname-char-set":         "[^A-Za-z0-9.-]",
		"hostname-char-replacement": "",
	}
	if v6 {
		// A stable server identifier without a file in Kea's data directory:
		// the enterprise number reserved for documentation and the node id.
		conf["server-id"] = obj{"type": "EN", "enterprise-id": 32473, "identifier": serverIdent(r.opt.NodeID), "persist": false}
	} else {
		conf["interfaces-config"].(obj)["dhcp-socket-type"] = "raw"
	}

	ha := r.pair != nil
	if ha {
		for _, s := range scopes {
			if !model.AppliesTo(s, r.opt.SiteID, r.pair.partnerID) {
				r.fail("DHCP scope %q applies to %s only, but it is in an HA pair with %s: put the scope at the site", s.Name,
					r.pair.me.Name, r.pair.peer.Name)
				ha = false
			}
		}
		if r.pair.me.SyncAddress == "" || r.pair.peer.SyncAddress == "" {
			ha = false
		}
	}
	if ha {
		url := func(n *model.ClusterNode) string {
			return fmt.Sprintf("http://%s/", net.JoinHostPort(n.SyncAddress, fmt.Sprint(port)))
		}
		first, second := r.pair.me, r.pair.peer
		if !r.pair.first {
			first, second = second, first
		}
		conf["multi-threading"] = obj{"enable-multi-threading": true, "thread-pool-size": 4, "packet-queue-size": 64}
		hooks = append(hooks, obj{"library": filepath.Join(r.opt.HooksDir, "libdhcp_ha.so"), "parameters": obj{
			"high-availability": []any{obj{
				"this-server-name": r.pair.me.Name,
				"mode":             "hot-standby",
				// The standby takes over six seconds after the primary stops
				// answering on the sync link.
				"heartbeat-delay": 2000, "max-response-delay": 6000, "max-ack-delay": 3000, "max-unacked-clients": 0,
				"sync-timeout": 30000,
				"multi-threading": obj{"enable-multi-threading": true, "http-dedicated-listener": true,
					"http-listener-threads": 2, "http-client-threads": 2},
				"peers": []any{
					obj{"name": first.Name, "url": url(first), "role": "primary", "auto-failover": true},
					obj{"name": second.Name, "url": url(second), "role": "standby", "auto-failover": true},
				},
			}},
		}})
	}
	conf["hooks-libraries"] = hooks

	b, err := json.MarshalIndent(obj{root: conf}, "", "  ")
	if err != nil {
		r.fail("kea: %v", err)
	}
	return string(b) + "\n", ifaces, ha
}

// serverIdent is the hex identifier in the DHCPv6 server DUID: the first
// eight bytes of the node id.
func serverIdent(nodeID string) string {
	b, err := hex.DecodeString(strings.ReplaceAll(nodeID, "-", ""))
	if err != nil || len(b) < 8 {
		return "7465737475646f00"
	}
	return hex.EncodeToString(b[:8])
}
