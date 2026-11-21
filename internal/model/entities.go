package model

import "time"

// Kind names. They are part of the wire format; never rename one without a
// migration.
const (
	KindInterface     Kind = "interface"
	KindZone          Kind = "zone"
	KindAlias         Kind = "alias"
	KindFilterRule    Kind = "filter_rule"
	KindNATRule       Kind = "nat_rule"
	KindGateway       Kind = "gateway"
	KindRoute         Kind = "route"
	KindBGPNeighbor   Kind = "bgp_neighbor"
	KindOSPFArea      Kind = "ospf_area"
	KindVRF           Kind = "vrf"
	KindWGTunnel      Kind = "wg_tunnel"
	KindWGPeer        Kind = "wg_peer"
	KindUser          Kind = "user"
	KindGroup         Kind = "group"
	KindRole          Kind = "role"
	KindCertificate   Kind = "certificate"
	KindLBService     Kind = "lb_service"
	KindLBBackendPool Kind = "lb_backend_pool"
	KindLBRouter      Kind = "lb_router"
	KindMiddleware    Kind = "middleware"
	KindSite          Kind = "site"
	KindClusterNode   Kind = "cluster_node"

	KindFirewallPolicy Kind = "firewall_policy"
	KindAccessResource Kind = "access_resource"
	KindAccessPolicy   Kind = "access_policy"
	KindPolicyRoute    Kind = "policy_route"
	KindOIDCProvider   Kind = "oidc_provider"
	KindAPIToken       Kind = "api_token"
	KindFabric         Kind = "fabric"
	KindPathPolicy     Kind = "path_policy"
	KindHAPair         Kind = "ha_pair"
	KindDHCPScope      Kind = "dhcp_scope"
	KindRouterAdvert   Kind = "router_advert"
	KindDNSResolver    Kind = "dns_resolver"
	KindDNSRecord      Kind = "dns_record"
	KindNTPService     Kind = "ntp_service"
	KindAccessGrant    Kind = "access_grant"
	KindNodeSettings   Kind = "node_settings"
	KindBond           Kind = "bond"
	KindBridge         Kind = "bridge"
	KindVLAN           Kind = "vlan"
)

func init() {
	register("interfaces", "Interface", "interfaces/assignments", nodeOnly, func() Entity { return &Interface{} })
	register("bonds", "Bond", "interfaces/bonds", nodeOnly, func() Entity { return &Bond{} })
	register("bridges", "Bridge", "interfaces/bridges", nodeOnly, func() Entity { return &Bridge{} })
	register("vlans", "VLAN", "interfaces/vlans", nodeOnly, func() Entity { return &VLAN{} })
	register("zones", "Zone", "firewall/zones", allLevels, func() Entity { return &Zone{} })
	register("aliases", "Alias", "firewall/aliases", allLevels, func() Entity { return &Alias{} })
	register("filter-rules", "Filter rule", "firewall/rules", allLevels, func() Entity { return &FilterRule{} })
	register("nat-rules", "NAT rule", "firewall/nat", allLevels, func() Entity { return &NATRule{} })
	register("gateways", "Gateway", "routing/gateways", []string{"site", "node"}, func() Entity { return &Gateway{} })
	register("routes", "Static route", "routing/static", allLevels, func() Entity { return &Route{} })
	register("bgp-neighbors", "BGP neighbor", "routing/bgp", []string{"site", "node"}, func() Entity { return &BGPNeighbor{} })
	register("ospf-areas", "OSPF area", "routing/ospf", []string{"site", "node"}, func() Entity { return &OSPFArea{} })
	register("vrfs", "VRF", "routing/vrfs", allLevels, func() Entity { return &VRF{} })
	register("wg-tunnels", "WireGuard tunnel", "vpn/tunnels", []string{"site", "node"}, func() Entity { return &WGTunnel{} })
	register("wg-peers", "WireGuard peer", "vpn/peers", allLevels, func() Entity { return &WGPeer{} })
	register("users", "User", "system/users", globalOny, func() Entity { return &User{} })
	register("groups", "Group", "system/groups", globalOny, func() Entity { return &Group{} })
	register("roles", "Role", "system/roles", globalOny, func() Entity { return &Role{} })
	register("certificates", "Certificate", "system/certificates", allLevels, func() Entity { return &Certificate{} })
	register("lb-services", "Load balancer service", "loadbalancer/services", allLevels, func() Entity { return &LBService{} })
	register("lb-backend-pools", "Backend pool", "loadbalancer/pools", allLevels, func() Entity { return &LBBackendPool{} })
	register("lb-routers", "Router", "loadbalancer/routers", allLevels, func() Entity { return &LBRouter{} })
	register("middlewares", "Middleware", "loadbalancer/middlewares", allLevels, func() Entity { return &Middleware{} })
	register("sites", "Site", "cluster/sites", globalOny, func() Entity { return &Site{} })
	register("cluster-nodes", "Cluster node", "cluster/nodes", globalOny, func() Entity { return &ClusterNode{} })
	register("firewall-policies", "Firewall policy", "firewall/policy", allLevels, func() Entity { return &FirewallPolicy{} })
	register("access-resources", "Access resource", "access/resources", allLevels, func() Entity { return &AccessResource{} })
	register("policy-routes", "Policy route", "routing/policy", allLevels, func() Entity { return &PolicyRoute{} })
	register("access-policies", "Access policy", "access/policies", allLevels, func() Entity { return &AccessPolicy{} })
	register("oidc-providers", "OIDC provider", "system/oidc", globalOny, func() Entity { return &OIDCProvider{} })
	register("api-tokens", "API token", "system/tokens", globalOny, func() Entity { return &APIToken{} })
	register("fabrics", "Fabric", "cluster/fabric", globalOny, func() Entity { return &Fabric{} })
	register("path-policies", "Path policy", "routing/paths", allLevels, func() Entity { return &PathPolicy{} })
	register("ha-pairs", "HA pair", "cluster/ha", []string{"site"}, func() Entity { return &HAPair{} })
	register("dhcp-scopes", "DHCP scope", "services/dhcp", []string{"site", "node"}, func() Entity { return &DHCPScope{} })
	register("router-adverts", "Router advertisement", "services/ra", []string{"site", "node"}, func() Entity { return &RouterAdvert{} })
	register("dns-resolvers", "DNS resolver", "services/dns", allLevels, func() Entity { return &DNSResolver{} })
	register("dns-records", "DNS record", "services/dns-records", allLevels, func() Entity { return &DNSRecord{} })
	register("ntp-services", "NTP service", "services/ntp", allLevels, func() Entity { return &NTPService{} })
	register("access-grants", "Access grant", "access/grants", allLevels, func() Entity { return &AccessGrant{} })
	register("node-settings", "Node settings", "system/settings", allLevels, func() Entity { return &NodeSettings{} })
}

// Interface binds a kernel network device on one node to a zone and says
// how it is configured: addresses, a DHCP client, the MTU, the link state.
// What is not set is left as the node has it; a disabled interface is not
// configured by Testudo at all.
type Interface struct {
	Meta      `yaml:",inline"`
	Device    string    `json:"device" yaml:"device" validate:"required,ifname" ui:"label=Device,order=10,help=Kernel device name such as eth0"`
	Zone      Ref[Zone] `json:"zone,omitzero" yaml:"zone,omitempty" validate:"-" ui:"label=Zone,widget=ref-picker,ref=zone,order=20"`
	Addresses []string  `json:"addresses,omitempty" yaml:"addresses,omitempty" validate:"max=64,dive,cidr" ui:"label=Addresses,widget=list,order=30,help=IPv4 or IPv6 in CIDR form"`
	DHCP      bool      `json:"dhcp,omitempty" yaml:"dhcp,omitempty" validate:"-" ui:"label=DHCP client,order=40,help=Gets an IPv4 address and routes from the network"`
	Down      bool      `json:"down,omitempty" yaml:"down,omitempty" validate:"-" ui:"label=Link down,order=45,help=Takes the link down"`
	MTU       int       `json:"mtu,omitempty" yaml:"mtu,omitempty" validate:"omitempty,min=576,max=65535" ui:"label=MTU,order=50"`
	VRF       Ref[VRF]  `json:"vrf,omitzero" yaml:"vrf,omitempty" validate:"-" ui:"label=VRF,widget=ref-picker,ref=vrf,order=60"`
	Enabled   bool      `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
}

func (Interface) Kind() Kind { return KindInterface }

// Zone groups interfaces and tunnels that share a trust level.
type Zone struct {
	Meta          `yaml:",inline"`
	DefaultAction string `json:"default_action" yaml:"default_action" validate:"required,oneof=accept drop reject" ui:"label=Default action,widget=select,order=10,help=Applied to traffic entering from this zone that no rule matches"`
	IntraZone     bool   `json:"intra_zone,omitempty" yaml:"intra_zone,omitempty" validate:"-" ui:"label=Allow traffic inside the zone,order=20"`
	AntiSpoof     bool   `json:"anti_spoof,omitempty" yaml:"anti_spoof,omitempty" validate:"-" ui:"label=Reverse-path check,order=30"`
}

func (Zone) Kind() Kind { return KindZone }

// Alias is a named set of hosts, networks or ports, or a set loaded from a
// URL or a GeoIP database.
type Alias struct {
	Meta    `yaml:",inline"`
	Type    string       `json:"type" yaml:"type" validate:"required,oneof=host network port url_table geoip" ui:"label=Type,widget=select,order=10"`
	Entries []string     `json:"entries,omitempty" yaml:"entries,omitempty" validate:"max=65536,dive,required,max=64" ui:"label=Entries,widget=list,order=20,help=Addresses or networks or port ranges or ISO country codes depending on type"`
	Members []Ref[Alias] `json:"members,omitempty" yaml:"members,omitempty" validate:"max=64" ui:"label=Nested aliases,widget=ref-picker,ref=alias,order=30"`
	URL     string       `json:"url,omitempty" yaml:"url,omitempty" validate:"required_if=Type url_table,omitempty,url" ui:"label=URL,order=40"`
	Refresh string       `json:"refresh,omitempty" yaml:"refresh,omitempty" validate:"omitempty,duration" ui:"label=Refresh interval,order=50,help=For example 1h"`
}

func (Alias) Kind() Kind { return KindAlias }

// FilterRule is one ordered packet-filter rule.
type FilterRule struct {
	Meta            `yaml:",inline"`
	Sequence        int           `json:"sequence" yaml:"sequence" validate:"min=0,max=1000000" ui:"label=Order,order=10,help=Rules are evaluated from low to high"`
	Enabled         bool          `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Action          string        `json:"action" yaml:"action" validate:"required,oneof=accept drop reject" ui:"label=Action,widget=select,order=20"`
	Direction       string        `json:"direction" yaml:"direction" validate:"required,oneof=in out forward" ui:"label=Direction,widget=select,order=30"`
	SourceZone      Ref[Zone]     `json:"source_zone,omitzero" yaml:"source_zone,omitempty" validate:"-" ui:"label=Source zone,widget=ref-picker,ref=zone,group=Match,order=40"`
	DestinationZone Ref[Zone]     `json:"destination_zone,omitzero" yaml:"destination_zone,omitempty" validate:"-" ui:"label=Destination zone,widget=ref-picker,ref=zone,group=Match,order=50"`
	Protocol        string        `json:"protocol" yaml:"protocol" validate:"required,oneof=any tcp udp icmp icmpv6" ui:"label=Protocol,widget=select,group=Match,order=60"`
	Source          []Ref[Alias]  `json:"source,omitempty" yaml:"source,omitempty" validate:"max=64" ui:"label=Source,widget=ref-picker,ref=alias,group=Match,order=70"`
	SourceNets      []string      `json:"source_nets,omitempty" yaml:"source_nets,omitempty" validate:"max=64,dive,cidr_or_ip" ui:"label=Source networks,widget=list,group=Match,order=71"`
	Destination     []Ref[Alias]  `json:"destination,omitempty" yaml:"destination,omitempty" validate:"max=64" ui:"label=Destination,widget=ref-picker,ref=alias,group=Match,order=80"`
	DestinationNets []string      `json:"destination_nets,omitempty" yaml:"destination_nets,omitempty" validate:"max=64,dive,cidr_or_ip" ui:"label=Destination networks,widget=list,group=Match,order=81"`
	Ports           []string      `json:"ports,omitempty" yaml:"ports,omitempty" validate:"max=64,dive,portrange" ui:"label=Destination ports,widget=list,group=Match,order=90"`
	PortAliases     []Ref[Alias]  `json:"port_aliases,omitempty" yaml:"port_aliases,omitempty" validate:"max=16" ui:"label=Port aliases,widget=ref-picker,ref=alias,group=Match,order=91"`
	States          []string      `json:"states,omitempty" yaml:"states,omitempty" validate:"max=4,dive,oneof=new established related invalid" ui:"label=Connection states,widget=multi-select,group=Match,order=100"`
	Tunnel          Ref[WGTunnel] `json:"tunnel,omitzero" yaml:"tunnel,omitempty" validate:"-" ui:"label=Only via tunnel,widget=ref-picker,ref=wg_tunnel,group=Match,order=110"`
	Log             bool          `json:"log,omitempty" yaml:"log,omitempty" validate:"-" ui:"label=Log matches,group=Options,order=120"`
	RateLimit       string        `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty" validate:"omitempty,ratelimit" ui:"label=Rate limit,group=Options,order=130,help=For example 10/second"`
	Mark            uint32        `json:"mark,omitempty" yaml:"mark,omitempty" validate:"-" ui:"label=Firewall mark,group=Options,order=140,help=Used by policy routing"`
	Owner           string        `json:"owner,omitempty" yaml:"owner,omitempty" validate:"max=128" ui:"label=Owner,widget=readonly,group=Options,order=150"`
}

func (FilterRule) Kind() Kind { return KindFilterRule }

// NATRule is a destination, source, masquerade or one-to-one translation.
type NATRule struct {
	Meta          `yaml:",inline"`
	Enabled       bool           `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Sequence      int            `json:"sequence" yaml:"sequence" validate:"min=0,max=1000000" ui:"label=Order,order=10"`
	Type          string         `json:"type" yaml:"type" validate:"required,oneof=dnat snat masquerade one_to_one" ui:"label=Type,widget=select,order=20"`
	Interface     Ref[Interface] `json:"interface,omitzero" yaml:"interface,omitempty" validate:"-" ui:"label=Interface,widget=ref-picker,ref=interface,order=30"`
	Zone          Ref[Zone]      `json:"zone,omitzero" yaml:"zone,omitempty" validate:"-" ui:"label=Zone,widget=ref-picker,ref=zone,order=31"`
	Protocol      string         `json:"protocol" yaml:"protocol" validate:"required,oneof=any tcp udp" ui:"label=Protocol,widget=select,order=40"`
	SourceNets    []string       `json:"source_nets,omitempty" yaml:"source_nets,omitempty" validate:"max=64,dive,cidr_or_ip" ui:"label=Source networks,widget=list,order=50"`
	Destination   string         `json:"destination,omitempty" yaml:"destination,omitempty" validate:"omitempty,cidr_or_ip" ui:"label=Original destination,order=60"`
	Port          string         `json:"port,omitempty" yaml:"port,omitempty" validate:"omitempty,portrange" ui:"label=Original port,order=70"`
	TranslateTo   string         `json:"translate_to,omitempty" yaml:"translate_to,omitempty" validate:"required_unless=Type masquerade,omitempty,cidr_or_ip" ui:"label=Translate to,order=80"`
	TranslatePort string         `json:"translate_port,omitempty" yaml:"translate_port,omitempty" validate:"omitempty,portrange" ui:"label=Translated port,order=90"`
	Reflection    bool           `json:"reflection,omitempty" yaml:"reflection,omitempty" validate:"-" ui:"label=NAT reflection,order=100,help=Make the forward reachable from inside"`
}

func (NATRule) Kind() Kind { return KindNATRule }

// Gateway is a next hop that can be monitored and grouped for multi-WAN.
type Gateway struct {
	Meta      `yaml:",inline"`
	Enabled   bool           `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Interface Ref[Interface] `json:"interface" yaml:"interface" validate:"required" ui:"label=Interface,widget=ref-picker,ref=interface,order=10"`
	Address   string         `json:"address" yaml:"address" validate:"required,ip" ui:"label=Address,order=20"`
	VRF       Ref[VRF]       `json:"vrf,omitzero" yaml:"vrf,omitempty" validate:"-" ui:"label=VRF,widget=ref-picker,ref=vrf,order=30"`
	Monitor   string         `json:"monitor,omitempty" yaml:"monitor,omitempty" validate:"omitempty,ip" ui:"label=Monitor address,order=40,help=Probed to decide whether the gateway is up"`
	Group     string         `json:"group,omitempty" yaml:"group,omitempty" validate:"omitempty,objname" ui:"label=Gateway group,order=50"`
	Priority  int            `json:"priority,omitempty" yaml:"priority,omitempty" validate:"min=0,max=255" ui:"label=Tier,order=60,help=Lower tiers are preferred; equal tiers balance"`
	Weight    int            `json:"weight,omitempty" yaml:"weight,omitempty" validate:"min=0,max=255" ui:"label=Weight,order=70"`
}

func (Gateway) Kind() Kind { return KindGateway }

// Route is a static route.
type Route struct {
	Meta         `yaml:",inline"`
	Enabled      bool         `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Destination  string       `json:"destination" yaml:"destination" validate:"required,cidr" ui:"label=Destination,order=10"`
	Gateway      Ref[Gateway] `json:"gateway,omitzero" yaml:"gateway,omitempty" validate:"required_without=GatewayGroup" ui:"label=Gateway,widget=ref-picker,ref=gateway,order=20"`
	GatewayGroup string       `json:"gateway_group,omitempty" yaml:"gateway_group,omitempty" validate:"omitempty,objname,excluded_with=Gateway" ui:"label=Gateway group,order=25,help=Use the healthy gateways of this group instead of one gateway; the lowest tier wins and equal tiers share the load"`
	VRF          Ref[VRF]     `json:"vrf,omitzero" yaml:"vrf,omitempty" validate:"-" ui:"label=VRF,widget=ref-picker,ref=vrf,order=30"`
	Metric       int          `json:"metric,omitempty" yaml:"metric,omitempty" validate:"min=0,max=65535" ui:"label=Metric,order=40"`
}

func (Route) Kind() Kind { return KindRoute }

// BGPNeighbor is one BGP session.
type BGPNeighbor struct {
	Meta           `yaml:",inline"`
	Enabled        bool           `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	LocalAS        uint32         `json:"local_as" yaml:"local_as" validate:"required,min=1" ui:"label=Local AS,order=10"`
	RemoteAS       uint32         `json:"remote_as" yaml:"remote_as" validate:"required,min=1" ui:"label=Remote AS,order=20"`
	Address        string         `json:"address" yaml:"address" validate:"required,ip" ui:"label=Neighbor address,order=30"`
	VRF            Ref[VRF]       `json:"vrf,omitzero" yaml:"vrf,omitempty" validate:"-" ui:"label=VRF,widget=ref-picker,ref=vrf,order=40"`
	UpdateSource   Ref[Interface] `json:"update_source,omitzero" yaml:"update_source,omitempty" validate:"-" ui:"label=Update source,widget=ref-picker,ref=interface,order=50"`
	BFD            bool           `json:"bfd,omitempty" yaml:"bfd,omitempty" validate:"-" ui:"label=BFD,order=60"`
	RRClient       bool           `json:"rr_client,omitempty" yaml:"rr_client,omitempty" validate:"-" ui:"label=Route reflector client,order=70"`
	PrefixListIn   []string       `json:"prefix_list_in,omitempty" yaml:"prefix_list_in,omitempty" validate:"max=256,dive,cidr" ui:"label=Accepted prefixes,widget=list,order=80"`
	PrefixListOut  []string       `json:"prefix_list_out,omitempty" yaml:"prefix_list_out,omitempty" validate:"max=256,dive,cidr" ui:"label=Announced prefixes,widget=list,order=90"`
	Announce       []string       `json:"announce,omitempty" yaml:"announce,omitempty" validate:"max=256,dive,cidr" ui:"label=Networks to originate,widget=list,order=95,help=Announced by this router when they are in its routing table"`
	Communities    []string       `json:"communities,omitempty" yaml:"communities,omitempty" validate:"max=32,dive,community" ui:"label=Communities,widget=list,order=100"`
	SessionSecret  string         `json:"session_secret,omitempty" yaml:"session_secret,omitempty" validate:"max=80" ui:"label=Session password,widget=password,order=110" secret:"true"`
	HoldTimeSecond int            `json:"hold_time_seconds,omitempty" yaml:"hold_time_seconds,omitempty" validate:"omitempty,min=3,max=65535" ui:"label=Hold time (s),order=120"`
}

func (BGPNeighbor) Kind() Kind { return KindBGPNeighbor }

// OSPFArea is an OSPFv2/v3 area and the interfaces in it.
type OSPFArea struct {
	Meta       `yaml:",inline"`
	Enabled    bool             `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Area       string           `json:"area" yaml:"area" validate:"required,ospfarea" ui:"label=Area ID,order=10,help=Dotted quad or number"`
	Interfaces []Ref[Interface] `json:"interfaces" yaml:"interfaces" validate:"required,min=1,max=64" ui:"label=Interfaces,widget=ref-picker,ref=interface,order=20"`
	VRF        Ref[VRF]         `json:"vrf,omitzero" yaml:"vrf,omitempty" validate:"-" ui:"label=VRF,widget=ref-picker,ref=vrf,order=30"`
	Stub       bool             `json:"stub,omitempty" yaml:"stub,omitempty" validate:"-" ui:"label=Stub area,order=40"`
	IPv6       bool             `json:"ipv6,omitempty" yaml:"ipv6,omitempty" validate:"-" ui:"label=OSPFv3,order=50"`
}

func (OSPFArea) Kind() Kind { return KindOSPFArea }

// VRF is a routing instance.
type VRF struct {
	Meta  `yaml:",inline"`
	Table uint32 `json:"table" yaml:"table" validate:"required,min=1,max=4294967294" ui:"label=Routing table,order=10"`
	// MeshSlot stretches the VRF across the fabric: every pair of sites
	// that both have it gets tunnels of its own for it.
	MeshSlot int      `json:"mesh_slot,omitempty" yaml:"mesh_slot,omitempty" validate:"min=0,max=3" ui:"label=Fabric slot,order=20,help=1 to 3 stretches the VRF across sites over tunnels of its own; 0 keeps it local"`
	Networks []string `json:"networks,omitempty" yaml:"networks,omitempty" validate:"max=64,dive,cidr" ui:"label=Networks announced into the fabric,widget=list,order=30,help=Usually set per site through an override"`
}

func (VRF) Kind() Kind { return KindVRF }

// WGTunnel is one WireGuard device. Its private key is never part of the
// model; KeyRef names the entry in the node's secret store.
type WGTunnel struct {
	Meta         `yaml:",inline"`
	Enabled      bool      `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Device       string    `json:"device" yaml:"device" validate:"required,ifname" ui:"label=Device,order=10"`
	Mode         string    `json:"mode" yaml:"mode" validate:"required,oneof=road_warrior site_to_site" ui:"label=Mode,widget=select,order=20"`
	ListenPort   int       `json:"listen_port" yaml:"listen_port" validate:"required,min=1,max=65535" ui:"label=Listen port,order=30"`
	Addresses    []string  `json:"addresses" yaml:"addresses" validate:"required,min=1,max=8,dive,cidr" ui:"label=Tunnel addresses,widget=list,order=40"`
	PublicKey    string    `json:"public_key" yaml:"public_key" validate:"required,wgkey" ui:"label=Public key,order=50"`
	KeyRef       string    `json:"key_ref,omitempty" yaml:"key_ref,omitempty" validate:"omitempty,objname" ui:"label=Private key entry,widget=readonly,order=60" secret:"true"`
	Zone         Ref[Zone] `json:"zone" yaml:"zone" validate:"required" ui:"label=Zone,widget=ref-picker,ref=zone,order=70"`
	MTU          int       `json:"mtu,omitempty" yaml:"mtu,omitempty" validate:"omitempty,min=1280,max=9000" ui:"label=MTU,order=80"`
	DNS          []string  `json:"dns,omitempty" yaml:"dns,omitempty" validate:"max=4,dive,ip" ui:"label=DNS servers pushed to clients,widget=list,order=90"`
	Endpoint     string    `json:"endpoint,omitempty" yaml:"endpoint,omitempty" validate:"omitempty,hostport" ui:"label=Public endpoint,order=95,help=host:port that clients connect to; written into client configurations"`
	ClientRoutes []string  `json:"client_routes,omitempty" yaml:"client_routes,omitempty" validate:"max=64,dive,cidr" ui:"label=Networks reachable through the tunnel,widget=list,order=96,help=Pushed to split-tunnel clients; full-tunnel clients route everything"`
}

func (WGTunnel) Kind() Kind { return KindWGTunnel }

// WGPeer is one peer of a tunnel, optionally bound to an identity.
type WGPeer struct {
	Meta         `yaml:",inline"`
	Enabled      bool          `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Tunnel       Ref[WGTunnel] `json:"tunnel" yaml:"tunnel" validate:"required" ui:"label=Tunnel,widget=ref-picker,ref=wg_tunnel,order=10"`
	PublicKey    string        `json:"public_key" yaml:"public_key" validate:"required,wgkey" ui:"label=Public key,order=20"`
	PresharedRef string        `json:"preshared_ref,omitempty" yaml:"preshared_ref,omitempty" validate:"omitempty,objname" ui:"label=Preshared key entry,widget=readonly,order=30" secret:"true"`
	AllowedIPs   []string      `json:"allowed_ips" yaml:"allowed_ips" validate:"required,min=1,max=64,dive,cidr" ui:"label=Allowed IPs,widget=list,order=40"`
	Endpoint     string        `json:"endpoint,omitempty" yaml:"endpoint,omitempty" validate:"omitempty,hostport" ui:"label=Endpoint,order=50"`
	Keepalive    int           `json:"keepalive,omitempty" yaml:"keepalive,omitempty" validate:"min=0,max=65535" ui:"label=Persistent keepalive (s),order=60"`
	FullTunnel   bool          `json:"full_tunnel,omitempty" yaml:"full_tunnel,omitempty" validate:"-" ui:"label=Full tunnel,order=70"`
	User         Ref[User]     `json:"user,omitzero" yaml:"user,omitempty" validate:"-" ui:"label=User,widget=ref-picker,ref=user,group=Identity,order=80"`
	Groups       []Ref[Group]  `json:"groups,omitempty" yaml:"groups,omitempty" validate:"max=64" ui:"label=Groups,widget=ref-picker,ref=group,group=Identity,order=90"`
	ExpiresAt    *time.Time    `json:"expires_at,omitempty" yaml:"expires_at,omitempty" validate:"-" ui:"label=Expires,widget=datetime,order=100"`
}

func (WGPeer) Kind() Kind { return KindWGPeer }

// User is an identity known to the appliance. Credentials are not stored
// here: local accounts authenticate through the host, others through OIDC.
type User struct {
	Meta     `yaml:",inline"`
	Username string       `json:"username" yaml:"username" validate:"required,objname" ui:"label=Username,order=10"`
	Email    string       `json:"email,omitempty" yaml:"email,omitempty" validate:"omitempty,email" ui:"label=Email,order=20"`
	Source   string       `json:"source" yaml:"source" validate:"required,oneof=local host oidc" ui:"label=Identity source,widget=select,order=30,help=local: a password (and code) kept by Testudo on every member; host: the host's PAM stack; oidc: the identity provider"`
	Subject  string       `json:"subject,omitempty" yaml:"subject,omitempty" validate:"max=255" ui:"label=OIDC subject,widget=readonly,order=40"`
	Groups   []Ref[Group] `json:"groups,omitempty" yaml:"groups,omitempty" validate:"max=64" ui:"label=Groups,widget=ref-picker,ref=group,order=50"`
	Roles    []Ref[Role]  `json:"roles,omitempty" yaml:"roles,omitempty" validate:"max=16" ui:"label=Roles,widget=ref-picker,ref=role,order=60"`
	Disabled bool         `json:"disabled,omitempty" yaml:"disabled,omitempty" validate:"-" ui:"label=Disabled,order=70"`
}

func (User) Kind() Kind { return KindUser }

// Group maps an identity-provider group or claim value to roles.
type Group struct {
	Meta  `yaml:",inline"`
	Claim string      `json:"claim,omitempty" yaml:"claim,omitempty" validate:"max=255" ui:"label=Claim value,order=10,help=Value of the group claim that maps to this group"`
	Roles []Ref[Role] `json:"roles,omitempty" yaml:"roles,omitempty" validate:"max=16" ui:"label=Roles,widget=ref-picker,ref=role,order=20"`
}

func (Group) Kind() Kind { return KindGroup }

// Role is a named set of permissions of the form "<area>:<read|write>".
type Role struct {
	Meta        `yaml:",inline"`
	Permissions []string `json:"permissions" yaml:"permissions" validate:"required,min=1,max=64,dive,permission" ui:"label=Permissions,widget=multi-select,order=10"`
}

func (Role) Kind() Kind { return KindRole }

// Certificate is a TLS certificate. The private key is not part of the
// model; KeyRef names the entry in the node's secret store.
type Certificate struct {
	Meta        `yaml:",inline"`
	Source      string     `json:"source" yaml:"source" validate:"required,oneof=acme import internal_ca" ui:"label=Source,widget=select,order=10,help=acme: Let's Encrypt obtains and renews it. internal_ca: issued by this appliance's local authority. import: issued elsewhere"`
	Domains     []string   `json:"domains" yaml:"domains" validate:"required,min=1,max=100,dive,fqdn_or_wildcard" ui:"label=Domains,widget=list,order=20"`
	Challenge   string     `json:"challenge,omitempty" yaml:"challenge,omitempty" validate:"required_if=Source acme,omitempty,oneof=http-01 tls-alpn-01 dns-01" ui:"label=Let's Encrypt challenge,widget=select,order=30"`
	Email       string     `json:"email,omitempty" yaml:"email,omitempty" validate:"required_if=Source acme,omitempty,email" ui:"label=Let's Encrypt account email,order=32"`
	Staging     bool       `json:"staging,omitempty" yaml:"staging,omitempty" validate:"-" ui:"label=Use the Let's Encrypt staging environment,order=33,help=For trying a setup out: no rate limits and certificates browsers do not trust"`
	DNSProvider string     `json:"dns_provider,omitempty" yaml:"dns_provider,omitempty" validate:"required_if=Challenge dns-01,omitempty,objname" ui:"label=DNS provider,order=34,help=Provider code for the DNS-01 challenge; its credentials come from the proxy's environment"`
	ChainPEM    string     `json:"chain_pem,omitempty" yaml:"chain_pem,omitempty" validate:"required_if=Source import,max=65536" ui:"label=Certificate chain (PEM),widget=textarea,order=40"`
	KeyRef      string     `json:"key_ref,omitempty" yaml:"key_ref,omitempty" validate:"omitempty,objname" ui:"label=Private key entry,widget=readonly,order=50" secret:"true"`
	NotAfter    *time.Time `json:"not_after,omitempty" yaml:"not_after,omitempty" validate:"-" ui:"label=Expires,widget=readonly,order=60"`
}

func (Certificate) Kind() Kind { return KindCertificate }

// LBBackend is one server in a pool.
type LBBackend struct {
	Address string    `json:"address" yaml:"address" validate:"required,hostport" ui:"label=Address,order=10,help=host:port"`
	Weight  int       `json:"weight,omitempty" yaml:"weight,omitempty" validate:"min=0,max=1000" ui:"label=Weight,order=20"`
	Drain   bool      `json:"drain,omitempty" yaml:"drain,omitempty" validate:"-" ui:"label=Drain,order=30,help=Finish existing sessions and accept no new ones"`
	Site    Ref[Site] `json:"site,omitzero" yaml:"site,omitempty" validate:"-" ui:"label=Site,widget=ref-picker,ref=site,order=40"`
}

// LBHealthCheck is the active health check of a pool.
type LBHealthCheck struct {
	Type     string `json:"type" yaml:"type" validate:"required,oneof=none tcp http" ui:"label=Type,widget=select,order=10"`
	Path     string `json:"path,omitempty" yaml:"path,omitempty" validate:"required_if=Type http,omitempty,startswith=/" ui:"label=Path,order=20"`
	Interval string `json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,duration" ui:"label=Interval,order=30"`
	Timeout  string `json:"timeout,omitempty" yaml:"timeout,omitempty" validate:"omitempty,duration" ui:"label=Timeout,order=40"`
}

// LBBackendPool is a set of backends with a balancing policy.
type LBBackendPool struct {
	Meta          `yaml:",inline"`
	Algorithm     string        `json:"algorithm" yaml:"algorithm" validate:"required,oneof=weighted_round_robin least_connections" ui:"label=Algorithm,widget=select,order=10"`
	Backends      []LBBackend   `json:"backends,omitempty" yaml:"backends,omitempty" validate:"max=256,dive" ui:"label=Backends,widget=table,order=20"`
	HealthCheck   LBHealthCheck `json:"health_check" yaml:"health_check" validate:"required" ui:"label=Health check,widget=group,order=30"`
	Sticky        bool          `json:"sticky,omitempty" yaml:"sticky,omitempty" validate:"-" ui:"label=Sticky sessions (cookie),order=40"`
	ProxyProtocol string        `json:"proxy_protocol,omitempty" yaml:"proxy_protocol,omitempty" validate:"omitempty,oneof=v1 v2" ui:"label=PROXY protocol,widget=select,order=50"`
}

func (LBBackendPool) Kind() Kind { return KindLBBackendPool }

// LBService is a listener.
type LBService struct {
	Meta        `yaml:",inline"`
	Enabled     bool               `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Zone        Ref[Zone]          `json:"zone" yaml:"zone" validate:"required" ui:"label=Listen zone,widget=ref-picker,ref=zone,order=10"`
	Address     string             `json:"address,omitempty" yaml:"address,omitempty" validate:"omitempty,ip" ui:"label=Listen address,order=20,help=Empty means every address in the zone"`
	Port        int                `json:"port" yaml:"port" validate:"required,min=1,max=65535" ui:"label=Port,order=30"`
	Protocol    string             `json:"protocol" yaml:"protocol" validate:"required,oneof=http https tcp udp" ui:"label=Protocol,widget=select,order=40"`
	Mode        string             `json:"mode" yaml:"mode" validate:"required,oneof=proxy kernel" ui:"label=Mode,widget=select,order=50,help=kernel balances in the packet filter for high throughput"`
	DefaultPool Ref[LBBackendPool] `json:"default_pool,omitzero" yaml:"default_pool,omitempty" validate:"-" ui:"label=Fallback pool,widget=ref-picker,ref=lb_backend_pool,order=60"`
	VRF         Ref[VRF]           `json:"vrf,omitzero" yaml:"vrf,omitempty" validate:"-" ui:"label=VRF,widget=ref-picker,ref=vrf,order=70"`
}

func (LBService) Kind() Kind { return KindLBService }

// LBRouter selects a pool for traffic arriving on a service.
type LBRouter struct {
	Meta          `yaml:",inline"`
	Enabled       bool               `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Service       Ref[LBService]     `json:"service" yaml:"service" validate:"required" ui:"label=Service,widget=ref-picker,ref=lb_service,order=10"`
	Priority      int                `json:"priority,omitempty" yaml:"priority,omitempty" validate:"min=0,max=100000" ui:"label=Priority,order=20"`
	Hosts         []string           `json:"hosts,omitempty" yaml:"hosts,omitempty" validate:"max=100,dive,fqdn_or_wildcard" ui:"label=Host names,widget=list,group=Match,order=30"`
	PathPrefix    string             `json:"path_prefix,omitempty" yaml:"path_prefix,omitempty" validate:"omitempty,startswith=/" ui:"label=Path prefix,group=Match,order=40"`
	SNI           []string           `json:"sni,omitempty" yaml:"sni,omitempty" validate:"max=100,dive,fqdn_or_wildcard" ui:"label=SNI names,widget=list,group=Match,order=50"`
	TLS           string             `json:"tls" yaml:"tls" validate:"required,oneof=none terminate passthrough" ui:"label=TLS,widget=select,order=60"`
	Certificate   Ref[Certificate]   `json:"certificate,omitzero" yaml:"certificate,omitempty" validate:"required_if=TLS terminate" ui:"label=Certificate,widget=ref-picker,ref=certificate,order=70"`
	Pool          Ref[LBBackendPool] `json:"pool" yaml:"pool" validate:"required" ui:"label=Pool,widget=ref-picker,ref=lb_backend_pool,order=80"`
	Middlewares   []Ref[Middleware]  `json:"middlewares,omitempty" yaml:"middlewares,omitempty" validate:"max=16" ui:"label=Middlewares,widget=ref-picker,ref=middleware,order=90"`
	RequireGroups []Ref[Group]       `json:"require_groups,omitempty" yaml:"require_groups,omitempty" validate:"max=64" ui:"label=Require login and one of,widget=ref-picker,ref=group,group=Identity,order=100"`
}

func (LBRouter) Kind() Kind { return KindLBRouter }

// Middleware is a reusable request-processing step.
type Middleware struct {
	Meta     `yaml:",inline"`
	Type     string            `json:"type" yaml:"type" validate:"required,oneof=headers rate_limit ip_allow_list retry circuit_breaker compress forward_auth redirect" ui:"label=Type,widget=select,order=10"`
	Settings map[string]string `json:"settings,omitempty" yaml:"settings,omitempty" validate:"max=64,dive,keys,objname,endkeys,max=1024" ui:"label=Settings,widget=key-value,order=20"`
}

func (Middleware) Kind() Kind { return KindMiddleware }

// Site is one location of the cluster.
type Site struct {
	Meta         `yaml:",inline"`
	Location     string           `json:"location,omitempty" yaml:"location,omitempty" validate:"max=128" ui:"label=Location,order=10"`
	Voter        Ref[ClusterNode] `json:"voter,omitzero" yaml:"voter,omitempty" validate:"-" ui:"label=Voting node,widget=ref-picker,ref=cluster_node,order=20"`
	Witness      bool             `json:"witness,omitempty" yaml:"witness,omitempty" validate:"-" ui:"label=Witness only,order=30,help=Votes but carries no traffic"`
	MeshEndpoint string           `json:"mesh_endpoint,omitempty" yaml:"mesh_endpoint,omitempty" validate:"omitempty,hostport" ui:"label=Mesh endpoint,order=40"`
	ASN          uint32           `json:"asn,omitempty" yaml:"asn,omitempty" validate:"-" ui:"label=AS number,order=50,help=Empty uses the fabric's; sites with the same number talk iBGP"`
	Networks     []string         `json:"networks,omitempty" yaml:"networks,omitempty" validate:"max=64,dive,cidr" ui:"label=Networks announced into the fabric,widget=list,order=60"`
	Hub          bool             `json:"hub,omitempty" yaml:"hub,omitempty" validate:"-" ui:"label=Hub,order=70,help=In a hub-and-spoke fabric spokes connect to hubs only"`
}

func (Site) Kind() Kind { return KindSite }

// ClusterNode is one appliance.
type ClusterNode struct {
	Meta         `yaml:",inline"`
	Site         Ref[Site] `json:"site" yaml:"site" validate:"required" ui:"label=Site,widget=ref-picker,ref=site,order=10"`
	Hostname     string    `json:"hostname" yaml:"hostname" validate:"required,hostname_rfc1123" ui:"label=Hostname,order=20"`
	Address      string    `json:"address" yaml:"address" validate:"required,ip" ui:"label=Cluster address,order=30,help=Address on the site mesh"`
	RouterID     string    `json:"router_id,omitempty" yaml:"router_id,omitempty" validate:"omitempty,ipv4" ui:"label=Router ID,order=35,help=For BGP and OSPF; defaults to the cluster address when that is IPv4"`
	VRRPPriority int       `json:"vrrp_priority,omitempty" yaml:"vrrp_priority,omitempty" validate:"min=0,max=254" ui:"label=VRRP priority,order=40"`
	// The node's place in the fabric. The public key is filled in by the
	// node itself; its private key never leaves it.
	SyncAddress   string   `json:"sync_address,omitempty" yaml:"sync_address,omitempty" validate:"omitempty,ip" ui:"label=Address on the HA sync link,group=HA,order=45,help=Where the partner node sends connection state"`
	MeshIndex     int      `json:"mesh_index,omitempty" yaml:"mesh_index,omitempty" validate:"min=0,max=31" ui:"label=Fabric index,group=Fabric,order=50,help=1 to 31 and unique; decides the tunnel addresses and ports of the node"`
	MeshPublicKey string   `json:"mesh_public_key,omitempty" yaml:"mesh_public_key,omitempty" validate:"omitempty,wgkey" ui:"label=Fabric public key,widget=readonly,group=Fabric,order=60"`
	Uplinks       []Uplink `json:"uplinks,omitempty" yaml:"uplinks,omitempty" validate:"max=4,dive" ui:"label=Uplinks,widget=table,group=Fabric,order=70"`
}

// Uplink is one way out of a node that the fabric builds tunnels over.
// Tunnels connect uplinks of the same color: the internet to the internet,
// the MPLS line to the MPLS line.
type Uplink struct {
	Color    string `json:"color" yaml:"color" validate:"required,objname" ui:"label=Color,order=10,help=One of the fabric's colors"`
	Endpoint string `json:"endpoint" yaml:"endpoint" validate:"required,max=253" ui:"label=Address the other sites reach,order=20,help=IP address or host name; the port follows from the fabric"`
}

func (ClusterNode) Kind() Kind { return KindClusterNode }

// FirewallPolicy holds the packet filter's defaults: whether unmatched
// traffic is dropped and which baseline traffic is always let through so the
// operator cannot be locked out.
type FirewallPolicy struct {
	Meta             `yaml:",inline"`
	DefaultDeny      bool     `json:"default_deny" yaml:"default_deny" validate:"-" ui:"label=Drop unmatched traffic,order=10"`
	AllowEstablished bool     `json:"allow_established" yaml:"allow_established" validate:"-" ui:"label=Allow established and related,group=Baseline,order=20"`
	DropInvalid      bool     `json:"drop_invalid" yaml:"drop_invalid" validate:"-" ui:"label=Drop invalid state,group=Baseline,order=30"`
	AllowLoopback    bool     `json:"allow_loopback" yaml:"allow_loopback" validate:"-" ui:"label=Allow loopback,group=Baseline,order=40"`
	AllowICMP        bool     `json:"allow_icmp" yaml:"allow_icmp" validate:"-" ui:"label=Allow ICMP and ICMPv6,group=Baseline,order=50"`
	AllowTCPPorts    []string `json:"allow_tcp_ports,omitempty" yaml:"allow_tcp_ports,omitempty" validate:"max=64,dive,portrange" ui:"label=Always-open TCP ports,widget=list,group=Baseline,order=60,help=Management access such as SSH and the web UI"`
	AllowUDPPorts    []string `json:"allow_udp_ports,omitempty" yaml:"allow_udp_ports,omitempty" validate:"max=64,dive,portrange" ui:"label=Always-open UDP ports,widget=list,group=Baseline,order=70"`
	TCPEstablished   string   `json:"tcp_established_timeout,omitempty" yaml:"tcp_established_timeout,omitempty" validate:"omitempty,duration" ui:"label=Idle timeout for established TCP,group=Connection tracking,order=74,help=Kernel default is 5 days; for example 2h"`
	UDPTimeout       string   `json:"udp_timeout,omitempty" yaml:"udp_timeout,omitempty" validate:"omitempty,duration" ui:"label=Idle timeout for UDP streams,group=Connection tracking,order=75,help=Kernel default is 2 minutes"`
	SynFloodGuard    bool     `json:"syn_flood_guard,omitempty" yaml:"syn_flood_guard,omitempty" validate:"-" ui:"label=SYN flood guard,group=Hardening,order=80"`
	LogDrops         bool     `json:"log_drops,omitempty" yaml:"log_drops,omitempty" validate:"-" ui:"label=Log dropped packets,group=Logging,order=90"`
	LogPrefix        string   `json:"log_prefix,omitempty" yaml:"log_prefix,omitempty" validate:"max=32" ui:"label=Log prefix,group=Logging,order=100"`
}

func (FirewallPolicy) Kind() Kind { return KindFirewallPolicy }

// AccessResource is something a just-in-time grant can open: a network
// target, optionally reached through a brokered ssh or rdp session.
type AccessResource struct {
	Meta      `yaml:",inline"`
	Type      string `json:"type" yaml:"type" validate:"required,oneof=network ssh rdp" ui:"label=Type,widget=select,order=10"`
	Target    string `json:"target" yaml:"target" validate:"required,cidr_or_ip" ui:"label=Target,order=20,help=Address or network"`
	Protocol  string `json:"protocol" yaml:"protocol" validate:"required,oneof=any tcp udp" ui:"label=Protocol,widget=select,order=30"`
	Ports     string `json:"ports,omitempty" yaml:"ports,omitempty" validate:"omitempty,portrange" ui:"label=Ports,order=40"`
	Login     string `json:"login,omitempty" yaml:"login,omitempty" validate:"max=64" ui:"label=Login name,order=50"`
	BrokerRef string `json:"broker_ref,omitempty" yaml:"broker_ref,omitempty" validate:"max=128" ui:"label=Broker connection,order=60,help=The broker holds the credentials; none are stored here"`
}

func (AccessResource) Kind() Kind { return KindAccessResource }

// AccessPolicy says who may request access to a resource and under which
// conditions.
type AccessPolicy struct {
	Meta             `yaml:",inline"`
	Resource         Ref[AccessResource] `json:"resource" yaml:"resource" validate:"required" ui:"label=Resource,widget=ref-picker,ref=access_resource,order=10"`
	Users            []Ref[User]         `json:"users,omitempty" yaml:"users,omitempty" validate:"max=256" ui:"label=Users,widget=ref-picker,ref=user,order=20"`
	Groups           []Ref[Group]        `json:"groups,omitempty" yaml:"groups,omitempty" validate:"max=64" ui:"label=Groups,widget=ref-picker,ref=group,order=30"`
	Everyone         bool                `json:"everyone,omitempty" yaml:"everyone,omitempty" validate:"-" ui:"label=Every authenticated user,order=40"`
	MaxDuration      string              `json:"max_duration" yaml:"max_duration" validate:"required,duration" ui:"label=Longest grant,order=50,help=For example 4h"`
	RequiresApproval bool                `json:"requires_approval,omitempty" yaml:"requires_approval,omitempty" validate:"-" ui:"label=Needs approval,order=60"`
	RequiresMFA      bool                `json:"requires_mfa,omitempty" yaml:"requires_mfa,omitempty" validate:"-" ui:"label=Needs a second factor,order=70"`
}

func (AccessPolicy) Kind() Kind { return KindAccessPolicy }

// AccessGrant is access to a resource that one user has for a limited
// time: what an approved request, a policy without approval or a
// break-glass becomes. The packet filter lets the user's WireGuard peers
// reach the resource while the grant exists; the grant is removed when it
// ends, and the connections it allowed are cut.
type AccessGrant struct {
	Meta       `yaml:",inline"`
	Resource   Ref[AccessResource] `json:"resource" yaml:"resource" validate:"required" ui:"label=Resource,widget=ref-picker,ref=access_resource,order=10"`
	User       Ref[User]           `json:"user" yaml:"user" validate:"required" ui:"label=User,widget=ref-picker,ref=user,order=20"`
	Ends       *time.Time          `json:"ends" yaml:"ends" validate:"required" ui:"label=Ends,widget=datetime,order=30"`
	Policy     Ref[AccessPolicy]   `json:"policy,omitzero" yaml:"policy,omitempty" validate:"-" ui:"label=Policy,widget=ref-picker,ref=access_policy,order=40"`
	Reason     string              `json:"reason,omitempty" yaml:"reason,omitempty" validate:"max=512" ui:"label=Justification,order=50"`
	ApprovedBy string              `json:"approved_by,omitempty" yaml:"approved_by,omitempty" validate:"max=128" ui:"label=Approved by,widget=readonly,order=60"`
	BreakGlass bool                `json:"break_glass,omitempty" yaml:"break_glass,omitempty" validate:"-" ui:"label=Break-glass,widget=readonly,order=70"`
	Request    string              `json:"request,omitempty" yaml:"request,omitempty" validate:"max=64" ui:"label=Request,widget=readonly,order=80,help=The request in the access log"`
}

func (AccessGrant) Kind() Kind { return KindAccessGrant }

// PolicyRoute sends traffic that a filter rule marked through a chosen
// gateway or gateway group instead of the main routing table.
type PolicyRoute struct {
	Meta         `yaml:",inline"`
	Enabled      bool         `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Mark         uint32       `json:"mark" yaml:"mark" validate:"required,min=1" ui:"label=Firewall mark,order=10,help=Set by a filter rule; traffic carrying it follows this route"`
	Gateway      Ref[Gateway] `json:"gateway,omitzero" yaml:"gateway,omitempty" validate:"required_without=GatewayGroup" ui:"label=Gateway,widget=ref-picker,ref=gateway,order=20"`
	GatewayGroup string       `json:"gateway_group,omitempty" yaml:"gateway_group,omitempty" validate:"omitempty,objname,excluded_with=Gateway" ui:"label=Gateway group,order=30"`
	Table        uint32       `json:"table,omitempty" yaml:"table,omitempty" validate:"omitempty,min=1,max=4294967294" ui:"label=Routing table,order=40,help=Chosen automatically when empty"`
}

func (PolicyRoute) Kind() Kind { return KindPolicyRoute }

// OIDCProvider is the identity provider people log in through. The client
// secret is not part of the model; ClientSecretRef names its entry in the
// node's secret store.
type OIDCProvider struct {
	Meta            `yaml:",inline"`
	Enabled         bool     `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Issuer          string   `json:"issuer" yaml:"issuer" validate:"required,url" ui:"label=Issuer URL,order=10,help=The provider's issuer; its discovery document is read from there"`
	ClientID        string   `json:"client_id" yaml:"client_id" validate:"required,max=255" ui:"label=Client ID,order=20"`
	ClientSecretRef string   `json:"client_secret_ref,omitempty" yaml:"client_secret_ref,omitempty" validate:"omitempty,objname" ui:"label=Client secret entry,widget=readonly,order=30,help=Empty for a public client; PKCE is always used" secret:"true"`
	RedirectURL     string   `json:"redirect_url" yaml:"redirect_url" validate:"required,url" ui:"label=Redirect URL,order=40,help=This console's public address followed by /auth/oidc/callback"`
	Scopes          []string `json:"scopes,omitempty" yaml:"scopes,omitempty" validate:"max=16,dive,min=1,max=64" ui:"label=Extra scopes,widget=list,order=50,help=openid profile and email are always requested"`
	UsernameClaim   string   `json:"username_claim,omitempty" yaml:"username_claim,omitempty" validate:"max=64" ui:"label=Username claim,order=60,help=Default preferred_username"`
	GroupsClaim     string   `json:"groups_claim,omitempty" yaml:"groups_claim,omitempty" validate:"max=64" ui:"label=Groups claim,order=70,help=Default groups; its values are matched against the claim value of groups"`
	SigningAlgs     []string `json:"signing_algs,omitempty" yaml:"signing_algs,omitempty" validate:"max=8,dive,oneof=RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 EdDSA" ui:"label=Accepted signature algorithms,widget=multi-select,order=80,help=Default RS256 and ES256"`
}

func (OIDCProvider) Kind() Kind { return KindOIDCProvider }

// APIToken lets a program call the API. Only a hash of the token is kept.
// A token carries its own permissions, fixed when it is created and never
// more than its creator had.
type APIToken struct {
	Meta        `yaml:",inline"`
	Owner       string     `json:"owner" yaml:"owner" validate:"required,max=255" ui:"label=Owner,widget=readonly,order=10"`
	Permissions []string   `json:"permissions" yaml:"permissions" validate:"required,min=1,max=64,dive,permission" ui:"label=Permissions,widget=multi-select,order=20"`
	Hash        string     `json:"hash" yaml:"hash" validate:"required,min=64,max=64" ui:"label=Token hash,widget=readonly,order=30" secret:"true"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty" validate:"-" ui:"label=Expires,order=40"`
	Disabled    bool       `json:"disabled,omitempty" yaml:"disabled,omitempty" validate:"-" ui:"label=Disabled,order=50"`
}

func (APIToken) Kind() Kind { return KindAPIToken }

// Fabric is the network between the sites: a WireGuard tunnel for every
// pair of nodes at different sites (or between every spoke and every hub)
// and every color they share, with BGP over the tunnels. There is one.
type Fabric struct {
	Meta     `yaml:",inline"`
	Enabled  bool      `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Topology string    `json:"topology" yaml:"topology" validate:"required,oneof=full_mesh hub_spoke" ui:"label=Topology,widget=select,order=10"`
	Pool     string    `json:"pool" yaml:"pool" validate:"required,cidr" ui:"label=Address pool,order=20,help=An IPv4 /16 for tunnel and loopback addresses and nothing else"`
	PortBase int       `json:"port_base" yaml:"port_base" validate:"required,min=1024,max=65023" ui:"label=First port,order=30,help=Tunnels listen on this port and the 511 after it"`
	ASN      uint32    `json:"asn" yaml:"asn" validate:"required,min=1" ui:"label=AS number,order=40,help=For sites without their own"`
	Colors   []string  `json:"colors" yaml:"colors" validate:"required,min=1,max=4,dive,objname" ui:"label=Colors,widget=list,order=50,help=Kinds of uplink such as internet or mpls; at most 4"`
	Zone     Ref[Zone] `json:"zone" yaml:"zone" validate:"required" ui:"label=Zone of the tunnels,widget=ref-picker,ref=zone,order=60"`
	BFD      bool      `json:"bfd,omitempty" yaml:"bfd,omitempty" validate:"-" ui:"label=BFD,order=70,help=Notice a dead tunnel in about a second instead of a minute and a half"`
	// Path selection: a color is preferred over another when it is better
	// by SwitchMargin milliseconds (and by a fifth) for HoldSeconds.
	SwitchMarginMs int `json:"switch_margin_ms,omitempty" yaml:"switch_margin_ms,omitempty" validate:"omitempty,min=1,max=10000" ui:"label=Switch margin (ms),order=80,help=Default 10"`
	HoldSeconds    int `json:"hold_seconds,omitempty" yaml:"hold_seconds,omitempty" validate:"omitempty,min=1,max=3600" ui:"label=Hold time (s),order=90,help=How long a path has to be better before traffic moves; default 15"`
}

func (Fabric) Kind() Kind { return KindFabric }

// PathPolicy steers marked traffic to the other sites over a chosen kind
// of path. A filter rule sets the mark.
type PathPolicy struct {
	Meta    `yaml:",inline"`
	Enabled bool   `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Mark    uint32 `json:"mark" yaml:"mark" validate:"required,min=1" ui:"label=Firewall mark,order=10,help=Set by a filter rule"`
	Prefer  string `json:"prefer" yaml:"prefer" validate:"required,max=32" ui:"label=Prefer,order=20,help=lowest_latency or lowest_loss or a color"`
	Table   uint32 `json:"table,omitempty" yaml:"table,omitempty" validate:"omitempty,min=1,max=4294967294" ui:"label=Routing table,order=30,help=Chosen automatically when empty"`
}

func (PathPolicy) Kind() Kind { return KindPathPolicy }

// HAPair makes two nodes of a site one router: VRRP moves the virtual
// addresses to whichever node is up, and conntrackd keeps the standby's
// connection table in step over a dedicated link, so connections survive
// the move.
type HAPair struct {
	Meta          `yaml:",inline"`
	Enabled       bool               `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Nodes         []Ref[ClusterNode] `json:"nodes" yaml:"nodes" validate:"required,min=2,max=2" ui:"label=Nodes,widget=ref-picker,ref=cluster_node,order=10,help=The first one is preferred unless the nodes set their own VRRP priority"`
	Instances     []VRRPInstance     `json:"instances" yaml:"instances" validate:"required,min=1,max=16,dive" ui:"label=Virtual addresses,widget=table,order=20"`
	SyncInterface string             `json:"sync_interface" yaml:"sync_interface" validate:"required,ifname" ui:"label=Sync link,order=30,help=A link between the two nodes that carries nothing else"`
	AdvertMs      int                `json:"advert_ms,omitempty" yaml:"advert_ms,omitempty" validate:"omitempty,min=100,max=40000" ui:"label=Advertisement interval (ms),order=40,help=Default 1000; the standby takes over after about three intervals"`
	Preempt       bool               `json:"preempt,omitempty" yaml:"preempt,omitempty" validate:"-" ui:"label=Take back when the preferred node returns,order=50"`
}

func (HAPair) Kind() Kind { return KindHAPair }

// VRRPInstance is one set of virtual addresses on one interface. All
// instances of a pair move together.
type VRRPInstance struct {
	Interface  string   `json:"interface" yaml:"interface" validate:"required,ifname" ui:"label=Interface,order=10"`
	VRID       int      `json:"vrid" yaml:"vrid" validate:"required,min=1,max=255" ui:"label=Virtual router ID,order=20,help=Unique on the network segment"`
	VirtualIPs []string `json:"virtual_ips" yaml:"virtual_ips" validate:"required,min=1,max=16,dive,cidr" ui:"label=Virtual addresses,widget=list,order=30,help=One address family per instance"`
}

// DHCPScope hands out addresses on one interface, for one address family:
// the family of its subnet. On the nodes of an HA pair both servers run and
// share their leases; the first node of the pair answers while it is up.
type DHCPScope struct {
	Meta         `yaml:",inline"`
	Enabled      bool              `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Interface    string            `json:"interface" yaml:"interface" validate:"required,ifname" ui:"label=Interface,order=10"`
	Subnet       string            `json:"subnet" yaml:"subnet" validate:"required,cidr" ui:"label=Subnet,order=20,help=The network on the interface such as 192.168.1.0/24 or 2001:db8:1::/64"`
	Pools        []string          `json:"pools,omitempty" yaml:"pools,omitempty" validate:"max=16,dive,iprange" ui:"label=Pools,widget=list,order=30,help=Address ranges to lease such as 192.168.1.100-192.168.1.199; empty: reservations only"`
	Router       string            `json:"router,omitempty" yaml:"router,omitempty" validate:"omitempty,ip" ui:"label=Default gateway,order=40,help=IPv4 only; default: the interface's virtual address or its own address in the subnet"`
	DNSServers   []string          `json:"dns_servers,omitempty" yaml:"dns_servers,omitempty" validate:"max=8,dive,ip" ui:"label=DNS servers,widget=list,order=50,help=Default: this node when its resolver answers on the interface"`
	Domain       string            `json:"domain,omitempty" yaml:"domain,omitempty" validate:"omitempty,hostname_rfc1123" ui:"label=Domain,order=60,help=Search domain; leased names are registered under it"`
	NTPServers   []string          `json:"ntp_servers,omitempty" yaml:"ntp_servers,omitempty" validate:"max=8,dive,ip" ui:"label=NTP servers,widget=list,order=70,help=Default: this node when its NTP service answers on the interface"`
	LeaseSeconds int               `json:"lease_seconds,omitempty" yaml:"lease_seconds,omitempty" validate:"omitempty,min=300,max=2592000" ui:"label=Lease time (s),order=80,help=Default 3600"`
	Reservations []DHCPReservation `json:"reservations,omitempty" yaml:"reservations,omitempty" validate:"max=1024,dive" ui:"label=Reservations,widget=table,order=90"`
	RegisterDNS  bool              `json:"register_dns,omitempty" yaml:"register_dns,omitempty" validate:"-" ui:"label=Register client names in DNS,order=100"`
}

func (DHCPScope) Kind() Kind { return KindDHCPScope }

// DHCPReservation gives one client a fixed address. An IPv4 client is known
// by its hardware address; an IPv6 client by its DUID or hardware address.
type DHCPReservation struct {
	MAC      string `json:"mac,omitempty" yaml:"mac,omitempty" validate:"omitempty,mac" ui:"label=Hardware address,order=10"`
	DUID     string `json:"duid,omitempty" yaml:"duid,omitempty" validate:"omitempty,duid" ui:"label=DUID (IPv6),order=20"`
	Address  string `json:"address" yaml:"address" validate:"required,ip" ui:"label=Address,order=30"`
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty" validate:"omitempty,hostname_rfc1123" ui:"label=Host name,order=40"`
}

// RouterAdvert announces this node as an IPv6 router on one interface, with
// the prefixes clients configure addresses from.
type RouterAdvert struct {
	Meta      `yaml:",inline"`
	Enabled   bool     `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Interface string   `json:"interface" yaml:"interface" validate:"required,ifname" ui:"label=Interface,order=10"`
	Mode      string   `json:"mode" yaml:"mode" validate:"required,oneof=slaac stateless managed" ui:"label=Address assignment,widget=select,order=20,help=slaac: clients form addresses; stateless: and ask DHCPv6 for options; managed: DHCPv6 assigns addresses"`
	Prefixes  []string `json:"prefixes,omitempty" yaml:"prefixes,omitempty" validate:"max=8,dive,cidr" ui:"label=Prefixes,widget=list,order=30,help=/64 prefixes; default: the interface's IPv6 networks"`
	DNS       []string `json:"dns,omitempty" yaml:"dns,omitempty" validate:"max=4,dive,ip" ui:"label=DNS servers (RDNSS),widget=list,order=40,help=Default: this node when its resolver answers on the interface"`
	Domains   []string `json:"domains,omitempty" yaml:"domains,omitempty" validate:"max=4,dive,hostname_rfc1123" ui:"label=Search domains (DNSSL),widget=list,order=50"`
	MTU       int      `json:"mtu,omitempty" yaml:"mtu,omitempty" validate:"omitempty,min=1280,max=65535" ui:"label=Announced MTU,order=60"`
}

func (RouterAdvert) Kind() Kind { return KindRouterAdvert }

// DNSResolver is the node's caching resolver. It answers only on the listed
// interfaces, and only to the networks behind them (plus AllowFrom).
type DNSResolver struct {
	Meta           `yaml:",inline"`
	Enabled        bool            `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Interfaces     []string        `json:"interfaces" yaml:"interfaces" validate:"required,min=1,max=32,dive,ifname" ui:"label=Answer on interfaces,widget=list,order=10"`
	Mode           string          `json:"mode" yaml:"mode" validate:"required,oneof=recursive forward" ui:"label=Resolution,widget=select,order=20,help=recursive: ask the root and authoritative servers; forward: ask the upstream servers"`
	Upstreams      []string        `json:"upstreams,omitempty" yaml:"upstreams,omitempty" validate:"required_if=Mode forward,max=8,dive,dnsupstream" ui:"label=Upstream servers,widget=list,order=30,help=Address or address#name for DNS over TLS such as 9.9.9.9#dns.quad9.net"`
	TLS            bool            `json:"tls,omitempty" yaml:"tls,omitempty" validate:"-" ui:"label=Upstream over TLS,order=40,help=Port 853; every upstream needs its #name"`
	DNSSEC         bool            `json:"dnssec" yaml:"dnssec" validate:"-" ui:"label=Validate DNSSEC,order=50"`
	LocalDomain    string          `json:"local_domain,omitempty" yaml:"local_domain,omitempty" validate:"omitempty,hostname_rfc1123" ui:"label=Local domain,order=60,help=Names under it are answered from records and leases only; default home.arpa"`
	DomainForwards []DomainForward `json:"domain_forwards,omitempty" yaml:"domain_forwards,omitempty" validate:"max=32,dive" ui:"label=Domain forwards,widget=table,order=70"`
	AllowFrom      []string        `json:"allow_from,omitempty" yaml:"allow_from,omitempty" validate:"max=32,dive,cidr" ui:"label=Also answer,widget=list,order=80,help=Networks reaching the listed interfaces through a router or tunnel"`
}

func (DNSResolver) Kind() Kind { return KindDNSResolver }

// DomainForward sends the questions for one domain to its own servers, for
// example an internal directory's domain.
type DomainForward struct {
	Domain  string   `json:"domain" yaml:"domain" validate:"required,hostname_rfc1123" ui:"label=Domain,order=10"`
	Servers []string `json:"servers" yaml:"servers" validate:"required,min=1,max=8,dive,dnsupstream" ui:"label=Servers,widget=list,order=20"`
}

// DNSRecord is a name the resolver answers itself. A and AAAA records get
// their reverse entries.
type DNSRecord struct {
	Meta  `yaml:",inline"`
	Host  string `json:"host" yaml:"host" validate:"required,hostname_rfc1123" ui:"label=Name,order=10,help=Fully qualified such as nas.home.arpa"`
	Type  string `json:"type" yaml:"type" validate:"required,oneof=A AAAA CNAME TXT" ui:"label=Type,widget=select,order=20"`
	Value string `json:"value" yaml:"value" validate:"required,max=255" ui:"label=Value,order=30"`
	TTL   int    `json:"ttl,omitempty" yaml:"ttl,omitempty" validate:"omitempty,min=0,max=86400" ui:"label=TTL (s),order=40,help=Default 3600"`
}

func (DNSRecord) Kind() Kind { return KindDNSRecord }

// NTPService keeps the node's clock in step with upstream servers and
// serves time on the listed interfaces.
type NTPService struct {
	Meta       `yaml:",inline"`
	Enabled    bool     `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Interfaces []string `json:"interfaces,omitempty" yaml:"interfaces,omitempty" validate:"max=32,dive,ifname" ui:"label=Serve time on interfaces,widget=list,order=10,help=Empty: keep this node's clock only"`
	Servers    []string `json:"servers,omitempty" yaml:"servers,omitempty" validate:"max=8,dive,hostorip" ui:"label=Servers,widget=list,order=20"`
	Pools      []string `json:"pools,omitempty" yaml:"pools,omitempty" validate:"max=4,dive,hostname_rfc1123" ui:"label=Pools,widget=list,order=30,help=Such as 2.debian.pool.ntp.org"`
	NTS        bool     `json:"nts,omitempty" yaml:"nts,omitempty" validate:"-" ui:"label=Authenticate servers with NTS,order=40"`
	AllowFrom  []string `json:"allow_from,omitempty" yaml:"allow_from,omitempty" validate:"max=32,dive,cidr" ui:"label=Also serve,widget=list,order=50,help=Networks reaching the listed interfaces through a router or tunnel"`
	ServeOnly  bool     `json:"serve_only,omitempty" yaml:"serve_only,omitempty" validate:"-" ui:"label=Leave the system clock alone,order=60,help=Track time and serve it without setting the clock: when something else sets it"`
}

func (NTPService) Kind() Kind { return KindNTPService }

// NodeSettings are a node's monitoring thresholds and integrations. The
// object with the narrowest scope that applies to a node is the one it
// uses; a value left empty is the built-in default. Whether the node may
// write to the kernel at all stays a switch of the node itself.
type NodeSettings struct {
	Meta               `yaml:",inline"`
	PacketLossPct      float64 `json:"packet_loss_pct,omitempty" yaml:"packet_loss_pct,omitempty" validate:"min=0,max=100" ui:"label=Packet loss threshold (%),group=Thresholds,order=10"`
	DNSLatencyMs       float64 `json:"dns_latency_ms,omitempty" yaml:"dns_latency_ms,omitempty" validate:"min=0" ui:"label=DNS latency threshold (ms),group=Thresholds,order=20"`
	JitterMs           float64 `json:"jitter_ms,omitempty" yaml:"jitter_ms,omitempty" validate:"min=0" ui:"label=Jitter threshold (ms),group=Thresholds,order=30"`
	RTTMs              float64 `json:"rtt_ms,omitempty" yaml:"rtt_ms,omitempty" validate:"min=0" ui:"label=Round-trip threshold (ms),group=Thresholds,order=40"`
	RetransmissionsPct float64 `json:"retransmissions_pct,omitempty" yaml:"retransmissions_pct,omitempty" validate:"min=0,max=100" ui:"label=Retransmissions threshold (%),group=Thresholds,order=50"`
	FlowRetransPct     float64 `json:"flow_retrans_pct,omitempty" yaml:"flow_retrans_pct,omitempty" validate:"min=0,max=100" ui:"label=Retransmissions per flow (%),group=Thresholds,order=60"`
	IncidentCooldown   string  `json:"incident_cooldown,omitempty" yaml:"incident_cooldown,omitempty" validate:"omitempty,duration" ui:"label=Incident cooldown,group=Thresholds,order=70,help=For example 5m"`
	ExpectedDownMbps   float64 `json:"expected_down_mbps,omitempty" yaml:"expected_down_mbps,omitempty" validate:"min=0" ui:"label=Expected download (Mbit/s),group=Thresholds,order=80"`
	ExpectedUpMbps     float64 `json:"expected_up_mbps,omitempty" yaml:"expected_up_mbps,omitempty" validate:"min=0" ui:"label=Expected upload (Mbit/s),group=Thresholds,order=90"`

	IPFIXEnabled     bool   `json:"ipfix_enabled,omitempty" yaml:"ipfix_enabled,omitempty" validate:"-" ui:"label=IPFIX export,group=Flow export,order=110"`
	IPFIXEndpoint    string `json:"ipfix_endpoint,omitempty" yaml:"ipfix_endpoint,omitempty" validate:"omitempty,hostport" ui:"label=IPFIX collector,group=Flow export,order=120"`
	IPFIXIntervalSec int    `json:"ipfix_interval_sec,omitempty" yaml:"ipfix_interval_sec,omitempty" validate:"min=0,max=3600" ui:"label=IPFIX interval (s),group=Flow export,order=130"`
	IPFIXDomainID    uint32 `json:"ipfix_domain_id,omitempty" yaml:"ipfix_domain_id,omitempty" validate:"-" ui:"label=IPFIX observation domain,group=Flow export,order=140"`
	EBPFEnabled      bool   `json:"ebpf_enabled,omitempty" yaml:"ebpf_enabled,omitempty" validate:"-" ui:"label=eBPF telemetry,group=Flow export,order=150"`

	SentryDSN string `json:"sentry_dsn,omitempty" yaml:"sentry_dsn,omitempty" validate:"omitempty,url,max=512" ui:"label=Sentry DSN,widget=password,group=Integrations,order=210" secret:"true"`

	GuacamoleURL            string `json:"guacamole_url,omitempty" yaml:"guacamole_url,omitempty" validate:"omitempty,url,max=512" ui:"label=Guacamole URL,group=Integrations,order=220"`
	GuacamoleConnID         string `json:"guacamole_conn_id,omitempty" yaml:"guacamole_conn_id,omitempty" validate:"max=128" ui:"label=Guacamole connection,group=Integrations,order=230"`
	GuacamoleTemplate       string `json:"guacamole_template,omitempty" yaml:"guacamole_template,omitempty" validate:"max=512" ui:"label=Connect URL template,group=Integrations,order=240"`
	GuacamoleAPIUser        string `json:"guacamole_api_user,omitempty" yaml:"guacamole_api_user,omitempty" validate:"max=128" ui:"label=Guacamole API user,group=Integrations,order=250"`
	GuacamoleAPIPassword    string `json:"guacamole_api_password,omitempty" yaml:"guacamole_api_password,omitempty" validate:"max=256" ui:"label=Guacamole API password,widget=password,group=Integrations,order=260" secret:"true"`
	GuacamoleRecordingPath  string `json:"guacamole_recording_path,omitempty" yaml:"guacamole_recording_path,omitempty" validate:"max=512" ui:"label=Guacamole recording path,group=Integrations,order=270"`
	GuacamoleTypescriptPath string `json:"guacamole_typescript_path,omitempty" yaml:"guacamole_typescript_path,omitempty" validate:"max=512" ui:"label=Guacamole typescript path,group=Integrations,order=280"`

	MaxMindEnabled      bool   `json:"maxmind_enabled,omitempty" yaml:"maxmind_enabled,omitempty" validate:"-" ui:"label=MaxMind databases,group=GeoIP,order=310"`
	MaxMindDBDir        string `json:"maxmind_db_dir,omitempty" yaml:"maxmind_db_dir,omitempty" validate:"max=512" ui:"label=Database directory,group=GeoIP,order=320"`
	MaxMindAccountID    string `json:"maxmind_account_id,omitempty" yaml:"maxmind_account_id,omitempty" validate:"max=64" ui:"label=Account ID,group=GeoIP,order=330"`
	MaxMindLicenseKey   string `json:"maxmind_license_key,omitempty" yaml:"maxmind_license_key,omitempty" validate:"max=128" ui:"label=License key,widget=password,group=GeoIP,order=340" secret:"true"`
	MaxMindEditions     string `json:"maxmind_editions,omitempty" yaml:"maxmind_editions,omitempty" validate:"max=256" ui:"label=Editions,group=GeoIP,order=350,help=Edition IDs separated by commas"`
	MaxMindAutoUpdate   bool   `json:"maxmind_auto_update,omitempty" yaml:"maxmind_auto_update,omitempty" validate:"-" ui:"label=Update automatically,group=GeoIP,order=360"`
	MaxMindRefreshHours int    `json:"maxmind_refresh_hours,omitempty" yaml:"maxmind_refresh_hours,omitempty" validate:"min=0,max=8760" ui:"label=Update every (hours),group=GeoIP,order=370"`
}

func (NodeSettings) Kind() Kind { return KindNodeSettings }

// Bond joins network devices of a node into one link: LACP (802.3ad) with
// a switch, or active-backup without one. Testudo creates the device and
// enslaves the members; an interface of the model gives it addresses.
type Bond struct {
	Meta       `yaml:",inline"`
	Enabled    bool     `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Device     string   `json:"device" yaml:"device" validate:"required,ifname" ui:"label=Device,order=10,help=Name of the bond such as bond0"`
	Members    []string `json:"members" yaml:"members" validate:"required,min=1,max=16,dive,ifname" ui:"label=Members,widget=list,order=20,help=Devices joined into the bond"`
	Mode       string   `json:"mode" yaml:"mode" validate:"required,oneof=802.3ad active-backup balance-rr balance-xor broadcast balance-tlb balance-alb" ui:"label=Mode,widget=select,order=30,help=802.3ad is LACP with a switch"`
	LACPRate   string   `json:"lacp_rate,omitempty" yaml:"lacp_rate,omitempty" validate:"omitempty,oneof=slow fast" ui:"label=LACP rate,widget=select,order=40"`
	HashPolicy string   `json:"hash_policy,omitempty" yaml:"hash_policy,omitempty" validate:"omitempty,oneof=layer2 layer2+3 layer3+4 encap2+3 encap3+4" ui:"label=Transmit hash,widget=select,order=50"`
	MIIMon     int      `json:"miimon,omitempty" yaml:"miimon,omitempty" validate:"min=0,max=10000" ui:"label=Link check interval (ms),order=60,help=Empty is 100"`
	Primary    string   `json:"primary,omitempty" yaml:"primary,omitempty" validate:"omitempty,ifname" ui:"label=Primary member,order=70,help=For active-backup and the balance-tlb and balance-alb modes"`
}

func (Bond) Kind() Kind { return KindBond }

// Bridge switches between network devices of a node.
type Bridge struct {
	Meta          `yaml:",inline"`
	Enabled       bool     `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Device        string   `json:"device" yaml:"device" validate:"required,ifname" ui:"label=Device,order=10,help=Name of the bridge such as br0"`
	Ports         []string `json:"ports,omitempty" yaml:"ports,omitempty" validate:"max=64,dive,ifname" ui:"label=Ports,widget=list,order=20"`
	STP           bool     `json:"stp,omitempty" yaml:"stp,omitempty" validate:"-" ui:"label=Spanning tree,order=30"`
	VLANFiltering bool     `json:"vlan_filtering,omitempty" yaml:"vlan_filtering,omitempty" validate:"-" ui:"label=VLAN-aware,order=40"`
}

func (Bridge) Kind() Kind { return KindBridge }

// VLAN is a tagged sub-interface of a node's device.
type VLAN struct {
	Meta     `yaml:",inline"`
	Enabled  bool   `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Device   string `json:"device" yaml:"device" validate:"required,ifname" ui:"label=Device,order=10,help=Name such as eth0.100"`
	Parent   string `json:"parent" yaml:"parent" validate:"required,ifname" ui:"label=Parent device,order=20"`
	VID      int    `json:"vid" yaml:"vid" validate:"required,min=1,max=4094" ui:"label=VLAN ID,order=30"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty" validate:"omitempty,oneof=802.1q 802.1ad" ui:"label=Protocol,widget=select,order=40,help=802.1ad for an outer tag (QinQ)"`
}

func (VLAN) Kind() Kind { return KindVLAN }
