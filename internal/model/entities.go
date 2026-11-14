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
)

func init() {
	register("interfaces", "Interface", "interfaces/assignments", nodeOnly, func() Entity { return &Interface{} })
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
}

// Interface binds a kernel network device on one node to a zone.
type Interface struct {
	Meta      `yaml:",inline"`
	Device    string    `json:"device" yaml:"device" validate:"required,ifname" ui:"label=Device,order=10,help=Kernel device name such as eth0"`
	Zone      Ref[Zone] `json:"zone,omitzero" yaml:"zone,omitempty" validate:"-" ui:"label=Zone,widget=ref-picker,ref=zone,order=20"`
	Addresses []string  `json:"addresses,omitempty" yaml:"addresses,omitempty" validate:"max=64,dive,cidr" ui:"label=Addresses,widget=list,order=30,help=IPv4 or IPv6 in CIDR form"`
	DHCP      bool      `json:"dhcp,omitempty" yaml:"dhcp,omitempty" validate:"-" ui:"label=DHCP client,order=40"`
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
	Meta        `yaml:",inline"`
	Enabled     bool         `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Destination string       `json:"destination" yaml:"destination" validate:"required,cidr" ui:"label=Destination,order=10"`
	Gateway     Ref[Gateway] `json:"gateway" yaml:"gateway" validate:"required" ui:"label=Gateway,widget=ref-picker,ref=gateway,order=20"`
	VRF         Ref[VRF]     `json:"vrf,omitzero" yaml:"vrf,omitempty" validate:"-" ui:"label=VRF,widget=ref-picker,ref=vrf,order=30"`
	Metric      int          `json:"metric,omitempty" yaml:"metric,omitempty" validate:"min=0,max=65535" ui:"label=Metric,order=40"`
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
}

func (VRF) Kind() Kind { return KindVRF }

// WGTunnel is one WireGuard device. Its private key is never part of the
// model; KeyRef names the entry in the node's secret store.
type WGTunnel struct {
	Meta       `yaml:",inline"`
	Enabled    bool      `json:"enabled" yaml:"enabled" validate:"-" ui:"label=Enabled,order=5"`
	Device     string    `json:"device" yaml:"device" validate:"required,ifname" ui:"label=Device,order=10"`
	Mode       string    `json:"mode" yaml:"mode" validate:"required,oneof=road_warrior site_to_site" ui:"label=Mode,widget=select,order=20"`
	ListenPort int       `json:"listen_port" yaml:"listen_port" validate:"required,min=1,max=65535" ui:"label=Listen port,order=30"`
	Addresses  []string  `json:"addresses" yaml:"addresses" validate:"required,min=1,max=8,dive,cidr" ui:"label=Tunnel addresses,widget=list,order=40"`
	PublicKey  string    `json:"public_key" yaml:"public_key" validate:"required,wgkey" ui:"label=Public key,order=50"`
	KeyRef     string    `json:"key_ref,omitempty" yaml:"key_ref,omitempty" validate:"omitempty,objname" ui:"label=Private key entry,widget=readonly,order=60" secret:"true"`
	Zone       Ref[Zone] `json:"zone" yaml:"zone" validate:"required" ui:"label=Zone,widget=ref-picker,ref=zone,order=70"`
	MTU        int       `json:"mtu,omitempty" yaml:"mtu,omitempty" validate:"omitempty,min=1280,max=9000" ui:"label=MTU,order=80"`
	DNS        []string  `json:"dns,omitempty" yaml:"dns,omitempty" validate:"max=4,dive,ip" ui:"label=DNS servers pushed to clients,widget=list,order=90"`
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
	Endpoint     string        `json:"endpoint,omitempty" yaml:"endpoint,omitempty" validate:"omitempty,hostname_port" ui:"label=Endpoint,order=50"`
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
	Source   string       `json:"source" yaml:"source" validate:"required,oneof=host oidc" ui:"label=Identity source,widget=select,order=30"`
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
	Meta      `yaml:",inline"`
	Source    string     `json:"source" yaml:"source" validate:"required,oneof=acme import internal_ca" ui:"label=Source,widget=select,order=10"`
	Domains   []string   `json:"domains" yaml:"domains" validate:"required,min=1,max=100,dive,fqdn_or_wildcard" ui:"label=Domains,widget=list,order=20"`
	Challenge string     `json:"challenge,omitempty" yaml:"challenge,omitempty" validate:"required_if=Source acme,omitempty,oneof=http-01 tls-alpn-01 dns-01" ui:"label=ACME challenge,widget=select,order=30"`
	ChainPEM  string     `json:"chain_pem,omitempty" yaml:"chain_pem,omitempty" validate:"required_if=Source import,max=65536" ui:"label=Certificate chain (PEM),widget=textarea,order=40"`
	KeyRef    string     `json:"key_ref,omitempty" yaml:"key_ref,omitempty" validate:"omitempty,objname" ui:"label=Private key entry,widget=readonly,order=50" secret:"true"`
	NotAfter  *time.Time `json:"not_after,omitempty" yaml:"not_after,omitempty" validate:"-" ui:"label=Expires,widget=readonly,order=60"`
}

func (Certificate) Kind() Kind { return KindCertificate }

// LBBackend is one server in a pool.
type LBBackend struct {
	Address string    `json:"address" yaml:"address" validate:"required,hostname_port" ui:"label=Address,order=10,help=host:port"`
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
	MeshEndpoint string           `json:"mesh_endpoint,omitempty" yaml:"mesh_endpoint,omitempty" validate:"omitempty,hostname_port" ui:"label=Mesh endpoint,order=40"`
	ASN          uint32           `json:"asn,omitempty" yaml:"asn,omitempty" validate:"-" ui:"label=AS number,order=50"`
}

func (Site) Kind() Kind { return KindSite }

// ClusterNode is one appliance.
type ClusterNode struct {
	Meta         `yaml:",inline"`
	Site         Ref[Site] `json:"site" yaml:"site" validate:"required" ui:"label=Site,widget=ref-picker,ref=site,order=10"`
	Hostname     string    `json:"hostname" yaml:"hostname" validate:"required,hostname_rfc1123" ui:"label=Hostname,order=20"`
	Address      string    `json:"address" yaml:"address" validate:"required,ip" ui:"label=Cluster address,order=30,help=Address on the site mesh"`
	VRRPPriority int       `json:"vrrp_priority,omitempty" yaml:"vrrp_priority,omitempty" validate:"min=0,max=254" ui:"label=VRRP priority,order=40"`
}

func (ClusterNode) Kind() Kind { return KindClusterNode }
