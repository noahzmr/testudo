package doctor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/probes"
)

// classify maps a probe/error string onto a machine-readable ErrorClass.
// Kept pure and string-based because the underlying probes surface errors as
// plain strings (probes.Result.Err), not typed errors.
func classify(errText string) ErrorClass {
	s := strings.ToLower(strings.TrimSpace(errText))
	switch {
	case s == "":
		return ClassNone
	case strings.Contains(s, "timeout") || strings.Contains(s, "timed out") || strings.Contains(s, "deadline exceeded") || s == "*":
		return ClassTimeout
	case strings.Contains(s, "operation not permitted") || strings.Contains(s, "permission denied") || strings.Contains(s, "cap_net_raw"):
		return ClassPermission
	case strings.Contains(s, "no route to host") || strings.Contains(s, "network is unreachable"):
		return ClassNoRoute
	case strings.Contains(s, "connection refused") || strings.Contains(s, "refused"):
		return ClassRefused
	case strings.Contains(s, "no such host") || strings.Contains(s, "server misbehaving") || strings.Contains(s, "lookup "):
		return ClassDNS
	default:
		return ClassUnknown
	}
}

// --- link layer --------------------------------------------------------------

type linkCheck struct{}

func (linkCheck) Name() string { return "link" }
func (linkCheck) Layer() Layer { return LayerLink }

func (linkCheck) Run(_ context.Context, env *Env) Result {
	ifaces, err := env.Net.Interfaces()
	if err != nil {
		return Result{Status: StatusFail, Class: ClassConfig,
			Summary: "could not read interfaces", Detail: err.Error(),
			Remedy: "ensure the process can read netlink (CAP_NET_ADMIN not required for reads)"}
	}
	var up []string
	for _, i := range ifaces {
		if isLoopbackName(i.Name) {
			continue
		}
		if i.Up && i.Running {
			up = append(up, i.Name)
		}
	}
	env.Findings.UpLinks = up
	if len(up) == 0 {
		return Result{Status: StatusFail, Class: ClassConfig,
			Summary: "no network links are up",
			Remedy:  "check cable / Wi-Fi association, then `ip link set <iface> up`"}
	}
	return Result{Status: StatusPass,
		Summary: fmt.Sprintf("%d link(s) up: %s", len(up), strings.Join(up, ", "))}
}

// --- address layer -----------------------------------------------------------

type addressCheck struct{}

func (addressCheck) Name() string { return "address" }
func (addressCheck) Layer() Layer { return LayerAddress }

func (addressCheck) Run(_ context.Context, env *Env) Result {
	if len(env.Findings.UpLinks) == 0 {
		return Result{Status: StatusSkip, Summary: "skipped: no link up"}
	}
	ifaces, err := env.Net.Interfaces()
	if err != nil {
		return Result{Status: StatusFail, Class: ClassConfig,
			Summary: "could not read interfaces", Detail: err.Error()}
	}
	var routable []string
	for _, i := range ifaces {
		if isLoopbackName(i.Name) || !(i.Up && i.Running) {
			continue
		}
		for _, cidr := range i.Addrs {
			ip := ipFromCIDR(cidr)
			if ip == nil || !isRoutable(ip) {
				continue
			}
			routable = append(routable, fmt.Sprintf("%s (%s)", cidr, i.Name))
		}
	}
	if len(routable) == 0 {
		return Result{Status: StatusFail, Class: ClassConfig,
			Summary: "no routable IP address assigned",
			Detail:  "only loopback/link-local addresses present - DHCP likely failed",
			Remedy:  "renew DHCP (`dhclient <iface>`) or assign a static address"}
	}
	return Result{Status: StatusPass,
		Summary: fmt.Sprintf("routable address(es): %s", strings.Join(routable, ", "))}
}

// --- route layer -------------------------------------------------------------

type routeCheck struct{}

func (routeCheck) Name() string { return "route" }
func (routeCheck) Layer() Layer { return LayerRoute }

func (routeCheck) Run(_ context.Context, env *Env) Result {
	if len(env.Findings.UpLinks) == 0 {
		return Result{Status: StatusSkip, Summary: "skipped: no link up"}
	}
	routes, err := env.Net.Routes()
	if err != nil {
		return Result{Status: StatusFail, Class: ClassConfig,
			Summary: "could not read routing table", Detail: err.Error()}
	}
	for _, r := range routes {
		if r.Dst != "default" || r.Family != "ipv4" {
			continue
		}
		env.Findings.GatewayIP = r.Gateway
		env.Findings.EgressIface = r.Iface
		via := r.Gateway
		if via == "" {
			via = "(on-link)"
		}
		return Result{Status: StatusPass,
			Summary: fmt.Sprintf("default route via %s dev %s", via, r.Iface)}
	}
	return Result{Status: StatusFail, Class: ClassConfig,
		Summary: "no default route",
		Remedy:  "add one: `ip route add default via <gateway> dev <iface>`"}
}

// --- gateway layer -----------------------------------------------------------

type gatewayCheck struct{}

func (gatewayCheck) Name() string { return "gateway" }
func (gatewayCheck) Layer() Layer { return LayerGateway }

func (gatewayCheck) Run(ctx context.Context, env *Env) Result {
	if env.Findings.GatewayIP == "" {
		return Result{Status: StatusSkip, Summary: "skipped: no default gateway to test"}
	}
	gw := env.Findings.GatewayIP
	res, perr := env.Probe.Run(ctx, probes.Request{Kind: probes.KindICMP, Target: gw, Timeout: env.Opts.CheckTimeout})
	if perr != nil {
		return Result{Status: StatusFail, Class: ClassUnknown,
			Summary: "gateway probe error", Detail: perr.Error()}
	}
	if res.OK {
		return Result{Status: StatusPass, Latency: res.Latency,
			Summary: fmt.Sprintf("gateway %s reachable (%s)", gw, res.Latency.Truncate(time.Microsecond))}
	}
	class := classify(res.Err)
	if class == ClassPermission {
		// We can't send ICMP without CAP_NET_RAW (or a permissive
		// ping_group_range). That's not the same as the gateway being down,
		// so warn rather than declaring connectivity broken.
		return Result{Status: StatusWarn, Class: ClassPermission,
			Summary: "gateway reachability untestable (no ICMP permission)",
			Remedy:  "grant CAP_NET_RAW: `sudo setcap cap_net_raw,cap_net_admin=+ep ./testudo`"}
	}
	return Result{Status: StatusFail, Class: class,
		Summary: fmt.Sprintf("gateway %s unreachable", gw), Detail: res.Err,
		Remedy: "L2/local problem: check switch/AP, ARP, or VLAN config"}
}

// --- dns layer ---------------------------------------------------------------

type dnsCheck struct{}

func (dnsCheck) Name() string { return "dns" }
func (dnsCheck) Layer() Layer { return LayerDNS }

func (dnsCheck) Run(ctx context.Context, env *Env) Result {
	if len(env.Findings.UpLinks) == 0 {
		return Result{Status: StatusSkip, Summary: "skipped: no link up"}
	}
	if servers, err := env.Net.DNSServers(); err == nil {
		env.Findings.Resolvers = servers
	}
	name := env.Opts.WANTargetName
	res, perr := env.Probe.Run(ctx, probes.Request{Kind: probes.KindDNS, Target: name, Timeout: env.Opts.CheckTimeout})
	if perr != nil {
		return Result{Status: StatusFail, Class: ClassUnknown,
			Summary: "dns probe error", Detail: perr.Error()}
	}
	resolvers := "(system)"
	if len(env.Findings.Resolvers) > 0 {
		resolvers = strings.Join(env.Findings.Resolvers, ", ")
	}
	if res.OK {
		return Result{Status: StatusPass, Latency: res.Latency,
			Summary: fmt.Sprintf("resolved %s via %s in %s", name, resolvers, res.Latency.Truncate(time.Millisecond))}
	}
	return Result{Status: StatusFail, Class: classify(res.Err),
		Summary: fmt.Sprintf("cannot resolve %s", name), Detail: res.Err,
		Remedy: "resolver unreachable or misconfigured; check /etc/resolv.conf or `resolvectl status`"}
}

// --- wan layer ---------------------------------------------------------------

type wanCheck struct{}

func (wanCheck) Name() string { return "wan" }
func (wanCheck) Layer() Layer { return LayerWAN }

func (wanCheck) Run(ctx context.Context, env *Env) Result {
	if env.Findings.GatewayIP == "" {
		return Result{Status: StatusSkip, Summary: "skipped: no default route to a WAN"}
	}
	ip := env.Opts.WANTargetIP
	res, perr := env.Probe.Run(ctx, probes.Request{Kind: probes.KindICMP, Target: ip, Timeout: env.Opts.CheckTimeout})
	if perr != nil {
		return Result{Status: StatusFail, Class: ClassUnknown,
			Summary: "wan probe error", Detail: perr.Error()}
	}
	if res.OK {
		return Result{Status: StatusPass, Latency: res.Latency,
			Summary: fmt.Sprintf("WAN host %s reachable (%s)", ip, res.Latency.Truncate(time.Microsecond))}
	}
	class := classify(res.Err)
	if class == ClassPermission {
		return Result{Status: StatusWarn, Class: ClassPermission,
			Summary: "WAN reachability untestable (no ICMP permission)",
			Remedy:  "grant CAP_NET_RAW to enable ICMP probes"}
	}
	// Gateway passed (or untested) but the WAN is unreachable by IP - this
	// isolates the fault to the upstream/ISP path rather than DNS or local.
	return Result{Status: StatusFail, Class: class,
		Summary: fmt.Sprintf("WAN host %s unreachable by IP", ip), Detail: res.Err,
		Remedy: "gateway is up but upstream is not - likely ISP / modem / NAT problem"}
}

// --- application layer (captive portal) --------------------------------------

type captiveCheck struct{}

func (captiveCheck) Name() string { return "captive-portal" }
func (captiveCheck) Layer() Layer { return LayerApp }

func (captiveCheck) Run(ctx context.Context, env *Env) Result {
	if env.Opts.SkipCaptive {
		return Result{Status: StatusSkip, Summary: "skipped (--no-captive)"}
	}
	if len(env.Findings.UpLinks) == 0 {
		return Result{Status: StatusSkip, Summary: "skipped: no link up"}
	}
	url := env.Opts.CaptiveURL
	req, err := newGetRequest(ctx, url)
	if err != nil {
		return Result{Status: StatusFail, Class: ClassConfig,
			Summary: "bad captive-portal URL", Detail: err.Error()}
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return Result{Status: StatusFail, Class: classify(err.Error()),
			Summary: "captive-portal probe failed", Detail: err.Error(),
			Remedy: "no clear internet egress at the app layer"}
	}
	defer resp.Body.Close()
	// A clean internet path returns the expected 204 with an empty body.
	// Anything else (302 to a login page, a 200 with HTML) means traffic is
	// being intercepted - the classic captive-portal signature.
	if resp.StatusCode == 204 {
		return Result{Status: StatusPass, Summary: "clean internet egress (HTTP 204)"}
	}
	return Result{Status: StatusWarn, Class: ClassConfig,
		Summary: fmt.Sprintf("captive portal or interception (HTTP %d)", resp.StatusCode),
		Detail:  redirectTarget(resp.Header.Get("Location")),
		Remedy:  "open a browser to complete portal sign-in, or this network filters traffic"}
}

func redirectTarget(loc string) string {
	if loc == "" {
		return ""
	}
	return "redirected to " + loc
}

// --- small pure helpers (unit-tested) ---------------------------------------

func isLoopbackName(name string) bool { return name == "lo" }

// ipFromCIDR parses "192.168.1.20/24" and returns the host IP, or nil.
func ipFromCIDR(cidr string) net.IP {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		// Tolerate a bare IP too.
		return net.ParseIP(cidr)
	}
	return ip
}

// isRoutable reports whether ip is a usable host address (not loopback,
// unspecified, or link-local). Both IPv4 169.254/16 and IPv6 fe80::/10 are
// rejected because they cannot reach a gateway.
func isRoutable(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}
