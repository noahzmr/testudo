// Package lbrender turns the configuration model's load-balancing objects
// into the configuration of the managed proxy (Traefik): the static part
// with one entry point per listener, the dynamic part with routers, services
// and middlewares, and the certificate files.
//
// Render is pure. Services in kernel mode are not rendered here; the packet
// filter balances those.
package lbrender

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// Options are the node-local facts the model does not hold.
type Options struct {
	SiteID, NodeID string
	// Dir is where the proxy's files live.
	Dir string
	// SecretsDir is the node's secret store; private keys are referenced
	// there, never copied.
	SecretsDir string
	// APIAddr is the loopback address of the proxy's own API and metrics.
	APIAddr string
	// AuthURL is where the proxy asks whether a request may pass, for
	// routers that require a login.
	AuthURL string
}

// Result is everything the proxy stage writes.
type Result struct {
	// Files maps a path below Options.Dir to its content.
	Files map[string]string `json:"files"`
	// Static is the proxy's static configuration; it is also in Files. A
	// change to it needs a restart, everything else is picked up live.
	Static string `json:"static"`
	// Empty is true when the model asks nothing of the proxy.
	Empty bool `json:"empty"`
	// Listeners names what the proxy listens on, for the firewall hints.
	Listeners []Listener `json:"listeners,omitempty"`
	// Routers and Pools map the proxy's object names back to model ids, so
	// its state and metrics can be reported per model object.
	Routers map[string]string `json:"routers,omitempty"`
	Pools   map[string]string `json:"pools,omitempty"`
}

// Listener is one address the proxy binds.
type Listener struct {
	Service  string `json:"service"` // model id
	Name     string `json:"name"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

const (
	StaticFile  = "traefik.yml"
	DynamicFile = "dynamic/testudo.yml"
)

type renderer struct {
	st   *confstore.State
	opt  Options
	errs []string
}

func (r *renderer) fail(e model.Entity, format string, a ...any) {
	r.errs = append(r.errs, fmt.Sprintf("%s %q: %s", e.Kind(), e.GetMeta().Name, fmt.Sprintf(format, a...)))
}

func effective[T model.Entity](r *renderer, kind model.Kind) map[string]T {
	out := map[string]T{}
	for _, e := range r.st.List(kind) {
		if !model.AppliesTo(e, r.opt.SiteID, r.opt.NodeID) {
			continue
		}
		eff, _, err := model.Effective(e, r.opt.SiteID, r.opt.NodeID)
		if err != nil {
			r.fail(e, "%v", err)
			continue
		}
		out[eff.GetMeta().ID] = eff.(T)
	}
	return out
}

// ident builds a proxy object name that is readable and cannot collide.
func ident(prefix string, m *model.Meta) string {
	name := strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			return c
		}
		return '-'
	}, m.Name)
	if len(name) > 40 {
		name = name[:40]
	}
	return prefix + "-" + name + "-" + strings.ReplaceAll(m.ID, "-", "")[:6]
}

func sortedIDs[V model.Entity](m map[string]V) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := m[ids[i]].GetMeta(), m[ids[j]].GetMeta()
		return a.Name+a.ID < b.Name+b.ID
	})
	return ids
}

func marshal(v any) string {
	out, err := yaml.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(out)
}

// hostRule matches a list of names for HTTP (Host) or TLS (HostSNI). A
// leading "*." label becomes a regular expression for one or more labels.
func hostRule(fn string, names []string) string {
	var parts []string
	for _, n := range names {
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			parts = append(parts, fmt.Sprintf("%sRegexp(`^.+\\.%s$`)", fn, strings.ReplaceAll(rest, ".", `\.`)))
		} else {
			parts = append(parts, fmt.Sprintf("%s(`%s`)", fn, n))
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " || ") + ")"
}

func duration(e model.Entity, r *renderer, s, fallback string) string {
	if s == "" {
		return fallback
	}
	if _, err := time.ParseDuration(s); err != nil {
		r.fail(e, "bad duration %q", s)
	}
	return s
}

// Render builds the proxy's configuration for the node.
func Render(st *confstore.State, opt Options) (Result, error) {
	r := &renderer{st: st, opt: opt}
	services := effective[*model.LBService](r, model.KindLBService)
	pools := effective[*model.LBBackendPool](r, model.KindLBBackendPool)
	routers := effective[*model.LBRouter](r, model.KindLBRouter)
	middlewares := effective[*model.Middleware](r, model.KindMiddleware)
	certs := effective[*model.Certificate](r, model.KindCertificate)

	res := Result{Files: map[string]string{}, Routers: map[string]string{}, Pools: map[string]string{}}
	entryPoints := map[string]any{"traefik": map[string]any{"address": opt.APIAddr}}
	epName := map[string]string{}
	binds := map[string]string{}
	for _, id := range sortedIDs(services) {
		s := services[id]
		if !s.Enabled || s.Mode != "proxy" {
			continue
		}
		name := ident("svc", &s.Meta)
		addr := net.JoinHostPort(s.Address, strconv.Itoa(s.Port))
		l4 := "tcp"
		ep := map[string]any{"address": addr}
		if s.Protocol == "udp" {
			l4 = "udp"
			ep["address"] = addr + "/udp"
		}
		if other, dup := binds[addr+"/"+l4]; dup {
			r.fail(s, "listens on %s like %q", addr, other)
			continue
		}
		binds[addr+"/"+l4] = s.Name
		if s.Protocol == "https" {
			ep["http3"] = map[string]any{}
		}
		entryPoints[name], epName[id] = ep, name
		res.Listeners = append(res.Listeners, Listener{Service: id, Name: s.Name, Address: s.Address, Port: s.Port, Protocol: s.Protocol})
	}

	httpRouters, httpServices, httpMW := map[string]any{}, map[string]any{}, map[string]any{}
	tcpRouters, tcpServices := map[string]any{}, map[string]any{}
	udpRouters, udpServices := map[string]any{}, map[string]any{}
	usedCerts := map[string]bool{}
	resolvers := map[string]any{}

	// pool renders a backend pool as a service of the given family and
	// returns its name. A pool is rendered once per family it is used in.
	pool := func(e model.Entity, id, family string) string {
		p := pools[id]
		if p == nil {
			r.fail(e, "its backend pool is not in effect on this node")
			return ""
		}
		name := ident("pool", &p.Meta)
		res.Pools[name] = p.ID
		if p.Algorithm != "weighted_round_robin" {
			r.fail(p, "%s is not available; use weighted round robin", strings.ReplaceAll(p.Algorithm, "_", " "))
			return ""
		}
		var servers []map[string]any
		equal := true
		for _, b := range p.Backends {
			if b.Drain {
				continue // no new traffic; connections that exist run out
			}
			w := b.Weight
			if w == 0 {
				w = 1
			}
			if len(servers) > 0 && w != servers[0]["weight"] {
				equal = false
			}
			servers = append(servers, map[string]any{"address": b.Address, "weight": w})
		}
		switch family {
		case "http":
			if _, done := httpServices[name]; done {
				return name
			}
			if p.ProxyProtocol != "" {
				r.fail(p, "the PROXY protocol toward backends is available for TCP services only")
			}
			lb := map[string]any{"passHostHeader": true}
			var list []any
			for _, s := range servers {
				list = append(list, map[string]any{"url": "http://" + s["address"].(string), "weight": s["weight"]})
			}
			lb["servers"] = list
			if p.HealthCheck.Type == "http" {
				lb["healthCheck"] = map[string]any{"path": p.HealthCheck.Path,
					"interval": duration(p, r, p.HealthCheck.Interval, "10s"), "timeout": duration(p, r, p.HealthCheck.Timeout, "3s")}
			}
			if p.Sticky {
				lb["sticky"] = map[string]any{"cookie": map[string]any{"name": "testudo_lb", "httpOnly": true}}
			}
			httpServices[name] = map[string]any{"loadBalancer": lb}
		case "tcp":
			if _, done := tcpServices[name]; done {
				return name
			}
			if p.Sticky {
				r.fail(p, "sticky sessions need an HTTP service")
			}
			one := func(list []map[string]any) map[string]any {
				var out []any
				for _, s := range list {
					out = append(out, map[string]any{"address": s["address"]})
				}
				lb := map[string]any{"servers": out}
				if p.ProxyProtocol != "" {
					lb["proxyProtocol"] = map[string]any{"version": int(p.ProxyProtocol[1] - '0')}
				}
				return map[string]any{"loadBalancer": lb}
			}
			if equal {
				tcpServices[name] = one(servers)
			} else {
				// TCP servers carry no weight; a weighted service over one
				// service per backend does.
				var weighted []any
				for i, s := range servers {
					sub := fmt.Sprintf("%s-b%d", name, i)
					tcpServices[sub] = one([]map[string]any{s})
					weighted = append(weighted, map[string]any{"name": sub, "weight": s["weight"]})
				}
				tcpServices[name] = map[string]any{"weighted": map[string]any{"services": weighted}}
			}
		case "udp":
			var list []any
			for _, s := range servers {
				list = append(list, map[string]any{"address": s["address"]})
			}
			udpServices[name] = map[string]any{"loadBalancer": map[string]any{"servers": list}}
		}
		return name
	}

	tlsFor := func(rt *model.LBRouter, family string) map[string]any {
		switch rt.TLS {
		case "passthrough":
			return map[string]any{"passthrough": true}
		case "terminate":
			c := certs[rt.Certificate.ID]
			if c == nil {
				r.fail(rt, "its certificate is not in effect on this node")
				return nil
			}
			if c.Source != "acme" {
				usedCerts[c.ID] = true
				return map[string]any{}
			}
			res := "acme-" + c.Challenge
			acme := map[string]any{"email": c.Email, "storage": filepath.Join(r.opt.Dir, "acme.json")}
			switch c.Challenge {
			case "http-01":
				web := ""
				for _, id := range sortedIDs(services) {
					if s := services[id]; s.Enabled && s.Mode == "proxy" && s.Protocol == "http" && s.Port == 80 {
						web = epName[id]
					}
				}
				if web == "" {
					r.fail(c, "the HTTP-01 challenge needs an enabled HTTP service on port 80")
				}
				acme["httpChallenge"] = map[string]any{"entryPoint": web}
			case "tls-alpn-01":
				acme["tlsChallenge"] = map[string]any{}
			case "dns-01":
				acme["dnsChallenge"] = map[string]any{"provider": c.DNSProvider}
			}
			resolvers[res] = map[string]any{"acme": acme}
			domain := map[string]any{"main": c.Domains[0]}
			if len(c.Domains) > 1 {
				domain["sans"] = c.Domains[1:]
			}
			return map[string]any{"certResolver": res, "domains": []any{domain}}
		}
		return nil
	}

	for _, id := range sortedIDs(routers) {
		rt := routers[id]
		s := services[rt.Service.ID]
		if !rt.Enabled || s == nil || epName[s.ID] == "" {
			continue
		}
		name := ident("rt", &rt.Meta)
		res.Routers[name] = rt.ID
		entry := []string{epName[s.ID]}
		switch s.Protocol {
		case "http", "https":
			var rule []string
			if len(rt.Hosts) > 0 {
				rule = append(rule, hostRule("Host", rt.Hosts))
			}
			if rt.PathPrefix != "" {
				rule = append(rule, fmt.Sprintf("PathPrefix(`%s`)", rt.PathPrefix))
			}
			if len(rule) == 0 {
				rule = []string{"PathPrefix(`/`)"}
			}
			if len(rt.SNI) > 0 {
				r.fail(rt, "SNI matching needs a tcp service; an HTTP router matches host names")
			}
			route := map[string]any{"entryPoints": entry, "rule": strings.Join(rule, " && "), "service": pool(rt, rt.Pool.ID, "http")}
			if rt.Priority > 0 {
				route["priority"] = rt.Priority
			}
			var mws []string
			if len(rt.RequireGroups) > 0 {
				// The proxy asks the appliance whether the request's user is
				// in one of the groups; without an answer it refuses.
				var groups []string
				for _, g := range rt.RequireGroups {
					groups = append(groups, g.ID)
				}
				sort.Strings(groups)
				auth := name + "-auth"
				httpMW[auth] = map[string]any{"forwardAuth": map[string]any{
					"address": r.opt.AuthURL + "?groups=" + strings.Join(groups, ","), "authResponseHeaders": []string{"X-Forwarded-User"}}}
				mws = append(mws, auth)
			}
			for _, ref := range rt.Middlewares {
				m := middlewares[ref.ID]
				if m == nil {
					r.fail(rt, "one of its middlewares is not in effect on this node")
					continue
				}
				mn := ident("mw", &m.Meta)
				if _, done := httpMW[mn]; !done {
					httpMW[mn] = r.middleware(m)
				}
				mws = append(mws, mn)
			}
			if len(mws) > 0 {
				route["middlewares"] = mws
			}
			switch {
			case rt.TLS == "passthrough":
				r.fail(rt, "TLS passthrough needs a tcp service")
			case rt.TLS == "terminate":
				if t := tlsFor(rt, "http"); t != nil {
					route["tls"] = t
				}
			case s.Protocol == "https":
				r.fail(rt, "a router on an https service has to terminate TLS")
			}
			httpRouters[name] = route
		case "tcp":
			rule := "HostSNI(`*`)"
			if len(rt.SNI) > 0 {
				if rt.TLS == "none" {
					r.fail(rt, "SNI matching needs TLS passthrough or termination")
				}
				rule = hostRule("HostSNI", rt.SNI)
			}
			route := map[string]any{"entryPoints": entry, "rule": rule, "service": pool(rt, rt.Pool.ID, "tcp")}
			if rt.Priority > 0 {
				route["priority"] = rt.Priority
			}
			if t := tlsFor(rt, "tcp"); t != nil {
				route["tls"] = t
			}
			if len(rt.Hosts) > 0 || rt.PathPrefix != "" || len(rt.Middlewares) > 0 || len(rt.RequireGroups) > 0 {
				r.fail(rt, "host names, paths, middlewares and required groups need an http or https service")
			}
			tcpRouters[name] = route
		case "udp":
			r.fail(rt, "a udp service has no routers; it sends everything to its fallback pool")
		}
	}

	// A service's fallback pool takes what no router matched. For UDP it is
	// the only way traffic is assigned.
	for _, id := range sortedIDs(services) {
		s := services[id]
		if epName[id] == "" || s.DefaultPool.ID == "" {
			if epName[id] != "" && s.Protocol == "udp" {
				r.fail(s, "a udp service needs a fallback pool")
			}
			continue
		}
		name := ident("svc", &s.Meta) + "-fallback"
		entry := []string{epName[id]}
		switch s.Protocol {
		case "http":
			httpRouters[name] = map[string]any{"entryPoints": entry, "rule": "PathPrefix(`/`)", "priority": 1, "service": pool(s, s.DefaultPool.ID, "http")}
		case "https":
			r.fail(s, "a fallback pool on an https service would need a certificate; use a router with a wildcard host instead")
		case "tcp":
			// Two routers: one for plain connections and one that passes TLS
			// with an unknown name through untouched. Without the second the
			// proxy would answer such a client itself with its default
			// certificate.
			svc := pool(s, s.DefaultPool.ID, "tcp")
			tcpRouters[name] = map[string]any{"entryPoints": entry, "rule": "HostSNI(`*`)", "priority": 1, "service": svc}
			tcpRouters[name+"-tls"] = map[string]any{"entryPoints": entry, "rule": "HostSNI(`*`)", "priority": 1, "service": svc,
				"tls": map[string]any{"passthrough": true}}
		case "udp":
			udpRouters[name] = map[string]any{"entryPoints": entry, "service": pool(s, s.DefaultPool.ID, "udp")}
		}
	}

	dynamic := map[string]any{}
	section := func(key string, parts map[string]map[string]any) {
		out := map[string]any{}
		for k, v := range parts {
			if len(v) > 0 {
				out[k] = v
			}
		}
		if len(out) > 0 {
			dynamic[key] = out
		}
	}
	section("http", map[string]map[string]any{"routers": httpRouters, "services": httpServices, "middlewares": httpMW})
	section("tcp", map[string]map[string]any{"routers": tcpRouters, "services": tcpServices})
	section("udp", map[string]map[string]any{"routers": udpRouters, "services": udpServices})

	var tlsCerts []any
	for _, id := range sortedIDs(certs) {
		c := certs[id]
		if !usedCerts[id] {
			continue
		}
		if c.ChainPEM == "" || c.KeyRef == "" {
			r.fail(c, "has no certificate chain or no private key entry")
			continue
		}
		file := "certs/" + c.ID + ".pem"
		res.Files[file] = c.ChainPEM
		// The key is used from the secret store, where it already is.
		tlsCerts = append(tlsCerts, map[string]any{"certFile": filepath.Join(opt.Dir, file), "keyFile": filepath.Join(opt.SecretsDir, c.KeyRef)})
	}
	if len(tlsCerts) > 0 {
		dynamic["tls"] = map[string]any{"certificates": tlsCerts}
	}

	static := map[string]any{
		"entryPoints": entryPoints,
		"api":         map[string]any{"insecure": true, "dashboard": false},
		"ping":        map[string]any{"entryPoint": "traefik"},
		"metrics":     map[string]any{"prometheus": map[string]any{"entryPoint": "traefik", "addRoutersLabels": true, "addServicesLabels": true}},
		"providers":   map[string]any{"file": map[string]any{"directory": filepath.Join(opt.Dir, "dynamic"), "watch": true}},
		"log":         map[string]any{"level": "INFO"},
		"accessLog":   map[string]any{"filePath": filepath.Join(opt.Dir, "access.log"), "format": "json"},
		"global":      map[string]any{"checkNewVersion": false, "sendAnonymousUsage": false},
	}
	if len(resolvers) > 0 {
		static["certificatesResolvers"] = resolvers
	}
	res.Static = marshal(static)
	res.Files[StaticFile] = res.Static
	res.Files[DynamicFile] = marshal(dynamic)
	res.Empty = len(entryPoints) == 1
	if len(r.errs) > 0 {
		sort.Strings(r.errs)
		return res, fmt.Errorf("lbrender: %s", strings.Join(r.errs, "; "))
	}
	return res, nil
}

// middleware translates a middleware's settings. Unknown settings are an
// error, so a typo never silently leaves a protection off.
func (r *renderer) middleware(m *model.Middleware) map[string]any {
	left := map[string]string{}
	for k, v := range m.Settings {
		left[k] = v
	}
	take := func(key string) string { v := left[key]; delete(left, key); return v }
	num := func(key string) (int, bool) {
		v := take(key)
		if v == "" {
			return 0, false
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			r.fail(m, "setting %s must be a number", key)
		}
		return n, true
	}
	list := func(key string) []string {
		var out []string
		for _, p := range strings.Split(take(key), ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	var out map[string]any
	switch m.Type {
	case "headers":
		req, resp := map[string]string{}, map[string]string{}
		for k, v := range m.Settings {
			if h, ok := strings.CutPrefix(k, "request."); ok {
				req[h] = v
				delete(left, k)
			} else if h, ok := strings.CutPrefix(k, "response."); ok {
				resp[h] = v
				delete(left, k)
			}
		}
		h := map[string]any{}
		if len(req) > 0 {
			h["customRequestHeaders"] = req
		}
		if len(resp) > 0 {
			h["customResponseHeaders"] = resp
		}
		out = map[string]any{"headers": h}
	case "rate_limit":
		rl := map[string]any{}
		if n, ok := num("average"); ok {
			rl["average"] = n
		} else {
			r.fail(m, "needs the setting average (requests per second)")
		}
		if n, ok := num("burst"); ok {
			rl["burst"] = n
		}
		out = map[string]any{"rateLimit": rl}
	case "ip_allow_list":
		src := list("source_range")
		if len(src) == 0 {
			r.fail(m, "needs the setting source_range (comma-separated networks)")
		}
		out = map[string]any{"ipAllowList": map[string]any{"sourceRange": src}}
	case "retry":
		n, ok := num("attempts")
		if !ok {
			n = 2
		}
		out = map[string]any{"retry": map[string]any{"attempts": n}}
	case "circuit_breaker":
		expr := take("expression")
		if expr == "" {
			expr = "NetworkErrorRatio() > 0.30"
		}
		out = map[string]any{"circuitBreaker": map[string]any{"expression": expr}}
	case "compress":
		out = map[string]any{"compress": map[string]any{}}
	case "redirect":
		scheme := take("scheme")
		if scheme == "" {
			scheme = "https"
		}
		out = map[string]any{"redirectScheme": map[string]any{"scheme": scheme, "permanent": true}}
	case "forward_auth":
		addr := take("address")
		if addr == "" {
			r.fail(m, "needs the setting address")
		}
		out = map[string]any{"forwardAuth": map[string]any{"address": addr}}
	}
	if len(left) > 0 {
		keys := make([]string, 0, len(left))
		for k := range left {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		r.fail(m, "unknown setting for %s: %s", m.Type, strings.Join(keys, ", "))
	}
	return out
}
