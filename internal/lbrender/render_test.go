package lbrender

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/testutil/golden"
)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }
func svc(n int) model.Ref[model.LBService] {
	return model.Ref[model.LBService]{ID: id(n)}
}
func pool(n int) model.Ref[model.LBBackendPool] {
	return model.Ref[model.LBBackendPool]{ID: id(n)}
}

func opts() Options {
	return Options{Dir: "/var/lib/testudo/proxy", SecretsDir: "/var/lib/testudo/secrets", APIAddr: "127.0.0.1:18089",
		AuthURL: "http://127.0.0.1:8080/api/v1/forward-auth"}
}

func build(t *testing.T, objs ...model.Entity) *confstore.State {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	wrr := func(n int, name string, backends ...model.LBBackend) *model.LBBackendPool {
		return &model.LBBackendPool{Meta: meta(n, name), Algorithm: "weighted_round_robin", Backends: backends,
			HealthCheck: model.LBHealthCheck{Type: "none"}}
	}
	web := wrr(20, "web", model.LBBackend{Address: "10.50.0.2:8080", Weight: 3}, model.LBBackend{Address: "10.50.0.3:8080", Weight: 1},
		model.LBBackend{Address: "10.50.0.4:8080", Drain: true})
	web.HealthCheck = model.LBHealthCheck{Type: "http", Path: "/healthz", Interval: "5s", Timeout: "2s"}
	web.Sticky = true
	tlsPool := wrr(22, "tls-b", model.LBBackend{Address: "10.50.0.3:8443", Weight: 2}, model.LBBackend{Address: "10.50.0.5:8443", Weight: 1})
	tlsPool.ProxyProtocol = "v2"
	base := []model.Entity{
		&model.Zone{Meta: meta(10, "wan"), DefaultAction: "drop"},
		web,
		wrr(21, "tls-a", model.LBBackend{Address: "10.50.0.2:8443"}),
		tlsPool,
		wrr(23, "dns", model.LBBackend{Address: "10.50.0.2:53"}, model.LBBackend{Address: "10.50.0.3:53"}),
		wrr(24, "api", model.LBBackend{Address: "10.50.0.6:9000"}),
	}
	for _, e := range append(base, objs...) {
		if _, err := s.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
	}
	return s.Current()
}

func service(n int, name, proto string, port int) *model.LBService {
	return &model.LBService{Meta: meta(n, name), Enabled: true, Zone: model.Ref[model.Zone]{ID: id(10)}, Port: port, Protocol: proto, Mode: "proxy"}
}

func full(t *testing.T) *confstore.State {
	fallbackHTTP := service(30, "http", "http", 80)
	fallbackHTTP.DefaultPool = pool(20)
	tcp := service(32, "tls", "tcp", 8443)
	tcp.DefaultPool = pool(21)
	udp := service(33, "dns", "udp", 53)
	udp.DefaultPool = pool(23)
	udp.Address = "192.0.2.1"
	kernel := service(34, "fast", "tcp", 9000)
	kernel.Mode, kernel.DefaultPool = "kernel", pool(24)
	return build(t, fallbackHTTP, service(31, "https", "https", 443), tcp, udp, kernel,
		&model.Group{Meta: meta(40, "staff")},
		&model.Certificate{Meta: meta(50, "internal"), Source: "internal_ca", Domains: []string{"app.example.com"},
			ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", KeyRef: "cert-app"},
		&model.Certificate{Meta: meta(51, "public"), Source: "acme", Domains: []string{"www.example.com", "example.com"},
			Challenge: "http-01", Email: "ops@example.com"},
		&model.Middleware{Meta: meta(60, "secure-headers"), Type: "headers",
			Settings: map[string]string{"response.Strict-Transport-Security": "max-age=31536000", "request.X-Forwarded-Proto": "https"}},
		&model.Middleware{Meta: meta(61, "limit"), Type: "rate_limit", Settings: map[string]string{"average": "100", "burst": "50"}},
		&model.Middleware{Meta: meta(62, "office-only"), Type: "ip_allow_list", Settings: map[string]string{"source_range": "10.0.0.0/8, 192.0.2.0/24"}},
		&model.Middleware{Meta: meta(63, "retry"), Type: "retry", Settings: map[string]string{"attempts": "3"}},
		&model.Middleware{Meta: meta(64, "breaker"), Type: "circuit_breaker"},
		&model.Middleware{Meta: meta(65, "gzip"), Type: "compress"},
		&model.Middleware{Meta: meta(66, "to-https"), Type: "redirect"},
		&model.LBRouter{Meta: meta(70, "redirect"), Enabled: true, Service: svc(30), Hosts: []string{"www.example.com"}, TLS: "none",
			Pool: pool(20), Middlewares: []model.Ref[model.Middleware]{{ID: id(66)}}, Priority: 50},
		&model.LBRouter{Meta: meta(71, "www"), Enabled: true, Service: svc(31), Hosts: []string{"www.example.com", "example.com"}, TLS: "terminate",
			Certificate: model.Ref[model.Certificate]{ID: id(51)}, Pool: pool(20),
			Middlewares: []model.Ref[model.Middleware]{{ID: id(60)}, {ID: id(61)}, {ID: id(63)}, {ID: id(64)}, {ID: id(65)}}},
		&model.LBRouter{Meta: meta(72, "app"), Enabled: true, Service: svc(31), Hosts: []string{"app.example.com", "*.apps.example.com"},
			PathPrefix: "/api", TLS: "terminate", Certificate: model.Ref[model.Certificate]{ID: id(50)}, Pool: pool(24),
			Middlewares: []model.Ref[model.Middleware]{{ID: id(62)}}, RequireGroups: []model.Ref[model.Group]{{ID: id(40)}}},
		&model.LBRouter{Meta: meta(73, "sni-a"), Enabled: true, Service: svc(32), SNI: []string{"a.example.com"}, TLS: "passthrough", Pool: pool(21)},
		&model.LBRouter{Meta: meta(74, "sni-b"), Enabled: true, Service: svc(32), SNI: []string{"b.example.com", "*.b.example.com"}, TLS: "passthrough", Pool: pool(22)},
		&model.LBRouter{Meta: meta(75, "sni-term"), Enabled: true, Service: svc(32), SNI: []string{"app.example.com"}, TLS: "terminate",
			Certificate: model.Ref[model.Certificate]{ID: id(50)}, Pool: pool(24)},
		&model.LBRouter{Meta: meta(76, "off"), Enabled: false, Service: svc(30), Hosts: []string{"off.example.com"}, TLS: "none", Pool: pool(20)},
	)
}

func TestRenderGolden(t *testing.T) {
	res, err := Render(full(t), opts())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for name := range res.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "### %s\n%s\n", name, res.Files[name])
	}
	golden.Assert(t, "proxy.golden", []byte(b.String()))

	dyn := res.Files[DynamicFile]
	for _, want := range []string{
		"HostSNI(`a.example.com`)", "HostSNIRegexp(`^.+\\.b\\.example\\.com$`)", "passthrough: true",
		"HostRegexp(`^.+\\.apps\\.example\\.com$`)", "PathPrefix(`/api`)", "forwardAuth", "?groups=" + id(40),
		"certResolver: acme-http-01", "keyFile: /var/lib/testudo/secrets/cert-app", "weight: 3", "version: 2",
		"name: testudo_lb", "path: /healthz",
	} {
		if !strings.Contains(dyn, want) {
			t.Errorf("dynamic configuration lacks %q", want)
		}
	}
	// A draining backend, a disabled router and a kernel-mode service are
	// not the proxy's business.
	for _, not := range []string{"10.50.0.4", "off.example.com", "address: :9000", "svc-fast"} {
		if strings.Contains(dyn+res.Static, not) {
			t.Errorf("configuration contains %q", not)
		}
	}
	if len(res.Listeners) != 4 || res.Empty {
		t.Errorf("listeners: %+v", res.Listeners)
	}
	// The private key is referenced where it is; it is not among the files.
	for name, content := range res.Files {
		if strings.Contains(content, "PRIVATE KEY") {
			t.Errorf("%s contains a private key", name)
		}
	}
}

func TestProblemsAreNamed(t *testing.T) {
	lc := &model.LBBackendPool{Meta: meta(25, "lc"), Algorithm: "least_connections",
		Backends: []model.LBBackend{{Address: "10.0.0.1:80"}}, HealthCheck: model.LBHealthCheck{Type: "none"}}
	https := service(31, "https", "https", 443)
	cases := map[string][]model.Entity{
		"least connections is not available": {service(30, "http", "http", 80), lc,
			&model.LBRouter{Meta: meta(70, "r"), Enabled: true, Service: svc(30), TLS: "none", Pool: pool(25)}},
		"has to terminate TLS": {https,
			&model.LBRouter{Meta: meta(70, "r"), Enabled: true, Service: svc(31), TLS: "none", Pool: pool(20)}},
		"unknown setting for rate_limit: colour": {service(30, "http", "http", 80),
			&model.Middleware{Meta: meta(60, "m"), Type: "rate_limit", Settings: map[string]string{"average": "5", "colour": "red"}},
			&model.LBRouter{Meta: meta(70, "r"), Enabled: true, Service: svc(30), TLS: "none", Pool: pool(20), Middlewares: []model.Ref[model.Middleware]{{ID: id(60)}}}},
		"needs an enabled HTTP service on port 80": {https,
			&model.Certificate{Meta: meta(51, "c"), Source: "acme", Domains: []string{"a.example.com"}, Challenge: "http-01", Email: "o@example.com"},
			&model.LBRouter{Meta: meta(70, "r"), Enabled: true, Service: svc(31), TLS: "terminate", Certificate: model.Ref[model.Certificate]{ID: id(51)}, Pool: pool(20)}},
		"sticky sessions need an HTTP service": {service(32, "t", "tcp", 9443),
			&model.LBRouter{Meta: meta(70, "r"), Enabled: true, Service: svc(32), TLS: "none", Pool: pool(20)}},
	}
	for want, objs := range cases {
		st, err := func() (st *confstore.State, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("%v", r)
				}
			}()
			return build(t, objs...), nil
		}()
		if err != nil {
			t.Errorf("%s: fixture: %v", want, err)
			continue
		}
		if _, err := Render(st, opts()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v", want, err)
		}
	}
}

func TestEmptyModelAsksNothing(t *testing.T) {
	s, _ := confstore.Open(t.TempDir())
	defer s.Close()
	res, err := Render(s.Current(), opts())
	if err != nil || !res.Empty {
		t.Errorf("empty model: empty=%v err=%v", res.Empty, err)
	}
}
