package doctor

import (
	"context"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/probes"
)

// --- fakes -------------------------------------------------------------------

type fakeNet struct {
	ifaces []netops.IfaceInfo
	routes []netops.RouteInfo
	dns    []string
	err    error
}

func (f fakeNet) Interfaces() ([]netops.IfaceInfo, error) { return f.ifaces, f.err }
func (f fakeNet) Routes() ([]netops.RouteInfo, error)     { return f.routes, f.err }
func (f fakeNet) DNSServers() ([]string, error)           { return f.dns, nil }

// fakeProber answers probes from a per-(kind,target) lookup; absent entries
// default to a timeout failure so an unconfigured target fails closed.
type fakeProber struct {
	answers map[string]*probes.Result
}

func (f fakeProber) Run(_ context.Context, r probes.Request) (*probes.Result, error) {
	key := string(r.Kind) + ":" + r.Target
	if res, ok := f.answers[key]; ok {
		res.Kind = r.Kind
		return res, nil
	}
	return &probes.Result{Kind: r.Kind, OK: false, Err: "timeout"}, nil
}

func ok(lat time.Duration) *probes.Result { return &probes.Result{OK: true, Latency: lat} }
func fail(err string) *probes.Result      { return &probes.Result{OK: false, Err: err} }

// healthyHost is a fully-working host: link up, routable addr, default route.
func healthyNet() fakeNet {
	return fakeNet{
		ifaces: []netops.IfaceInfo{
			{Name: "lo", Up: true, Running: true, Addrs: []string{"127.0.0.1/8"}},
			{Name: "eth0", Up: true, Running: true, Addrs: []string{"192.168.1.20/24"}},
		},
		routes: []netops.RouteInfo{
			{Dst: "default", Gateway: "192.168.1.1", Iface: "eth0", Family: "ipv4"},
		},
		dns: []string{"192.168.1.1"},
	}
}

// runDoctor builds a doctor with fakes and SkipCaptive set (no real HTTP).
func runDoctor(t *testing.T, net NetInfo, p Prober) Report {
	t.Helper()
	opts := DefaultOptions()
	opts.SkipCaptive = true
	opts.CheckTimeout = 100 * time.Millisecond
	d := New(net, p, nil, opts)
	return d.Run(context.Background())
}

// --- selectRootCause ---------------------------------------------------------

func TestSelectRootCause(t *testing.T) {
	tests := []struct {
		name    string
		results []Result
		want    *Layer // nil = expect no root cause
	}{
		{
			name:    "all pass",
			results: []Result{{Layer: LayerLink, Status: StatusPass}, {Layer: LayerDNS, Status: StatusPass}},
			want:    nil,
		},
		{
			name: "lowest failing layer wins",
			results: []Result{
				{Layer: LayerDNS, Status: StatusFail},
				{Layer: LayerRoute, Status: StatusFail},
				{Layer: LayerWAN, Status: StatusFail},
			},
			want: layerPtr(LayerRoute),
		},
		{
			name: "warn is not a root cause",
			results: []Result{
				{Layer: LayerGateway, Status: StatusWarn},
				{Layer: LayerWAN, Status: StatusFail},
			},
			want: layerPtr(LayerWAN),
		},
		{
			name: "skip is not a root cause",
			results: []Result{
				{Layer: LayerLink, Status: StatusSkip},
				{Layer: LayerDNS, Status: StatusFail},
			},
			want: layerPtr(LayerDNS),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectRootCause(tt.results)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("want nil root cause, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want root cause at layer %v, got nil", *tt.want)
			}
			if got.Layer != *tt.want {
				t.Fatalf("want root cause at layer %v, got %v", *tt.want, got.Layer)
			}
		})
	}
}

func layerPtr(l Layer) *Layer { return &l }

// --- verdict / score ---------------------------------------------------------

func TestVerdict(t *testing.T) {
	cases := []struct {
		name string
		res  []Result
		want Verdict
	}{
		{"all pass", []Result{{Status: StatusPass}, {Status: StatusPass}}, VerdictHealthy},
		{"a warn", []Result{{Status: StatusPass}, {Status: StatusWarn}}, VerdictDegraded},
		{"a fail beats a warn", []Result{{Status: StatusWarn}, {Status: StatusFail}}, VerdictBroken},
		{"skips are neutral", []Result{{Status: StatusPass}, {Status: StatusSkip}}, VerdictHealthy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := verdict(c.res); got != c.want {
				t.Fatalf("verdict=%v want %v", got, c.want)
			}
		})
	}
}

func TestScore(t *testing.T) {
	if s := score([]Result{{Status: StatusPass}, {Status: StatusPass}}); s != 100 {
		t.Fatalf("all-pass score=%d want 100", s)
	}
	// A broken link is a heavy (40pt) penalty.
	if s := score([]Result{{Layer: LayerLink, Status: StatusFail}}); s != 60 {
		t.Fatalf("link-fail score=%d want 60", s)
	}
	// A captive-portal warning is a light penalty.
	if s := score([]Result{{Layer: LayerApp, Status: StatusWarn}}); s != 92 {
		t.Fatalf("app-warn score=%d want 92", s)
	}
	// Score floors at zero, never negative.
	if s := score([]Result{
		{Layer: LayerLink, Status: StatusFail},
		{Layer: LayerAddress, Status: StatusFail},
		{Layer: LayerRoute, Status: StatusFail},
	}); s != 0 {
		t.Fatalf("multi-fail score=%d want 0 floor", s)
	}
}

// --- full-run scenarios ------------------------------------------------------

func TestRun_Healthy(t *testing.T) {
	p := fakeProber{answers: map[string]*probes.Result{
		"icmp:192.168.1.1":    ok(2 * time.Millisecond),
		"dns:one.one.one.one": ok(15 * time.Millisecond),
		"icmp:1.1.1.1":        ok(12 * time.Millisecond),
	}}
	rep := runDoctor(t, healthyNet(), p)
	if rep.Verdict != VerdictHealthy {
		t.Fatalf("verdict=%v want healthy; results=%+v", rep.Verdict, rep.Results)
	}
	if rep.RootCause != nil {
		t.Fatalf("healthy host has root cause: %+v", rep.RootCause)
	}
	if rep.Findings.GatewayIP != "192.168.1.1" || rep.Findings.EgressIface != "eth0" {
		t.Fatalf("findings not populated: %+v", rep.Findings)
	}
}

func TestRun_NoLink(t *testing.T) {
	net := fakeNet{ifaces: []netops.IfaceInfo{
		{Name: "lo", Up: true, Running: true, Addrs: []string{"127.0.0.1/8"}},
		{Name: "eth0", Up: false, Running: false},
	}}
	rep := runDoctor(t, net, fakeProber{})
	if rep.RootCause == nil || rep.RootCause.Layer != LayerLink {
		t.Fatalf("want link root cause, got %+v", rep.RootCause)
	}
	// Everything above link should be skipped, not failed - no cascade.
	for _, r := range rep.Results {
		if r.Layer > LayerLink && r.Status == StatusFail {
			t.Fatalf("layer %v failed instead of skipping after link down: %+v", r.Layer, r)
		}
	}
}

func TestRun_NoDefaultRoute(t *testing.T) {
	net := healthyNet()
	net.routes = nil // link + addr fine, but no default route
	rep := runDoctor(t, net, fakeProber{})
	if rep.RootCause == nil || rep.RootCause.Layer != LayerRoute {
		t.Fatalf("want route root cause, got %+v", rep.RootCause)
	}
	// Gateway and WAN depend on a route; they must skip, not fail.
	for _, r := range rep.Results {
		if (r.Name == "gateway" || r.Name == "wan") && r.Status != StatusSkip {
			t.Fatalf("%s should skip without a route, got %v", r.Name, r.Status)
		}
	}
}

func TestRun_DNSDownButWANUp(t *testing.T) {
	// Gateway + raw WAN reachable, but name resolution is broken: DNS (lower
	// layer) must be the reported root cause, not WAN.
	p := fakeProber{answers: map[string]*probes.Result{
		"icmp:192.168.1.1":    ok(2 * time.Millisecond),
		"icmp:1.1.1.1":        ok(12 * time.Millisecond),
		"dns:one.one.one.one": fail("no such host"),
	}}
	rep := runDoctor(t, healthyNet(), p)
	if rep.RootCause == nil || rep.RootCause.Layer != LayerDNS {
		t.Fatalf("want dns root cause, got %+v", rep.RootCause)
	}
	if rep.RootCause.Class != ClassDNS {
		t.Fatalf("want ClassDNS, got %q", rep.RootCause.Class)
	}
}

func TestRun_GatewayPermissionWarnsNotFails(t *testing.T) {
	// ICMP unavailable (no CAP_NET_RAW) must warn, not declare the gateway
	// down - a privilege gap is not a connectivity failure.
	p := fakeProber{answers: map[string]*probes.Result{
		"icmp:192.168.1.1":    fail("socket: operation not permitted"),
		"icmp:1.1.1.1":        fail("socket: operation not permitted"),
		"dns:one.one.one.one": ok(15 * time.Millisecond),
	}}
	rep := runDoctor(t, healthyNet(), p)
	if rep.Verdict == VerdictBroken {
		t.Fatalf("permission gap should not break verdict; got %v", rep.Verdict)
	}
	for _, r := range rep.Results {
		if r.Name == "gateway" {
			if r.Status != StatusWarn || r.Class != ClassPermission {
				t.Fatalf("gateway want warn/permission, got %v/%v", r.Status, r.Class)
			}
		}
	}
}
