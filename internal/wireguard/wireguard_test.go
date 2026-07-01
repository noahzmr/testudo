package wireguard

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/netops"
)

func TestClassifyPeer(t *testing.T) {
	tests := []struct {
		name string
		peer Peer
		want Severity
	}{
		{"never", Peer{Never: true}, SevCritical},
		{"fresh keepalive", Peer{HandshakeAge: 10 * time.Second, PersistentKeepalive: 25 * time.Second}, SevOK},
		{"warn keepalive", Peer{HandshakeAge: 200 * time.Second, PersistentKeepalive: 25 * time.Second}, SevWarn},
		{"error keepalive", Peer{HandshakeAge: 400 * time.Second, PersistentKeepalive: 25 * time.Second}, SevError},
		{"stale no keepalive stays OK under 300", Peer{HandshakeAge: 200 * time.Second}, SevOK},
		{"error no keepalive over 300", Peer{HandshakeAge: 400 * time.Second}, SevError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPeer(tc.peer); got != tc.want {
				t.Fatalf("classifyPeer = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSubScore(t *testing.T) {
	// No devices -> neutral, excluded.
	if s, ok := (Snapshot{}).SubScore(); s != 100 || ok {
		t.Fatalf("empty snapshot SubScore = %d,%v want 100,false", s, ok)
	}
	// Device, no peers -> healthy, has data.
	dev := Snapshot{Devices: []Device{{Name: "wg0"}}}
	if s, ok := dev.SubScore(); s != 100 || !ok {
		t.Fatalf("no-peer SubScore = %d,%v want 100,true", s, ok)
	}
	// One healthy, one critical -> 50.
	mixed := Snapshot{Devices: []Device{{Name: "wg0", Peers: []Peer{
		{Severity: SevOK}, {Severity: SevCritical},
	}}}}
	if s, ok := mixed.SubScore(); s != 50 || !ok {
		t.Fatalf("mixed SubScore = %d,%v want 50,true", s, ok)
	}
}

func TestAllocateIP(t *testing.T) {
	// Server .1 reserved, .2 taken -> next is .3.
	got, err := AllocateIP("10.8.0.0/24", "10.8.0.1", []string{"10.8.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.8.0.3/32" {
		t.Fatalf("AllocateIP = %s want 10.8.0.3/32", got)
	}
	// Bare-address taken entries are honoured too.
	got, err = AllocateIP("10.8.0.0/24", "10.8.0.1", []string{"10.8.0.3", "10.8.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.8.0.4/32" {
		t.Fatalf("AllocateIP = %s want 10.8.0.4/32", got)
	}
	// Tiny /30 (usable .1,.2): server .1, .2 taken -> exhausted.
	if _, err := AllocateIP("10.9.0.0/30", "10.9.0.1", []string{"10.9.0.2/32"}); err == nil {
		t.Fatal("expected exhaustion error on /30")
	}
}

func TestKeygenRoundTrip(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFor(kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub != kp.PublicKey {
		t.Fatalf("derived pub %s != generated pub %s", pub, kp.PublicKey)
	}
}

// fakeBackend records the exact ordered sequence of netops calls so the
// transaction + rollback ordering can be asserted.
type fakeBackend struct {
	dev     netops.WGDeviceInfo
	calls   []string
	failOn  string // method name to fail on ("" = never)
	failErr error
}

func (f *fakeBackend) ListWGDevices() ([]netops.WGDeviceInfo, error) {
	return []netops.WGDeviceInfo{f.dev}, nil
}
func (f *fakeBackend) rec(name string) error {
	f.calls = append(f.calls, name)
	if name == f.failOn {
		if f.failErr == nil {
			f.failErr = errors.New("boom")
		}
		return f.failErr
	}
	return nil
}
func (f *fakeBackend) ConfigureWGPeer(dev, pub string, aips []string, endpoint string, keepalive int) error {
	return f.rec("ConfigureWGPeer")
}
func (f *fakeBackend) RemoveWGPeer(dev, pub string) error       { return f.rec("RemoveWGPeer") }
func (f *fakeBackend) AddRoute(cidr, gw, iface string) error    { return f.rec("AddRoute") }
func (f *fakeBackend) DelRoute(cidr string) error               { return f.rec("DelRoute") }
func (f *fakeBackend) AddFilterRule(fr netops.FilterRule) error { return f.rec("AddFilterRule") }
func (f *fakeBackend) DelFilterRule(fr netops.FilterRule) error { return f.rec("DelFilterRule") }
func (f *fakeBackend) AddMasquerade(out, src string) error      { return f.rec("AddMasquerade") }
func (f *fakeBackend) DelMasquerade(out, src string) error      { return f.rec("DelMasquerade") }
func (f *fakeBackend) WriteNetplan(path, content string) error  { return f.rec("WriteNetplan") }

func baseReq() ProvisionRequest {
	return ProvisionRequest{
		Device: "wg0", Name: "phone", Preset: PresetFullTunnel,
		ServerSideKeygen: true, TunnelSubnet: "10.8.0.0/24",
		ServerAddr: "10.8.0.1", WANIface: "eth0",
		ServerPublicKey: "srvpub", Endpoint: "home:51820",
	}
}

func TestProvisionSuccessFullTunnel(t *testing.T) {
	be := &fakeBackend{dev: netops.WGDeviceInfo{Name: "wg0"}}
	res, err := Provision(be, baseReq())
	if err != nil {
		t.Fatal(err)
	}
	if res.AssignedIP != "10.8.0.2/32" {
		t.Fatalf("assigned %s want 10.8.0.2/32", res.AssignedIP)
	}
	if res.ClientConfig == "" {
		t.Fatal("expected one-shot client config in server-keygen mode")
	}
	// Full tunnel applies: peer config, route, two forward accepts, masquerade.
	want := []string{"ConfigureWGPeer", "AddRoute", "AddFilterRule", "AddFilterRule", "AddMasquerade"}
	assertCalls(t, be.calls, want)
}

func TestProvisionRollbackOnFirewallFailure(t *testing.T) {
	be := &fakeBackend{dev: netops.WGDeviceInfo{Name: "wg0"}, failOn: "AddMasquerade"}
	_, err := Provision(be, baseReq())
	if err == nil {
		t.Fatal("expected error")
	}
	// Applied: peer, route, 2 accepts, masq(fail) -> rollback in reverse:
	// del the two filter rules, del route, remove peer.
	want := []string{
		"ConfigureWGPeer", "AddRoute", "AddFilterRule", "AddFilterRule", "AddMasquerade",
		"DelFilterRule", "DelFilterRule", "DelRoute", "RemoveWGPeer",
	}
	assertCalls(t, be.calls, want)
}

func TestProvisionDuplicatePeerRejected(t *testing.T) {
	be := &fakeBackend{dev: netops.WGDeviceInfo{Name: "wg0", Peers: []netops.WGPeerInfo{{PublicKey: "dup"}}}}
	req := baseReq()
	req.ServerSideKeygen = false
	req.PeerPublicKey = "dup"
	if _, err := Provision(be, req); err == nil {
		t.Fatal("expected duplicate-peer rejection")
	}
}

func TestPresetRulesOrdering(t *testing.T) {
	// Split preset: accept-subnet(s) then return then catch-all DROP last.
	rules, masq := presetRules(PresetSplit, "wg0", "10.8.0.5", "", []string{"192.168.1.0/24"})
	if masq != nil {
		t.Fatal("split preset must not masquerade")
	}
	if len(rules) != 3 {
		t.Fatalf("split rules = %d want 3", len(rules))
	}
	if rules[len(rules)-1].Action != "drop" {
		t.Fatal("catch-all DROP must be last")
	}
	// Isolated: single forward drop, no masq.
	rules, masq = presetRules(PresetIsolated, "wg0", "10.8.0.5", "eth0", nil)
	if masq != nil || len(rules) != 1 || rules[0].Action != "drop" {
		t.Fatalf("isolated preset unexpected: rules=%v masq=%v", rules, masq)
	}
	// Full: masquerade present.
	_, masq = presetRules(PresetFullTunnel, "wg0", "10.8.0.5", "eth0", nil)
	if masq == nil || masq.outIface != "eth0" || masq.srcCIDR != "10.8.0.5/32" {
		t.Fatalf("full preset masq unexpected: %v", masq)
	}
}

func TestDeprovision(t *testing.T) {
	be := &fakeBackend{dev: netops.WGDeviceInfo{Name: "wg0", Peers: []netops.WGPeerInfo{
		{PublicKey: "p1", AllowedIPs: []string{"10.8.0.5/32"}},
	}}}
	if err := Deprovision(be, DeprovisionRequest{
		Device: "wg0", PeerPublicKey: "p1", WANIface: "eth0", LANSubnets: []string{"192.168.1.0/24"},
	}); err != nil {
		t.Fatal(err)
	}
	// Must end by removing the peer.
	if be.calls[len(be.calls)-1] != "RemoveWGPeer" {
		t.Fatalf("deprovision must remove the peer last; calls=%v", be.calls)
	}
}

func TestUpdatePeerPresetOnly(t *testing.T) {
	be := &fakeBackend{dev: netops.WGDeviceInfo{Name: "wg0", Peers: []netops.WGPeerInfo{
		{PublicKey: "p1", AllowedIPs: []string{"10.8.0.5/32"}},
	}}}
	err := UpdatePeer(be, UpdateRequest{
		Device: "wg0", PeerPublicKey: "p1", Preset: PresetIsolated,
		WANIface: "eth0", LANSubnets: []string{"192.168.1.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Reconfigure happens first, then old rules are torn down, then the new
	// (isolated = single forward drop) rule is added last.
	if be.calls[0] != "ConfigureWGPeer" {
		t.Fatalf("update must reconfigure the peer first; calls=%v", be.calls)
	}
	if be.calls[len(be.calls)-1] != "AddFilterRule" {
		t.Fatalf("update must end by applying the new preset; calls=%v", be.calls)
	}
	for _, c := range be.calls {
		if c == "AddMasquerade" {
			t.Fatalf("isolated preset must not add masquerade; calls=%v", be.calls)
		}
	}
}

func TestUpdatePeerChangesAllowedIPs(t *testing.T) {
	be := &fakeBackend{dev: netops.WGDeviceInfo{Name: "wg0", Peers: []netops.WGPeerInfo{
		{PublicKey: "p1", AllowedIPs: []string{"10.8.0.5/32"}},
	}}}
	err := UpdatePeer(be, UpdateRequest{
		Device: "wg0", PeerPublicKey: "p1", Preset: PresetIsolated,
		Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.8.0.6/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The new IP gets a route added and the old IP's route removed.
	var addRoute, delRoute bool
	for _, c := range be.calls {
		if c == "AddRoute" {
			addRoute = true
		}
		if c == "DelRoute" {
			delRoute = true
		}
	}
	if !addRoute || !delRoute {
		t.Fatalf("changing AllowedIPs must add the new route and drop the old; calls=%v", be.calls)
	}
}

func TestRenderNetplan(t *testing.T) {
	out, err := RenderNetplan(InterfaceConfig{
		Name: "wg0", Address: "10.8.0.1/24", ListenPort: 51820,
		PrivateKey: "PRIVKEY",
		Peers:      []NetplanPeer{{PublicKey: "PUB", AllowedIPs: []string{"10.8.0.5/32"}, Keepalive: 25}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mode: wireguard", "addresses: [10.8.0.1/24]", "port: 51820", "key: PRIVKEY", "public: PUB", "allowed-ips: [10.8.0.5/32]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("netplan render missing %q:\n%s", want, out)
		}
	}
}

// fakeReader drives the collector: controllable devices + interface counters.
type fakeReader struct {
	devs    []netops.WGDeviceInfo
	ifs     []netops.IfaceInfo
	netplan []netops.NetplanFile
}

func (f *fakeReader) ListWGDevices() ([]netops.WGDeviceInfo, error) { return f.devs, nil }
func (f *fakeReader) ListIfaces() ([]netops.IfaceInfo, error)       { return f.ifs, nil }
func (f *fakeReader) ListNetplan() ([]netops.NetplanFile, error)    { return f.netplan, nil }

func TestClassifyIfaceErrors(t *testing.T) {
	if got := classifyIfaceErrors(0, 0); got != SevOK {
		t.Fatalf("no growth = %v want OK", got)
	}
	if got := classifyIfaceErrors(0, 3); got != SevWarn {
		t.Fatalf("drops growing = %v want WARN", got)
	}
	if got := classifyIfaceErrors(2, 0); got != SevError {
		t.Fatalf("errors growing = %v want ERROR", got)
	}
}

func TestCollectorErrorHealthFoldsIntoPeer(t *testing.T) {
	fr := &fakeReader{
		devs: []netops.WGDeviceInfo{{Name: "wg0", Peers: []netops.WGPeerInfo{
			// Fresh handshake so the peer's handshake severity is OK.
			{PublicKey: "p1", LastHandshake: time.Now()},
		}}},
		ifs: []netops.IfaceInfo{{Name: "wg0", Up: true, Running: true}},
	}

	c := &Collector{Netops: fr, Interval: time.Second}
	c.prevBytes = map[string]byteCounter{}
	c.history = map[string]*peerHistory{}
	c.prevIface = map[string]ifaceCounter{}

	// Tick 1 seeds interface baseline (no delta yet).
	c.tick(nil)
	snap, ok := c.Snapshot()
	if !ok || len(snap.Devices) != 1 {
		t.Fatal("expected one device after tick 1")
	}
	if snap.Devices[0].ErrHealth != SevOK {
		t.Fatalf("tick1 ErrHealth = %v want OK (no delta yet)", snap.Devices[0].ErrHealth)
	}

	// Tick 2: interface errors grew -> device ERROR, and the healthy peer's
	// Health is dragged to ERROR by the device error-health.
	fr.ifs[0].RxErrors = 5
	c.tick(nil)
	snap, _ = c.Snapshot()
	d := snap.Devices[0]
	if d.ErrHealth != SevError {
		t.Fatalf("tick2 device ErrHealth = %v want ERROR", d.ErrHealth)
	}
	if d.ErrDelta != 5 {
		t.Fatalf("tick2 ErrDelta = %d want 5", d.ErrDelta)
	}
	if d.Peers[0].Severity != SevOK {
		t.Fatalf("peer handshake severity = %v want OK", d.Peers[0].Severity)
	}
	if d.Peers[0].Health != SevError {
		t.Fatalf("peer Health = %v want ERROR (device errors folded in)", d.Peers[0].Health)
	}
}

func TestParseNetplanTunnels(t *testing.T) {
	yaml := `network:
  version: 2
  tunnels:
    wg0:
      mode: wireguard
      addresses: [10.8.0.1/24]
      port: 51820
      key: SECRETKEYSHOULDBEIGNORED=
      peers:
        - keys:
            public: PUBKEY1
          allowed-ips: [10.8.0.2/32]
          endpoint: home:51820
          keepalive: 25
    eth0-tunnel:
      mode: sit
`
	devs, err := ParseNetplanTunnels(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 { // only the wireguard tunnel, not the sit one
		t.Fatalf("expected 1 wg tunnel, got %d: %+v", len(devs), devs)
	}
	d := devs[0]
	if d.Name != "wg0" || d.Address != "10.8.0.1/24" || d.ListenPort != 51820 {
		t.Fatalf("device fields wrong: %+v", d)
	}
	if len(d.Peers) != 1 || d.Peers[0].PublicKey != "PUBKEY1" || d.Peers[0].Endpoint != "home:51820" {
		t.Fatalf("peer parse wrong: %+v", d.Peers)
	}
	// The private key must never appear in the parsed model.
	for _, p := range d.Peers {
		if p.PublicKey == "SECRETKEYSHOULDBEIGNORED=" {
			t.Fatal("private key leaked into parsed peers")
		}
	}
}

func TestMergeNetplanDrift(t *testing.T) {
	// Live device wg0 has peer P_LIVE (not in netplan) and P_BOTH (in netplan,
	// matching). Netplan additionally declares P_CONF (not live).
	npYAML := `network:
  version: 2
  tunnels:
    wg0:
      mode: wireguard
      addresses: [10.8.0.1/24]
      peers:
        - keys:
            public: P_BOTH
          allowed-ips: [10.8.0.2/32]
        - keys:
            public: P_CONF
          allowed-ips: [10.8.0.9/32]
`
	fr := &fakeReader{
		devs: []netops.WGDeviceInfo{{Name: "wg0", Peers: []netops.WGPeerInfo{
			{PublicKey: "P_LIVE", LastHandshake: time.Now(), AllowedIPs: []string{"10.8.0.3/32"}},
			{PublicKey: "P_BOTH", LastHandshake: time.Now(), AllowedIPs: []string{"10.8.0.2/32"}},
		}}},
		ifs:     []netops.IfaceInfo{{Name: "wg0", Up: true, Running: true}},
		netplan: []netops.NetplanFile{{Name: "60-wg.yaml", Content: npYAML}},
	}
	c := &Collector{Netops: fr, Interval: time.Second, Names: func() map[string]string {
		return map[string]string{"P_BOTH": "laptop"}
	}}
	c.prevBytes = map[string]byteCounter{}
	c.history = map[string]*peerHistory{}
	c.prevIface = map[string]ifaceCounter{}
	c.tick(nil)
	snap, ok := c.Snapshot()
	if !ok || len(snap.Devices) != 1 {
		t.Fatal("expected one device")
	}
	d := snap.Devices[0]
	if !d.NetplanKnown {
		t.Fatal("device should be netplan-known")
	}
	byKey := map[string]Peer{}
	for _, p := range d.Peers {
		byKey[p.PublicKey] = p
	}
	if byKey["P_LIVE"].Drift != DriftNotPersistent {
		t.Fatalf("P_LIVE drift = %q want not-persistent", byKey["P_LIVE"].Drift)
	}
	if byKey["P_BOTH"].Drift != DriftNone {
		t.Fatalf("P_BOTH drift = %q want none", byKey["P_BOTH"].Drift)
	}
	if byKey["P_BOTH"].Name != "laptop" {
		t.Fatalf("P_BOTH name = %q want laptop", byKey["P_BOTH"].Name)
	}
	cp, ok := byKey["P_CONF"]
	if !ok || !cp.ConfiguredOnly || cp.Drift != DriftConfigOnly {
		t.Fatalf("P_CONF should be a config-only peer: %+v", cp)
	}
	if d.DriftCount < 2 {
		t.Fatalf("expected >=2 drift peers, got %d", d.DriftCount)
	}
}

func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("calls = %v\nwant   %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call[%d] = %s want %s (full %v)", i, got[i], want[i], got)
		}
	}
}
