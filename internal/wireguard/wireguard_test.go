package wireguard

import (
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
