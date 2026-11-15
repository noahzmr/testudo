package wgrender

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/testutil/golden"
)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

const (
	siteN, nodeN = 1, 2
	keyA         = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	keyB         = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
	keyC         = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func opts() Options { return Options{SiteID: id(siteN), NodeID: id(nodeN), Now: now} }

func build(t *testing.T, objs ...model.Entity) *confstore.State {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	nodeScope := func(n int, name string) model.Meta {
		m := meta(n, name)
		m.Scope = model.NodeScope(id(nodeN))
		return m
	}
	base := []model.Entity{
		&model.Site{Meta: meta(siteN, "hq")},
		&model.ClusterNode{Meta: meta(nodeN, "fw1"), Site: model.Ref[model.Site]{ID: id(siteN)}, Hostname: "fw1", Address: "10.0.0.1"},
		&model.Zone{Meta: meta(10, "vpn"), DefaultAction: "drop"},
		&model.WGTunnel{Meta: nodeScope(20, "roadwarriors"), Enabled: true, Device: "wg0", Mode: "road_warrior", ListenPort: 51820,
			Addresses: []string{"10.8.0.1/24", "fd08::1/64"}, PublicKey: keyA, KeyRef: "wg0-key", Zone: model.Ref[model.Zone]{ID: id(10)},
			MTU: 1380, DNS: []string{"10.8.0.1"}, Endpoint: "vpn.example.com:51820", ClientRoutes: []string{"192.168.10.0/24"}},
		&model.WGTunnel{Meta: nodeScope(21, "branch"), Enabled: true, Device: "wg1", Mode: "site_to_site", ListenPort: 51821,
			Addresses: []string{"10.9.0.1/30"}, PublicKey: keyA, Zone: model.Ref[model.Zone]{ID: id(10)}},
	}
	for _, e := range append(base, objs...) {
		if _, err := s.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
	}
	return s.Current()
}

func tun(n int) model.Ref[model.WGTunnel] { return model.Ref[model.WGTunnel]{ID: id(n)} }

func TestRenderGolden(t *testing.T) {
	later, past := now.Add(48*time.Hour), now.Add(-time.Hour)
	st := build(t,
		&model.WGPeer{Meta: meta(30, "alice-laptop"), Enabled: true, Tunnel: tun(20), PublicKey: keyB, PresharedRef: "alice-psk",
			AllowedIPs: []string{"10.8.0.2/32", "fd08::2/128"}, Keepalive: 25},
		&model.WGPeer{Meta: meta(31, "contractor"), Enabled: true, Tunnel: tun(20), PublicKey: keyC, AllowedIPs: []string{"10.8.0.3/32"}, ExpiresAt: &later},
		&model.WGPeer{Meta: meta(32, "expired"), Enabled: true, Tunnel: tun(20), PublicKey: keyA, AllowedIPs: []string{"10.8.0.4/32"}, ExpiresAt: &past},
		&model.WGPeer{Meta: meta(33, "revoked"), Enabled: false, Tunnel: tun(20), PublicKey: keyA, AllowedIPs: []string{"10.8.0.5/32"}},
		&model.WGPeer{Meta: meta(34, "branch-office"), Enabled: true, Tunnel: tun(21), PublicKey: keyB,
			AllowedIPs: []string{"10.9.0.2/32", "192.168.50.0/24"}, Endpoint: "branch.example.com:51821"},
	)
	res, err := Render(st, opts())
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.MarshalIndent(res, "", " ")
	golden.Assert(t, "devices.json", append(out, '\n'))
	if len(res.Devices) != 2 || len(res.Devices[0].Peers) != 2 || len(res.Devices[1].Peers) != 1 {
		t.Fatalf("devices: %+v", res.Devices)
	}
	if strings.Join(res.Expired, ",") != "expired" || !res.NextExpiry.Equal(later) {
		t.Errorf("expired %v, next expiry %v", res.Expired, res.NextExpiry)
	}
	// Once the clock passes the expiry, the peer is gone.
	o := opts()
	o.Now = later.Add(time.Second)
	res, _ = Render(st, o)
	if len(res.Devices[0].Peers) != 1 || !res.NextExpiry.IsZero() {
		t.Errorf("after expiry: %d peers, next %v", len(res.Devices[0].Peers), res.NextExpiry)
	}
	// Private keys are named, never present.
	if strings.Contains(string(out), "private") && !strings.Contains(string(out), "key_ref") {
		t.Error("the artifact carries key material")
	}
}

func TestConflictsAreNamed(t *testing.T) {
	cases := map[string][]model.Entity{
		"overlaps with peer": {
			&model.WGPeer{Meta: meta(30, "a"), Enabled: true, Tunnel: tun(20), PublicKey: keyB, AllowedIPs: []string{"10.8.0.2/32"}},
			&model.WGPeer{Meta: meta(31, "b"), Enabled: true, Tunnel: tun(20), PublicKey: keyC, AllowedIPs: []string{"10.8.0.0/28"}}},
		"same public key": {
			&model.WGPeer{Meta: meta(30, "a"), Enabled: true, Tunnel: tun(20), PublicKey: keyB, AllowedIPs: []string{"10.8.0.2/32"}},
			&model.WGPeer{Meta: meta(31, "b"), Enabled: true, Tunnel: tun(20), PublicKey: keyB, AllowedIPs: []string{"10.8.0.3/32"}}},
	}
	for want, objs := range cases {
		if _, err := Render(build(t, objs...), opts()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
	// The same key on two different tunnels is fine.
	ok := build(t,
		&model.WGPeer{Meta: meta(30, "a"), Enabled: true, Tunnel: tun(20), PublicKey: keyB, AllowedIPs: []string{"10.8.0.2/32"}},
		&model.WGPeer{Meta: meta(31, "b"), Enabled: true, Tunnel: tun(21), PublicKey: keyB, AllowedIPs: []string{"10.9.0.2/32"}})
	if _, err := Render(ok, opts()); err != nil {
		t.Errorf("same key on two tunnels: %v", err)
	}
}

func TestClientConfig(t *testing.T) {
	st := build(t,
		&model.WGPeer{Meta: meta(30, "alice-laptop"), Enabled: true, Tunnel: tun(20), PublicKey: keyB, PresharedRef: "alice-psk",
			AllowedIPs: []string{"10.8.0.2/32", "fd08::2/128"}, Keepalive: 25},
		&model.WGPeer{Meta: meta(31, "bob-phone"), Enabled: true, Tunnel: tun(20), PublicKey: keyC, AllowedIPs: []string{"10.8.0.3/32"}, FullTunnel: true},
		&model.WGPeer{Meta: meta(34, "branch-office"), Enabled: true, Tunnel: tun(21), PublicKey: keyB, AllowedIPs: []string{"10.9.0.2/32"}},
	)
	split, err := ClientConfig(st, id(30))
	if err != nil {
		t.Fatal(err)
	}
	golden.Assert(t, "client-split.conf", []byte(split))
	for _, want := range []string{"Address = 10.8.0.2/32, fd08::2/128", "DNS = 10.8.0.1", "PublicKey = " + keyA,
		"AllowedIPs = 10.8.0.0/24, fd08::/64, 192.168.10.0/24", "Endpoint = vpn.example.com:51820", "PersistentKeepalive = 25",
		PrivateKeyPlaceholder, PresharedKeyPlaceholder} {
		if !strings.Contains(split, want) {
			t.Errorf("split-tunnel config lacks %q", want)
		}
	}
	full, _ := ClientConfig(st, id(31))
	if !strings.Contains(full, "AllowedIPs = 0.0.0.0/0, ::/0") || strings.Contains(full, "PresharedKey") {
		t.Errorf("full-tunnel config:\n%s", full)
	}
	if _, err := ClientConfig(st, id(34)); err == nil || !strings.Contains(err.Error(), "no public endpoint") {
		t.Errorf("tunnel without endpoint: %v", err)
	}
}
