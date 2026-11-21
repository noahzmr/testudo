//go:build linux

package svcstage

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/svcrender"
	"github.com/noahzmr/testudo/internal/testnet"
)

var _ confapply.Stage = (*Stage)(nil)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

func hooksDir(t *testing.T) string {
	m, _ := filepath.Glob("/usr/lib/*/kea/hooks/libdhcp_lease_cmds.so")
	if len(m) == 0 {
		t.Skip("Kea's hook libraries are not installed")
	}
	return filepath.Dir(m[0])
}

// TestServicesOnARealKernel: the node (this namespace) serves DHCPv4,
// DHCPv6 with router advertisements, DNS and NTP on its LAN interface and
// nothing on its WAN interface, all from the model through the stage. A
// client on the LAN gets an address, its gateway, resolver and time
// server, finds its own name and the model's names in DNS, and gets the
// time; a host on the WAN side gets none of it.
//
//	client eth0 ── lan 192.168.1.1/24, 2001:db8:1::1/64 [node] wan 198.51.100.1/24 ── eth0 outsider
func TestServicesOnARealKernel(t *testing.T) {
	for _, bin := range []string{"kea-dhcp4", "kea-dhcp6", "unbound", "chronyd", "radvd", "dhclient", "dig"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	hooks := hooksDir(t)
	if testnet.Isolate(t) {
		return
	}
	run := func(script string) string {
		t.Helper()
		out, err := exec.Command("sh", "-ec", script).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
		return string(out)
	}
	in := func(ns *testnet.NS, script string) (string, error) {
		var out []byte
		err := ns.Do(func() error {
			var err error
			out, err = exec.Command("sh", "-c", script).CombinedOutput()
			return err
		})
		return string(out), err
	}
	client, outsider := testnet.NewNS(t, "client"), testnet.NewNS(t, "outsider")
	testnet.Veth(t, "lan", client, "eth0")
	testnet.Veth(t, "wan", outsider, "eth0")
	run(`sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.lan.accept_dad=0
		ip addr add 192.168.1.1/24 dev lan && ip addr add 2001:db8:1::1/64 dev lan nodad && ip addr add 198.51.100.1/24 dev wan
		ip link set lan up && ip link set wan up && ip link set lo up`)
	for _, ns := range []*testnet.NS{client, outsider} {
		if out, err := in(ns, "sysctl -qw net.ipv6.conf.eth0.accept_dad=0 net.ipv6.conf.eth0.accept_ra=2; ip link set lo up; ip link set eth0 up"); err != nil {
			t.Fatal(out)
		}
	}
	if out, err := in(outsider, "ip addr add 198.51.100.7/24 dev eth0"); err != nil {
		t.Fatal(out)
	}

	dir := t.TempDir()
	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	atSite := func(m model.Meta) model.Meta { m.Scope = model.SiteScope(id(1)); return m }
	atNode := func(m model.Meta) model.Meta { m.Scope = model.NodeScope(id(2)); return m }
	for _, e := range []model.Entity{
		&model.Site{Meta: meta(1, "hq")},
		&model.ClusterNode{Meta: meta(2, "fw1"), Site: model.Ref[model.Site]{ID: id(1)}, Hostname: "fw1", Address: "192.168.1.1"},
		&model.Interface{Meta: atNode(meta(10, "lan")), Device: "lan", Enabled: true, Addresses: []string{"192.168.1.1/24", "2001:db8:1::1/64"}},
		&model.Interface{Meta: atNode(meta(11, "wan")), Device: "wan", Enabled: true, Addresses: []string{"198.51.100.1/24"}},
		&model.DNSResolver{Meta: atSite(meta(20, "resolver")), Enabled: true, Interfaces: []string{"lan"}, Mode: "recursive"},
		// No upstream is reachable here: the node serves its own clock and
		// leaves the system clock alone.
		&model.NTPService{Meta: atSite(meta(21, "ntp")), Enabled: true, Interfaces: []string{"lan"}, Servers: []string{"192.0.2.123"}, ServeOnly: true},
		&model.DHCPScope{Meta: atSite(meta(30, "lan4")), Enabled: true, Interface: "lan", Subnet: "192.168.1.0/24",
			Pools: []string{"192.168.1.100-192.168.1.150"}, RegisterDNS: true,
			Reservations: []model.DHCPReservation{{MAC: "52:54:00:aa:00:01", Address: "192.168.1.10", Hostname: "nas"}}},
		&model.DHCPScope{Meta: atSite(meta(31, "lan6")), Enabled: true, Interface: "lan", Subnet: "2001:db8:1::/64",
			Pools: []string{"2001:db8:1::1000-2001:db8:1::1fff"}},
		&model.RouterAdvert{Meta: atSite(meta(32, "lan-ra")), Enabled: true, Interface: "lan", Mode: "managed"},
		&model.DNSRecord{Meta: meta(40, "printer"), Host: "printer.home.arpa", Type: "A", Value: "192.168.1.40"},
	} {
		if _, err := store.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s: %v", e.GetMeta().Name, err)
		}
	}

	nw := &netops.Writer{AllowWrites: true}
	runDir := "/run/tsvc-" + fmt.Sprint(os.Getpid())
	s := &Stage{Runner: nw, Dir: filepath.Join(dir, "services"), RunDir: runDir, HooksDir: hooks,
		Locate: func(*confstore.State) (string, string) { return id(1), id(2) }}
	t.Cleanup(func() {
		for _, d := range svcrender.AllDaemons {
			nw.DaemonControl(netops.DaemonRequest{Name: d, Mode: netops.DaemonStop, RunDir: runDir})
		}
		os.RemoveAll(runDir)
	})
	logs := func() {
		for _, d := range svcrender.AllDaemons {
			if b, err := os.ReadFile(filepath.Join(s.Dir, d+".log")); err == nil {
				t.Logf("%s.log:\n%s", d, b)
			}
		}
	}
	raw, err := s.Render(store.Current())
	testnet.Must(t, err)
	ctx := context.Background()
	if err := s.Check(ctx, raw); err != nil {
		t.Fatal(err)
	}
	testnet.Must(t, s.Apply(ctx, raw))
	if err := s.Healthy(ctx); err != nil {
		logs()
		t.Fatal(err)
	}

	// DHCPv4. dhclient may only read its configuration from /etc/dhcp.
	testnet.Must(t, os.MkdirAll("/etc/dhcp", 0o755))
	testnet.Must(t, os.WriteFile("/etc/dhcp/dhclient.conf", []byte(`send host-name "laptop";
request subnet-mask, routers, domain-name, domain-name-servers, domain-search, ntp-servers;
`), 0o644))
	out, err := in(client, "timeout 30 dhclient -4 -1 -v -cf /etc/dhcp/dhclient.conf -lf /var/lib/dhcp/dhclient-c4.leases -pf /run/dhclient-c4.pid eth0 2>&1; cat /var/lib/dhcp/dhclient-c4.leases")
	if err != nil || !strings.Contains(out, "bound to 192.168.1.") {
		logs()
		t.Fatalf("no DHCPv4 lease: %v\n%s", err, out)
	}
	for _, want := range []string{"option routers 192.168.1.1;", "option domain-name-servers 192.168.1.1;", "option ntp-servers 192.168.1.1;", `option domain-name "home.arpa";`} {
		if !strings.Contains(out, want) {
			t.Errorf("the lease lacks %q:\n%s", want, out)
		}
	}
	var leased string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "fixed-address ") {
			leased = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(l), "fixed-address "), ";")
		}
	}

	// DHCPv6 and the router advertisement: the default route comes from the
	// advertisement, the address from DHCPv6.
	ok := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && !ok; time.Sleep(500 * time.Millisecond) {
		out, _ = in(client, "ip -6 route show default")
		ok = strings.Contains(out, "via fe80:")
	}
	if !ok {
		logs()
		t.Fatalf("no IPv6 default route from the advertisement: %q", out)
	}
	out, err = in(client, "timeout 30 dhclient -6 -1 -v -cf /etc/dhcp/dhclient.conf -lf /var/lib/dhcp/dhclient-c6.leases -pf /run/dhclient-c6.pid eth0 2>&1; ip -6 addr show dev eth0 scope global")
	if err != nil || !strings.Contains(out, "inet6 2001:db8:1::1") {
		logs()
		t.Fatalf("no DHCPv6 address: %v\n%s", err, out)
	}

	// The leases, read back from Kea, become names in the resolver.
	leases, err := Leases(ctx, runDir, false)
	testnet.Must(t, err)
	res, err := decode(raw)
	testnet.Must(t, err)
	want := DesiredNames(res, leases, time.Now())
	if got := fmt.Sprint(want); got != fmt.Sprintf("map[laptop.home.arpa:[%s]]", leased) {
		t.Fatalf("names from the leases: %s (leases %+v)", got, leases)
	}
	names := &Names{RunDir: runDir}
	testnet.Must(t, names.Sync(ctx, want))
	dig := func(ns *testnet.NS, server, q string) string {
		out, _ := in(ns, "dig +short +time=2 +tries=1 @"+server+" "+q)
		return strings.TrimSpace(out)
	}
	for q, wantA := range map[string]string{"laptop.home.arpa": leased, "nas.home.arpa": "192.168.1.10", "printer.home.arpa": "192.168.1.40",
		"-x " + leased: "laptop.home.arpa.", "unknown.home.arpa": ""} {
		if got := dig(client, "192.168.1.1", q); got != wantA {
			t.Errorf("dig %s: %q, want %q", q, got, wantA)
		}
	}
	// A name that changes goes through the control socket, without a reload.
	want["phone.home.arpa"] = []string{"192.168.1.120"}
	delete(want, "laptop.home.arpa")
	testnet.Must(t, names.Sync(ctx, want))
	if got := dig(client, "192.168.1.1", "phone.home.arpa"); got != "192.168.1.120" {
		t.Errorf("a new name: %q", got)
	}
	if got := dig(client, "192.168.1.1", "laptop.home.arpa"); got != "" {
		t.Errorf("a released name still answers: %q", got)
	}
	// The resolver answers over IPv6 on the LAN too.
	if got := dig(client, "2001:db8:1::1", "printer.home.arpa"); got != "192.168.1.40" {
		t.Errorf("over IPv6: %q", got)
	}

	// NTP from the LAN.
	out, err = in(client, `timeout 20 chronyd -Q -t 15 "server 192.168.1.1 iburst maxsamples 1" 2>&1`)
	if err != nil || !strings.Contains(out, "System clock wrong by") {
		logs()
		t.Errorf("no time from the node: %v\n%s", err, out)
	}

	// Nothing on the WAN side.
	if got := dig(outsider, "198.51.100.1", "printer.home.arpa"); got != "" && !strings.Contains(got, "timed out") && !strings.Contains(got, "refused") {
		t.Errorf("the resolver answers on the WAN: %q", got)
	}
	if out, err := in(outsider, `timeout 10 chronyd -Q -t 6 "server 198.51.100.1 iburst maxsamples 1" 2>&1`); err == nil && strings.Contains(out, "System clock wrong by") {
		t.Errorf("NTP answers on the WAN:\n%s", out)
	}
	if out, _ := in(outsider, "timeout 12 dhclient -4 -1 -v -cf /etc/dhcp/dhclient.conf -lf /var/lib/dhcp/dhclient-o4.leases -pf /run/dhclient-o4.pid eth0 2>&1"); strings.Contains(out, "bound to") {
		t.Errorf("a lease on the WAN:\n%s", out)
	}

	// Switching a service off stops its daemon.
	r, _ := store.Current().Get(model.KindRouterAdvert, id(32))
	ra := *r.(*model.RouterAdvert)
	ra.Enabled = false
	_, err = store.Update(ctx, "test", &ra, ra.Version)
	testnet.Must(t, err)
	raw, err = s.Render(store.Current())
	testnet.Must(t, err)
	testnet.Must(t, s.Apply(ctx, raw))
	if st, _ := nw.DaemonState("radvd", runDir); st != "stopped" {
		t.Errorf("radvd after the advertisement was switched off: %s", st)
	}
	_ = net.ParseIP
}
