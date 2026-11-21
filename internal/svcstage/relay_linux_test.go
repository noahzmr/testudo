package svcstage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/svcrender"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestDHCPRelayOnARealKernel: a client on the node's LAN gets its address
// from a DHCP server behind the node, through the relay of the model.
//
//	client eth0 ── lan 10.70.0.1/24 [node] up 10.71.0.1/24 ── eth0 server (Kea, 10.71.0.2)
func TestDHCPRelayOnARealKernel(t *testing.T) {
	for _, bin := range []string{"dnsmasq", "kea-dhcp4", "dhclient"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	if testnet.Isolate(t) {
		return
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
	client, server := testnet.NewNS(t, "client"), testnet.NewNS(t, "server")
	testnet.Veth(t, "lan", client, "eth0")
	testnet.Veth(t, "up", server, "eth0")
	testnet.Must(t, testnet.Addr("lan", "10.70.0.1/24"))
	testnet.Must(t, testnet.Addr("up", "10.71.0.1/24"))
	if out, err := in(server, "ip addr add 10.71.0.2/24 dev eth0 && ip route add 10.70.0.0/24 via 10.71.0.1"); err != nil {
		t.Fatal(out)
	}
	dir := t.TempDir()
	keaConf := filepath.Join(dir, "kea-dhcp4.conf")
	testnet.Must(t, os.WriteFile(keaConf, []byte(`{"Dhcp4": {
		"interfaces-config": {"interfaces": ["eth0"], "dhcp-socket-type": "udp"},
		"lease-database": {"type": "memfile", "persist": false},
		"subnet4": [{"id": 1, "subnet": "10.70.0.0/24", "pools": [{"pool": "10.70.0.100-10.70.0.150"}],
			"option-data": [{"name": "routers", "data": "10.70.0.1"}]}]}}`), 0o600))
	var kea *exec.Cmd
	testnet.Must(t, server.Do(func() error {
		kea = exec.Command("kea-dhcp4", "-c", keaConf)
		kea.Env = append(os.Environ(), "KEA_PIDFILE_DIR="+dir, "KEA_LOCKFILE_DIR="+dir)
		return kea.Start()
	}))
	t.Cleanup(func() { _ = kea.Process.Kill(); _ = kea.Wait() })

	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	atNode := func(m model.Meta) model.Meta { m.Scope = model.NodeScope(id(2)); return m }
	for _, e := range []model.Entity{
		&model.Site{Meta: meta(1, "hq")},
		&model.ClusterNode{Meta: meta(2, "fw1"), Site: model.Ref[model.Site]{ID: id(1)}, Hostname: "fw1", Address: "10.71.0.1"},
		&model.Interface{Meta: atNode(meta(10, "lan")), Device: "lan", Enabled: true, Addresses: []string{"10.70.0.1/24"}},
		&model.Interface{Meta: atNode(meta(11, "up")), Device: "up", Enabled: true, Addresses: []string{"10.71.0.1/24"}},
		&model.DHCPRelay{Meta: meta(20, "to-server"), Enabled: true, Interfaces: []string{"lan"}, Servers: []string{"10.71.0.2"}},
	} {
		if _, err := store.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s: %v", e.GetMeta().Name, err)
		}
	}
	nw := &netops.Writer{AllowWrites: true}
	runDir := "/run/trelay-" + fmt.Sprint(os.Getpid())
	s := &Stage{Runner: nw, Dir: filepath.Join(dir, "services"), RunDir: runDir,
		Locate: func(*confstore.State) (string, string) { return id(1), id(2) }}
	t.Cleanup(func() {
		for _, d := range svcrender.AllDaemons {
			nw.DaemonControl(netops.DaemonRequest{Name: d, Mode: netops.DaemonStop, RunDir: runDir})
		}
		os.RemoveAll(runDir)
	})
	raw, err := s.Render(store.Current())
	testnet.Must(t, err)
	ctx := context.Background()
	testnet.Must(t, s.Check(ctx, raw))
	testnet.Must(t, s.Apply(ctx, raw))
	if err := s.Healthy(ctx); err != nil {
		b, _ := os.ReadFile(filepath.Join(s.Dir, "dnsmasq.log"))
		t.Fatalf("health: %v\n%s", err, b)
	}
	testnet.Must(t, os.MkdirAll("/var/lib/dhcp", 0o755))
	out, err := in(client, "timeout 30 dhclient -4 -1 -v -lf /var/lib/dhcp/dhclient-relay.leases -pf /run/dhclient-relay.pid eth0 2>&1; ip -4 addr show dev eth0")
	if err != nil || !strings.Contains(out, "inet 10.70.0.1") {
		b, _ := os.ReadFile(filepath.Join(s.Dir, "dnsmasq.log"))
		t.Fatalf("the client got no address through the relay: %v\n%s\ndnsmasq:\n%s", err, out, b)
	}
	_, _ = in(client, "dhclient -x -pf /run/dhclient-relay.pid eth0")
}
