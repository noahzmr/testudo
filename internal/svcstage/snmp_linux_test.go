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

// TestSNMPv3OnARealKernel: a monitoring system reads the node's interface
// table over SNMPv3 with the model's user; a wrong password gets nothing,
// and the configuration file with the passwords is root's alone.
//
//	nms eth0 10.80.0.2 ── mgmt 10.80.0.1 [node]
func TestSNMPv3OnARealKernel(t *testing.T) {
	for _, bin := range []string{"snmpd", "snmpget"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	if testnet.Isolate(t) {
		return
	}
	nms := testnet.NewNS(t, "nms")
	testnet.Veth(t, "mgmt", nms, "eth0")
	testnet.Must(t, testnet.Addr("mgmt", "10.80.0.1/24"))
	testnet.Must(t, nms.Do(func() error { return testnet.Addr("eth0", "10.80.0.2/24") }))
	dir := t.TempDir()
	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	atNode := func(m model.Meta) model.Meta { m.Scope = model.NodeScope(id(2)); return m }
	for _, e := range []model.Entity{
		&model.Site{Meta: meta(1, "hq")},
		&model.ClusterNode{Meta: meta(2, "fw1"), Site: model.Ref[model.Site]{ID: id(1)}, Hostname: "fw1", Address: "10.80.0.1"},
		&model.Interface{Meta: atNode(meta(10, "mgmt")), Device: "mgmt", Enabled: true, Addresses: []string{"10.80.0.1/24"}},
		&model.SNMPUser{Meta: meta(20, "nms"), Username: "nms", AuthPassword: "auth-secret-1", PrivPassword: "priv-secret-1"},
		&model.SNMPAgent{Meta: meta(21, "agent"), Enabled: true, Interfaces: []string{"mgmt"}, AllowFrom: []string{"10.80.0.0/24"},
			Users: []model.Ref[model.SNMPUser]{{ID: id(20)}}, Location: "rack 4"},
	} {
		if _, err := store.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s: %v", e.GetMeta().Name, err)
		}
	}
	nw := &netops.Writer{AllowWrites: true}
	runDir := "/run/tsnmp-" + fmt.Sprint(os.Getpid())
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
	testnet.Must(t, s.Healthy(ctx))
	if fi, err := os.Stat(filepath.Join(runDir, svcrender.SNMPConf)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("snmpd.conf: %v %v", fi.Mode().Perm(), err)
	}
	get := func(auth string) (string, error) {
		var out []byte
		err := nms.Do(func() error {
			var err error
			out, err = exec.Command("snmpget", "-v3", "-l", "authPriv", "-u", "nms", "-a", "SHA-256", "-A", auth,
				"-x", "AES", "-X", "priv-secret-1", "-t", "2", "-r", "4", "10.80.0.1",
				".1.3.6.1.2.1.1.6.0", ".1.3.6.1.2.1.2.1.0").CombinedOutput() // sysLocation, ifNumber
			return err
		})
		return string(out), err
	}
	out, err := get("auth-secret-1")
	if err != nil || !strings.Contains(out, "rack 4") || !strings.Contains(out, "INTEGER") {
		t.Fatalf("snmpget: %v\n%s", err, out)
	}
	if out, err := get("wrong-secret"); err == nil && strings.Contains(out, "rack 4") {
		t.Errorf("a wrong password read the agent:\n%s", out)
	}
}
