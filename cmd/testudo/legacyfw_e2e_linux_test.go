//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestLegacyFirewallMovesIntoTheModel: a node of an older install starts
// with the old firewall manager's policy file and an empty model. The file
// moves into the model by itself (the policy, a rule, a port forward and a
// rule the old WireGuard provisioner made), the kernel holds the model's
// ruleset, and the file is kept as firewall.json.migrated.
func TestLegacyFirewallMovesIntoTheModel(t *testing.T) {
	bin := os.Getenv("TESTUDO_E2E_BIN")
	if bin == "" {
		t.Skip("TESTUDO_E2E_BIN is not set")
	}
	if testnet.Isolate(t) {
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	testnet.Must(t, exec.Command("ip", "link", "set", "lo", "up").Run())
	testnet.Must(t, exec.Command("sh", "-c", "ip link add eth0 type dummy && ip link set eth0 up && ip link add wg9 type dummy && ip link set wg9 up").Run())
	dir := t.TempDir()
	pol := firewall.Policy{Version: 1, Enforce: true,
		Baseline: netops.FilterBaseline{AllowEstablished: true, AllowLoopback: true, AllowICMP: true, AllowTCPPorts: []uint16{22}},
		Rules: []netops.FilterRule{
			{Chain: "input", Action: "accept", Proto: "tcp", Port: 443, InIface: "eth0", Comment: "web"},
			{Chain: "forward", Action: "accept", InIface: "wg9", SrcCIDR: "10.8.0.2/32", DstCIDR: "192.168.1.0/24", Owner: "wg-peer:abc"},
		},
		Forwards: []netops.PortForward{{Proto: "tcp", WANPort: 8443, LANIP: "192.168.1.10", LANPort: 443, InIface: "eth0"}},
	}
	raw, _ := json.Marshal(pol)
	testnet.Must(t, os.WriteFile(filepath.Join(dir, "firewall.json"), raw, 0o600))

	var stderr bytes.Buffer
	cmd := exec.Command(bin, "web", "--listen", "127.0.0.1:18086", "--storage", dir, "--db", filepath.Join(dir, "testudo.db"), "--allow-netops-write")
	cmd.Env = append(os.Environ(), "HOME="+dir)
	cmd.Stderr = &stderr
	testnet.Must(t, cmd.Start())
	defer func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
		if t.Failed() {
			t.Logf("daemon stderr:\n%s", stderr.String())
		}
	}()
	var pw string
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && pw == ""; time.Sleep(100 * time.Millisecond) {
		if m := regexp.MustCompile(`password: (\S+)`).FindStringSubmatch(stderr.String()); m != nil {
			if c, err := net.DialTimeout("tcp", "127.0.0.1:18086", time.Second); err == nil {
				c.Close()
				pw = m[1]
			}
		}
	}
	if pw == "" {
		t.Fatal("the daemon did not come up")
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	res, err := hc.PostForm("http://127.0.0.1:18086/login", url.Values{"username": {"testudo"}, "password": {pw}})
	testnet.Must(t, err)
	res.Body.Close()
	list := func(plural string) []map[string]any {
		res, err := hc.Get("http://127.0.0.1:18086/api/v1/" + plural)
		testnet.Must(t, err)
		defer res.Body.Close()
		var out []map[string]any
		b, _ := io.ReadAll(res.Body)
		json.Unmarshal(b, &out)
		return out
	}
	if p := list("firewall-policies"); len(p) != 1 || p[0]["default_deny"] != true {
		t.Errorf("policy in the model: %v", p)
	}
	rules := list("filter-rules")
	owners := ""
	for _, r := range rules {
		owners += " " + strings.TrimSpace(r["name"].(string)+":"+func() string { o, _ := r["owner"].(string); return o }())
	}
	if len(rules) != 2 || !strings.Contains(owners, "wg-peer:abc") {
		t.Errorf("rules in the model:%s", owners)
	}
	if n := list("nat-rules"); len(n) != 1 || n[0]["type"] != "dnat" {
		t.Errorf("NAT in the model: %v", n)
	}
	if n := list("cluster-nodes"); len(n) != 1 {
		t.Errorf("this node in the model: %v", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "firewall.json.migrated")); err != nil {
		t.Errorf("the file was not kept as firewall.json.migrated: %v", err)
	}
	out, _ := exec.Command("nft", "list", "table", "inet", "testudo").CombinedOutput()
	for _, want := range []string{"policy drop", "tcp dport 443", "10.8.0.2", "dnat ip to 192.168.1.10:443"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the kernel's ruleset lacks %q:\n%s", want, out)
		}
	}
	if tables, _ := exec.Command("nft", "list", "tables").CombinedOutput(); strings.Contains(string(tables), "testudo_filter") {
		t.Errorf("the old manager's table is still there:\n%s", tables)
	}
	// The command line shows the same, through the daemon.
	c := exec.Command(bin, "firewall", "status", "--storage", dir)
	c.Env = append(os.Environ(), "HOME="+dir)
	if out, err := c.CombinedOutput(); err != nil || !strings.Contains(string(out), "DEFAULT-DENY") || !strings.Contains(string(out), "holds the model's ruleset") {
		t.Errorf("firewall status: %v\n%s", err, out)
	}
}
