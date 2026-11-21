//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	"github.com/noahzmr/testudo/internal/testnet"
)

// TestServicesEndToEnd drives the real binary: the operator puts DHCP, DNS
// and NTP on the LAN through the API, under a default-deny policy. A
// client gets a lease, finds its own name through the resolver, gets the
// time, and the console lists the lease.
//
//	client eth0 --- lan0 192.168.7.1/24 [testudo]
func TestServicesEndToEnd(t *testing.T) {
	bin := os.Getenv("TESTUDO_E2E_BIN")
	if bin == "" {
		t.Skip("TESTUDO_E2E_BIN is not set")
	}
	for _, b := range []string{"kea-dhcp4", "unbound", "chronyd", "dhclient", "dig"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip(b + " is not installed")
		}
	}
	if testnet.Isolate(t) {
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	client := testnet.NewNS(t, "client")
	testnet.Veth(t, "lan0", client, "eth0")
	testnet.Must(t, testnet.Addr("lan0", "192.168.7.1/24"))
	testnet.Must(t, exec.Command("ip", "link", "set", "lo", "up").Run())
	in := func(script string) (string, error) {
		var out []byte
		err := client.Do(func() error {
			var err error
			out, err = exec.Command("sh", "-c", script).CombinedOutput()
			return err
		})
		return string(out), err
	}
	if out, err := in("ip link set lo up; ip link set eth0 up"); err != nil {
		t.Fatal(out)
	}

	dir := t.TempDir()
	var stderr bytes.Buffer
	cmd := exec.Command(bin, "web", "--listen", "127.0.0.1:18080", "--storage", dir, "--db", filepath.Join(dir, "testudo.db"), "--allow-netops-write")
	cmd.Env = append(os.Environ(), "HOME="+dir)
	cmd.Stderr = &stderr
	testnet.Must(t, cmd.Start())
	defer func() {
		cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
		}
		if t.Failed() {
			t.Logf("daemon stderr:\n%s", stderr.String())
			out, _ := exec.Command("nft", "list", "table", "inet", "testudo").CombinedOutput()
			t.Logf("ruleset:\n%s", out)
		}
	}()

	// session is one logged-in operator, reaching the API through dial.
	type session struct {
		base string
		hc   *http.Client
	}
	login := func(base string, dial func(ctx context.Context, network, addr string) (net.Conn, error), pw string) *session {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		s := &session{base: base, hc: &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: dial}}}
		res, err := s.hc.PostForm(base+"/login", url.Values{"username": {"testudo"}, "password": {pw}})
		if err != nil {
			t.Fatalf("login at %s: %v", base, err)
		}
		res.Body.Close()
		return s
	}
	call := func(s *session, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			js, _ := json.Marshal(body)
			rd = bytes.NewReader(js)
		}
		req, _ := http.NewRequest(method, s.base+path, rd)
		req.Header.Set("Content-Type", "application/json")
		res, err := s.hc.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		out := map[string]any{}
		if json.Unmarshal(raw, &out) != nil {
			out = map[string]any{"raw": string(raw)}
		}
		return res.StatusCode, out
	}
	create := func(s *session, path string, body any) map[string]any {
		t.Helper()
		status, out := call(s, "POST", path, body)
		if status != 201 {
			t.Fatalf("POST %s: %d %v", path, status, out)
		}
		if status, out := call(s, "POST", "/api/v1/apply/confirm", nil); status != 204 {
			t.Fatalf("confirm after %s: %d %v", path, status, out)
		}
		return out
	}

	var pw string
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline) && pw == ""; time.Sleep(100 * time.Millisecond) {
		if m := regexp.MustCompile(`password: (\S+)`).FindStringSubmatch(stderr.String()); m != nil {
			if c, err := net.DialTimeout("tcp", "127.0.0.1:18080", time.Second); err == nil {
				c.Close()
				pw = m[1]
			}
		}
	}
	if pw == "" {
		t.Fatal("the daemon did not come up")
	}
	local := login("http://127.0.0.1:18080", nil, pw)

	host, _ := os.Hostname()
	site := create(local, "/api/v1/sites", map[string]any{"name": "hq"})["id"].(string)
	node := create(local, "/api/v1/cluster-nodes", map[string]any{"name": "fw1", "site": site, "hostname": strings.ToLower(host), "address": "192.168.7.1"})["id"].(string)
	lan := create(local, "/api/v1/zones", map[string]any{"name": "lan", "default_action": "drop"})["id"].(string)
	create(local, "/api/v1/interfaces", map[string]any{"name": "lan0", "scope": "node:" + node, "device": "lan0", "zone": lan, "enabled": true,
		"addresses": []string{"192.168.7.1/24"}})
	create(local, "/api/v1/firewall-policies", map[string]any{"name": "default", "default_deny": true, "allow_established": true, "allow_loopback": true})
	create(local, "/api/v1/dns-resolvers", map[string]any{"name": "resolver", "enabled": true, "interfaces": []string{"lan0"}, "mode": "recursive"})
	create(local, "/api/v1/ntp-services", map[string]any{"name": "ntp", "enabled": true, "interfaces": []string{"lan0"},
		"servers": []string{"192.0.2.123"}, "serve_only": true})
	create(local, "/api/v1/dhcp-scopes", map[string]any{"name": "lan4", "scope": "site:" + site, "enabled": true, "interface": "lan0",
		"subnet": "192.168.7.0/24", "pools": []string{"192.168.7.100-192.168.7.120"}, "register_dns": true})
	create(local, "/api/v1/dns-records", map[string]any{"name": "printer", "host": "printer.home.arpa", "type": "A", "value": "192.168.7.40"})

	testnet.Must(t, os.MkdirAll("/etc/dhcp", 0o755))
	testnet.Must(t, os.WriteFile("/etc/dhcp/dhclient.conf", []byte("send host-name \"laptop\";\n"), 0o644))
	out, err := in("timeout 30 dhclient -4 -1 -v -cf /etc/dhcp/dhclient.conf -lf /var/lib/dhcp/dhclient-e2e.leases -pf /run/dhclient-e2e.pid eth0 2>&1")
	m := regexp.MustCompile(`bound to (192\.168\.7\.\d+)`).FindStringSubmatch(out)
	if err != nil || m == nil {
		t.Fatalf("no lease: %v\n%s", err, out)
	}
	leased := m[1]

	// The engine enters the client's name in the resolver when Kea
	// announces it; the default-deny policy lets DNS in on the LAN.
	dig := func(q string) string {
		out, _ := in("dig +short +time=2 +tries=1 @192.168.7.1 " + q)
		return strings.TrimSpace(out)
	}
	got := ""
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline) && got != leased; time.Sleep(300 * time.Millisecond) {
		got = dig("laptop.home.arpa")
	}
	if got != leased {
		t.Errorf("laptop.home.arpa: %q, want %s", got, leased)
	}
	if got := dig("printer.home.arpa"); got != "192.168.7.40" {
		t.Errorf("printer.home.arpa: %q", got)
	}
	if out, err := in(`timeout 20 chronyd -Q -t 15 "server 192.168.7.1 iburst maxsamples 1" 2>&1`); err != nil || !strings.Contains(out, "System clock wrong by") {
		t.Errorf("no time from the node: %v\n%s", err, out)
	}

	status, body := call(local, "GET", "/api/v1/dhcp/leases", nil)
	if status != 200 || !strings.Contains(fmt.Sprint(body), "laptop.home.arpa") {
		// The list is an array; call() keeps it as raw text.
		t.Errorf("leases: %d %v", status, body)
	}
	req, _ := http.NewRequest("GET", local.base+"/metrics", nil)
	res, err := local.hc.Do(req)
	testnet.Must(t, err)
	metrics, _ := io.ReadAll(res.Body)
	res.Body.Close()
	for _, want := range []string{`testudo_service_up{daemon="kea-dhcp4"} 1`, `testudo_service_up{daemon="unbound"} 1`,
		`testudo_dhcp_leases_active{interface="lan0",scope="lan4"} 1`} {
		if !strings.Contains(string(metrics), want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if out, _ := exec.Command("nft", "list", "chain", "inet", "testudo", "input").CombinedOutput(); !strings.Contains(string(out), `"service: dns"`) {
		t.Errorf("no DNS opening in the ruleset:\n%s", out)
	}
	_ = context.Background
}
