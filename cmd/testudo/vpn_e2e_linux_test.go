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

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/noahzmr/testudo/internal/testnet"
)

// TestVPNEndToEnd drives the real binary and a WireGuard client in another
// namespace. Everything the operator does happens over HTTP; the second half
// happens over the tunnel itself.
//
//	client 192.0.2.2 --- wan0 [testudo] lan0 --- server 10.50.0.2
//	       wg0 10.8.0.2 ======== wg0 10.8.0.1
func TestVPNEndToEnd(t *testing.T) {
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
	client, server := testnet.NewNS(t, "client"), testnet.NewNS(t, "server")
	testnet.Veth(t, "wan0", client, "eth0")
	testnet.Veth(t, "lan0", server, "eth0")
	testnet.Must(t, testnet.Addr("wan0", "192.0.2.1/24"))
	testnet.Must(t, testnet.Addr("lan0", "10.50.0.1/24"))
	testnet.Must(t, testnet.Sysctl("net/ipv4/ip_forward", "1"))
	testnet.Must(t, client.Do(func() error { return testnet.Addr("eth0", "192.0.2.2/24") }))
	testnet.Must(t, server.Do(func() error {
		if err := testnet.Addr("eth0", "10.50.0.2/24"); err != nil {
			return err
		}
		return testnet.DefaultRoute("10.50.0.1")
	}))
	for _, port := range []int{8443, 8444} {
		var ln net.Listener
		testnet.Must(t, server.Do(func() error {
			var err error
			ln, err = net.Listen("tcp", fmt.Sprintf("10.50.0.2:%d", port))
			return err
		}))
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				fmt.Fprint(c, c.RemoteAddr().(*net.TCPAddr).IP.String())
				c.Close()
			}
		}()
	}

	dir := t.TempDir()
	var stderr bytes.Buffer
	cmd := exec.Command(bin, "web", "--listen", "0.0.0.0:18080", "--storage", dir, "--db", filepath.Join(dir, "testudo.db"), "--allow-netops-write")
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

	// The operator builds the VPN through the API.
	host, _ := os.Hostname()
	site := create(local, "/api/v1/sites", map[string]any{"name": "hq"})["id"].(string)
	node := create(local, "/api/v1/cluster-nodes", map[string]any{"name": "fw1", "site": site, "hostname": strings.ToLower(host), "address": "192.0.2.1"})["id"].(string)
	vpn := create(local, "/api/v1/zones", map[string]any{"name": "vpn", "default_action": "drop"})["id"].(string)
	lan := create(local, "/api/v1/zones", map[string]any{"name": "lan", "default_action": "drop"})["id"].(string)
	create(local, "/api/v1/interfaces", map[string]any{"name": "lan0", "scope": "node:" + node, "device": "lan0", "zone": lan, "enabled": true})
	create(local, "/api/v1/firewall-policies", map[string]any{"name": "default", "default_deny": true, "allow_established": true,
		"allow_loopback": true, "allow_icmp": true, "allow_udp_ports": []string{"51820"}})

	status, key := call(local, "POST", "/api/v1/wg/tunnel-key", nil)
	if status != 201 || key["key_ref"] == "" {
		t.Fatalf("tunnel key: %d %v", status, key)
	}
	tunnel := create(local, "/api/v1/wg-tunnels", map[string]any{"name": "roadwarriors", "scope": "node:" + node, "enabled": true,
		"device": "wg0", "mode": "road_warrior", "listen_port": 51820, "addresses": []string{"10.8.0.1/24"},
		"public_key": key["public_key"], "key_ref": key["key_ref"], "zone": vpn, "endpoint": "192.0.2.1:51820",
		"client_routes": []string{"10.50.0.0/24"}})
	if tunnel["key_ref"] != "********" {
		t.Errorf("the API shows the private key's entry name: %v", tunnel["key_ref"])
	}
	alice := create(local, "/api/v1/users", map[string]any{"name": "alice", "username": "alice", "source": "host"})["id"].(string)
	_, pair := call(local, "POST", "/api/v1/wg/client-keypair", nil)
	_, psk := call(local, "POST", "/api/v1/wg/preshared-key", nil)
	peer := create(local, "/api/v1/wg-peers", map[string]any{"name": "alice-laptop", "enabled": true, "tunnel": tunnel["id"],
		"public_key": pair["public_key"], "preshared_ref": psk["preshared_ref"], "allowed_ips": []string{"10.8.0.2/32"}, "user": alice})["id"].(string)
	app := create(local, "/api/v1/access-resources", map[string]any{"name": "app", "type": "network", "target": "10.50.0.2",
		"protocol": "tcp", "ports": "8443"})["id"].(string)
	policy := create(local, "/api/v1/access-policies", map[string]any{"name": "alice-app", "resource": app, "users": []string{alice}, "max_duration": "8h"})

	// The client configuration has everything but the two secrets.
	status, conf := call(local, "GET", "/api/v1/wg-peers/"+peer+"/client-config", nil)
	text, _ := conf["config"].(string)
	for _, want := range []string{"Address = 10.8.0.2/32", "Endpoint = 192.0.2.1:51820", "AllowedIPs = 10.8.0.0/24, 10.50.0.0/24",
		"PublicKey = " + fmt.Sprint(key["public_key"])} {
		if !strings.Contains(text, want) {
			t.Errorf("client config (%d) lacks %q:\n%s", status, want, text)
		}
	}
	if strings.Contains(text, fmt.Sprint(pair["private_key"])) || strings.Contains(text, fmt.Sprint(psk["preshared_key"])) {
		t.Error("the client configuration endpoint returned a secret")
	}
	// No key material in the configuration log.
	if raw, err := os.ReadFile(filepath.Join(dir, "config", "config.log")); err != nil ||
		bytes.Contains(raw, []byte(fmt.Sprint(pair["private_key"]))) || bytes.Contains(raw, []byte(fmt.Sprint(psk["preshared_key"]))) {
		t.Errorf("key material in the configuration log (read error: %v)", err)
	}

	// The client device, configured the way the client configuration says.
	testnet.Must(t, client.Do(func() error {
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg0"}}); err != nil {
			return err
		}
		wg, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer wg.Close()
		priv, _ := wgtypes.ParseKey(fmt.Sprint(pair["private_key"]))
		pub, _ := wgtypes.ParseKey(fmt.Sprint(key["public_key"]))
		shared, _ := wgtypes.ParseKey(fmt.Sprint(psk["preshared_key"]))
		_, vpnNet, _ := net.ParseCIDR("10.8.0.0/24")
		_, lanNet, _ := net.ParseCIDR("10.50.0.0/24")
		if err := wg.ConfigureDevice("wg0", wgtypes.Config{PrivateKey: &priv, Peers: []wgtypes.PeerConfig{{
			PublicKey: pub, PresharedKey: &shared, Endpoint: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820},
			AllowedIPs: []net.IPNet{*vpnNet, *lanNet}}}}); err != nil {
			return err
		}
		if err := testnet.Addr("wg0", "10.8.0.2/32"); err != nil {
			return err
		}
		link, _ := netlink.LinkByName("wg0")
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		for _, n := range []*net.IPNet{vpnNet, lanNet} {
			if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: n}); err != nil {
				return err
			}
		}
		return nil
	}))
	viaClient := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var conn net.Conn
		err := client.Do(func() error {
			var err error
			conn, err = (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, addr)
			return err
		})
		return conn, err
	}
	reach := func(addr string) string {
		conn, err := viaClient(context.Background(), "tcp", addr)
		if err != nil {
			return ""
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		return string(b)
	}

	// Management over the VPN: log in, read and change configuration, all
	// through the tunnel address.
	remote := login("http://10.8.0.1:18080", viaClient, pw)
	if status, who := call(remote, "GET", "/api/v1/whoami", nil); status != 200 || who["name"] != "testudo" {
		t.Fatalf("whoami over the VPN: %d %v", status, who)
	}
	create(remote, "/api/v1/aliases", map[string]any{"name": "made-over-vpn", "type": "host", "entries": []string{"10.50.0.2"}})
	if status, _ := call(remote, "GET", "/api/v1/schema/ui.json", nil); status != 200 {
		t.Errorf("UI schema over the VPN: %d", status)
	}
	if status, page := call(remote, "GET", "/", nil); status != 200 || !strings.Contains(fmt.Sprint(page["raw"]), "Testudo") {
		t.Errorf("console over the VPN: %d", status)
	}

	// Flow capture, to see whose traffic the tunnel carries.
	if status, out := call(local, "POST", "/api/capture/start", map[string]any{"ifaces": []string{}}); status/100 != 2 {
		t.Fatalf("start capture: %d %v", status, out)
	}
	time.Sleep(6 * time.Second) // capture has found the tunnel device

	// Identity-aware access: alice's device reaches what her policy names,
	// seen at the server with her tunnel address, and nothing else.
	if got := reach("10.50.0.2:8443"); got != "10.8.0.2" {
		t.Errorf("the resource a policy grants: server saw %q, want 10.8.0.2", got)
	}
	// The flow in the tunnel is hers: the peer and the person are named.
	attributed := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && !attributed; time.Sleep(500 * time.Millisecond) {
		reach("10.50.0.2:8443")
		_, snap := call(local, "GET", "/api/snapshot", nil)
		list, _ := snap["flows"].([]any)
		for _, f := range list {
			fm := f.(map[string]any)
			attrs, _ := fm["attrs"].(map[string]any)
			if attrs != nil && attrs["user"] == "alice" && attrs["peer"] == "alice-laptop" && attrs["tunnel"] != nil &&
				strings.Contains(fmt.Sprint(fm["a"], fm["b"]), "10.8.0.2") {
				attributed = true
			}
		}
	}
	if !attributed {
		t.Error("no flow in the tunnel names alice and her peer")
	}
	if got := reach("10.50.0.2:8444"); got != "" {
		t.Errorf("a port no policy grants was reachable (%q)", got)
	}
	// Taking alice out of the policy closes it.
	policy["users"], policy["everyone"] = []string{}, false
	req, _ := json.Marshal(policy)
	hreq, _ := http.NewRequest("PUT", local.base+"/api/v1/access-policies/"+fmt.Sprint(policy["id"]), bytes.NewReader(req))
	hreq.Header.Set("If-Match", fmt.Sprintf(`"%v"`, policy["version"]))
	hreq.Header.Set("Content-Type", "application/json")
	if res, err := local.hc.Do(hreq); err != nil || res.StatusCode != 200 {
		t.Fatalf("update policy: %v %v", err, res)
	} else {
		res.Body.Close()
	}
	call(local, "POST", "/api/v1/apply/confirm", nil)
	if got := reach("10.50.0.2:8443"); got != "" {
		t.Errorf("the resource is still reachable after the user left the policy (%q)", got)
	}
	// Management still works: it does not depend on an access policy.
	if status, _ := call(remote, "GET", "/api/v1/whoami", nil); status != 200 {
		t.Errorf("management over the VPN after the policy change: %d", status)
	}
	// Revoking the peer ends the tunnel for it.
	_, p := call(local, "GET", "/api/v1/wg-peers/"+peer, nil)
	p["enabled"] = false
	req, _ = json.Marshal(p)
	hreq, _ = http.NewRequest("PUT", local.base+"/api/v1/wg-peers/"+peer, bytes.NewReader(req))
	hreq.Header.Set("If-Match", fmt.Sprintf(`"%v"`, p["version"]))
	hreq.Header.Set("Content-Type", "application/json")
	if res, err := local.hc.Do(hreq); err != nil || res.StatusCode != 200 {
		t.Fatalf("revoke peer: %v %v", err, res)
	} else {
		res.Body.Close()
	}
	call(local, "POST", "/api/v1/apply/confirm", nil)
	if c, err := viaClient(context.Background(), "tcp", "10.8.0.1:18080"); err == nil {
		c.Close()
		t.Error("a revoked peer still reaches the appliance through the tunnel")
	}
}
