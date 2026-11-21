//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/testnet"
)

// TestFabricEndToEnd builds the network between sites from the model, with
// real daemons and real routing daemons:
//
//	         inet 100.64.N.0/24 (20 ms)   mpls 100.65.N.0/24 (5 ms)
//	site N:  nN eth0 ---------------- router ---------------- eth1 nN
//	         lan0 10.N.0.1/24 (the site's network)
//
// Three nodes form a cluster over the internet uplinks. Two sites are put
// in the model; the fabric comes up by itself: tunnels per color, BGP with
// BFD over them, the sites' networks reachable through the tunnels over
// the better path. The MPLS line degrades and traffic moves to the
// internet. A third site is added and is connected without anything else
// being done; it is removed again and its tunnels go.
func TestFabricEndToEnd(t *testing.T) {
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
	if _, err := os.Stat("/usr/lib/frr/frrinit.sh"); err != nil {
		t.Skip("FRR is not installed")
	}
	sh := func(script string) string {
		out, err := exec.Command("sh", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
		return string(out)
	}
	testnet.Must(t, testnet.Sysctl("net/ipv4/ip_forward", "1"))
	sh("mkdir -p /run/frr /etc/frr")
	var nodes []*clusterNode
	for i := 1; i <= 3; i++ {
		n := &clusterNode{t: t, name: fmt.Sprintf("n%d", i), ip: fmt.Sprintf("100.64.%d.1", i), dir: t.TempDir(), bin: bin}
		n.ns = testnet.NewNS(t, n.name)
		inet, mpls := fmt.Sprintf("i%d", i), fmt.Sprintf("m%d", i)
		testnet.Veth(t, inet, n.ns, "eth0")
		testnet.Veth(t, mpls, n.ns, "eth1")
		testnet.Must(t, testnet.Addr(inet, fmt.Sprintf("100.64.%d.254/24", i)))
		testnet.Must(t, testnet.Addr(mpls, fmt.Sprintf("100.65.%d.254/24", i)))
		sh(fmt.Sprintf("tc qdisc add dev %s root netem delay 20ms 2ms", inet))
		sh(fmt.Sprintf("tc qdisc add dev %s root netem delay 5ms 1ms", mpls))
		testnet.Must(t, n.ns.Do(func() error {
			for _, c := range [][]string{
				{"ip", "addr", "add", n.ip + "/24", "dev", "eth0"},
				{"ip", "addr", "add", fmt.Sprintf("100.65.%d.1/24", i), "dev", "eth1"},
				{"ip", "route", "add", "default", "via", fmt.Sprintf("100.64.%d.254", i)},
				{"ip", "route", "add", "100.65.0.0/16", "via", fmt.Sprintf("100.65.%d.254", i)},
				{"ip", "link", "add", "lan0", "type", "dummy"},
				{"ip", "addr", "add", fmt.Sprintf("10.%d.0.1/24", i), "dev", "lan0"},
				{"ip", "link", "set", "lan0", "up"},
				{"sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.ping_group_range=0 2147483647"},
			} {
				if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
					return fmt.Errorf("%v: %v %s", c, err, out)
				}
			}
			return nil
		}))
		// The node's own routing daemon, seen by its processes alone.
		n.frr = filepath.Join(n.dir, "frr")
		sh(fmt.Sprintf(`mkdir -p %[1]s/run %[1]s/etc && cp -a /etc/frr/. %[1]s/etc/ &&
			sed -i 's/^bgpd=no/bgpd=yes/;s/^bfdd=no/bfdd=yes/' %[1]s/etc/daemons &&
			printf 'frr defaults traditional\nhostname %[2]s\nservice integrated-vtysh-config\n!\n' > %[1]s/etc/frr.conf &&
			chown -R frr:frr %[1]s`, n.frr, n.name))
		frr := exec.Command("unshare", "-m", "--propagation", "private", "sh", "-c",
			"mount --bind "+n.frr+"/run /run/frr && mount --bind "+n.frr+"/etc /etc/frr && exec /usr/lib/frr/frrinit.sh start")
		testnet.Must(t, n.ns.Do(func() error { return frr.Run() }))
		nodes = append(nodes, n)
	}
	n1, n2, n3 := nodes[0], nodes[1], nodes[2]
	// Each site's network answers on its LAN address with the site's name.
	for i, n := range nodes {
		var ln net.Listener
		testnet.Must(t, n.ns.Do(func() error {
			var err error
			ln, err = net.Listen("tcp", fmt.Sprintf("10.%d.0.1:9999", i+1))
			return err
		}))
		t.Cleanup(func() { ln.Close() })
		name := n.name
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				fmt.Fprint(c, name)
				c.Close()
			}
		}()
	}
	// reach connects from one site's network to another's and reports
	// whether the other site answered.
	reach := func(from *clusterNode, src, dst string) bool {
		var c net.Conn
		err := from.ns.Do(func() error {
			var err error
			d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
			c, err = d.Dial("tcp", dst+":9999")
			return err
		})
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(c)
		return len(b) > 0
	}
	defer func() {
		for _, n := range nodes {
			n.stop(syscall.SIGINT)
			if t.Failed() && n.stderr != nil {
				t.Logf("%s stderr:\n%.4000s", n.name, n.stderr.String())
			}
		}
	}()
	// in runs a command in a node's namespaces, routing daemon included.
	in := func(n *clusterNode, cmd string) string {
		pid, _ := os.ReadFile(filepath.Join(n.frr, "run", "zebra.pid"))
		out, _ := exec.Command("nsenter", "-t", strings.TrimSpace(string(pid)), "-m", "-n", "--", "sh", "-c", cmd).CombinedOutput()
		return string(out)
	}
	eventually := func(what string, within time.Duration, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			if cond() {
				return
			}
		}
		for _, n := range nodes {
			if n.cmd != nil {
				t.Logf("== %s\n%s\n%s\n%s", n.name, in(n, "ip -br link | grep tm; ip route"), in(n, "vtysh -c 'show bgp summary'"),
					in(n, "nft list ruleset | head -60"))
			}
		}
		t.Fatalf("never: %s", what)
	}
	write := func(n *clusterNode, method, path string, body any) map[string]any {
		t.Helper()
		status, data, h := n.call(method, "/api/v1"+path, body)
		if status/100 != 2 {
			t.Fatalf("%s %s on %s: %d %s", method, path, n.name, status, data)
		}
		if h.Get("Testudo-Pending") != "" {
			if s, d, _ := n.call("POST", "/api/v1/apply/confirm", nil); s != 204 {
				t.Fatalf("confirm on %s: %d %s", n.name, s, d)
			}
		}
		var m map[string]any
		json.Unmarshal(data, &m)
		return m
	}

	// The cluster, over the internet uplinks.
	for _, n := range nodes {
		n.start()
	}
	for _, n := range nodes {
		n.login()
		// Flow capture is off by default; switch it on, on every interface
		// that exists now or later.
		if status, body, _ := n.call("POST", "/api/capture/start", map[string]any{"ifaces": []string{}}); status/100 != 2 {
			t.Fatalf("start capture on %s: %d %s", n.name, status, body)
		}
	}
	if status, body, _ := n1.call("POST", "/api/v1/cluster/init", nil); status != 200 {
		t.Fatalf("init: %d %s", status, body)
	}
	for _, n := range []*clusterNode{n2, n3} {
		_, data, _ := n1.call("POST", "/api/v1/cluster/token", map[string]any{"voter": true})
		var tok map[string]any
		json.Unmarshal(data, &tok)
		if status, body, _ := n.call("POST", "/api/v1/cluster/join", map[string]any{"token": tok["token"]}); status != 200 {
			t.Fatalf("join %s: %d %s", n.name, status, body)
		}
	}
	eventually("the cluster has three voters", 90*time.Second, func() bool {
		members, _ := n1.status()["members"].([]any)
		voters := 0
		for _, m := range members {
			if r := m.(map[string]any)["role"]; r == "leader" || r == "voter" {
				voters++
			}
		}
		return voters == 3
	})

	// The fabric, two sites first.
	zone := write(n1, "POST", "/zones", map[string]any{"name": "fabric", "default_action": "accept"})
	write(n1, "POST", "/firewall-policies", map[string]any{"name": "default", "allow_established": true, "allow_loopback": true, "allow_icmp": true})
	site := func(i int) map[string]any {
		return write(n1, "POST", "/sites", map[string]any{"name": fmt.Sprintf("site%d", i), "asn": 65000 + i, "networks": []string{fmt.Sprintf("10.%d.0.0/24", i)}})
	}
	node := func(i int, s map[string]any) map[string]any {
		return write(n1, "POST", "/cluster-nodes", map[string]any{"name": fmt.Sprintf("n%d", i), "site": s["id"], "hostname": fmt.Sprintf("n%d", i),
			"address": fmt.Sprintf("100.64.%d.1", i), "mesh_index": i, "uplinks": []map[string]any{
				{"color": "inet", "endpoint": fmt.Sprintf("100.64.%d.1", i)}, {"color": "mpls", "endpoint": fmt.Sprintf("100.65.%d.1", i)}}})
	}
	s1, s2 := site(1), site(2)
	write(n1, "POST", "/fabrics", map[string]any{"name": "fabric", "enabled": true, "topology": "full_mesh", "pool": "10.255.0.0/16",
		"port_base": 52000, "asn": 65000, "colors": []string{"inet", "mpls"}, "zone": zone["id"], "bfd": true,
		"switch_margin_ms": 5, "hold_seconds": 3})
	node(1, s1)
	node(2, s2)

	// Each node made its key and the cluster wrote the public halves into
	// the model; then the tunnels appear and BGP comes up over them.
	eventually("both nodes have published their keys", 60*time.Second, func() bool {
		_, data, _ := n1.call("GET", "/api/v1/cluster-nodes", nil)
		return strings.Count(string(data), `"mesh_public_key":"`) == 2
	})
	eventually("n1 has both tunnels to n2", 60*time.Second, func() bool {
		out := in(n1, "ip -br link")
		return strings.Contains(out, "tm02c0s0") && strings.Contains(out, "tm02c1s0")
	})
	eventually("n1 learns site2's network over BGP", 90*time.Second, func() bool {
		return strings.Contains(in(n1, "ip route show 10.2.0.0/24"), "proto bgp")
	})
	eventually("site1 reaches site2 through the fabric", 30*time.Second, func() bool {
		return reach(n1, "10.1.0.1", "10.2.0.1")
	})
	// What the sites saw of that: one connection, seen at both, with the
	// fabric path it took. Each member captured its own; the view joins
	// them member to member.
	lastSites := ""
	defer func() {
		if t.Failed() {
			t.Logf("flows/sites: %.6000s", lastSites)
		}
	}()
	eventually("the connection is seen at both sites", 60*time.Second, func() bool {
		reach(n1, "10.1.0.1", "10.2.0.1")
		_, data, _ := n1.call("GET", "/api/v1/flows/sites?all=1", nil)
		lastSites = ""
		for _, line := range strings.Split(string(data), "},{\"proto\"") {
			if strings.Contains(line, "10.2.0.1:9999") {
				lastSites += line + "\n"
			}
		}
		var v struct {
			Connections []struct {
				Proto     string   `json:"proto"`
				Sites     []string `json:"sites"`
				Paths     []string `json:"paths"`
				Sightings []struct {
					Node  string `json:"node"`
					Iface string `json:"iface"`
					Attrs struct {
						Tunnel   string `json:"tunnel"`
						Peer     string `json:"peer"`
						PeerSite string `json:"peer_site"`
						Path     string `json:"path"`
					} `json:"attrs"`
				} `json:"sightings"`
			} `json:"connections"`
		}
		json.Unmarshal(data, &v)
		for _, c := range v.Connections {
			if c.Proto != "tcp" || fmt.Sprint(c.Sites) != "[site1 site2]" || len(c.Paths) == 0 {
				continue
			}
			tunnelAt := map[string]bool{}
			for _, s := range c.Sightings {
				if strings.HasPrefix(s.Iface, "tm") && s.Attrs.Tunnel == "fabric" && s.Attrs.Peer != "" && s.Attrs.PeerSite != "" {
					tunnelAt[s.Node] = true
				}
			}
			if tunnelAt["n1"] && tunnelAt["n2"] {
				return true
			}
		}
		return false
	})
	// The private key never left its node.
	for _, n := range []*clusterNode{n1, n2} {
		if _, err := os.Stat(filepath.Join(n.dir, "secrets", "mesh-key")); err != nil {
			t.Errorf("%s has no key of its own: %v", n.name, err)
		}
	}
	other, _ := os.ReadFile(filepath.Join(n2.dir, "secrets", "mesh-key"))
	if mine, _ := os.ReadFile(filepath.Join(n1.dir, "secrets", "mesh-key")); string(mine) == string(other) {
		t.Error("two nodes share a fabric key")
	}

	// The MPLS line is faster: it is preferred.
	route := func(n *clusterNode) string { return in(n, "ip route get 10.2.0.1 from 10.1.0.1") }
	eventually("traffic to site2 takes the MPLS tunnel", 60*time.Second, func() bool { return strings.Contains(route(n1), "dev tm02c1s0") })
	// It degrades; after the hold time traffic moves to the internet.
	sh("tc qdisc change dev m1 root netem delay 120ms 5ms")
	eventually("traffic to site2 moves to the internet tunnel", 90*time.Second, func() bool { return strings.Contains(route(n1), "dev tm02c0s0") })
	_, data, _ := n1.call("GET", "/api/v1/runtime", nil)
	if !strings.Contains(string(data), `"latency_ms"`) || !strings.Contains(string(data), `"tm02c1s0"`) {
		t.Errorf("the runtime report lacks the path measurements: %.400s", data)
	}
	sh("tc qdisc change dev m1 root netem delay 5ms 1ms")

	// A third site: put it in the model and nothing else.
	s3 := site(3)
	n3obj := node(3, s3)
	eventually("site1 reaches site3", 120*time.Second, func() bool {
		return reach(n1, "10.1.0.1", "10.3.0.1")
	})
	eventually("site2 reaches site3", 30*time.Second, func() bool {
		return reach(n2, "10.2.0.1", "10.3.0.1")
	})
	if !strings.Contains(in(n3, "vtysh -c 'show bfd peers brief'"), "up") {
		t.Error("BFD is not up on the new site's sessions")
	}
	// And it leaves again: its tunnels go everywhere.
	// The node object has moved on since it was made (its key was filled
	// in): delete the version that is there now.
	_, cur, _ := n1.call("GET", "/api/v1/cluster-nodes/"+n3obj["id"].(string), nil)
	var now map[string]any
	json.Unmarshal(cur, &now)
	req, _ := http.NewRequest("DELETE", n1.base()+"/api/v1/cluster-nodes/"+n3obj["id"].(string), nil)
	req.Header.Set("If-Match", fmt.Sprintf(`"%v"`, now["version"]))
	res, err := n1.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	status, h := res.StatusCode, res.Header
	if status/100 != 2 {
		t.Fatalf("remove n3 from the fabric: %d %s", status, body)
	}
	if h.Get("Testudo-Pending") != "" {
		n1.call("POST", "/api/v1/apply/confirm", nil)
	}
	eventually("the tunnels to n3 are gone", 60*time.Second, func() bool {
		return !strings.Contains(in(n1, "ip -br link"), "tm03") && !strings.Contains(in(n2, "ip -br link"), "tm03")
	})
	if !reach(n1, "10.1.0.1", "10.2.0.1") {
		t.Error("site1 lost site2 when site3 left")
	}
}
