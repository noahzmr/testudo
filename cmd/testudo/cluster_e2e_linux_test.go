//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/testnet"
)

// clusterNode is one daemon in its own network namespace.
type clusterNode struct {
	t      *testing.T
	name   string
	ip     string
	dir    string
	ns     *testnet.NS
	cmd    *exec.Cmd
	stderr *bytes.Buffer
	hc     *http.Client
	bin    string
}

func (n *clusterNode) base() string { return "http://" + n.ip + ":8080" }

func (n *clusterNode) start() {
	n.t.Helper()
	n.stderr = &bytes.Buffer{}
	n.cmd = exec.Command(n.bin, "web", "--listen", n.ip+":8080", "--storage", n.dir, "--db", filepath.Join(n.dir, "testudo.db"),
		"--allow-netops-write", "--node-name", n.name, "--cluster-raft", n.ip+":7946", "--cluster-api", n.ip+":7947")
	n.cmd.Env = append(os.Environ(), "HOME="+n.dir)
	n.cmd.Stderr = n.stderr
	// The child is created from a thread that sits in the namespace.
	testnet.Must(n.t, n.ns.Do(func() error { return n.cmd.Start() }))
	jar, _ := cookiejar.New(nil)
	n.hc = &http.Client{Jar: jar, Timeout: 30 * time.Second}
}

func (n *clusterNode) stop(sig syscall.Signal) {
	if n.cmd == nil || n.cmd.Process == nil {
		return
	}
	n.cmd.Process.Signal(sig)
	done := make(chan struct{})
	go func() { n.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		n.cmd.Process.Kill()
		<-done
	}
	n.cmd = nil
}

// call sends a request to the node's console API.
func (n *clusterNode) call(method, path string, body any) (int, []byte, http.Header) {
	var rd io.Reader
	if body != nil {
		if form, ok := body.(url.Values); ok {
			req, _ := http.NewRequest(method, n.base()+path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			res, err := n.hc.Do(req)
			if err != nil {
				return 0, []byte(err.Error()), nil
			}
			defer res.Body.Close()
			data, _ := io.ReadAll(res.Body)
			return res.StatusCode, data, res.Header
		}
		js, _ := json.Marshal(body)
		rd = bytes.NewReader(js)
	}
	req, _ := http.NewRequest(method, n.base()+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := n.hc.Do(req)
	if err != nil {
		return 0, []byte(err.Error()), nil
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res.StatusCode, data, res.Header
}

// login waits for the console and logs in as the built-in administrator.
func (n *clusterNode) login() {
	n.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		m := regexp.MustCompile(`password: (\S+)`).FindStringSubmatch(n.stderr.String())
		pw := ""
		if m != nil {
			pw = m[1]
			os.WriteFile(filepath.Join(n.dir, "pw"), []byte(pw), 0o600)
		} else if saved, err := os.ReadFile(filepath.Join(n.dir, "pw")); err == nil {
			pw = string(saved)
		}
		if pw == "" {
			continue
		}
		if status, _, _ := n.call("POST", "/login", url.Values{"username": {"testudo"}, "password": {pw}}); status == 200 || status == http.StatusSeeOther {
			if s, _, _ := n.call("GET", "/api/me", nil); s == 200 {
				return
			}
		}
	}
	n.t.Fatalf("%s: the console did not come up:\n%s", n.name, n.stderr.String())
}

func (n *clusterNode) status() map[string]any {
	_, data, _ := n.call("GET", "/api/v1/cluster", nil)
	var m map[string]any
	json.Unmarshal(data, &m)
	return m
}

func (n *clusterNode) leads() bool {
	st := n.status()
	return st["leader"] == n.name && st["quorum"] == true
}

// rules lists the node's packet filter, from inside its namespace.
func (n *clusterNode) rules() string {
	var out []byte
	n.ns.Do(func() error {
		out, _ = exec.Command("nft", "list", "table", "inet", "testudo").CombinedOutput()
		return nil
	})
	return string(out)
}

// TestClusterEndToEnd runs three daemons in three network namespaces
// behind a router, on links with delay, jitter and loss, and takes them
// through the life of a cluster.
//
//	n1 10.99.1.1 --+
//	n2 10.99.2.1 --+-- router (this namespace; the test talks from here)
//	n3 10.99.3.1 --+
func TestClusterEndToEnd(t *testing.T) {
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
	sh := func(script string) string {
		out, err := exec.Command("sh", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
		return string(out)
	}
	testnet.Must(t, testnet.Sysctl("net/ipv4/ip_forward", "1"))
	var nodes []*clusterNode
	for i := 1; i <= 3; i++ {
		n := &clusterNode{t: t, name: fmt.Sprintf("n%d", i), ip: fmt.Sprintf("10.99.%d.1", i), dir: t.TempDir(), bin: bin}
		n.ns = testnet.NewNS(t, n.name)
		link := fmt.Sprintf("c%d", i)
		testnet.Veth(t, link, n.ns, "eth0")
		testnet.Must(t, testnet.Addr(link, fmt.Sprintf("10.99.%d.254/24", i)))
		gw := fmt.Sprintf("10.99.%d.254", i)
		testnet.Must(t, n.ns.Do(func() error {
			if err := testnet.Addr("eth0", n.ip+"/24"); err != nil {
				return err
			}
			return testnet.DefaultRoute(gw)
		}))
		// A WAN link: 20 ms each way with jitter, and some loss.
		sh("tc qdisc add dev " + link + " root netem delay 20ms 5ms loss 0.5%")
		testnet.Must(t, n.ns.Do(func() error {
			return exec.Command("tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "20ms", "5ms", "loss", "0.5%").Run()
		}))
		nodes = append(nodes, n)
	}
	n1, n2, n3 := nodes[0], nodes[1], nodes[2]
	defer func() {
		for _, n := range nodes {
			n.stop(syscall.SIGINT)
			if t.Failed() && n.stderr != nil {
				t.Logf("%s stderr:\n%.3000s", n.name, n.stderr.String())
			}
		}
	}()
	// cut isolates the named nodes from each other and from the rest; the
	// test itself still reaches every node. heal undoes it.
	cut := func(groups ...[]*clusterNode) {
		sh("nft add table inet partition; nft flush table inet partition; nft 'add chain inet partition cut { type filter hook forward priority 0; }'")
		for i, g := range groups {
			for j, h := range groups {
				if i == j {
					continue
				}
				for _, a := range g {
					for _, b := range h {
						sh(fmt.Sprintf("nft add rule inet partition cut ip saddr %s ip daddr %s drop", a.ip, b.ip))
					}
				}
			}
		}
	}
	heal := func() { sh("nft delete table inet partition 2>/dev/null || true") }
	eventually := func(what string, within time.Duration, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			if cond() {
				return
			}
		}
		var st []string
		for _, n := range nodes {
			if n.cmd != nil {
				st = append(st, fmt.Sprintf("%s: %v", n.name, n.status()))
			}
		}
		t.Fatalf("never: %s\n%s", what, strings.Join(st, "\n"))
	}
	leader := func(among ...*clusterNode) *clusterNode {
		t.Helper()
		var l *clusterNode
		eventually("a leader", 30*time.Second, func() bool {
			for _, n := range among {
				if n.cmd != nil && n.leads() {
					l = n
					return true
				}
			}
			return false
		})
		return l
	}
	// write sends a model change and confirms it on the same node.
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
	count := func(n *clusterNode, plural string) int {
		_, data, _ := n.call("GET", "/api/v1/"+plural, nil)
		var list []any
		json.Unmarshal(data, &list)
		return len(list)
	}

	for _, n := range nodes {
		n.start()
	}
	for _, n := range nodes {
		n.login()
	}

	// 1. One node has a configuration already. It becomes the cluster's.
	zone := write(n1, "POST", "/zones", map[string]any{"name": "wan", "default_action": "drop"})
	write(n1, "POST", "/firewall-policies", map[string]any{"name": "default", "default_deny": false, "allow_established": true,
		"allow_loopback": true, "allow_icmp": true})
	if status, body, _ := n1.call("POST", "/api/v1/cluster/init", nil); status != 200 {
		t.Fatalf("init: %d %s", status, body)
	}
	for _, n := range []*clusterNode{n2, n3} {
		status, data, _ := n1.call("POST", "/api/v1/cluster/token", map[string]any{"voter": true})
		var tok map[string]any
		json.Unmarshal(data, &tok)
		if status != 201 || tok["token"] == nil {
			t.Fatalf("token: %d %s", status, data)
		}
		if status, body, _ := n.call("POST", "/api/v1/cluster/join", map[string]any{"token": tok["token"]}); status != 200 {
			t.Fatalf("join %s: %d %s", n.name, status, body)
		}
	}
	eventually("three voters", 60*time.Second, func() bool {
		members, _ := n1.status()["members"].([]any)
		voters := 0
		for _, m := range members {
			if role := m.(map[string]any)["role"]; role == "leader" || role == "voter" {
				voters++
			}
		}
		return voters == 3
	})
	for _, n := range []*clusterNode{n2, n3} {
		n := n
		eventually(n.name+" has the first node's model", 30*time.Second, func() bool { return count(n, "zones") == 1 })
	}

	// 2. A change made on a member that does not lead is decided by the
	//    leader and takes effect in every node's own packet filter.
	l := leader(nodes...)
	var follower *clusterNode
	for _, n := range nodes {
		if n != l {
			follower = n
			break
		}
	}
	write(follower, "POST", "/filter-rules", map[string]any{"name": "ssh-in", "enabled": true, "action": "accept", "direction": "in",
		"protocol": "tcp", "source_zone": zone["id"], "ports": []string{"2222"}})
	for _, n := range nodes {
		n := n
		eventually(n.name+" enforces the rule", 30*time.Second, func() bool { return strings.Contains(n.rules(), "2222") })
	}
	// Every member reports what it applied; the overview says so.
	eventually("all members report applied", 30*time.Second, func() bool {
		members, _ := l.status()["members"].([]any)
		for _, m := range members {
			if m.(map[string]any)["state"] != "applied" {
				return false
			}
		}
		return len(members) == 3
	})
	// The audit row on the leader names the person, not the member that
	// passed the request on.
	_, data, _ := l.call("GET", "/api/v1/audit?limit=100", nil)
	if !strings.Contains(string(data), "create filter_rule ssh-in") || !strings.Contains(string(data), `"actor":"testudo"`) {
		t.Errorf("the leader's audit log lacks the forwarded change: %.600s", data)
	}

	// 3. The leader is killed. The others elect a new one and go on; the
	//    old one comes back as a follower with everything.
	l.stop(syscall.SIGKILL)
	var rest []*clusterNode
	for _, n := range nodes {
		if n != l {
			rest = append(rest, n)
		}
	}
	next := leader(rest...)
	write(next, "POST", "/aliases", map[string]any{"name": "after-leader-loss", "type": "host", "entries": []string{"192.0.2.9"}})
	l.start()
	l.login()
	eventually("the old leader caught up", 60*time.Second, func() bool { return count(l, "aliases") == 1 })

	// 4. Partition 2:1. The minority keeps forwarding with what it has and
	//    turns read-only; the majority goes on.
	lead := leader(nodes...)
	var alone *clusterNode
	var majority []*clusterNode
	for _, n := range nodes {
		if n != lead && alone == nil {
			alone = n
		} else {
			majority = append(majority, n)
		}
	}
	cut([]*clusterNode{alone}, majority)
	eventually("the cut-off member notices", 30*time.Second, func() bool { return alone.status()["quorum"] == false })
	if status, body, _ := alone.call("POST", "/api/v1/aliases", map[string]any{"name": "minority", "type": "host", "entries": []string{"192.0.2.1"}}); status != http.StatusServiceUnavailable {
		t.Errorf("write on the cut-off member: %d %s", status, body)
	}
	if count(alone, "zones") != 1 || !strings.Contains(alone.rules(), "2222") {
		t.Error("the cut-off member lost its configuration or stopped enforcing it")
	}
	lead = leader(majority...)
	write(lead, "POST", "/aliases", map[string]any{"name": "majority", "type": "host", "entries": []string{"192.0.2.2"}})
	if count(alone, "aliases") != 1 {
		t.Error("the cut-off member received a change through the partition")
	}

	// 5. Break-glass on the cut-off member: an explicit, local override.
	//    Only what runs changes; the model does not.
	ruleBody, _ := json.Marshal(map[string]any{"name": "emergency", "enabled": true, "action": "accept", "direction": "in",
		"protocol": "tcp", "source_zone": zone["id"], "ports": []string{"3333"}})
	override := map[string]any{"reason": "uplink moved", "ops": []map[string]any{{"type": "create", "kind": "filter_rule", "object": json.RawMessage(ruleBody)}}}
	if status, body, _ := alone.call("POST", "/api/v1/cluster/override", override); status != 200 {
		t.Fatalf("override: %d %s", status, body)
	}
	if !strings.Contains(alone.rules(), "3333") || count(alone, "filter-rules") != 1 {
		t.Errorf("after the override: enforced %v, rules in the model %d", strings.Contains(alone.rules(), "3333"), count(alone, "filter-rules"))
	}
	heal()
	// It gets the cluster's model again and keeps running the override
	// until someone has looked at it.
	eventually("the member has the majority's change", 60*time.Second, func() bool { return count(alone, "aliases") == 2 })
	time.Sleep(3 * time.Second)
	if !strings.Contains(alone.rules(), "3333") {
		t.Error("the override was overwritten when the partition healed")
	}
	eventually("the override shows as drift", 30*time.Second, func() bool {
		members, _ := leader(nodes...).status()["members"].([]any)
		for _, m := range members {
			mm := m.(map[string]any)
			if mm["id"] == alone.name && mm["state"] == "drift" {
				return true
			}
		}
		return false
	})
	if status, body, _ := alone.call("DELETE", "/api/v1/cluster/override", nil); status != 200 || !strings.Contains(string(body), "emergency") {
		t.Fatalf("resolve the override: %d %s", status, body)
	}
	eventually("the member runs the cluster's model again", 30*time.Second, func() bool { return !strings.Contains(alone.rules(), "3333") })

	// 6. Partition 1:1:1. Nobody decides anything; everybody keeps
	//    forwarding. When it heals the cluster works again.
	cut([]*clusterNode{n1}, []*clusterNode{n2}, []*clusterNode{n3})
	eventually("nobody has a quorum", 40*time.Second, func() bool {
		for _, n := range nodes {
			if n.status()["quorum"] != false {
				return false
			}
		}
		return true
	})
	for _, n := range nodes {
		if status, _, _ := n.call("POST", "/api/v1/aliases", map[string]any{"name": "alone-" + n.name, "type": "host", "entries": []string{"192.0.2.3"}}); status/100 == 2 {
			t.Errorf("%s accepted a change on its own", n.name)
		}
		if !strings.Contains(n.rules(), "2222") {
			t.Errorf("%s stopped enforcing its configuration", n.name)
		}
	}
	heal()
	lead = leader(nodes...)
	// A change that was refused during the partition may surface now and
	// is rolled back because nobody confirmed it; wait for that to settle.
	eventually("nothing is pending", 90*time.Second, func() bool {
		_, d, _ := lead.call("GET", "/api/v1/apply", nil)
		return strings.Contains(string(d), `"pending":null`)
	})
	lead = leader(nodes...)
	write(lead, "POST", "/aliases", map[string]any{"name": "after-three-way", "type": "host", "entries": []string{"192.0.2.4"}})
	want := count(lead, "aliases")
	for _, n := range nodes {
		n := n
		eventually(n.name+" converged", 60*time.Second, func() bool { return count(n, "aliases") == want })
		for _, name := range []string{"alone-n1", "alone-n2", "alone-n3", "minority"} {
			if _, d, _ := n.call("GET", "/api/v1/aliases", nil); strings.Contains(string(d), `"`+name+`"`) {
				t.Errorf("%s holds %s, which was refused", n.name, name)
			}
		}
	}

	// 7. Two of three voters are lost for good. The last one is read-only
	//    until an operator recovers it on purpose; then it works alone.
	n2.stop(syscall.SIGKILL)
	n3.stop(syscall.SIGKILL)
	eventually("the survivor has no quorum", 40*time.Second, func() bool { return n1.status()["quorum"] == false })
	if status, _, _ := n1.call("POST", "/api/v1/aliases", map[string]any{"name": "no", "type": "host", "entries": []string{"192.0.2.5"}}); status/100 == 2 {
		t.Error("the survivor accepted a change without a quorum")
	}
	n1.stop(syscall.SIGINT)
	var recover *exec.Cmd
	recover = exec.Command(bin, "cluster", "recover", "--storage", n1.dir, "--node-name", "n1", "--cluster-raft", n1.ip+":7946")
	recover.Env = append(os.Environ(), "HOME="+n1.dir)
	if out, err := recover.CombinedOutput(); err == nil || !strings.Contains(string(out), "--unsafe") {
		t.Errorf("recover without --unsafe: %v %s", err, out)
	}
	recover = exec.Command(bin, "cluster", "recover", "--unsafe", "--storage", n1.dir, "--node-name", "n1", "--cluster-raft", n1.ip+":7946")
	recover.Env = append(os.Environ(), "HOME="+n1.dir)
	if out, err := recover.CombinedOutput(); err != nil {
		t.Fatalf("recover: %v %s", err, out)
	}
	n1.start()
	n1.login()
	eventually("the survivor leads alone", 40*time.Second, n1.leads)
	if count(n1, "aliases") != want {
		t.Errorf("after the recovery the survivor has %d aliases, had %d", count(n1, "aliases"), want)
	}
	write(n1, "POST", "/aliases", map[string]any{"name": "after-recovery", "type": "host", "entries": []string{"192.0.2.6"}})
}
