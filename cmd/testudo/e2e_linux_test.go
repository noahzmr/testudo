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
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/testnet"
)

// TestPrivilegedPathEndToEnd runs the real binary with privilege separation:
// the web process drops its capabilities, so a ruleset can only reach the
// kernel through the helper and its nft runner. It needs root, a private
// network namespace and the binary named by TESTUDO_E2E_BIN.
func TestPrivilegedPathEndToEnd(t *testing.T) {
	bin := os.Getenv("TESTUDO_E2E_BIN")
	if bin == "" {
		t.Skip("TESTUDO_E2E_BIN is not set")
	}
	if testnet.Isolate(t) {
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for the helper to hold network capabilities")
	}
	dir := t.TempDir()
	var stderr bytes.Buffer
	cmd := exec.Command(bin, "web", "--listen", "127.0.0.1:18080", "--storage", dir, "--db", filepath.Join(dir, "testudo.db"),
		"--allow-netops-write")
	cmd.Env = append(os.Environ(), "HOME="+dir)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			t.Error("the daemon did not stop within 5 s")
		}
		if t.Failed() {
			t.Logf("daemon stderr:\n%s", stderr.String())
		}
	}()

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	base := "http://127.0.0.1:18080"
	var pw string
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if m := regexp.MustCompile(`password: (\S+)`).FindStringSubmatch(stderr.String()); m != nil {
			if res, err := hc.Get(base + "/login"); err == nil {
				res.Body.Close()
				pw = m[1]
				break
			}
		}
	}
	if pw == "" {
		t.Fatal("the daemon did not come up")
	}
	if res, err := hc.PostForm(base+"/login", url.Values{"username": {"testudo"}, "password": {pw}}); err != nil {
		t.Fatal(err)
	} else {
		res.Body.Close()
	}
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			js, _ := json.Marshal(body)
			rd = bytes.NewReader(js)
		}
		req, _ := http.NewRequest(method, base+path, rd)
		req.Header.Set("Content-Type", "application/json")
		res, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var out map[string]any
		json.Unmarshal(raw, &out)
		if out == nil {
			out = map[string]any{"raw": string(raw)}
		}
		return res.StatusCode, out
	}
	write := func(path string, body any) map[string]any {
		t.Helper()
		status, out := call("POST", path, body)
		if status != 201 {
			t.Fatalf("POST %s: %d %v", path, status, out)
		}
		if status, out := call("POST", "/api/v1/apply/confirm", nil); status != 204 {
			t.Fatalf("confirm: %d %v", status, out)
		}
		return out
	}

	if _, rt := call("GET", "/api/v1/runtime", nil); rt["packet_filter"] != "nftables" {
		t.Fatalf("the daemon is not on the nftables path: %v", rt)
	}
	write("/api/v1/firewall-policies", map[string]any{"name": "default", "default_deny": true, "allow_established": true,
		"allow_loopback": true, "allow_icmp": true})
	alias := write("/api/v1/aliases", map[string]any{"name": "servers", "type": "host", "entries": []string{"192.0.2.10", "2001:db8::10"}})
	rule := write("/api/v1/filter-rules", map[string]any{"name": "to-servers", "enabled": true, "action": "accept",
		"direction": "forward", "protocol": "tcp", "destination": []string{alias["id"].(string)}, "ports": []string{"443"}})

	// The web process holds no capabilities; nft run from this test (root)
	// shows what its helper loaded.
	out, err := exec.Command("nft", "list", "table", "inet", "testudo").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v\n%s", err, out)
	}
	listing := string(out)
	for _, want := range []string{
		"hook input priority filter; policy drop;",
		"tcp dport 18080", // the web UI's own port is protected
		"ip daddr 192.0.2.10 tcp dport 443",
		"ip6 daddr 2001:db8::10 tcp dport 443",
		fmt.Sprint(rule["id"]),
	} {
		if !strings.Contains(listing, want) {
			t.Errorf("the loaded ruleset lacks %q", want)
		}
	}
	if t.Failed() {
		t.Logf("ruleset:\n%s", listing)
	}
	// A ruleset nft refuses is stopped in the dry run: nothing is committed.
	status, problem := call("POST", "/api/v1/filter-rules", map[string]any{"name": "bad-limit", "enabled": true, "action": "accept",
		"direction": "in", "protocol": "tcp", "rate_limit": "999999999/second"})
	if status == 201 {
		call("POST", "/api/v1/apply/confirm", nil)
	} else if status != 422 || problem["phase"] != "check" {
		t.Errorf("a refused ruleset: %d %v", status, problem)
	}
	if _, rt := call("GET", "/api/v1/runtime", nil); rt["counters"] == nil {
		t.Errorf("no counters from the running ruleset: %v", rt)
	}
	// The apply shows up in the audit log without the ruleset text.
	if strings.Contains(stderr.String(), "nft runner unavailable") {
		t.Error("the helper could not start its nft runner")
	}
}
