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

// TestPublishedServiceNeedsLogin puts a service behind the real proxy with
// a router that requires a group, and visits it like a browser: sent to
// the console, logged in, sent back, let through; then access is taken
// away in each of the ways it can be.
func TestPublishedServiceNeedsLogin(t *testing.T) {
	bin := os.Getenv("TESTUDO_E2E_BIN")
	if bin == "" {
		t.Skip("TESTUDO_E2E_BIN is not set")
	}
	if _, err := exec.LookPath("traefik"); err != nil {
		t.Skip("traefik is not installed")
	}
	if testnet.Isolate(t) {
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const console, app = "http://127.0.0.1:18080", "http://app.example.com:8081"
	// The published application says who the proxy told it the visitor is.
	backend := &http.Server{Addr: "127.0.0.1:9000", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s at %s", r.Header.Get("X-Forwarded-User"), r.URL.RequestURI())
	})}
	go backend.ListenAndServe()
	defer backend.Close()

	dir := t.TempDir()
	var stderr bytes.Buffer
	cmd := exec.Command(bin, "web", "--listen", "127.0.0.1:18080", "--storage", dir, "--db", filepath.Join(dir, "testudo.db"),
		"--allow-netops-write", "--public-url", console)
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
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
		}
		if t.Failed() {
			t.Logf("daemon stderr:\n%s", stderr.String())
		}
	}()

	type browser struct{ *http.Client }
	newBrowser := func() browser {
		jar, _ := cookiejar.New(nil)
		// Every host name is this machine; the port decides who answers.
		dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
		}
		return browser{&http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: dial, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	}
	do := func(b browser, method, target string, body any, hdr ...string) (int, string, http.Header) {
		t.Helper()
		var rd io.Reader
		ctype := ""
		switch v := body.(type) {
		case nil:
		case url.Values:
			rd, ctype = strings.NewReader(v.Encode()), "application/x-www-form-urlencoded"
		default:
			js, _ := json.Marshal(v)
			rd, ctype = bytes.NewReader(js), "application/json"
		}
		req, _ := http.NewRequest(method, target, rd)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		res, err := b.Do(req)
		if err != nil {
			return 0, err.Error(), nil
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(data), res.Header
	}
	admin := newBrowser()
	pw := ""
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && pw == ""; time.Sleep(100 * time.Millisecond) {
		if m := regexp.MustCompile(`password: (\S+)`).FindStringSubmatch(stderr.String()); m != nil {
			if status, _, _ := do(admin, "GET", console+"/login", nil); status == 200 {
				pw = m[1]
			}
		}
	}
	if pw == "" {
		t.Fatalf("the console did not come up:\n%s", stderr.String())
	}
	if status, _, _ := do(admin, "POST", console+"/login", url.Values{"username": {"testudo"}, "password": {pw}}); status != http.StatusSeeOther {
		t.Fatalf("admin login: %d", status)
	}
	write := func(method, path string, body any, hdr ...string) map[string]any {
		t.Helper()
		status, data, h := do(admin, method, console+"/api/v1"+path, body, hdr...)
		if status/100 != 2 {
			t.Fatalf("%s %s: %d %s", method, path, status, data)
		}
		if h.Get("Testudo-Pending") != "" {
			if s, d, _ := do(admin, "POST", console+"/api/v1/apply/confirm", nil); s != 204 {
				t.Fatalf("confirm: %d %s", s, d)
			}
		}
		var m map[string]any
		json.Unmarshal([]byte(data), &m)
		return m
	}
	// Two local users; the model says which groups they are in.
	var roles []map[string]any
	_, rolesRaw, _ := do(admin, "GET", console+"/api/v1/roles", nil)
	json.Unmarshal([]byte(rolesRaw), &roles)
	readOnly := ""
	for _, r := range roles {
		if r["name"] == "read-only" {
			readOnly = r["id"].(string)
		}
	}
	staff := write("POST", "/groups", map[string]any{"name": "staff"})
	erin := write("POST", "/users", map[string]any{"name": "erin", "username": "erin", "source": "local", "roles": []string{readOnly},
		"groups": []string{staff["id"].(string)}})
	frank := write("POST", "/users", map[string]any{"name": "frank", "username": "frank", "source": "local", "roles": []string{readOnly}})
	for name, u := range map[string]map[string]any{"erin": erin, "frank": frank} {
		write("POST", "/users/"+u["id"].(string)+"/password", map[string]string{"password": name + "-Passw0rd-for-test"})
	}
	zone := write("POST", "/zones", map[string]any{"name": "wan", "default_action": "drop"})
	pool := write("POST", "/lb-backend-pools", map[string]any{"name": "app", "algorithm": "weighted_round_robin",
		"backends": []map[string]any{{"address": "127.0.0.1:9000"}}, "health_check": map[string]any{"type": "none"}})
	svc := write("POST", "/lb-services", map[string]any{"name": "web", "enabled": true, "zone": zone["id"], "port": 8081, "protocol": "http", "mode": "proxy"})
	write("POST", "/lb-routers", map[string]any{"name": "app", "enabled": true, "service": svc["id"], "hosts": []string{"app.example.com"},
		"tls": "none", "pool": pool["id"], "require_groups": []string{staff["id"].(string)}})
	write("POST", "/lb-routers", map[string]any{"name": "open", "enabled": true, "service": svc["id"], "hosts": []string{"open.example.com"},
		"tls": "none", "pool": pool["id"]})

	// 1. A router without the requirement is simply open.
	if status, body, _ := do(newBrowser(), "GET", "http://open.example.com:8081/x", nil); status != 200 || body != "hello  at /x" {
		t.Fatalf("open router: %d %q", status, body)
	}
	// A request that is not a page load is refused, not redirected.
	if status, _, _ := do(newBrowser(), "POST", app+"/api", nil); status != http.StatusUnauthorized {
		t.Errorf("POST without access: %d", status)
	}

	// visit goes to the application and follows the redirects through the
	// console's login, and returns what the application finally answered.
	visit := func(b browser, user string) (int, string) {
		t.Helper()
		at := app + "/reports?year=2026"
		status, body, h := do(b, "GET", at, nil)
		for hops := 0; status/100 == 3 && hops < 8; hops++ {
			// A relative redirect stays with whoever sent it.
			base, _ := url.Parse(at)
			next, err := base.Parse(h.Get("Location"))
			if err != nil {
				t.Fatalf("redirect to %q", h.Get("Location"))
			}
			at = next.String()
			if next.Path == "/login" {
				status, body, h = do(b, "POST", at, url.Values{"username": {user}, "password": {user + "-Passw0rd-for-test"}})
				continue
			}
			status, body, h = do(b, "GET", at, nil)
			t.Logf("  %s -> %d %s", at, status, h.Get("Location"))
		}
		return status, body
	}

	// 2. erin is in the group: after the detour she is at the page she
	//    asked for, and the application is told who she is.
	eb := newBrowser()
	status, _, h := do(eb, "GET", app+"/reports?year=2026", nil)
	if status != http.StatusFound || !strings.HasPrefix(h.Get("Location"), console+"/access/login?") {
		t.Fatalf("first visit: %d %q", status, h.Get("Location"))
	}
	if status, body := visit(eb, "erin"); status != 200 || body != "hello erin at /reports?year=2026" {
		t.Fatalf("erin after logging in: %d %q", status, body)
	}
	// From now on she is simply let through.
	if status, body, _ := do(eb, "GET", app+"/other", nil); status != 200 || body != "hello erin at /other" {
		t.Errorf("erin's next request: %d %q", status, body)
	}
	// Her cookie means nothing for another browser without it, and a
	// made-up ticket opens nothing.
	if status, _, _ := do(newBrowser(), "GET", app+"/?testudo_ticket=made-up", nil); status != http.StatusFound {
		t.Errorf("a made-up ticket: %d", status)
	}
	// The console does not make tickets for hosts it does not publish.
	if status, _, _ := do(eb, "GET", console+"/access/login?host=evil.example.org&proto=http&rd=/", nil); status != http.StatusBadRequest {
		t.Errorf("ticket for a foreign host: %d", status)
	}

	// 3. frank logs in fine and is not in the group.
	fb := newBrowser()
	if status, body := visit(fb, "frank"); status != http.StatusForbidden || !strings.Contains(body, "not open to you") {
		t.Errorf("frank: %d %q", status, body)
	}

	// 4. Taking erin out of the group closes the service at her next
	//    request.
	erin["groups"] = []string{}
	write("PUT", "/users/"+erin["id"].(string), erin, "If-Match", fmt.Sprintf(`"%v"`, erin["version"]))
	if status, _, _ := do(eb, "GET", app+"/other", nil); status != http.StatusForbidden {
		t.Errorf("erin after leaving the group: %d", status)
	}
	_, data, _ := do(admin, "GET", console+"/api/v1/users/"+erin["id"].(string), nil)
	json.Unmarshal([]byte(data), &erin)
	erin["groups"] = []string{staff["id"].(string)}
	write("PUT", "/users/"+erin["id"].(string), erin, "If-Match", fmt.Sprintf(`"%v"`, erin["version"]))
	if status, _, _ := do(eb, "GET", app+"/other", nil); status != 200 {
		t.Errorf("erin back in the group: %d", status)
	}

	// 5. Logging out of the console closes the service too.
	if status, _, _ := do(eb, "POST", console+"/api/logout", nil); status/100 != 2 {
		t.Fatalf("logout: %d", status)
	}
	if status, _, h := do(eb, "GET", app+"/other", nil); status != http.StatusFound || !strings.HasPrefix(h.Get("Location"), console+"/access/login?") {
		t.Errorf("erin after logging out: %d %q", status, h.Get("Location"))
	}
}
