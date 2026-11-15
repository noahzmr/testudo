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
)

// TestProviderIsUp succeeds once the test provider answers; the run script
// waits on it.
func TestProviderIsUp(t *testing.T) {
	if os.Getenv("TESTUDO_OIDC_WAIT") == "" {
		t.Skip("TESTUDO_OIDC_WAIT is not set")
	}
	res, err := http.Get("http://127.0.0.1:18480/realms/testudo/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("provider: %s", res.Status)
	}
}

// TestOIDCLoginEndToEnd logs in to the real binary through a real identity
// provider. It needs the provider from scripts/oidc-test (a Keycloak with
// the test realm); scripts/oidc-test/run.sh starts it and sets:
//
//	TESTUDO_E2E_BIN       the binary under test
//	TESTUDO_OIDC_ISSUER   the realm's issuer URL
//	TESTUDO_OIDC_STOP     a command that stops the provider (optional; with
//	                      it the test also checks logins while it is down)
func TestOIDCLoginEndToEnd(t *testing.T) {
	bin, issuer := os.Getenv("TESTUDO_E2E_BIN"), os.Getenv("TESTUDO_OIDC_ISSUER")
	if bin == "" || issuer == "" {
		t.Skip("TESTUDO_E2E_BIN and TESTUDO_OIDC_ISSUER are not set")
	}
	const base = "http://127.0.0.1:18182" // the realm's client is registered for this address
	dir := t.TempDir()
	var stderr bytes.Buffer
	cmd := exec.Command(bin, "web", "--listen", "127.0.0.1:18182", "--storage", dir, "--db", filepath.Join(dir, "testudo.db"), "--privsep=false")
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	password := ""
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && password == ""; time.Sleep(200 * time.Millisecond) {
		if m := regexp.MustCompile(`password: (\S+)`).FindStringSubmatch(stderr.String()); m != nil {
			password = m[1]
		}
	}
	if password == "" {
		t.Fatalf("no first-run password:\n%s", stderr.String())
	}

	// browser is one person's browser: cookies, no automatic redirects, so
	// each step of the flow can be looked at.
	type browser struct{ *http.Client }
	newBrowser := func() browser {
		jar, _ := cookiejar.New(nil)
		return browser{&http.Client{Jar: jar, Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	}
	do := func(b browser, method, target string, body any, hdr ...string) (int, []byte, http.Header) {
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
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		return res.StatusCode, data, res.Header
	}
	wait := func(b browser) {
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if res, err := b.Get(base + "/login"); err == nil {
				res.Body.Close()
				return
			}
		}
		t.Fatal("the console did not come up")
	}
	object := func(data []byte) map[string]any {
		var m map[string]any
		json.Unmarshal(data, &m)
		return m
	}
	// write sends a change to the model and confirms it.
	write := func(b browser, method, path string, body any) map[string]any {
		t.Helper()
		status, data, hdr := do(b, method, base+"/api/v1"+path, body)
		if status/100 != 2 {
			t.Fatalf("%s %s: %d %s", method, path, status, data)
		}
		if hdr.Get("Testudo-Pending") != "" {
			if s, d, _ := do(b, "POST", base+"/api/v1/apply/confirm", nil); s != 204 {
				t.Fatalf("confirm: %d %s", s, d)
			}
		}
		return object(data)
	}

	// 1. The local administrator sets the provider up.
	admin := newBrowser()
	wait(admin)
	if status, _, _ := do(admin, "POST", base+"/login", url.Values{"username": {"testudo"}, "password": {password}}); status != http.StatusSeeOther {
		t.Fatalf("local login: %d", status)
	}
	if _, page, _ := do(admin, "GET", base+"/login", nil); strings.Contains(string(page), "/auth/oidc/login") {
		t.Error("the login page offers a provider before one is configured")
	}
	ref := write(admin, "POST", "/oidc/client-secret", map[string]string{"secret": "test-only-client-secret"})["client_secret_ref"]
	write(admin, "POST", "/oidc-providers", map[string]any{"name": "Keycloak", "enabled": true, "issuer": issuer, "client_id": "testudo",
		"client_secret_ref": ref, "redirect_url": base + "/auth/oidc/callback"})
	_, data, _ := do(admin, "GET", base+"/api/v1/roles", nil)
	var roles []map[string]any
	json.Unmarshal(data, &roles)
	roleID := map[string]string{}
	for _, r := range roles {
		roleID[r["name"].(string)] = r["id"].(string)
	}
	if roleID["operator"] == "" || roleID["admin"] == "" || roleID["read-only"] == "" || roleID["vpn-user"] == "" {
		t.Fatalf("built-in roles: %v", roleID)
	}
	netops := write(admin, "POST", "/groups", map[string]any{"name": "netops", "claim": "/network/operators", "roles": []string{roleID["operator"]}})
	write(admin, "POST", "/groups", map[string]any{"name": "staff", "claim": "/staff", "roles": []string{roleID["vpn-user"]}})
	if _, page, _ := do(admin, "GET", base+"/login", nil); !strings.Contains(string(page), "Sign in with Keycloak") {
		t.Error("the login page does not offer the provider")
	}

	// login walks the provider's login form like a person would and returns
	// the status and body of the console's callback.
	login := func(b browser, user, pass string) (int, string) {
		t.Helper()
		status, _, hdr := do(b, "GET", base+"/auth/oidc/login", nil)
		authURL := hdr.Get("Location")
		if status != http.StatusFound || !strings.HasPrefix(authURL, issuer) {
			t.Fatalf("redirect to the provider: %d %q", status, authURL)
		}
		q, _ := url.Parse(authURL)
		if q.Query().Get("code_challenge_method") != "S256" || q.Query().Get("nonce") == "" || q.Query().Get("state") == "" {
			t.Fatalf("authorization request lacks PKCE, nonce or state: %s", authURL)
		}
		_, page, _ := do(b, "GET", authURL, nil)
		m := regexp.MustCompile(`<form[^>]*action="([^"]+)"`).FindSubmatch(page)
		if m == nil {
			t.Fatalf("no login form at the provider:\n%.400s", page)
		}
		action := strings.ReplaceAll(string(m[1]), "&amp;", "&")
		status, body, hdr := do(b, "POST", action, url.Values{"username": {user}, "password": {pass}, "credentialId": {""}})
		back := hdr.Get("Location")
		if status != http.StatusFound || !strings.HasPrefix(back, base+"/auth/oidc/callback") {
			t.Fatalf("the provider did not redirect back for %s: %d %q\n%.300s", user, status, back, body)
		}
		status, body, _ = do(b, "GET", back, nil)
		return status, string(body)
	}

	// 2. alice is in a group that maps to the operator role.
	alice := newBrowser()
	if status, body := login(alice, "alice", "alice-test-password"); status != http.StatusSeeOther {
		t.Fatalf("alice's login: %d %s", status, body)
	}
	_, data, _ = do(alice, "GET", base+"/api/me", nil)
	me := object(data)
	if me["user"] != "alice" || me["source"] != "oidc" || me["role"] != "operator" {
		t.Errorf("alice is %v", me)
	}
	// The role is enforced by the API: she manages the firewall and not
	// who may log in.
	write(alice, "POST", "/zones", map[string]any{"name": "wan", "default_action": "drop"})
	if status, _, _ := do(alice, "POST", base+"/api/v1/roles", map[string]any{"name": "mine", "permissions": []string{"*:write"}}); status != http.StatusForbidden {
		t.Errorf("an operator created a role: %d", status)
	}
	if status, _, _ := do(alice, "POST", base+"/api/users/add", map[string]string{"name": "x", "password": "long-enough-password", "role": "admin"}); status != http.StatusForbidden {
		t.Errorf("an operator reached an admin-only endpoint: %d", status)
	}
	// A token of hers carries at most her permissions.
	if status, _, _ := do(alice, "POST", base+"/api/v1/tokens", map[string]any{"name": "too-much", "permissions": []string{"system:write"}}); status != http.StatusForbidden {
		t.Errorf("token beyond her permissions: %d", status)
	}
	_, data, _ = do(alice, "POST", base+"/api/v1/tokens", map[string]any{"name": "ci", "permissions": []string{"firewall:read"}})
	token, _ := object(data)["token"].(string)
	script := newBrowser()
	if status, _, _ := do(script, "GET", base+"/api/v1/zones", nil, "Authorization", "Bearer "+token); status != 200 {
		t.Errorf("read with the token: %d", status)
	}
	if status, _, _ := do(script, "POST", base+"/api/v1/zones", map[string]any{"name": "lan", "default_action": "drop"}, "Authorization", "Bearer "+token); status != http.StatusForbidden {
		t.Errorf("write with a read-only token: %d", status)
	}
	if status, _, _ := do(script, "GET", base+"/api/v1/zones", nil, "Authorization", "Bearer "+token+"x"); status != http.StatusUnauthorized {
		t.Errorf("a wrong token: %d", status)
	}

	// 3. Being known to the provider is not enough: mallory has no group,
	//    bob only one that may not use the console.
	for user, pass := range map[string]string{"mallory": "mallory-test-password", "bob": "bob-test-password"} {
		b := newBrowser()
		if status, body := login(b, user, pass); status != http.StatusForbidden || !strings.Contains(body, "no role") {
			t.Errorf("%s: %d %.200s", user, status, body)
		}
		if status, _, _ := do(b, "GET", base+"/api/me", nil); status != http.StatusUnauthorized {
			t.Errorf("%s has a session: %d", user, status)
		}
	}
	// A callback with a state nobody asked for is refused.
	if status, _, _ := do(newBrowser(), "GET", base+"/auth/oidc/callback?state=made-up&code=x", nil); status != http.StatusBadRequest {
		t.Errorf("callback with an unknown state: %d", status)
	}

	// 4. Taking the role away ends her access at the next request, not at
	//    the next login.
	netops["roles"] = []string{roleID["vpn-user"]}
	status, _, hdr := do(admin, "PUT", base+"/api/v1/groups/"+netops["id"].(string), netops, "If-Match", fmt.Sprintf(`"%v"`, netops["version"]))
	if status != 200 {
		t.Fatalf("change the group: %d", status)
	}
	if hdr.Get("Testudo-Pending") != "" {
		do(admin, "POST", base+"/api/v1/apply/confirm", nil)
	}
	if status, _, _ := do(alice, "GET", base+"/api/me", nil); status != http.StatusUnauthorized {
		t.Errorf("alice after her role was withdrawn: %d", status)
	}
	// Put it back and log in again for the logout checks.
	_, data, _ = do(admin, "GET", base+"/api/v1/groups/"+netops["id"].(string), nil)
	netops = object(data)
	netops["roles"] = []string{roleID["operator"]}
	if status, _, hdr := do(admin, "PUT", base+"/api/v1/groups/"+netops["id"].(string), netops, "If-Match", fmt.Sprintf(`"%v"`, netops["version"])); status != 200 {
		t.Fatalf("restore the group: %d", status)
	} else if hdr.Get("Testudo-Pending") != "" {
		do(admin, "POST", base+"/api/v1/apply/confirm", nil)
	}

	// 5. Logout at the console leads to the provider's logout; following
	//    it makes the provider call back and end the session it knows.
	alice = newBrowser()
	if status, body := login(alice, "alice", "alice-test-password"); status != http.StatusSeeOther {
		t.Fatalf("alice's second login: %d %s", status, body)
	}
	second := newBrowser() // the same person in another browser, same provider session? No: a separate one.
	if status, body := login(second, "alice", "alice-test-password"); status != http.StatusSeeOther {
		t.Fatalf("alice in a second browser: %d %s", status, body)
	}
	status, data, _ = do(alice, "POST", base+"/api/logout", nil)
	logoutURL, _ := object(data)["logout_url"].(string)
	if status != 200 || !strings.HasPrefix(logoutURL, issuer) || !strings.Contains(logoutURL, "id_token_hint=") {
		t.Fatalf("logout: %d %s", status, data)
	}
	if status, _, _ := do(alice, "GET", base+"/api/me", nil); status != http.StatusUnauthorized {
		t.Errorf("after logout the session still works: %d", status)
	}
	if status, _, _ := do(second, "GET", base+"/api/me", nil); status != 200 {
		t.Errorf("logging out one browser ended the other: %d", status)
	}
	// The provider ends the second browser's session itself (an
	// administrator there logs the user out everywhere): back-channel.
	kc := strings.Split(issuer, "/realms/")[0]
	_, data, _ = do(newBrowser(), "POST", kc+"/realms/master/protocol/openid-connect/token",
		url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin-test-password"}})
	adminToken, _ := object(data)["access_token"].(string)
	_, data, _ = do(newBrowser(), "GET", kc+"/admin/realms/testudo/users?username=alice&exact=true", nil, "Authorization", "Bearer "+adminToken)
	var users []map[string]any
	json.Unmarshal(data, &users)
	if adminToken == "" || len(users) != 1 {
		t.Fatalf("provider admin API: %.200s", data)
	}
	if status, body, _ := do(newBrowser(), "POST", kc+"/admin/realms/testudo/users/"+users[0]["id"].(string)+"/logout", nil, "Authorization", "Bearer "+adminToken); status/100 != 2 {
		t.Fatalf("logout at the provider: %d %s", status, body)
	}
	gone := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && !gone; time.Sleep(200 * time.Millisecond) {
		status, _, _ := do(second, "GET", base+"/api/me", nil)
		gone = status == http.StatusUnauthorized
	}
	if !gone {
		t.Error("the provider logged the user out and the console session lives on")
	}

	// 6. With the provider down the local administrator still gets in, and
	//    the login page says what is wrong instead of failing.
	if stop := os.Getenv("TESTUDO_OIDC_STOP"); stop != "" {
		if out, err := exec.Command("sh", "-c", stop).CombinedOutput(); err != nil {
			t.Fatalf("stop the provider: %v %s", err, out)
		}
		b := newBrowser()
		status, body, _ := do(b, "GET", base+"/auth/oidc/login", nil)
		// The client may still hold the discovery document; then the
		// redirect happens and it is the provider that cannot be reached.
		if status != http.StatusBadGateway && status != http.StatusFound {
			t.Errorf("login at a provider that is down: %d %.200s", status, body)
		}
		if status, _, _ := do(b, "POST", base+"/login", url.Values{"username": {"testudo"}, "password": {password}}); status != http.StatusSeeOther {
			t.Errorf("local login while the provider is down: %d", status)
		}
		if status, _, _ := do(b, "GET", base+"/api/v1/zones", nil); status != 200 {
			t.Errorf("the local administrator cannot work while the provider is down: %d", status)
		}
	}

	// 7. Every login and logout is in the audit log, with its source.
	_, data, _ = do(admin, "GET", base+"/api/v1/audit?limit=500", nil)
	for _, want := range []string{`"source":"oidc"`, `"source":"local"`, `"by":"provider"`, "no role is assigned", "config_applied", "create group netops"} {
		if !strings.Contains(strings.ReplaceAll(string(data), `\"`, `"`), want) {
			t.Errorf("the audit log lacks %s", want)
		}
	}
}
