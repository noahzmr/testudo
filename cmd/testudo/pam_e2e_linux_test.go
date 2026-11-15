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
)

// TestPAMLoginEndToEnd logs in to the real binary with real host accounts:
// pam_unix against the shadow database, pam_faillock, the account phase.
// It creates users and writes /etc/pam.d/testudo, so it only runs where it
// is asked to, as root, in a throwaway container (scripts/pam-test/run.sh).
// The binary has to be built with the "pam" tag.
func TestPAMLoginEndToEnd(t *testing.T) {
	bin := os.Getenv("TESTUDO_E2E_BIN")
	if bin == "" || os.Getenv("TESTUDO_PAM_E2E") != "1" {
		t.Skip("TESTUDO_E2E_BIN and TESTUDO_PAM_E2E=1 are not set")
	}
	if os.Geteuid() != 0 {
		t.Fatal("needs root")
	}
	sh := func(script string) {
		t.Helper()
		if out, err := exec.Command("sh", "-ec", script).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
	}
	stack, err := os.ReadFile(os.Getenv("TESTUDO_PAM_STACK"))
	if err != nil {
		t.Fatalf("TESTUDO_PAM_STACK: %v", err)
	}
	if err := os.WriteFile("/etc/pam.d/testudo", stack, 0o644); err != nil {
		t.Fatal(err)
	}
	const (
		adminPw = "admin-Passw0rd-for-test"
		opsPw   = "ops-Passw0rd-for-test"
		anyPw   = "any-Passw0rd-for-test"
	)
	sh(`groupadd -f testudo-admin; groupadd -f netops
useradd -m -G testudo-admin tdadmin; useradd -m -G netops tdops; useradd -m tdnobody; useradd -m tdexpired; useradd -m -G netops tdlocked
printf 'tdadmin:` + adminPw + `\ntdops:` + opsPw + `\ntdnobody:` + anyPw + `\ntdexpired:` + anyPw + `\ntdlocked:` + anyPw + `\n' | chpasswd
chage -E 1 tdexpired`)

	dir := t.TempDir()
	var stderr bytes.Buffer
	cmd := exec.Command(bin, "web", "--listen", "127.0.0.1:18183", "--storage", dir, "--db", filepath.Join(dir, "testudo.db"), "--allow-netops-write")
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
		}
		if t.Failed() {
			t.Logf("daemon stderr:\n%s", stderr.String())
		}
	}()
	const base = "http://127.0.0.1:18183"
	localPw := ""
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && localPw == ""; time.Sleep(100 * time.Millisecond) {
		if m := regexp.MustCompile(`password: (\S+)`).FindStringSubmatch(stderr.String()); m != nil {
			if res, err := http.Get(base + "/login"); err == nil {
				res.Body.Close()
				localPw = m[1]
			}
		}
	}
	if localPw == "" {
		t.Fatalf("the console did not come up:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "helper") && strings.Contains(stderr.String(), "privsep disabled") {
		t.Fatal("the test is meant to run with privilege separation")
	}

	type browser struct{ *http.Client }
	newBrowser := func() browser {
		jar, _ := cookiejar.New(nil)
		return browser{&http.Client{Jar: jar, Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	}
	do := func(b browser, method, path string, body any, hdr ...string) (int, []byte, http.Header) {
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
		req, _ := http.NewRequest(method, base+path, rd)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		res, err := b.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		return res.StatusCode, data, res.Header
	}
	login := func(b browser, user, pass string) (int, string) {
		status, body, _ := do(b, "POST", "/login", url.Values{"username": {user}, "password": {pass}})
		return status, string(body)
	}
	me := func(b browser) map[string]any {
		_, data, _ := do(b, "GET", "/api/me", nil)
		var m map[string]any
		json.Unmarshal(data, &m)
		return m
	}
	write := func(b browser, method, path string, body any, hdr ...string) map[string]any {
		t.Helper()
		status, data, h := do(b, method, "/api/v1"+path, body, hdr...)
		if status/100 != 2 {
			t.Fatalf("%s %s: %d %s", method, path, status, data)
		}
		if h.Get("Testudo-Pending") != "" {
			if s, d, _ := do(b, "POST", "/api/v1/apply/confirm", nil); s != 204 {
				t.Fatalf("confirm: %d %s", s, d)
			}
		}
		var m map[string]any
		json.Unmarshal(data, &m)
		return m
	}

	// 1. Break-glass: a member of testudo-admin is an administrator with a
	//    model that knows nothing about them.
	admin := newBrowser()
	if status, body := login(admin, "tdadmin", adminPw); status != http.StatusSeeOther {
		t.Fatalf("break-glass login: %d %.300s", status, body)
	}
	if m := me(admin); m["user"] != "tdadmin" || m["source"] != "pam" || m["role"] != "admin" || m["break_glass"] != true {
		t.Errorf("break-glass admin is %v", m)
	}
	if status, _ := login(newBrowser(), "tdadmin", "not-the-password"); status != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", status)
	}
	if status, _ := login(newBrowser(), "no-such-user", "x"); status != http.StatusUnauthorized {
		t.Errorf("unknown user: %d", status)
	}

	// 2. A host account nothing gives a role to stays out, with the right
	//    password.
	if status, body := login(newBrowser(), "tdops", opsPw); status != http.StatusForbidden || !strings.Contains(body, "no role") {
		t.Errorf("host account without a role: %d %.200s", status, body)
	}
	// The administrator maps the host group to the operator role.
	_, data, _ := do(admin, "GET", "/api/v1/roles", nil)
	var roles []map[string]any
	json.Unmarshal(data, &roles)
	operator := ""
	for _, r := range roles {
		if r["name"] == "operator" {
			operator = r["id"].(string)
		}
	}
	group := write(admin, "POST", "/groups", map[string]any{"name": "netops", "claim": "netops", "roles": []string{operator}})
	ops := newBrowser()
	if status, body := login(ops, "tdops", opsPw); status != http.StatusSeeOther {
		t.Fatalf("operator login: %d %.300s", status, body)
	}
	if m := me(ops); m["source"] != "pam" || m["role"] != "operator" || m["break_glass"] == true {
		t.Errorf("tdops is %v", m)
	}
	write(ops, "POST", "/zones", map[string]any{"name": "wan", "default_action": "drop"})
	if status, _, _ := do(ops, "POST", "/api/v1/roles", map[string]any{"name": "mine", "permissions": []string{"*:write"}}); status != http.StatusForbidden {
		t.Errorf("an operator created a role: %d", status)
	}
	// Removing the mapping ends the session at its next request.
	if status, _, h := do(admin, "DELETE", "/api/v1/groups/"+group["id"].(string), nil, "If-Match", fmt.Sprintf(`"%v"`, group["version"])); status/100 != 2 {
		t.Fatalf("delete the group: %d", status)
	} else if h.Get("Testudo-Pending") != "" {
		do(admin, "POST", "/api/v1/apply/confirm", nil)
	}
	if status, _, _ := do(ops, "GET", "/api/me", nil); status != http.StatusUnauthorized {
		t.Errorf("tdops after the mapping was removed: %d", status)
	}
	write(admin, "POST", "/groups", map[string]any{"name": "netops", "claim": "netops", "roles": []string{operator}})

	// 3. The account phase: an expired account has the right password and
	//    still does not get in.
	if status, body := login(newBrowser(), "tdexpired", anyPw); status != http.StatusForbidden || !strings.Contains(body, "cannot log in") {
		t.Errorf("expired account: %d %.300s", status, body)
	}

	// 4. Lock-out: after three wrong passwords the right one is refused
	//    too, by the host's own module.
	for i := 0; i < 3; i++ {
		if status, _ := login(newBrowser(), "tdlocked", "wrong-"+fmt.Sprint(i)); status != http.StatusUnauthorized {
			t.Errorf("wrong password %d for tdlocked: %d", i, status)
		}
	}
	if status, _ := login(newBrowser(), "tdlocked", anyPw); status == http.StatusSeeOther {
		t.Error("the account is not locked after three failures")
	}
	sh("faillock --user tdlocked --reset")
	if status, body := login(newBrowser(), "tdlocked", anyPw); status != http.StatusSeeOther {
		t.Errorf("after the lock was reset: %d %.200s", status, body)
	}

	// 5. The built-in account still works next to the host's.
	local := newBrowser()
	if status, _ := login(local, "testudo", localPw); status != http.StatusSeeOther {
		t.Errorf("built-in account: %d", status)
	}
	if m := me(local); m["source"] != "local" || m["role"] != "admin" {
		t.Errorf("built-in account is %v", m)
	}

	// 6. Too many failures from one address are refused before they reach
	//    the stack.
	throttled := false
	for i := 0; i < 12 && !throttled; i++ {
		status, _ := login(newBrowser(), "tdnobody", "guess")
		throttled = status == http.StatusTooManyRequests
	}
	if !throttled {
		t.Error("failed logins are not throttled")
	}

	// 7. Logins are in the audit log with their source, and no password is
	//    anywhere on disk.
	_, data, _ = do(admin, "GET", "/api/v1/audit?limit=500", nil)
	audit := strings.ReplaceAll(string(data), `\"`, `"`)
	for _, want := range []string{`"source":"pam"`, `"break_glass":true`, `"result":"denied"`, `"result":"throttled"`, "no role is assigned"} {
		if !strings.Contains(audit, want) {
			t.Errorf("the audit log lacks %s", want)
		}
	}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		content, _ := os.ReadFile(path)
		for _, secret := range []string{adminPw, opsPw, anyPw, "not-the-password"} {
			if bytes.Contains(content, []byte(secret)) {
				t.Errorf("a password is in %s", path)
			}
		}
		return nil
	})
	if strings.Contains(stderr.String(), adminPw) || strings.Contains(stderr.String(), opsPw) {
		t.Error("a password is in the daemon's output")
	}
}
