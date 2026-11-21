//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestLocalUsersEndToEnd: a node of an older install with users.json
// starts; its accounts move into the model with their passwords. The
// command line then changes a password and adds and removes a user through
// the daemon's control socket.
func TestLocalUsersEndToEnd(t *testing.T) {
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
	dir := t.TempDir()
	old, err := auth.Open(filepath.Join(dir, "users.json"))
	testnet.Must(t, err)
	testnet.Must(t, old.Add("testudo", "old admin password", auth.RoleAdmin))
	testnet.Must(t, old.Add("olivia", "old operator password", auth.RoleOperator))

	var stderr bytes.Buffer
	cmd := exec.Command(bin, "web", "--listen", "127.0.0.1:18085", "--storage", dir, "--db", filepath.Join(dir, "testudo.db"), "--allow-netops-write")
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
	base := "http://127.0.0.1:18085"
	login := func(user, pw string) (*http.Client, int) {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		hc := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := hc.PostForm(base+"/login", url.Values{"username": {user}, "password": {pw}})
		if err != nil {
			return hc, -1 // not listening yet
		}
		res.Body.Close()
		return hc, res.StatusCode
	}
	me := func(hc *http.Client) map[string]any {
		t.Helper()
		res, err := hc.Get(base + "/api/me")
		testnet.Must(t, err)
		defer res.Body.Close()
		var m map[string]any
		json.NewDecoder(res.Body).Decode(&m)
		return m
	}
	var ok bool
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && !ok; time.Sleep(200 * time.Millisecond) {
		_, st := login("olivia", "old operator password")
		ok = st == http.StatusSeeOther
	}
	if !ok {
		t.Fatal("the moved operator cannot log in with the old password")
	}
	if strings.Contains(stderr.String(), "password:") {
		t.Error("a first administrator was created although users moved in")
	}
	if _, err := os.Stat(filepath.Join(dir, "users.json.migrated")); err != nil {
		t.Errorf("users.json was not kept as users.json.migrated: %v", err)
	}
	hc, _ := login("olivia", "old operator password")
	if m := me(hc); m["source"] != "local" || !strings.Contains(strings.Join(toStrings(m["permissions"]), ","), "firewall:write") {
		t.Errorf("olivia: %v", m)
	}
	if _, st := login("olivia", "wrong password"); st != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", st)
	}

	cli := func(stdin string, args ...string) (string, error) {
		c := exec.Command(bin, append(args, "--storage", dir)...)
		c.Env = append(os.Environ(), "HOME="+dir)
		c.Stdin = strings.NewReader(stdin)
		out, err := c.CombinedOutput()
		return string(out), err
	}
	if out, err := cli("a brand new password\n", "user", "passwd", "olivia"); err != nil {
		t.Fatalf("user passwd: %v\n%s", err, out)
	}
	if _, st := login("olivia", "old operator password"); st != http.StatusUnauthorized {
		t.Error("the old password still works")
	}
	if _, st := login("olivia", "a brand new password"); st != http.StatusSeeOther {
		t.Error("the new password does not work")
	}
	if out, err := cli("reader password 1\n", "user", "add", "bob", "--role", "viewer"); err != nil {
		t.Fatalf("user add: %v\n%s", err, out)
	}
	bob, st := login("bob", "reader password 1")
	if st != http.StatusSeeOther {
		t.Fatalf("bob: %d", st)
	}
	if perms := strings.Join(toStrings(me(bob)["permissions"]), ","); perms != "*:read" {
		t.Errorf("bob may: %s", perms)
	}
	out, err := cli("", "user", "list")
	if err != nil || !strings.Contains(out, "bob") || !strings.Contains(out, "read-only") || !strings.Contains(out, "olivia") {
		t.Errorf("user list: %v\n%s", err, out)
	}
	if out, err := cli("", "user", "del", "bob"); err != nil {
		t.Fatalf("user del: %v\n%s", err, out)
	}
	if _, st := login("bob", "reader password 1"); st != http.StatusUnauthorized {
		t.Error("a deleted user logs in")
	}
	// Its password hash is gone from the secret store.
	var left []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		left = nil
		entries, _ := os.ReadDir(filepath.Join(dir, "secrets"))
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "user-") {
				left = append(left, e.Name())
			}
		}
		if len(left) == 2 { // testudo and olivia
			break
		}
	}
	if len(left) != 2 {
		t.Errorf("user secrets after the deletion: %v", left)
	}
	// Without the daemon the command line says so.
	c := exec.Command(bin, "user", "list", "--storage", t.TempDir())
	if out, err := c.CombinedOutput(); err == nil || !strings.Contains(string(out), "not running") {
		t.Errorf("user list without a daemon: %v %s", err, out)
	}
	_ = io.Discard
}

func toStrings(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
