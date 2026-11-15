//go:build linux && cgo && pam

package pamauth

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// stack writes a PAM service file into a private directory. The modules are
// pam_exec with scripts, so the test needs neither root nor real accounts
// and still goes through the real library and its conversation.
func stack(t *testing.T, lines ...string) (confdir string, script func(name, body string) string) {
	t.Helper()
	if _, err := os.Stat("/usr/lib/x86_64-linux-gnu/security/pam_exec.so"); err != nil {
		if _, err := os.Stat("/lib/security/pam_exec.so"); err != nil {
			t.Skip("pam_exec is not installed")
		}
	}
	dir := t.TempDir()
	script = func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Cleanup(func() {})
	return dir, script
}

func write(t *testing.T, dir string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "testudo"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPhasesOfTheStack(t *testing.T) {
	if !Available() {
		t.Fatal("built with the pam tag and still unavailable")
	}
	dir, script := stack(t)
	// The password arrives on the script's standard input.
	check := script("check", `read -r pw; [ "$PAM_USER" = alice ] && [ "$pw" = "correct horse" ]`)
	account := script("account", `[ ! -e "`+dir+`/locked" ]`)
	session := script("session", `echo "$PAM_TYPE $PAM_USER $PAM_RHOST" >> "`+dir+`/sessions"`)
	write(t, dir,
		"auth     required pam_exec.so expose_authtok quiet "+check,
		"account  required pam_exec.so quiet "+account,
		"session  required pam_exec.so quiet "+session,
	)
	req := Request{ConfDir: dir, User: "alice", Password: "correct horse", RemoteHost: "192.0.2.7"}

	res, err := Authenticate(req)
	if err != nil || res.User != "alice" {
		t.Fatalf("right password: %+v %v", res, err)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "sessions"))
	if string(log) != "open_session alice 192.0.2.7\nclose_session alice 192.0.2.7\n" {
		t.Errorf("session phase: %q", log)
	}

	for name, bad := range map[string]Request{
		"wrong password": {ConfDir: dir, User: "alice", Password: "wrong"},
		"empty password": {ConfDir: dir, User: "alice"},
		"unknown user":   {ConfDir: dir, User: "mallory", Password: "correct horse"},
		"no user":        {ConfDir: dir, Password: "correct horse"},
	} {
		if _, err := Authenticate(bad); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The right password is not enough when the account phase says no.
	os.WriteFile(filepath.Join(dir, "locked"), nil, 0o600)
	var acct *AccountError
	if _, err := Authenticate(req); !errors.As(err, &acct) {
		t.Errorf("locked account with the right password: %v", err)
	}
	os.Remove(filepath.Join(dir, "locked"))
	if _, err := Authenticate(req); err != nil {
		t.Errorf("after unlocking: %v", err)
	}

	// A service that does not exist denies; it does not fall through to
	// something permissive.
	if _, err := Authenticate(Request{ConfDir: dir, Service: "nothing-here", User: "alice", Password: "correct horse"}); err == nil {
		t.Error("a missing service file let someone in")
	}
}

// twoPrompts is a PAM module that asks two hidden questions, the way a
// stack with a password and a one-time code does, and accepts one pair.
const twoPrompts = `
#include <stdlib.h>
#include <string.h>
struct pam_message { int msg_style; const char *msg; };
struct pam_response { char *resp; int resp_retcode; };
struct pam_conv { int (*conv)(int, const struct pam_message **, struct pam_response **, void *); void *appdata_ptr; };
typedef struct pam_handle pam_handle_t;
int pam_get_item(const pam_handle_t *, int, const void **);

static int ask(const struct pam_conv *c, const char *prompt, char **out) {
	struct pam_message m = { 1, prompt };
	const struct pam_message *mp = &m;
	struct pam_response *r = 0;
	int rc = c->conv(1, &mp, &r, c->appdata_ptr);
	if (rc != 0 || !r || !r->resp) return 7;
	*out = r->resp;
	free(r);
	return 0;
}

int pam_sm_authenticate(pam_handle_t *h, int flags, int argc, const char **argv) {
	const void *item = 0;
	if (pam_get_item(h, 5, &item) != 0 || !item) return 7;
	const struct pam_conv *c = item;
	char *pw = 0, *code = 0;
	if (ask(c, "Password: ", &pw) != 0) return 7;
	if (strcmp(pw, "correct horse") != 0) { free(pw); return 7; }
	free(pw);
	if (ask(c, "One-time code: ", &code) != 0) return 7;
	int ok = strcmp(code, "492039") == 0;
	free(code);
	return ok ? 0 : 7;
}
int pam_sm_setcred(pam_handle_t *h, int flags, int argc, const char **argv) { return 0; }
`

func TestSecondPromptIsTheCode(t *testing.T) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir, _ := stack(t)
	src, mod := filepath.Join(dir, "two.c"), filepath.Join(dir, "pam_two.so")
	os.WriteFile(src, []byte(twoPrompts), 0o600)
	if out, err := exec.Command(gcc, "-shared", "-fPIC", "-o", mod, src).CombinedOutput(); err != nil {
		t.Skipf("cannot build the test module: %v %s", err, out)
	}
	write(t, dir,
		"auth    required "+mod,
		"account required pam_permit.so",
		"session required pam_permit.so",
	)
	req := Request{ConfDir: dir, User: "alice", Password: "correct horse", Code: "492039"}
	if _, err := Authenticate(req); err != nil {
		t.Fatalf("password and code: %v", err)
	}
	// Without a code the caller learns that one is wanted, and only after
	// the password was right.
	req.Code = ""
	if _, err := Authenticate(req); !errors.Is(err, ErrNeedCode) {
		t.Errorf("right password, no code: %v", err)
	}
	req.Password = "wrong"
	if _, err := Authenticate(req); !errors.Is(err, ErrDenied) {
		t.Errorf("wrong password, no code: %v", err)
	}
	req.Password, req.Code = "correct horse", "000000"
	if _, err := Authenticate(req); !errors.Is(err, ErrDenied) {
		t.Errorf("right password, wrong code: %v", err)
	}
	// The password is not offered again as the code.
	req.Password, req.Code = "492039", ""
	if _, err := Authenticate(req); !errors.Is(err, ErrDenied) {
		t.Errorf("the code as the password: %v", err)
	}
}

func TestGroupsOfTheCurrentUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	groups := groupsOf(me.Username)
	if len(groups) == 0 {
		t.Errorf("no groups for %s", me.Username)
	}
	if groupsOf("no-such-user-here") != nil {
		t.Error("groups for a user that does not exist")
	}
}
