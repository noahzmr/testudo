package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/config"
)

// controlSocketPath is where the daemon listens for the command line.
func controlSocketPath(storage string) string { return filepath.Join(storage, "control.sock") }

// control is a client of the daemon's control socket.
type control struct{ hc *http.Client }

func dialControl(storage string) (*control, error) {
	path := controlSocketPath(storage)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("testudo is not running here (no %s); users live in the configuration model, which the daemon serves: start it first", path)
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
	return &control{hc: &http.Client{Transport: tr, Timeout: 30 * time.Second}}, nil
}

// call sends a request and decodes a JSON answer into out (when not nil).
func (c *control) call(method, path string, body any, ifMatch int64, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://testudo"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if ifMatch > 0 {
		req.Header.Set("If-Match", fmt.Sprintf(`"%d"`, ifMatch))
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		var p struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &p) == nil && p.Message != "" {
			return errors.New(p.Message)
		}
		return fmt.Errorf("%s %s: %s", method, path, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// change makes a model change and confirms it: the command line has no
// one to click "confirm" later.
func (c *control) change(method, path string, body any, ifMatch int64, out any) error {
	if err := c.call(method, path, body, ifMatch, out); err != nil {
		return err
	}
	return c.call("POST", "/api/v1/apply/confirm", nil, 0, nil)
}

type userObj struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  int64    `json:"version"`
	Username string   `json:"username"`
	Source   string   `json:"source"`
	Roles    []string `json:"roles"`
	Disabled bool     `json:"disabled"`
	raw      map[string]any
}

func (c *control) users() ([]userObj, map[string]string, error) {
	var raw []map[string]any
	if err := c.call("GET", "/api/v1/users", nil, 0, &raw); err != nil {
		return nil, nil, err
	}
	var users []userObj
	for _, r := range raw {
		b, _ := json.Marshal(r)
		var u userObj
		_ = json.Unmarshal(b, &u)
		u.raw = r
		users = append(users, u)
	}
	var roles []struct{ ID, Name string }
	if err := c.call("GET", "/api/v1/roles", nil, 0, &roles); err != nil {
		return nil, nil, err
	}
	names := map[string]string{}
	for _, r := range roles {
		names[r.ID] = r.Name
	}
	return users, names, nil
}

func (c *control) roleID(name string) (string, error) {
	var roles []struct{ ID, Name string }
	if err := c.call("GET", "/api/v1/roles", nil, 0, &roles); err != nil {
		return "", err
	}
	var have []string
	for _, r := range roles {
		if r.Name == name {
			return r.ID, nil
		}
		have = append(have, r.Name)
	}
	return "", fmt.Errorf("no role %q (the model has: %s)", name, strings.Join(have, ", "))
}

func (c *control) find(name string) (*userObj, error) {
	users, _, err := c.users()
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].Username == name && users[i].Source == "local" {
			return &users[i], nil
		}
	}
	return nil, fmt.Errorf("no local user %q", name)
}

// legacyRoleNames keeps the old role names of this command working.
var legacyRoleNames = map[string]string{"viewer": "read-only"}

// cmdUser manages the model's local users through the running daemon.
func cmdUser(args []string) error {
	const usage = "usage: testudo user <list | add <name> [--role R] | del <name> | role <name> <role> | disable <name> | enable <name> | passwd [name] | totp <enroll|disable> <name>> [--storage DIR]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	cfg := config.Default()
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	storage := fs.String("storage", cfg.StorageDir, "storage directory of the running daemon")
	role := fs.String("role", "read-only", "add: the role of the new user")
	sub := args[0]
	rest := parseInterleaved(fs, args[1:])
	if r, ok := legacyRoleNames[*role]; ok {
		*role = r
	}
	c, err := dialControl(*storage)
	if err != nil {
		return err
	}
	need := func(n int) error {
		if len(rest) < n {
			return errors.New(usage)
		}
		return nil
	}
	switch sub {
	case "list":
		users, roles, err := c.users()
		if err != nil {
			return err
		}
		sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
		fmt.Printf("  %-20s %-7s %-24s %s\n", "NAME", "SOURCE", "ROLES", "STATE")
		for _, u := range users {
			var rn []string
			for _, r := range u.Roles {
				rn = append(rn, roles[r])
			}
			state := "enabled"
			if u.Disabled {
				state = "DISABLED"
			}
			fmt.Printf("  %-20s %-7s %-24s %s\n", u.Username, u.Source, strings.Join(rn, ","), state)
		}
		return nil
	case "add":
		if err := need(1); err != nil {
			return err
		}
		rid, err := c.roleID(*role)
		if err != nil {
			return err
		}
		pw, err := promptPassword("Password for " + rest[0])
		if err != nil {
			return err
		}
		var created userObj
		if err := c.change("POST", "/api/v1/users", map[string]any{"name": rest[0], "username": rest[0], "source": "local",
			"roles": []string{rid}}, 0, &created); err != nil {
			return err
		}
		return c.call("POST", "/api/v1/users/"+created.ID+"/password", map[string]string{"password": pw}, 0, nil)
	case "passwd":
		name := "testudo"
		if len(rest) > 0 {
			name = rest[0]
		}
		u, err := c.find(name)
		if err != nil {
			// The historical contract: an unknown name becomes an administrator.
			rid, rerr := c.roleID("admin")
			if rerr != nil {
				return err
			}
			var created userObj
			if err := c.change("POST", "/api/v1/users", map[string]any{"name": name, "username": name, "source": "local",
				"roles": []string{rid}}, 0, &created); err != nil {
				return err
			}
			u = &created
		}
		pw, err := promptPassword("New password for " + name)
		if err != nil {
			return err
		}
		return c.call("POST", "/api/v1/users/"+u.ID+"/password", map[string]string{"password": pw}, 0, nil)
	case "del":
		if err := need(1); err != nil {
			return err
		}
		u, err := c.find(rest[0])
		if err != nil {
			return err
		}
		return c.change("DELETE", "/api/v1/users/"+u.ID, nil, u.Version, nil)
	case "role", "disable", "enable":
		n := 1
		if sub == "role" {
			n = 2
		}
		if err := need(n); err != nil {
			return err
		}
		u, err := c.find(rest[0])
		if err != nil {
			return err
		}
		obj := u.raw
		switch sub {
		case "role":
			r := rest[1]
			if alias, ok := legacyRoleNames[r]; ok {
				r = alias
			}
			rid, err := c.roleID(r)
			if err != nil {
				return err
			}
			obj["roles"] = []string{rid}
		default:
			obj["disabled"] = sub == "disable"
		}
		return c.change("PUT", "/api/v1/users/"+u.ID, obj, u.Version, nil)
	case "totp":
		if err := need(2); err != nil {
			return err
		}
		u, err := c.find(rest[1])
		if err != nil {
			return err
		}
		switch rest[0] {
		case "enroll":
			var out struct {
				OTPAuth string `json:"otpauth"`
			}
			if err := c.call("POST", "/api/v1/users/"+u.ID+"/totp", nil, 0, &out); err != nil {
				return err
			}
			fmt.Println("Add this to the authenticator app; it is shown once:")
			fmt.Println(out.OTPAuth)
			return nil
		case "disable":
			return c.call("DELETE", "/api/v1/users/"+u.ID+"/totp", nil, 0, nil)
		}
		return errors.New(usage)
	}
	return fmt.Errorf("unknown user subcommand %q\n%s", sub, usage)
}

var stdinReader = bufio.NewReader(os.Stdin)

// parseInterleaved parses flags wherever they are among the positional
// arguments ("user passwd olivia --storage /x") and returns the positional
// ones.
func parseInterleaved(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}
