package netops

import (
	"errors"
	"strings"
	"testing"
)

// TestDaemonRequestsAreChecked: the privileged side runs only the daemons
// it knows, with their own configuration file name, from clean paths.
func TestDaemonRequestsAreChecked(t *testing.T) {
	for _, tc := range []struct {
		req  DaemonRequest
		want string
	}{
		{DaemonRequest{Name: "sshd", Mode: DaemonEnsure, ConfigFile: "/x/sshd_config", RunDir: "/run/x"}, "unknown daemon"},
		{DaemonRequest{Name: "keepalived", Mode: "explode", ConfigFile: "/x/keepalived.conf", RunDir: "/run/x"}, "unknown mode"},
	} {
		if r := RunDaemon(tc.req); !strings.Contains(r.Error, tc.want) {
			t.Errorf("%+v: %q, want %q", tc.req, r.Error, tc.want)
		}
	}
	spec := daemonSpecs["keepalived"]
	for _, req := range []DaemonRequest{
		{Name: "keepalived", ConfigFile: "/x/other.conf", RunDir: "/run/x"},
		{Name: "keepalived", ConfigFile: "/x/../etc/keepalived.conf", RunDir: "/run/x"},
		{Name: "keepalived", ConfigFile: "relative/keepalived.conf", RunDir: "/run/x"},
		{Name: "keepalived", ConfigFile: "/x/keepalived.conf", RunDir: "/run/../x"},
	} {
		if err := startDaemon(req, spec, "/bin/true"); err == nil || !strings.Contains(err.Error(), "bad configuration") {
			t.Errorf("%+v was accepted: %v", req, err)
		}
	}
	// Options come from the daemon's own list.
	bad := DaemonRequest{Name: "chronyd", ConfigFile: "/x/chrony.conf", RunDir: t.TempDir(), Options: []string{"-q"}}
	if err := startDaemon(bad, daemonSpecs["chronyd"], "/bin/true"); err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Errorf("an option chronyd does not list was accepted: %v", err)
	}
	if args := daemonSpecs["chronyd"].args(DaemonRequest{ConfigFile: "/x/chrony.conf", Options: []string{"serve-only"}}); args[len(args)-1] != "-x" {
		t.Errorf("serve-only: %v", args)
	}
	// Without a running daemon the status is "stopped" (or "missing" when
	// it is not installed), never "running".
	if r := RunDaemon(DaemonRequest{Name: "conntrackd", Mode: DaemonStatus, RunDir: "/run/none"}); r.Output == "running" {
		t.Errorf("status of a daemon never started: %q", r.Output)
	}
}

// TestDHCPClientRequestsAreChecked: a DHCP client runs for a valid
// interface name only, never takes a configuration file, and an interface
// name cannot smuggle in an option.
func TestDHCPClientRequestsAreChecked(t *testing.T) {
	spec := daemonSpecs["dhclient"]
	dir := t.TempDir()
	for _, req := range []DaemonRequest{
		{Name: "dhclient", Interface: "-sf/tmp/x", RunDir: dir},
		{Name: "dhclient", Interface: "eth0 eth1", RunDir: dir},
		{Name: "dhclient", Interface: "averyveryverylongname", RunDir: dir},
		{Name: "dhclient", Interface: "", RunDir: dir},
		{Name: "dhclient", Interface: "eth0", ConfigFile: "/x/dhclient.conf", RunDir: dir},
	} {
		if err := startDaemon(req, spec, "/bin/true"); err == nil || !strings.Contains(err.Error(), "bad interface") {
			t.Errorf("%+v was accepted: %v", req, err)
		}
	}
	// A daemon with one instance per node does not take an interface.
	if err := startDaemon(DaemonRequest{Name: "radvd", Interface: "eth0", ConfigFile: "/x/radvd.conf", RunDir: dir}, daemonSpecs["radvd"], "/bin/true"); err == nil {
		t.Error("radvd took an interface")
	}
	args := spec.args(DaemonRequest{Interface: "eth0"})
	if args[len(args)-1] != "eth0" || !strings.Contains(strings.Join(args, " "), "/var/lib/dhcp/dhclient-testudo-eth0.leases") {
		t.Errorf("dhclient arguments: %v", args)
	}
	// Two interfaces are two instances.
	if procKey(DaemonRequest{Name: "dhclient", Interface: "eth0", RunDir: dir}) == procKey(DaemonRequest{Name: "dhclient", Interface: "eth1", RunDir: dir}) {
		t.Error("one process key for two interfaces")
	}
}

// TestDHCPClientsRunAsUnitsUnderSystemd: where systemd runs the host and
// knows the template, a DHCP client is its unit; an interface name that a
// unit name cannot hold never reaches systemctl.
func TestDHCPClientsRunAsUnitsUnderSystemd(t *testing.T) {
	var calls []string
	active := map[string]bool{}
	oldHas, oldCtl := systemdHasUnit, systemctl
	t.Cleanup(func() { systemdHasUnit, systemctl = oldHas, oldCtl })
	systemdHasUnit = func(string) bool { return true }
	systemctl = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "start":
			active[args[1]] = true
		case "stop":
			delete(active, args[1])
		case "is-active":
			if active[args[1]] {
				return "active", nil
			}
			return "inactive", errors.New("exit status 3")
		}
		return "", nil
	}
	spec := daemonSpecs["dhclient"]
	run := func(mode DaemonMode, iface string) NftResult {
		return runUnit(DaemonRequest{Name: "dhclient", Mode: mode, Interface: iface}, spec, nil)
	}
	if r := run(DaemonEnsure, "eth0"); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := run(DaemonStatus, "eth0"); r.Output != "running" {
		t.Errorf("status: %+v", r)
	}
	run(DaemonStop, "eth0")
	if r := run(DaemonStatus, "eth0"); r.Output != "stopped" {
		t.Errorf("status after stop: %+v", r)
	}
	n := len(calls)
	if r := run(DaemonEnsure, "eth0;x"); r.Error == "" || len(calls) != n {
		t.Errorf("a bad interface name reached systemctl: %v", calls[n:])
	}
	if want := "start testudo-dhcp@eth0.service"; calls[0] != want {
		t.Errorf("first call %q, want %q", calls[0], want)
	}
}
