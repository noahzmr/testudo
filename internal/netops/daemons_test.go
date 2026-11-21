package netops

import (
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
