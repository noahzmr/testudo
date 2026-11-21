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
	// Without a running daemon the status is "stopped" (or "missing" when
	// it is not installed), never "running".
	if r := RunDaemon(DaemonRequest{Name: "conntrackd", Mode: DaemonStatus, RunDir: "/run/none"}); r.Output == "running" {
		t.Errorf("status of a daemon never started: %q", r.Output)
	}
}
