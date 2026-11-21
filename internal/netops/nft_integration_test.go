//go:build linux

package netops

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/noahzmr/testudo/internal/privsep"
)

// nsEnv marks the re-executed test process that runs inside a fresh user +
// network namespace (unshare -Urn). Inside it we hold CAP_NET_ADMIN over a
// private netns, so nftables netlink works without root and nothing we do can
// touch the host's ruleset.
const nsEnv = "TESTUDO_NFT_NS"

// runInNamespace re-executes the current test binary under unshare -Urn with
// only the named test selected. Skips (not fails) when namespaces are
// unavailable (containers, hardened kernels, missing unshare).
func runInNamespace(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv(nsEnv) != "" {
		return false // already inside
	}
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate test binary: %v", err)
	}
	// Root needs only a network namespace; a user namespace would leave it
	// without rights over a test binary another user owns.
	flags := "-Urn"
	if os.Geteuid() == 0 {
		flags = "-n"
	}
	cmd := exec.Command("unshare", flags, exe, "-test.run", "^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), nsEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var execErr *exec.Error
		s := string(out)
		if errors.As(err, &execErr) || strings.Contains(s, "unshare failed") ||
			strings.Contains(s, "Operation not permitted") || strings.Contains(s, "No such file") {
			t.Skipf("user/net namespace unavailable: %v\n%s", err, s)
		}
		t.Fatalf("namespaced test failed: %v\n%s", err, s)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("namespaced test did not report PASS:\n%s", out)
	}
	return true
}

// TestIntegrationHelperQueryPath: every privileged read returns the same
// through the helper as it does in-process, including a rule dump larger
// than one privsep frame, and a load still works on the same connection
// after large reads.
func TestIntegrationHelperQueryPath(t *testing.T) {
	if runInNamespace(t, "TestIntegrationHelperQueryPath") {
		return
	}
	direct := &Writer{AllowWrites: true}
	if !direct.NftAvailable() {
		t.Skip("nft cannot load rulesets here")
	}

	// Enough rules that the rule dump is well over one 64 KiB frame.
	var b strings.Builder
	b.WriteString("table inet testudo {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "\t\tiifname \"wg0\" ip saddr 10.%d.%d.0/24 ip daddr 192.168.0.0/16 tcp dport %d counter accept comment \"bulk rule %d\"\n",
			i/250, i%250, 1000+i, i)
	}
	b.WriteString("\t}\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	b.WriteString("\t\ttcp dport 443 dnat ip to 192.168.1.10\n\t}\n}\n")
	if err := direct.NftApply(b.String()); err != nil {
		t.Fatalf("load: %v", err)
	}

	// In-process helper: a privsep server over a socketpair whose handler
	// runs the direct Writer, exactly like cmd/testudo's runHelper.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(fd int, name string) *net.UnixConn {
		f := os.NewFile(uintptr(fd), name)
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	clientConn, serverConn := mk(fds[0], "engine"), mk(fds[1], "helper")
	srv := privsep.NewServer(serverConn, func(op byte, body []byte) ([]byte, int, error) {
		o, err := DecodeOp(body)
		if err != nil {
			return nil, -1, err
		}
		switch op {
		case privsep.OpMutate:
			return nil, -1, direct.ApplyOp(o)
		case privsep.OpQuery:
			resp, err := direct.QueryOp(o)
			return resp, -1, err
		}
		return nil, -1, fmt.Errorf("unexpected op %#x", op)
	})
	go func() { _ = srv.Serve(t.Context()) }()
	client := privsep.NewClient(clientConn)
	defer client.Close()
	helperBacked := NewHelperWriter(true, client)

	wantRules, _ := direct.ListFirewallRules()
	gotRules, err := helperBacked.ListFirewallRules()
	if err != nil || len(gotRules) != len(wantRules) || len(gotRules) < 400 {
		t.Fatalf("firewall rules via helper: err=%v got %d want %d", err, len(gotRules), len(wantRules))
	}
	if b, _ := json.Marshal(gotRules); len(b) <= privsep.MaxFrame {
		t.Fatalf("rule dump is %d bytes - too small to exercise chunking", len(b))
	}
	wantSum, _ := direct.ListFirewall()
	gotSum, err := helperBacked.ListFirewall()
	if err != nil || !reflect.DeepEqual(gotSum, wantSum) {
		t.Fatalf("firewall summary via helper: %v", err)
	}
	// Conntrack: an empty namespace has no flows, but the query must round
	// trip (and honour a filter) rather than fail.
	ct, err := helperBacked.ListConntrackQuery(ConntrackQuery{SrcIPs: []string{"10.8.0.2"}, DstCIDR: "192.168.1.0/24", Limit: 10})
	if err != nil {
		t.Fatalf("conntrack via helper: %v", err)
	}
	if ct.Total != 0 || len(ct.Flows) != 0 {
		t.Fatalf("unexpected flows in a fresh namespace: %+v", ct)
	}
	if _, err := helperBacked.ListConntrackQuery(ConntrackQuery{DstCIDR: "not-an-address"}); err == nil {
		t.Fatal("bad filter accepted")
	}
	// WireGuard: no device in the namespace; the read must still succeed and
	// come back empty (the collector reports "no device", not "unprivileged").
	devs, err := helperBacked.ListWGDevices()
	if err != nil && !strings.Contains(err.Error(), "not supported") && !strings.Contains(err.Error(), "no such") {
		t.Fatalf("wg devices via helper: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("unexpected wg devices: %+v", devs)
	}
	// A load through the same connection still works after large reads.
	if err := helperBacked.NftApply("delete table inet testudo\n"); err != nil {
		t.Fatalf("load via helper: %v", err)
	}
	after, _ := helperBacked.ListFirewallRules()
	if len(after) >= len(gotRules) {
		t.Fatalf("rules after the helper's load: %d", len(after))
	}
}
