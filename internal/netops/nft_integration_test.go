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

	"github.com/google/nftables"
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
	cmd := exec.Command("unshare", "-Urn", exe, "-test.run", "^"+name+"$", "-test.v")
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

func TestIntegrationApplyFilterTable(t *testing.T) {
	if runInNamespace(t, "TestIntegrationApplyFilterTable") {
		return
	}
	w := &Writer{AllowWrites: true}
	spec := FilterTableSpec{
		Enforce:  true,
		Baseline: DefaultBaseline(),
		Rules: []FilterRule{
			{Chain: "input", Action: "accept", Proto: "tcp", Port: 8080, Comment: "web ui"},
			{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.2/32", DstCIDR: "192.168.1.0/24", CtState: "new", Owner: "wg-peer:abc"},
			{Chain: "forward", Action: "drop", InIface: "wg0", SrcCIDR: "10.8.0.2/32", Log: true, Owner: "wg-peer:abc"},
			{Chain: "input", Action: "reject", Proto: "tcp", Port: 1000, PortEnd: 2000},
			{Chain: "input", Action: "drop", SrcCIDR: "2001:db8::/32"},
			{Chain: "input", Action: "drop", Proto: "tcp", Port: 22, CtState: "new", RateLimit: "5/minute", RateOver: true},
			{Chain: "output", Action: "reject", Proto: "udp", Port: 53, DstCIDR: "9.9.9.9"},
		},
	}
	if err := w.ApplyFilterTable(spec); err != nil {
		t.Fatalf("apply: %v", err)
	}
	assertFilterState(t, w, spec)

	// Re-applying the same spec is idempotent (same ids, same order).
	if err := w.ApplyFilterTable(spec); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	assertFilterState(t, w, spec)

	// Flipping enforce off changes only the policies; a removed rule is gone.
	spec.Enforce = false
	spec.Rules = spec.Rules[:3]
	if err := w.ApplyFilterTable(spec); err != nil {
		t.Fatalf("apply non-enforce: %v", err)
	}
	st := assertFilterState(t, w, spec)
	if st.Policies["input"] != "accept" || st.Policies["forward"] != "accept" {
		t.Fatalf("policies after enforce off: %v", st.Policies)
	}

	// The generic decoder renders our rules sensibly (ranges, ct, log...).
	rules, err := w.ListFirewallRules()
	if err != nil {
		t.Fatal(err)
	}
	seenOurs := 0
	for _, r := range rules {
		if r.Table == filterTableName {
			seenOurs++
			if !r.HasCounter {
				t.Fatalf("managed rule without counter: %+v", r)
			}
		}
	}
	if want := len(RenderFilterRules(spec)); seenOurs != want {
		t.Fatalf("ListFirewallRules saw %d managed rules, want %d", seenOurs, want)
	}
}

// assertFilterState checks the live table matches spec: exists, policies,
// per-chain id order, counters present.
func assertFilterState(t *testing.T, w *Writer, spec FilterTableSpec) FilterTableState {
	t.Helper()
	st, err := w.FilterTableState()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if !st.Exists {
		t.Fatal("table missing after apply")
	}
	for chain, pol := range ChainPolicies(spec) {
		if st.Policies[chain] != pol {
			t.Fatalf("chain %s policy = %q, want %q", chain, st.Policies[chain], pol)
		}
	}
	want := map[string][]string{}
	for _, r := range RenderFilterRules(spec) {
		want[r.Chain] = append(want[r.Chain], r.ID())
	}
	got := map[string][]string{}
	for _, r := range st.Rules {
		if r.ID == "" {
			t.Fatalf("live rule without managed id: %+v", r)
		}
		if !r.HasCounter {
			t.Fatalf("live rule without counter: %+v", r)
		}
		got[r.Chain] = append(got[r.Chain], r.ID)
	}
	for _, chain := range []string{"input", "forward", "output"} {
		if strings.Join(want[chain], ",") != strings.Join(got[chain], ",") {
			t.Fatalf("chain %s ids\n got %v\nwant %v", chain, got[chain], want[chain])
		}
	}
	return st
}

func TestIntegrationApplyNATTable(t *testing.T) {
	if runInNamespace(t, "TestIntegrationApplyNATTable") {
		return
	}
	w := &Writer{AllowWrites: true}

	// Plant a legacy testudo_masq table (pre-policy builds) so we can prove
	// the apply imports-then-removes path has something to find.
	plantLegacyMasq(t)
	before, err := w.NATTableState()
	if err != nil {
		t.Fatal(err)
	}
	if !before.LegacyMasqTable || len(before.Masquerades) != 1 || !before.Masquerades[0].Legacy {
		t.Fatalf("legacy masq not detected: %+v", before)
	}
	if before.Masquerades[0].SrcCIDR != "10.9.0.0/24" || before.Masquerades[0].OutIface != "eth9" {
		t.Fatalf("legacy masq decode: %+v", before.Masquerades[0])
	}

	spec := NATSpec{
		Forwards: []PortForward{
			{Proto: "tcp", WANPort: 443, LANIP: "192.168.1.10", LANPort: 8443, Comment: "reverse proxy"},
			{Proto: "udp", WANPort: 51820, LANIP: "192.168.1.20", InIface: "eth0"},
		},
		Masquerades: []Masquerade{
			{OutIface: "eth0", SrcCIDR: "10.8.0.0/24", Owner: "wg-peer:abc"},
		},
	}
	if err := w.ApplyNATTable(spec); err != nil {
		t.Fatalf("apply nat: %v", err)
	}
	st, err := w.NATTableState()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Exists || st.LegacyMasqTable {
		t.Fatalf("state after apply: exists=%v legacy=%v", st.Exists, st.LegacyMasqTable)
	}
	if len(st.Forwards) != 2 || len(st.Masquerades) != 1 {
		t.Fatalf("counts: %d forwards, %d masqs", len(st.Forwards), len(st.Masquerades))
	}
	for i, f := range st.Forwards {
		want := spec.Forwards[i].Normalize()
		if f.ID != want.ID() || f.Legacy {
			t.Fatalf("forward %d id=%s legacy=%v want %s", i, f.ID, f.Legacy, want.ID())
		}
		if f.Proto != want.Proto || f.WANPort != want.WANPort || f.LANIP != want.LANIP || f.LANPort != want.LANPort || f.InIface != want.InIface {
			t.Fatalf("forward %d decoded %+v want %+v", i, f.PortForward, want)
		}
		if !f.HasCounter {
			t.Fatalf("forward %d has no counter", i)
		}
	}
	m := st.Masquerades[0]
	if m.ID != spec.Masquerades[0].ID() || m.Legacy || m.OutIface != "eth0" || m.SrcCIDR != "10.8.0.0/24" {
		t.Fatalf("masq decoded %+v", m)
	}

	// Empty spec leaves an empty (but present) table.
	if err := w.ApplyNATTable(NATSpec{}); err != nil {
		t.Fatal(err)
	}
	st, _ = w.NATTableState()
	if !st.Exists || len(st.Forwards) != 0 || len(st.Masquerades) != 0 {
		t.Fatalf("empty apply: %+v", st)
	}
}

// plantLegacyMasq writes a masquerade rule the way pre-policy Testudo did: its
// own ip-family table with a pipe-delimited UserData key and no counter.
func plantLegacyMasq(t *testing.T) {
	t.Helper()
	conn, err := nftConn()
	if err != nil {
		t.Fatal(err)
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: legacyMasqTableName})
	chain := conn.AddChain(&nftables.Chain{
		Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
	})
	ex, err := buildMasqueradeExprs(Masquerade{OutIface: "eth9", SrcCIDR: "10.9.0.0/24"}.Normalize())
	if err != nil {
		t.Fatal(err)
	}
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: ex, UserData: []byte("masq|10.9.0.0/24|eth9")})
	if err := conn.Flush(); err != nil {
		t.Fatalf("plant legacy masq: %v", err)
	}
}

func TestIntegrationLegacyFilterImport(t *testing.T) {
	if runInNamespace(t, "TestIntegrationLegacyFilterImport") {
		return
	}
	// Plant a legacy-format filter table: default-accept chain, pipe key.
	conn, err := nftConn()
	if err != nil {
		t.Fatal(err)
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: filterTableName})
	chain := conn.AddChain(&nftables.Chain{
		Name: "forward", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
	})
	legacy := FilterRule{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.2/32", DstCIDR: "192.168.1.0/24"}
	ex, err := buildFilterExprs(legacy, "")
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Join([]string{"forward", "accept", "", "0", "wg0", "", "10.8.0.2/32", "192.168.1.0/24"}, "|")
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: ex, UserData: []byte(key)})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	w := &Writer{AllowWrites: true}
	st, err := w.FilterTableState()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Exists || len(st.Rules) != 1 || st.Rules[0].Legacy == nil || st.Rules[0].ID != "" {
		t.Fatalf("legacy state: %+v", st)
	}
	if got := st.Rules[0].Legacy; got.InIface != "wg0" || got.DstCIDR != "192.168.1.0/24" || got.Chain != "forward" {
		t.Fatalf("legacy decode: %+v", got)
	}
	// A base chain created without an explicit policy reports the kernel
	// default (accept) - never drop.
	if st.Policies["forward"] == "drop" {
		t.Fatalf("legacy chain must not report drop, got %v", st.Policies)
	}
	// Applying a spec replaces the legacy table wholesale.
	if err := w.ApplyFilterTable(FilterTableSpec{Baseline: DefaultBaseline(), Rules: []FilterRule{legacy}}); err != nil {
		t.Fatal(err)
	}
	st, _ = w.FilterTableState()
	for _, r := range st.Rules {
		if r.Legacy != nil || r.ID == "" {
			t.Fatalf("legacy rule survived apply: %+v", r)
		}
	}
}

// TestIntegrationHelperQueryPath drives the privileged reads the way the
// unprivileged engine does: through a helper-backed Writer whose queries
// cross a real privsep SEQPACKET connection to an in-process "helper" that
// executes them directly. A large rule set makes the responses span several
// frames, exercising the chunked transport end to end.
func TestIntegrationHelperQueryPath(t *testing.T) {
	if runInNamespace(t, "TestIntegrationHelperQueryPath") {
		return
	}
	direct := &Writer{AllowWrites: true}

	// Enough rules that the rule dump is well over one 64 KiB frame.
	spec := FilterTableSpec{Enforce: true, Baseline: DefaultBaseline()}
	for i := 0; i < 400; i++ {
		spec.Rules = append(spec.Rules, FilterRule{
			Chain: "forward", Action: "accept", InIface: "wg0",
			SrcCIDR: fmt.Sprintf("10.%d.%d.0/24", i/250, i%250), DstCIDR: "192.168.0.0/16",
			Proto: "tcp", Port: uint16(1000 + i), Comment: fmt.Sprintf("bulk rule %d", i),
		})
	}
	if err := direct.ApplyFilterTable(spec); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := direct.ApplyNATTable(NATSpec{
		Forwards:    []PortForward{{Proto: "tcp", WANPort: 443, LANIP: "192.168.1.10"}},
		Masquerades: []Masquerade{{OutIface: "eth0", SrcCIDR: "10.8.0.0/24"}},
	}); err != nil {
		t.Fatalf("apply nat: %v", err)
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

	// Every privileged read returns the same thing through the helper as it
	// does directly.
	wantState, _ := direct.FilterTableState()
	gotState, err := helperBacked.FilterTableState()
	if err != nil {
		t.Fatalf("FilterTableState via helper: %v", err)
	}
	if len(gotState.Rules) != len(wantState.Rules) || len(gotState.Rules) < 400 || !reflect.DeepEqual(gotState.Policies, wantState.Policies) {
		t.Fatalf("filter state mismatch: %d vs %d rules, policies %v vs %v", len(gotState.Rules), len(wantState.Rules), gotState.Policies, wantState.Policies)
	}
	for i := range gotState.Rules {
		if gotState.Rules[i].ID != wantState.Rules[i].ID || gotState.Rules[i].Chain != wantState.Rules[i].Chain {
			t.Fatalf("rule %d differs via helper: %+v vs %+v", i, gotState.Rules[i], wantState.Rules[i])
		}
	}
	wantNAT, _ := direct.NATTableState()
	gotNAT, err := helperBacked.NATTableState()
	if err != nil || !reflect.DeepEqual(gotNAT, wantNAT) {
		t.Fatalf("nat state via helper: %v\n got %+v\nwant %+v", err, gotNAT, wantNAT)
	}
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
	// Mutations through the same connection still work after large reads.
	if err := helperBacked.ApplyFilterTable(FilterTableSpec{Baseline: DefaultBaseline()}); err != nil {
		t.Fatalf("apply via helper: %v", err)
	}
	after, _ := helperBacked.FilterTableState()
	if len(after.Rules) != len(RenderFilterRules(FilterTableSpec{Baseline: DefaultBaseline()})) {
		t.Fatalf("state after helper apply: %d rules", len(after.Rules))
	}
}
