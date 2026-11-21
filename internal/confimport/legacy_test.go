package confimport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testutil/golden"
)

const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func sample() Legacy {
	return Legacy{
		Hostname: "fw1", NodeAddress: "10.0.0.1",
		Firewall: &firewall.Policy{
			Enforce:  true,
			Baseline: netops.FilterBaseline{AllowEstablished: true, DropInvalid: true, AllowLoopback: true, AllowICMP: true, AllowTCPPorts: []uint16{22, 8080}},
			Rules: []netops.FilterRule{
				{Chain: "input", Action: "accept", Proto: "tcp", Port: 443, Comment: "web"},
				{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.2/32", DstCIDR: "192.168.1.0/24", CtState: "new", Owner: "wg-peer:abc"},
				{Chain: "forward", Action: "drop", InIface: "wg0", SrcCIDR: "10.8.0.2/32", Log: true, Owner: "wg-peer:abc"},
				{Chain: "input", Action: "reject", Proto: "tcp", Port: 1000, PortEnd: 2000, RateLimit: "10/minute"},
				{Chain: "input", Action: "drop", Proto: "tcp", Port: 22, RateLimit: "5/minute", RateOver: true},
				{Chain: "input", Action: "log", Proto: "udp", Port: 53},
				{Chain: "output", Action: "reject", Proto: "udp", Port: 53, DstCIDR: "2001:db8::1"},
			},
			Forwards:    []netops.PortForward{{Proto: "tcp", WANPort: 443, LANIP: "192.168.1.10", InIface: "eth0", Comment: "nas"}},
			Masquerades: []netops.Masquerade{{OutIface: "eth0", SrcCIDR: "10.8.0.0/24"}},
		},
		Tunnels: []Tunnel{{
			WGDeviceInfo: netops.WGDeviceInfo{Name: "wg0", PublicKey: key, ListenPort: 51820, Peers: []netops.WGPeerInfo{
				{PublicKey: key, AllowedIPs: []string{"10.8.0.2/32"}, PersistentKeepalive: 25 * time.Second},
				{PublicKey: key, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, Endpoint: "198.51.100.7:51820"},
				{PublicKey: key},
			}},
			Addresses: []string{"10.8.0.1/24"}, PeerNames: map[string]string{},
		}, {WGDeviceInfo: netops.WGDeviceInfo{Name: "wg1", PublicKey: key}}},
	}
}

func fakeIDs() func() string {
	n := 0
	return func() string { n++; return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
}

func TestTranslateProducesAModelTheStoreAccepts(t *testing.T) {
	res := Translate(sample(), fakeIDs())

	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Commit(context.Background(), "system:import", "import", res.Ops); err != nil {
		t.Fatalf("the store rejects the import: %v", err)
	}
	st := store.Current()
	count := func(k model.Kind) int { return len(st.List(k)) }
	for kind, want := range map[model.Kind]int{
		model.KindSite: 1, model.KindClusterNode: 1, model.KindRole: 0, model.KindUser: 0,
		model.KindFirewallPolicy: 1, model.KindFilterRule: 3, model.KindNATRule: 2,
		model.KindZone: 2, model.KindInterface: 2, model.KindWGTunnel: 1, model.KindWGPeer: 2,
	} {
		if got := count(kind); got != want {
			t.Errorf("%s: %d objects, want %d", kind, got, want)
		}
	}

	// What became model objects leaves the old policy; what did not, stays
	// there and keeps working: the two WireGuard rules, the rate-over rule
	// and the log-only rule.
	rest := res.Remaining
	if rest == nil || len(rest.Rules) != 4 || len(rest.Forwards) != 0 || len(rest.Masquerades) != 0 || !rest.Enforce {
		t.Errorf("remaining policy: %+v", rest)
	}
	for _, r := range rest.Rules {
		if r.Owner != "wg-peer:abc" && !r.RateOver && r.Action != "log" {
			t.Errorf("a translated rule stayed in the old policy: %+v", r)
		}
	}

	// Nothing secret crosses over.
	all, _ := json.Marshal(res.Ops)
	for _, secret := range []string{"secret-hash", "other-hash", "JBSWY3DPEHPK3PXP"} {
		if bytes.Contains(all, []byte(secret)) {
			t.Errorf("import carries %q", secret)
		}
	}
	// Everything that was not carried over is named.
	notes := strings.Join(res.Notes, "\n")
	for _, want := range []string{"rule 5", "over the rate", "rule 6", "action \"log\"",
		"wg1", "no allowed IPs", "private key stays"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes do not mention %q:\n%s", want, notes)
		}
	}

	var buf bytes.Buffer
	for _, op := range res.Ops {
		var pretty bytes.Buffer
		json.Indent(&pretty, op.Object, "", "  ")
		fmt.Fprintf(&buf, "## %s\n%s\n", op.Kind, pretty.String())
	}
	buf.WriteString("## notes\n" + notes + "\n")
	golden.Assert(t, "import.golden", buf.Bytes())
}

func TestTranslateEmptyInputStillGivesAClusterOfOne(t *testing.T) {
	res := Translate(Legacy{}, nil)
	if len(res.Ops) != 2 || res.Ops[0].Kind != model.KindSite || res.Ops[1].Kind != model.KindClusterNode {
		t.Fatalf("ops: %+v", res.Ops)
	}
	store, _ := confstore.Open(t.TempDir())
	defer store.Close()
	if _, err := store.Commit(context.Background(), "x", "", res.Ops); err != nil {
		t.Fatal(err)
	}
}

// TestTranslateIntoAModel: a policy file left from before the model goes
// into a model that has its node, an interface with a zone and a policy:
// those are used, nothing is created twice, and the old WireGuard
// provisioner's rules come along.
func TestTranslateIntoAModel(t *testing.T) {
	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	mk := func(e model.Entity) string {
		obj, err := store.Create(ctx, "a", e)
		if err != nil {
			t.Fatal(err)
		}
		return obj.GetMeta().ID
	}
	site := mk(&model.Site{Meta: model.Meta{Name: "hq"}})
	node := mk(&model.ClusterNode{Meta: model.Meta{Name: "fw1"}, Site: model.Ref[model.Site]{ID: site}, Hostname: "fw1", Address: "10.0.0.1"})
	wan := mk(&model.Zone{Meta: model.Meta{Name: "wan"}, DefaultAction: "drop"})
	mk(&model.Interface{Meta: model.Meta{Name: "eth0", Scope: model.NodeScope(node)}, Device: "eth0", Zone: model.Ref[model.Zone]{ID: wan}, Enabled: true})
	mk(&model.FirewallPolicy{Meta: model.Meta{Name: "default"}, DefaultDeny: true})
	mk(&model.FilterRule{Meta: model.Meta{Name: "rule-001"}, Enabled: true, Action: "accept", Direction: "in", Protocol: "tcp", Ports: []string{"22"}})

	res := TranslateFirewall(Into{State: store.Current(), NodeID: node}, sample().Firewall, nil)
	if _, err := store.Commit(ctx, "system", "import", res.Ops); err != nil {
		t.Fatalf("the store rejects the translation: %v", err)
	}
	st := store.Current()
	if n := len(st.List(model.KindFirewallPolicy)); n != 1 {
		t.Errorf("policies: %d", n)
	}
	rules := st.List(model.KindFilterRule)
	var wg, names int
	for _, e := range rules {
		r := e.(*model.FilterRule)
		if r.Owner == "wg-peer:abc" {
			wg++
		}
		if r.Name == "rule-001" {
			names++
		}
	}
	if wg != 2 || names != 1 {
		t.Errorf("the provisioner's rules: %d (want 2); rule-001 named %d times", wg, names)
	}
	// The forward on eth0 is in the existing wan zone.
	for _, e := range st.List(model.KindNATRule) {
		if r := e.(*model.NATRule); r.Type == "dnat" && r.Zone.ID != wan {
			t.Errorf("the forward on eth0 is not in the model's wan zone: %v", r.Zone.ID)
		}
	}
	notes := strings.Join(res.Notes, "\n")
	for _, want := range []string{"firewall policy already", "over the rate", "stays behind"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
}
