package firewall

import (
	"errors"
	"testing"

	"github.com/noahzmr/testudo/internal/netops"
)

func TestReplaceOwnedLeavesOtherOwnersAlone(t *testing.T) {
	be := &fakeBE{writes: true}
	m, path := openTemp(t, be, Options{})
	if err := m.AddRule(netops.FilterRule{Chain: "input", Action: "accept", Proto: "tcp", Port: 443}); err != nil {
		t.Fatal(err)
	}
	if err := m.AddRule(netops.FilterRule{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.2/32", Owner: "wg-peer:abc"}); err != nil {
		t.Fatal(err)
	}
	before, _ := be.applies()

	set := OwnedSet{
		Rules:       []netops.FilterRule{{Chain: "forward", Action: "accept", Proto: "tcp", Port: 8443, DstCIDR: "192.0.2.10"}},
		Forwards:    []netops.PortForward{{Proto: "tcp", WANPort: 443, LANIP: "192.0.2.10", LANPort: 8443}},
		Masquerades: []netops.Masquerade{{OutIface: "wan0", SrcCIDR: "10.0.0.0/8"}},
	}
	// A dry run changes nothing, in memory or in the kernel.
	if err := m.ReplaceOwned(OwnerModel, set, true); err != nil {
		t.Fatal(err)
	}
	if n, _ := be.applies(); n != before || len(m.Policy().Rules) != 2 {
		t.Fatalf("dry run applied something: applies %d->%d, %d rules", before, n, len(m.Policy().Rules))
	}

	if err := m.ReplaceOwned(OwnerModel, set, false); err != nil {
		t.Fatal(err)
	}
	p := m.Policy()
	if len(p.Rules) != 3 || p.Rules[0].Owner == OwnerModel || p.Rules[1].Owner != "wg-peer:abc" || p.Rules[2].Owner != OwnerModel {
		t.Fatalf("rules after replace: %+v", p.Rules)
	}
	if len(p.Forwards) != 1 || p.Forwards[0].Owner != OwnerModel || len(p.Masquerades) != 1 {
		t.Fatalf("nat after replace: %+v %+v", p.Forwards, p.Masquerades)
	}
	if got := loadFile(t, path); len(got.Rules) != 3 {
		t.Errorf("policy file has %d rules", len(got.Rules))
	}

	// The same set again is not re-applied.
	f1, n1 := be.applies()
	if err := m.ReplaceOwned(OwnerModel, set, false); err != nil {
		t.Fatal(err)
	}
	if f2, n2 := be.applies(); f2 != f1 || n2 != n1 {
		t.Errorf("unchanged set was re-applied: filter %d->%d nat %d->%d", f1, f2, n1, n2)
	}

	// An empty set removes the owner's rules and nothing else.
	if err := m.ReplaceOwned(OwnerModel, OwnedSet{}, false); err != nil {
		t.Fatal(err)
	}
	p = m.Policy()
	if len(p.Rules) != 2 || len(p.Forwards) != 0 || len(p.Masquerades) != 0 {
		t.Errorf("after clearing: %+v", p)
	}
	if r, f, x := m.CountOwned("wg-peer:abc"); r != 1 || f != 0 || x != 0 {
		t.Errorf("CountOwned = %d %d %d", r, f, x)
	}
}

func TestReplaceOwnedSetsDefaultsAndRespectsTheWriteGate(t *testing.T) {
	be := &fakeBE{writes: true}
	m, _ := openTemp(t, be, Options{})
	on := true
	bl := netops.DefaultBaseline()
	bl.AllowTCPPorts = []uint16{22, 443}
	if err := m.ReplaceOwned(OwnerModel, OwnedSet{Enforce: &on, Baseline: &bl}, false); err != nil {
		t.Fatal(err)
	}
	if p := m.Policy(); !p.Enforce || len(p.Baseline.AllowTCPPorts) != 2 {
		t.Errorf("defaults not applied: %+v", p)
	}
	// An invalid rule is refused in the dry run already.
	bad := OwnedSet{Rules: []netops.FilterRule{{Chain: "nowhere", Action: "accept"}}}
	if err := m.ReplaceOwned(OwnerModel, bad, true); err == nil {
		t.Error("invalid rule passed the dry run")
	}
	be.writes = false
	err := m.ReplaceOwned(OwnerModel, OwnedSet{Rules: []netops.FilterRule{{Chain: "input", Action: "drop", Proto: "tcp", Port: 23}}}, false)
	if !errors.Is(err, ErrWritesDisabled) {
		t.Errorf("write with the gate closed: %v", err)
	}
}
