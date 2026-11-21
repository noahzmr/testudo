package ifstage

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

// fakeKernel holds devices and records what was asked of it.
type fakeKernel struct {
	links   map[string]*Link
	clients map[string]string // device -> running client
	made    map[string]bool   // links SyncLinks created
	calls   []string
	fail    string
}

func newKernel() *fakeKernel {
	return &fakeKernel{links: map[string]*Link{
		"eth0": {Up: true, MTU: 1500, Addresses: []string{"192.0.2.10/24", "fe80::1/64"}, Dynamic: []string{}},
		"eth1": {Up: false, MTU: 1500},
	}, clients: map[string]string{}}
}

func (k *fakeKernel) do(call string) error {
	k.calls = append(k.calls, call)
	if k.fail != "" && strings.HasPrefix(call, k.fail) {
		return fmt.Errorf("refused: %s", call)
	}
	return nil
}

func (k *fakeKernel) SetIfaceUp(n string) error {
	if err := k.do("up " + n); err != nil {
		return err
	}
	k.links[n].Up = true
	return nil
}

func (k *fakeKernel) SetIfaceDown(n string) error {
	if err := k.do("down " + n); err != nil {
		return err
	}
	k.links[n].Up = false
	return nil
}

func (k *fakeKernel) AddAddr(n, a string) error {
	if err := k.do("add " + n + " " + a); err != nil {
		return err
	}
	k.links[n].Addresses = append(k.links[n].Addresses, a)
	return nil
}

func (k *fakeKernel) DelAddr(n, a string) error {
	if err := k.do("del " + n + " " + a); err != nil {
		return err
	}
	l := k.links[n]
	l.Addresses = slices.DeleteFunc(l.Addresses, func(x string) bool { return x == a })
	l.Dynamic = slices.DeleteFunc(l.Dynamic, func(x string) bool { return x == a })
	return nil
}

func (k *fakeKernel) SetMTU(n string, mtu int) error {
	if err := k.do(fmt.Sprintf("mtu %s %d", n, mtu)); err != nil {
		return err
	}
	k.links[n].MTU = mtu
	return nil
}

func (k *fakeKernel) DaemonControl(r netops.DaemonRequest) error {
	if err := k.do(fmt.Sprintf("%s %s %s", r.Mode, r.Name, r.Interface)); err != nil {
		return err
	}
	switch r.Mode {
	case netops.DaemonEnsure:
		if k.clients[r.Interface] == "" {
			k.clients[r.Interface] = r.Name
			// The lease arrives.
			l := k.links[r.Interface]
			l.Addresses = append(l.Addresses, "198.51.100.20/24")
			l.Dynamic = append(l.Dynamic, "198.51.100.20/24")
		}
	case netops.DaemonStop:
		delete(k.clients, r.Interface)
	}
	return nil
}

func (k *fakeKernel) DaemonStateOf(r netops.DaemonRequest) (string, error) {
	if r.Name == "dhclient" {
		if k.clients[r.Interface] == r.Name {
			return "running", nil
		}
		return "stopped", nil
	}
	return "missing", nil
}

// SyncLinks makes the fake's links match spec: missing ones appear,
// members get their master, links the stage made and no longer wants go.
func (k *fakeKernel) SyncLinks(spec netops.LinksSpec) error {
	if err := k.do(fmt.Sprintf("links %d", len(spec.Links))); err != nil {
		return err
	}
	if k.made == nil {
		k.made = map[string]bool{}
	}
	want := map[string]bool{}
	for _, l := range spec.Links {
		want[l.Name] = true
		if _, ok := k.links[l.Name]; !ok {
			k.links[l.Name] = &Link{MTU: 1500}
			k.made[l.Name] = true
		}
		k.links[l.Name].Up = true
		for _, m := range l.Members {
			if ml, ok := k.links[m]; ok {
				ml.Master = l.Name
			}
		}
	}
	for name := range k.made {
		if !want[name] {
			delete(k.links, name)
			delete(k.made, name)
			for _, l := range k.links {
				if l.Master == name {
					l.Master = ""
				}
			}
		}
	}
	return nil
}

func (k *fakeKernel) read(n string) (Link, bool, error) {
	l, ok := k.links[n]
	if !ok {
		return Link{}, false, nil
	}
	return Link{Up: l.Up, MTU: l.MTU, Master: l.Master, Addresses: slices.Clone(l.Addresses), Dynamic: slices.Clone(l.Dynamic)}, true, nil
}

type fixture struct {
	t     *testing.T
	node  string
	store *confstore.Store
	k     *fakeKernel
	s     *Stage
	dir   string
}

func newFixture(t *testing.T) *fixture {
	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	k := newKernel()
	f := &fixture{t: t, store: store, k: k, dir: t.TempDir()}
	ctx := context.Background()
	site, err := store.Create(ctx, "t", &model.Site{Meta: model.Meta{Name: "hq"}})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.Create(ctx, "t", &model.ClusterNode{Meta: model.Meta{Name: "fw1"},
		Site: model.Ref[model.Site]{ID: site.GetMeta().ID}, Hostname: "fw1", Address: "10.255.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	f.node = node.GetMeta().ID
	f.s = f.stage()
	return f
}

// stage is a new stage over the same record, as after a restart.
func (f *fixture) stage() *Stage {
	return &Stage{Runner: f.k, Links: f.k.read, Dir: f.dir, RunDir: "/run/x",
		Locate: func(st *confstore.State) (string, string) {
			o, _ := st.Get(model.KindClusterNode, f.node)
			return o.(*model.ClusterNode).Site.ID, f.node
		}}
}

func (f *fixture) set(e *model.Interface) {
	f.t.Helper()
	e.Scope = model.NodeScope(f.node)
	ctx := context.Background()
	for _, o := range f.store.Current().List(model.KindInterface) {
		if o.GetMeta().Name == e.Name {
			e.ID, e.Version = o.GetMeta().ID, o.GetMeta().Version
			if _, err := f.store.Update(ctx, "t", e, e.Version); err != nil {
				f.t.Fatal(err)
			}
			return
		}
	}
	if _, err := f.store.Create(ctx, "t", e); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) apply() error {
	f.t.Helper()
	raw, err := f.s.Render(f.store.Current())
	if err != nil {
		f.t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.s.Check(ctx, raw); err != nil {
		return err
	}
	if err := f.s.Apply(ctx, raw); err != nil {
		return err
	}
	return f.s.Healthy(ctx)
}

func TestAddressesMTUAndLinkComeAndGo(t *testing.T) {
	f := newFixture(t)
	f.set(&model.Interface{Meta: model.Meta{Name: "lan"}, Device: "eth1", Enabled: true,
		Addresses: []string{"10.0.0.1/24", "2001:db8::1/64"}, MTU: 9000})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	l := f.k.links["eth1"]
	if !l.Up || l.MTU != 9000 || !slices.Contains(l.Addresses, "10.0.0.1/24") || !slices.Contains(l.Addresses, "2001:db8::1/64") {
		t.Fatalf("eth1 after the apply: %+v", l)
	}

	// An address someone else put there is never the stage's to remove.
	f.k.links["eth1"].Addresses = append(f.k.links["eth1"].Addresses, "10.0.0.99/24")

	f.set(&model.Interface{Meta: model.Meta{Name: "lan"}, Device: "eth1", Enabled: true,
		Addresses: []string{"10.0.0.2/24"}, Down: true})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if l.Up || l.MTU != 1500 || slices.Contains(l.Addresses, "10.0.0.1/24") || slices.Contains(l.Addresses, "2001:db8::1/64") ||
		!slices.Contains(l.Addresses, "10.0.0.2/24") || !slices.Contains(l.Addresses, "10.0.0.99/24") {
		t.Fatalf("eth1 after the change: %+v", l)
	}

	// After a restart, switching the interface off undoes what the stage
	// did: its address goes, the link comes back up; the foreign address
	// stays.
	f.s = f.stage()
	f.set(&model.Interface{Meta: model.Meta{Name: "lan"}, Device: "eth1", Enabled: false,
		Addresses: []string{"10.0.0.2/24"}, Down: true})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if !l.Up || slices.Contains(l.Addresses, "10.0.0.2/24") || !slices.Contains(l.Addresses, "10.0.0.99/24") {
		t.Fatalf("eth1 after switching the interface off: %+v", l)
	}
}

func TestAZoneOnlyInterfaceIsLeftAlone(t *testing.T) {
	f := newFixture(t)
	f.set(&model.Interface{Meta: model.Meta{Name: "wan"}, Device: "eth1", Enabled: true})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if len(f.k.calls) != 0 || f.k.links["eth1"].Up {
		t.Errorf("an interface that only names a zone was configured: %v", f.k.calls)
	}
	// Nor does it need privileges.
	f.s.Runner = nil
	if err := f.apply(); err != nil {
		t.Errorf("without privileges: %v", err)
	}
}

func TestDHCPClientAndItsLease(t *testing.T) {
	f := newFixture(t)
	f.set(&model.Interface{Meta: model.Meta{Name: "wan"}, Device: "eth0", Enabled: true, DHCP: true})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if f.k.clients["eth0"] != "dhclient" {
		t.Fatalf("no DHCP client on eth0: %v", f.k.calls)
	}
	f.set(&model.Interface{Meta: model.Meta{Name: "wan"}, Device: "eth0", Enabled: true, Addresses: []string{"192.0.2.10/24"}})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	l := f.k.links["eth0"]
	if f.k.clients["eth0"] != "" || slices.Contains(l.Addresses, "198.51.100.20/24") {
		t.Fatalf("the client or its lease stayed: %v %+v", f.k.clients, l)
	}
	// The address the device had all along, now in the model, stays; so
	// does the link-local address.
	if !slices.Contains(l.Addresses, "192.0.2.10/24") || !slices.Contains(l.Addresses, "fe80::1/64") {
		t.Errorf("eth0: %+v", l)
	}
}

func TestAMissingDeviceIsNoFailure(t *testing.T) {
	f := newFixture(t)
	f.set(&model.Interface{Meta: model.Meta{Name: "usb"}, Device: "usb0", Enabled: true, Addresses: []string{"10.1.0.1/24"}})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if m := f.s.Missing(); len(m) != 1 || m[0] != "usb0" {
		t.Errorf("missing: %v", m)
	}
}

func TestOneAddressOnTwoDevicesIsRefused(t *testing.T) {
	f := newFixture(t)
	f.set(&model.Interface{Meta: model.Meta{Name: "a"}, Device: "eth0", Enabled: true, Addresses: []string{"10.0.0.1/24"}})
	f.set(&model.Interface{Meta: model.Meta{Name: "b"}, Device: "eth1", Enabled: true, Addresses: []string{"10.0.0.1/32"}})
	if _, err := f.s.Render(f.store.Current()); err == nil || !strings.Contains(err.Error(), "on both") {
		t.Errorf("render: %v", err)
	}
}

// TestRollbackRestoresTheDevice: confapply rolls back by applying the
// previous artifact; the device is as it was.
func TestRollbackRestoresTheDevice(t *testing.T) {
	f := newFixture(t)
	f.set(&model.Interface{Meta: model.Meta{Name: "lan"}, Device: "eth0", Enabled: true, Addresses: []string{"192.0.2.10/24"}})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	before, _ := f.s.Render(f.store.Current())
	f.set(&model.Interface{Meta: model.Meta{Name: "lan"}, Device: "eth0", Enabled: true, Addresses: []string{"192.0.2.11/24"}, MTU: 1400})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Apply(context.Background(), before); err != nil {
		t.Fatal(err)
	}
	l := f.k.links["eth0"]
	if l.MTU != 1500 || !slices.Contains(l.Addresses, "192.0.2.10/24") || slices.Contains(l.Addresses, "192.0.2.11/24") {
		t.Errorf("after the rollback: %+v", l)
	}
}

func (f *fixture) create(e model.Entity) {
	f.t.Helper()
	e.GetMeta().Scope = model.NodeScope(f.node)
	if _, err := f.store.Create(context.Background(), "t", e); err != nil {
		f.t.Fatal(err)
	}
}

// TestABondWithAVLANOnTop: the stage makes the bond and the VLAN on it,
// enslaves the members, gives the VLAN its address, and takes it all
// away again when the bond leaves the model.
func TestABondWithAVLANOnTop(t *testing.T) {
	f := newFixture(t)
	f.k.links["eth1"].Up = true
	f.create(&model.Bond{Meta: model.Meta{Name: "uplink"}, Enabled: true, Device: "bond0", Members: []string{"eth0", "eth1"}, Mode: "802.3ad"})
	f.create(&model.VLAN{Meta: model.Meta{Name: "office"}, Enabled: true, Device: "bond0.20", Parent: "bond0", VID: 20})
	f.set(&model.Interface{Meta: model.Meta{Name: "office"}, Device: "bond0.20", Enabled: true, Addresses: []string{"10.20.0.1/24"}})
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if f.k.links["eth0"].Master != "bond0" || f.k.links["eth1"].Master != "bond0" {
		t.Errorf("members: %+v %+v", f.k.links["eth0"], f.k.links["eth1"])
	}
	if l := f.k.links["bond0.20"]; l == nil || !slices.Contains(l.Addresses, "10.20.0.1/24") {
		t.Fatalf("the VLAN lacks its address: %+v", l)
	}

	// Away with all of it.
	for _, k := range []model.Kind{model.KindInterface, model.KindVLAN, model.KindBond} {
		for _, o := range f.store.Current().List(k) {
			if err := f.store.Delete(context.Background(), "t", k, o.GetMeta().ID, o.GetMeta().Version); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.k.links["bond0"]; ok || f.k.links["eth0"].Master != "" {
		t.Errorf("the bond stayed: %v %+v", f.k.links["bond0"], f.k.links["eth0"])
	}
	if len(f.s.done) != 0 {
		t.Errorf("the record keeps devices that are gone: %v", f.s.done)
	}
	// With nothing made any more, an empty model asks nothing of the kernel.
	n := len(f.k.calls)
	if err := f.apply(); err != nil || len(f.k.calls) != n {
		t.Errorf("an empty model still syncs links: %v %v", err, f.k.calls[n:])
	}
}

func TestAMemberHasNoAddressOfItsOwn(t *testing.T) {
	f := newFixture(t)
	f.create(&model.Bridge{Meta: model.Meta{Name: "lan"}, Enabled: true, Device: "br0", Ports: []string{"eth1"}})
	f.set(&model.Interface{Meta: model.Meta{Name: "eth1"}, Device: "eth1", Enabled: true, Addresses: []string{"10.0.0.1/24"}})
	if _, err := f.s.Render(f.store.Current()); err == nil || !strings.Contains(err.Error(), "member of br0") {
		t.Errorf("render: %v", err)
	}
}

// TestTheFirstArtifactFormStillApplies: a change waiting from before links
// is a plain list of devices.
func TestTheFirstArtifactFormStillApplies(t *testing.T) {
	a, err := decode([]byte(`[{"name":"eth1","addresses":["10.0.0.1/24"]}]`))
	if err != nil || len(a.Devices) != 1 || a.Devices[0].Name != "eth1" || len(a.Links) != 0 {
		t.Errorf("decode: %+v %v", a, err)
	}
}
