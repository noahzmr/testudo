// Package ifstage configures the network devices the model's interfaces
// name: their addresses, a DHCP client, the MTU and the link state.
//
// The stage changes only what an interface sets, and undoes only what it
// did itself: an address it added, an MTU it changed, a link it took down,
// a DHCP client it started. What it did is kept in a file, so that holds
// across restarts. Addresses other parts of the node own (a DHCP lease,
// the HA pair's virtual addresses, WireGuard tunnel addresses, IPv6
// link-local and SLAAC addresses) are never touched.
package ifstage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

// Runner is the privileged side. *netops.Writer implements it.
type Runner interface {
	SetIfaceUp(name string) error
	SetIfaceDown(name string) error
	AddAddr(iface, cidr string) error
	DelAddr(iface, cidr string) error
	SetMTU(iface string, mtu int) error
	DaemonControl(req netops.DaemonRequest) error
	DaemonStateOf(req netops.DaemonRequest) (string, error)
}

// Link is what the kernel says about a device.
type Link struct {
	Up  bool
	MTU int
	// Addresses are "address/prefix"; Dynamic are those with a lifetime
	// (from a DHCP client or SLAAC).
	Addresses []string
	Dynamic   []string
}

// Links reads devices. ok is false when the device does not exist.
type Links func(name string) (l Link, ok bool, err error)

// Stage implements confapply.Stage.
type Stage struct {
	// Runner may be nil on a node without network privileges; then only a
	// model that configures no interface can be applied.
	Runner Runner
	// Links reads the kernel's devices; nil means netlink.
	Links  Links
	Locate func(*confstore.State) (siteID, nodeID string)
	// Dir keeps the record of what the stage did; RunDir is the DHCP
	// clients' run directory.
	Dir, RunDir string

	mu      sync.Mutex
	done    map[string]*record // by device; nil until loaded
	applied []Device
	cmu     sync.Mutex
	client  string // the DHCP client installed here, once known (cmu)
	missing []string
}

// Device is how one device is to be configured.
type Device struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses,omitempty"`
	DHCP      bool     `json:"dhcp,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
	Down      bool     `json:"down,omitempty"`
}

func (d Device) configures() bool {
	return len(d.Addresses) > 0 || d.DHCP || d.MTU > 0 || d.Down
}

// record is what the stage did to one device.
type record struct {
	Addresses []string `json:"addresses,omitempty"`
	// MTU is the device's MTU before the stage changed it; 0: unchanged.
	MTU  int    `json:"mtu,omitempty"`
	Down bool   `json:"down,omitempty"`
	DHCP string `json:"dhcp,omitempty"` // the client the stage started
}

func (r *record) empty() bool {
	return len(r.Addresses) == 0 && r.MTU == 0 && !r.Down && r.DHCP == ""
}

func (s *Stage) Name() string { return "interfaces" }

// Render lists the devices this node's interfaces configure.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	var site, node string
	if s.Locate != nil {
		site, node = s.Locate(st)
	}
	rank := map[string]int{"global": 1, "site": 2, "node": 3}
	best := map[string]*model.Interface{}
	var errs []error
	for _, e := range st.List(model.KindInterface) {
		if !model.AppliesTo(e, site, node) {
			continue
		}
		eff, _, err := model.Effective(e, site, node)
		if err != nil {
			errs = append(errs, fmt.Errorf("interface %q: %w", e.GetMeta().Name, err))
			continue
		}
		i := eff.(*model.Interface)
		if cur := best[i.Device]; cur == nil || rank[i.Scope.Level()] > rank[cur.Scope.Level()] {
			best[i.Device] = i
		}
	}
	devs := []Device{}
	owner := map[string]string{}
	for name, i := range best {
		if !i.Enabled {
			continue
		}
		d := Device{Name: name, DHCP: i.DHCP, MTU: i.MTU, Down: i.Down}
		for _, a := range i.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				errs = append(errs, fmt.Errorf("interface %q: address %q: %w", i.Name, a, err))
				continue
			}
			a = p.String()
			if other, ok := owner[p.Addr().String()]; ok {
				errs = append(errs, fmt.Errorf("address %s is on both %s and %s", p.Addr(), other, name))
			}
			owner[p.Addr().String()] = name
			d.Addresses = append(d.Addresses, a)
		}
		sort.Strings(d.Addresses)
		if d.configures() {
			devs = append(devs, d)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sort.Slice(devs, func(a, b int) bool { return devs[a].Name < devs[b].Name })
	return json.MarshalIndent(devs, "", " ")
}

func decode(raw []byte) ([]Device, error) {
	var devs []Device
	err := json.Unmarshal(raw, &devs)
	return devs, err
}

// Check makes sure the node can do what the devices ask for. Nothing is
// changed.
func (s *Stage) Check(_ context.Context, raw []byte) error {
	devs, err := decode(raw)
	if err != nil || len(devs) == 0 {
		return err
	}
	if s.Runner == nil {
		return errors.New("interfaces cannot be configured on this node (no network privileges)")
	}
	for _, d := range devs {
		if d.DHCP {
			if _, err := s.dhcpClient(); err != nil {
				return fmt.Errorf("interface %s: %w", d.Name, err)
			}
			break
		}
	}
	return nil
}

// dhcpClient finds the DHCP client installed on this node.
func (s *Stage) dhcpClient() (string, error) {
	s.cmu.Lock()
	c := s.client
	s.cmu.Unlock()
	if c != "" {
		return c, nil
	}
	for _, name := range netops.DHCPClients {
		state, err := s.Runner.DaemonStateOf(netops.DaemonRequest{Name: name, RunDir: s.RunDir, Interface: "lo"})
		if err != nil {
			return "", err
		}
		if state != "missing" {
			s.cmu.Lock()
			s.client = name
			s.cmu.Unlock()
			return name, nil
		}
	}
	return "", errors.New("no DHCP client is installed (dhclient or dhcpcd)")
}

func (s *Stage) links() Links {
	if s.Links != nil {
		return s.Links
	}
	return netlinkLinks
}

func (s *Stage) recordPath() string { return filepath.Join(s.Dir, "managed.json") }

func (s *Stage) loadLocked() error {
	if s.done != nil {
		return nil
	}
	s.done = map[string]*record{}
	b, err := os.ReadFile(s.recordPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &s.done)
}

func (s *Stage) saveLocked() error {
	for name, r := range s.done {
		if r.empty() {
			delete(s.done, name)
		}
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.done, "", " ")
	if err != nil {
		return err
	}
	tmp := s.recordPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.recordPath())
}

// Apply configures every device of the artifact and undoes what the stage
// did to devices that left it.
func (s *Stage) Apply(_ context.Context, raw []byte) error {
	devs, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return fmt.Errorf("record of configured interfaces: %w", err)
	}
	if len(devs) == 0 && len(s.done) == 0 {
		s.applied, s.missing = nil, nil
		return nil
	}
	if s.Runner == nil {
		return errors.New("interfaces cannot be configured on this node (no network privileges)")
	}
	want := map[string]Device{}
	names := map[string]bool{}
	for _, d := range devs {
		want[d.Name], names[d.Name] = d, true
	}
	for name := range s.done {
		names[name] = true
	}
	order := make([]string, 0, len(names))
	for n := range names {
		order = append(order, n)
	}
	sort.Strings(order)

	var errs []error
	s.missing = nil
	for _, name := range order {
		d := want[name] // zero: undo what the stage did
		d.Name = name
		r := s.done[name]
		if r == nil {
			r = &record{}
			s.done[name] = r
		}
		link, ok, err := s.links()(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if !ok {
			if _, wanted := want[name]; wanted {
				s.missing = append(s.missing, name)
			}
			continue
		}
		if err := s.configure(d, r, link); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	saveErr := s.saveLocked()
	if err := errors.Join(append(errs, saveErr)...); err != nil {
		return err
	}
	s.applied = devs
	return nil
}

// configure brings one device to d, starting from what the stage did (r)
// and what the kernel has (l).
func (s *Stage) configure(d Device, r *record, l Link) error {
	has := map[string]bool{}
	for _, a := range l.Addresses {
		has[a] = true
	}

	// Link state: down when asked; up again when the stage took it down,
	// and up for a device it configures (an address on a link that is down
	// serves nobody).
	switch {
	case d.Down:
		if l.Up {
			if err := s.Runner.SetIfaceDown(d.Name); err != nil {
				return err
			}
		}
		r.Down = true
	case r.Down || ((len(d.Addresses) > 0 || d.DHCP) && !l.Up):
		if err := s.Runner.SetIfaceUp(d.Name); err != nil {
			return err
		}
		r.Down = false
	}

	// MTU, remembering the device's own to go back to.
	switch {
	case d.MTU > 0 && l.MTU != d.MTU:
		if r.MTU == 0 {
			r.MTU = l.MTU
		}
		if err := s.Runner.SetMTU(d.Name, d.MTU); err != nil {
			return err
		}
	case d.MTU == 0 && r.MTU > 0:
		if l.MTU != r.MTU {
			if err := s.Runner.SetMTU(d.Name, r.MTU); err != nil {
				return err
			}
		}
		r.MTU = 0
	}

	// Addresses: add what is missing, remove what the stage added before
	// and the model no longer has.
	keep := map[string]bool{}
	for _, a := range d.Addresses {
		keep[a] = true
		if !has[a] {
			if err := s.Runner.AddAddr(d.Name, a); err != nil {
				return err
			}
		}
	}
	var still []string
	for _, a := range r.Addresses {
		if keep[a] {
			continue
		}
		if has[a] {
			if err := s.Runner.DelAddr(d.Name, a); err != nil {
				still = append(still, a)
				continue
			}
		}
	}
	r.Addresses = append(append([]string(nil), d.Addresses...), still...)

	// DHCP client.
	switch {
	case d.DHCP:
		client := r.DHCP
		if client == "" {
			c, err := s.dhcpClient()
			if err != nil {
				return err
			}
			client = c
		}
		if err := s.Runner.DaemonControl(netops.DaemonRequest{Name: client, Mode: netops.DaemonEnsure, RunDir: s.RunDir,
			Interface: d.Name}); err != nil {
			return err
		}
		r.DHCP = client
	case r.DHCP != "":
		if err := s.Runner.DaemonControl(netops.DaemonRequest{Name: r.DHCP, Mode: netops.DaemonStop, RunDir: s.RunDir,
			Interface: d.Name}); err != nil {
			return err
		}
		// The lease's IPv4 addresses go with the client; IPv6 addresses
		// with a lifetime come from router advertisements and stay.
		for _, a := range l.Dynamic {
			if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is4() && !keep[a] {
				_ = s.Runner.DelAddr(d.Name, a)
			}
		}
		r.DHCP = ""
	}
	return nil
}

// Healthy reports whether every device that exists has what was applied.
func (s *Stage) Healthy(context.Context) error {
	s.mu.Lock()
	devs := s.applied
	s.mu.Unlock()
	var errs []error
	for _, d := range devs {
		l, ok, err := s.links()(d.Name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.Name, err))
			continue
		}
		if !ok {
			continue
		}
		if d.Down && l.Up {
			errs = append(errs, fmt.Errorf("%s is up, the model takes it down", d.Name))
		}
		if !d.Down && (len(d.Addresses) > 0 || d.DHCP) && !l.Up {
			errs = append(errs, fmt.Errorf("%s is down", d.Name))
		}
		if d.MTU > 0 && l.MTU != d.MTU {
			errs = append(errs, fmt.Errorf("%s has MTU %d, not %d", d.Name, l.MTU, d.MTU))
		}
		has := map[string]bool{}
		for _, a := range l.Addresses {
			has[a] = true
		}
		for _, a := range d.Addresses {
			if !has[a] {
				errs = append(errs, fmt.Errorf("%s lacks the address %s", d.Name, a))
			}
		}
		if d.DHCP {
			client := ""
			s.mu.Lock()
			if r := s.done[d.Name]; r != nil {
				client = r.DHCP
			}
			s.mu.Unlock()
			state, err := s.Runner.DaemonStateOf(netops.DaemonRequest{Name: client, RunDir: s.RunDir, Interface: d.Name})
			if err != nil || state != "running" {
				errs = append(errs, fmt.Errorf("the DHCP client of %s is not running (%s%v)", d.Name, state, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Missing returns the devices the model configures that this node does
// not have.
func (s *Stage) Missing() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.missing...)
}
