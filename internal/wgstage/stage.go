// Package wgstage applies the WireGuard devices that internal/wgrender
// produces. Private and preshared keys stay in the node's secret store: the
// stage and the privileged side only pass their names.
package wgstage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/secrets"
	"github.com/noahzmr/testudo/internal/wgrender"
)

// Runner is the privileged side. *netops.Writer implements it.
type Runner interface {
	SyncWG(spec netops.WGSpec) error
	ListWGDevices() ([]netops.WGDeviceInfo, error)
}

// Stage implements confapply.Stage.
type Stage struct {
	// Runner may be nil on a node without network privileges; then only a
	// model without tunnels can be applied.
	Runner  Runner
	Locate  func(*confstore.State) (siteID, nodeID string)
	Secrets secrets.Store
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	applied string
	owned   bool // this run has configured devices, so removing them is its job
	next    time.Time
}

func (s *Stage) Name() string { return "wireguard" }

func (s *Stage) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Render builds the devices for this node.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	opt := wgrender.Options{Now: s.now()}
	if s.Locate != nil {
		opt.SiteID, opt.NodeID = s.Locate(st)
	}
	res, err := wgrender.Render(st, opt)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(res, "", " ")
}

func decode(raw []byte) (wgrender.Result, error) {
	var res wgrender.Result
	err := json.Unmarshal(raw, &res)
	return res, err
}

// Check makes sure every key the devices name is in the secret store.
// Nothing is applied.
func (s *Stage) Check(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil || len(res.Devices) == 0 {
		return err
	}
	if s.Runner == nil {
		return errors.New("WireGuard is not available on this node (no network privileges)")
	}
	var missing []error
	for _, d := range res.Devices {
		if d.KeyRef != "" && !s.Secrets.Has(d.KeyRef) {
			missing = append(missing, fmt.Errorf("tunnel %s: private key entry %q is not in this node's secret store", d.Name, d.KeyRef))
		}
		for _, p := range d.Peers {
			if p.PresharedRef != "" && !s.Secrets.Has(p.PresharedRef) {
				missing = append(missing, fmt.Errorf("tunnel %s: preshared key entry %q is not in this node's secret store", d.Name, p.PresharedRef))
			}
		}
	}
	return errors.Join(missing...)
}

// Apply makes the kernel's devices match the artifact.
func (s *Stage) Apply(_ context.Context, raw []byte) error {
	res, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(res.Devices) == 0 && !s.owned {
		// Nothing to configure and nothing configured by this run: leave
		// the node's WireGuard devices alone.
		s.applied, s.next = string(raw), res.NextExpiry
		return nil
	}
	if s.Runner == nil {
		return errors.New("WireGuard is not available on this node (no network privileges)")
	}
	if err := s.Runner.SyncWG(netops.WGSpec{SecretDir: s.Secrets.Dir, Devices: res.Devices}); err != nil {
		return err
	}
	s.applied, s.next, s.owned = string(raw), res.NextExpiry, true
	return nil
}

// Healthy reports whether every device of the artifact exists.
func (s *Stage) Healthy(context.Context) error {
	s.mu.Lock()
	raw := s.applied
	s.mu.Unlock()
	res, err := decode([]byte(raw))
	if raw == "" || err != nil || len(res.Devices) == 0 {
		return nil
	}
	have, err := s.Runner.ListWGDevices()
	if err != nil {
		return err
	}
	found := map[string]bool{}
	for _, d := range have {
		found[d.Name] = true
	}
	for _, d := range res.Devices {
		if !found[d.Name] {
			return fmt.Errorf("WireGuard device %s is missing after the apply", d.Name)
		}
	}
	return nil
}

// Due reports whether a peer has expired since the last apply.
func (s *Stage) Due() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.next.IsZero() && !s.next.After(s.now())
}

// Refresh renders again and applies the result if it differs. It is how an
// expired peer leaves the device: without a model change and without a
// confirmation window.
func (s *Stage) Refresh(ctx context.Context, st *confstore.State) error {
	raw, err := s.Render(st)
	if err != nil {
		return err
	}
	s.mu.Lock()
	same := string(raw) == s.applied
	s.mu.Unlock()
	if same {
		return nil
	}
	return s.Apply(ctx, raw)
}
