package wgstage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/secrets"
)

var (
	_   confapply.Stage = (*Stage)(nil)
	_   Runner          = (*netops.Writer)(nil)
	ctx                 = context.Background()
)

type fakeRunner struct {
	spec  netops.WGSpec
	syncs int
}

func (f *fakeRunner) SyncWG(spec netops.WGSpec) error { f.spec = spec; f.syncs++; return nil }
func (f *fakeRunner) ListWGDevices() ([]netops.WGDeviceInfo, error) {
	var out []netops.WGDeviceInfo
	for _, d := range f.spec.Devices {
		out = append(out, netops.WGDeviceInfo{Name: d.Name})
	}
	return out, nil
}

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestStage(t *testing.T) {
	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	run := &fakeRunner{}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	st := &Stage{Runner: run, Secrets: secrets.Store{Dir: t.TempDir()}, Now: func() time.Time { return now },
		Locate: func(*confstore.State) (string, string) { return id(1), id(2) }}

	// No tunnels: the node's devices are not touched at all.
	raw, _ := st.Render(store.Current())
	if err := st.Check(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if err := st.Apply(ctx, raw); err != nil || run.syncs != 0 {
		t.Fatalf("empty model: err=%v syncs=%d", err, run.syncs)
	}
	// Without privileges an empty model is fine, a tunnel is not.
	if err := (&Stage{}).Apply(ctx, raw); err != nil {
		t.Errorf("empty model without a runner: %v", err)
	}

	expiry := now.Add(time.Hour)
	for _, e := range []model.Entity{
		&model.Site{Meta: meta(1, "hq")},
		&model.ClusterNode{Meta: meta(2, "fw1"), Site: model.Ref[model.Site]{ID: id(1)}, Hostname: "fw1", Address: "10.0.0.1"},
		&model.Zone{Meta: meta(10, "vpn"), DefaultAction: "drop"},
		&model.WGTunnel{Meta: model.Meta{ID: id(20), Name: "rw", Scope: model.NodeScope(id(2))}, Enabled: true, Device: "wg0", Mode: "road_warrior", ListenPort: 51820,
			Addresses: []string{"10.8.0.1/24"}, PublicKey: key, KeyRef: "wg0-key", Zone: model.Ref[model.Zone]{ID: id(10)}},
		&model.WGPeer{Meta: meta(30, "temp"), Enabled: true, Tunnel: model.Ref[model.WGTunnel]{ID: id(20)}, PublicKey: key,
			PresharedRef: "temp-psk", AllowedIPs: []string{"10.8.0.2/32"}, ExpiresAt: &expiry},
	} {
		if _, err := store.Create(ctx, "test", e); err != nil {
			t.Fatal(err)
		}
	}
	raw, err = st.Render(store.Current())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PrivateKey") {
		t.Error("the artifact has room for a private key")
	}
	// Keys that are not on this node stop the change in the dry run.
	err = st.Check(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), `"wg0-key"`) || !strings.Contains(err.Error(), `"temp-psk"`) {
		t.Fatalf("missing keys: %v", err)
	}
	if err := (&Stage{}).Check(ctx, raw); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Errorf("tunnel without a runner: %v", err)
	}
	st.Secrets.Put("wg0-key", []byte(key))
	st.Secrets.Put("temp-psk", []byte(key))
	if err := st.Check(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if err := st.Apply(ctx, raw); err != nil || run.syncs != 1 || len(run.spec.Devices[0].Peers) != 1 || run.spec.SecretDir != st.Secrets.Dir {
		t.Fatalf("apply: err=%v spec=%+v", err, run.spec)
	}
	if err := st.Healthy(ctx); err != nil {
		t.Errorf("healthy: %v", err)
	}

	// Nothing is due before the expiry; afterwards the peer leaves.
	if st.Due() {
		t.Error("due before the expiry")
	}
	if err := st.Refresh(ctx, store.Current()); err != nil || run.syncs != 1 {
		t.Errorf("refresh without a change synced again: %v, %d", err, run.syncs)
	}
	now = expiry.Add(time.Second)
	if !st.Due() {
		t.Fatal("not due after the expiry")
	}
	if err := st.Refresh(ctx, store.Current()); err != nil || run.syncs != 2 || len(run.spec.Devices[0].Peers) != 0 {
		t.Fatalf("after expiry: err=%v peers=%d", err, len(run.spec.Devices[0].Peers))
	}
	if st.Due() {
		t.Error("still due after the expired peer was removed")
	}

	// A device that disappears fails the health check.
	run.spec.Devices = nil
	if err := st.Healthy(ctx); err == nil || !errors.Is(err, err) || !strings.Contains(err.Error(), "wg0") {
		t.Errorf("missing device: %v", err)
	}
}
