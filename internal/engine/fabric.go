package engine

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/mesh"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/pathmon"
)

// fabricCore is this node's part in the network between the sites: its
// tunnel key and the measurements of its paths.
type fabricCore struct {
	paths *pathmon.Monitor
	// pub is the public key of the node's fabric tunnels, once there is one.
	pub atomic.Pointer[string]
}

// meshPublicKey returns the public key of this node's fabric tunnels. With
// create it makes the key pair first when there is none. The private key
// is written to this node's own secret store, past the cluster's
// replication: it never leaves the node.
func (e *Engine) meshPublicKey(create bool) string {
	if p := e.fabric.pub.Load(); p != nil {
		return *p
	}
	local := e.conf.secrets.Local()
	raw, err := local.Get(mesh.KeyRef)
	if err != nil {
		if !create {
			return ""
		}
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return ""
		}
		if err := local.Put(mesh.KeyRef, []byte(k.String()+"\n")); err != nil {
			log.Printf("fabric: store the tunnel key: %v", err)
			return ""
		}
		raw = []byte(k.String())
	}
	k, err := wgtypes.ParseKey(strings.TrimSpace(string(raw)))
	if err != nil {
		log.Printf("fabric: the stored tunnel key is unreadable: %v", err)
		return ""
	}
	pub := k.PublicKey().String()
	e.fabric.pub.Store(&pub)
	return pub
}

// fabricLoop keeps the node's key published and its paths measured.
func (e *Engine) fabricLoop(ctx context.Context) {
	if e.conf.store == nil {
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		st := e.conf.store.Current()
		f := mesh.Fabric(st)
		if f == nil {
			continue
		}
		pub := e.meshPublicKey(true)
		e.publishMeshKeys(ctx, st, pub)

		site, node := e.locate(st)
		plan, _ := mesh.Build(st, site, node)
		var targets []pathmon.Target
		for _, t := range plan.Tunnels {
			targets = append(targets, pathmon.Target{Device: t.Device, Peer: t.Peer, PeerNode: t.PeerNode, Slot: t.Slot, Color: t.Color})
		}
		m := e.fabric.paths
		m.Margin = time.Duration(f.SwitchMarginMs) * time.Millisecond
		m.Hold = time.Duration(f.HoldSeconds) * time.Second
		if !m.Check(ctx, targets, time.Now()) {
			continue
		}
		if _, pending := e.conf.apply.Pending(); pending {
			continue // the pending change is settled first; the next round catches up
		}
		if err := e.conf.routing.Refresh(ctx, st); err != nil {
			log.Printf("fabric: move traffic after a path change: %v", err)
		}
	}
}

// publishMeshKeys puts fabric keys into the model, where the other nodes
// find them. A node writes its own when it decides alone (no cluster); in a
// cluster every member announces its key and the leader copies them all.
func (e *Engine) publishMeshKeys(ctx context.Context, st *confstore.State, own string) {
	want := map[string]string{} // node name -> public key
	mgr := e.cluster.mgr
	switch {
	case mgr == nil || mgr.Node() == nil:
		name := strings.ToLower(e.cfg.NodeName)
		if name == "" {
			_, id := e.locate(st)
			if obj, ok := st.Get(model.KindClusterNode, id); ok {
				name = strings.ToLower(obj.GetMeta().Name)
			}
		}
		if name != "" && own != "" {
			want[name] = own
		}
	case mgr.Node().IsLeader():
		for _, m := range mgr.Node().State().Members {
			if m.MeshKey != "" {
				want[strings.ToLower(m.ID)] = m.MeshKey
			}
		}
	default:
		return
	}
	var ops []confstore.Op
	for _, e := range st.List(model.KindClusterNode) {
		n := e.(*model.ClusterNode)
		key := want[strings.ToLower(n.Name)]
		if key == "" {
			key = want[strings.ToLower(n.Hostname)]
		}
		if key == "" || key == n.MeshPublicKey {
			continue
		}
		c := *n
		c.MeshPublicKey = key
		obj, err := json.Marshal(&c)
		if err != nil {
			continue
		}
		ops = append(ops, confstore.Op{Type: confstore.OpUpdate, Kind: model.KindClusterNode, ID: n.ID, Object: obj, IfMatch: n.Version})
	}
	if len(ops) == 0 {
		return
	}
	if _, pending := e.conf.apply.Pending(); pending {
		return
	}
	if _, err := e.conf.apply.Apply(ctx, "system", "fabric keys", ops); err != nil {
		log.Printf("fabric: publish tunnel keys: %v", err)
		return
	}
	if err := e.conf.apply.Confirm("system"); err != nil {
		log.Printf("fabric: confirm tunnel keys: %v", err)
	}
}

// fabricRuntime describes this node's tunnels and their measurements.
func (e *Engine) fabricRuntime() map[string]any {
	st := e.conf.store.Current()
	f := mesh.Fabric(st)
	if f == nil {
		return nil
	}
	site, node := e.locate(st)
	plan, err := mesh.Build(st, site, node)
	out := map[string]any{"enabled": plan.Enabled, "public_key": e.meshPublicKey(false), "paths": e.fabric.paths.Status()}
	if err != nil {
		out["error"] = err.Error()
	}
	if plan.Enabled {
		type tunnel struct {
			Device   string `json:"device"`
			Peer     string `json:"peer"`
			PeerNode string `json:"peer_node"`
			Color    string `json:"color"`
			Slot     int    `json:"slot"`
			VRF      string `json:"vrf,omitempty"`
			Endpoint string `json:"endpoint"`
			Session  string `json:"session"`
		}
		out["loopback"], out["asn"] = plan.Loopback, plan.ASN
		var list []tunnel
		for _, t := range plan.Tunnels {
			list = append(list, tunnel{Device: t.Device, Peer: t.Peer, PeerNode: t.PeerName, Color: t.Color, Slot: t.Slot, VRF: t.VRF,
				Endpoint: t.Endpoint, Session: "ibgp"})
			if !t.IBGP {
				list[len(list)-1].Session = "ebgp"
			}
		}
		out["tunnels"] = list
	}
	return out
}
