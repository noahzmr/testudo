package engine

import (
	"context"
	"time"

	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/storage"
	"github.com/noahzmr/testudo/internal/topology"
)

// startSnapshotter periodically captures the state of firewall counters,
// the route table, NAT rules, and the topology graph, and writes them into
// the per-session snapshots table. These rows are what replay reads back to
// reconstruct subsystem state at any timestamp in the session window.
//
// All snapshots are JSON-encoded — the storage layer is schema-agnostic
// (one column holds whichever subsystem struct).
func (e *Engine) startSnapshotter(ctx context.Context) {
	if e.netops == nil {
		return
	}
	interval := e.cfg.SnapshotInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	topo := topology.NewBuilder()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		e.snapshotOnce(ctx, topo)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.snapshotOnce(ctx, topo)
			}
		}
	}()
}

func (e *Engine) snapshotOnce(ctx context.Context, topo *topology.Builder) {
	if fw, err := e.netops.ListFirewall(); err == nil {
		_ = e.store.InsertSnapshot(ctx, e.sessionID, storage.SnapshotKindFirewall, fw)
	}
	if routes, err := e.netops.ListRoutes(); err == nil {
		_ = e.store.InsertSnapshot(ctx, e.sessionID, storage.SnapshotKindRoute, routes)
	}
	if nats, err := e.netops.ListPortForwards(); err == nil {
		_ = e.store.InsertSnapshot(ctx, e.sessionID, storage.SnapshotKindNAT, nats)
	}
	devs := []flows.FlowStats{}
	if e.flowAgg != nil {
		devs = e.flowAgg.Snapshot()
	}
	g := topo.Build(e.inventory.Snapshot(), devs)
	_ = e.store.InsertSnapshot(ctx, e.sessionID, storage.SnapshotKindTopology, g)
}
