package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/storage"
	"github.com/noahzmr/testudo/internal/topology"
)

// startSnapshotter periodically captures the state of firewall counters,
// the route table, NAT rules, and the topology graph, and writes them into
// the per-session snapshots table. These rows are what replay reads back to
// reconstruct subsystem state at any timestamp in the session window.
//
// All snapshots are JSON-encoded - the storage layer is schema-agnostic
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
	if rules, err := e.netops.ListFirewallRules(); err == nil {
		e.processFirewallRules(ctx, rules)
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

// fwDropAnomalyThreshold is the per-rule packet increase within one snapshot
// window above which we raise a named anomaly (so the Alerts tab points at
// the exact rule). Below it, the delta still feeds the drop-rate gauge and a
// KindFirewallDrop event, but doesn't clutter Alerts.
const fwDropAnomalyThreshold = 100

// fwRuleTracker holds the previous per-rule blocking counters so successive
// snapshots can be diffed into a DROP/REJECT velocity. Guarded by its own
// mutex because the snapshot goroutine writes it while the render path
// (FirewallSignal) reads it.
type fwRuleTracker struct {
	mu           sync.Mutex
	last         map[string]uint64 // rule key -> blocking packet count
	lastTime     time.Time
	dropRate     float64 // drops/sec across all managed blocking rules
	hasDropRules bool
}

func (t *fwRuleTracker) signal() (float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dropRate, t.hasDropRules
}

func fwRuleKey(r netops.RuleInfo) string {
	return fmt.Sprintf("%s/%s/%s/%d", r.Family, r.Table, r.Chain, r.Handle)
}

// processFirewallRules persists a per-rule counter sample for every counted
// rule, diffs blocking-rule counters against the previous snapshot to derive
// a drops/sec gauge for Network Quality, and emits KindFirewallDrop events
// (plus a named anomaly for notable spikes) so the data is live and
// replayable. No-op effect on the grade when no blocking rules carry
// counters - the gauge stays neutral.
func (e *Engine) processFirewallRules(ctx context.Context, rules []netops.RuleInfo) {
	now := time.Now()
	cur := make(map[string]uint64, len(rules))
	hasDropRules := false

	for _, r := range rules {
		if r.HasCounter {
			_ = e.store.InsertFirewallRuleSample(ctx, e.sessionID, storage.FirewallRuleSample{
				TS: now, Family: r.Family, Table: r.Table, Chain: r.Chain,
				Handle: r.Handle, Packets: r.Packets, Bytes: r.Bytes,
			})
		}
		if r.IsBlocking() && r.HasCounter {
			hasDropRules = true
			cur[fwRuleKey(r)] = r.Packets
		}
	}

	e.fwTrack.mu.Lock()
	prev, prevTime := e.fwTrack.last, e.fwTrack.lastTime
	e.fwTrack.last = cur
	e.fwTrack.lastTime = now
	e.fwTrack.hasDropRules = hasDropRules
	dt := now.Sub(prevTime).Seconds()
	if prev == nil || dt <= 0 {
		// First sample (or clock skew): establish a baseline, no rate yet.
		e.fwTrack.dropRate = 0
		e.fwTrack.mu.Unlock()
		return
	}
	e.fwTrack.mu.Unlock()

	var totalDelta uint64
	for _, r := range rules {
		if !r.IsBlocking() || !r.HasCounter {
			continue
		}
		before, ok := prev[fwRuleKey(r)]
		if !ok || r.Packets <= before {
			continue
		}
		delta := r.Packets - before
		totalDelta += delta

		e.bus.Publish(events.Event{
			Kind:   events.KindFirewallDrop,
			Time:   now,
			Source: "firewall",
			Payload: events.FirewallDropPayload{
				Family: r.Family, Table: r.Table, Chain: r.Chain, Handle: r.Handle,
				Match: r.Match, Verdict: r.Verdict,
				DeltaPackets: delta, Rate: float64(delta) / dt,
			},
		})

		if delta >= fwDropAnomalyThreshold {
			e.bus.Publish(events.Event{
				Kind:   events.KindAnomaly,
				Time:   now,
				Source: "firewall",
				Payload: events.AnomalyPayload{
					Severity: string(events.SevWarn),
					Message: fmt.Sprintf("firewall %s rule %s/%s/%s handle %d dropped %d pkts (%s)",
						r.Verdict, r.Family, r.Table, r.Chain, r.Handle, delta, r.Match),
				},
			})
		}
	}

	e.fwTrack.mu.Lock()
	e.fwTrack.dropRate = float64(totalDelta) / dt
	e.fwTrack.mu.Unlock()
}
