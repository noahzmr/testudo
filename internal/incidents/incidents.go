// Package incidents listens for CRITICAL anomalies and bundles a JSON
// snapshot of the surrounding flow / metric context onto disk. Each bundle
// becomes a row in the `incidents` SQLite table.
package incidents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/storage"
)

// Engine watches the bus for severe anomalies and persists incident bundles.
type Engine struct {
	store     *storage.Store
	flowAgg   *flows.Aggregator
	bundleDir string
	cooldown  time.Duration

	mu          sync.Mutex
	lastFire    time.Time
	conntrackFn func() any // optional: live conntrack flows folded into the bundle
}

// SetConntrackProvider registers a source of live conntrack flows. When set,
// each incident bundle includes a conntrack snapshot so post-mortems can see
// what was NAT'd at the moment of the fault. Safe to call after Run starts.
func (e *Engine) SetConntrackProvider(fn func() any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conntrackFn = fn
}

func New(store *storage.Store, fa *flows.Aggregator, storageDir string, cooldown time.Duration) *Engine {
	if cooldown <= 0 {
		cooldown = 60 * time.Second
	}
	return &Engine{
		store:     store,
		flowAgg:   fa,
		bundleDir: filepath.Join(storageDir, "incidents"),
		cooldown:  cooldown,
	}
}

// Run consumes the bus until ctx is cancelled. Any anomaly at severity
// CRITICAL fires an incident snapshot (subject to cooldown).
func (e *Engine) Run(ctx context.Context, sessionID string, in <-chan events.Event, bus *events.Bus) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			if ev.Kind != events.KindAnomaly {
				continue
			}
			p, ok := ev.Payload.(events.AnomalyPayload)
			if !ok {
				continue
			}
			if events.Severity(p.Severity) != events.SevCritical {
				continue
			}
			if !e.cooldownPassed() {
				continue
			}
			e.snapshot(ctx, sessionID, ev.Time, p, bus)
		}
	}
}

func (e *Engine) cooldownPassed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.lastFire.IsZero() && time.Since(e.lastFire) < e.cooldown {
		return false
	}
	e.lastFire = time.Now()
	return true
}

func (e *Engine) snapshot(ctx context.Context, sessionID string, ts time.Time, p events.AnomalyPayload, bus *events.Bus) {
	if ts.IsZero() {
		ts = time.Now()
	}
	id := newID(ts)
	e.mu.Lock()
	ctFn := e.conntrackFn
	e.mu.Unlock()
	var conntrack any
	if ctFn != nil {
		conntrack = ctFn()
	}
	// Bundle = JSON of (trigger, summary, top flows + conntrack at this moment).
	bundle := struct {
		IncidentID string            `json:"incident_id"`
		SessionID  string            `json:"session_id"`
		TS         time.Time         `json:"ts"`
		Trigger    string            `json:"trigger"`
		Summary    string            `json:"summary"`
		Flows      []flows.FlowStats `json:"flows"`
		Conntrack  any               `json:"conntrack,omitempty"`
	}{
		IncidentID: id, SessionID: sessionID, TS: ts,
		Trigger: p.Severity, Summary: p.Message,
		Flows:     e.flowAgg.TopByRecency(50),
		Conntrack: conntrack,
	}

	_ = os.MkdirAll(e.bundleDir, 0o755)
	path := filepath.Join(e.bundleDir, id+".json")
	data, _ := json.MarshalIndent(bundle, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		// fall back to db row without path
		path = ""
	}
	_ = e.store.InsertIncident(ctx, sessionID, storage.IncidentRow{
		ID: id, TS: ts, Trigger: p.Severity, Summary: p.Message, BundlePath: path,
	})
	bus.Publish(events.Event{
		Kind: events.KindIncident, Source: "incidents",
		Payload: events.IncidentPayload{
			IncidentID: id, Trigger: p.Severity, Summary: p.Message,
		},
	})
}

func newID(ts time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "inc-" + ts.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}
