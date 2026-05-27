// Package replay reconstructs a historical session by reading its persisted
// samples back into the metrics aggregator. Phase 1 supports list + load;
// timeline scrubbing and event correlation are Phase 2 work.
package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/noahzmr/testudo/internal/metrics"
	"github.com/noahzmr/testudo/internal/storage"
)

type SessionSummary struct {
	ID        string
	StartedAt time.Time
	EndedAt   *time.Time
	Targets   []string
	Duration  time.Duration
}

// List returns recent sessions newest-first.
func List(ctx context.Context, store *storage.Store, limit int) ([]SessionSummary, error) {
	recs, err := store.ListSessions(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]SessionSummary, 0, len(recs))
	for _, r := range recs {
		s := SessionSummary{
			ID: r.ID, StartedAt: r.StartedAt, EndedAt: r.EndedAt, Targets: r.Targets,
		}
		if r.EndedAt != nil {
			s.Duration = r.EndedAt.Sub(r.StartedAt)
		}
		out = append(out, s)
	}
	return out, nil
}

// LoadIntoAggregator replays a session's samples into an aggregator so the
// TUI can render historical state with the same code path as live state.
func LoadIntoAggregator(ctx context.Context, store *storage.Store, sessionID string, agg *metrics.Aggregator) error {
	samples, err := store.SamplesBySession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("load samples: %w", err)
	}
	for _, sm := range samples {
		switch sm.Kind {
		case "latency":
			agg.RecordLatency(sm.Label, time.Duration(sm.Value)*time.Microsecond)
		case "packet_loss":
			agg.RecordLoss(sm.Label)
		case "dns":
			agg.RecordDNS(sm.Label, time.Duration(sm.Value)*time.Microsecond, sm.Failed)
		}
	}
	return nil
}

// RuleDropPoint is one (time, cumulative counter) reading for a single
// firewall rule, used to plot how a rule's drops climbed over a session.
type RuleDropPoint struct {
	TS      time.Time
	Packets uint64
	Bytes   uint64
}

// FirewallRuleTimeline reconstructs per-rule counter timelines for a session
// from the persisted firewall_rule_samples - the replay answer to "which
// rule's drops climbed during the incident". The result is keyed by
// "family/table/chain/handle" with points in ascending time order.
func FirewallRuleTimeline(ctx context.Context, store *storage.Store, sessionID string) (map[string][]RuleDropPoint, error) {
	samples, err := store.FirewallRuleSamplesBySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("load firewall rule samples: %w", err)
	}
	out := make(map[string][]RuleDropPoint, len(samples))
	for _, sm := range samples {
		key := fmt.Sprintf("%s/%s/%s/%d", sm.Family, sm.Table, sm.Chain, sm.Handle)
		out[key] = append(out[key], RuleDropPoint{TS: sm.TS, Packets: sm.Packets, Bytes: sm.Bytes})
	}
	return out, nil
}
