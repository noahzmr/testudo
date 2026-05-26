package tui

import (
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
)

// ProbeResult is the latest outcome for one (source, target) tuple.
// Server is populated for DNS results so the Health tab can render
// per-resolver rows.
type ProbeResult struct {
	Source string
	Target string
	Kind   events.Kind
	RTT    time.Duration
	OK     bool
	Server string
	Time   time.Time
}

// ProbeState is a thread-safe cache of the latest probe result keyed by
// (source, target). One bus subscription feeds it from a background
// goroutine; the Health tab reads snapshots on each render tick. Keeping
// a snapshot here means the bus doesn't have to re-fan-out to the TUI on
// every event and the render path stays O(snapshot-size).
type ProbeState struct {
	mu      sync.RWMutex
	results map[string]map[string]ProbeResult // source -> key -> latest

	sub  *events.Subscription
	done chan struct{}
}

// NewProbeState subscribes to latency/loss/DNS events on the given bus
// and starts the ingest loop. Caller must invoke Close to release the
// subscription on shutdown.
func NewProbeState(bus *events.Bus) *ProbeState {
	s := &ProbeState{
		results: map[string]map[string]ProbeResult{},
		sub: bus.SubscribeKinds(
			events.KindLatency,
			events.KindPacketLoss,
			events.KindDNSResult,
			events.KindDNSFailure,
		),
		done: make(chan struct{}),
	}
	go s.loop()
	return s
}

func (s *ProbeState) loop() {
	defer close(s.done)
	for ev := range s.sub.C() {
		s.ingest(ev)
	}
}

func (s *ProbeState) ingest(ev events.Event) {
	r := ProbeResult{Source: ev.Source, Kind: ev.Kind, Time: ev.Time}
	switch p := ev.Payload.(type) {
	case events.LatencyPayload:
		r.Target = p.Target
		r.RTT = p.RTT
		r.OK = true
	case events.PacketLossPayload:
		r.Target = p.Target
		r.OK = false
	case events.DNSResultPayload:
		r.Target = p.Name
		r.Server = p.Server
		r.RTT = p.Duration
		r.OK = true
	case events.DNSFailurePayload:
		r.Target = p.Name
		r.Server = p.Server
		r.RTT = p.Duration
		r.OK = false
	default:
		return
	}
	key := r.Target
	if r.Server != "" {
		key = r.Server + "|" + r.Target
	}
	s.mu.Lock()
	if _, ok := s.results[r.Source]; !ok {
		s.results[r.Source] = map[string]ProbeResult{}
	}
	s.results[r.Source][key] = r
	s.mu.Unlock()
}

// BySource returns a copy of every result currently cached under source.
// Order is unspecified; callers that need stable order should sort.
func (s *ProbeState) BySource(source string) []ProbeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.results[source]
	out := make([]ProbeResult, 0, len(src))
	for _, r := range src {
		out = append(out, r)
	}
	return out
}

// Close cancels the subscription and waits for the ingest loop to exit.
// Safe to call more than once.
func (s *ProbeState) Close() {
	if s.sub == nil {
		return
	}
	s.sub.Close()
	<-s.done
	s.sub = nil
}
