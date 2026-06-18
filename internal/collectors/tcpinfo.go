package collectors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/telemetry"
)

// TCPInfoCollector samples per-flow TCP quality (smoothed RTT, retransmit rate,
// cwnd) the userspace flow path can't cheaply get, and joins it onto the flow
// table by 5-tuple. It is the Stage-A, pure-Go backend (INET_DIAG / tcp_info);
// when the binary is built with -tags ebpf and the kernel supports it, the
// source tag flips to "ebpf" and the same join happens - no parallel table.
//
// Besides enrichment it raises two anomaly classes:
//   - a per-flow RTX-rate WARN when a single connection's retransmission rate
//     crosses the configured threshold (the "which connection is suffering"
//     signal), and
//   - a frag-needed / PMTU black-hole anomaly when a flow retransmits heavily
//     while making no forward progress - the classic "some sites won't load"
//     fault, raised here as a conservative pure-Go heuristic and authoritatively
//     by the eBPF drop-path tracepoint when that backend is active.
type TCPInfoCollector struct {
	Interval time.Duration
	Flows    *flows.Aggregator
	Settings *config.SettingsStore

	ebpf telemetry.EBPFInfo

	mu     sync.RWMutex
	status TCPInfoStatus

	prev       map[string]flowCounters // 5-tuple -> last cumulative counters
	cooldown   map[string]time.Time    // 5-tuple -> next time an anomaly may fire
	connecting map[string]time.Time    // 5-tuple -> first time seen mid-handshake

	portLow, portHigh int               // cached ephemeral local-port range
	prevReset         connResetCounters // last cumulative snmp reset counters
	prevResetAt       time.Time         // when prevReset was sampled (for rate)
}

// flowCounters is the per-flow cumulative state kept between ticks to derive
// per-interval rates and forward-progress.
type flowCounters struct {
	totalRetrans uint32
	segsOut      uint32
	wqueue       uint32 // send-queue depth, for the zero-window / send-stall shape
	seen         time.Time
}

// TCPInfoStatus is the Health-tab status card for the telemetry source.
type TCPInfoStatus struct {
	Source        string             // active backend: inet_diag | ebpf
	EBPF          telemetry.EBPFInfo // build/runtime eBPF detection result
	Flows         int                // flows carrying TCP stats at the last sample
	WorstRTX      float64            // highest per-flow RTX rate observed (percent)
	WorstRTT      float64            // highest per-flow smoothed RTT (ms)
	PMTUBlackhole bool               // a flow shows the frag-needed / black-hole shape now
	Connecting    int                // sockets mid-handshake (SYN_SENT/SYN_RECV) now
	StalledConn   int                // sockets stuck mid-handshake across >=1 interval
	ConnectStall  bool               // a stalled handshake is present now -> grade penalty

	// Ephemeral-port pressure: TimeWait is the live TIME_WAIT count; EphemeralUtil
	// is local ephemeral-port usage / range size; EphemeralExhaust trips past the
	// comfort line, when new outbound connections start failing host-wide.
	TimeWait         int
	EphemeralUtil    float64
	EphemeralExhaust bool

	// Send-stall / zero-window: SendStalls counts sockets with data wedged in the
	// send queue making no forward progress (peer advertised a zero window or the
	// path is blocked); SendStall flags the live condition for the grade.
	SendStalls int
	SendStall  bool

	// Connection failures: ConnFailRate is failed-connect + established-reset
	// events per second (refused/timed-out connects and RST teardowns);
	// ConnResetSpike trips past the comfort line.
	ConnFailRate   float64
	ConnResetSpike bool

	LastErr string // last sample error, empty when healthy
	Updated time.Time
}

func (c *TCPInfoCollector) Name() string { return "tcpinfo" }

// Status returns the current telemetry-source status for rendering.
func (c *TCPInfoCollector) Status() TCPInfoStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *TCPInfoCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Interval <= 0 {
		c.Interval = 10 * time.Second
	}
	c.ebpf = telemetry.EBPFStatus()
	c.prev = map[string]flowCounters{}
	c.cooldown = map[string]time.Time{}
	c.connecting = map[string]time.Time{}
	c.portLow, c.portHigh = readEphemeralPortRange()

	c.sample(bus) // prime immediately so the first render has data
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.sample(bus)
		}
	}
}

// sample runs one collection pass: query the source, derive per-flow rates,
// join onto the flow table, and raise anomalies. Errors are recorded in the
// status card rather than returned - the collector is optional and degraded,
// never fatal.
func (c *TCPInfoCollector) sample(bus *events.Bus) {
	th := config.DefaultThresholds()
	if c.Settings != nil {
		th = c.Settings.Snapshot()
	}
	source := telemetry.SourceInetDiag
	if th.EBPFEnabled && c.ebpf.Available {
		source = telemetry.SourceEBPF
	}

	samples, err := telemetry.Query()
	now := time.Now()
	st := TCPInfoStatus{Source: source, EBPF: c.ebpf, Updated: now}
	if err != nil {
		st.LastErr = err.Error()
		c.mu.Lock()
		c.status = st
		c.mu.Unlock()
		return
	}

	live := make(map[string]struct{}, len(samples))
	connectingNow := make(map[string]struct{})
	var ephemeralInUse int
	for _, s := range samples {
		key := flowTupleKey(s)
		live[key] = struct{}{}

		// Ephemeral-port accounting spans every socket state (an outbound socket
		// in TIME_WAIT still holds its local port). Count local ports inside the
		// ephemeral range so near-exhaustion - where connect() starts failing
		// host-wide - is visible before it bites.
		if int(s.SrcPort) >= c.portLow && int(s.SrcPort) <= c.portHigh {
			ephemeralInUse++
		}
		if s.State == telemetry.TCPTimeWait {
			st.TimeWait++
		}

		// Connection-establishment health. A socket still mid-handshake carries
		// no useful RTT/RTX, so it never reaches the enrichment path below - but
		// one that lingers in SYN_SENT across ticks is a connect that can't
		// complete, the exact "waiting for connection" timeout users feel. We
		// track first-seen per tuple and flag a stall once it has persisted at
		// least one sample interval.
		if telemetry.IsConnecting(s.State) {
			connectingNow[key] = struct{}{}
			st.Connecting++
			first, seen := c.connecting[key]
			if !seen {
				c.connecting[key] = now
			} else if now.Sub(first) >= c.Interval {
				st.StalledConn++
				st.ConnectStall = true
				c.reportConnectStall(bus, s, now)
			}
			continue
		}

		prev := c.prev[key]
		rate := telemetry.RetransRate(
			uint64(prev.totalRetrans), uint64(prev.segsOut),
			uint64(s.TotalRetrans), uint64(s.SegsOut),
		)

		if c.Flows != nil {
			c.Flows.ApplyTCPStats(
				"", s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, "tcp",
				flows.FlowTCPStats{
					RTTus:       s.RTTus,
					RTTVarus:    s.RTTVarus,
					Retrans:     s.TotalRetrans,
					RetransRate: rate,
					Cwnd:        s.Cwnd,
					Source:      source,
				},
			)
		}

		st.Flows++
		if rate > st.WorstRTX {
			st.WorstRTX = rate
		}
		if rttMs := float64(s.RTTus) / 1000.0; rttMs > st.WorstRTT {
			st.WorstRTT = rttMs
		}

		if c.detectAnomalies(bus, s, prev, rate, th, now) {
			st.PMTUBlackhole = true
		}

		// Zero-window / send-stall: data sat in the send queue across two ticks
		// while no new segments went out and nothing was retransmitted - the
		// sender wants to push but can't, classically because the peer advertised
		// a zero receive window or the path wedged. Distinct from the PMTU shape
		// (which retransmits): here the connection is simply frozen.
		dSegs := int64(s.SegsOut) - int64(prev.segsOut)
		dRetrans := int64(s.TotalRetrans) - int64(prev.totalRetrans)
		if !prev.seen.IsZero() && prev.wqueue > 0 && s.WQueue > 0 && dSegs <= 0 && dRetrans <= 0 {
			st.SendStalls++
			st.SendStall = true
			c.reportSendStall(bus, s, now)
		}

		c.prev[key] = flowCounters{totalRetrans: s.TotalRetrans, segsOut: s.SegsOut, wqueue: s.WQueue, seen: now}
	}

	// Drop prev state for flows that have gone away, bounding memory.
	for key := range c.prev {
		if _, ok := live[key]; !ok {
			delete(c.prev, key)
			delete(c.cooldown, key)
		}
	}
	// Drop handshake-tracking state for sockets that are no longer connecting:
	// they either established (good) or were torn down. Either way the stall, if
	// any, is over, so clear its alert cooldown too.
	for key := range c.connecting {
		if _, ok := connectingNow[key]; !ok {
			delete(c.connecting, key)
			delete(c.cooldown, "connect:"+key)
		}
	}

	c.scoreEphemeral(bus, &st, ephemeralInUse, now)
	c.scoreConnFailures(bus, &st, now)

	c.mu.Lock()
	c.status = st
	c.mu.Unlock()
}

// ephemeralComfort is the local-port utilisation past which we warn: a host
// with 80% of its ephemeral range tied up (often by TIME_WAIT churn to one
// busy destination) is close to connect() failures.
const ephemeralComfort = 0.80

// scoreEphemeral folds ephemeral-port utilisation into the status and raises a
// WARN when usage crosses the comfort line. inUse is the count of live local
// ports inside the ephemeral range; the range size is the denominator.
func (c *TCPInfoCollector) scoreEphemeral(bus *events.Bus, st *TCPInfoStatus, inUse int, now time.Time) {
	size := c.portHigh - c.portLow + 1
	if size <= 0 {
		return
	}
	util := float64(inUse) / float64(size)
	st.EphemeralUtil = util
	if util < ephemeralComfort {
		return
	}
	st.EphemeralExhaust = true
	if bus == nil {
		return
	}
	key := "ephemeral"
	if t, ok := c.cooldown[key]; ok && now.Before(t) {
		return
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: c.Name(), Time: now,
		Payload: events.AnomalyPayload{
			Severity: string(events.SevWarn),
			Message: fmt.Sprintf("ephemeral ports %.0f%% used (%d/%d) - new outbound connections may start failing",
				util*100, inUse, size),
		},
	})
	c.cooldown[key] = now.Add(2 * time.Minute)
}

// detectAnomalies raises the per-flow RTX-rate WARN and the frag-needed / PMTU
// black-hole signal, each behind a per-flow cooldown so a persistent condition
// doesn't spam the Alerts tab. It returns true when this flow currently shows
// the PMTU black-hole shape (independent of the publish cooldown), so the
// status card and grade reflect the live condition.
func (c *TCPInfoCollector) detectAnomalies(bus *events.Bus, s telemetry.Sample, prev flowCounters, rate float64, th config.Thresholds, now time.Time) bool {
	thresh := th.FlowRetransPct
	if thresh <= 0 {
		thresh = 5
	}

	// PMTU black-hole heuristic: heavy retransmits with ~no new data segments
	// over the window means the connection is wedged - the frag-needed shape.
	dRetrans := int64(s.TotalRetrans) - int64(prev.totalRetrans)
	dSegs := int64(s.SegsOut) - int64(prev.segsOut)
	pmtu := !prev.seen.IsZero() && dRetrans >= 4 && dSegs <= dRetrans

	if bus == nil {
		return pmtu
	}
	key := flowTupleKey(s)
	if t, ok := c.cooldown[key]; ok && now.Before(t) {
		return pmtu
	}

	if pmtu {
		bus.Publish(events.Event{
			Kind: events.KindFragNeeded, Source: c.Name(), Time: now,
			Payload: events.FragNeededPayload{
				SrcIP: s.SrcIP, DstIP: s.DstIP, DstPort: s.DstPort, Suspect: true,
			},
		})
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(), Time: now,
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message: fmt.Sprintf("suspected PMTU black-hole: %s -> %s:%d retransmitting without progress (%d retx, no new data)",
					s.SrcIP, s.DstIP, s.DstPort, dRetrans),
			},
		})
		c.cooldown[key] = now.Add(5 * time.Minute)
		return true
	}

	if rate >= thresh {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(), Time: now,
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message: fmt.Sprintf("flow %s -> %s:%d RTX rate %.1f%% (>= %.1f%%), RTT %.0fms",
					s.SrcIP, s.DstIP, s.DstPort, rate, thresh, float64(s.RTTus)/1000.0),
			},
		})
		c.cooldown[key] = now.Add(2 * time.Minute)
	}
	return false
}

// reportConnectStall publishes an ERROR anomaly for a connection wedged in its
// TCP handshake, behind a per-tuple cooldown so a persistently unreachable host
// doesn't spam the Alerts tab. The SYN-retransmit count comes straight from
// tcp_info and is the smoking gun for a lossy uplink dropping handshake packets.
func (c *TCPInfoCollector) reportConnectStall(bus *events.Bus, s telemetry.Sample, now time.Time) {
	if bus == nil {
		return
	}
	key := "connect:" + flowTupleKey(s)
	if t, ok := c.cooldown[key]; ok && now.Before(t) {
		return
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: c.Name(), Time: now,
		Payload: events.AnomalyPayload{
			Severity: string(events.SevError),
			Message: fmt.Sprintf("connection to %s:%d stuck in handshake (SYN_SENT, %d SYN retransmit(s)) - failing to connect",
				s.DstIP, s.DstPort, s.TotalRetrans),
		},
	})
	c.cooldown[key] = now.Add(2 * time.Minute)
}

// reportSendStall publishes a WARN for a connection frozen with data wedged in
// its send queue (zero-window / send-stall), behind a per-tuple cooldown.
func (c *TCPInfoCollector) reportSendStall(bus *events.Bus, s telemetry.Sample, now time.Time) {
	if bus == nil {
		return
	}
	key := "stall:" + flowTupleKey(s)
	if t, ok := c.cooldown[key]; ok && now.Before(t) {
		return
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: c.Name(), Time: now,
		Payload: events.AnomalyPayload{
			Severity: string(events.SevWarn),
			Message: fmt.Sprintf("connection %s -> %s:%d send-stalled (%d bytes queued, no progress) - peer zero-window or path blocked",
				s.SrcIP, s.DstIP, s.DstPort, s.WQueue),
		},
	})
	c.cooldown[key] = now.Add(2 * time.Minute)
}

// connFailComfort is the per-second rate of failed connects + established
// resets past which we warn. A trickle is normal (every RST-closed socket
// counts); a sustained burst is the "connections keep dropping" fault.
const connFailComfort = 2.0

// scoreConnFailures derives the failed-connect + reset rate from the cumulative
// /proc/net/snmp counters across two samples, folds it into the status, and
// raises an anomaly past the comfort line. Primes silently on the first pass.
func (c *TCPInfoCollector) scoreConnFailures(bus *events.Bus, st *TCPInfoStatus, now time.Time) {
	cur := readTCPResetCounters()
	if !cur.ok {
		return
	}
	prev, prevAt := c.prevReset, c.prevResetAt
	c.prevReset, c.prevResetAt = cur, now
	if !prev.ok || prevAt.IsZero() {
		return // first pass: prime only
	}
	secs := now.Sub(prevAt).Seconds()
	if secs <= 0 {
		return
	}
	// Guard against counter resets (reboot / wrap) producing a negative delta.
	var dFail, dReset uint64
	if cur.attemptFails >= prev.attemptFails {
		dFail = cur.attemptFails - prev.attemptFails
	}
	if cur.estabResets >= prev.estabResets {
		dReset = cur.estabResets - prev.estabResets
	}
	rate := float64(dFail+dReset) / secs
	st.ConnFailRate = rate
	if rate < connFailComfort {
		return
	}
	st.ConnResetSpike = true
	if bus == nil {
		return
	}
	key := "connfail"
	if t, ok := c.cooldown[key]; ok && now.Before(t) {
		return
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: c.Name(), Time: now,
		Payload: events.AnomalyPayload{
			Severity: string(events.SevError),
			Message: fmt.Sprintf("connection failures at %.1f/s (%d refused/failed connects, %d resets over %.0fs)",
				rate, dFail, dReset, secs),
		},
	})
	c.cooldown[key] = now.Add(2 * time.Minute)
}

// flowTupleKey is the directional 5-tuple identity used to track per-flow
// cumulative counters between ticks.
func flowTupleKey(s telemetry.Sample) string {
	return fmt.Sprintf("%s:%d>%s:%d", s.SrcIP, s.SrcPort, s.DstIP, s.DstPort)
}
