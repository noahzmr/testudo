package analyzers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/events"
)

// netopsPoller is the common ticker loop for the system-counter-driven
// detectors below. Each detector implements a poll() function; the loop
// drives it at the configured interval and exits cleanly on ctx.Done.
type netopsPoller struct {
	name     string
	interval time.Duration
	poll     func(ctx context.Context, bus *events.Bus)
}

func (p *netopsPoller) run(ctx context.Context, bus *events.Bus) error {
	if p.interval <= 0 {
		p.interval = 10 * time.Second
	}
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			p.poll(ctx, bus)
		}
	}
}

// FirewallDropDetector watches the kernel's iptables/nftables drop counters
// (via /proc/net/netstat + /proc/net/snmp) and fires when the drop rate over
// the last interval exceeds the threshold.
type FirewallDropDetector struct {
	Interval  time.Duration
	Threshold uint64 // drops per interval before WARN; 4× => CRIT

	mu       sync.Mutex
	lastDrop uint64
	primed   bool
	lastFire time.Time
}

func (d *FirewallDropDetector) Name() string { return "firewall_drops" }

func (d *FirewallDropDetector) Run(ctx context.Context, _ <-chan events.Event, bus *events.Bus) error {
	if d.Threshold == 0 {
		d.Threshold = 100
	}
	p := &netopsPoller{name: d.Name(), interval: d.Interval, poll: d.poll}
	return p.run(ctx, bus)
}

func (d *FirewallDropDetector) poll(_ context.Context, bus *events.Bus) {
	drops := readInputDrops()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.primed {
		d.lastDrop = drops
		d.primed = true
		return
	}
	delta := uint64(0)
	if drops >= d.lastDrop {
		delta = drops - d.lastDrop
	}
	d.lastDrop = drops
	if delta < d.Threshold {
		return
	}
	if !d.lastFire.IsZero() && time.Since(d.lastFire) < 30*time.Second {
		return
	}
	d.lastFire = time.Now()
	sev := events.SevWarn
	if delta >= 4*d.Threshold {
		sev = events.SevCritical
	} else if delta >= 2*d.Threshold {
		sev = events.SevError
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(sev),
			Message:  fmt.Sprintf("firewall dropped %d packets in the last interval (threshold %d)", delta, d.Threshold),
		},
	})
}

// readInputDrops reads the "InNoRoutes" + "InDiscards" + listener overflow
// counters from /proc/net/snmp and /proc/net/netstat. Returns 0 if the
// files can't be read (e.g. running without root).
func readInputDrops() uint64 {
	var total uint64
	total += parseProcCounter("/proc/net/snmp", "Ip:", "InDiscards")
	total += parseProcCounter("/proc/net/netstat", "TcpExt:", "ListenDrops")
	total += parseProcCounter("/proc/net/netstat", "TcpExt:", "ListenOverflows")
	return total
}

// RouteInstabilityDetector watches /proc/net/route for default-route changes
// and fires when the route table flips repeatedly within a short window.
type RouteInstabilityDetector struct {
	Interval time.Duration
	Window   time.Duration // how long the "recent" memory is
	Limit    int           // changes within window before alerting

	mu       sync.Mutex
	last     string
	changes  []time.Time
	lastFire time.Time
}

func (d *RouteInstabilityDetector) Name() string { return "route_instability" }

func (d *RouteInstabilityDetector) Run(ctx context.Context, _ <-chan events.Event, bus *events.Bus) error {
	if d.Window <= 0 {
		d.Window = 2 * time.Minute
	}
	if d.Limit <= 0 {
		d.Limit = 3
	}
	p := &netopsPoller{name: d.Name(), interval: d.Interval, poll: d.poll}
	return p.run(ctx, bus)
}

func (d *RouteInstabilityDetector) poll(_ context.Context, bus *events.Bus) {
	sig := readDefaultRouteSignature()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == "" {
		d.last = sig
		return
	}
	if sig == d.last {
		return
	}
	d.last = sig
	now := time.Now()
	d.changes = append(d.changes, now)
	cutoff := now.Add(-d.Window)
	pruned := d.changes[:0]
	for _, t := range d.changes {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	d.changes = pruned
	if len(d.changes) < d.Limit {
		return
	}
	if !d.lastFire.IsZero() && time.Since(d.lastFire) < d.Window {
		return
	}
	d.lastFire = now
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(events.SevError),
			Message:  fmt.Sprintf("default route changed %d× in the last %s", len(d.changes), d.Window),
		},
	})
}

// readDefaultRouteSignature returns a stable string for the current default
// gateway. Two snapshots with different signatures imply the default route
// flipped.
func readDefaultRouteSignature() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	var sig strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Default route has Destination=00000000.
		if fields[1] != "00000000" {
			continue
		}
		sig.WriteString(fields[0])
		sig.WriteByte('|')
		sig.WriteString(fields[2])
		sig.WriteByte(';')
	}
	return sig.String()
}

// BandwidthSpikeDetector watches /proc/net/dev byte counters and fires when
// the per-interval throughput on any interface exceeds the baseline factor.
type BandwidthSpikeDetector struct {
	Interval time.Duration
	Factor   float64 // 3.0 means "3× the rolling baseline"
	Window   int     // baseline window size

	mu       sync.Mutex
	primed   bool
	last     map[string]ifaceCounter
	history  map[string][]float64 // rolling per-iface throughput (B/s)
	lastFire map[string]time.Time
}

type ifaceCounter struct {
	RxBytes, TxBytes uint64
	TS               time.Time
}

func (d *BandwidthSpikeDetector) Name() string { return "bandwidth_spike" }

func (d *BandwidthSpikeDetector) Run(ctx context.Context, _ <-chan events.Event, bus *events.Bus) error {
	if d.Factor <= 0 {
		d.Factor = 3.0
	}
	if d.Window <= 0 {
		d.Window = 12
	}
	d.last = map[string]ifaceCounter{}
	d.history = map[string][]float64{}
	d.lastFire = map[string]time.Time{}
	p := &netopsPoller{name: d.Name(), interval: d.Interval, poll: d.poll}
	return p.run(ctx, bus)
}

func (d *BandwidthSpikeDetector) poll(_ context.Context, bus *events.Bus) {
	current := readDevCounters()
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.primed {
		d.last = current
		d.primed = true
		return
	}
	for iface, c := range current {
		prev, ok := d.last[iface]
		if !ok {
			continue
		}
		dt := c.TS.Sub(prev.TS).Seconds()
		if dt <= 0 {
			continue
		}
		bytes := uint64(0)
		if c.RxBytes >= prev.RxBytes && c.TxBytes >= prev.TxBytes {
			bytes = (c.RxBytes - prev.RxBytes) + (c.TxBytes - prev.TxBytes)
		}
		rate := float64(bytes) / dt
		hist := d.history[iface]
		if len(hist) >= d.Window {
			var sum float64
			for _, v := range hist {
				sum += v
			}
			baseline := sum / float64(len(hist))
			if baseline > 0 && rate > d.Factor*baseline {
				last := d.lastFire[iface]
				if last.IsZero() || time.Since(last) > 60*time.Second {
					d.lastFire[iface] = now
					sev := events.SevWarn
					if rate > 8*baseline {
						sev = events.SevError
					}
					bus.Publish(events.Event{
						Kind: events.KindAnomaly, Source: d.Name(),
						Payload: events.AnomalyPayload{
							Severity: string(sev),
							Message: fmt.Sprintf(
								"bandwidth spike on %s: %.1f MB/s (baseline %.1f MB/s, factor %.1fx)",
								iface, rate/1e6, baseline/1e6, rate/baseline,
							),
						},
					})
				}
			}
		}
		hist = append(hist, rate)
		if len(hist) > d.Window {
			hist = hist[1:]
		}
		d.history[iface] = hist
	}
	d.last = current
}

func readDevCounters() map[string]ifaceCounter {
	out := map[string]ifaceCounter{}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return out
	}
	now := time.Now()
	for i, line := range strings.Split(string(data), "\n") {
		if i < 2 {
			continue // headers
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		out[name] = ifaceCounter{RxBytes: rx, TxBytes: tx, TS: now}
	}
	return out
}

// NATExhaustionDetector watches /proc/sys/net/netfilter/nf_conntrack_count
// vs /proc/sys/net/netfilter/nf_conntrack_max and fires when occupancy
// crosses warning / critical thresholds.
type NATExhaustionDetector struct {
	Interval  time.Duration
	WarnRatio float64 // 0.80 => WARN at 80%
	CritRatio float64 // 0.95 => CRIT at 95%

	mu       sync.Mutex
	lastFire time.Time
}

func (d *NATExhaustionDetector) Name() string { return "nat_exhaustion" }

func (d *NATExhaustionDetector) Run(ctx context.Context, _ <-chan events.Event, bus *events.Bus) error {
	if d.WarnRatio <= 0 {
		d.WarnRatio = 0.80
	}
	if d.CritRatio <= 0 {
		d.CritRatio = 0.95
	}
	p := &netopsPoller{name: d.Name(), interval: d.Interval, poll: d.poll}
	return p.run(ctx, bus)
}

func (d *NATExhaustionDetector) poll(_ context.Context, bus *events.Bus) {
	count := readUint64File("/proc/sys/net/netfilter/nf_conntrack_count")
	max := readUint64File("/proc/sys/net/netfilter/nf_conntrack_max")
	if max == 0 {
		return
	}
	ratio := float64(count) / float64(max)
	if ratio < d.WarnRatio {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.lastFire.IsZero() && time.Since(d.lastFire) < 60*time.Second {
		return
	}
	d.lastFire = time.Now()
	sev := events.SevWarn
	if ratio >= d.CritRatio {
		sev = events.SevCritical
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(sev),
			Message:  fmt.Sprintf("conntrack table %.0f%% full (%d / %d)", ratio*100, count, max),
		},
	})
}

// RetransmissionDetector watches the kernel TCP retransmission counter
// (/proc/net/snmp Tcp: RetransSegs vs OutSegs) and fires when the
// per-interval retransmission rate exceeds Settings.RetransmissionsPct.
type RetransmissionDetector struct {
	Settings *config.SettingsStore
	Interval time.Duration

	mu          sync.Mutex
	lastRetrans uint64
	lastOut     uint64
	primed      bool
	lastFire    time.Time
}

func (d *RetransmissionDetector) Name() string { return "retransmissions" }

func (d *RetransmissionDetector) Run(ctx context.Context, _ <-chan events.Event, bus *events.Bus) error {
	p := &netopsPoller{name: d.Name(), interval: d.Interval, poll: d.poll}
	return p.run(ctx, bus)
}

func (d *RetransmissionDetector) poll(_ context.Context, bus *events.Bus) {
	retrans := parseProcCounter("/proc/net/snmp", "Tcp:", "RetransSegs")
	out := parseProcCounter("/proc/net/snmp", "Tcp:", "OutSegs")
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.primed {
		d.lastRetrans = retrans
		d.lastOut = out
		d.primed = true
		return
	}
	dRetrans := uint64(0)
	dOut := uint64(0)
	if retrans >= d.lastRetrans {
		dRetrans = retrans - d.lastRetrans
	}
	if out >= d.lastOut {
		dOut = out - d.lastOut
	}
	d.lastRetrans = retrans
	d.lastOut = out
	if dOut < 100 {
		return // not enough traffic to judge
	}
	rate := float64(dRetrans) / float64(dOut) * 100
	thresh := d.Settings.Snapshot().RetransmissionsPct
	if rate < thresh {
		return
	}
	if !d.lastFire.IsZero() && time.Since(d.lastFire) < 60*time.Second {
		return
	}
	d.lastFire = time.Now()
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(escalate(rate, thresh)),
			Message: fmt.Sprintf(
				"TCP retransmissions at %.1f%% (%d / %d) - threshold %.0f%%",
				rate, dRetrans, dOut, thresh,
			),
		},
	})
}

// parseProcCounter reads the named counter from /proc-style files whose
// format is a "header line" of field names followed by a "value line" of
// numeric values, e.g.:
//
//	Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens ... RetransSegs ...
//	Tcp: 1 200 120000 -1 18 4 ... 12345 ...
func parseProcCounter(path, prefix, field string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	var headerIdx int = -1
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			if headerIdx == -1 {
				headerIdx = i
				continue
			}
			// Value line.
			headerFields := strings.Fields(lines[headerIdx])
			valueFields := strings.Fields(line)
			if len(headerFields) != len(valueFields) {
				return 0
			}
			for j := 1; j < len(headerFields); j++ {
				if headerFields[j] == field {
					v, _ := strconv.ParseUint(valueFields[j], 10, 64)
					return v
				}
			}
			return 0
		}
	}
	return 0
}

func readUint64File(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return v
}
