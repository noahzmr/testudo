// Package engine wires collectors, analyzers, storage, correlation, and
// the metric/flow aggregators behind a single Start/Stop lifecycle.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/analyzers"
	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/incidents"
	"github.com/noahzmr/testudo/internal/ipfix"
	"github.com/noahzmr/testudo/internal/metrics"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/storage"
)

type Engine struct {
	cfg       config.Config
	bus       *events.Bus
	agg       *metrics.Aggregator
	bw        *metrics.BandwidthHistory
	flowAgg   *flows.Aggregator
	deviceBW  *flows.DeviceBandwidth
	dnsCache  *flows.DNSCache
	procMatch *flows.ProcMatcher
	tagger    *flows.Tagger
	ring      *capture.RingBuffer
	tcpdump   *capture.TCPDumpManager
	ipfixMgr  *ipfix.Manager
	settings  *config.SettingsStore
	netops    *netops.Writer
	incidents *incidents.Engine
	inventory *discovery.Inventory
	store     *storage.Store
	wifi      *collectors.WiFiCollector
	neigh     *collectors.NeighConntrackCollector
	netwatch  *collectors.NetlinkWatchCollector
	sessionID string

	// fwTrack derives a DROP/REJECT velocity from successive firewall-rule
	// counter snapshots (see snapshotter.go). The grade reads it via
	// FirewallSignal; updates happen on the snapshot ticker.
	fwTrack fwRuleTracker

	// flowsCache holds the most recent decorated-flow snapshot. The TUI
	// reads it on every render; a background goroutine refreshes it once
	// per second so the render path never pays for /proc reads.
	flowsCacheMu sync.RWMutex
	flowsCache   []flows.FlowStats

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Capture lifecycle is independent of the engine root context so the
	// TUI can toggle it without restarting collectors / analyzers.
	rootCtx       context.Context
	captureMu     sync.Mutex
	captureCancel context.CancelFunc
	captureWG     sync.WaitGroup
	captureIfaces []string
}

// New wires the engine. settings must already be loaded; nw is optional
// (may be nil if netops are unavailable).
func New(cfg config.Config, store *storage.Store, settings *config.SettingsStore, nw *netops.Writer) *Engine {
	return &Engine{
		cfg:       cfg,
		bus:       events.NewBus(2048),
		agg:       metrics.NewAggregator(),
		bw:        metrics.NewBandwidthHistory(120),
		flowAgg:   flows.NewAggregator(),
		deviceBW:  flows.NewDeviceBandwidth(5*time.Second, 120),
		dnsCache:  flows.NewDNSCache(),
		procMatch: flows.NewProcMatcher(),
		tagger:    flows.NewTagger(),
		ring:      capture.NewRingBuffer(4096),
		settings:  settings,
		netops:    nw,
		inventory: discovery.NewInventory(),
		store:     store,
	}
}

func (e *Engine) Bus() *events.Bus                        { return e.bus }
func (e *Engine) Aggregator() *metrics.Aggregator         { return e.agg }
func (e *Engine) Bandwidth() *metrics.BandwidthHistory    { return e.bw }
func (e *Engine) Flows() *flows.Aggregator                { return e.flowAgg }
func (e *Engine) DeviceBandwidth() *flows.DeviceBandwidth { return e.deviceBW }
func (e *Engine) DNSCache() *flows.DNSCache               { return e.dnsCache }
func (e *Engine) ProcMatcher() *flows.ProcMatcher         { return e.procMatch }
func (e *Engine) Tagger() *flows.Tagger                   { return e.tagger }
func (e *Engine) Ring() *capture.RingBuffer               { return e.ring }
func (e *Engine) TCPDump() *capture.TCPDumpManager {
	if e.tcpdump == nil {
		e.tcpdump = capture.NewTCPDumpManager(
			e.cfg.StorageDir+"/captures", e.sessionID,
		)
	}
	return e.tcpdump
}
func (e *Engine) Settings() *config.SettingsStore { return e.settings }
func (e *Engine) Netops() *netops.Writer          { return e.netops }
func (e *Engine) Inventory() *discovery.Inventory { return e.inventory }
func (e *Engine) Store() *storage.Store           { return e.store }
func (e *Engine) SessionID() string               { return e.sessionID }
func (e *Engine) Config() config.Config           { return e.cfg }

// WiFi returns the WiFi collector so the TUI / Web UI can read the
// rich per-interface snapshot (SSID, BSSID, frequency, bitrate,
// txpower, etc.). Returns nil when WiFi monitoring is disabled in
// config — callers must nil-check before invoking Snapshot.
func (e *Engine) WiFi() *collectors.WiFiCollector { return e.wifi }

// Neigh returns the neighbour/conntrack collector so the TUI and Web UI can
// read the cached ARP/NDP table, IP conflicts, and live conntrack flows from
// one source. Returns nil when the collector is disabled or netops are
// unavailable — callers must nil-check.
func (e *Engine) Neigh() *collectors.NeighConntrackCollector { return e.neigh }

// NetlinkWatch returns the RTNETLINK push watcher so the TUI and Web UI can
// read its live/polled status and the flap-rate / route-churn signal. Returns
// nil when the watcher is disabled or netops are unavailable - callers must
// nil-check.
func (e *Engine) NetlinkWatch() *collectors.NetlinkWatchCollector { return e.netwatch }

// FirewallSignal returns the current DROP/REJECT velocity (drops per second
// across managed blocking rules) and whether any counted blocking rule
// exists. hasDropRules=false maps to a neutral firewall sub-score so hosts
// without managed DROP rules aren't penalised.
func (e *Engine) FirewallSignal() (dropRate float64, hasDropRules bool) {
	return e.fwTrack.signal()
}

// Start begins capture. The session row is created immediately; collectors
// and analyzers run in background goroutines until Stop is called.
func (e *Engine) Start(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	e.cancel = cancel
	e.rootCtx = ctx

	e.sessionID = newSessionID()
	targets := append([]string{}, e.cfg.ICMPTargets...)
	if err := e.store.StartSession(ctx, e.sessionID, targets, ""); err != nil {
		cancel()
		return fmt.Errorf("start session: %w", err)
	}

	e.incidents = incidents.New(e.store, e.flowAgg, e.cfg.StorageDir, e.cfg.Thresholds.IncidentCooldown)

	e.startMetricsAndStorageConsumer(ctx)
	e.startAnalyzers(ctx)
	e.startIncidentEngine(ctx)
	e.startCollectorsNonCapture(ctx)
	// Once the neighbour/conntrack collector exists, let incident bundles
	// fold in a live conntrack snapshot.
	if e.neigh != nil {
		e.incidents.SetConntrackProvider(func() any { return e.neigh.Conntrack() })
	}
	if e.cfg.CaptureEnabled {
		_ = e.StartCapture(e.cfg.CaptureIfaces)
	}
	if e.cfg.DiscoveryEnabled {
		e.startDiscovery(ctx)
	}
	e.startSnapshotter(ctx)
	e.startDownsampler(ctx)
	if e.cfg.PCAPMaxSize > 0 {
		e.startPCAPWriter(ctx)
	}
	e.startIPFIX(ctx)
	e.startBandwidthPoller(ctx)
	e.startDeviceBandwidthSampler(ctx)
	return nil
}

// startDeviceBandwidthSampler periodically folds the flow aggregator
// into per-LAN-device byte buckets. The cadence matches the configured
// bucket width so each tick produces one bucket of data; faster ticks
// would just accumulate into the same bucket.
func (e *Engine) startDeviceBandwidthSampler(ctx context.Context) {
	if e.deviceBW == nil || e.flowAgg == nil {
		return
	}
	interval := e.deviceBW.BucketSizeDuration()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				e.deviceBW.Sample(e.flowAgg.Snapshot(), now)
			}
		}
	}()
}

// startBandwidthPoller samples kernel interface counters once per second
// and feeds the BandwidthHistory. Cheap - netlink LinkList + iface byte
// counters; the result drives the dashboard's live bandwidth chart.
func (e *Engine) startBandwidthPoller(ctx context.Context) {
	if e.netops == nil || e.bw == nil {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		sample := func() {
			ifs, err := e.netops.ListIfaces()
			if err != nil {
				return
			}
			for _, ifi := range ifs {
				// Skip loopback so the chart isn't dominated by lo's
				// internal traffic on a quiet machine.
				if strings.EqualFold(ifi.Name, "lo") {
					continue
				}
				e.bw.Update(ifi.Name, ifi.RxBytes, ifi.TxBytes)
			}
		}
		sample()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sample()
			}
		}
	}()
}

// startIPFIX runs the IPFIX exporter manager. It does its own reconcile
// against the live SettingsStore on a 5-second cadence, so toggling the
// "ipfix enabled" / "ipfix endpoint" fields in the Settings tab takes
// effect without a restart.
func (e *Engine) startIPFIX(ctx context.Context) {
	if e.flowAgg == nil || e.settings == nil {
		return
	}
	e.ipfixMgr = ipfix.NewManager(e.settings, e.flowAgg)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		_ = e.ipfixMgr.Run(ctx)
	}()
}

// IPFIX returns the live IPFIX manager (may be nil if the engine hasn't
// started yet). Useful for status panels in the Settings tab.
func (e *Engine) IPFIX() *ipfix.Manager { return e.ipfixMgr }

// StartCapture spawns the capture multi-iface worker plus its companion
// loops (flow flusher, /proc refresher, decorator). Idempotent - returns
// nil when capture is already running.
//
// Pass an empty ifaces slice to use auto-discovery (the default in cfg).
func (e *Engine) StartCapture(ifaces []string) error {
	e.captureMu.Lock()
	if e.captureCancel != nil {
		e.captureMu.Unlock()
		return nil
	}
	if e.rootCtx == nil {
		e.captureMu.Unlock()
		return fmt.Errorf("engine not started")
	}
	ctx, cancel := context.WithCancel(e.rootCtx)
	e.captureCancel = cancel
	e.captureIfaces = append([]string(nil), ifaces...)
	e.captureMu.Unlock()

	multi := &capture.Multi{
		Ifaces: ifaces,
		Flows:  e.flowAgg,
		Ring:   e.ring,
	}
	e.captureWG.Add(1)
	go func() {
		defer e.captureWG.Done()
		if err := multi.Run(ctx, e.bus); err != nil {
			log.Printf("capture exited: %v", err)
		}
	}()
	e.captureWG.Add(1)
	go func() {
		defer e.captureWG.Done()
		e.flowFlusherLoop(ctx)
	}()
	e.captureWG.Add(1)
	go func() {
		defer e.captureWG.Done()
		e.procRefresherLoop(ctx)
	}()
	e.captureWG.Add(1)
	go func() {
		defer e.captureWG.Done()
		e.flowDecoratorLoop(ctx)
	}()
	e.bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: "capture-control",
		Payload: events.AnomalyPayload{
			Severity: string(events.SevInfo),
			Message:  "flow capture started",
		},
	})
	return nil
}

// StopCapture cancels the capture context and waits for the workers to
// drain. Safe to call when capture is not running.
func (e *Engine) StopCapture() {
	e.captureMu.Lock()
	cancel := e.captureCancel
	e.captureCancel = nil
	e.captureIfaces = nil
	e.captureMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	e.captureWG.Wait()
	e.bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: "capture-control",
		Payload: events.AnomalyPayload{
			Severity: string(events.SevInfo),
			Message:  "flow capture stopped",
		},
	})
}

// IsCaptureRunning reports whether a capture window is currently active.
func (e *Engine) IsCaptureRunning() bool {
	e.captureMu.Lock()
	defer e.captureMu.Unlock()
	return e.captureCancel != nil
}

// CaptureIfaces returns the interface set the active capture was started
// with. Empty slice means "auto-discover".
func (e *Engine) CaptureIfaces() []string {
	e.captureMu.Lock()
	defer e.captureMu.Unlock()
	out := make([]string, len(e.captureIfaces))
	copy(out, e.captureIfaces)
	return out
}

// startPCAPWriter wires the rotated PCAP capture: it consumes anomalies from
// the bus, and on any ERROR/CRITICAL event opens a 60-second capture window
// that drains the live ring buffer to disk under storage/captures/<session>/.
func (e *Engine) startPCAPWriter(ctx context.Context) {
	captureDir := e.cfg.StorageDir + "/captures"
	w := capture.NewPCAPWriter(captureDir, e.sessionID, e.cfg.PCAPMaxSize, e.ring)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		w.Run(ctx)
	}()
	sub := e.bus.SubscribeKinds(events.KindAnomaly)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-sub.C():
				if !ok {
					return
				}
				p, ok := ev.Payload.(events.AnomalyPayload)
				if !ok {
					continue
				}
				sev := events.Severity(p.Severity)
				if events.SeverityRank(sev) < events.SeverityRank(events.SevError) {
					continue
				}
				_ = w.Trigger(60 * time.Second)
			}
		}
	}()
}

// startDownsampler periodically compacts older samples into N-minute buckets
// and prunes anything past the retention horizon. Default: keep 30 days raw,
// compact anything older than 24h into 5-minute buckets.
func (e *Engine) startDownsampler(ctx context.Context) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		run := func() {
			_ = e.store.DownsampleSamples(ctx, 30*24*time.Hour, 24*time.Hour, 5*time.Minute)
		}
		run()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
}

// Stop cancels all goroutines and finalises the session row. Safe to call
// multiple times.
func (e *Engine) Stop(ctx context.Context) error {
	e.StopCapture()
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.wg.Wait()
	if e.sessionID != "" {
		// Final flow flush so on-disk counts match the last in-memory state.
		e.flushFlows(ctx)
		if err := e.store.EndSession(ctx, e.sessionID); err != nil {
			return err
		}
	}
	return nil
}

// startCollectorsNonCapture starts the always-on collectors (ICMP, DNS).
// Capture is intentionally NOT started here - its lifecycle is driven by
// StartCapture / StopCapture so the TUI can toggle it at runtime.
func (e *Engine) startCollectorsNonCapture(ctx context.Context) {
	cs := []collectors.Collector{
		&collectors.ICMPCollector{
			Targets:  e.cfg.ICMPTargets,
			Interval: e.cfg.ICMPInterval,
			Timeout:  e.cfg.ICMPTimeout,
		},
		&collectors.DNSCollector{
			Names:    e.cfg.DNSNames,
			Interval: e.cfg.DNSInterval,
			Timeout:  e.cfg.DNSTimeout,
		},
	}
	if e.cfg.TopTalkersEnabled && e.flowAgg != nil {
		cs = append(cs, &collectors.TopTalkersCollector{
			Flows:    e.flowAgg,
			Interval: e.cfg.TopTalkersInterval,
			Timeout:  e.cfg.TopTalkersTimeout,
			MaxHosts: e.cfg.TopTalkersMaxHosts,
		})
	}
	if e.cfg.IfaceHealthEnabled && e.netops != nil {
		cs = append(cs, &collectors.IfaceHealthCollector{
			Netops:   e.netops,
			Interval: e.cfg.IfaceHealthInterval,
		})
	}
	if e.cfg.DNSInternalEnabled {
		cs = append(cs, &collectors.InternalDNSCollector{
			Servers:  e.cfg.DNSInternalServers,
			Names:    e.cfg.DNSNames,
			Interval: e.cfg.DNSInterval,
			Timeout:  e.cfg.DNSTimeout,
		})
	}
	// HTTP and TLS targets fall back to DNSNames when not configured -
	// gives an out-of-the-box health view that exercises the same set of
	// names the DNS probe already trusts, without forcing the operator
	// to populate two more config slices.
	httpEndpoints := e.cfg.HTTPEndpoints
	if len(httpEndpoints) == 0 {
		for _, name := range e.cfg.DNSNames {
			n := strings.TrimSpace(name)
			if n == "" {
				continue
			}
			httpEndpoints = append(httpEndpoints, "https://"+n+"/")
		}
	}
	if len(httpEndpoints) > 0 {
		cs = append(cs, &collectors.HTTPEndpointCollector{
			Endpoints: httpEndpoints,
			Interval:  e.cfg.HTTPInterval,
			Timeout:   e.cfg.HTTPTimeout,
		})
	}
	tlsTargets := e.cfg.TLSCertTargets
	if len(tlsTargets) == 0 {
		for _, name := range e.cfg.DNSNames {
			n := strings.TrimSpace(name)
			if n == "" {
				continue
			}
			tlsTargets = append(tlsTargets, n+":443")
		}
	}
	if len(tlsTargets) > 0 {
		cs = append(cs, &collectors.TLSCertCollector{
			Targets:  tlsTargets,
			Interval: e.cfg.TLSCertInterval,
			WarnDays: e.cfg.TLSCertWarnDays,
			CritDays: e.cfg.TLSCertCritDays,
		})
	}
	if e.cfg.TracerouteEnabled {
		targets := e.cfg.TracerouteTargets
		if len(targets) == 0 {
			targets = e.cfg.ICMPTargets
		}
		cs = append(cs, &collectors.TracerouteCollector{
			Targets:  targets,
			Interval: e.cfg.TracerouteInterval,
			MaxHops:  e.cfg.TracerouteHops,
		})
	}
	if e.cfg.BufferbloatEnabled {
		target := e.cfg.BufferbloatTarget
		if target == "" && len(e.cfg.ICMPTargets) > 0 {
			target = e.cfg.ICMPTargets[0]
		}
		cs = append(cs, &collectors.BufferbloatCollector{
			Target:   target,
			LoadURL:  e.cfg.BufferbloatLoadURL,
			Interval: e.cfg.BufferbloatInterval,
			Duration: e.cfg.BufferbloatDuration,
			Timeout:  e.cfg.ICMPTimeout,
		})
	}
	if e.cfg.WiFiEnabled {
		e.wifi = &collectors.WiFiCollector{
			Interval:  e.cfg.WiFiInterval,
			MinSignal: e.cfg.WiFiMinSignal,
		}
		cs = append(cs, e.wifi)
	}
	if e.cfg.LANReachEnabled && e.inventory != nil {
		cs = append(cs, &collectors.LANReachabilityCollector{
			Inventory: e.inventory,
			Interval:  e.cfg.LANReachInterval,
		})
	}
	if (e.cfg.NeighbourEnabled || e.cfg.ConntrackEnabled) && e.netops != nil {
		neighInt := e.cfg.NeighbourInterval
		if !e.cfg.NeighbourEnabled {
			neighInt = 0
		}
		ctInt := e.cfg.ConntrackInterval
		if !e.cfg.ConntrackEnabled {
			ctInt = 0
		}
		e.neigh = &collectors.NeighConntrackCollector{
			Netops:            e.netops,
			NeighInterval:     neighInt,
			ConntrackInterval: ctInt,
			ConntrackMaxRows:  e.cfg.ConntrackMaxRows,
		}
		cs = append(cs, e.neigh)
	}
	if e.cfg.NetlinkWatchEnabled && e.netops != nil {
		e.netwatch = &collectors.NetlinkWatchCollector{
			Netops:            e.netops,
			CoalesceWindow:    e.cfg.NetlinkWatchCoalesceWindow,
			ReconcileInterval: e.cfg.NetlinkWatchReconcileInterval,
		}
		cs = append(cs, e.netwatch)
	}
	if e.cfg.L2Enabled && e.netops != nil {
		cs = append(cs, &collectors.L2Collector{
			Netops:             e.netops,
			Interval:           e.cfg.L2Interval,
			MulticastThreshold: e.cfg.L2MulticastThreshold,
		})
	}
	for _, c := range cs {
		c := c
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := c.Run(ctx, e.bus); err != nil {
				log.Printf("collector %s exited: %v", c.Name(), err)
				e.bus.Publish(events.Event{
					Kind: events.KindAnomaly, Source: c.Name(),
					Payload: events.AnomalyPayload{
						Severity: string(events.SevError),
						Message:  fmt.Sprintf("%s collector failed: %v", c.Name(), err),
					},
				})
			}
		}()
	}
}

func (e *Engine) startAnalyzers(ctx context.Context) {
	// Each analyzer subscribes only to the event kinds it consumes. Without
	// kind filtering, capture's per-packet stream would wake every analyzer
	// just to discard the event - pure overhead at scale.
	type analyzerSpec struct {
		a     analyzers.Analyzer
		kinds []events.Kind
	}
	specs := []analyzerSpec{
		{&analyzers.PacketLossDetector{Settings: e.settings, Window: 20, CoolDown: 30 * time.Second},
			[]events.Kind{events.KindLatency, events.KindPacketLoss}},
		{&analyzers.HighRTTDetector{Settings: e.settings, CoolDown: 20 * time.Second},
			[]events.Kind{events.KindLatency}},
		{&analyzers.LatencySpikeDetector{Settings: e.settings, Window: 30, Factor: 3.0, CoolDown: 20 * time.Second},
			[]events.Kind{events.KindLatency}},
		{&analyzers.JitterSpikeDetector{Settings: e.settings, Window: 20, CoolDown: 60 * time.Second},
			[]events.Kind{events.KindLatency}},
		{&analyzers.HighDNSLatencyDetector{Settings: e.settings, CoolDown: 20 * time.Second},
			[]events.Kind{events.KindDNSResult, events.KindDNSFailure}},
		{&analyzers.DNSBurstDetector{Window: 10, Threshold: 0.30, CoolDown: 30 * time.Second},
			[]events.Kind{events.KindDNSResult, events.KindDNSFailure}},
		// Tick-driven detectors that poll /proc and netlink directly.
		// They consume no events but still receive a (closed) subscription
		// so the analyzer dispatcher uniformly waits for them on shutdown.
		{&analyzers.FirewallDropDetector{Interval: 10 * time.Second, Threshold: 100},
			[]events.Kind{}},
		{&analyzers.RouteInstabilityDetector{Interval: 15 * time.Second, Window: 2 * time.Minute, Limit: 3},
			[]events.Kind{}},
		{&analyzers.BandwidthSpikeDetector{Interval: 5 * time.Second, Factor: 3.0, Window: 12},
			[]events.Kind{}},
		{&analyzers.NATExhaustionDetector{Interval: 30 * time.Second, WarnRatio: 0.80, CritRatio: 0.95},
			[]events.Kind{}},
		{&analyzers.RetransmissionDetector{Settings: e.settings, Interval: 20 * time.Second},
			[]events.Kind{}},
	}
	if e.cfg.DeviceChatterEnabled && e.deviceBW != nil {
		specs = append(specs, analyzerSpec{
			a: &analyzers.DeviceChatterDetector{
				Bandwidth: e.deviceBW,
				Interval:  15 * time.Second,
				Factor:    e.cfg.DeviceChatterFactor,
			},
			kinds: []events.Kind{},
		})
	}
	for _, spec := range specs {
		spec := spec
		sub := e.bus.SubscribeKinds(spec.kinds...)
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer sub.Close()
			_ = spec.a.Run(ctx, sub.C(), e.bus)
		}()
	}
}

func (e *Engine) startIncidentEngine(ctx context.Context) {
	sub := e.bus.SubscribeKinds(events.KindAnomaly)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer sub.Close()
		_ = e.incidents.Run(ctx, e.sessionID, sub.C(), e.bus)
	}()
}

// flowFlusherLoop writes the in-memory flow table to SQLite on a fixed
// cadence. Per-packet writes would crush I/O; periodic upsert preserves
// replay fidelity at a fraction of the cost. Runs until ctx ends - the
// caller owns the goroutine lifecycle.
func (e *Engine) flowFlusherLoop(ctx context.Context) {
	interval := e.cfg.FlowFlushInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.flushFlows(ctx)
		}
	}
}

func (e *Engine) flushFlows(ctx context.Context) {
	snap := e.flowAgg.Snapshot()
	decorated := flows.Decorate(snap, e.dnsCache, e.procMatch)
	tagged := e.tagger.Tag(decorated)
	for _, f := range tagged {
		// Project through the documented FlowSummary type, then map onto
		// the storage row. Keeps the persistence schema in lockstep with
		// the spec.
		sum := f.Summarize()
		_ = e.store.UpsertFlow(ctx, e.sessionID, storage.FlowRow{
			Iface: f.Key.Iface,
			AIP:   f.Key.A.IP, APort: f.Key.A.Port,
			BIP: f.Key.B.IP, BPort: f.Key.B.Port,
			Proto:     sum.Protocol,
			Packets:   f.Packets,
			Bytes:     f.Bytes,
			BytesAtoB: sum.BytesOut,
			BytesBtoA: sum.BytesIn,
			FirstSeen: f.FirstSeen,
			LastSeen:  f.LastSeen,
			Process:   sum.ProcessName,
			DNSName:   sum.DNSName,
		})
	}
}

// startDiscovery runs the active scanner (ARP/ICMP/mDNS/SNMP), the
// passive LLDP listener, and a periodic flush of the inventory to SQLite.
func (e *Engine) startDiscovery(ctx context.Context) {
	scanner := &discovery.Scanner{
		Inventory:     e.inventory,
		Interval:      e.cfg.DiscoveryInterval,
		Active:        e.cfg.DiscoveryActive,
		MaxSubnetBits: e.cfg.DiscoveryMaxSubnetBits,
		SNMPCommunity: e.cfg.SNMPCommunity,
		SNMPTimeout:   e.cfg.SNMPTimeout,
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		_ = scanner.Run(ctx, e.bus)
	}()
	if e.cfg.LLDPEnabled {
		lldp := &discovery.LLDPListener{Inventory: e.inventory}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			_ = lldp.Run(ctx)
		}()
	}
	// Periodic devices-table flush.
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				e.flushDevices(context.Background())
				return
			case <-ticker.C:
				e.flushDevices(ctx)
			}
		}
	}()
}

func (e *Engine) flushDevices(ctx context.Context) {
	if e.inventory == nil {
		return
	}
	for _, d := range e.inventory.Snapshot() {
		_ = e.store.UpsertDevice(ctx, storage.DeviceRow{
			IP: d.IP, MAC: d.MAC, Hostname: d.Hostname, Vendor: d.Vendor,
			Iface: d.Iface, OSHint: d.OSHint, Source: d.Source,
			FirstSeen: d.FirstSeen, LastSeen: d.LastSeen,
			OpenPorts: joinPorts(d.OpenPorts),
			Services:  strings.Join(d.Services, ","),
		})
	}
}

func joinPorts(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ",")
}

// procRefresherLoop repopulates the proc-socket index so DecorateFlows can
// attach process names without scanning /proc on every render tick. Refresh
// is *expensive* - it readlinks every fd of every /proc/<pid> - so we run
// it at a slow cadence. Per-render flow correlation reads the cached map
// under a short RLock and never touches the filesystem.
func (e *Engine) procRefresherLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	e.procMatch.Refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.procMatch.Refresh()
		}
	}
}

// DecoratedFlows returns a defensively-copied slice of the most-recent flow
// snapshot with process / DNS / service correlation applied. The result is
// cached and refreshed on a slow ticker - render code can call this at any
// rate without paying for /proc reads or service lookups on the hot path.
func (e *Engine) DecoratedFlows(limit int) []flows.FlowStats {
	e.flowsCacheMu.RLock()
	defer e.flowsCacheMu.RUnlock()
	if limit > 0 && len(e.flowsCache) > limit {
		out := make([]flows.FlowStats, limit)
		copy(out, e.flowsCache[:limit])
		return out
	}
	out := make([]flows.FlowStats, len(e.flowsCache))
	copy(out, e.flowsCache)
	return out
}

// flowDecoratorLoop periodically rebuilds the DecoratedFlows cache from the
// live aggregator. One decorate per second covers the dashboard and the
// Flows tab - every TUI render after that reads the cached slice.
func (e *Engine) flowDecoratorLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	rebuild := func() {
		snap := e.flowAgg.TopByRecency(200)
		dec := flows.Decorate(snap, e.dnsCache, e.procMatch)
		e.flowsCacheMu.Lock()
		e.flowsCache = dec
		e.flowsCacheMu.Unlock()
	}
	rebuild()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rebuild()
		}
	}
}

// startMetricsAndStorageConsumer subscribes to the metric-bearing event
// kinds (latency, DNS, packet-loss, anomalies). Flow updates are NOT on
// this list - capture writes the flow aggregator directly to avoid
// running every packet through the channel fan-out.
func (e *Engine) startMetricsAndStorageConsumer(ctx context.Context) {
	sub := e.bus.SubscribeKinds(
		events.KindLatency, events.KindPacketLoss,
		events.KindDNSResult, events.KindDNSFailure,
		events.KindAnomaly,
		events.KindLinkStateChange, events.KindAddrChange, events.KindRouteChange,
	)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer sub.Close()
		in := sub.C()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				e.applyEvent(ctx, ev)
			}
		}
	}()
}

func (e *Engine) applyEvent(ctx context.Context, ev events.Event) {
	switch ev.Kind {
	case events.KindLatency:
		p, ok := ev.Payload.(events.LatencyPayload)
		if !ok {
			return
		}
		e.agg.RecordLatency(p.Target, p.RTT)
		_ = e.store.InsertSample(ctx, e.sessionID, storage.Sample{
			Kind: "latency", Label: p.Target,
			Value: float64(p.RTT.Microseconds()), TS: ev.Time,
		})
	case events.KindPacketLoss:
		p, ok := ev.Payload.(events.PacketLossPayload)
		if !ok {
			return
		}
		e.agg.RecordLoss(p.Target)
		_ = e.store.InsertSample(ctx, e.sessionID, storage.Sample{
			Kind: "packet_loss", Label: p.Target,
			Value: p.LossPct, Failed: true, TS: ev.Time,
		})
	case events.KindDNSResult:
		p, ok := ev.Payload.(events.DNSResultPayload)
		if !ok {
			return
		}
		e.agg.RecordDNS(p.Name, p.Duration, false)
		// Seed the reverse cache so the flow renderer can attach the name
		// to any subsequent packet headed to one of these addresses.
		if len(p.IPs) > 0 {
			e.dnsCache.Record(p.Name, p.IPs)
		}
		_ = e.store.InsertSample(ctx, e.sessionID, storage.Sample{
			Kind: "dns", Label: p.Name,
			Value: float64(p.Duration.Microseconds()), TS: ev.Time,
		})
	case events.KindDNSFailure:
		p, ok := ev.Payload.(events.DNSFailurePayload)
		if !ok {
			return
		}
		e.agg.RecordDNS(p.Name, p.Duration, true)
		_ = e.store.InsertSample(ctx, e.sessionID, storage.Sample{
			Kind: "dns", Label: p.Name,
			Value: float64(p.Duration.Microseconds()), Failed: true, TS: ev.Time,
		})
	case events.KindAnomaly:
		p, ok := ev.Payload.(events.AnomalyPayload)
		if !ok {
			return
		}
		_ = e.store.InsertAnomaly(ctx, e.sessionID, p.Severity, p.Message)
	case events.KindLinkStateChange, events.KindAddrChange, events.KindRouteChange:
		// Persist push-based state changes onto the timeline at their precise
		// kernel timestamp so replay shows sub-second change times rather than
		// poll-quantised ones.
		if msg := stateChangeMessage(ev); msg != "" {
			_ = e.store.InsertAnomalyAt(ctx, e.sessionID, string(events.SevInfo), msg, ev.Time)
		}
	}
}

// stateChangeMessage renders a one-line timeline description for a push-based
// state-change event. Returns "" for an unrecognised payload.
func stateChangeMessage(ev events.Event) string {
	switch p := ev.Payload.(type) {
	case events.LinkChangePayload:
		if p.Removed {
			return fmt.Sprintf("link %s removed", p.Iface)
		}
		return fmt.Sprintf("link %s changed: up=%t running=%t", p.Iface, p.Up, p.Running)
	case events.AddrChangePayload:
		verb := "added to"
		if !p.Added {
			verb = "removed from"
		}
		return fmt.Sprintf("addr %s %s %s", p.Addr, verb, p.Iface)
	case events.RouteChangePayload:
		verb := "added"
		if !p.Added {
			verb = "removed"
		}
		via := ""
		if p.Gateway != "" {
			via = " via " + p.Gateway
		}
		return fmt.Sprintf("route %s%s dev %s %s", p.Dst, via, p.Iface, verb)
	}
	return ""
}

func newSessionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}
