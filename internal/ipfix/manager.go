package ipfix

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/flows"
)

// Manager keeps an Exporter's lifecycle in sync with what the operator has
// configured in the Settings tab. It polls the live SettingsStore on a
// short cadence; when the endpoint / interval / enabled flag changes it
// transparently re-dials.
type Manager struct {
	// Attribute, when set, fills in each flow's attribution before it is
	// sent; the translated addresses go out with the flow.
	Attribute func([]flows.FlowStats) []flows.FlowStats

	settings *config.SettingsStore
	flowAgg  *flows.Aggregator

	mu       sync.Mutex
	exporter *Exporter
	state    state
	lastSend time.Time
	lastErr  string
}

// state mirrors the parts of the threshold snapshot we react to.
type state struct {
	Enabled  bool
	Endpoint string
	Interval time.Duration
	Domain   uint32
}

func NewManager(settings *config.SettingsStore, flowAgg *flows.Aggregator) *Manager {
	return &Manager{settings: settings, flowAgg: flowAgg}
}

// Status is a snapshot of what the manager is doing right now.
type Status struct {
	Enabled  bool
	Endpoint string
	Interval time.Duration
	LastSend time.Time
	LastErr  string
	Dialed   bool
}

// Status reports current state. Safe to call from any goroutine.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		Enabled:  m.state.Enabled,
		Endpoint: m.state.Endpoint,
		Interval: m.state.Interval,
		LastSend: m.lastSend,
		LastErr:  m.lastErr,
		Dialed:   m.exporter != nil,
	}
}

// Run blocks until ctx ends, periodically reconciling exporter state with
// settings and emitting flow snapshots. The reconcile tick is 5s; the
// export tick is whatever the operator has configured.
func (m *Manager) Run(ctx context.Context) error {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	m.reconcile()
	m.maybeExport()
	for {
		select {
		case <-ctx.Done():
			m.shutdown()
			return nil
		case <-t.C:
			m.reconcile()
			m.maybeExport()
		}
	}
}

// reconcile re-dials the exporter if the operator changed any of the
// settings that affect the transport.
func (m *Manager) reconcile() {
	if m.settings == nil {
		return
	}
	th := m.settings.Snapshot()
	target := state{
		Enabled:  th.IPFIXEnabled,
		Endpoint: strings.TrimSpace(th.IPFIXEndpoint),
		Interval: time.Duration(th.IPFIXIntervalSec) * time.Second,
		Domain:   th.IPFIXDomainID,
	}
	if target.Interval <= 0 {
		target.Interval = 30 * time.Second
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if target == m.state {
		return
	}
	// Tear down the previous exporter regardless of why we're reconciling.
	if m.exporter != nil {
		_ = m.exporter.Close()
		m.exporter = nil
	}
	m.state = target
	m.lastErr = ""
	if !target.Enabled || target.Endpoint == "" {
		return
	}
	exp, err := NewExporter(Config{
		Endpoint: target.Endpoint,
		Interval: target.Interval,
		DomainID: target.Domain,
	})
	if err != nil {
		m.lastErr = err.Error()
		log.Printf("ipfix: dial failed: %v", err)
		return
	}
	m.exporter = exp
	log.Printf("ipfix: exporter ready => %s every %s", target.Endpoint, target.Interval)
}

// maybeExport sends one IPFIX message when the configured interval has
// elapsed since the last send.
func (m *Manager) maybeExport() {
	m.mu.Lock()
	exp := m.exporter
	interval := m.state.Interval
	due := m.lastSend.IsZero() || time.Since(m.lastSend) >= interval
	m.mu.Unlock()
	if exp == nil || !due {
		return
	}
	snap := m.flowAgg.Snapshot()
	if m.Attribute != nil {
		snap = m.Attribute(snap)
	}
	recs := toFlowRecs(snap)
	if err := exp.Export(recs); err != nil {
		m.mu.Lock()
		m.lastErr = err.Error()
		m.mu.Unlock()
		log.Printf("ipfix: export failed: %v", err)
		return
	}
	m.mu.Lock()
	m.lastErr = ""
	m.lastSend = time.Now()
	m.mu.Unlock()
}

func (m *Manager) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exporter != nil {
		_ = m.exporter.Close()
		m.exporter = nil
	}
}

// toFlowRecs converts the engine's flow snapshot into the IPFIX record
// shape. Proto strings ("tcp"/"udp") are mapped to IANA numbers.
func toFlowRecs(snap []flows.FlowStats) []FlowRec {
	out := make([]FlowRec, 0, len(snap))
	for _, f := range snap {
		srcIP, dstIP := parseIPOrNil(f.Key.A.IP), parseIPOrNil(f.Key.B.IP)
		if srcIP == nil || dstIP == nil {
			continue
		}
		rec := FlowRec{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: f.Key.A.Port,
			DstPort: f.Key.B.Port,
			Proto:   protoNumber(f.Key.Proto),
			Bytes:   f.Bytes,
			Packets: f.Packets,
			Start:   f.FirstSeen,
			End:     f.LastSeen,
		}
		// A translated connection is sent the way it was opened, with the
		// addresses and ports it had after the translation.
		if pre, ok := parseTuple(f.Attrs.PreNAT); ok {
			if post, ok := parseTuple(f.Attrs.PostNAT); ok {
				rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort = pre.src, pre.sport, pre.dst, pre.dport
				rec.PostSrcIP, rec.PostSrcPort, rec.PostDstIP, rec.PostDstPort = post.src, post.sport, post.dst, post.dport
			}
		}
		out = append(out, rec)
	}
	return out
}

func parseIPOrNil(s string) []byte {
	if s == "" {
		return nil
	}
	ip := netParseIP(s)
	return ip
}

// netParseIP is split out so we don't have to drag net into the recs path
// directly - keeps the test surface small.
func netParseIP(s string) []byte {
	return netParseIPImpl(s)
}

// protoNumber maps the proto strings we store in FlowKey to IANA numbers.
func protoNumber(s string) uint8 {
	switch strings.ToLower(s) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmpv6", "icmp6":
		return 58
	}
	// Numeric fallback in case the producer ever puts "6", "17" etc.
	if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= 255 {
		return uint8(v)
	}
	return 0
}

type natTuple struct {
	src, dst     net.IP
	sport, dport uint16
}

// parseTuple reads the "proto src:port > dst:port" form of flows.Attrs.
func parseTuple(s string) (natTuple, bool) {
	_, rest, ok := strings.Cut(s, " ")
	if !ok {
		return natTuple{}, false
	}
	a, b, ok := strings.Cut(rest, " > ")
	if !ok {
		return natTuple{}, false
	}
	var t natTuple
	for _, part := range []struct {
		hp   string
		ip   *net.IP
		port *uint16
	}{{a, &t.src, &t.sport}, {b, &t.dst, &t.dport}} {
		h, p, err := net.SplitHostPort(part.hp)
		if err != nil {
			return natTuple{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 65535 {
			return natTuple{}, false
		}
		*part.ip, *part.port = net.ParseIP(h), uint16(n)
		if *part.ip == nil {
			return natTuple{}, false
		}
	}
	return t, true
}
