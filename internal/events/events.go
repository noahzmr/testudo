// Package events defines the event bus that decouples collectors,
// analyzers, storage, and the TUI. Producers publish; subscribers consume.
package events

import (
	"context"
	"sync"
	"time"
)

type Kind string

const (
	KindLatency      Kind = "latency"
	KindPacketLoss   Kind = "packet_loss"
	KindDNSResult    Kind = "dns_result"
	KindDNSFailure   Kind = "dns_failure"
	KindAnomaly      Kind = "anomaly"
	KindSessionStart Kind = "session_start"
	KindSessionEnd   Kind = "session_end"
	KindFlowUpdate   Kind = "flow_update"
	KindIncident     Kind = "incident"
	KindFirewallDrop Kind = "firewall_drop"
	KindNeighChange  Kind = "neigh_change"
	KindDuplicateIP  Kind = "duplicate_ip"

	// State-change kinds fed by the RTNETLINK push watcher (see
	// internal/collectors/netlink_watch.go). Each is emitted the instant the
	// kernel multicasts the change, rather than on the next poll tick.
	KindLinkStateChange Kind = "link_state_change"
	KindAddrChange      Kind = "addr_change"
	KindRouteChange     Kind = "route_change"
)

// Severity is the canonical 4-level alert ladder defined in CLAUDE.md.
// Use these as the AnomalyPayload.Severity value.
type Severity string

const (
	SevInfo     Severity = "INFO"
	SevWarn     Severity = "WARN"
	SevError    Severity = "ERROR"
	SevCritical Severity = "CRITICAL"
)

// SeverityRank lets callers compare/escalate without string ordering.
func SeverityRank(s Severity) int {
	switch s {
	case SevInfo:
		return 0
	case SevWarn:
		return 1
	case SevError:
		return 2
	case SevCritical:
		return 3
	}
	return 0
}

// Event is the unit of communication on the bus. Payload is kind-specific.
type Event struct {
	Kind    Kind
	Time    time.Time
	Source  string
	Payload any
}

// LatencyPayload reports a single round-trip measurement.
type LatencyPayload struct {
	Target string
	RTT    time.Duration
}

// PacketLossPayload reports observed loss over a probe window.
type PacketLossPayload struct {
	Target  string
	Sent    int
	Lost    int
	LossPct float64
}

// DNSResultPayload reports a successful DNS resolution.
type DNSResultPayload struct {
	Name     string
	Server   string
	Duration time.Duration
	Answers  int
	IPs      []string // addresses returned; populated for cache-seeding
}

// DNSFailurePayload reports a DNS resolution failure.
type DNSFailurePayload struct {
	Name     string
	Server   string
	Duration time.Duration
	Err      string
}

// AnomalyPayload describes a detected operational anomaly.
type AnomalyPayload struct {
	Severity string
	Message  string
}

// FlowUpdatePayload reports an incremental update to a normalised flow.
// The capture collector emits this once per packet observed; the flow
// aggregator merges by (A, B, Proto, Iface) where A is the lexicographically
// smaller endpoint. Iface lets a single conversation be tracked separately
// on each interface it traverses (NAT, bridges, VPN tunnels).
type FlowUpdatePayload struct {
	Iface            string
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Proto            string
	Bytes            uint64
}

// FirewallDropPayload reports the growth of a single rule's DROP/REJECT
// counter between two snapshots. DeltaPackets/DeltaBytes are the increase
// over the sample window; Rate is drops/sec. The (Family, Table, Chain,
// Handle) tuple names the exact rule so the Alerts tab can point at it.
type FirewallDropPayload struct {
	Family       string
	Table        string
	Chain        string
	Handle       uint64
	Match        string
	Verdict      string
	DeltaPackets uint64
	DeltaBytes   uint64
	Rate         float64 // drops per second over the window
}

// NeighChangePayload reports a neighbour-table transition between two dumps:
// a new entry, a MAC reassignment, or a slide into FAILED/INCOMPLETE. The
// Alerts tab keys off (IP, Dev) so it can point at the exact neighbour.
type NeighChangePayload struct {
	IP       string
	Dev      string
	Family   string // ipv4 / ipv6
	OldMAC   string // empty for a brand-new neighbour
	NewMAC   string
	OldState string
	NewState string
}

// DuplicateIPPayload reports one IP answered by more than one MAC - an IP
// conflict / rogue device. A hard local-network fault that penalises the LAN
// sub-score for as long as it persists.
type DuplicateIPPayload struct {
	IP   string
	MACs []string
	Devs []string
}

// LinkChangePayload reports a link-state transition seen on the RTNETLINK
// RTNLGRP_LINK multicast group. Removed=true marks an interface that was
// deleted (RTM_DELLINK) rather than a flag change.
type LinkChangePayload struct {
	Iface   string
	Up      bool
	Running bool
	Removed bool
}

// AddrChangePayload reports an address add/del on RTNLGRP_IPV4_IFADDR /
// RTNLGRP_IPV6_IFADDR. Added=false means the address was removed.
type AddrChangePayload struct {
	Iface  string
	Addr   string // CIDR
	Family string // ipv4 / ipv6
	Added  bool
}

// RouteChangePayload reports a route add/del on RTNLGRP_IPV4_ROUTE /
// RTNLGRP_IPV6_ROUTE. IsDefault marks a default-route change, the signal that
// feeds route-churn (uplink instability) into the grade.
type RouteChangePayload struct {
	Dst       string // CIDR or "default"
	Gateway   string
	Iface     string
	Family    string // ipv4 / ipv6
	Added     bool
	IsDefault bool
}

// IncidentPayload bundles the context captured around a CRITICAL anomaly:
// the trigger reason plus the IDs of correlated artifacts.
type IncidentPayload struct {
	IncidentID string
	Trigger    string
	Summary    string
}

// Subscription is a live bus subscription. Always call Close when done -
// otherwise the underlying channel stays in the bus's fan-out loop forever
// and Publish keeps iterating dead subscribers. Bubble Tea code that
// re-issues commands per message MUST reuse a single Subscription rather
// than calling Subscribe() inside the Cmd factory.
type Subscription struct {
	id     uint64
	bus    *Bus
	ch     chan Event
	filter uint64 // bitmask of accepted kinds; 0 = accept all
}

// C returns the channel this subscription receives on.
func (s *Subscription) C() <-chan Event { return s.ch }

// Close removes the subscription from the bus. Safe to call multiple times.
func (s *Subscription) Close() {
	if s == nil || s.bus == nil {
		return
	}
	s.bus.unsubscribe(s.id)
}

// Bus is a fan-out, non-blocking event bus. Slow subscribers drop events
// rather than back-pressuring producers - the TUI must never stall capture.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[uint64]*Subscription
	nextID      uint64
	bufSize     int
}

func NewBus(bufSize int) *Bus {
	if bufSize <= 0 {
		bufSize = 256
	}
	return &Bus{
		subscribers: make(map[uint64]*Subscription),
		bufSize:     bufSize,
	}
}

// Subscribe returns a subscription that receives every event. Caller MUST
// Close() the subscription when done, otherwise it leaks.
func (b *Bus) Subscribe() *Subscription { return b.subscribeFiltered(0) }

// SubscribeKinds returns a subscription that only receives events matching
// the given kinds. Filtering happens inside Publish - non-matching events
// don't even hit the channel - which keeps fast-path producers (capture)
// from waking up consumers (analyzers, TUI) that don't care.
func (b *Bus) SubscribeKinds(kinds ...Kind) *Subscription {
	var mask uint64
	for _, k := range kinds {
		mask |= kindMask(k)
	}
	return b.subscribeFiltered(mask)
}

func (b *Bus) subscribeFiltered(mask uint64) *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	s := &Subscription{
		id:     b.nextID,
		bus:    b,
		ch:     make(chan Event, b.bufSize),
		filter: mask,
	}
	b.subscribers[s.id] = s
	return s
}

func (b *Bus) unsubscribe(id uint64) {
	b.mu.Lock()
	s, ok := b.subscribers[id]
	delete(b.subscribers, id)
	b.mu.Unlock()
	if ok {
		// Close after removing from the map so Publish never sends to a
		// closed channel.
		close(s.ch)
	}
}

// Publish fans an event out to all matching subscribers without blocking.
func (b *Bus) Publish(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	bit := kindMask(e.Kind)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subscribers {
		// filter==0 means "any kind". Otherwise the kind must be in mask.
		if s.filter != 0 && s.filter&bit == 0 {
			continue
		}
		select {
		case s.ch <- e:
		default:
			// Subscriber is slow; drop rather than block the producer.
		}
	}
}

// Close shuts down every subscriber channel. After Close, Publish is a
// no-op against closed channels - callers should stop publishing first.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.subscribers {
		close(s.ch)
	}
	b.subscribers = make(map[uint64]*Subscription)
}

// kindMask maps each Kind to a unique bit in a uint64. Up to 64 kinds are
// supported, which is generous for our taxonomy.
func kindMask(k Kind) uint64 {
	switch k {
	case KindLatency:
		return 1 << 0
	case KindPacketLoss:
		return 1 << 1
	case KindDNSResult:
		return 1 << 2
	case KindDNSFailure:
		return 1 << 3
	case KindAnomaly:
		return 1 << 4
	case KindSessionStart:
		return 1 << 5
	case KindSessionEnd:
		return 1 << 6
	case KindFlowUpdate:
		return 1 << 7
	case KindIncident:
		return 1 << 8
	case KindFirewallDrop:
		return 1 << 9
	case KindNeighChange:
		return 1 << 10
	case KindDuplicateIP:
		return 1 << 11
	case KindLinkStateChange:
		return 1 << 12
	case KindAddrChange:
		return 1 << 13
	case KindRouteChange:
		return 1 << 14
	}
	// Unknown kinds match no filter; only the unfiltered subscriber sees them.
	return 1 << 63
}

// Forward copies events from src to the bus until ctx is cancelled.
func (b *Bus) Forward(ctx context.Context, src <-chan Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-src:
			if !ok {
				return
			}
			b.Publish(e)
		}
	}
}

// SubscriberCount reports the current number of active subscriptions. Use
// it from diagnostics or tests to catch leak regressions.
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}
