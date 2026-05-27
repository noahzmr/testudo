package collectors

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/netops"
)

// NeighConntrackCollector polls the two L3-state tables the platform was
// blind to: the netlink neighbour table (ARP for IPv4, NDP for IPv6) and the
// nf_conntrack flow table. It caches the latest dump behind a mutex so the
// TUI and Web UI render without re-hitting netlink, publishes deltas to the
// bus (KindNeighChange / KindDuplicateIP), and exposes a Signal() the grade
// folds into LAN / Stability / NAT-exhaustion. Reads soft-fail: a missing
// CAP_NET_ADMIN leaves the cache empty, which maps to a neutral grade rather
// than a crash.
type NeighConntrackCollector struct {
	Netops            *netops.Writer
	NeighInterval     time.Duration
	ConntrackInterval time.Duration
	ConntrackMaxRows  int

	mu         sync.RWMutex
	neighbours []netops.Neighbour
	conflicts  []netops.IPConflict
	conntrack  []netops.ConntrackFlow
	ctCount    uint64
	ctMax      uint64

	prevNeigh     map[string]neighState
	prevConflicts map[string]bool
}

type neighState struct {
	mac, state, family string
}

// NeighConntrackSignal is the grade-facing summary of L3 state. Empty inputs
// map to the neutral defaults (no duplicates, ratio 0, HasConntrack=false) so
// a host lacking the signal isn't penalised.
type NeighConntrackSignal struct {
	DuplicateIPs  int
	StaleRatio    float64 // (FAILED+INCOMPLETE)/total neighbours
	HasNeigh      bool
	ConntrackUtil float64 // live entries / nf_conntrack_max, 0..1
	HasConntrack  bool
}

func (c *NeighConntrackCollector) Name() string { return "neigh_conntrack" }

func (c *NeighConntrackCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Netops == nil {
		return nil
	}
	// Prime baselines before the first delta so we don't alert on the
	// initial full table. A subsystem with interval<=0 is disabled and not
	// primed or polled.
	var wg sync.WaitGroup
	if c.NeighInterval > 0 {
		c.pollNeigh(bus, true)
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.loop(ctx, c.NeighInterval, func() { c.pollNeigh(bus, false) })
		}()
	}
	if c.ConntrackInterval > 0 {
		c.pollConntrack()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.loop(ctx, c.ConntrackInterval, func() { c.pollConntrack() })
		}()
	}
	wg.Wait()
	return nil
}

func (c *NeighConntrackCollector) loop(ctx context.Context, d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

func (c *NeighConntrackCollector) pollNeigh(bus *events.Bus, prime bool) {
	ns, err := c.Netops.ListNeighbours()
	if err != nil {
		return // soft-fail: keep the last good cache
	}
	conflicts := netops.DuplicateIPs(ns)

	cur := make(map[string]neighState, len(ns))
	for _, n := range ns {
		cur[neighKey(n.IP, n.Dev)] = neighState{mac: n.MAC, state: n.State, family: n.Family}
	}

	c.mu.Lock()
	prev := c.prevNeigh
	prevConf := c.prevConflicts
	c.neighbours = ns
	c.conflicts = conflicts
	c.prevNeigh = cur
	curConf := make(map[string]bool, len(conflicts))
	for _, cf := range conflicts {
		curConf[cf.IP] = true
	}
	c.prevConflicts = curConf
	c.mu.Unlock()

	if !prime && prev != nil {
		c.publishNeighDeltas(bus, prev, cur)
	}
	// Fire on newly-appeared conflicts only; clearing one is silent.
	for _, cf := range conflicts {
		if prevConf != nil && prevConf[cf.IP] {
			continue
		}
		c.publishConflict(bus, cf)
	}
}

func (c *NeighConntrackCollector) publishNeighDeltas(bus *events.Bus, prev, cur map[string]neighState) {
	for key, st := range cur {
		ip, dev := splitNeighKey(key)
		old, seen := prev[key]
		switch {
		case !seen:
			// Brand-new neighbour: informational, no anomaly.
			bus.Publish(events.Event{
				Kind: events.KindNeighChange, Source: c.Name(),
				Payload: events.NeighChangePayload{
					IP: ip, Dev: dev, Family: st.family,
					NewMAC: st.mac, NewState: st.state,
				},
			})
		case old.mac != st.mac && st.mac != "" && old.mac != "":
			// MAC reassignment: IP conflict or rogue device. WARN.
			bus.Publish(events.Event{
				Kind: events.KindNeighChange, Source: c.Name(),
				Payload: events.NeighChangePayload{
					IP: ip, Dev: dev, Family: st.family,
					OldMAC: old.mac, NewMAC: st.mac,
					OldState: old.state, NewState: st.state,
				},
			})
			bus.Publish(events.Event{
				Kind: events.KindAnomaly, Source: c.Name(),
				Payload: events.AnomalyPayload{
					Severity: string(events.SevWarn),
					Message: fmt.Sprintf("neighbour %s on %s changed MAC %s -> %s (conflict or rogue device?)",
						ip, dev, old.mac, st.mac),
				},
			})
		case old.state != st.state && (st.state == "FAILED" || st.state == "INCOMPLETE"):
			// Slid into an unreachable state: gateway loss precursor.
			bus.Publish(events.Event{
				Kind: events.KindNeighChange, Source: c.Name(),
				Payload: events.NeighChangePayload{
					IP: ip, Dev: dev, Family: st.family,
					OldMAC: old.mac, NewMAC: st.mac,
					OldState: old.state, NewState: st.state,
				},
			})
		}
	}
}

func (c *NeighConntrackCollector) publishConflict(bus *events.Bus, cf netops.IPConflict) {
	bus.Publish(events.Event{
		Kind: events.KindDuplicateIP, Source: c.Name(),
		Payload: events.DuplicateIPPayload{IP: cf.IP, MACs: cf.MACs, Devs: cf.Devs},
	})
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: c.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(events.SevError),
			Message: fmt.Sprintf("duplicate IP %s answered by %d MACs: %s",
				cf.IP, len(cf.MACs), strings.Join(cf.MACs, ", ")),
		},
	})
}

func (c *NeighConntrackCollector) pollConntrack() {
	flows, err := c.Netops.ListConntrack()
	if err != nil {
		flows = nil // soft-fail
	}
	if c.ConntrackMaxRows > 0 && len(flows) > c.ConntrackMaxRows {
		flows = flows[:c.ConntrackMaxRows]
	}
	count := readProcUint64("/proc/sys/net/netfilter/nf_conntrack_count")
	max := readProcUint64("/proc/sys/net/netfilter/nf_conntrack_max")

	c.mu.Lock()
	c.conntrack = flows
	c.ctCount = count
	c.ctMax = max
	c.mu.Unlock()
}

// Neighbours returns a copy-free snapshot of the last neighbour dump. Safe
// for concurrent reads; the slice is replaced wholesale on each poll, never
// mutated in place.
func (c *NeighConntrackCollector) Neighbours() []netops.Neighbour {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.neighbours
}

func (c *NeighConntrackCollector) Conflicts() []netops.IPConflict {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conflicts
}

func (c *NeighConntrackCollector) Conntrack() []netops.ConntrackFlow {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conntrack
}

// ConntrackCounts returns live entries and nf_conntrack_max (from /proc, the
// authoritative totals - the cached flow slice is capped for render).
func (c *NeighConntrackCollector) ConntrackCounts() (count, max uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ctCount, c.ctMax
}

// Signal summarises the cached state for the Network Quality grade.
func (c *NeighConntrackCollector) Signal() NeighConntrackSignal {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ratio, total := netops.UnreachableRatio(c.neighbours)
	util, hasUtil := netops.ConntrackUtilisation(c.ctCount, c.ctMax)
	return NeighConntrackSignal{
		DuplicateIPs:  len(c.conflicts),
		StaleRatio:    ratio,
		HasNeigh:      total > 0,
		ConntrackUtil: util,
		HasConntrack:  hasUtil,
	}
}

func neighKey(ip, dev string) string { return ip + "|" + dev }

func splitNeighKey(k string) (ip, dev string) {
	if i := strings.IndexByte(k, '|'); i >= 0 {
		return k[:i], k[i+1:]
	}
	return k, ""
}

// readProcUint64 reads a single unsigned integer from a /proc/sys file.
// Returns 0 on any error (missing file, unparseable), which the callers treat
// as "signal unavailable".
func readProcUint64(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
