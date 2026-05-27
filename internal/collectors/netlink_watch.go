package collectors

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/netops"
)

// NetlinkWatchCollector subscribes to the RTNETLINK multicast groups
// (RTNLGRP_LINK / IPV4_IFADDR / IPV6_IFADDR / IPV4_ROUTE / IPV6_ROUTE) and
// turns each kernel state-change message into a bus event the instant it is
// emitted, rather than waiting for the next poll tick. This drops link-flap /
// route-change detection latency from "up to one poll interval" to sub-second.
//
// It is push-first but not push-only: a slow reconcile timer re-reads the full
// state and diffs it against last-known, catching any multicast message the
// kernel dropped under load. If the kernel refuses the subscriptions
// (restricted namespace, missing capability) the watcher soft-fails to a
// reconcile-only ("polled") mode and reports itself degraded - it never
// crashes.
//
// Every transition is published immediately as a KindLinkStateChange /
// KindAddrChange / KindRouteChange event (so the TUI/Web tables and replay see
// precise timestamps). A separate coalescer groups rapid link transitions into
// a single "eth0 flapped 6x in 2s" anomaly so the Alerts tab isn't flooded.
type NetlinkWatchCollector struct {
	Netops *netops.Writer

	// CoalesceWindow is the quiet period after which a burst of link
	// transitions on one interface is summarised into a single anomaly.
	// Zero uses defaultCoalesceWindow.
	CoalesceWindow time.Duration

	// ReconcileInterval is the slow safety-net cadence for the full-state
	// diff. Zero uses defaultReconcileInterval.
	ReconcileInterval time.Duration

	// now is injectable for tests; nil means time.Now.
	now func() time.Time

	mu        sync.RWMutex
	attached  bool   // at least one subscription succeeded
	active    bool   // Run has started (subscriptions or reconcile loop)
	degraded  bool   // a subscription failed -> reconcile-only fallback
	statusMsg string // human-readable detail for the UI

	last      netState // last-known full state, kept in sync by push + reconcile
	flaps     []time.Time
	churns    []time.Time
	rateWin   time.Duration // sliding window for flap-rate / route-churn
	coalescer *flapCoalescer
}

const (
	defaultCoalesceWindow    = 250 * time.Millisecond
	defaultReconcileInterval = 60 * time.Second
	rateWindow               = time.Minute
)

func (c *NetlinkWatchCollector) Name() string { return "netlink-watch" }

func (c *NetlinkWatchCollector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Run subscribes to the RTNETLINK groups and translates kernel messages into
// bus events until ctx is cancelled. It owns its goroutines (one per
// subscription plus a coalesce flusher and a reconcile timer) and drains them
// before returning, so a leak check stays clean.
func (c *NetlinkWatchCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Netops == nil {
		return nil
	}
	window := c.CoalesceWindow
	if window <= 0 {
		window = defaultCoalesceWindow
	}
	reconcile := c.ReconcileInterval
	if reconcile <= 0 {
		reconcile = defaultReconcileInterval
	}

	c.mu.Lock()
	c.active = true
	c.rateWin = rateWindow
	c.coalescer = &flapCoalescer{window: window, now: c.clock}
	// Seed last-known state so the first reconcile doesn't re-announce the
	// world as fresh changes.
	c.last = c.readState()
	c.mu.Unlock()

	var wg sync.WaitGroup

	// Each subscription runs in its own goroutine. A subscribe failure is
	// soft: we mark the subsystem degraded and rely on the reconcile timer.
	c.subscribeLink(ctx, &wg, bus)
	c.subscribeAddr(ctx, &wg, bus)
	c.subscribeRoute(ctx, &wg, bus)

	// Coalesce flusher: turns bursts of link transitions into summary anomalies.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(window)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				// Final drain so a burst in flight at shutdown still reports.
				c.publishFlaps(bus, c.coalescer.flushAll())
				return
			case <-t.C:
				c.publishFlaps(bus, c.coalescer.flushReady())
			}
		}
	}()

	// Reconcile safety net.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(reconcile)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.reconcile(bus)
			}
		}
	}()

	wg.Wait()
	c.mu.Lock()
	c.active = false
	c.mu.Unlock()
	return nil
}

// ---- subscriptions ----

func (c *NetlinkWatchCollector) subscribeLink(ctx context.Context, wg *sync.WaitGroup, bus *events.Bus) {
	ch := make(chan netlink.LinkUpdate, 256)
	done := make(chan struct{})
	if err := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{}); err != nil {
		c.markDegraded("link", err)
		close(done)
		return
	}
	c.markAttached()
	wg.Add(1)
	go func() {
		defer wg.Done()
		drainUpdates(ctx, ch, done, func(u netlink.LinkUpdate) {
			attrs := u.Link.Attrs()
			name := attrs.Name
			if name == "" || strings.EqualFold(name, "lo") {
				return
			}
			removed := u.Header.Type == unix.RTM_DELLINK
			up := attrs.Flags&netlinkFlagUp != 0
			running := attrs.OperState == netlink.OperUp || attrs.OperState == netlink.OperUnknown
			c.onLink(bus, name, up, running, removed)
		})
	}()
}

func (c *NetlinkWatchCollector) subscribeAddr(ctx context.Context, wg *sync.WaitGroup, bus *events.Bus) {
	ch := make(chan netlink.AddrUpdate, 256)
	done := make(chan struct{})
	if err := netlink.AddrSubscribeWithOptions(ch, done, netlink.AddrSubscribeOptions{}); err != nil {
		c.markDegraded("addr", err)
		close(done)
		return
	}
	c.markAttached()
	wg.Add(1)
	go func() {
		defer wg.Done()
		drainUpdates(ctx, ch, done, func(u netlink.AddrUpdate) {
			iface := ifaceName(u.LinkIndex)
			cidr := u.LinkAddress.String()
			fam := "ipv4"
			if u.LinkAddress.IP.To4() == nil {
				fam = "ipv6"
			}
			c.onAddr(bus, iface, cidr, fam, u.NewAddr)
		})
	}()
}

func (c *NetlinkWatchCollector) subscribeRoute(ctx context.Context, wg *sync.WaitGroup, bus *events.Bus) {
	ch := make(chan netlink.RouteUpdate, 256)
	done := make(chan struct{})
	if err := netlink.RouteSubscribeWithOptions(ch, done, netlink.RouteSubscribeOptions{}); err != nil {
		c.markDegraded("route", err)
		close(done)
		return
	}
	c.markAttached()
	wg.Add(1)
	go func() {
		defer wg.Done()
		drainUpdates(ctx, ch, done, func(u netlink.RouteUpdate) {
			info := routeUpdateToInfo(u)
			c.onRoute(bus, info, u.Type != unix.RTM_DELROUTE)
		})
	}()
}

// drainUpdates consumes subscription updates until ctx is cancelled or the
// channel closes, then tears the subscription down cleanly. It ALWAYS closes
// done (via the once) so the netlink library's "<-done; socket.Close()" helper
// goroutine cannot leak, and it drains any in-flight send so the library's
// receive goroutine isn't wedged on a blocked channel write.
func drainUpdates[T any](ctx context.Context, ch <-chan T, done chan struct{}, handle func(T)) {
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	defer stop()
	for {
		select {
		case <-ctx.Done():
			stop()
			for range ch {
			}
			return
		case u, ok := <-ch:
			if !ok {
				return
			}
			handle(u)
		}
	}
}

// ---- transition handlers ----

func (c *NetlinkWatchCollector) onLink(bus *events.Bus, name string, up, running, removed bool) {
	bus.Publish(events.Event{
		Kind: events.KindLinkStateChange, Source: c.Name(),
		Payload: events.LinkChangePayload{Iface: name, Up: up, Running: running, Removed: removed},
	})
	c.mu.Lock()
	prev, seen := c.last.links[name]
	if removed {
		delete(c.last.links, name)
	} else {
		c.last.links[name] = running
	}
	transition := removed || (seen && prev != running) || (!seen && !running)
	if transition {
		c.recordFlap()
		c.coalescer.add(name, running)
	}
	c.mu.Unlock()
}

func (c *NetlinkWatchCollector) onAddr(bus *events.Bus, iface, cidr, fam string, added bool) {
	bus.Publish(events.Event{
		Kind: events.KindAddrChange, Source: c.Name(),
		Payload: events.AddrChangePayload{Iface: iface, Addr: cidr, Family: fam, Added: added},
	})
	key := iface + "/" + cidr
	c.mu.Lock()
	if added {
		c.last.addrs[key] = true
	} else {
		delete(c.last.addrs, key)
	}
	c.mu.Unlock()
}

func (c *NetlinkWatchCollector) onRoute(bus *events.Bus, r netops.RouteInfo, added bool) {
	isDefault := r.Dst == "default"
	bus.Publish(events.Event{
		Kind: events.KindRouteChange, Source: c.Name(),
		Payload: events.RouteChangePayload{
			Dst: r.Dst, Gateway: r.Gateway, Iface: r.Iface, Family: r.Family,
			Added: added, IsDefault: isDefault,
		},
	})
	key := routeKey(r)
	c.mu.Lock()
	_, seen := c.last.routes[key]
	if added {
		c.last.routes[key] = true
	} else {
		delete(c.last.routes, key)
	}
	// A default-route appearing/disappearing/changing is uplink churn.
	if isDefault && (added != seen) {
		c.recordChurn()
	}
	c.mu.Unlock()
}

func (c *NetlinkWatchCollector) publishFlaps(bus *events.Bus, bursts []flapBurst) {
	for _, b := range bursts {
		if b.Count >= 2 {
			sev := events.SevWarn
			if !b.LastRunning {
				sev = events.SevError
			}
			bus.Publish(events.Event{
				Kind: events.KindAnomaly, Source: c.Name(),
				Payload: events.AnomalyPayload{
					Severity: string(sev),
					Message: fmt.Sprintf("%s flapped %d× in %s (now %s)",
						b.Iface, b.Count, b.Duration().Round(time.Millisecond),
						runningWord(b.LastRunning)),
				},
			})
		}
	}
}

// ---- reconcile ----

func (c *NetlinkWatchCollector) reconcile(bus *events.Bus) {
	fresh := c.readState()
	c.mu.Lock()
	prev := c.last
	c.last = fresh
	c.mu.Unlock()
	for _, ch := range diffNetState(prev, fresh) {
		bus.Publish(ch.event(c.Name()))
	}
}

func (c *NetlinkWatchCollector) readState() netState {
	s := newNetState()
	ifs, err := c.Netops.ListIfaces()
	if err == nil {
		for _, ifi := range ifs {
			if strings.EqualFold(ifi.Name, "lo") {
				continue
			}
			s.links[ifi.Name] = ifi.Running
			for _, a := range ifi.Addrs {
				s.addrs[ifi.Name+"/"+a] = true
			}
		}
	}
	routes, err := c.Netops.ListRoutes()
	if err == nil {
		for _, r := range routes {
			s.routes[routeKey(r)] = true
		}
	}
	return s
}

// ---- rate tracking ----

func (c *NetlinkWatchCollector) recordFlap()  { c.flaps = pruneAppend(c.flaps, c.clock(), c.rateWin) }
func (c *NetlinkWatchCollector) recordChurn() { c.churns = pruneAppend(c.churns, c.clock(), c.rateWin) }

// pruneAppend drops timestamps older than win and appends now.
func pruneAppend(ts []time.Time, now time.Time, win time.Duration) []time.Time {
	cut := now.Add(-win)
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	ts = ts[i:]
	return append(ts, now)
}

func countWithin(ts []time.Time, now time.Time, win time.Duration) float64 {
	cut := now.Add(-win)
	n := 0
	for _, t := range ts {
		if !t.Before(cut) {
			n++
		}
	}
	return float64(n)
}

// ---- status / signal ----

// NetlinkWatchSignal carries the push-derived stability inputs into the grade.
// The zero value is neutral (no flaps, no churn). HasData is true whenever the
// watcher is running, so a quiet network maps to a neutral 100 rather than
// being excluded.
type NetlinkWatchSignal struct {
	FlapRate   float64 // link transitions per minute (non-loopback)
	RouteChurn float64 // default-route changes per minute
	HasData    bool
}

// Signal summarises the recent flap-rate / route-churn for the grade.
func (c *NetlinkWatchCollector) Signal() NetlinkWatchSignal {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.clock()
	win := c.rateWin
	if win <= 0 {
		win = rateWindow
	}
	return NetlinkWatchSignal{
		FlapRate:   countWithin(c.flaps, now, win),
		RouteChurn: countWithin(c.churns, now, win),
		HasData:    c.active,
	}
}

// NetlinkWatchStatus is the UI-facing freshness summary. Mode is "live" when at
// least one multicast subscription is attached, "polled" when the watcher
// soft-failed to reconcile-only, and "off" before Run starts.
type NetlinkWatchStatus struct {
	Mode       string
	Attached   bool
	Degraded   bool
	Detail     string
	FlapRate   float64
	RouteChurn float64
}

// Status reports whether the push feed is attached, for the "live/polled"
// indicator shown in both UIs.
func (c *NetlinkWatchCollector) Status() NetlinkWatchStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	mode := "off"
	if c.active {
		mode = "polled"
		if c.attached {
			mode = "live"
		}
	}
	now := c.clock()
	win := c.rateWin
	if win <= 0 {
		win = rateWindow
	}
	return NetlinkWatchStatus{
		Mode: mode, Attached: c.attached, Degraded: c.degraded, Detail: c.statusMsg,
		FlapRate:   countWithin(c.flaps, now, win),
		RouteChurn: countWithin(c.churns, now, win),
	}
}

func (c *NetlinkWatchCollector) markAttached() {
	c.mu.Lock()
	c.attached = true
	c.mu.Unlock()
}

func (c *NetlinkWatchCollector) markDegraded(group string, err error) {
	c.mu.Lock()
	c.degraded = true
	c.statusMsg = fmt.Sprintf("%s subscribe unavailable: %v (reconcile-only)", group, err)
	c.mu.Unlock()
}

// ---- helpers ----

// netlinkFlagUp mirrors net.FlagUp (IFF_UP) without importing net in the hot
// path; LinkAttrs.Flags is a net.Flags whose Up bit is 1<<0.
const netlinkFlagUp = 1 << 0

func runningWord(running bool) string {
	if running {
		return "up"
	}
	return "down"
}

func ifaceName(index int) string {
	if index <= 0 {
		return ""
	}
	if link, err := netlink.LinkByIndex(index); err == nil {
		return link.Attrs().Name
	}
	return fmt.Sprintf("if%d", index)
}

func routeKey(r netops.RouteInfo) string {
	return strings.Join([]string{r.Family, r.Dst, r.Gateway, r.Iface}, "|")
}

func routeUpdateToInfo(u netlink.RouteUpdate) netops.RouteInfo {
	info := netops.RouteInfo{Metric: u.Priority}
	if u.Dst == nil {
		info.Dst = "default"
		info.Family = "ipv4"
		if u.Family == unix.AF_INET6 {
			info.Family = "ipv6"
		}
	} else {
		info.Dst = u.Dst.String()
		if u.Dst.IP.To4() != nil {
			info.Family = "ipv4"
		} else {
			info.Family = "ipv6"
		}
	}
	if u.Gw != nil {
		info.Gateway = u.Gw.String()
	}
	if u.LinkIndex > 0 {
		info.Iface = ifaceName(u.LinkIndex)
	}
	return info
}

// ---- reconcile-diff (pure, unit-tested) ----

// netState is a comparable snapshot of the kernel state the watcher tracks.
type netState struct {
	links  map[string]bool // iface -> running
	addrs  map[string]bool // "iface/cidr" -> present
	routes map[string]bool // routeKey -> present
}

func newNetState() netState {
	return netState{
		links:  map[string]bool{},
		addrs:  map[string]bool{},
		routes: map[string]bool{},
	}
}

// stateChange is one synthetic change the reconcile diff found the multicast
// feed had missed.
type stateChange struct {
	kind    events.Kind
	payload any
}

func (s stateChange) event(source string) events.Event {
	return events.Event{Kind: s.kind, Source: source, Payload: s.payload}
}

// diffNetState compares an old snapshot to a fresh one and returns the change
// events needed to bring a consumer from old to new. Deterministic ordering
// (links, addrs, routes; each sorted) keeps the unit test stable.
func diffNetState(old, fresh netState) []stateChange {
	var out []stateChange

	for _, name := range sortedKeys(fresh.links) {
		running := fresh.links[name]
		prev, seen := old.links[name]
		if !seen || prev != running {
			out = append(out, stateChange{
				kind:    events.KindLinkStateChange,
				payload: events.LinkChangePayload{Iface: name, Up: running, Running: running},
			})
		}
	}
	for _, name := range sortedKeys(old.links) {
		if _, seen := fresh.links[name]; !seen {
			out = append(out, stateChange{
				kind:    events.KindLinkStateChange,
				payload: events.LinkChangePayload{Iface: name, Removed: true},
			})
		}
	}

	for _, key := range sortedKeys(fresh.addrs) {
		if !old.addrs[key] {
			iface, cidr := splitAddrKey(key)
			out = append(out, stateChange{
				kind:    events.KindAddrChange,
				payload: events.AddrChangePayload{Iface: iface, Addr: cidr, Family: famOf(cidr), Added: true},
			})
		}
	}
	for _, key := range sortedKeys(old.addrs) {
		if !fresh.addrs[key] {
			iface, cidr := splitAddrKey(key)
			out = append(out, stateChange{
				kind:    events.KindAddrChange,
				payload: events.AddrChangePayload{Iface: iface, Addr: cidr, Family: famOf(cidr), Added: false},
			})
		}
	}

	for _, key := range sortedKeys(fresh.routes) {
		if !old.routes[key] {
			out = append(out, routeChangeFromKey(key, true))
		}
	}
	for _, key := range sortedKeys(old.routes) {
		if !fresh.routes[key] {
			out = append(out, routeChangeFromKey(key, false))
		}
	}
	return out
}

func routeChangeFromKey(key string, added bool) stateChange {
	parts := strings.SplitN(key, "|", 4)
	for len(parts) < 4 {
		parts = append(parts, "")
	}
	return stateChange{
		kind: events.KindRouteChange,
		payload: events.RouteChangePayload{
			Family: parts[0], Dst: parts[1], Gateway: parts[2], Iface: parts[3],
			Added: added, IsDefault: parts[1] == "default",
		},
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func splitAddrKey(k string) (iface, cidr string) {
	if i := strings.IndexByte(k, '/'); i >= 0 {
		return k[:i], k[i+1:]
	}
	return k, ""
}

func famOf(cidr string) string {
	if strings.Contains(cidr, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// ---- flap coalescer (pure timing logic, injectable clock, unit-tested) ----

// flapBurst summarises a run of link transitions on one interface that were
// separated by less than the coalesce window.
type flapBurst struct {
	Iface       string
	Count       int
	First       time.Time
	Last        time.Time
	LastRunning bool
}

// Duration is the wall-clock span of the burst.
func (b flapBurst) Duration() time.Duration { return b.Last.Sub(b.First) }

type burstState struct {
	count       int
	first       time.Time
	last        time.Time
	lastRunning bool
}

// flapCoalescer accumulates per-interface link transitions and releases a
// summary once an interface has been quiet for the window. The clock is
// injectable so the timing logic is deterministically testable.
type flapCoalescer struct {
	window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	bursts map[string]*burstState
}

func (f *flapCoalescer) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// add records a transition on iface at the current clock time.
func (f *flapCoalescer) add(iface string, running bool) {
	t := f.clock()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bursts == nil {
		f.bursts = map[string]*burstState{}
	}
	b, ok := f.bursts[iface]
	if !ok {
		b = &burstState{first: t}
		f.bursts[iface] = b
	}
	b.count++
	b.last = t
	b.lastRunning = running
}

// flushReady returns and clears every burst that has been quiet (no new
// transition) for at least the window, as of the current clock.
func (f *flapCoalescer) flushReady() []flapBurst {
	now := f.clock()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.collectLocked(func(b *burstState) bool {
		return now.Sub(b.last) >= f.window
	})
}

// flushAll returns and clears every pending burst regardless of quiet time -
// used to drain in-flight bursts at shutdown.
func (f *flapCoalescer) flushAll() []flapBurst {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.collectLocked(func(*burstState) bool { return true })
}

func (f *flapCoalescer) collectLocked(ready func(*burstState) bool) []flapBurst {
	var out []flapBurst
	for iface, b := range f.bursts {
		if !ready(b) {
			continue
		}
		out = append(out, flapBurst{
			Iface: iface, Count: b.count, First: b.first, Last: b.last,
			LastRunning: b.lastRunning,
		})
		delete(f.bursts, iface)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out
}
