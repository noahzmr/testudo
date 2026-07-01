package wireguard

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/netops"
)

// historyLen is how many per-tick throughput buckets are retained per peer for
// the RX/TX sparkline. At the default ~7 s poll this is roughly a minute of
// history.
const historyLen = 16

// Reader is the read surface the collector needs from netops. *netops.Writer
// satisfies it; tests can substitute a fake. ListIfaces supplies the kernel link
// stats (tx/rx errors + drops); ListNetplan supplies the configured intent for
// the merged read + drift detection.
type Reader interface {
	ListWGDevices() ([]netops.WGDeviceInfo, error)
	ListIfaces() ([]netops.IfaceInfo, error)
	ListNetplan() ([]netops.NetplanFile, error)
}

// Collector polls WireGuard device/peer state on Interval and publishes a
// Snapshot on the bus each tick. It also keeps per-peer rolling throughput
// history (M3) so the UIs can draw a sparkline, and caches the latest snapshot
// for pull-based consumers (the grade computation, the health row).
//
// Reading WireGuard state needs CAP_NET_ADMIN; when the read fails (no
// privilege, or wgctrl unavailable) the collector degrades softly - it records
// the error, publishes nothing, and reports Available()==false so the health
// tab can show "not available" rather than a hard failure. When there is simply
// no WireGuard device the read succeeds with zero devices, which is also a
// soft, non-error "nothing to show" state.
type Collector struct {
	Netops   Reader
	Interval time.Duration
	// Names resolves peer public keys to display names (from wg_peer_meta in
	// SQLite). Optional; when nil, peers fall back to a truncated key. Set by the
	// engine so the collector needn't import storage.
	Names func() map[string]string
	// IfaceNames resolves device names to human labels (from wg_iface_meta).
	// Optional; when nil, devices have no label.
	IfaceNames func() map[string]string

	mu        sync.RWMutex
	last      Snapshot
	lastErr   error
	everRead  bool
	available bool
	// prevBytes tracks the previous tick's cumulative RX/TX per peer public key
	// so we can compute per-tick deltas for the sparkline.
	prevBytes map[string]byteCounter
	// history holds the rolling delta buckets per peer public key.
	history map[string]*peerHistory
	// prevIface tracks the previous tick's cumulative interface error/drop
	// counters per device name, so device error-health reflects growth, not just
	// a nonzero lifetime total.
	prevIface map[string]ifaceCounter
}

type byteCounter struct{ rx, tx int64 }

type ifaceCounter struct{ rxErr, txErr, rxDrop, txDrop uint64 }

type peerHistory struct {
	rx []float64
	tx []float64
}

func (c *Collector) Name() string { return "wireguard" }

// Run polls until ctx is cancelled. The first read happens immediately so the
// UIs and health row have data without waiting a full interval.
func (c *Collector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Netops == nil {
		return nil
	}
	if c.Interval <= 0 {
		c.Interval = 7 * time.Second
	}
	c.prevBytes = map[string]byteCounter{}
	c.history = map[string]*peerHistory{}
	c.prevIface = map[string]ifaceCounter{}

	c.tick(bus)
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.tick(bus)
		}
	}
}

func (c *Collector) tick(bus *events.Bus) {
	now := time.Now()
	devs, err := c.Netops.ListWGDevices()
	if err != nil {
		c.mu.Lock()
		c.lastErr = err
		c.available = false
		c.everRead = true
		c.mu.Unlock()
		return
	}

	snap := Snapshot{Time: now, Devices: fromNetops(devs, now)}
	c.enrichIfaceHealth(&snap)
	c.mergeNetplan(&snap)
	c.updateHistory(&snap)

	c.mu.Lock()
	c.last = snap
	c.lastErr = nil
	c.available = true
	c.everRead = true
	c.mu.Unlock()

	if bus != nil {
		bus.Publish(events.Event{
			Kind:    events.KindWireGuardSnapshot,
			Time:    now,
			Source:  c.Name(),
			Payload: snap,
		})
	}
}

// updateHistory folds this tick's cumulative byte counters into per-peer rolling
// delta buckets and attaches the resulting sparkline slices to the snapshot's
// peers. Counter resets (peer re-created) clamp to zero rather than spiking.
func (c *Collector) updateHistory(snap *Snapshot) {
	seen := map[string]struct{}{}
	for di := range snap.Devices {
		dev := &snap.Devices[di]
		for pi := range dev.Peers {
			p := &dev.Peers[pi]
			seen[p.PublicKey] = struct{}{}
			prev := c.prevBytes[p.PublicKey]
			dRx := nonNegDelta(p.ReceiveBytes, prev.rx)
			dTx := nonNegDelta(p.TransmitBytes, prev.tx)
			c.prevBytes[p.PublicKey] = byteCounter{rx: p.ReceiveBytes, tx: p.TransmitBytes}

			h := c.history[p.PublicKey]
			if h == nil {
				h = &peerHistory{}
				c.history[p.PublicKey] = h
			}
			h.rx = appendCapped(h.rx, float64(dRx))
			h.tx = appendCapped(h.tx, float64(dTx))
			p.RXHistory = append([]float64(nil), h.rx...)
			p.TXHistory = append([]float64(nil), h.tx...)
		}
	}
	// Drop history for peers that no longer exist so the maps don't grow
	// unbounded across deprovisions.
	for k := range c.prevBytes {
		if _, ok := seen[k]; !ok {
			delete(c.prevBytes, k)
			delete(c.history, k)
		}
	}
}

// enrichIfaceHealth attaches kernel link stats to each device, computes the
// per-tick error/drop growth, and derives device + per-peer error-health. A
// device's ErrHealth is ERROR when tx/rx errors grew this tick, WARN when drops
// grew, else OK; each peer's Health is the worst of its handshake severity and
// its device's error-health (peers share the interface counters). Interface
// reads that fail (no privilege) simply leave the health neutral.
func (c *Collector) enrichIfaceHealth(snap *Snapshot) {
	ifs, err := c.Netops.ListIfaces()
	if err != nil {
		return
	}
	byName := make(map[string]netops.IfaceInfo, len(ifs))
	for _, ifi := range ifs {
		byName[ifi.Name] = ifi
	}
	seen := map[string]struct{}{}
	for di := range snap.Devices {
		d := &snap.Devices[di]
		ifi, ok := byName[d.Name]
		if !ok {
			d.ErrHealth = SevOK
			d.Health = SevOK
			continue
		}
		seen[d.Name] = struct{}{}
		d.Up, d.Running = ifi.Up, ifi.Running
		d.MTU, d.TxQLen = ifi.MTU, ifi.TxQLen
		d.RxBytes, d.TxBytes = ifi.RxBytes, ifi.TxBytes
		d.RxErrors, d.TxErrors = ifi.RxErrors, ifi.TxErrors
		d.RxDropped, d.TxDropped = ifi.RxDropped, ifi.TxDropped

		cur := ifaceCounter{rxErr: ifi.RxErrors, txErr: ifi.TxErrors, rxDrop: ifi.RxDropped, txDrop: ifi.TxDropped}
		prev, hadPrev := c.prevIface[d.Name]
		c.prevIface[d.Name] = cur
		if hadPrev {
			d.ErrDelta = deltaU(cur.rxErr, prev.rxErr) + deltaU(cur.txErr, prev.txErr)
			d.DropDelta = deltaU(cur.rxDrop, prev.rxDrop) + deltaU(cur.txDrop, prev.txDrop)
		}
		d.ErrHealth = classifyIfaceErrors(d.ErrDelta, d.DropDelta)

		// Overall device health also folds link state.
		linkSev := SevOK
		if !d.Up {
			linkSev = SevError
		}
		d.Health = WorstOf(linkSev, d.ErrHealth)

		// Fold device error-health into each peer.
		for pi := range d.Peers {
			d.Peers[pi].Health = WorstOf(d.Peers[pi].Severity, d.ErrHealth)
		}
	}
	// Forget interface state for devices that disappeared.
	for name := range c.prevIface {
		if _, ok := seen[name]; !ok {
			delete(c.prevIface, name)
		}
	}
}

// classifyIfaceErrors maps per-tick interface counter growth to a verdict:
// errors growing is an operational fault (ERROR); drops growing is degradation
// (WARN); no growth is OK.
func classifyIfaceErrors(errDelta, dropDelta uint64) Severity {
	switch {
	case errDelta > 0:
		return SevError
	case dropDelta > 0:
		return SevWarn
	default:
		return SevOK
	}
}

func deltaU(cur, prev uint64) uint64 {
	if cur < prev {
		return 0 // counter reset (link bounce) - don't spike
	}
	return cur - prev
}

// mergeNetplan folds the configured intent (netplan YAML) and peer names
// (SQLite) into the live snapshot, computing per-peer drift. This is the merged
// read at the heart of the plan: live from the kernel, intent from netplan,
// names from SQLite, joined by public key.
//
//   - peer live but not in netplan .......... DriftNotPersistent (WARN: lost on apply)
//   - peer in netplan but not live .......... added as a ConfiguredOnly peer
//   - AllowedIPs live != netplan ............ DriftConfig
//
// A netplan read that fails (no privilege, unparseable) leaves the snapshot as
// pure-live with NetplanKnown=false, so monitoring degrades softly.
func (c *Collector) mergeNetplan(snap *Snapshot) {
	var names map[string]string
	if c.Names != nil {
		names = c.Names()
	}
	nameFor := func(pub string) string {
		if names != nil {
			return names[pub]
		}
		return ""
	}
	var ifaceNames map[string]string
	if c.IfaceNames != nil {
		ifaceNames = c.IfaceNames()
	}
	labelFor := func(dev string) string {
		if ifaceNames != nil {
			return ifaceNames[dev]
		}
		return ""
	}

	configured := map[string]ConfiguredDevice{}
	if files, err := c.Netops.ListNetplan(); err == nil {
		fm := make(map[string]string, len(files))
		for _, f := range files {
			fm[f.Name] = f.Content
		}
		configured, _ = ParseNetplanFiles(fm)
	}

	live := map[string]struct{}{}
	for di := range snap.Devices {
		d := &snap.Devices[di]
		d.Label = labelFor(d.Name)
		live[d.Name] = struct{}{}
		cfg, known := configured[d.Name]
		d.NetplanKnown = known
		if known {
			d.ConfiguredAddress = cfg.Address
			d.ConfiguredPeers = len(cfg.Peers)
		}
		cfgByKey := map[string]ConfiguredPeer{}
		for _, cp := range cfg.Peers {
			cfgByKey[cp.PublicKey] = cp
		}
		matched := map[string]struct{}{}
		for pi := range d.Peers {
			p := &d.Peers[pi]
			p.Name = nameFor(p.PublicKey)
			if !known {
				continue
			}
			cp, ok := cfgByKey[p.PublicKey]
			if !ok {
				p.Drift = DriftNotPersistent // live but not persisted
				continue
			}
			matched[p.PublicKey] = struct{}{}
			p.ConfiguredAllowedIPs = cp.AllowedIPs
			p.ConfiguredEndpoint = cp.Endpoint
			// Only AllowedIPs drift is reliable; endpoints legitimately differ
			// (configured hostname vs live resolved/roaming address).
			if !sameIPSet(p.AllowedIPs, cp.AllowedIPs) {
				p.Drift = DriftConfig
			}
		}
		// Configured-but-not-live peers: declared in netplan, absent on the device.
		if known {
			for _, cp := range cfg.Peers {
				if _, ok := matched[cp.PublicKey]; ok {
					continue
				}
				d.Peers = append(d.Peers, Peer{
					PublicKey:            cp.PublicKey,
					Name:                 nameFor(cp.PublicKey),
					AllowedIPs:           cp.AllowedIPs,
					ConfiguredAllowedIPs: cp.AllowedIPs,
					ConfiguredEndpoint:   cp.Endpoint,
					Never:                true,
					ConfiguredOnly:       true,
					Drift:                DriftConfigOnly,
					Severity:             SevCritical, // never handshaked
					Health:               WorstOf(SevCritical, d.ErrHealth),
				})
			}
		}
		for _, p := range d.Peers {
			if p.Drift != DriftNone {
				d.DriftCount++
			}
		}
	}

	// Devices declared in netplan but with no live kernel device (interface down
	// or not yet applied) - surface them so the dashboard shows "configured, not up".
	for name, cfg := range configured {
		if _, ok := live[name]; ok {
			continue
		}
		dev := Device{
			Name:              name,
			Label:             labelFor(name),
			ListenPort:        cfg.ListenPort,
			NetplanKnown:      true,
			ConfiguredAddress: cfg.Address,
			ConfiguredPeers:   len(cfg.Peers),
			ErrHealth:         SevOK,
			Health:            SevError, // configured but not up
		}
		for _, cp := range cfg.Peers {
			dev.Peers = append(dev.Peers, Peer{
				PublicKey:            cp.PublicKey,
				Name:                 nameFor(cp.PublicKey),
				AllowedIPs:           cp.AllowedIPs,
				ConfiguredAllowedIPs: cp.AllowedIPs,
				ConfiguredEndpoint:   cp.Endpoint,
				Never:                true,
				ConfiguredOnly:       true,
				Drift:                DriftConfigOnly,
				Severity:             SevCritical,
				Health:               SevCritical,
			})
			dev.DriftCount++
		}
		snap.Devices = append(snap.Devices, dev)
	}
}

// sameIPSet compares two AllowedIP lists as normalised (host-CIDR, trimmed) sets.
func sameIPSet(a, b []string) bool {
	na, nb := normIPSet(a), normIPSet(b)
	if len(na) != len(nb) {
		return false
	}
	for k := range na {
		if _, ok := nb[k]; !ok {
			return false
		}
	}
	return true
}

func normIPSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out[hostCIDR(s)] = struct{}{}
	}
	return out
}

// Snapshot returns the most recent snapshot (public material only). ok is false
// when no successful read has happened yet.
func (c *Collector) Snapshot() (Snapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.everRead || !c.available {
		return Snapshot{}, false
	}
	return c.last, true
}

// Available reports whether WireGuard state could be read this tick. It is false
// before the first read and whenever the read errors (e.g. missing
// CAP_NET_ADMIN). A successful read with zero devices is still "available".
func (c *Collector) Available() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.available
}

// LastErr returns the last read error, if any.
func (c *Collector) LastErr() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastErr
}

func nonNegDelta(cur, prev int64) int64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func appendCapped(s []float64, v float64) []float64 {
	s = append(s, v)
	if len(s) > historyLen {
		s = s[len(s)-historyLen:]
	}
	return s
}
