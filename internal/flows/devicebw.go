package flows

import (
	"sync"
	"time"
)

// DeviceBandwidth holds a rolling per-device RX/TX byte history. Each
// LAN host gets a fixed-length ring of buckets, BucketSize wide; the
// Sample method is called periodically (typically every BucketSize) with
// a flow snapshot and a now-time. Cumulative byte counters from the flow
// aggregator are differenced against the previous sample to derive the
// per-bucket delta; flows evicted from the aggregator look like a
// counter reset and are clamped to 0.
//
// All accesses are guarded by a single RWMutex - the sampler holds the
// write lock during the (cheap) ingest, every renderer takes RLock for
// the snapshot copy. Read-heavy by design.
type DeviceBandwidth struct {
	mu             sync.RWMutex
	bucketSize     time.Duration
	numBuckets     int
	devices        map[string]*deviceHistory
	prevCumulative map[string]bytePair
}

type bytePair struct{ rx, tx uint64 }

type deviceHistory struct {
	rx         []uint64
	tx         []uint64
	head       int // newest bucket index
	lastTickAt time.Time
}

func NewDeviceBandwidth(bucketSize time.Duration, numBuckets int) *DeviceBandwidth {
	if bucketSize <= 0 {
		bucketSize = 5 * time.Second
	}
	if numBuckets <= 0 {
		numBuckets = 120 // 10 minutes at 5s buckets
	}
	return &DeviceBandwidth{
		bucketSize:     bucketSize,
		numBuckets:     numBuckets,
		devices:        map[string]*deviceHistory{},
		prevCumulative: map[string]bytePair{},
	}
}

// Sample folds the flow snapshot into per-device counters. Should be
// called once per BucketSize - calling more often is harmless (deltas
// accumulate in the current bucket), but spacing the calls means the
// per-bucket value reads as a rate.
func (d *DeviceBandwidth) Sample(snap []FlowStats, now time.Time) {
	current := map[string]bytePair{}
	for _, f := range snap {
		// RX/TX is relative to the device side - bytes received by the
		// LAN host are bytes flowing TOWARDS its endpoint.
		if IsLAN(f.Key.A.IP) {
			c := current[f.Key.A.IP]
			c.rx += f.BytesBtoA
			c.tx += f.BytesAtoB
			current[f.Key.A.IP] = c
		}
		if IsLAN(f.Key.B.IP) {
			c := current[f.Key.B.IP]
			c.rx += f.BytesAtoB
			c.tx += f.BytesBtoA
			current[f.Key.B.IP] = c
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for ip, cur := range current {
		h := d.devices[ip]
		if h == nil {
			h = &deviceHistory{
				rx:         make([]uint64, d.numBuckets),
				tx:         make([]uint64, d.numBuckets),
				lastTickAt: now,
			}
			d.devices[ip] = h
		}
		d.advance(h, now)
		prev := d.prevCumulative[ip]
		var dr, dt uint64
		if cur.rx >= prev.rx {
			dr = cur.rx - prev.rx
		}
		if cur.tx >= prev.tx {
			dt = cur.tx - prev.tx
		}
		h.rx[h.head] += dr
		h.tx[h.head] += dt
		d.prevCumulative[ip] = cur
	}
}

// advance rolls the ring head forward by the number of bucketSize
// intervals that have elapsed since the last update. Empty buckets
// passed through are zeroed so a quiet device doesn't show stale rates.
func (d *DeviceBandwidth) advance(h *deviceHistory, now time.Time) {
	if h.lastTickAt.IsZero() {
		h.lastTickAt = now
		return
	}
	steps := int(now.Sub(h.lastTickAt) / d.bucketSize)
	if steps <= 0 {
		return
	}
	if steps > d.numBuckets {
		steps = d.numBuckets
	}
	for i := 0; i < steps; i++ {
		h.head = (h.head + 1) % d.numBuckets
		h.rx[h.head] = 0
		h.tx[h.head] = 0
	}
	h.lastTickAt = h.lastTickAt.Add(time.Duration(steps) * d.bucketSize)
}

// DeviceSample is a single device's rolling history, returned by
// Snapshot in chronological (oldest-first) order. RX/TX are bytes per
// bucket - divide by bucketSize for byte/s.
type DeviceSample struct {
	IP         string
	RX         []uint64
	TX         []uint64
	TotalRX    uint64
	TotalTX    uint64
	BucketSize time.Duration
}

// Snapshot returns chronological RX/TX histories for the requested IP,
// or zero-value if the IP hasn't been seen. The returned slices are
// fresh copies; callers may mutate them.
func (d *DeviceBandwidth) Snapshot(ip string) DeviceSample {
	d.mu.RLock()
	defer d.mu.RUnlock()
	h := d.devices[ip]
	if h == nil {
		return DeviceSample{IP: ip, BucketSize: d.bucketSize}
	}
	rx, tx := make([]uint64, d.numBuckets), make([]uint64, d.numBuckets)
	var totalRX, totalTX uint64
	// head is newest; we want oldest-first. Walk forward from head+1.
	for i := 0; i < d.numBuckets; i++ {
		src := (h.head + 1 + i) % d.numBuckets
		rx[i] = h.rx[src]
		tx[i] = h.tx[src]
		totalRX += rx[i]
		totalTX += tx[i]
	}
	return DeviceSample{
		IP: ip, RX: rx, TX: tx,
		TotalRX: totalRX, TotalTX: totalTX,
		BucketSize: d.bucketSize,
	}
}

// All returns a snapshot for every device currently tracked, sorted by
// total RX+TX desc. n<=0 returns all.
func (d *DeviceBandwidth) All(n int) []DeviceSample {
	d.mu.RLock()
	ips := make([]string, 0, len(d.devices))
	for ip := range d.devices {
		ips = append(ips, ip)
	}
	d.mu.RUnlock()
	out := make([]DeviceSample, 0, len(ips))
	for _, ip := range ips {
		out = append(out, d.Snapshot(ip))
	}
	// In-place insertion sort is fine; LAN host counts are tiny.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && (out[j].TotalRX+out[j].TotalTX) > (out[j-1].TotalRX+out[j-1].TotalTX); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// BucketSize exposes the configured bucket width so renderers can label
// the sparkline correctly.
func (d *DeviceBandwidth) BucketSizeDuration() time.Duration { return d.bucketSize }
