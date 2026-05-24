package metrics

import (
	"sort"
	"sync"
	"time"
)

// BandwidthHistory stores per-interface RX/TX byte counters and computes a
// rolling per-second rate. The engine ticks Update once per second from
// netops.ListIfaces; the TUI/web dashboards read Snapshot.
//
// One sniffnet feature we adopt verbatim: a small, low-allocation rolling
// chart of bytes-per-second per interface. Combined with the existing
// sparkline renderer this gives "live bandwidth" parity.
type BandwidthHistory struct {
	mu     sync.RWMutex
	window int // samples per interface
	last   map[string]ifSample
	rx     map[string][]float64 // bytes/sec
	tx     map[string][]float64
	// Cumulative — survives Snapshot; useful for "Total RX/TX since
	// start" summary panels.
	cumRx map[string]uint64
	cumTx map[string]uint64
	// Per-iface "first sample at" — lets the UI distinguish a brand-new
	// interface from one that's been seen for a while.
	firstSeen map[string]time.Time
}

type ifSample struct {
	rx, tx uint64
	at     time.Time
}

// NewBandwidthHistory returns a history that keeps `window` samples per
// interface. 120 covers two minutes of 1Hz data — enough for a smooth chart
// without dragging tens of KB per iface.
func NewBandwidthHistory(window int) *BandwidthHistory {
	if window < 8 {
		window = 8
	}
	return &BandwidthHistory{
		window:    window,
		last:      map[string]ifSample{},
		rx:        map[string][]float64{},
		tx:        map[string][]float64{},
		cumRx:     map[string]uint64{},
		cumTx:     map[string]uint64{},
		firstSeen: map[string]time.Time{},
	}
}

// Update records one (rx,tx) cumulative-counter pair for an interface. The
// first call seeds; subsequent calls compute the byte/second rate vs the
// previous sample.
func (b *BandwidthHistory) Update(name string, rx, tx uint64) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.firstSeen[name]; !ok {
		b.firstSeen[name] = now
	}
	prev, hadPrev := b.last[name]
	b.last[name] = ifSample{rx: rx, tx: tx, at: now}
	if !hadPrev {
		// Seed the rings with a single 0 so the chart isn't empty on the
		// very first paint.
		b.rx[name] = []float64{0}
		b.tx[name] = []float64{0}
		return
	}
	dt := now.Sub(prev.at).Seconds()
	if dt <= 0 {
		return
	}
	// Kernel counters are monotonic, but link state changes (down → up)
	// can reset them. Clamp negative deltas to 0 rather than overflowing.
	var dRx, dTx float64
	if rx >= prev.rx {
		dRx = float64(rx-prev.rx) / dt
	}
	if tx >= prev.tx {
		dTx = float64(tx-prev.tx) / dt
	}
	b.rx[name] = appendRing(b.rx[name], dRx, b.window)
	b.tx[name] = appendRing(b.tx[name], dTx, b.window)
	if rx >= prev.rx {
		b.cumRx[name] += rx - prev.rx
	}
	if tx >= prev.tx {
		b.cumTx[name] += tx - prev.tx
	}
}

// BandwidthSnapshot is the read-side view of one interface's history.
type BandwidthSnapshot struct {
	Iface       string
	RxBytesPerS []float64
	TxBytesPerS []float64
	CurrentRx   float64
	CurrentTx   float64
	PeakRx      float64
	PeakTx      float64
	CumRx       uint64
	CumTx       uint64
	FirstSeen   time.Time
}

// Snapshot returns one entry per known interface, sorted by current TX+RX
// (busiest first — matches sniffnet's "Overview" ordering).
func (b *BandwidthHistory) Snapshot() []BandwidthSnapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]BandwidthSnapshot, 0, len(b.rx))
	for name, rxRing := range b.rx {
		txRing := b.tx[name]
		snap := BandwidthSnapshot{
			Iface:       name,
			RxBytesPerS: append([]float64(nil), rxRing...),
			TxBytesPerS: append([]float64(nil), txRing...),
			CumRx:       b.cumRx[name],
			CumTx:       b.cumTx[name],
			FirstSeen:   b.firstSeen[name],
		}
		if n := len(rxRing); n > 0 {
			snap.CurrentRx = rxRing[n-1]
		}
		if n := len(txRing); n > 0 {
			snap.CurrentTx = txRing[n-1]
		}
		for _, v := range rxRing {
			if v > snap.PeakRx {
				snap.PeakRx = v
			}
		}
		for _, v := range txRing {
			if v > snap.PeakTx {
				snap.PeakTx = v
			}
		}
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].CurrentRx + out[i].CurrentTx) > (out[j].CurrentRx + out[j].CurrentTx)
	})
	return out
}

func appendRing(buf []float64, v float64, max int) []float64 {
	buf = append(buf, v)
	if len(buf) > max {
		buf = buf[len(buf)-max:]
	}
	return buf
}
