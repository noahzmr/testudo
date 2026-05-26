package analyzers

import (
	"context"
	"fmt"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
)

// DeviceChatterDetector watches the per-device bandwidth history and
// alerts when a device's recent TX rate exceeds a multiple of its
// rolling baseline. Catches exfil-y patterns, runaway containers,
// loops - anything where a previously quiet host suddenly goes loud.
//
// The detector is tick-driven (no event subscription), so the input
// channel is ignored. Engine.startAnalyzers still wires the closed sub
// for uniform shutdown.
type DeviceChatterDetector struct {
	Bandwidth *flows.DeviceBandwidth

	// Interval is how often we evaluate; should be no shorter than the
	// bandwidth aggregator's bucket size.
	Interval time.Duration

	// RecentBuckets is how many of the newest buckets count as "now"
	// (default 3 - last 15s at 5s/bucket).
	RecentBuckets int

	// BaselineBuckets is how many buckets define the baseline median
	// (default 60 - last 5 min at 5s/bucket). Must be > RecentBuckets.
	BaselineBuckets int

	// Factor is the multiplier above baseline that fires WARN; 2×
	// Factor fires ERROR.
	Factor float64

	// MinBaselineBps suppresses noise: don't alert on a device that's
	// idle most of the time and gets a small burst. 1 KB/s default.
	MinBaselineBps float64

	cool map[string]time.Time
}

func (d *DeviceChatterDetector) Name() string { return "device-chatter" }

func (d *DeviceChatterDetector) Run(ctx context.Context, _ <-chan events.Event, bus *events.Bus) error {
	if d.Bandwidth == nil || d.Interval <= 0 {
		return nil
	}
	if d.RecentBuckets <= 0 {
		d.RecentBuckets = 3
	}
	if d.BaselineBuckets <= d.RecentBuckets {
		d.BaselineBuckets = d.RecentBuckets + 60
	}
	if d.Factor <= 0 {
		d.Factor = 3.0
	}
	if d.MinBaselineBps <= 0 {
		d.MinBaselineBps = 1024
	}
	d.cool = map[string]time.Time{}
	ticker := time.NewTicker(d.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			d.evaluate(bus)
		}
	}
}

func (d *DeviceChatterDetector) evaluate(bus *events.Bus) {
	bucketSize := d.Bandwidth.BucketSizeDuration()
	if bucketSize == 0 {
		return
	}
	now := time.Now()
	for _, s := range d.Bandwidth.All(0) {
		if len(s.TX) < d.BaselineBuckets {
			continue
		}
		// Newest buckets are at the END of the chronological slice.
		recent := s.TX[len(s.TX)-d.RecentBuckets:]
		baseline := s.TX[len(s.TX)-d.BaselineBuckets : len(s.TX)-d.RecentBuckets]
		recentBps := bytesPerSecond(recent, bucketSize)
		baseBps := medianBps(baseline, bucketSize)
		if baseBps < d.MinBaselineBps {
			continue
		}
		if recentBps < baseBps*d.Factor {
			continue
		}
		if t, ok := d.cool[s.IP]; ok && now.Sub(t) < 5*time.Minute {
			continue
		}
		d.cool[s.IP] = now
		sev := events.SevWarn
		if recentBps >= baseBps*d.Factor*2 {
			sev = events.SevError
		}
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: d.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(sev),
				Message: fmt.Sprintf("%s TX %.1f KB/s is %.1f× baseline (%.1f KB/s)",
					s.IP, recentBps/1024, recentBps/baseBps, baseBps/1024),
			},
		})
	}
}

func bytesPerSecond(buckets []uint64, bucketSize time.Duration) float64 {
	if len(buckets) == 0 || bucketSize == 0 {
		return 0
	}
	var sum uint64
	for _, b := range buckets {
		sum += b
	}
	total := float64(sum)
	dur := bucketSize.Seconds() * float64(len(buckets))
	return total / dur
}

// medianBps converts a baseline window to bytes/sec using the median
// bucket value (robust to one-off spikes that would skew an average).
func medianBps(buckets []uint64, bucketSize time.Duration) float64 {
	if len(buckets) == 0 || bucketSize == 0 {
		return 0
	}
	cp := make([]uint64, len(buckets))
	copy(cp, buckets)
	// Insertion sort - baseline windows are small.
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j] < cp[j-1]; j-- {
			cp[j], cp[j-1] = cp[j-1], cp[j]
		}
	}
	med := cp[len(cp)/2]
	return float64(med) / bucketSize.Seconds()
}
