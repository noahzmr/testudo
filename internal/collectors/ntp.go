package collectors

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/noahzmr/testudo/internal/events"
)

// NTPCollector reports system-clock health from the kernel's time-discipline
// state via adjtimex(2). It is pure-Go, makes no network query and execs
// nothing: adjtimex with Modes=0 is a read-only snapshot of whatever NTP daemon
// (chrony/ntpd/systemd-timesyncd) is - or isn't - disciplining the clock.
//
// It surfaces two faults:
//   - the clock is unsynchronised (STA_UNSYNC) - no daemon is keeping time, so
//     TLS handshakes, tokens, logs and Kerberos quietly drift wrong, and
//   - the estimated offset exceeds the configured warning threshold.
type NTPCollector struct {
	Interval     time.Duration
	OffsetWarnMs float64

	mu     sync.RWMutex
	status NTPStatus

	lastFired map[string]time.Time
}

// NTPStatus is the Health-tab card for clock health.
type NTPStatus struct {
	Synchronised bool    // clock is being disciplined (STA_UNSYNC clear)
	OffsetMs     float64 // current estimated offset, ms (signed)
	EstErrorMs   float64 // kernel's estimated error, ms
	MaxErrorMs   float64 // kernel's maximum error, ms
	State        string  // human label (synchronised / unsynchronised / error)
	Supported    bool    // adjtimex succeeded on this host
	LastErr      string  // last sample error, empty when healthy
	Updated      time.Time
}

func (c *NTPCollector) Name() string { return "ntp" }

// Status returns the current clock-health card for rendering.
func (c *NTPCollector) Status() NTPStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *NTPCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.OffsetWarnMs <= 0 {
		c.OffsetWarnMs = 100
	}
	c.lastFired = map[string]time.Time{}

	c.sample(bus)
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.sample(bus)
		}
	}
}

func (c *NTPCollector) sample(bus *events.Bus) {
	now := time.Now()
	var tx unix.Timex // Modes=0 -> read-only query, no clock adjustment
	state, err := unix.Adjtimex(&tx)
	st := NTPStatus{Updated: now}
	if err != nil {
		st.LastErr = err.Error()
		c.store(st)
		return
	}
	st.Supported = true

	// Offset/error units are microseconds unless STA_NANO is set, then nanos.
	div := 1000.0 // us -> ms
	if tx.Status&unix.STA_NANO != 0 {
		div = 1_000_000.0 // ns -> ms
	}
	st.OffsetMs = float64(tx.Offset) / div
	st.EstErrorMs = float64(tx.Esterror) / 1000.0 // esterror is always us
	st.MaxErrorMs = float64(tx.Maxerror) / 1000.0
	st.Synchronised = tx.Status&unix.STA_UNSYNC == 0 && state != unix.TIME_ERROR

	switch {
	case !st.Synchronised:
		st.State = "unsynchronised"
	default:
		st.State = "synchronised"
	}
	c.store(st)

	if bus == nil {
		return
	}
	if !st.Synchronised {
		c.fire(bus, now, "unsync", events.SevWarn,
			"system clock not synchronised - no NTP discipline (chrony/ntpd/timesyncd); time-sensitive checks may drift")
		return
	}
	if abs := math.Abs(st.OffsetMs); abs >= c.OffsetWarnMs {
		sev := events.SevWarn
		if abs >= 4*c.OffsetWarnMs {
			sev = events.SevError
		}
		c.fire(bus, now, "offset", sev,
			fmt.Sprintf("system clock offset %.1fms (warn %.0fms) - NTP discipline lagging", st.OffsetMs, c.OffsetWarnMs))
	}
}

func (c *NTPCollector) store(st NTPStatus) {
	c.mu.Lock()
	c.status = st
	c.mu.Unlock()
}

// fire publishes an anomaly behind a per-key 5-minute cooldown so a persistent
// clock condition doesn't flood the Alerts tab.
func (c *NTPCollector) fire(bus *events.Bus, now time.Time, key string, sev events.Severity, msg string) {
	if last, ok := c.lastFired[key]; ok && now.Sub(last) < 5*time.Minute {
		return
	}
	c.lastFired[key] = now
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: c.Name(), Time: now,
		Payload: events.AnomalyPayload{Severity: string(sev), Message: msg},
	})
}
