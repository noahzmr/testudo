package analyzers

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/events"
)

// runDetector feeds evs through a detector and returns the anomaly messages
// it published.
func runDetector(t *testing.T, a Analyzer, evs []events.Event) []string {
	t.Helper()
	bus := events.NewBus(64)
	sub := bus.SubscribeKinds(events.KindAnomaly)
	defer sub.Close()
	in := make(chan events.Event, len(evs))
	for _, e := range evs {
		in <- e
	}
	close(in)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = a.Run(ctx, in, bus)
	var out []string
	for {
		select {
		case e := <-sub.C():
			out = append(out, e.Payload.(events.AnomalyPayload).Message)
		default:
			return out
		}
	}
}

func lat(target string, ms float64) events.Event {
	return events.Event{Kind: events.KindLatency, Payload: events.LatencyPayload{
		Target: target, RTT: time.Duration(ms * float64(time.Millisecond)),
	}}
}

// The WiFi collector publishes link metrics as KindLatency ("wifi:freq:…"
// carries 5180 for a 5 GHz channel). Before the fix every such sample raised
// a CRITICAL "high RTT" alert; only real host targets may.
func TestHighRTTIgnoresEncodedSeries(t *testing.T) {
	d := &HighRTTDetector{Settings: config.NewSettingsStore(filepath.Join(t.TempDir(), "s.json"))}
	msgs := runDetector(t, d, []events.Event{
		lat("wifi:freq:wlan0", 5180),
		lat("wifi:tx-rate:wlan0", 1080),
		lat("trace:1.1.1.1:hop4", 900),
		lat("bufferbloat:loaded:1.1.1.1", 400),
		lat("https://example.org/", 450),
		lat("2001:4860:4860::8888", 400), // IPv6 host: a real target
		lat("10.0.0.5:22", 300),          // TCP probe: a real target
	})
	if len(msgs) != 2 {
		t.Fatalf("got %d alerts, want 2 (IPv6 host + TCP probe): %q", len(msgs), msgs)
	}
	for _, m := range msgs {
		if strings.Contains(m, "wifi:") || strings.Contains(m, "trace:") || strings.Contains(m, "bufferbloat:") || strings.Contains(m, "https://") {
			t.Errorf("alert for a non-RTT series: %s", m)
		}
	}
}

func TestBandwidthSpikeNeedsAbsoluteRate(t *testing.T) {
	d := &BandwidthSpikeDetector{Factor: 3, MinRate: 1e6}
	if d.isSpike("docker0", 7_000, 1_000) {
		t.Error("7 KB/s over a 1 KB/s baseline on an idle bridge is not a spike")
	}
	if d.isSpike("lo", 30e6, 1e3) {
		t.Error("loopback bursts are host-local")
	}
	if !d.isSpike("eth0", 5e6, 1e6) {
		t.Error("5 MB/s over a 1 MB/s baseline is a spike")
	}
	if d.isSpike("eth0", 2.5e6, 1e6) {
		t.Error("2.5x is under the 3x factor")
	}
}
