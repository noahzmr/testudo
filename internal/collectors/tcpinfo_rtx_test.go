package collectors

import (
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/telemetry"
)

// A near-idle flow with one retransmit out of five segments reads "20%"; it
// must not raise an alert. A busy flow over the threshold must.
func TestFlowRTXAlertNeedsEvidence(t *testing.T) {
	th := config.DefaultThresholds()
	now := time.Now()
	prev := flowCounters{totalRetrans: 10, segsOut: 100, seen: now.Add(-5 * time.Second)}

	cases := []struct {
		name          string
		retrans, segs uint32 // deltas over the interval
		rate          float64
		want          bool
	}{
		{"keep-alive: 1 of 5", 1, 5, 20, false},
		{"small burst: 2 of 40", 2, 40, 5, false},
		{"thin flow: 4 of 20", 4, 20, 20, false},
		{"busy flow: 12 of 200", 12, 200, 6, true},
		{"busy but under threshold: 3 of 200", 3, 200, 1.5, false},
	}
	for _, tc := range cases {
		c := &TCPInfoCollector{cooldown: map[string]time.Time{}}
		bus := events.NewBus(8)
		sub := bus.SubscribeKinds(events.KindAnomaly)
		s := telemetry.Sample{
			SrcIP: "10.0.0.2", DstIP: "1.1.1.1", DstPort: 443, RTTus: 15000,
			TotalRetrans: prev.totalRetrans + tc.retrans,
			SegsOut:      prev.segsOut + tc.segs,
		}
		c.detectAnomalies(bus, s, prev, tc.rate, th, now)
		got := false
		select {
		case <-sub.C():
			got = true
		default:
		}
		sub.Close()
		if got != tc.want {
			t.Errorf("%s: alert=%v, want %v", tc.name, got, tc.want)
		}
	}
}
