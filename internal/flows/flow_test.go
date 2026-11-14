package flows

import (
	"fmt"
	"testing"
)

// These tests pin the flow table's contract without touching the kernel, so
// they run everywhere (including hosts where the namespace baseline in
// internal/capture has to skip).

func TestAggregatorMergesBothDirections(t *testing.T) {
	a := NewAggregator()
	a.Update("eth0", "10.0.0.2", 40000, "10.0.0.9", 443, "tcp", 100)
	a.Update("eth0", "10.0.0.9", 443, "10.0.0.2", 40000, "tcp", 900)
	a.Update("eth0", "10.0.0.2", 40000, "10.0.0.9", 443, "tcp", 60)

	snap := a.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d flows, want 1 bidirectional flow", len(snap))
	}
	f := snap[0]
	wantKey := FlowKey{Iface: "eth0", Proto: "tcp",
		A: Endpoint{IP: "10.0.0.2", Port: 40000}, B: Endpoint{IP: "10.0.0.9", Port: 443}}
	if f.Key != wantKey {
		t.Errorf("key = %+v, want %+v", f.Key, wantKey)
	}
	if f.Packets != 3 || f.Bytes != 1060 || f.BytesAtoB != 160 || f.BytesBtoA != 900 {
		t.Errorf("packets=%d bytes=%d a->b=%d b->a=%d; want 3/1060/160/900",
			f.Packets, f.Bytes, f.BytesAtoB, f.BytesBtoA)
	}
	if f.FirstSeen.IsZero() || f.LastSeen.Before(f.FirstSeen) {
		t.Errorf("bad timestamps: first=%v last=%v", f.FirstSeen, f.LastSeen)
	}
}

func TestAggregatorKeysPerInterfaceProtoAndPort(t *testing.T) {
	a := NewAggregator()
	// The same conversation seen on two interfaces (a routed or NATed path)
	// stays two flows; so do different protocols and different ports.
	a.Update("lan0", "10.0.0.2", 1000, "10.0.1.2", 53, "udp", 10)
	a.Update("wan0", "10.0.0.2", 1000, "10.0.1.2", 53, "udp", 10)
	a.Update("lan0", "10.0.0.2", 1000, "10.0.1.2", 53, "tcp", 10)
	a.Update("lan0", "10.0.0.2", 1001, "10.0.1.2", 53, "udp", 10)
	if n := len(a.Snapshot()); n != 4 {
		t.Fatalf("got %d flows, want 4", n)
	}
}

func TestAggregatorSamePeerOrdersByPort(t *testing.T) {
	a := NewAggregator()
	a.Update("lo", "127.0.0.1", 9000, "127.0.0.1", 80, "tcp", 7)
	f := a.Snapshot()[0]
	if f.Key.A.Port != 80 || f.Key.B.Port != 9000 || f.BytesBtoA != 7 || f.BytesAtoB != 0 {
		t.Errorf("key=%+v a->b=%d b->a=%d", f.Key, f.BytesAtoB, f.BytesBtoA)
	}
}

func TestAggregatorIsBounded(t *testing.T) {
	a := NewAggregator()
	const extra = 50
	for i := 0; i < a.maxKeep+extra; i++ {
		a.Update("eth0", "10.0.0.2", uint16(1+i%60000), fmt.Sprintf("10.1.%d.%d", i/250, i%250), 443, "tcp", 1)
	}
	if n := len(a.Snapshot()); n != a.maxKeep {
		t.Fatalf("table holds %d flows, want it capped at %d", n, a.maxKeep)
	}
}

func TestAggregatorResetAndRecencyOrder(t *testing.T) {
	a := NewAggregator()
	a.Update("eth0", "10.0.0.2", 1, "10.0.0.3", 2, "udp", 1)
	a.Update("eth0", "10.0.0.2", 3, "10.0.0.3", 4, "udp", 1)
	top := a.TopByRecency(1)
	if len(top) != 1 || top[0].Key.A.Port != 3 {
		t.Fatalf("TopByRecency(1) = %+v, want the most recent flow (port 3)", top)
	}
	a.Reset()
	if n := len(a.Snapshot()); n != 0 {
		t.Fatalf("after Reset: %d flows", n)
	}
}

func TestSummarizeDirections(t *testing.T) {
	a := NewAggregator()
	a.Update("eth0", "10.0.0.2", 40000, "10.0.0.9", 443, "tcp", 100)
	a.Update("eth0", "10.0.0.9", 443, "10.0.0.2", 40000, "tcp", 900)
	f := a.Snapshot()[0]
	f.Process = "curl"
	got := f.Summarize()
	want := FlowSummary{Interface: "eth0", SrcIP: "10.0.0.2", DstIP: "10.0.0.9", Protocol: "tcp",
		BytesOut: 100, BytesIn: 900, ProcessName: "curl"}
	if got != want {
		t.Errorf("Summarize() = %+v, want %+v", got, want)
	}
}

func TestApplyTCPStatsJoinsExistingFlow(t *testing.T) {
	a := NewAggregator()
	a.Update("eth0", "10.0.0.2", 40000, "10.0.0.9", 443, "tcp", 100)
	// Telemetry reports the tuple from the other side; it must land on the
	// same flow instead of creating a second one.
	a.ApplyTCPStats("eth0", "10.0.0.9", 443, "10.0.0.2", 40000, "tcp", FlowTCPStats{RTTus: 1500, Source: "inet_diag"})
	snap := a.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d flows, want 1", len(snap))
	}
	if !snap[0].HasTCP() || snap[0].TCP.RTTms() != 1.5 || snap[0].Packets != 1 {
		t.Errorf("flow = %+v", snap[0])
	}
}
