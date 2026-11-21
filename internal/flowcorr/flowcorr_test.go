package flowcorr

import (
	"fmt"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/flows"
)

func f(iface, proto, a string, ap uint16, b string, bp uint16, bytes uint64, at time.Time, attrs flows.Attrs) flows.FlowStats {
	return flows.FlowStats{Key: flows.FlowKey{Iface: iface, Proto: proto, A: flows.Endpoint{IP: a, Port: ap}, B: flows.Endpoint{IP: b, Port: bp}},
		Bytes: bytes, FirstSeen: at, LastSeen: at.Add(time.Second), Attrs: attrs}
}

func TestCorrelate(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	hq := NodeFlows{Node: "n1", Site: "hq", Flows: []flows.FlowStats{
		// hq's host talks to the branch: on the LAN and in the tunnel.
		f("lan0", "tcp", "10.1.0.5", 33000, "10.2.0.9", 443, 1000, t0, flows.Attrs{Site: "hq", Zone: "lan"}),
		f("tm02c1s0", "tcp", "10.2.0.9", 443, "10.1.0.5", 33000, 1100, t0, flows.Attrs{Site: "hq", Tunnel: "fabric", Peer: "n2", PeerSite: "branch", Path: "mpls"}),
		// the tunnel's carrier is a connection of its own
		f("eth1", "udp", "100.65.1.1", 52033, "100.65.2.1", 52034, 5000, t0, flows.Attrs{Site: "hq", Tunnel: "fabric", Path: "mpls", Carrier: true}),
		// only hq saw this one
		f("lan0", "udp", "10.1.0.5", 5353, "10.1.0.6", 5353, 10, t0, flows.Attrs{}),
		// the same addresses an hour later: another connection
	}}
	branch := NodeFlows{Node: "n2", Site: "branch", Flows: []flows.FlowStats{
		f("tm01c1s0", "tcp", "10.1.0.5", 33000, "10.2.0.9", 443, 1050, t0.Add(500*time.Millisecond), flows.Attrs{Site: "branch", Path: "mpls", Tunnel: "fabric"}),
		f("lan0", "tcp", "10.1.0.5", 33000, "10.2.0.9", 443, 1000, t0.Add(500*time.Millisecond), flows.Attrs{Site: "branch"}),
		f("lan0", "udp", "10.1.0.5", 5353, "10.1.0.6", 5353, 10, t0.Add(time.Hour), flows.Attrs{}),
		// a port forward at the branch, seen before and after translation;
		// hq saw the client's side of it on its way out.
		f("wan0", "tcp", "198.51.100.9", 4000, "100.64.2.1", 8443, 700, t0, flows.Attrs{PreNAT: "tcp 198.51.100.9:4000 > 100.64.2.1:8443", PostNAT: "tcp 198.51.100.9:4000 > 10.2.0.20:443"}),
		f("lan0", "tcp", "10.2.0.20", 443, "198.51.100.9", 4000, 650, t0, flows.Attrs{PreNAT: "tcp 198.51.100.9:4000 > 100.64.2.1:8443", PostNAT: "tcp 198.51.100.9:4000 > 10.2.0.20:443"}),
	}}
	hq.Flows = append(hq.Flows, f("eth0", "tcp", "198.51.100.9", 4000, "100.64.2.1", 8443, 720, t0, flows.Attrs{}))

	got := Correlate([]NodeFlows{hq, branch}, 30*time.Second, false)
	if len(got) != 2 {
		for _, c := range got {
			t.Logf("%s %s %s %v", c.Proto, c.A, c.B, c.Sites)
		}
		t.Fatalf("%d connections seen at both sites, want 2", len(got))
	}
	c := got[0]
	if c.A != "10.1.0.5:33000" && c.B != "10.1.0.5:33000" || fmt.Sprint(c.Sites) != "[branch hq]" || fmt.Sprint(c.Paths) != "[mpls]" ||
		len(c.Sightings) != 4 || c.Bytes != 1100 {
		t.Errorf("site to site: %+v", c)
	}
	nat := got[1]
	if nat.A != "198.51.100.9:4000" || nat.B != "100.64.2.1:8443" || len(nat.Sightings) != 3 || fmt.Sprint(nat.Sites) != "[branch hq]" {
		t.Errorf("the port forward: %+v", nat)
	}
	// With all, the local-only ones come too, and the hour-apart pair
	// stays two connections.
	all := Correlate([]NodeFlows{hq, branch}, 30*time.Second, true)
	mdns := 0
	for _, c := range all {
		if c.Proto == "udp" && c.A == "10.1.0.5:5353" {
			mdns++
		}
	}
	if mdns != 2 {
		t.Errorf("connections an hour apart were joined: %d", mdns)
	}
}
