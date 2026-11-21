//go:build linux

package capture_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/testnet"
)

// The flow-analysis baseline.
//
// Topology (the test process is the router, exactly where Testudo sits on an
// appliance):
//
//	client ns                 router (test process)               server ns
//	eth0 10.77.1.2/24 ─────── lan0 10.77.1.1/24
//	     fd77:1::2/64              fd77:1::1/64
//	                          wan0 10.77.2.1/24 ─────── eth0 10.77.2.2/24
//	                               fd77:2::1/64              fd77:2::2/64
//
// Known traffic is pushed client -> server through the router and the real
// capture pipeline (AF_PACKET -> decode -> flows.Aggregator) must report
// exactly the expected flows, packet counts, byte counts and directions on
// both interfaces. Every later change to filtering, NAT, routing, VPN or load
// balancing has to keep this test green.
const (
	clientV4, serverV4 = "10.77.1.2", "10.77.2.2"
	clientV6, serverV6 = "fd77:1::2", "fd77:2::2"

	ethHdr, ipv4Hdr, ipv6Hdr, udpHdr = 14, 20, 40, 8

	probePort = 5999 // warm-up traffic, excluded from the assertions
)

type udpCase struct {
	name               string
	client, server     string
	cport, sport       uint16
	nReq, reqSize      int // client -> server datagrams
	nResp, respSize    int // server -> client datagrams
	ipHdr              int
	wantPkts, wantAtoB uint64
	wantBtoA           uint64
}

func (c udpCase) key(iface string) flows.FlowKey {
	// The client address sorts below the server address in both families, so
	// the client is always endpoint A and A->B is the request direction.
	return flows.FlowKey{
		Iface: iface, Proto: "udp",
		A: flows.Endpoint{IP: c.client, Port: c.cport},
		B: flows.Endpoint{IP: c.server, Port: c.sport},
	}
}

func newUDPCase(name, client, server string, cport, sport uint16, nReq, reqSize, nResp, respSize, ipHdr int) udpCase {
	c := udpCase{name: name, client: client, server: server, cport: cport, sport: sport,
		nReq: nReq, reqSize: reqSize, nResp: nResp, respSize: respSize, ipHdr: ipHdr}
	frame := func(payload int) uint64 { return uint64(ethHdr + ipHdr + udpHdr + payload) }
	c.wantPkts = uint64(nReq + nResp)
	c.wantAtoB = uint64(nReq) * frame(reqSize)
	c.wantBtoA = uint64(nResp) * frame(respSize)
	return c
}

func TestFlowBaseline(t *testing.T) {
	if testnet.Isolate(t) {
		return
	}
	client, server := buildTopology(t)

	agg := flows.NewAggregator()
	ring := capture.NewRingBuffer(4096)
	bus := events.NewBus(64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ifaces := []string{"lan0", "wan0"}
	go func() {
		_ = (&capture.Multi{Ifaces: ifaces, Flows: agg, Ring: ring}).Run(ctx, bus)
	}()

	warmUp(t, agg, client, server, ifaces)

	udp := []udpCase{
		newUDPCase("udp4", clientV4, serverV4, 40001, 5301, 7, 100, 3, 300, ipv4Hdr),
		newUDPCase("udp6", clientV6, serverV6, 40006, 5306, 5, 200, 2, 50, ipv6Hdr),
	}
	for _, c := range udp {
		runUDP(t, client, server, c)
	}
	const tcpUp, tcpDown = 64 << 10, 1 << 10
	runTCP(t, client, server, 40002, 8443, tcpUp, tcpDown)
	tcpKey := func(iface string) flows.FlowKey {
		return flows.FlowKey{Iface: iface, Proto: "tcp",
			A: flows.Endpoint{IP: clientV4, Port: 40002},
			B: flows.Endpoint{IP: serverV4, Port: 8443}}
	}

	// Wait until every expected counter has been reached, then let the
	// capture settle so over-counting (duplicates) would show up as well.
	deadline := time.Now().Add(5 * time.Second)
	for {
		snap := index(agg.Snapshot())
		done := true
		for _, ifc := range ifaces {
			for _, c := range udp {
				if snap[c.key(ifc)].Packets < c.wantPkts {
					done = false
				}
			}
			tk := snap[tcpKey(ifc)]
			if tk.BytesAtoB < tcpUp || tk.BytesBtoA < tcpDown {
				done = false
			}
		}
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	snap := index(agg.Snapshot())

	for _, ifc := range ifaces {
		for _, c := range udp {
			got, ok := snap[c.key(ifc)]
			if !ok {
				t.Errorf("%s on %s: flow missing; have %v", c.name, ifc, keys(snap))
				continue
			}
			if got.Packets != c.wantPkts || got.BytesAtoB != c.wantAtoB || got.BytesBtoA != c.wantBtoA ||
				got.Bytes != c.wantAtoB+c.wantBtoA {
				t.Errorf("%s on %s: packets=%d bytes=%d a->b=%d b->a=%d; want packets=%d bytes=%d a->b=%d b->a=%d",
					c.name, ifc, got.Packets, got.Bytes, got.BytesAtoB, got.BytesBtoA,
					c.wantPkts, c.wantAtoB+c.wantBtoA, c.wantAtoB, c.wantBtoA)
			}
			if got.FirstSeen.IsZero() || got.LastSeen.Before(got.FirstSeen) {
				t.Errorf("%s on %s: bad timestamps first=%v last=%v", c.name, ifc, got.FirstSeen, got.LastSeen)
			}
			// The persisted projection keeps the same directions.
			sum := got.Summarize()
			if sum.Interface != ifc || sum.SrcIP != c.client || sum.DstIP != c.server ||
				sum.Protocol != "udp" || sum.BytesOut != c.wantAtoB || sum.BytesIn != c.wantBtoA {
				t.Errorf("%s on %s: summary %+v", c.name, ifc, sum)
			}
		}

		// TCP segment counts depend on offloads and ACK timing, so the stream
		// is checked with bounds: all payload accounted for, header overhead
		// plausible, direction asymmetry preserved.
		got, ok := snap[tcpKey(ifc)]
		if !ok {
			t.Errorf("tcp on %s: flow missing; have %v", ifc, keys(snap))
			continue
		}
		if got.BytesAtoB < tcpUp || got.BytesAtoB > tcpUp+tcpUp/4 {
			t.Errorf("tcp on %s: a->b=%d, want %d..%d", ifc, got.BytesAtoB, tcpUp, tcpUp+tcpUp/4)
		}
		if got.BytesBtoA < tcpDown || got.BytesBtoA > tcpDown+8<<10 {
			t.Errorf("tcp on %s: b->a=%d, want %d..%d", ifc, got.BytesBtoA, tcpDown, tcpDown+8<<10)
		}
		if got.Packets < 6 || got.Bytes != got.BytesAtoB+got.BytesBtoA {
			t.Errorf("tcp on %s: packets=%d bytes=%d a->b=%d b->a=%d", ifc, got.Packets, got.Bytes, got.BytesAtoB, got.BytesBtoA)
		}
	}

	// Nothing but the generated traffic may appear: 3 flows per interface.
	if want := 3 * len(ifaces); len(snap) != want {
		t.Errorf("flow table has %d flows, want %d: %v", len(snap), want, keys(snap))
	}
	if ring.Len() == 0 {
		t.Error("ring buffer received no frames")
	}
}

// buildTopology wires client <-> router <-> server and enables forwarding.
func buildTopology(t *testing.T) (client, server *testnet.NS) {
	t.Helper()
	client = testnet.NewNS(t, "client")
	server = testnet.NewNS(t, "server")
	testnet.Veth(t, "lan0", client, "eth0")
	testnet.Veth(t, "wan0", server, "eth0")

	for _, a := range [][2]string{
		{"lan0", "10.77.1.1/24"}, {"lan0", "fd77:1::1/64"},
		{"wan0", "10.77.2.1/24"}, {"wan0", "fd77:2::1/64"},
	} {
		testnet.Must(t, testnet.Addr(a[0], a[1]))
	}
	testnet.Must(t, testnet.Sysctl("net/ipv4/ip_forward", "1"))
	testnet.Must(t, testnet.Sysctl("net/ipv6/conf/all/forwarding", "1"))

	testnet.Must(t, client.Do(func() error {
		for _, step := range []func() error{
			func() error { return testnet.Addr("eth0", clientV4+"/24") },
			func() error { return testnet.Addr("eth0", clientV6+"/64") },
			func() error { return testnet.DefaultRoute("10.77.1.1") },
			func() error { return testnet.DefaultRoute("fd77:1::1") },
		} {
			if err := step(); err != nil {
				return err
			}
		}
		return nil
	}))
	testnet.Must(t, server.Do(func() error {
		for _, step := range []func() error{
			func() error { return testnet.Addr("eth0", serverV4+"/24") },
			func() error { return testnet.Addr("eth0", serverV6+"/64") },
			func() error { return testnet.DefaultRoute("10.77.2.1") },
			func() error { return testnet.DefaultRoute("fd77:2::1") },
		} {
			if err := step(); err != nil {
				return err
			}
		}
		return nil
	}))
	return client, server
}

func listenUDP(t *testing.T, ns *testnet.NS, ip string, port uint16) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	testnet.Must(t, ns.Do(func() error {
		var err error
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip), Port: int(port)})
		return err
	}))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// warmUp sends probe datagrams in both address families until the capture
// reports them on every interface. This proves the AF_PACKET sockets are
// bound and resolves ARP/NDP before the measured traffic starts.
func warmUp(t *testing.T, agg *flows.Aggregator, client, server *testnet.NS, ifaces []string) {
	t.Helper()
	type pair struct{ c, s string }
	pairs := []pair{{clientV4, serverV4}, {clientV6, serverV6}}
	var senders []*net.UDPConn
	for _, p := range pairs {
		listenUDP(t, server, p.s, probePort) // sink: avoids ICMP port-unreachable noise
		senders = append(senders, listenUDP(t, client, p.c, 40999))
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for i, p := range pairs {
			_, _ = senders[i].WriteToUDP([]byte("probe"), &net.UDPAddr{IP: net.ParseIP(p.s), Port: probePort})
		}
		time.Sleep(50 * time.Millisecond)
		seen := map[string]bool{}
		for _, f := range agg.Snapshot() {
			if f.Key.B.Port == probePort || f.Key.A.Port == probePort {
				fam := "4"
				if net.ParseIP(f.Key.A.IP).To4() == nil {
					fam = "6"
				}
				seen[f.Key.Iface+"/"+fam] = true
			}
		}
		if len(seen) == 2*len(ifaces) {
			// Let in-flight probes drain, then start from a clean table.
			time.Sleep(200 * time.Millisecond)
			agg.Reset()
			return
		}
	}
	t.Fatalf("capture never saw warm-up traffic on all of %v (v4+v6); saw %d flows", ifaces, len(agg.Snapshot()))
}

func runUDP(t *testing.T, client, server *testnet.NS, c udpCase) {
	t.Helper()
	srv := listenUDP(t, server, c.server, c.sport)
	cli := listenUDP(t, client, c.client, c.cport)
	_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
	_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
	dst := &net.UDPAddr{IP: net.ParseIP(c.server), Port: int(c.sport)}

	buf := make([]byte, 2048)
	var from *net.UDPAddr
	for i := 0; i < c.nReq; i++ {
		if _, err := cli.WriteToUDP(make([]byte, c.reqSize), dst); err != nil {
			t.Fatalf("%s: send request %d: %v", c.name, i, err)
		}
		n, addr, err := srv.ReadFromUDP(buf)
		if err != nil || n != c.reqSize {
			t.Fatalf("%s: server read %d: n=%d err=%v", c.name, i, n, err)
		}
		from = addr
	}
	for i := 0; i < c.nResp; i++ {
		if _, err := srv.WriteToUDP(make([]byte, c.respSize), from); err != nil {
			t.Fatalf("%s: send response %d: %v", c.name, i, err)
		}
		if n, _, err := cli.ReadFromUDP(buf); err != nil || n != c.respSize {
			t.Fatalf("%s: client read %d: n=%d err=%v", c.name, i, n, err)
		}
	}
}

// runTCP uploads up bytes client -> server, downloads down bytes back and
// closes the connection cleanly.
func runTCP(t *testing.T, client, server *testnet.NS, cport, sport uint16, up, down int) {
	t.Helper()
	var ln net.Listener
	testnet.Must(t, server.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", net.JoinHostPort(serverV4, fmt.Sprint(sport)))
		return err
	}))
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.CopyN(io.Discard, c, int64(up)); err != nil {
			srvErr <- fmt.Errorf("server read: %w", err)
			return
		}
		_, err = c.Write(make([]byte, down))
		srvErr <- err
	}()

	var conn net.Conn
	testnet.Must(t, client.Do(func() error {
		d := net.Dialer{Timeout: 5 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientV4), Port: int(cport)}}
		var err error
		conn, err = d.Dial("tcp", net.JoinHostPort(serverV4, fmt.Sprint(sport)))
		return err
	}))
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(make([]byte, up)); err != nil {
		t.Fatalf("tcp: client write: %v", err)
	}
	if _, err := io.CopyN(io.Discard, conn, int64(down)); err != nil {
		t.Fatalf("tcp: client read: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("tcp: %v", err)
	}
}

func index(snap []flows.FlowStats) map[flows.FlowKey]flows.FlowStats {
	m := make(map[flows.FlowKey]flows.FlowStats, len(snap))
	for _, f := range snap {
		// Warm-up probes can still be in flight after the table reset (the
		// router queues them while neighbour discovery completes), so they
		// are ignored here instead of being required to be absent.
		if f.Key.A.Port == probePort || f.Key.B.Port == probePort {
			continue
		}
		m[f.Key] = f
	}
	return m
}

func keys(m map[flows.FlowKey]flows.FlowStats) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s %s %s<->%s pkts=%d", k.Iface, k.Proto, k.A, k.B, v.Packets))
	}
	return out
}

// TestCaptureFollowsNewInterfaces: an auto-discovered capture starts on a
// interface that appears after the start, and its traffic is
// counted there.
func TestCaptureFollowsNewInterfaces(t *testing.T) {
	if testnet.Isolate(t) {
		return
	}
	old := capture.Rediscover
	capture.Rediscover = 200 * time.Millisecond
	defer func() { capture.Rediscover = old }()
	agg := flows.NewAggregator()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = (&capture.Multi{Flows: agg}).Run(ctx, events.NewBus(16))
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	// An interface that appears later, as a tunnel the appliance creates does.
	peer := testnet.NewNS(t, "peer")
	testnet.Veth(t, "late0", peer, "eth0")
	testnet.Must(t, testnet.Addr("late0", "10.77.9.1/24"))
	testnet.Must(t, peer.Do(func() error { return testnet.Addr("eth0", "10.77.9.2/24") }))
	srv := listenUDP(t, peer, "10.77.9.2", 6000)
	defer srv.Close()
	var seen bool
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && !seen; time.Sleep(100 * time.Millisecond) {
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("10.77.9.2"), Port: 6000})
		if err == nil {
			c.Write([]byte("hello"))
			c.Close()
		}
		for _, f := range agg.Snapshot() {
			if f.Key.Iface == "late0" && (f.Key.A.Port == 6000 || f.Key.B.Port == 6000) {
				seen = true
			}
		}
	}
	if !seen {
		t.Fatal("the capture did not pick up an interface that appeared after it started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the capture did not stop")
	}
}
