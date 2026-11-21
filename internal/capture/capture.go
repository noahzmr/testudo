// Package capture provides pure-Go packet capture via AF_PACKET (Linux).
// A single Multi instance spawns one capture goroutine per interface and
// tags each flow update with the originating iface name. No libpcap.
//
// Requires CAP_NET_RAW on the binary.
package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
)

// rawIPDecoder dispatches a frame that starts at the IP header (no link
// layer) to LayerTypeIPv4 or LayerTypeIPv6 based on the version nibble.
// This is the entry decoder for L3-only interfaces - wg*, tun*, ppp*,
// ipip*, sit*, etc. - whose AF_PACKET frames have no Ethernet header.
// Decoding such frames as Ethernet silently drops every packet because
// the first 14 bytes don't form a valid Ethernet header.
type rawIPDecoder struct{}

func (rawIPDecoder) Decode(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 1 {
		return errors.New("capture: empty L3 frame")
	}
	switch data[0] >> 4 {
	case 4:
		return layers.LayerTypeIPv4.Decode(data, p)
	case 6:
		return layers.LayerTypeIPv6.Decode(data, p)
	}
	return errors.New("capture: non-IP frame on L3 interface")
}

// isL3Interface reports whether iface delivers frames that start at the
// IP header (no link layer). Detected by the absence of a hardware
// address - tunnel interfaces (wg, tun, ppp, ipip, sit, gre) have none,
// while Ethernet, bridges, vlans, and wifi do.
func isL3Interface(iface string) bool {
	ifi, err := net.InterfaceByName(iface)
	if err != nil || ifi == nil {
		return false
	}
	return len(ifi.HardwareAddr) == 0
}

// Multi captures packets from many interfaces concurrently. With an
// explicit list the set is fixed; auto-discovery follows interfaces that
// come and go.
//
// Capture writes directly into the supplied FlowAggregator rather than
// publishing per-packet events on the bus - on a busy link the bus fanout
// would multiply each packet by the number of subscribers and saturate a
// CPU with channel ops. The bus is reserved for low-frequency operational
// signals (anomalies, lifecycle, status).
type Multi struct {
	// Ifaces is the explicit interface list. If empty, AutoDiscover is used.
	Ifaces []string
	// ExcludePatterns are name prefixes to skip during auto-discovery -
	// loopback, veth, etc. Augments the built-in deny-list.
	ExcludePatterns []string
	// Flows is the aggregator that receives every parsed packet. Required.
	Flows *flows.Aggregator
	// Ring is the Layer-1 live-storage buffer that receives a copy of every
	// raw frame seen. Optional - if nil, frames are not retained.
	Ring *RingBuffer
}

func (m *Multi) Name() string { return "capture" }

// Rediscover is how often an auto-discovered capture looks for interfaces
// that came or went: tunnels the appliance creates after the start (a
// WireGuard device, a fabric tunnel) are captured too.
var Rediscover = 5 * time.Second

// Run spawns one capture goroutine per interface. Each goroutine respects
// ctx cancellation. With an explicit interface list the set is fixed; with
// auto-discovery it follows the interfaces that come and go. Returns nil
// once all per-iface workers exit.
func (m *Multi) Run(ctx context.Context, bus *events.Bus) error {
	if m.Flows == nil {
		return fmt.Errorf("capture: Flows aggregator required")
	}
	fixed := len(m.Ifaces) > 0
	discover := func() ([]string, error) {
		if fixed {
			return m.Ifaces, nil
		}
		return AutoDiscover(m.ExcludePatterns)
	}
	ifaces, err := discover()
	if err != nil {
		return fmt.Errorf("auto-discover interfaces: %w", err)
	}
	if len(ifaces) == 0 && fixed {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: m.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message:  "capture: no eligible interfaces found",
			},
		})
		return nil
	}

	var wg sync.WaitGroup
	running := map[string]context.CancelFunc{}
	start := func(iface string) {
		ictx, cancel := context.WithCancel(ctx)
		running[iface] = cancel
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := captureOne(ictx, iface, m.Flows, m.Ring, bus); err != nil && ictx.Err() == nil {
				bus.Publish(events.Event{
					Kind: events.KindAnomaly, Source: m.Name(),
					Payload: events.AnomalyPayload{
						Severity: string(events.SevError),
						Message:  fmt.Sprintf("capture on %s failed: %v", iface, err),
					},
				})
			}
		}()
	}
	for _, iface := range ifaces {
		start(iface)
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: m.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(events.SevInfo),
			Message:  fmt.Sprintf("capture started on %d interface(s): %s", len(ifaces), strings.Join(ifaces, ", ")),
		},
	})
	if !fixed {
		tick := time.NewTicker(Rediscover)
		defer tick.Stop()
	follow:
		for {
			select {
			case <-ctx.Done():
				break follow
			case <-tick.C:
			}
			now, err := AutoDiscover(m.ExcludePatterns)
			if err != nil {
				continue
			}
			seen := map[string]bool{}
			var added []string
			for _, iface := range now {
				seen[iface] = true
				if _, ok := running[iface]; !ok {
					start(iface)
					added = append(added, iface)
				}
			}
			for iface, cancel := range running {
				if !seen[iface] {
					cancel()
					delete(running, iface)
				}
			}
			if len(added) > 0 {
				bus.Publish(events.Event{
					Kind: events.KindAnomaly, Source: m.Name(),
					Payload: events.AnomalyPayload{
						Severity: string(events.SevInfo),
						Message:  "capture follows new interface(s): " + strings.Join(added, ", "),
					},
				})
			}
		}
	}
	wg.Wait()
	return nil
}

func captureOne(ctx context.Context, iface string, agg *flows.Aggregator, ring *RingBuffer, bus *events.Bus) error {
	handle, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return err
	}
	defer handle.Close()

	var firstLayer gopacket.Decoder = layers.LayerTypeEthernet
	if isL3Interface(iface) {
		firstLayer = rawIPDecoder{}
	}
	source := gopacket.NewPacketSource(handle, firstLayer)
	source.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	pkts := source.Packets()
	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-pkts:
			if !ok {
				return nil
			}
			if ring != nil {
				ring.Push(iface, pkt.Data())
			}
			if payload := decode(pkt, iface); payload != nil {
				agg.Update(payload.Iface, payload.SrcIP, payload.SrcPort,
					payload.DstIP, payload.DstPort, payload.Proto, payload.Bytes)
			}
		}
	}
}

func decode(pkt gopacket.Packet, iface string) *events.FlowUpdatePayload {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return nil
	}
	src, dst := netLayer.NetworkFlow().Endpoints()

	var srcPort, dstPort uint16
	var proto string
	switch tl := pkt.TransportLayer().(type) {
	case *layers.TCP:
		srcPort, dstPort, proto = uint16(tl.SrcPort), uint16(tl.DstPort), "tcp"
	case *layers.UDP:
		srcPort, dstPort, proto = uint16(tl.SrcPort), uint16(tl.DstPort), "udp"
	default:
		return nil
	}
	bytes := uint64(0)
	if md := pkt.Metadata(); md != nil {
		bytes = uint64(md.Length)
	}
	return &events.FlowUpdatePayload{
		Iface: iface,
		SrcIP: src.String(), DstIP: dst.String(),
		SrcPort: srcPort, DstPort: dstPort,
		Proto: proto, Bytes: bytes,
	}
}

// AutoDiscover returns all up, non-loopback interfaces with an address.
// Container veth pairs and the loopback are excluded by default; tunnel
// interfaces (wg*, tun*, ppp*) are intentionally included so the inner
// decrypted flows on a VPN tunnel are captured alongside the encrypted
// outer flow on the underlay. Pass extra prefixes via excludeExtra to
// skip more.
func AutoDiscover(excludeExtra []string) ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	denylist := append([]string{"veth", "lo"}, excludeExtra...)
	out := make([]string, 0, len(ifs))
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if hasPrefixAny(ifi.Name, denylist) {
			continue
		}
		addrs, _ := ifi.Addrs()
		if len(addrs) == 0 {
			continue
		}
		out = append(out, ifi.Name)
	}
	return out, nil
}

func hasPrefixAny(s string, prefixes []string) bool {
	lower := strings.ToLower(s)
	for _, p := range prefixes {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// ListInterfaces returns a human-readable list (name + addresses) for the
// `testudo ifaces` command.
func ListInterfaces() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ifs))
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s (%s)", ifi.Name, ifaceAddrs(ifi)))
	}
	return out, nil
}

func ifaceAddrs(ifi net.Interface) string {
	addrs, err := ifi.Addrs()
	if err != nil {
		return "?"
	}
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			parts = append(parts, ipn.IP.String())
		}
	}
	if len(parts) == 0 {
		return "no addr"
	}
	const max = 2
	if len(parts) > max {
		parts = append(parts[:max], "…")
	}
	return strings.Join(parts, ", ")
}
