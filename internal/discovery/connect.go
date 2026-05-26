package discovery

import (
	"context"
	"sort"
	"sync"
	"time"
)

// ConnectionProto is one of the standard remote-management protocols we
// know how to surface on a device row. Test against ServicePortMap to
// classify an open port.
type ConnectionProto string

const (
	ProtoSSH    ConnectionProto = "ssh"
	ProtoTelnet ConnectionProto = "telnet"
	ProtoRDP    ConnectionProto = "rdp"
	ProtoVNC    ConnectionProto = "vnc"
	ProtoHTTP   ConnectionProto = "http"
	ProtoHTTPS  ConnectionProto = "https"
)

// ServicePortMap is the curated map of ports => connection protocols. Used
// by the scan-and-connect feature to suggest "click here to SSH / RDP / …"
// from any device row. Ports outside this map are still tracked as open but
// don't get a one-click action.
var ServicePortMap = map[uint16]ConnectionProto{
	22:   ProtoSSH,
	23:   ProtoTelnet,
	80:   ProtoHTTP,
	443:  ProtoHTTPS,
	3389: ProtoRDP,
	5800: ProtoVNC,
	5900: ProtoVNC,
	5901: ProtoVNC,
	8080: ProtoHTTP,
	8081: ProtoHTTP,
	8443: ProtoHTTPS,
}

// ConnectionPorts is the ordered list of ports we probe when a user asks
// for a "what can I connect to" scan. It's tighter than DefaultProbePorts
// (curated for connection discovery, not generic port enumeration).
var ConnectionPorts = []uint16{
	22, 23, 80, 443, 3389,
	5800, 5900, 5901, 8080, 8081, 8443,
}

// DeviceConnections is the per-device summary of what we found.
type DeviceConnections struct {
	IP        string
	OpenPorts []uint16          // sorted ascending
	Protocols []ConnectionProto // distinct, in canonical order
}

// ProtocolsForPorts is the pure-function variant - given a sorted port
// list, return the distinct protocols that map to them. The TUI uses this
// to render the "ssh · rdp · vnc" badge on device rows without having to
// re-scan.
func ProtocolsForPorts(ports []uint16) []ConnectionProto {
	seen := map[ConnectionProto]struct{}{}
	out := make([]ConnectionProto, 0, 4)
	for _, p := range ports {
		if proto, ok := ServicePortMap[p]; ok {
			if _, already := seen[proto]; already {
				continue
			}
			seen[proto] = struct{}{}
			out = append(out, proto)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return protoOrder(out[i]) < protoOrder(out[j])
	})
	return out
}

// protoOrder gives a stable ranking for UI display (most common
// management protocols first, web last).
func protoOrder(p ConnectionProto) int {
	switch p {
	case ProtoSSH:
		return 0
	case ProtoRDP:
		return 1
	case ProtoVNC:
		return 2
	case ProtoTelnet:
		return 3
	case ProtoHTTPS:
		return 4
	case ProtoHTTP:
		return 5
	}
	return 99
}

// ScanHost runs a synchronous on-demand scan against the connection-ports
// list for one host. Updates the inventory with whatever it finds. Returns
// the resulting connection summary. Concurrency is bounded so calling this
// while a sweep is running doesn't fan out 100 sockets.
//
// Per-port timeout is short (300ms) so a typical scan finishes in under
// 4s even when most ports are silent.
func (s *Scanner) ScanHost(ctx context.Context, ip string) DeviceConnections {
	if s == nil || ip == "" {
		return DeviceConnections{}
	}
	timeout := 300 * time.Millisecond
	open := make([]uint16, 0, 4)
	mu := sync.Mutex{}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, port := range ConnectionPorts {
		port := port
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if probeTCPOnce(ctx, ip, port, timeout) {
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i] < open[j] })

	if s.Inventory != nil && len(open) > 0 {
		s.Inventory.Observe(Device{
			IP:        ip,
			OpenPorts: open,
			Source:    "scan",
			LastSeen:  time.Now(),
		})
	}
	return DeviceConnections{
		IP:        ip,
		OpenPorts: open,
		Protocols: ProtocolsForPorts(open),
	}
}
