package metrics

import (
	"net"
	"strconv"
	"strings"
)

// TargetKind says what an aggregator target name stands for.
//
// The aggregator is shared: besides real probe targets, collectors publish
// encoded series through KindLatency events - traceroute path and hop RTTs
// and bufferbloat idle/loaded medians. Every consumer that treats a target as
// a round-trip time to a host (alerting, baselines, the grade, the dashboards)
// must ask ClassifyTarget instead of guessing from the string.
//
// WiFi link metrics now travel as events.KindWiFiMetric into
// Aggregator.RecordSeries; TargetWiFi remains so a "wifi:" name from an older
// build (or older stored session) is still never mistaken for a host.
type TargetKind uint8

const (
	// TargetICMP is a host name or IP address (v4 or v6) probed with ICMP echo.
	TargetICMP TargetKind = iota
	// TargetTCP is a host:port (or [v6]:port) TCP-connect probe.
	TargetTCP
	// TargetHTTP is an http(s):// endpoint; its value is time to first byte.
	TargetHTTP
	// TargetWiFi is a legacy "wifi:<metric>:<iface>" link metric - not a latency.
	TargetWiFi
	// TargetTrace is a "trace:<dest>" path RTT or "trace:<dest>:hopN" hop.
	TargetTrace
	// TargetBufferbloat is a "bufferbloat:idle|loaded:<target>" median.
	TargetBufferbloat
)

func (k TargetKind) String() string {
	switch k {
	case TargetICMP:
		return "icmp"
	case TargetTCP:
		return "tcp"
	case TargetHTTP:
		return "http"
	case TargetWiFi:
		return "wifi"
	case TargetTrace:
		return "trace"
	case TargetBufferbloat:
		return "bufferbloat"
	}
	return "unknown"
}

// IsHostRTT reports whether values are round-trip times to one host
// (ICMP echo or TCP handshake) - what the RTT threshold and baselines mean.
func (k TargetKind) IsHostRTT() bool { return k == TargetICMP || k == TargetTCP }

// IsProbe reports whether the target is a real probe target an operator
// would recognise (a host or an endpoint), as opposed to an encoded series.
func (k TargetKind) IsProbe() bool { return k.IsHostRTT() || k == TargetHTTP }

// ClassifyTarget maps an aggregator target name to its kind.
func ClassifyTarget(t string) TargetKind {
	switch {
	case strings.HasPrefix(t, "wifi:"):
		return TargetWiFi
	case strings.HasPrefix(t, "trace:"):
		return TargetTrace
	case strings.HasPrefix(t, "bufferbloat:"):
		return TargetBufferbloat
	case strings.HasPrefix(t, "http://"), strings.HasPrefix(t, "https://"):
		return TargetHTTP
	}
	// A bare IPv6 address has colons but no port; SplitHostPort rejects it
	// ("too many colons"), so it stays ICMP. host:port and [v6]:port are TCP.
	if _, port, err := net.SplitHostPort(t); err == nil {
		if _, err := strconv.ParseUint(port, 10, 16); err == nil {
			return TargetTCP
		}
	}
	return TargetICMP
}
