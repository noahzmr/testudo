// Package config holds runtime configuration for Testudo. Defaults are
// chosen to be useful out-of-the-box; the cmd layer overrides via flags,
// and the Settings TUI mutates Thresholds at runtime.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Thresholds drives the anomaly detectors and a handful of runtime
// toggles. Defaults from CLAUDE.md § "Configurable Thresholds". All fields
// are user-tunable via the Settings TUI and persisted to settings.json.
//
// AllowNetopsWrite lives here so it gets the same treatment as the numeric
// thresholds - live-mutable via SettingsStore, survives restarts. The CLI
// `--allow-netops-write` flag is a one-shot override at startup.
type Thresholds struct {
	PacketLossPct      float64       // alert when single-window loss exceeds this percentage
	DNSLatencyMs       float64       // alert when a DNS query exceeds this latency
	JitterMs           float64       // alert when rolling jitter exceeds this
	RTTMs              float64       // alert when a single RTT exceeds this
	RetransmissionsPct float64       // (Phase 3 reserved) % retransmitted segments
	IncidentCooldown   time.Duration // minimum gap between incident snapshots
	AllowNetopsWrite   bool          // permit destructive netlink/nftables operations

	// Integration endpoints. CLAUDE.md states these are configurable from the
	// Settings tab; they're persisted to settings.json alongside the numeric
	// thresholds so the same edit-and-save path works for both.
	SentryDSN       string // empty disables Sentry; non-empty re-inits on save
	GuacamoleURL    string // base URL of an Apache Guacamole instance
	GuacamoleConnID string // connection identifier inside Guacamole

	// GuacamoleTemplate is the URL pattern used to build a per-device
	// quick-connect link. Supports {host}, {port}, {proto} placeholders.
	// When blank, Testudo falls back to native browser URI handlers
	// (ssh://, rdp://, vnc://) so the "Connect" button still works without
	// a Guacamole instance.
	GuacamoleTemplate string

	// IPFIX flow export. The exporter (internal/ipfix) reconciles its
	// live state against these on a 5-second cadence - toggling Enabled
	// or rewriting Endpoint mid-session re-dials transparently.
	IPFIXEnabled     bool   // master switch
	IPFIXEndpoint    string // "host:port" of the collector (UDP)
	IPFIXIntervalSec int    // export cadence in seconds; default 30
	IPFIXDomainID    uint32 // observation domain id; 0 = derive from hostname

	// Per-flow TCP telemetry (internal/telemetry, internal/collectors/tcpinfo.go).
	// EBPFEnabled opts into the eBPF backend when the binary is built with
	// -tags ebpf and the kernel supports it; it's a no-op (INET_DIAG fallback)
	// otherwise. FlowRetransPct is the per-flow retransmission-rate alert
	// threshold - a single suffering connection raises a WARN at this rate even
	// when the host-wide rate is fine.
	EBPFEnabled    bool    // enable eBPF backend (requires -tags ebpf + caps)
	FlowRetransPct float64 // per-flow RTX-rate alert threshold, percent

	// MaxMind GeoIP enrichment (internal/integrations/maxmind). When enabled,
	// observed public IPs are annotated with country / ASN / anonymity signals
	// from local .mmdb files (or a sidecar mmdb-server). The engine reconciles
	// these against the live enricher on a 2-second cadence, so editing them in
	// the Settings tab takes effect without a restart.
	MaxMindEnabled      bool   // master switch
	MaxMindDBDir        string // directory holding the .mmdb files
	MaxMindAccountID    string // optional; required for some commercial editions
	MaxMindLicenseKey   string // license key for auto-update; empty disables it
	MaxMindEditions     string // comma-separated edition IDs to auto-download
	MaxMindAutoUpdate   bool   // periodically re-download the configured editions
	MaxMindRefreshHours int    // refresh cadence in hours; 0 => 7-day default
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		PacketLossPct:      2.0,
		DNSLatencyMs:       120,
		JitterMs:           20,
		RTTMs:              150,
		RetransmissionsPct: 5,
		IncidentCooldown:   60 * time.Second,
		AllowNetopsWrite:   false,
		IPFIXEnabled:       false,
		IPFIXEndpoint:      "",
		IPFIXIntervalSec:   30,
		IPFIXDomainID:      0,
		EBPFEnabled:        false,
		FlowRetransPct:     5,
	}
}

type Config struct {
	// ICMP probe targets - addresses pinged on each tick.
	ICMPTargets []string
	// ICMPInterval is the delay between probe rounds.
	ICMPInterval time.Duration
	// ICMPTimeout is the per-probe deadline.
	ICMPTimeout time.Duration

	// DNSNames are resolved on each tick to monitor resolver health.
	DNSNames []string
	// DNSInterval is the delay between DNS probe rounds.
	DNSInterval time.Duration
	// DNSTimeout is the per-query deadline.
	DNSTimeout time.Duration

	// ReverseDNSEnabled turns on asynchronous reverse (PTR) resolution of
	// flow endpoints. When on, any IP seen in a flow - public or private -
	// that wasn't actively probed forward is resolved to a hostname in the
	// background and surfaces on a later render tick.
	ReverseDNSEnabled bool

	// DNSInternalEnabled turns on the internal-resolver probe. It sends
	// DNSNames directly to LAN DNS servers (not via the stub) so the
	// operator can tell whether the internal resolver is healthy
	// independently of any local caching layer.
	DNSInternalEnabled bool
	// DNSInternalServers is the explicit list of LAN resolvers to probe.
	// When empty, /etc/resolv.conf is parsed each tick and any non-loopback
	// RFC1918 / link-local nameserver is picked up automatically.
	DNSInternalServers []string

	// StorageDir holds the SQLite file and per-session artifacts.
	StorageDir string
	// SQLitePath is the absolute path to the metrics database.
	SQLitePath string
	// SettingsPath is the JSON file storing runtime-mutable thresholds.
	SettingsPath string

	// Mode is "live" (capture + render) or "replay" (read past session).
	Mode string
	// ReplaySessionID selects the session to replay when Mode == "replay".
	ReplaySessionID string

	// CaptureEnabled toggles AF_PACKET flow capture.
	CaptureEnabled bool
	// CaptureIfaces is the explicit set of interfaces to capture on. Empty
	// means "auto-discover all eligible interfaces" - see capture package.
	CaptureIfaces []string
	// FlowFlushInterval is how often the in-memory flow aggregator is
	// upserted into SQLite. Lower = more accurate replay, higher = less I/O.
	FlowFlushInterval time.Duration

	// Thresholds is the live snapshot used by analyzers. The Settings TUI
	// mutates this via a controller, not directly.
	Thresholds Thresholds

	// DiscoveryEnabled toggles the network discovery scanner. Passive
	// collectors (ARP cache read, LLDP listener) are always on when this
	// is true; active probes are gated by DiscoveryActive.
	DiscoveryEnabled bool
	// DiscoveryActive enables active probing (ARP broadcast sweep, ICMP
	// sweep, TCP/UDP port probe, SNMPv2c GET).
	DiscoveryActive bool
	// DiscoveryInterval is the sweep cadence.
	DiscoveryInterval time.Duration
	// DiscoveryMaxSubnetBits caps prefix expansion for the ARP and ICMP
	// sweeps. 10 = /22 (1024 hosts) by default; 8 keeps it at /24.
	DiscoveryMaxSubnetBits int
	// DiscoveryIntensity tunes scan breadth: "fast", "balanced" (default), or
	// "aggressive". It controls probe port lists, timeouts, the effective
	// subnet cap, and which hostname-resolution fallbacks (DHCP/rDNS/NetBIOS)
	// run each pass.
	DiscoveryIntensity string
	// LLDPEnabled toggles the passive LLDP listener. Requires CAP_NET_RAW;
	// soft-fails per interface when the cap is missing.
	LLDPEnabled bool
	// SNMPCommunity is the read community used by the SNMPv2c probe.
	// Empty string disables SNMP probing.
	SNMPCommunity string
	// SNMPTimeout is the per-host UDP/161 deadline.
	SNMPTimeout time.Duration

	// TopTalkersEnabled turns on the internal top-talkers prober. It ranks
	// the live flow table by bytes, filters to RFC1918 / link-local hosts,
	// and pings the top MaxHosts at TopTalkersInterval so the operator
	// gets latency/loss numbers for the busiest internal hosts without
	// having to list them in ICMPTargets manually.
	TopTalkersEnabled  bool
	TopTalkersInterval time.Duration
	TopTalkersTimeout  time.Duration
	TopTalkersMaxHosts int

	// IfaceHealthEnabled turns on the per-interface health monitor. It
	// polls every interface on IfaceHealthInterval and emits an anomaly
	// on link-state transitions or growing error / drop counters.
	IfaceHealthEnabled  bool
	IfaceHealthInterval time.Duration

	// HTTPEndpoints is a list of URLs to GET on each tick. The collector
	// reports TTFB, TLS handshake time, and status-code class. Empty
	// disables the collector entirely.
	HTTPEndpoints []string
	HTTPInterval  time.Duration
	HTTPTimeout   time.Duration

	// TLSCertTargets is a list of "host:port" pairs whose certificate
	// expiry is checked on TLSCertInterval. WARN fires inside
	// TLSCertWarnDays, CRITICAL inside TLSCertCritDays.
	TLSCertTargets  []string
	TLSCertInterval time.Duration
	TLSCertWarnDays int
	TLSCertCritDays int

	// TracerouteEnabled turns on the continuous traceroute collector.
	// Each target is traced every TracerouteInterval; hop set changes
	// and per-hop RTT spikes raise anomalies.
	TracerouteEnabled  bool
	TracerouteTargets  []string
	TracerouteInterval time.Duration
	TracerouteHops     int

	// Bufferbloat probing saturates the link with HTTP downloads while
	// measuring RTT to BufferbloatTarget, and reports the loaded-vs-idle
	// RTT delta. Heavy and invasive - default disabled.
	BufferbloatEnabled  bool
	BufferbloatInterval time.Duration
	BufferbloatTarget   string
	BufferbloatLoadURL  string // empty = cloudflare default
	BufferbloatDuration time.Duration

	// WiFi monitoring publishes a rich per-radio snapshot (SSID,
	// BSSID, channel, frequency, bitrate, TX power, noise, station
	// counters) on WiFiInterval. The collector enumerates wireless
	// NICs via /sys/class/net/<iface>/wireless and prefers the `iw`
	// userspace tool for nl80211 data, falling back to
	// /proc/net/wireless when iw is not installed. Anomalies fire on
	// low signal, lost association, growing retries / TX failures /
	// beacon loss.
	WiFiEnabled   bool
	WiFiInterval  time.Duration
	WiFiMinSignal float64

	// LANReachEnabled turns on continuous ICMP probing of every device
	// in the discovery inventory. Slow cadence by default (1×/min) so
	// total LAN ping load stays under 1 pps on a typical home network.
	LANReachEnabled  bool
	LANReachInterval time.Duration

	// L2Enabled turns on L2 monitoring: per-iface multicast/broadcast
	// burst detection and ARP-table churn (IP-conflict / rogue device
	// signal).
	L2Enabled            bool
	L2Interval           time.Duration
	L2MulticastThreshold uint64

	// NeighbourEnabled turns on the netlink neighbour (ARP/NDP) collector:
	// it dumps RTM_GETNEIGH for both families on NeighbourInterval, persists
	// a snapshot, and fires KindNeighChange / KindDuplicateIP on state
	// transitions and IP conflicts.
	NeighbourEnabled  bool
	NeighbourInterval time.Duration

	// ConntrackEnabled turns on the nf_conntrack table collector. It dumps
	// the live table on ConntrackInterval (capped at ConntrackMaxRows for
	// render/storage so a busy router doesn't blow up memory) and feeds
	// conntrack utilisation into the NAT-exhaustion signal.
	ConntrackEnabled  bool
	ConntrackInterval time.Duration
	ConntrackMaxRows  int

	// NetlinkWatchEnabled turns on the RTNETLINK push watcher: it subscribes
	// to the link / addr / route multicast groups and emits state-change
	// events the instant the kernel does, instead of waiting for a poll tick.
	// NetlinkWatchCoalesceWindow groups rapid link flaps into one anomaly;
	// NetlinkWatchReconcileInterval is the slow full-state diff that catches
	// any dropped multicast message. Soft-fails to reconcile-only if the
	// kernel refuses the subscription.
	NetlinkWatchEnabled           bool
	NetlinkWatchCoalesceWindow    time.Duration
	NetlinkWatchReconcileInterval time.Duration

	// TCPTelemetryEnabled turns on the per-flow TCP telemetry collector
	// (internal/collectors/tcpinfo.go). It samples tcp_info via INET_DIAG on
	// TCPTelemetryInterval, joins per-flow RTT/RTX/cwnd onto the flow table,
	// and raises per-flow RTX and PMTU-black-hole anomalies. Pure-Go by
	// default; the eBPF backend is opted into via the EBPFEnabled threshold.
	TCPTelemetryEnabled  bool
	TCPTelemetryInterval time.Duration

	// DeviceChatterEnabled turns on the per-device baseline anomaly.
	// Reads from the in-memory DeviceBandwidth aggregator, so it
	// requires capture to be running to be useful.
	DeviceChatterEnabled bool
	DeviceChatterFactor  float64

	// WebEnabled toggles the embedded HTTP UI.
	WebEnabled bool
	// WebListen is the bind address for the HTTP UI (host:port).
	WebListen string

	// SnapshotInterval is the cadence for per-session firewall/route/NAT/topology
	// snapshots. Lower = finer replay resolution, higher = less storage churn.
	SnapshotInterval time.Duration

	// PCAPMaxSize is the size in bytes a single PCAP file may reach before
	// it's rotated. 0 disables PCAP capture.
	PCAPMaxSize int64

	// SentryDSN, when set, sends panics + errors to Sentry.
	SentryDSN string

	// GuacamoleURL, when set, is appended with target hints in the TUI to
	// produce a clickable Guacamole launch URL.
	GuacamoleURL string
}

func Default() Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	storage := filepath.Join(home, ".testudo")
	return Config{
		ICMPTargets:                   []string{"1.1.1.1", "8.8.8.8"},
		ICMPInterval:                  time.Second,
		ICMPTimeout:                   2 * time.Second,
		DNSNames:                      []string{"spiegel.de", "autonubil.de"},
		DNSInterval:                   5 * time.Second,
		DNSTimeout:                    3 * time.Second,
		ReverseDNSEnabled:             true,
		DNSInternalEnabled:            true,
		StorageDir:                    storage,
		SQLitePath:                    filepath.Join(storage, "testudo.db"),
		SettingsPath:                  filepath.Join(storage, "settings.json"),
		Mode:                          "live",
		CaptureEnabled:                false,
		FlowFlushInterval:             5 * time.Second,
		Thresholds:                    DefaultThresholds(),
		DiscoveryEnabled:              true,
		DiscoveryActive:               false,
		DiscoveryInterval:             60 * time.Second,
		DiscoveryMaxSubnetBits:        10,
		DiscoveryIntensity:            "balanced",
		LLDPEnabled:                   true,
		SNMPCommunity:                 "public",
		SNMPTimeout:                   time.Second,
		TopTalkersEnabled:             true,
		TopTalkersInterval:            30 * time.Second,
		TopTalkersTimeout:             2 * time.Second,
		TopTalkersMaxHosts:            5,
		IfaceHealthEnabled:            true,
		IfaceHealthInterval:           5 * time.Second,
		HTTPInterval:                  30 * time.Second,
		HTTPTimeout:                   5 * time.Second,
		TLSCertInterval:               6 * time.Hour,
		TLSCertWarnDays:               14,
		TLSCertCritDays:               3,
		TracerouteEnabled:             true,
		TracerouteInterval:            5 * time.Minute,
		TracerouteHops:                16,
		BufferbloatEnabled:            false,
		BufferbloatInterval:           time.Hour,
		BufferbloatTarget:             "1.1.1.1",
		BufferbloatDuration:           10 * time.Second,
		WiFiEnabled:                   true,
		WiFiInterval:                  10 * time.Second,
		WiFiMinSignal:                 -75.0,
		LANReachEnabled:               true,
		LANReachInterval:              60 * time.Second,
		L2Enabled:                     true,
		L2Interval:                    10 * time.Second,
		L2MulticastThreshold:          1000,
		NeighbourEnabled:              true,
		NeighbourInterval:             15 * time.Second,
		ConntrackEnabled:              true,
		ConntrackInterval:             15 * time.Second,
		ConntrackMaxRows:              2000,
		NetlinkWatchEnabled:           true,
		NetlinkWatchCoalesceWindow:    250 * time.Millisecond,
		NetlinkWatchReconcileInterval: 60 * time.Second,
		TCPTelemetryEnabled:           true,
		TCPTelemetryInterval:          10 * time.Second,
		DeviceChatterEnabled:          true,
		DeviceChatterFactor:           3.0,
		WebEnabled:                    false,
		WebListen:                     "127.0.0.1:8080",
		SnapshotInterval:              30 * time.Second,
		PCAPMaxSize:                   64 * 1024 * 1024, // 64 MiB per rotated file
	}
}

// EnsureDirs creates the on-disk layout used for sessions, metrics, PCAPs.
func (c Config) EnsureDirs() error {
	for _, sub := range []string{"sessions", "metrics", "captures", "incidents"} {
		p := filepath.Join(c.StorageDir, sub)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", p, err)
		}
	}
	return nil
}
