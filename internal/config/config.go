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
// thresholds — live-mutable via SettingsStore, survives restarts. The CLI
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
	// live state against these on a 5-second cadence — toggling Enabled
	// or rewriting Endpoint mid-session re-dials transparently.
	IPFIXEnabled     bool   // master switch
	IPFIXEndpoint    string // "host:port" of the collector (UDP)
	IPFIXIntervalSec int    // export cadence in seconds; default 30
	IPFIXDomainID    uint32 // observation domain id; 0 = derive from hostname
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
	}
}

type Config struct {
	// ICMP probe targets — addresses pinged on each tick.
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
	// means "auto-discover all eligible interfaces" — see capture package.
	CaptureIfaces []string
	// FlowFlushInterval is how often the in-memory flow aggregator is
	// upserted into SQLite. Lower = more accurate replay, higher = less I/O.
	FlowFlushInterval time.Duration

	// Thresholds is the live snapshot used by analyzers. The Settings TUI
	// mutates this via a controller, not directly.
	Thresholds Thresholds

	// DiscoveryEnabled toggles the network discovery scanner (ARP + mDNS,
	// passive only by default).
	DiscoveryEnabled bool
	// DiscoveryActive enables ICMP sweeps on local subnets.
	DiscoveryActive bool
	// DiscoveryInterval is the sweep cadence.
	DiscoveryInterval time.Duration

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
		ICMPTargets:       []string{"1.1.1.1", "8.8.8.8"},
		ICMPInterval:      time.Second,
		ICMPTimeout:       2 * time.Second,
		DNSNames:          []string{"spiegel.de", "autonubil.de"},
		DNSInterval:       5 * time.Second,
		DNSTimeout:        3 * time.Second,
		StorageDir:        storage,
		SQLitePath:        filepath.Join(storage, "testudo.db"),
		SettingsPath:      filepath.Join(storage, "settings.json"),
		Mode:              "live",
		CaptureEnabled:    false,
		FlowFlushInterval: 5 * time.Second,
		Thresholds:        DefaultThresholds(),
		DiscoveryEnabled:  true,
		DiscoveryActive:   false,
		DiscoveryInterval: 60 * time.Second,
		WebEnabled:        false,
		WebListen:         "127.0.0.1:8080",
		SnapshotInterval:  30 * time.Second,
		PCAPMaxSize:       64 * 1024 * 1024, // 64 MiB per rotated file
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
