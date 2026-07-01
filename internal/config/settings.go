package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// SettingsStore is a thread-safe, JSON-backed live store for tunable
// thresholds. The Settings TUI mutates it; analyzers read snapshots.
type SettingsStore struct {
	mu   sync.RWMutex
	path string
	cur  Thresholds
}

func NewSettingsStore(path string) *SettingsStore {
	return &SettingsStore{path: path, cur: DefaultThresholds()}
}

// Load reads the JSON file if present. Missing file is not an error - the
// store keeps DefaultThresholds.
func (s *SettingsStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read settings: %w", err)
	}
	var stored persistedThresholds
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse settings: %w", err)
	}
	s.cur = stored.toThresholds()
	return nil
}

// Save writes the current thresholds to disk atomically (write tmp + rename).
func (s *SettingsStore) Save() error {
	s.mu.RLock()
	snap := s.cur
	path := s.path
	s.mu.RUnlock()

	data, err := json.MarshalIndent(persistedFromThresholds(snap), "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Snapshot returns a copy callers can read without holding the lock.
func (s *SettingsStore) Snapshot() Thresholds {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Update applies fn under the write lock and persists the result.
func (s *SettingsStore) Update(fn func(*Thresholds)) error {
	s.mu.Lock()
	fn(&s.cur)
	snap := s.cur
	s.mu.Unlock()
	_ = snap // captured by Save() via RLock
	return s.Save()
}

// persistedThresholds is the on-disk form - durations stored as seconds.
type persistedThresholds struct {
	PacketLossPct       float64 `json:"packet_loss_pct"`
	DNSLatencyMs        float64 `json:"dns_latency_ms"`
	JitterMs            float64 `json:"jitter_ms"`
	RTTMs               float64 `json:"rtt_ms"`
	RetransmissionsPct  float64 `json:"retransmissions_pct"`
	IncidentCooldownSec float64 `json:"incident_cooldown_sec"`
	AllowNetopsWrite    bool    `json:"allow_netops_write"`
	SentryDSN           string  `json:"sentry_dsn"`
	GuacamoleURL        string  `json:"guacamole_url"`
	GuacamoleConnID     string  `json:"guacamole_conn_id"`
	GuacamoleTemplate   string  `json:"guacamole_template"`
	IPFIXEnabled        bool    `json:"ipfix_enabled"`
	IPFIXEndpoint       string  `json:"ipfix_endpoint"`
	IPFIXIntervalSec    int     `json:"ipfix_interval_sec"`
	IPFIXDomainID       uint32  `json:"ipfix_domain_id"`
	EBPFEnabled         bool    `json:"ebpf_enabled"`
	FlowRetransPct      float64 `json:"flow_retrans_pct"`
	ExpectedDownMbps    float64 `json:"expected_down_mbps"`
	ExpectedUpMbps      float64 `json:"expected_up_mbps"`
	MaxMindEnabled      bool    `json:"maxmind_enabled"`
	MaxMindDBDir        string  `json:"maxmind_db_dir"`
	MaxMindAccountID    string  `json:"maxmind_account_id"`
	MaxMindLicenseKey   string  `json:"maxmind_license_key"`
	MaxMindEditions     string  `json:"maxmind_editions"`
	MaxMindAutoUpdate   bool    `json:"maxmind_auto_update"`
	MaxMindRefreshHours int     `json:"maxmind_refresh_hours"`

	WireGuardDevice          string `json:"wireguard_device"`
	WireGuardTunnelSubnet    string `json:"wireguard_tunnel_subnet"`
	WireGuardServerAddr      string `json:"wireguard_server_addr"`
	WireGuardServerPublicKey string `json:"wireguard_server_public_key"`
	WireGuardEndpoint        string `json:"wireguard_endpoint"`
	WireGuardDNS             string `json:"wireguard_dns"`
	WireGuardWANIface        string `json:"wireguard_wan_iface"`
	WireGuardLANSubnets      string `json:"wireguard_lan_subnets"`
	WireGuardListenPort      int    `json:"wireguard_listen_port"`
	WireGuardNetplanPath     string `json:"wireguard_netplan_path"`
}

func (p persistedThresholds) toThresholds() Thresholds {
	return Thresholds{
		PacketLossPct:       p.PacketLossPct,
		DNSLatencyMs:        p.DNSLatencyMs,
		JitterMs:            p.JitterMs,
		RTTMs:               p.RTTMs,
		RetransmissionsPct:  p.RetransmissionsPct,
		IncidentCooldown:    time.Duration(p.IncidentCooldownSec * float64(time.Second)),
		AllowNetopsWrite:    p.AllowNetopsWrite,
		SentryDSN:           p.SentryDSN,
		GuacamoleURL:        p.GuacamoleURL,
		GuacamoleConnID:     p.GuacamoleConnID,
		GuacamoleTemplate:   p.GuacamoleTemplate,
		IPFIXEnabled:        p.IPFIXEnabled,
		IPFIXEndpoint:       p.IPFIXEndpoint,
		IPFIXIntervalSec:    p.IPFIXIntervalSec,
		IPFIXDomainID:       p.IPFIXDomainID,
		EBPFEnabled:         p.EBPFEnabled,
		FlowRetransPct:      p.FlowRetransPct,
		ExpectedDownMbps:    p.ExpectedDownMbps,
		ExpectedUpMbps:      p.ExpectedUpMbps,
		MaxMindEnabled:      p.MaxMindEnabled,
		MaxMindDBDir:        p.MaxMindDBDir,
		MaxMindAccountID:    p.MaxMindAccountID,
		MaxMindLicenseKey:   p.MaxMindLicenseKey,
		MaxMindEditions:     p.MaxMindEditions,
		MaxMindAutoUpdate:   p.MaxMindAutoUpdate,
		MaxMindRefreshHours: p.MaxMindRefreshHours,

		WireGuardDevice:          p.WireGuardDevice,
		WireGuardTunnelSubnet:    p.WireGuardTunnelSubnet,
		WireGuardServerAddr:      p.WireGuardServerAddr,
		WireGuardServerPublicKey: p.WireGuardServerPublicKey,
		WireGuardEndpoint:        p.WireGuardEndpoint,
		WireGuardDNS:             p.WireGuardDNS,
		WireGuardWANIface:        p.WireGuardWANIface,
		WireGuardLANSubnets:      p.WireGuardLANSubnets,
		WireGuardListenPort:      p.WireGuardListenPort,
		WireGuardNetplanPath:     p.WireGuardNetplanPath,
	}
}

func persistedFromThresholds(t Thresholds) persistedThresholds {
	return persistedThresholds{
		PacketLossPct:       t.PacketLossPct,
		DNSLatencyMs:        t.DNSLatencyMs,
		JitterMs:            t.JitterMs,
		RTTMs:               t.RTTMs,
		RetransmissionsPct:  t.RetransmissionsPct,
		IncidentCooldownSec: t.IncidentCooldown.Seconds(),
		AllowNetopsWrite:    t.AllowNetopsWrite,
		SentryDSN:           t.SentryDSN,
		GuacamoleURL:        t.GuacamoleURL,
		GuacamoleConnID:     t.GuacamoleConnID,
		GuacamoleTemplate:   t.GuacamoleTemplate,
		IPFIXEnabled:        t.IPFIXEnabled,
		IPFIXEndpoint:       t.IPFIXEndpoint,
		IPFIXIntervalSec:    t.IPFIXIntervalSec,
		IPFIXDomainID:       t.IPFIXDomainID,
		EBPFEnabled:         t.EBPFEnabled,
		FlowRetransPct:      t.FlowRetransPct,
		ExpectedDownMbps:    t.ExpectedDownMbps,
		ExpectedUpMbps:      t.ExpectedUpMbps,
		MaxMindEnabled:      t.MaxMindEnabled,
		MaxMindDBDir:        t.MaxMindDBDir,
		MaxMindAccountID:    t.MaxMindAccountID,
		MaxMindLicenseKey:   t.MaxMindLicenseKey,
		MaxMindEditions:     t.MaxMindEditions,
		MaxMindAutoUpdate:   t.MaxMindAutoUpdate,
		MaxMindRefreshHours: t.MaxMindRefreshHours,

		WireGuardDevice:          t.WireGuardDevice,
		WireGuardTunnelSubnet:    t.WireGuardTunnelSubnet,
		WireGuardServerAddr:      t.WireGuardServerAddr,
		WireGuardServerPublicKey: t.WireGuardServerPublicKey,
		WireGuardEndpoint:        t.WireGuardEndpoint,
		WireGuardDNS:             t.WireGuardDNS,
		WireGuardWANIface:        t.WireGuardWANIface,
		WireGuardLANSubnets:      t.WireGuardLANSubnets,
		WireGuardListenPort:      t.WireGuardListenPort,
		WireGuardNetplanPath:     t.WireGuardNetplanPath,
	}
}
