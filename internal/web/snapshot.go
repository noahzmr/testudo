package web

import (
	"context"
	"time"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/netlabel"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/quality"
)

// snapshot is the JSON shape consumed by the SPA. Keep field names stable;
// the JS reads them by name.
type snapshot struct {
	Session       string               `json:"session"`
	Uptime        string               `json:"uptime"`
	Grade         gradeView            `json:"grade"`
	Capture       captureView          `json:"capture"`
	Targets       []targetView         `json:"targets"`
	DNS           []dnsView            `json:"dns"`
	Flows         []flowView           `json:"flows"`
	Devices       []deviceView         `json:"devices"`
	Ifaces        []ifaceView          `json:"ifaces"`
	Routes        []routeView          `json:"routes"`
	Watcher       watcherView          `json:"watcher"`
	Firewall      []firewallTable      `json:"firewall"`
	FirewallRules []firewallRuleView   `json:"firewall_rules"`
	FilterRules   []filterRuleView     `json:"filter_rules"`
	NAT           []natView            `json:"nat"`
	Neighbours    []neighbourView      `json:"neighbours"`
	Conflicts     []ipConflictView     `json:"ip_conflicts"`
	Conntrack     conntrackView        `json:"conntrack"`
	Anomalies     []anomalyView        `json:"anomalies"`
	Thresholds    thresholdsView       `json:"thresholds"`
	TCPDump       []tcpdumpView        `json:"tcpdump"`
	IPFIX         ipfixView            `json:"ipfix"`
	LatencySeries map[string][]float64 `json:"latency_series"`
	DNSSeries     map[string][]float64 `json:"dns_series"`
	Bandwidth     []bandwidthView      `json:"bandwidth"`
	TopHosts      []hostRollupView     `json:"top_hosts"`
	TopProcesses  []procRollupView     `json:"top_processes"`
	TopServices   []serviceRollupView  `json:"top_services"`
	Telemetry     telemetryView        `json:"telemetry"`
	WiFi          []wifiView           `json:"wifi"`
	Subsystems    []subsystemView      `json:"subsystems"`
	Audit         []auditView          `json:"audit"`
	Privsep       string               `json:"privsep"`
}

// wifiView is the per-interface wireless snapshot the dashboard
// renders into a dedicated card. Mirrors collectors.WiFiSnapshot but
// uses JSON-friendly types (timestamps as RFC3339, no time.Time).
type wifiView struct {
	Iface        string  `json:"iface"`
	HWAddr       string  `json:"hw_addr"`
	PhyType      string  `json:"phy_type"`
	SSID         string  `json:"ssid"`
	BSSID        string  `json:"bssid"`
	Frequency    int     `json:"frequency_mhz"`
	Channel      int     `json:"channel"`
	ChannelWMHz  int     `json:"channel_width_mhz"`
	Band         string  `json:"band"`
	Signal       float64 `json:"signal_dbm"`
	SignalAvg    float64 `json:"signal_avg_dbm"`
	Noise        float64 `json:"noise_dbm"`
	TXBitrateM   float64 `json:"tx_bitrate_mbps"`
	RXBitrateM   float64 `json:"rx_bitrate_mbps"`
	TXPower      float64 `json:"tx_power_dbm"`
	LinkQuality  float64 `json:"link_quality"`
	LinkMax      int     `json:"link_quality_max"`
	Retries      uint64  `json:"retries"`
	BeaconLoss   uint64  `json:"beacon_loss"`
	TxFailed     uint64  `json:"tx_failed"`
	RxBytes      uint64  `json:"rx_bytes"`
	TxBytes      uint64  `json:"tx_bytes"`
	RxPackets    uint64  `json:"rx_packets"`
	TxPackets    uint64  `json:"tx_packets"`
	Associated   bool    `json:"associated"`
	ConnectedFor string  `json:"connected_for"`
	Source       string  `json:"source"`
}

// subsystemView mirrors health.Status for the Web self-status table.
type subsystemView struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	LastErr  string `json:"last_err"`
	Hint     string `json:"hint"`
	Restarts int    `json:"restarts"`
	Core     bool   `json:"core"`
}

// auditView mirrors storage.AuditEntry for the Web read-only audit log.
type auditView struct {
	TS      string `json:"ts"`
	Op      string `json:"op"`
	Args    string `json:"args"`
	PeerUID uint32 `json:"peer_uid"`
	Result  string `json:"result"`
}

type gradeView struct {
	Score   int    `json:"score"`
	Letter  string `json:"letter"`
	Verdict string `json:"verdict"`
	// SelfHealth flags the grade as measured with reduced coverage when a core
	// signal collector (ICMP/DNS/capture) is degraded or unprivileged, so the
	// front end can show a "⚠ reduced coverage" badge on the grade card.
	SelfHealthDegraded bool   `json:"self_health_degraded"`
	SelfHealthState    string `json:"self_health_state"`
	// HasData mirrors NetworkGrade.HasData in the TUI: false when every
	// sub-score is still "no data", so the front end can switch the
	// badge into a violet placeholder rather than rendering an
	// inflated "A+" derived from a neutral fallback.
	HasData    bool `json:"has_data"`
	Loss       int  `json:"loss_score"`
	RTT        int  `json:"rtt_score"`
	Jitter     int  `json:"jitter_score"`
	DNS        int  `json:"dns_score"`
	LAN        int  `json:"lan_score"`
	HTTP       int  `json:"http_score"`
	Stab       int  `json:"stab_score"`
	WiFi       int  `json:"wifi_score"`
	Firewall   int  `json:"firewall_score"`
	NAT        int  `json:"nat_score"`
	Congestion int  `json:"congestion_score"`

	// PMTUBlackhole mirrors NetworkGrade: a frag-needed condition is active,
	// and PMTUPenalty is the points it shaved off the score.
	PMTUBlackhole bool `json:"pmtu_blackhole"`
	PMTUPenalty   int  `json:"pmtu_penalty"`
	// NoData lists the sub-score names that have not yet produced a
	// measurement (e.g. ["WiFi", "HTTP"]). The dashboard renders these
	// bars violet and excludes them from the overall grade.
	NoData []string `json:"no_data"`

	// Baseline-relative early warning (mirrors NetworkGrade): worst
	// current÷normal RTT ratio and the points the modifier shaved off.
	BaselineRatio   float64 `json:"baseline_ratio"`
	BaselinePenalty int     `json:"baseline_penalty"`
	HasBaseline     bool    `json:"has_baseline"`

	// Bufferbloat A–F letter from the idle-vs-loaded delta.
	BufferbloatGrade string `json:"bufferbloat_grade"`
	HasBufferbloat   bool   `json:"has_bufferbloat"`

	// ISP-degradation isolation verdict.
	FaultLayer   string `json:"fault_layer"`
	FaultVerdict string `json:"fault_verdict"`
	HasFault     bool   `json:"has_fault"`
}

type captureView struct {
	Running bool     `json:"running"`
	Ifaces  []string `json:"ifaces"`
}

type targetView struct {
	Target    string  `json:"target"`
	LastRTTus int64   `json:"last_rtt_us"`
	AvgRTTus  int64   `json:"avg_rtt_us"`
	P50RTTus  int64   `json:"p50_rtt_us"`
	P95RTTus  int64   `json:"p95_rtt_us"`
	P99RTTus  int64   `json:"p99_rtt_us"`
	LossPct   float64 `json:"loss_pct"`
	JitterMs  float64 `json:"jitter_ms"`

	// Baseline band for this target's current hour bucket (the learned
	// normal envelope). HasBaseline is false until a baseline is learned.
	HasBaseline     bool    `json:"has_baseline"`
	BaselineP50Ms   float64 `json:"baseline_p50_ms"`
	BaselineP95Ms   float64 `json:"baseline_p95_ms"`
	BaselineDescr   string  `json:"baseline_descr"`
	BaselineSamples int64   `json:"baseline_samples"`
}

type dnsView struct {
	Name     string `json:"name"`
	LastUs   int64  `json:"last_us"`
	AvgUs    int64  `json:"avg_us"`
	Queries  int    `json:"queries"`
	Failures int    `json:"failures"`
}

// ipLabel is the routability classification of one address, shared by flow
// endpoints and devices so the SPA renders one badge component everywhere.
type ipLabel struct {
	Scope  string `json:"scope"`            // public | private | internal | multicast | unknown
	Class  string `json:"class,omitempty"`  // IPv4 classful network A-E
	Detail string `json:"detail,omitempty"` // human reason, used as the badge tooltip
}

// labelFor classifies ip via netlabel - the same source the TUI renders from.
func labelFor(ip string) ipLabel {
	l := netlabel.Classify(ip)
	return ipLabel{Scope: string(l.Scope), Class: l.Class, Detail: l.Detail}
}

type flowView struct {
	Proto   string  `json:"proto"`
	Iface   string  `json:"iface"`
	Process string  `json:"process"`
	A       string  `json:"a"`
	ALabel  ipLabel `json:"a_label"`
	B       string  `json:"b"`
	BLabel  ipLabel `json:"b_label"`
	Service string  `json:"service"`
	DNS     string  `json:"dns"`
	Packets uint64  `json:"packets"`
	Bytes   uint64  `json:"bytes"`

	// Per-flow TCP telemetry (INET_DIAG / eBPF). Zero/empty when no telemetry
	// has been observed for this flow. RTTms is the smoothed RTT.
	TCPSource   string  `json:"tcp_source,omitempty"`
	RTTms       float64 `json:"rtt_ms,omitempty"`
	RetransRate float64 `json:"retrans_rate,omitempty"`
	Cwnd        uint32  `json:"cwnd,omitempty"`
}

// telemetryView mirrors the TUI Health card's per-flow TCP telemetry source
// status: the active backend, the eBPF detection detail, and the worst-flow
// figures.
type telemetryView struct {
	Source    string  `json:"source"`
	EBPFOn    bool    `json:"ebpf_available"`
	Detail    string  `json:"detail"`
	Flows     int     `json:"flows"`
	WorstRTX  float64 `json:"worst_rtx"`
	WorstRTT  float64 `json:"worst_rtt_ms"`
	LastError string  `json:"last_error,omitempty"`
}

type deviceView struct {
	IP         string   `json:"ip"`
	IPLabel    ipLabel  `json:"ip_label"`
	MAC        string   `json:"mac"`
	MACType    string   `json:"mac_type,omitempty"`
	Hostname   string   `json:"hostname"`
	Vendor     string   `json:"vendor"`
	Iface      string   `json:"iface"`
	Source     string   `json:"source"`
	DeviceType string   `json:"device_type,omitempty"`
	OpenPorts  []uint16 `json:"open_ports"`
	Protocols  []string `json:"protocols"`

	SysName     string `json:"sys_name,omitempty"`
	SysDescr    string `json:"sys_descr,omitempty"`
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysContact  string `json:"sys_contact,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	SysUptime   string `json:"sys_uptime,omitempty"`
	IfCount     int    `json:"if_count,omitempty"`

	LLDPChassisID    string   `json:"lldp_chassis_id,omitempty"`
	LLDPPortID       string   `json:"lldp_port_id,omitempty"`
	LLDPPortDesc     string   `json:"lldp_port_desc,omitempty"`
	LLDPMgmtAddrs    []string `json:"lldp_mgmt_addrs,omitempty"`
	LLDPCapabilities []string `json:"lldp_capabilities,omitempty"`
	LLDPLocalIface   string   `json:"lldp_local_iface,omitempty"`
}

type ifaceView struct {
	Name       string   `json:"name"`
	Up         bool     `json:"up"`
	Running    bool     `json:"running"`
	MTU        int      `json:"mtu"`
	HW         string   `json:"hw"`
	Addrs      []string `json:"addrs"`
	RxBytes    uint64   `json:"rx_bytes"`
	TxBytes    uint64   `json:"tx_bytes"`
	RxPackets  uint64   `json:"rx_packets"`
	TxPackets  uint64   `json:"tx_packets"`
	RxErrors   uint64   `json:"rx_errors"`
	TxErrors   uint64   `json:"tx_errors"`
	RxDropped  uint64   `json:"rx_dropped"`
	TxDropped  uint64   `json:"tx_dropped"`
	Collisions uint64   `json:"collisions"`
	IsWireless bool     `json:"is_wireless"`
}

type routeView struct {
	Family  string `json:"family"`
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Iface   string `json:"iface"`
	Proto   string `json:"proto"`
	Metric  int    `json:"metric"`
}

// watcherView surfaces the RTNETLINK push watcher's freshness so the web
// header can show the same "live / polled" indicator the TUI does. Mode is
// "live" when the multicast subscriptions are attached, "polled" when the
// watcher soft-failed to reconcile-only, "off" when disabled.
type watcherView struct {
	Mode       string  `json:"mode"`
	Attached   bool    `json:"attached"`
	Degraded   bool    `json:"degraded"`
	Detail     string  `json:"detail"`
	FlapRate   float64 `json:"flap_rate"`
	RouteChurn float64 `json:"route_churn"`
}

type firewallTable struct {
	Family string          `json:"family"`
	Name   string          `json:"name"`
	Chains []firewallChain `json:"chains"`
}

type firewallChain struct {
	Name  string `json:"name"`
	Hook  string `json:"hook"`
	Type  string `json:"type"`
	Rules int    `json:"rules"`
}

// firewallRuleView is one decoded kernel rule with per-rule counters. It
// mirrors the TUI's per-rule view so the web table and any external consumer
// see identical data. Rules arrive top-sorted per chain (highest-hit
// DROP/REJECT first).
type firewallRuleView struct {
	Family     string `json:"family"`
	Table      string `json:"table"`
	Chain      string `json:"chain"`
	Handle     uint64 `json:"handle"`
	Match      string `json:"match"`
	Verdict    string `json:"verdict"`
	Comment    string `json:"comment"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	HasCounter bool   `json:"has_counter"`
	Blocking   bool   `json:"blocking"`
}

type filterRuleView struct {
	Chain    string `json:"chain"`
	Action   string `json:"action"`
	Proto    string `json:"proto"`
	Port     uint16 `json:"port"`
	InIface  string `json:"in_iface"`
	OutIface string `json:"out_iface"`
	SrcCIDR  string `json:"src"`
	DstCIDR  string `json:"dst"`
}

type natView struct {
	Proto   string `json:"proto"`
	WANPort uint16 `json:"wan_port"`
	LANIP   string `json:"lan_ip"`
	LANPort uint16 `json:"lan_port"`
}

// neighbourView mirrors netops.Neighbour for the Devices view. Conflict is
// true when this IP is also answered by another MAC (duplicate-IP badge).
type neighbourView struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Dev      string `json:"dev"`
	Family   string `json:"family"`
	State    string `json:"state"`
	Router   bool   `json:"router"`
	Conflict bool   `json:"conflict"`
}

type ipConflictView struct {
	IP   string   `json:"ip"`
	MACs []string `json:"macs"`
	Devs []string `json:"devs"`
}

// conntrackView carries the live flow table plus the utilisation totals so
// the NAT view can render both the per-row flush and a saturation gauge.
type conntrackView struct {
	Count uint64              `json:"count"` // live entries (nf_conntrack_count)
	Max   uint64              `json:"max"`   // nf_conntrack_max
	Flows []conntrackFlowView `json:"flows"` // capped at ConntrackMaxRows
}

type conntrackFlowView struct {
	Proto      string `json:"proto"`
	OrigSrc    string `json:"orig_src"`
	OrigDst    string `json:"orig_dst"`
	OrigSport  uint16 `json:"orig_sport"`
	OrigDport  uint16 `json:"orig_dport"`
	ReplySrc   string `json:"reply_src"`
	ReplyDst   string `json:"reply_dst"`
	State      string `json:"state"`
	NATed      bool   `json:"natted"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	TimeoutSec int    `json:"timeout_sec"`
}

type anomalyView struct {
	TS       string `json:"ts"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type thresholdsView struct {
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
}

type tcpdumpView struct {
	ID         string `json:"id"`
	Iface      string `json:"iface"`
	Filter     string `json:"filter"`
	OutputPath string `json:"output_path"`
	Name       string `json:"name"`
	State      string `json:"state"`
	StartedAt  string `json:"started_at"`
	EndedAt    string `json:"ended_at"`
	Bytes      int64  `json:"bytes"`
	ExitErr    string `json:"exit_err"`
}

type ipfixView struct {
	Enabled     bool   `json:"enabled"`
	Endpoint    string `json:"endpoint"`
	IntervalSec int    `json:"interval_sec"`
	LastSend    string `json:"last_send"`
	LastErr     string `json:"last_err"`
	Dialed      bool   `json:"dialed"`
}

type bandwidthView struct {
	Iface     string    `json:"iface"`
	Rx        []float64 `json:"rx"` // bytes/sec, oldest => newest
	Tx        []float64 `json:"tx"`
	CurrentRx float64   `json:"current_rx"`
	CurrentTx float64   `json:"current_tx"`
	PeakRx    float64   `json:"peak_rx"`
	PeakTx    float64   `json:"peak_tx"`
	CumRx     uint64    `json:"cum_rx"`
	CumTx     uint64    `json:"cum_tx"`
}

type hostRollupView struct {
	Host    string `json:"host"`
	DNS     string `json:"dns"`
	IsLAN   bool   `json:"is_lan"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   int    `json:"flows"`
}

type procRollupView struct {
	Process string `json:"process"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   int    `json:"flows"`
}

type serviceRollupView struct {
	Service string `json:"service"`
	Proto   string `json:"proto"`
	Port    uint16 `json:"port"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   int    `json:"flows"`
}

// startedAt is set on first snapshot to keep uptime stable across requests.
var startedAt = time.Now()

func (s *Server) buildSnapshot() snapshot {
	eng := s.Engine
	cfg := eng.Config()

	snap := snapshot{
		Session:       eng.SessionID(),
		Uptime:        time.Since(startedAt).Truncate(time.Second).String(),
		LatencySeries: map[string][]float64{},
		DNSSeries:     map[string][]float64{},
	}

	// Baseline-relative context (cached; cheap on the request path).
	qc := eng.QualitySnapshot()
	gctx := qc.GradeContext()

	// Targets / DNS from the metrics aggregator.
	targets := eng.Aggregator().SnapshotTargets()
	for _, t := range targets {
		tv := targetView{
			Target:    t.Target,
			LastRTTus: t.LastRTT.Microseconds(),
			AvgRTTus:  t.AvgRTT.Microseconds(),
			P50RTTus:  t.P50RTT.Microseconds(),
			P95RTTus:  t.P95RTT.Microseconds(),
			P99RTTus:  t.P99RTT.Microseconds(),
			LossPct:   t.LossPct,
			JitterMs:  t.JitterMs,
		}
		if b, ok := qc.Baselines[t.Target]; ok && b.Samples > 0 {
			tv.HasBaseline = true
			tv.BaselineP50Ms = b.P50RTT
			tv.BaselineP95Ms = b.P95RTT
			tv.BaselineSamples = b.Samples
			tv.BaselineDescr = quality.BaselineDescr(b, quality.Sample{RTTms: float64(t.AvgRTT.Microseconds()) / 1000.0})
		}
		snap.Targets = append(snap.Targets, tv)
		// Per-target rolling sample series - front end renders these as
		// sparklines so the dashboard mirrors the TUI.
		samples := eng.Aggregator().LatencySamples(t.Target)
		if len(samples) > 0 {
			series := make([]float64, len(samples))
			for i, d := range samples {
				series[i] = float64(d.Microseconds()) / 1000.0
			}
			snap.LatencySeries[t.Target] = series
		}
	}
	dnsList := eng.Aggregator().SnapshotDNS()
	for _, d := range dnsList {
		snap.DNS = append(snap.DNS, dnsView{
			Name: d.Name, LastUs: d.LastLatency.Microseconds(),
			AvgUs:   d.AvgLatency.Microseconds(),
			Queries: d.Queries, Failures: d.Failures,
		})
		samples := eng.Aggregator().DNSSamples(d.Name)
		if len(samples) > 0 {
			series := make([]float64, len(samples))
			for i, dur := range samples {
				series[i] = float64(dur.Microseconds()) / 1000.0
			}
			snap.DNSSeries[d.Name] = series
		}
	}

	// Network quality grade - same algorithm the TUI uses, exposed as JSON
	// so the front end doesn't need to duplicate the scoring logic.
	th := cfg.Thresholds
	if eng.Settings() != nil {
		th = eng.Settings().Snapshot()
	}
	var ifs []netops.IfaceInfo
	if nw := eng.Netops(); nw != nil {
		ifs, _ = nw.ListIfaces()
	}
	// WiFi snapshot is sampled once and reused for both the grade
	// (signal sub-score) and the dashboard / iface rendering below.
	var wifiSnap []collectors.WiFiSnapshot
	if wc := eng.WiFi(); wc != nil {
		wifiSnap = wc.Snapshot()
	}
	fwRate, fwHas := eng.FirewallSignal()
	var l3 collectors.NeighConntrackSignal
	if nc := eng.Neigh(); nc != nil {
		l3 = nc.Signal()
	}
	var nlw collectors.NetlinkWatchSignal
	if nw := eng.NetlinkWatch(); nw != nil {
		nlw = nw.Signal()
		st := nw.Status()
		snap.Watcher = watcherView{
			Mode: st.Mode, Attached: st.Attached, Degraded: st.Degraded,
			Detail: st.Detail, FlapRate: st.FlapRate, RouteChurn: st.RouteChurn,
		}
	}
	snap.Grade = computeGradeView(targets, dnsList, ifs, wifiSnap, fwRate, fwHas, l3, nlw, tcpGradeFrom(eng), th, gctx)

	// Self-status surface: subsystem health table, privsep posture, and the
	// grade self-health badge. The web server is now unprivileged - the privsep
	// line states it explicitly.
	snap.Privsep = eng.PrivsepInfo()
	worst, coreDegraded := eng.SelfHealth()
	snap.Grade.SelfHealthState = string(worst)
	snap.Grade.SelfHealthDegraded = coreDegraded
	for _, st := range eng.Health() {
		snap.Subsystems = append(snap.Subsystems, subsystemView{
			Name: st.Name, State: string(st.State), LastErr: st.LastErr,
			Hint: st.Hint, Restarts: st.Restarts, Core: st.Core,
		})
	}
	if auditEntries, err := eng.RecentAudit(context.Background(), 100); err == nil {
		for _, e := range auditEntries {
			snap.Audit = append(snap.Audit, auditView{
				TS: e.TS.Format(time.RFC3339), Op: e.Op, Args: e.Args,
				PeerUID: e.PeerUID, Result: e.Result,
			})
		}
	}

	// Neighbour (ARP/NDP) table + IP conflicts, and live conntrack flows.
	if nc := eng.Neigh(); nc != nil {
		conflictSet := map[string]bool{}
		for _, cf := range nc.Conflicts() {
			conflictSet[cf.IP] = true
			snap.Conflicts = append(snap.Conflicts, ipConflictView{IP: cf.IP, MACs: cf.MACs, Devs: cf.Devs})
		}
		for _, n := range nc.Neighbours() {
			snap.Neighbours = append(snap.Neighbours, neighbourView{
				IP: n.IP, MAC: n.MAC, Dev: n.Dev, Family: n.Family,
				State: n.State, Router: n.Router, Conflict: conflictSet[n.IP],
			})
		}
		ctCount, ctMax := nc.ConntrackCounts()
		snap.Conntrack.Count, snap.Conntrack.Max = ctCount, ctMax
		for _, f := range nc.Conntrack() {
			snap.Conntrack.Flows = append(snap.Conntrack.Flows, conntrackFlowView{
				Proto: f.Proto, OrigSrc: f.OrigSrc, OrigDst: f.OrigDst,
				OrigSport: f.OrigSport, OrigDport: f.OrigDport,
				ReplySrc: f.ReplySrc, ReplyDst: f.ReplyDst,
				State: f.State, NATed: f.NATed,
				Packets: f.Packets, Bytes: f.Bytes, TimeoutSec: f.TimeoutSec,
			})
		}
	}

	// Capture status.
	snap.Capture = captureView{
		Running: eng.IsCaptureRunning(),
		Ifaces:  eng.CaptureIfaces(),
	}

	// Flows (top 100 by recency, decorated). Per-flow TCP telemetry rides
	// along on the same row so the dashboard renders identical numbers to the
	// TUI - one flow table, source-tagged.
	for _, f := range flows.Decorate(eng.Flows().TopByRecency(100), eng.DNSCache(), eng.ProcMatcher()) {
		fv := flowView{
			Proto: f.Key.Proto, Iface: f.Key.Iface,
			Process: f.Process, A: f.Key.A.String(), B: f.Key.B.String(),
			ALabel: labelFor(f.Key.A.IP), BLabel: labelFor(f.Key.B.IP),
			Service: f.Service, DNS: f.DNSName,
			Packets: f.Packets, Bytes: f.Bytes,
		}
		if f.HasTCP() {
			fv.TCPSource = f.TCP.Source
			fv.RTTms = f.TCP.RTTms()
			fv.RetransRate = f.TCP.RetransRate
			fv.Cwnd = f.TCP.Cwnd
		}
		snap.Flows = append(snap.Flows, fv)
	}

	// Per-flow TCP telemetry source status (mirrors the TUI Health card).
	if ti := eng.TCPInfo(); ti != nil {
		st := ti.Status()
		snap.Telemetry = telemetryView{
			Source:    st.Source,
			EBPFOn:    st.EBPF.Available,
			Detail:    st.EBPF.Detail,
			Flows:     st.Flows,
			WorstRTX:  st.WorstRTX,
			WorstRTT:  st.WorstRTT,
			LastError: st.LastErr,
		}
	}

	// Devices from inventory - enriched with the connection-protocol
	// classification (SSH / RDP / VNC / HTTP / HTTPS / Telnet) so the web
	// UI can render one-click "Connect via …" buttons per row.
	if inv := eng.Inventory(); inv != nil {
		for _, d := range inv.Snapshot() {
			protos := discovery.ProtocolsForPorts(d.OpenPorts)
			protoStrs := make([]string, 0, len(protos))
			for _, p := range protos {
				protoStrs = append(protoStrs, string(p))
			}
			snap.Devices = append(snap.Devices, deviceView{
				IP: d.IP, IPLabel: labelFor(d.IP), MAC: d.MAC, MACType: d.MACType, Hostname: d.Hostname,
				Vendor: d.Vendor, Iface: d.Iface, Source: d.Source,
				DeviceType: d.DeviceType,
				OpenPorts:  d.OpenPorts,
				Protocols:  protoStrs,

				SysName: d.SysName, SysDescr: d.SysDescr,
				SysObjectID: d.SysObjectID,
				SysContact:  d.SysContact, SysLocation: d.SysLocation,
				SysUptime: d.SysUptime, IfCount: d.IfCount,

				LLDPChassisID:    d.LLDPChassisID,
				LLDPPortID:       d.LLDPPortID,
				LLDPPortDesc:     d.LLDPPortDesc,
				LLDPMgmtAddrs:    d.LLDPMgmtAddrs,
				LLDPCapabilities: d.LLDPCapabilities,
				LLDPLocalIface:   d.LLDPLocalIface,
			})
		}
	}

	// Reuse the wifiSnap captured above for the grade so we don't
	// re-poll /proc + run iw for every snapshot request.
	wifiByIface := map[string]bool{}
	{
		for _, w := range wifiSnap {
			wifiByIface[w.Iface] = true
			view := wifiView{
				Iface: w.Iface, HWAddr: w.HWAddr, PhyType: w.PhyType,
				SSID: w.SSID, BSSID: w.BSSID,
				Frequency: w.Frequency, Channel: w.Channel,
				ChannelWMHz: w.ChannelWMHz, Band: w.Band,
				Signal: w.Signal, SignalAvg: w.SignalAvg, Noise: w.Noise,
				TXBitrateM: w.TXBitrateM, RXBitrateM: w.RXBitrateM,
				TXPower:     w.TXPower,
				LinkQuality: w.LinkQuality, LinkMax: w.LinkMax,
				Retries: w.Retries, BeaconLoss: w.BeaconLoss, TxFailed: w.TxFailed,
				RxBytes: w.RxBytes, TxBytes: w.TxBytes,
				RxPackets: w.RxPackets, TxPackets: w.TxPackets,
				Associated: w.Associated, Source: w.Source,
			}
			if !w.ConnectedAt.IsZero() {
				view.ConnectedFor = time.Since(w.ConnectedAt).Truncate(time.Second).String()
			}
			snap.WiFi = append(snap.WiFi, view)
		}
	}

	// netops snapshots - silently empty when netops unavailable.
	if nw := eng.Netops(); nw != nil {
		if ifs, err := nw.ListIfaces(); err == nil {
			for _, i := range ifs {
				snap.Ifaces = append(snap.Ifaces, ifaceView{
					Name: i.Name, Up: i.Up && i.Running, Running: i.Running,
					MTU: i.MTU, HW: i.HWAddr,
					Addrs:   i.Addrs,
					RxBytes: i.RxBytes, TxBytes: i.TxBytes,
					RxPackets: i.RxPackets, TxPackets: i.TxPackets,
					RxErrors: i.RxErrors, TxErrors: i.TxErrors,
					RxDropped: i.RxDropped, TxDropped: i.TxDropped,
					Collisions: i.Collisions,
					IsWireless: wifiByIface[i.Name],
				})
			}
		}
		if rs, err := nw.ListRoutes(); err == nil {
			for _, r := range rs {
				snap.Routes = append(snap.Routes, routeView{
					Family: r.Family, Dst: r.Dst, Gateway: r.Gateway,
					Iface: r.Iface, Proto: r.Protocol, Metric: r.Metric,
				})
			}
		}
		if fwSum, err := nw.ListFirewall(); err == nil {
			for _, t := range fwSum.Tables {
				ft := firewallTable{Family: t.Family, Name: t.Name}
				for _, c := range t.Chains {
					ft.Chains = append(ft.Chains, firewallChain{
						Name: c.Name, Hook: c.Hook, Type: c.Type, Rules: c.Rules,
					})
				}
				snap.Firewall = append(snap.Firewall, ft)
			}
		}
		if fwRules, err := nw.ListFirewallRules(); err == nil {
			for _, ru := range fwRules {
				snap.FirewallRules = append(snap.FirewallRules, firewallRuleView{
					Family: ru.Family, Table: ru.Table, Chain: ru.Chain,
					Handle: ru.Handle, Match: ru.Match, Verdict: ru.Verdict,
					Comment: ru.Comment, Packets: ru.Packets, Bytes: ru.Bytes,
					HasCounter: ru.HasCounter, Blocking: ru.IsBlocking(),
				})
			}
		}
		if rules, err := nw.ListFilterRules(); err == nil {
			for _, fr := range rules {
				snap.FilterRules = append(snap.FilterRules, filterRuleView{
					Chain: fr.Chain, Action: fr.Action,
					Proto: fr.Proto, Port: fr.Port,
					InIface: fr.InIface, OutIface: fr.OutIface,
					SrcCIDR: fr.SrcCIDR, DstCIDR: fr.DstCIDR,
				})
			}
		}
		if pfs, err := nw.ListPortForwards(); err == nil {
			for _, p := range pfs {
				snap.NAT = append(snap.NAT, natView{
					Proto: p.Proto, WANPort: p.WANPort,
					LANIP: p.LANIP, LANPort: p.LANPort,
				})
			}
		}
	}

	// TCPDump jobs.
	if mgr := eng.TCPDump(); mgr != nil {
		for _, j := range mgr.List() {
			snap.TCPDump = append(snap.TCPDump, tcpdumpView{
				ID: j.ID, Iface: j.Iface, Filter: j.Filter,
				OutputPath: j.OutputPath, Name: j.Name, State: j.State,
				StartedAt: j.StartedAt.Format(time.RFC3339),
				EndedAt:   ifEndedAt(j),
				Bytes:     j.Bytes, ExitErr: j.ExitErr,
			})
		}
	}

	// Per-interface bandwidth time series (sniffnet parity).
	if bw := eng.Bandwidth(); bw != nil {
		for _, s := range bw.Snapshot() {
			snap.Bandwidth = append(snap.Bandwidth, bandwidthView{
				Iface:     s.Iface,
				Rx:        append([]float64(nil), s.RxBytesPerS...),
				Tx:        append([]float64(nil), s.TxBytesPerS...),
				CurrentRx: s.CurrentRx, CurrentTx: s.CurrentTx,
				PeakRx: s.PeakRx, PeakTx: s.PeakTx,
				CumRx: s.CumRx, CumTx: s.CumTx,
			})
		}
	}

	// Top-talkers rollups, built from the decorated flow snapshot.
	decorated := flows.Decorate(eng.Flows().TopByRecency(500), eng.DNSCache(), eng.ProcMatcher())
	for _, h := range flows.TopHosts(decorated, 20) {
		snap.TopHosts = append(snap.TopHosts, hostRollupView{
			Host: h.Host, DNS: h.DNS, IsLAN: h.IsLAN,
			Bytes: h.Bytes, Packets: h.Packets, Flows: h.Flows,
		})
	}
	for _, p := range flows.TopProcesses(decorated, 20) {
		snap.TopProcesses = append(snap.TopProcesses, procRollupView{
			Process: p.Process, Bytes: p.Bytes,
			Packets: p.Packets, Flows: p.Flows,
		})
	}
	for _, s := range flows.TopServices(decorated, 20) {
		snap.TopServices = append(snap.TopServices, serviceRollupView{
			Service: s.Service, Proto: s.Proto, Port: s.Port,
			Bytes: s.Bytes, Packets: s.Packets, Flows: s.Flows,
		})
	}

	// IPFIX live status.
	if im := eng.IPFIX(); im != nil {
		st := im.Status()
		snap.IPFIX = ipfixView{
			Enabled: st.Enabled, Endpoint: st.Endpoint,
			IntervalSec: int(st.Interval / time.Second),
			LastErr:     st.LastErr, Dialed: st.Dialed,
		}
		if !st.LastSend.IsZero() {
			snap.IPFIX.LastSend = st.LastSend.Format(time.RFC3339)
		}
	}

	// Anomalies - recent in-DB tail for this session.
	if rows, err := s.Engine.Store().AnomaliesBySession(context.Background(), eng.SessionID()); err == nil {
		for _, a := range rows {
			snap.Anomalies = append(snap.Anomalies, anomalyView{
				TS: a.TS.Format("15:04:05"), Severity: a.Severity, Message: a.Message,
			})
		}
	}

	snap.Thresholds = thresholdsView{
		PacketLossPct:       th.PacketLossPct,
		DNSLatencyMs:        th.DNSLatencyMs,
		JitterMs:            th.JitterMs,
		RTTMs:               th.RTTMs,
		RetransmissionsPct:  th.RetransmissionsPct,
		IncidentCooldownSec: th.IncidentCooldown.Seconds(),
		AllowNetopsWrite:    th.AllowNetopsWrite,
		SentryDSN:           th.SentryDSN,
		GuacamoleURL:        th.GuacamoleURL,
		GuacamoleConnID:     th.GuacamoleConnID,
		GuacamoleTemplate:   th.GuacamoleTemplate,
		IPFIXEnabled:        th.IPFIXEnabled,
		IPFIXEndpoint:       th.IPFIXEndpoint,
		IPFIXIntervalSec:    th.IPFIXIntervalSec,
		IPFIXDomainID:       th.IPFIXDomainID,
		EBPFEnabled:         th.EBPFEnabled,
		FlowRetransPct:      th.FlowRetransPct,
	}
	return snap
}

func ifEndedAt(j capture.TCPDumpJob) string {
	if j.EndedAt.IsZero() {
		return ""
	}
	return j.EndedAt.Format(time.RFC3339)
}
