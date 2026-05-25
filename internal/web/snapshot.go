package web

import (
	"context"
	"time"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/flows"
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
	Firewall      []firewallTable      `json:"firewall"`
	FilterRules   []filterRuleView     `json:"filter_rules"`
	NAT           []natView            `json:"nat"`
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
}

type gradeView struct {
	Score   int    `json:"score"`
	Letter  string `json:"letter"`
	Verdict string `json:"verdict"`
	Loss    int    `json:"loss_score"`
	RTT     int    `json:"rtt_score"`
	Jitter  int    `json:"jitter_score"`
	DNS     int    `json:"dns_score"`
}

type captureView struct {
	Running bool     `json:"running"`
	Ifaces  []string `json:"ifaces"`
}

type targetView struct {
	Target    string  `json:"target"`
	LastRTTus int64   `json:"last_rtt_us"`
	AvgRTTus  int64   `json:"avg_rtt_us"`
	P95RTTus  int64   `json:"p95_rtt_us"`
	LossPct   float64 `json:"loss_pct"`
	JitterMs  float64 `json:"jitter_ms"`
}

type dnsView struct {
	Name     string `json:"name"`
	LastUs   int64  `json:"last_us"`
	AvgUs    int64  `json:"avg_us"`
	Queries  int    `json:"queries"`
	Failures int    `json:"failures"`
}

type flowView struct {
	Proto   string `json:"proto"`
	Iface   string `json:"iface"`
	Process string `json:"process"`
	A       string `json:"a"`
	B       string `json:"b"`
	Service string `json:"service"`
	DNS     string `json:"dns"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type deviceView struct {
	IP         string   `json:"ip"`
	MAC        string   `json:"mac"`
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
	Name    string   `json:"name"`
	Up      bool     `json:"up"`
	MTU     int      `json:"mtu"`
	HW      string   `json:"hw"`
	Addrs   []string `json:"addrs"`
	RxBytes uint64   `json:"rx_bytes"`
	TxBytes uint64   `json:"tx_bytes"`
}

type routeView struct {
	Family  string `json:"family"`
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Iface   string `json:"iface"`
	Proto   string `json:"proto"`
	Metric  int    `json:"metric"`
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
	Rx        []float64 `json:"rx"` // bytes/sec, oldest → newest
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

	// Targets / DNS from the metrics aggregator.
	targets := eng.Aggregator().SnapshotTargets()
	for _, t := range targets {
		snap.Targets = append(snap.Targets, targetView{
			Target:    t.Target,
			LastRTTus: t.LastRTT.Microseconds(),
			AvgRTTus:  t.AvgRTT.Microseconds(),
			P95RTTus:  t.P95RTT.Microseconds(),
			LossPct:   t.LossPct,
			JitterMs:  t.JitterMs,
		})
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
	snap.Grade = computeGradeView(targets, dnsList, th)

	// Capture status.
	snap.Capture = captureView{
		Running: eng.IsCaptureRunning(),
		Ifaces:  eng.CaptureIfaces(),
	}

	// Flows (top 100 by recency, decorated).
	for _, f := range flows.Decorate(eng.Flows().TopByRecency(100), eng.DNSCache(), eng.ProcMatcher()) {
		snap.Flows = append(snap.Flows, flowView{
			Proto: f.Key.Proto, Iface: f.Key.Iface,
			Process: f.Process, A: f.Key.A.String(), B: f.Key.B.String(),
			Service: f.Service, DNS: f.DNSName,
			Packets: f.Packets, Bytes: f.Bytes,
		})
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
				IP: d.IP, MAC: d.MAC, Hostname: d.Hostname,
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

	// netops snapshots - silently empty when netops unavailable.
	if nw := eng.Netops(); nw != nil {
		if ifs, err := nw.ListIfaces(); err == nil {
			for _, i := range ifs {
				snap.Ifaces = append(snap.Ifaces, ifaceView{
					Name: i.Name, Up: i.Up && i.Running, MTU: i.MTU, HW: i.HWAddr,
					Addrs: i.Addrs, RxBytes: i.RxBytes, TxBytes: i.TxBytes,
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
	}
	return snap
}

func ifEndedAt(j capture.TCPDumpJob) string {
	if j.EndedAt.IsZero() {
		return ""
	}
	return j.EndedAt.Format(time.RFC3339)
}
