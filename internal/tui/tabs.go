package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/integrations/guacamole"
	sentryx "github.com/noahzmr/testudo/internal/integrations/sentry"
	"github.com/noahzmr/testudo/internal/metrics"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/probes"
	"github.com/noahzmr/testudo/internal/quality"
)

// tickMsg + slowTickMsg are owned by the App, not by individual tabs.
//
// History: tabs used to return dashTick() / slowTick() from their Update
// methods after each tick. Combined with the App's untyped-broadcast loop
// that forwarded every message to every tab, each tick fired N new ticks
// (one per responding tab). The number of pending timers grew geometrically
// per tick - within a minute the netlink-querying tabs (Devices, Ifaces,
// Routes, Firewall, NAT) had hundreds of concurrent timers each kicking off
// ListIfaces/ListRoutes/ListFirewall, and the binary was unusable.
//
// Now: the App schedules exactly one dashTick and one slowTick at a time
// and re-issues them after delivery. Tabs never return tick commands.
type tickMsg struct{ at time.Time }
type slowTickMsg struct{ at time.Time }

func dashTick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg{at: t} })
}

func slowTick() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg { return slowTickMsg{at: t} })
}

// ---- Dashboard ----

type dashboardTab struct {
	eng     *engine.Engine
	targets []metrics.TargetStats
	dns     []metrics.DNSStats
	flows   []flows.FlowStats
}

func newDashboardTab(eng *engine.Engine) *dashboardTab { return &dashboardTab{eng: eng} }
func (t *dashboardTab) Title() string                  { return "Dashboard" }
func (t *dashboardTab) HelpHints() []KeyHint           { return nil }
func (t *dashboardTab) ShortKey() string               { return "1" }
func (t *dashboardTab) Init() tea.Cmd                  { return nil }
func (t *dashboardTab) Update(msg tea.Msg) tea.Cmd {
	if _, ok := msg.(tickMsg); ok {
		t.targets = t.eng.Aggregator().SnapshotTargets()
		t.dns = t.eng.Aggregator().SnapshotDNS()
		// Read the pre-decorated cache instead of calling Decorate per tick.
		// The engine refreshes the cache once a second on a separate ticker.
		t.flows = t.eng.DecoratedFlows(5)
	}
	return nil
}
func (t *dashboardTab) View(w, h int) string {
	if w <= 0 {
		w = 100
	}
	var b strings.Builder

	// --- Grade panel ------------------------------------------------------
	var ifaces []netops.IfaceInfo
	if nw := t.eng.Netops(); nw != nil {
		ifaces, _ = nw.ListIfaces()
	}
	var wifi []collectors.WiFiSnapshot
	if wc := t.eng.WiFi(); wc != nil {
		wifi = wc.Snapshot()
	}
	fwRate, fwHas := t.eng.FirewallSignal()
	qc := t.eng.QualitySnapshot()
	grade := ComputeGrade(t.targets, t.dns, ifaces, wifi, fwRate, fwHas, l3InputFrom(t.eng.Neigh(), t.eng.NetlinkWatch()), tcpInputFrom(t.eng.TCPInfo(), t.eng.Flows()), t.eng.Settings().Snapshot(), qc.GradeContext())
	gradeRows := []string{
		headerStyle.Render("Network Quality"),
		"",
		renderGradeBadge(grade, w),
		"",
		renderSubScoreBar(grade.Loss, w),
		renderSubScoreBar(grade.RTT, w),
		renderSubScoreBar(grade.Jitter, w),
		renderSubScoreBar(grade.DNS, w),
		renderSubScoreBar(grade.LAN, w),
		renderSubScoreBar(grade.HTTP, w),
		renderSubScoreBar(grade.Stab, w),
		renderSubScoreBar(grade.WiFi, w),
		renderSubScoreBar(grade.Firewall, w),
		renderSubScoreBar(grade.NAT, w),
		renderSubScoreBar(grade.Congestion, w),
	}
	if grade.PMTUBlackhole {
		gradeRows = append(gradeRows,
			errStyle.Render(fmt.Sprintf("  ⚠ PMTU black-hole detected (-%d) - a flow is retransmitting without progress", grade.PMTUPenalty)))
	}
	if ctxRows := renderQualityContext(grade); len(ctxRows) > 0 {
		gradeRows = append(gradeRows, "")
		gradeRows = append(gradeRows, ctxRows...)
	}
	if len(t.targets) == 0 && len(t.dns) == 0 {
		gradeRows = append(gradeRows, "",
			subtitleStyle.Render("  …awaiting first probes"))
	}
	b.WriteString(boxStyle.Render(strings.Join(gradeRows, "\n")))
	b.WriteString("\n")

	// --- Bandwidth (per interface) - sniffnet-style live chart ----------
	bwRows := []string{headerStyle.Render("Bandwidth - per interface (1Hz, 120s window)")}
	bw := t.eng.Bandwidth().Snapshot()
	if len(bw) == 0 {
		bwRows = append(bwRows, subtitleStyle.Render("  …awaiting first sample"))
	} else {
		for _, bws := range bw {
			rxLine := fmt.Sprintf("%-10s rx %s/s peak %s/s",
				bws.Iface, fmtBytes(uint64(bws.CurrentRx)), fmtBytes(uint64(bws.PeakRx)))
			txLine := fmt.Sprintf("%-10s tx %s/s peak %s/s",
				bws.Iface, fmtBytes(uint64(bws.CurrentTx)), fmtBytes(uint64(bws.PeakTx)))
			rxSpark := sparkline(bws.RxBytesPerS, max(w-len(rxLine)-6, 20))
			txSpark := sparkline(bws.TxBytesPerS, max(w-len(txLine)-6, 20))
			bwRows = append(bwRows,
				fmt.Sprintf("  %s  %s", dimStyle.Render(rxLine), okStyle.Render(rxSpark)),
				fmt.Sprintf("  %s  %s", dimStyle.Render(txLine), warnStyle.Render(txSpark)),
			)
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(bwRows, "\n")))
	b.WriteString("\n")

	// --- Live charts ------------------------------------------------------
	// Filter out synthetic latency entries that other collectors write into
	// the aggregator (traceroute hops + end-to-end, wifi signal encoded as
	// negative RTT, bufferbloat idle/loaded pairs). Those have their own
	// Health-tab sections; rendering them here produced one near-identical
	// sparkline per hop.
	icmpTargets := filterICMPTargets(t.targets)
	chartRows := []string{headerStyle.Render("ICMP latency (rolling samples)")}
	if len(icmpTargets) == 0 {
		chartRows = append(chartRows, subtitleStyle.Render("  …awaiting first probe"))
	} else {
		for _, tg := range icmpTargets {
			samples := t.eng.Aggregator().LatencySamples(tg.Target)
			line := renderSparklineWithLabel(tg.Target, samples, w)
			if b, ok := qc.Baselines[tg.Target]; ok && b.Samples > 0 {
				descr := quality.BaselineDescr(b, quality.Sample{RTTms: float64(tg.AvgRTT) / float64(time.Millisecond)})
				if descr != "" {
					line += "  " + dimStyle.Render("("+descr+")")
				}
				chartRows = append(chartRows, line)
				// The baseline band behind the live line: the learned normal
				// envelope for this hour-of-day.
				chartRows = append(chartRows, dimStyle.Render(
					fmt.Sprintf("                 normal band: p50 %.0fms · p95 %.0fms (n=%d)",
						b.P50RTT, b.P95RTT, b.Samples)))
			} else {
				chartRows = append(chartRows, line)
			}
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(chartRows, "\n")))
	b.WriteString("\n")

	dnsRows := []string{headerStyle.Render("DNS latency (rolling samples)")}
	if len(t.dns) == 0 {
		dnsRows = append(dnsRows, subtitleStyle.Render("  …awaiting first query"))
	} else {
		for _, d := range t.dns {
			samples := t.eng.Aggregator().DNSSamples(d.Name)
			dnsRows = append(dnsRows,
				renderSparklineWithLabel(d.Name, samples, w))
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(dnsRows, "\n")))
	b.WriteString("\n")

	// --- Detail tables ----------------------------------------------------
	// innerW is the width available inside boxStyle (border 2 + pad 2).
	innerW := w - 4
	icmpWidths := []int{16, 10, 10, 10, 10, 10}
	rows := []string{headerStyle.Render("ICMP - per-target detail")}
	rows = append(rows, renderTableRow(innerW, icmpWidths,
		"TARGET", "LAST", "AVG", "P95", "LOSS%", "JITTER"))
	if len(icmpTargets) == 0 {
		rows = append(rows, subtitleStyle.Render("  …awaiting first probe"))
	} else {
		for _, tg := range icmpTargets {
			lossStyled := okStyle.Render(fmt.Sprintf("%.1f%%", tg.LossPct))
			switch {
			case tg.LossPct >= 8:
				lossStyled = errStyle.Render(fmt.Sprintf("%.1f%%", tg.LossPct))
			case tg.LossPct >= 2:
				lossStyled = warnStyle.Render(fmt.Sprintf("%.1f%%", tg.LossPct))
			}
			rows = append(rows, renderTableRow(innerW, icmpWidths,
				tg.Target, fmtRTT(tg.LastRTT), fmtRTT(tg.AvgRTT), fmtRTT(tg.P95RTT),
				lossStyled, fmt.Sprintf("%.1fms", tg.JitterMs)))
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(rows, "\n")))
	b.WriteString("\n")

	// DNS detail table - same shape as the legacy dashboard, restored
	// because the sparkline above only shows latency over time, not the
	// query/failure counters operators rely on.
	dnsWidths := []int{20, 10, 10, 10, 10}
	dnsDetail := []string{headerStyle.Render("DNS - per-resolver detail")}
	dnsDetail = append(dnsDetail, renderTableRow(innerW, dnsWidths,
		"NAME", "LAST", "AVG", "QUERIES", "FAIL"))
	if len(t.dns) == 0 {
		dnsDetail = append(dnsDetail, subtitleStyle.Render("  …awaiting first query"))
	} else {
		for _, d := range t.dns {
			failStyled := okStyle.Render(fmt.Sprintf("%d", d.Failures))
			if d.Failures > 0 {
				failStyled = warnStyle.Render(fmt.Sprintf("%d", d.Failures))
			}
			dnsDetail = append(dnsDetail, renderTableRow(innerW, dnsWidths,
				d.Name, fmtRTT(d.LastLatency), fmtRTT(d.AvgLatency),
				fmt.Sprintf("%d", d.Queries), failStyled))
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(dnsDetail, "\n")))
	b.WriteString("\n")

	// Flows preview
	flowsWidths := []int{8, 10, 24, 24, 10, 12}
	rows = []string{headerStyle.Render("Top flows (last 5 by recency)")}
	rows = append(rows, renderTableRow(innerW, flowsWidths,
		"PROTO", "IFACE", "A", "B", "PKTS", "BYTES"))
	if len(t.flows) == 0 {
		rows = append(rows, subtitleStyle.Render("  enable capture (Flows tab => 's') to populate flow data"))
	} else {
		for _, f := range t.flows {
			label := f.Key.B.String()
			if f.DNSName != "" {
				label = f.DNSName + " (" + f.Key.B.String() + ")"
			}
			rows = append(rows, renderTableRow(innerW, flowsWidths,
				strings.ToUpper(f.Key.Proto), f.Key.Iface,
				f.Key.A.String(), label,
				fmt.Sprintf("%d", f.Packets), fmtBytes(f.Bytes)))
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(rows, "\n")))
	return b.String()
}

// ---- Flows ----

type flowsTab struct {
	eng    *engine.Engine
	app    *App
	rows   []flows.FlowStats
	cursor int
	// filter is a case-insensitive substring matched against proto / iface /
	// process / either endpoint address / DNS name. Set by the chrome via the
	// Filterable interface when the user types in the `/` prompt.
	filter string
}

func newFlowsTab(eng *engine.Engine, app *App) *flowsTab { return &flowsTab{eng: eng, app: app} }

func (t *flowsTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "s", Desc: "start/stop flow capture (auto-discover ifaces)"},
		{Key: "i", Desc: "start capture on a specific interface set"},
		{Key: "c", Desc: "clear the in-memory flow table"},
		{Key: "↑/↓ · j/k", Desc: "select row"},
		{Key: "/", Desc: "filter (proto / iface / process / IP / DNS)"},
	}
}
func (t *flowsTab) Title() string    { return "Flows" }
func (t *flowsTab) ShortKey() string { return "2" }
func (t *flowsTab) Init() tea.Cmd    { return nil }

// SetFilter implements Filterable. Lowercased once at assignment so View can
// substring-match without repeating ToLower per row.
func (t *flowsTab) SetFilter(s string) {
	t.filter = strings.ToLower(strings.TrimSpace(s))
	t.cursor = 0
}

// matchesFilter is the per-row gate used by View. Empty filter passes all.
func (t *flowsTab) matchesFilter(f flows.FlowStats) bool {
	if t.filter == "" {
		return true
	}
	fields := []string{
		strings.ToLower(f.Key.Proto),
		strings.ToLower(f.Key.Iface),
		strings.ToLower(f.Process),
		strings.ToLower(f.Key.A.String()),
		strings.ToLower(f.Key.B.String()),
		strings.ToLower(f.DNSName),
	}
	for _, v := range fields {
		if strings.Contains(v, t.filter) {
			return true
		}
	}
	return false
}
func (t *flowsTab) Update(msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case tickMsg:
		// Read the decorated cache. The 500ms render tick stays free of
		// /proc reads and DNS-cache lookups; the cache is rebuilt once a
		// second by the engine.
		t.rows = t.eng.DecoratedFlows(100)
	case tea.KeyMsg:
		switch m.String() {
		case "up", "k":
			if t.cursor > 0 {
				t.cursor--
			}
		case "down", "j":
			// Upper bound uses the visible count; View clamps further when
			// the filter shrinks the window between key events.
			max := t.visibleCount()
			if t.cursor < max-1 {
				t.cursor++
			}
		case "s":
			// Single-key toggle: start if off, stop if on. Uses auto-discover.
			if t.eng.IsCaptureRunning() {
				t.eng.StopCapture()
				return statusCmd("capture stopped")
			}
			if err := t.eng.StartCapture(nil); err != nil {
				return statusCmd("start failed: " + err.Error())
			}
			return statusCmd("capture started (auto-discover)")
		case "i":
			// Explicit interface picker.
			return t.openIfacePickerModal()
		case "c":
			t.eng.Flows().Reset()
			t.cursor = 0
			return statusCmd("flow table cleared")
		}
	}
	return nil
}

// openIfacePickerModal lets the user start capture on an explicit comma-
// separated interface list. Empty input falls back to auto-discover.
func (t *flowsTab) openIfacePickerModal() tea.Cmd {
	modal := NewFormModal("Start flow capture",
		[]FormField{
			{Label: "ifaces", Value: "", Hint: "comma-separated names; blank = auto-discover"},
		},
		func(values map[string]string) error {
			raw := strings.TrimSpace(values["ifaces"])
			var ifaces []string
			if raw != "" {
				for _, part := range strings.Split(raw, ",") {
					if p := strings.TrimSpace(part); p != "" {
						ifaces = append(ifaces, p)
					}
				}
			}
			// Toggle to a clean state then start with the picked set.
			if t.eng.IsCaptureRunning() {
				t.eng.StopCapture()
			}
			return t.eng.StartCapture(ifaces)
		},
	)
	return t.app.SetModal(modal)
}

// statusCmd is a tiny helper that emits a transient toast in the chrome.
func statusCmd(msg string) tea.Cmd {
	return func() tea.Msg { return statusMessageMsg(msg) }
}

// visibleCount returns how many flows pass the current filter - used by the
// arrow-key handler to bound the cursor.
func (t *flowsTab) visibleCount() int {
	if t.filter == "" {
		return len(t.rows)
	}
	n := 0
	for _, f := range t.rows {
		if t.matchesFilter(f) {
			n++
		}
	}
	return n
}
func (t *flowsTab) View(w, h int) string {
	// innerW: inside boxStyle (border 2 + pad 2 = 4) without a row indent.
	innerW := w - 4
	widths := []int{6, 9, 16, 24, 14, 7, 9, 18, 12, 13, 9}
	headers := []string{"PROTO", "IFACE", "PROCESS", "A => B", "SCOPE", "PKTS", "BYTES", "RTT·RTX·CWND", "DNS", "AGE", "BYTE A=>B"}
	// Apply filter once per render.
	visible := t.rows
	if t.filter != "" {
		visible = visible[:0:0]
		for _, f := range t.rows {
			if t.matchesFilter(f) {
				visible = append(visible, f)
			}
		}
	} else {
		visible = append(visible[:0:0], visible...)
	}
	// Surface the connection that's actually suffering: flows carrying TCP
	// telemetry with a high retransmission rate float to the top, otherwise
	// the existing recency order is preserved.
	sort.SliceStable(visible, func(i, j int) bool {
		ri, rj := visible[i].TCP.RetransRate, visible[j].TCP.RetransRate
		if ri != rj {
			return ri > rj
		}
		return visible[i].LastSeen.After(visible[j].LastSeen)
	})
	// Capture status badge - surfaces the live toggle so operators always
	// know whether the table is reflecting reality.
	var status string
	if t.eng.IsCaptureRunning() {
		ifaces := t.eng.CaptureIfaces()
		ifList := "auto"
		if len(ifaces) > 0 {
			ifList = strings.Join(ifaces, ", ")
		}
		status = okStyle.Render(fmt.Sprintf("● capture ON [%s]", ifList))
	} else {
		status = errStyle.Render("○ capture OFF")
	}
	title := fmt.Sprintf("Flows - %d active · %s · s=start/stop · i=pick ifaces · c=clear",
		len(t.rows), status)
	if t.filter != "" {
		title = fmt.Sprintf("Flows - %d / %d match `%s` · %s",
			len(visible), len(t.rows), t.filter, status)
	}
	// Source tag for the per-flow TCP columns, labelled the way WiFi labels
	// its nl80211/proc backend.
	if ti := t.eng.TCPInfo(); ti != nil {
		st := ti.Status()
		title += dimStyle.Render(" · tcp:" + st.Source)
	}
	rows := []string{
		headerStyle.Render(title),
		renderTableRow(innerW, widths, headers...),
	}
	if len(t.rows) == 0 {
		hint := "  no flows captured - press 's' to start capture (or 'i' to pick interfaces)"
		if t.eng.IsCaptureRunning() {
			hint = "  capture running but no flows observed yet - give it a moment"
		}
		rows = append(rows, subtitleStyle.Render(hint))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	if len(visible) == 0 {
		rows = append(rows, subtitleStyle.Render("  no flows match the active filter"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	// Clamp cursor to current visible window.
	if t.cursor >= len(visible) {
		t.cursor = len(visible) - 1
	}
	for i, f := range visible {
		age := time.Since(f.LastSeen).Truncate(100 * time.Millisecond)
		ab := f.Key.A.String() + " => " + f.Key.B.String()
		dns := f.DNSName
		if dns == "" {
			dns = "-"
		}
		proc := f.Process
		if proc == "" {
			proc = "-"
		}
		tcp := "-"
		if f.HasTCP() {
			tcp = fmt.Sprintf("%.0fms %.1f%% %d", f.TCP.RTTms(), f.TCP.RetransRate, f.TCP.Cwnd)
		}
		scope := scopePair(f.Key.A.IP, f.Key.B.IP)
		row := renderTableRow(innerW, widths,
			strings.ToUpper(f.Key.Proto), f.Key.Iface, proc, ab, scope,
			fmt.Sprintf("%d", f.Packets), fmtBytes(f.Bytes), tcp, dns,
			fmt.Sprintf("%s ago", age), fmtBytes(f.BytesAtoB))
		if i == t.cursor {
			rows = append(rows, selectedRowStyle.Render(row))
		} else {
			rows = append(rows, rowStyle.Render(row))
		}
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// watchIndicator renders the RTNETLINK push watcher's freshness as a small
// trailing badge for the Interfaces / Routes headers: a green "● live" when
// the multicast subscriptions are attached (updates are sub-second), or an
// amber "● polled" when the watcher soft-failed and falls back to the slow
// reconcile timer. Empty when the watcher is disabled.
func watchIndicator(eng *engine.Engine) string {
	nw := eng.NetlinkWatch()
	if nw == nil {
		return ""
	}
	st := nw.Status()
	switch st.Mode {
	case "live":
		return okStyle.Render("● live")
	case "polled":
		s := warnStyle.Render("● polled - netlink subscribe unavailable")
		if st.Detail != "" {
			s = warnStyle.Render("● polled - " + st.Detail)
		}
		return s
	default:
		return ""
	}
}

// ---- Interfaces ----

type ifacesTab struct {
	eng    *engine.Engine
	app    *App
	infos  []netops.IfaceInfo
	err    error
	cursor int
}

func newIfacesTab(eng *engine.Engine, app *App) *ifacesTab {
	return &ifacesTab{eng: eng, app: app}
}

func (t *ifacesTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select interface"},
		{Key: "u", Desc: "bring selected interface up"},
		{Key: "d", Desc: "bring selected interface down"},
		{Key: "a", Desc: "add IP/CIDR to selected"},
		{Key: "x", Desc: "remove IP/CIDR from selected"},
		{Key: "m", Desc: "set MTU on selected"},
		{Key: "h", Desc: "switch selected to DHCP"},
		{Key: "s", Desc: "switch selected to static (cidr)"},
		{Key: "r", Desc: "refresh"},
	}
}
func (t *ifacesTab) Title() string    { return "Interfaces" }
func (t *ifacesTab) ShortKey() string { return "4" }
func (t *ifacesTab) Init() tea.Cmd    { return nil }
func (t *ifacesTab) refresh() {
	if t.eng.Netops() == nil {
		t.err = fmt.Errorf("netops not initialized")
		return
	}
	t.infos, t.err = t.eng.Netops().ListIfaces()
}
func (t *ifacesTab) Update(msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case slowTickMsg:
		t.refresh()
	case tea.KeyMsg:
		switch m.String() {
		case "up", "k":
			if t.cursor > 0 {
				t.cursor--
			}
		case "down", "j":
			if t.cursor < len(t.infos)-1 {
				t.cursor++
			}
		case "u":
			if len(t.infos) > 0 {
				if err := t.eng.Netops().SetIfaceUp(t.infos[t.cursor].Name); err != nil {
					return func() tea.Msg { return statusMessageMsg(err.Error()) }
				}
				return func() tea.Msg { return statusMessageMsg("brought up " + t.infos[t.cursor].Name) }
			}
		case "d":
			if len(t.infos) > 0 {
				if err := t.eng.Netops().SetIfaceDown(t.infos[t.cursor].Name); err != nil {
					return func() tea.Msg { return statusMessageMsg(err.Error()) }
				}
				return func() tea.Msg { return statusMessageMsg("brought down " + t.infos[t.cursor].Name) }
			}
		case "a":
			return t.openAddAddrModal()
		case "x":
			return t.openDelAddrModal()
		case "m":
			return t.openSetMTUModal()
		case "h":
			return t.openDHCPModal()
		case "s":
			return t.openStaticModal()
		case "r":
			t.refresh()
		}
	}
	return nil
}

func (t *ifacesTab) selectedName() string {
	if t.cursor < 0 || t.cursor >= len(t.infos) {
		return ""
	}
	return t.infos[t.cursor].Name
}

func (t *ifacesTab) openAddAddrModal() tea.Cmd {
	name := t.selectedName()
	if name == "" {
		return nil
	}
	modal := NewFormModal("Add Address to "+name,
		[]FormField{
			{Label: "cidr", Value: "", Hint: "e.g. 192.168.1.20/24"},
		},
		func(values map[string]string) error {
			return t.eng.Netops().AddAddr(name, values["cidr"])
		},
	)
	return t.app.SetModal(modal)
}

func (t *ifacesTab) openDelAddrModal() tea.Cmd {
	name := t.selectedName()
	if name == "" {
		return nil
	}
	modal := NewFormModal("Remove Address from "+name,
		[]FormField{
			{Label: "cidr", Value: "", Hint: "e.g. 192.168.1.20/24"},
		},
		func(values map[string]string) error {
			return t.eng.Netops().DelAddr(name, values["cidr"])
		},
	)
	return t.app.SetModal(modal)
}

func (t *ifacesTab) openSetMTUModal() tea.Cmd {
	name := t.selectedName()
	if name == "" {
		return nil
	}
	modal := NewFormModal("Set MTU on "+name,
		[]FormField{
			{Label: "mtu", Value: "1500", Hint: "e.g. 1500 or 9000"},
		},
		func(values map[string]string) error {
			var mtu int
			if _, err := fmt.Sscanf(values["mtu"], "%d", &mtu); err != nil || mtu <= 0 {
				return fmt.Errorf("mtu must be a positive integer")
			}
			return t.eng.Netops().SetMTU(name, mtu)
		},
	)
	return t.app.SetModal(modal)
}

// openDHCPModal confirms the operation, then asks netops to release any
// existing lease and request a fresh one via dhclient/dhcpcd.
func (t *ifacesTab) openDHCPModal() tea.Cmd {
	name := t.selectedName()
	if name == "" {
		return nil
	}
	modal := NewFormModal("Switch "+name+" to DHCP",
		[]FormField{
			{Label: "confirm", Value: "yes", Hint: "type 'yes' to release existing addrs + request DHCP"},
		},
		func(values map[string]string) error {
			if strings.ToLower(strings.TrimSpace(values["confirm"])) != "yes" {
				return fmt.Errorf("aborted")
			}
			return t.eng.Netops().SetIfaceDHCP(name)
		},
	)
	return t.app.SetModal(modal)
}

// openStaticModal flushes existing addresses and assigns the supplied CIDR.
func (t *ifacesTab) openStaticModal() tea.Cmd {
	name := t.selectedName()
	if name == "" {
		return nil
	}
	modal := NewFormModal("Switch "+name+" to static IP",
		[]FormField{
			{Label: "cidr", Value: "", Hint: "e.g. 192.168.1.20/24"},
		},
		func(values map[string]string) error {
			cidr := strings.TrimSpace(values["cidr"])
			if cidr == "" {
				return fmt.Errorf("cidr required")
			}
			return t.eng.Netops().SetIfaceStatic(name, cidr)
		},
	)
	return t.app.SetModal(modal)
}

func (t *ifacesTab) View(w, h int) string {
	header := headerStyle.Render("Interfaces - u=up · d=down · a=add addr · x=del addr · m=mtu · h=dhcp · s=static · r=refresh")
	if ind := watchIndicator(t.eng); ind != "" {
		header += "  " + ind
	}
	rows := []string{header}
	if t.err != nil {
		rows = append(rows, errStyle.Render("  "+t.err.Error()))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	// innerW: inside boxStyle (border 2 + pad 2 = 4) without a row indent.
	innerW := w - 4
	widths := []int{14, 6, 8, 8, 18, 30, 12, 12}
	rows = append(rows, renderTableRow(innerW, widths,
		"NAME", "INDEX", "MTU", "STATE", "HWADDR", "ADDRS", "RX", "TX"))
	for i, ifi := range t.infos {
		state := "DOWN"
		stateStyle := errStyle
		if ifi.Up && ifi.Running {
			state = "UP"
			stateStyle = okStyle
		} else if ifi.Up {
			state = "DORM"
			stateStyle = warnStyle
		}
		row := renderTableRow(innerW, widths,
			ifi.Name, fmt.Sprintf("%d", ifi.Index), fmt.Sprintf("%d", ifi.MTU),
			stateStyle.Render(state), ifi.HWAddr, strings.Join(ifi.Addrs, ","),
			fmtBytes(ifi.RxBytes), fmtBytes(ifi.TxBytes),
		)
		if i == t.cursor {
			rows = append(rows, selectedRowStyle.Render(row))
		} else {
			rows = append(rows, rowStyle.Render(row))
		}
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// ---- Routes ----

type routesTab struct {
	eng    *engine.Engine
	app    *App
	routes []netops.RouteInfo
	err    error
	cursor int
}

func newRoutesTab(eng *engine.Engine, app *App) *routesTab {
	return &routesTab{eng: eng, app: app}
}

func (t *routesTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select route"},
		{Key: "a", Desc: "add route (cidr / gateway / iface)"},
		{Key: "x", Desc: "delete the selected route"},
		{Key: "r", Desc: "refresh"},
	}
}
func (t *routesTab) Title() string    { return "Routes" }
func (t *routesTab) ShortKey() string { return "5" }
func (t *routesTab) Init() tea.Cmd    { return nil }
func (t *routesTab) refresh() {
	if t.eng.Netops() == nil {
		t.err = fmt.Errorf("netops not initialized")
		return
	}
	t.routes, t.err = t.eng.Netops().ListRoutes()
}
func (t *routesTab) Update(msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case slowTickMsg:
		t.refresh()
	case tea.KeyMsg:
		switch m.String() {
		case "up", "k":
			if t.cursor > 0 {
				t.cursor--
			}
		case "down", "j":
			if t.cursor < len(t.routes)-1 {
				t.cursor++
			}
		case "a":
			return t.openAddModal()
		case "x":
			return t.openDelModal()
		case "r":
			t.refresh()
		}
	}
	return nil
}

func (t *routesTab) openAddModal() tea.Cmd {
	preselected := ""
	if t.cursor >= 0 && t.cursor < len(t.routes) {
		preselected = t.routes[t.cursor].Iface
	}
	modal := NewFormModal("Add Route",
		[]FormField{
			{Label: "cidr", Value: "", Hint: "destination CIDR, e.g. 10.0.0.0/24"},
			{Label: "gateway", Value: "", Hint: "next-hop IP (blank for direct)"},
			{Label: "iface", Value: preselected, Hint: "outgoing interface (blank to auto-pick)"},
		},
		func(values map[string]string) error {
			return t.eng.Netops().AddRoute(values["cidr"], values["gateway"], values["iface"])
		},
	)
	return t.app.SetModal(modal)
}

func (t *routesTab) openDelModal() tea.Cmd {
	preselected := ""
	if t.cursor >= 0 && t.cursor < len(t.routes) {
		preselected = t.routes[t.cursor].Dst
	}
	modal := NewFormModal("Delete Route",
		[]FormField{
			{Label: "cidr", Value: preselected, Hint: "destination CIDR to remove"},
		},
		func(values map[string]string) error {
			return t.eng.Netops().DelRoute(values["cidr"])
		},
	)
	return t.app.SetModal(modal)
}

func (t *routesTab) View(w, h int) string {
	header := headerStyle.Render(fmt.Sprintf("Routes - %d entries · a=add · x=del · r=refresh", len(t.routes)))
	if ind := watchIndicator(t.eng); ind != "" {
		header += "  " + ind
	}
	rows := []string{header}
	if t.err != nil {
		rows = append(rows, netopsErrLines(t.err)...)
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	// innerW: inside boxStyle (border 2 + pad 2 = 4) without a row indent.
	innerW := w - 4
	widths := []int{6, 22, 18, 12, 12, 10, 8}
	rows = append(rows, renderTableRow(innerW, widths,
		"FAMILY", "DST", "GATEWAY", "IFACE", "PROTO", "SCOPE", "METRIC"))
	for i, r := range t.routes {
		gw := r.Gateway
		if gw == "" {
			gw = "-"
		}
		row := renderTableRow(innerW, widths,
			r.Family, r.Dst, gw, r.Iface, r.Protocol, r.Scope,
			fmt.Sprintf("%d", r.Metric))
		if i == t.cursor {
			rows = append(rows, selectedRowStyle.Render(row))
		} else {
			rows = append(rows, rowStyle.Render(row))
		}
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// ---- Firewall ----

type firewallTab struct {
	eng     *engine.Engine
	app     *App
	rules   []netops.RuleInfo
	managed []netops.FilterRule
	err     error
	cursor  int
}

func newFirewallTab(eng *engine.Engine, app *App) *firewallTab {
	return &firewallTab{eng: eng, app: app}
}

func (t *firewallTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select rule"},
		{Key: "a", Desc: "add filter rule (chain / action / proto / port / in / out / src / dst)"},
		{Key: "e", Desc: "edit: open a pre-filled add modal from the selected managed rule"},
		{Key: "x", Desc: "delete the selected managed rule (full tuple match)"},
		{Key: "R", Desc: "reset the selected rule's counter (needs netops writes)"},
		{Key: "r", Desc: "refresh"},
	}
}
func (t *firewallTab) Title() string    { return "Firewall" }
func (t *firewallTab) ShortKey() string { return "6" }
func (t *firewallTab) Init() tea.Cmd    { return nil }
func (t *firewallTab) refresh() {
	if t.eng.Netops() == nil {
		t.err = fmt.Errorf("netops not initialized")
		return
	}
	t.rules, t.err = t.eng.Netops().ListFirewallRules()
	if t.err == nil {
		t.managed, _ = t.eng.Netops().ListFilterRules()
	}
}

// firewallRowKind classifies one row in the unified firewall list.
type firewallRowKind int

const (
	firewallRowManaged firewallRowKind = iota
	firewallRowRule
)

// firewallRow is one navigable row. Managed rules carry their slice index
// into t.managed; decoded rules carry their index into t.rules (which holds
// family/table/chain/handle for counter reset).
type firewallRow struct {
	kind       firewallRowKind
	managedIdx int
	ruleIdx    int
}

// rows returns every navigable row in the firewall tab: editable managed
// rules first, then every decoded kernel rule (with per-rule counters). The
// cursor indexes into this slice so j/k always lands on something visible.
func (t *firewallTab) rows() []firewallRow {
	out := make([]firewallRow, 0, len(t.managed)+len(t.rules))
	for i := range t.managed {
		out = append(out, firewallRow{kind: firewallRowManaged, managedIdx: i})
	}
	for i := range t.rules {
		out = append(out, firewallRow{kind: firewallRowRule, ruleIdx: i})
	}
	return out
}

func (t *firewallTab) Update(msg tea.Msg) tea.Cmd {
	if _, ok := msg.(slowTickMsg); ok {
		t.refresh()
		total := len(t.rows())
		if t.cursor >= total {
			t.cursor = total - 1
		}
		if t.cursor < 0 {
			t.cursor = 0
		}
		return nil
	}
	if m, ok := msg.(tea.KeyMsg); ok {
		rows := t.rows()
		switch m.String() {
		case "up", "k":
			if t.cursor > 0 {
				t.cursor--
			}
		case "down", "j":
			if t.cursor < len(rows)-1 {
				t.cursor++
			}
		case "r":
			t.refresh()
		case "a":
			return t.openAddModal()
		case "e":
			// Edit = open the add modal pre-filled from the selected managed
			// rule. Decoded kernel rules aren't Testudo-managed, so editing
			// them isn't offered.
			if t.cursor >= 0 && t.cursor < len(rows) && rows[t.cursor].kind == firewallRowManaged {
				return t.openEditModal(t.managed[rows[t.cursor].managedIdx])
			}
			return statusCmd("select a Testudo-managed rule to edit")
		case "x":
			// Only managed rules can be deleted from here; tell the user
			// when they try to delete a decoded kernel rule.
			if t.cursor >= 0 && t.cursor < len(rows) {
				if rows[t.cursor].kind == firewallRowRule {
					return statusCmd("kernel rule is read-only here - delete managed rules only")
				}
			}
			return t.openDelModal()
		case "R":
			return t.resetSelectedCounter()
		}
	}
	return nil
}

func (t *firewallTab) openAddModal() tea.Cmd {
	modal := NewFormModal("Add Filter Rule (testudo_filter)",
		[]FormField{
			{Label: "chain", Value: "input", Hint: "input / output / forward"},
			{Label: "action", Value: "drop", Hint: "accept or drop"},
			{Label: "proto", Value: "tcp", Hint: "tcp / udp / blank=any"},
			{Label: "port", Value: "", Hint: "destination port 1-65535; blank=any (needs proto)"},
			{Label: "in_iface", Value: "", Hint: "incoming interface (input/forward); blank=any"},
			{Label: "out_iface", Value: "", Hint: "outgoing interface (output/forward); blank=any"},
			{Label: "src", Value: "", Hint: "source IPv4 or CIDR (10.0.0.0/24); blank=any"},
			{Label: "dst", Value: "", Hint: "destination IPv4 or CIDR; blank=any"},
		},
		func(values map[string]string) error {
			port := uint16(0)
			if v := strings.TrimSpace(values["port"]); v != "" {
				p, err := parseUint16(v)
				if err != nil {
					return fmt.Errorf("port: %v", err)
				}
				port = p
			}
			return t.eng.Netops().AddFilterRule(netops.FilterRule{
				Chain:    strings.TrimSpace(values["chain"]),
				Action:   strings.TrimSpace(values["action"]),
				Proto:    strings.TrimSpace(values["proto"]),
				Port:     port,
				InIface:  strings.TrimSpace(values["in_iface"]),
				OutIface: strings.TrimSpace(values["out_iface"]),
				SrcCIDR:  strings.TrimSpace(values["src"]),
				DstCIDR:  strings.TrimSpace(values["dst"]),
			})
		},
	)
	return t.app.SetModal(modal)
}

// openEditModal opens an add-rule modal pre-filled from an existing managed
// rule. nftables filter rules aren't mutated in place; "edit" here means
// "add the corrected rule" (the operator removes the stale one with x), which
// keeps the modal workflow identical to add.
func (t *firewallTab) openEditModal(src netops.FilterRule) tea.Cmd {
	portStr := ""
	if src.Port != 0 {
		portStr = fmt.Sprintf("%d", src.Port)
	}
	modal := NewFormModal("Edit Filter Rule (adds a new rule)",
		[]FormField{
			{Label: "chain", Value: src.Chain, Hint: "input / output / forward"},
			{Label: "action", Value: src.Action, Hint: "accept or drop"},
			{Label: "proto", Value: src.Proto, Hint: "tcp / udp / blank=any"},
			{Label: "port", Value: portStr, Hint: "destination port 1-65535; blank=any (needs proto)"},
			{Label: "in_iface", Value: src.InIface, Hint: "incoming interface (input/forward); blank=any"},
			{Label: "out_iface", Value: src.OutIface, Hint: "outgoing interface (output/forward); blank=any"},
			{Label: "src", Value: src.SrcCIDR, Hint: "source IPv4 or CIDR; blank=any"},
			{Label: "dst", Value: src.DstCIDR, Hint: "destination IPv4 or CIDR; blank=any"},
		},
		func(values map[string]string) error {
			port := uint16(0)
			if v := strings.TrimSpace(values["port"]); v != "" {
				p, err := parseUint16(v)
				if err != nil {
					return fmt.Errorf("port: %v", err)
				}
				port = p
			}
			return t.eng.Netops().AddFilterRule(netops.FilterRule{
				Chain:    strings.TrimSpace(values["chain"]),
				Action:   strings.TrimSpace(values["action"]),
				Proto:    strings.TrimSpace(values["proto"]),
				Port:     port,
				InIface:  strings.TrimSpace(values["in_iface"]),
				OutIface: strings.TrimSpace(values["out_iface"]),
				SrcCIDR:  strings.TrimSpace(values["src"]),
				DstCIDR:  strings.TrimSpace(values["dst"]),
			})
		},
	)
	return t.app.SetModal(modal)
}

// resetSelectedCounter zeroes the per-rule counter on the highlighted decoded
// rule. Write-gated: ResetRuleCounter returns ErrWritesDisabled when netops
// writes are off, surfaced here as a toast.
func (t *firewallTab) resetSelectedCounter() tea.Cmd {
	all := t.rows()
	if t.cursor < 0 || t.cursor >= len(all) || all[t.cursor].kind != firewallRowRule {
		return statusCmd("select a kernel rule row to reset its counter")
	}
	r := t.rules[all[t.cursor].ruleIdx]
	if !r.HasCounter {
		return statusCmd("legacy rule has no counter - recreate via Testudo to enable counting")
	}
	if err := t.eng.Netops().ResetRuleCounter(r.Family, r.Table, r.Chain, r.Handle); err != nil {
		return statusCmd("reset counter: " + err.Error())
	}
	t.refresh()
	return statusCmd(fmt.Sprintf("counter reset on %s/%s/%s handle %d", r.Family, r.Table, r.Chain, r.Handle))
}

func (t *firewallTab) openDelModal() tea.Cmd {
	target := netops.FilterRule{Chain: "input"}
	all := t.rows()
	if t.cursor >= 0 && t.cursor < len(all) && all[t.cursor].kind == firewallRowManaged {
		target = t.managed[all[t.cursor].managedIdx]
	}
	portStr := ""
	if target.Port != 0 {
		portStr = fmt.Sprintf("%d", target.Port)
	}
	modal := NewFormModal("Delete Filter Rule",
		[]FormField{
			{Label: "chain", Value: target.Chain, Hint: "input / output / forward"},
			{Label: "action", Value: target.Action, Hint: "accept / drop / blank=any"},
			{Label: "proto", Value: target.Proto, Hint: "tcp / udp / blank=any"},
			{Label: "port", Value: portStr, Hint: "destination port; blank=any"},
			{Label: "in_iface", Value: target.InIface, Hint: "incoming iface; blank=any"},
			{Label: "out_iface", Value: target.OutIface, Hint: "outgoing iface; blank=any"},
			{Label: "src", Value: target.SrcCIDR, Hint: "source IPv4/CIDR; blank=any"},
			{Label: "dst", Value: target.DstCIDR, Hint: "destination IPv4/CIDR; blank=any"},
		},
		func(values map[string]string) error {
			port := uint16(0)
			if v := strings.TrimSpace(values["port"]); v != "" {
				p, err := parseUint16(v)
				if err != nil {
					return fmt.Errorf("port: %v", err)
				}
				port = p
			}
			return t.eng.Netops().DelFilterRule(netops.FilterRule{
				Chain:    strings.TrimSpace(values["chain"]),
				Action:   strings.TrimSpace(values["action"]),
				Proto:    strings.TrimSpace(values["proto"]),
				Port:     port,
				InIface:  strings.TrimSpace(values["in_iface"]),
				OutIface: strings.TrimSpace(values["out_iface"]),
				SrcCIDR:  strings.TrimSpace(values["src"]),
				DstCIDR:  strings.TrimSpace(values["dst"]),
			})
		},
	)
	return t.app.SetModal(modal)
}

func (t *firewallTab) View(w, h int) string {
	all := t.rows()
	out := []string{headerStyle.Render(fmt.Sprintf(
		"Firewall - %d managed · %d kernel rules · ↑/↓ select · a=add · e=edit · x=del · R=reset · r=refresh",
		len(t.managed), len(t.rules)))}
	if t.err != nil {
		out = append(out, netopsErrLines(t.err)...)
		return boxStyle.Render(strings.Join(out, "\n"))
	}
	if len(all) == 0 {
		out = append(out, subtitleStyle.Render("  no rules visible - press 'a' to add the first managed rule"))
		return boxStyle.Render(strings.Join(out, "\n"))
	}

	// innerW: inside boxStyle (border 2 + pad 2 = 4) with a 2-char row
	// marker / indent, the actual table width is w - 6.
	innerW := w - 6

	// Managed section first. Cursor index 0..len(managed)-1 falls here.
	mw := []int{8, 7, 6, 6, 8, 8, 18, 18}
	if len(t.managed) > 0 {
		out = append(out, headerStyle.Render("Testudo-managed rules (editable)"))
		out = append(out, "  "+renderTableRow(innerW, mw,
			"CHAIN", "ACTION", "PROTO", "PORT", "IN", "OUT", "SRC", "DST"))
	}
	// Decoded per-rule section. Rules arrive already top-sorted per chain
	// (highest-hit DROP/REJECT first); we print a sub-header whenever the
	// family/table/chain changes so each chain reads as its own block.
	ruleWidths := []int{8, 38, 14, 10, 10}
	ruleHeaderShown := false
	lastChainKey := ""
	for i, r := range all {
		var rendered string
		switch r.kind {
		case firewallRowManaged:
			fr := t.managed[r.managedIdx]
			rendered = renderTableRow(innerW, mw,
				fr.Chain,
				strings.ToUpper(fr.Action),
				orDash(strings.ToUpper(fr.Proto)),
				orDash(portOrAny(fr.Port)),
				orDash(fr.InIface),
				orDash(fr.OutIface),
				orDash(fr.SrcCIDR),
				orDash(fr.DstCIDR),
			)
		case firewallRowRule:
			ru := t.rules[r.ruleIdx]
			if !ruleHeaderShown {
				out = append(out, "")
				out = append(out, headerStyle.Render("Kernel rules - per-rule counters (R resets the selected counter)"))
				ruleHeaderShown = true
			}
			if key := ru.Family + "/" + ru.Table + "/" + ru.Chain; key != lastChainKey {
				lastChainKey = key
				out = append(out, dimStyle.Render("  "+key))
				out = append(out, "  "+renderTableRow(innerW, ruleWidths,
					"HANDLE", "MATCH", "VERDICT", "PKTS", "BYTES"))
			}
			pkts, bytes := "-", "-"
			if ru.HasCounter {
				pkts = fmt.Sprintf("%d", ru.Packets)
				bytes = fmtBytes(ru.Bytes)
			}
			match := ru.Match
			if match == "" {
				match = "any"
			}
			rendered = renderTableRow(innerW, ruleWidths,
				fmt.Sprintf("%d", ru.Handle), match, orDash(ru.Verdict), pkts, bytes)
		}
		marker := "  "
		if i == t.cursor {
			marker = "▸ "
		}
		switch {
		case i == t.cursor:
			out = append(out, selectedRowStyle.Render(marker+rendered))
		case r.kind == firewallRowRule && t.rules[r.ruleIdx].IsBlocking() && t.rules[r.ruleIdx].Packets > 0:
			// Active blocking rules are the "what's blocking me" signal -
			// keep them at full intensity so they stand out.
			out = append(out, rowStyle.Render(marker+rendered))
		case r.kind == firewallRowRule:
			out = append(out, dimStyle.Render(marker+rendered))
		default:
			out = append(out, rowStyle.Render(marker+rendered))
		}
	}
	return boxStyle.Render(strings.Join(out, "\n"))
}

// ---- NAT ----

type natTab struct {
	eng      *engine.Engine
	app      *App
	forwards []netops.PortForward
	err      error
	cursor   int

	// focusCT moves the cursor into the live conntrack table (below the
	// port forwards) so a translated flow can be selected and flushed.
	focusCT  bool
	ctCursor int
}

func newNATTab(eng *engine.Engine, app *App) *natTab { return &natTab{eng: eng, app: app} }

func (t *natTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select row"},
		{Key: "a", Desc: "add port forward (proto / wan_port / lan_ip / lan_port)"},
		{Key: "x", Desc: "delete the selected port forward"},
		{Key: "c", Desc: "focus the live conntrack table"},
		{Key: "F", Desc: "flush the selected conntrack flow (needs netops writes)"},
		{Key: "r", Desc: "refresh"},
	}
}
func (t *natTab) Title() string    { return "NAT" }
func (t *natTab) ShortKey() string { return "7" }
func (t *natTab) Init() tea.Cmd    { return nil }
func (t *natTab) refresh() {
	if t.eng.Netops() == nil {
		t.err = fmt.Errorf("netops not initialized")
		return
	}
	t.forwards, t.err = t.eng.Netops().ListPortForwards()
	if t.cursor >= len(t.forwards) {
		t.cursor = len(t.forwards) - 1
	}
	if t.cursor < 0 {
		t.cursor = 0
	}
}
func (t *natTab) Update(msg tea.Msg) tea.Cmd {
	if _, ok := msg.(slowTickMsg); ok {
		t.refresh()
		return nil
	}
	if m, ok := msg.(tea.KeyMsg); ok {
		switch m.String() {
		case "c":
			t.focusCT = !t.focusCT
			t.ctCursor = 0
		case "up", "k":
			if t.focusCT {
				if t.ctCursor > 0 {
					t.ctCursor--
				}
			} else if t.cursor > 0 {
				t.cursor--
			}
		case "down", "j":
			if t.focusCT {
				if t.ctCursor < len(t.conntrack())-1 {
					t.ctCursor++
				}
			} else if t.cursor < len(t.forwards)-1 {
				t.cursor++
			}
		case "r":
			t.refresh()
		case "a":
			return t.openAddModal()
		case "x":
			return t.openDelModal()
		case "F":
			return t.flushSelectedConntrack()
		}
	}
	return nil
}

// conntrack returns the collector's cached flow table (nil when disabled).
func (t *natTab) conntrack() []netops.ConntrackFlow {
	if nc := t.eng.Neigh(); nc != nil {
		return nc.Conntrack()
	}
	return nil
}

// flushSelectedConntrack opens the standard confirm modal for the selected
// live flow. Write-gated: greys out with a toast when netops writes are off,
// matching every other mutation.
func (t *natTab) flushSelectedConntrack() tea.Cmd {
	if !t.focusCT {
		return statusCmd("press 'c' to focus the conntrack table, then 'F' to flush")
	}
	flows := t.conntrack()
	if t.ctCursor < 0 || t.ctCursor >= len(flows) {
		return statusCmd("no conntrack flow selected")
	}
	if !t.eng.Settings().Snapshot().AllowNetopsWrite {
		return statusCmd("netops writes disabled - enable in Settings to flush flows")
	}
	return t.openFlushModal(flows[t.ctCursor])
}

func (t *natTab) openFlushModal(f netops.ConntrackFlow) tea.Cmd {
	modal := NewFormModal(
		fmt.Sprintf("Flush %s flow %s:%d -> %s:%d", strings.ToUpper(f.Proto), f.OrigSrc, f.OrigSport, f.OrigDst, f.OrigDport),
		[]FormField{
			{Label: "proto", Value: f.Proto, Hint: "tcp / udp / icmp ..."},
			{Label: "orig_src", Value: f.OrigSrc, Hint: "original source IP"},
			{Label: "orig_dst", Value: f.OrigDst, Hint: "original destination IP"},
			{Label: "orig_sport", Value: fmt.Sprintf("%d", f.OrigSport), Hint: "original source port"},
			{Label: "orig_dport", Value: fmt.Sprintf("%d", f.OrigDport), Hint: "original destination port"},
		},
		func(values map[string]string) error {
			sport, _ := parseUint16(values["orig_sport"])
			dport, _ := parseUint16(values["orig_dport"])
			return t.eng.Netops().FlushConntrack(netops.ConntrackFlow{
				Proto: values["proto"], OrigSrc: values["orig_src"], OrigDst: values["orig_dst"],
				OrigSport: sport, OrigDport: dport, NATed: f.NATed,
			})
		},
	)
	return t.app.SetModal(modal)
}

func (t *natTab) openAddModal() tea.Cmd {
	modal := NewFormModal("Add Port Forward",
		[]FormField{
			{Label: "proto", Value: "tcp", Hint: "tcp or udp"},
			{Label: "wan_port", Value: "", Hint: "external port (1-65535)"},
			{Label: "lan_ip", Value: "", Hint: "internal IPv4 target"},
			{Label: "lan_port", Value: "", Hint: "internal port; blank = same as wan_port"},
		},
		func(values map[string]string) error {
			proto := values["proto"]
			wanP, err := parseUint16(values["wan_port"])
			if err != nil {
				return fmt.Errorf("wan_port: %v", err)
			}
			lanP, _ := parseUint16(values["lan_port"])
			return t.eng.Netops().AddPortForward(netops.PortForward{
				Proto: proto, WANPort: wanP, LANIP: values["lan_ip"], LANPort: lanP,
			})
		},
	)
	return t.app.SetModal(modal)
}

// openDelModal prompts for proto + wan_port. When a row is currently
// selected (cursor on a valid forward), its proto/port pre-fill the form so
// the common case is a one-keystroke confirm.
func (t *natTab) openDelModal() tea.Cmd {
	proto, wanPort := "tcp", ""
	if t.cursor >= 0 && t.cursor < len(t.forwards) {
		pf := t.forwards[t.cursor]
		proto = pf.Proto
		wanPort = fmt.Sprintf("%d", pf.WANPort)
	}
	modal := NewFormModal("Delete Port Forward",
		[]FormField{
			{Label: "proto", Value: proto, Hint: "tcp or udp"},
			{Label: "wan_port", Value: wanPort, Hint: "external port to remove"},
		},
		func(values map[string]string) error {
			wanP, err := parseUint16(values["wan_port"])
			if err != nil {
				return fmt.Errorf("wan_port: %v", err)
			}
			return t.eng.Netops().DelPortForward(values["proto"], wanP)
		},
	)
	return t.app.SetModal(modal)
}

func parseUint16(s string) (uint16, error) {
	if s == "" {
		return 0, fmt.Errorf("required")
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("out of range")
	}
	return uint16(n), nil
}
func (t *natTab) View(w, h int) string {
	rows := []string{headerStyle.Render("NAT - port forwards in testudo_nat table · a=add · x=del · c=conntrack · r=refresh")}
	if t.err != nil {
		rows = append(rows, netopsErrLines(t.err)...)
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	// innerW: inside boxStyle (border 2 + pad 2 = 4) without a row indent.
	innerW := w - 4
	if len(t.forwards) == 0 {
		rows = append(rows, subtitleStyle.Render("  no port forwards configured by Testudo"))
		rows = append(rows, dimStyle.Render("  press 'a' to add · or CLI: testudo nat add tcp 8080 192.168.1.10:80"))
	} else {
		widths := []int{6, 8, 8, 18, 8}
		rows = append(rows, renderTableRow(innerW, widths, "PROTO", "WAN", "=>", "LAN IP", "LAN PORT"))
		for i, pf := range t.forwards {
			row := renderTableRow(innerW, widths,
				strings.ToUpper(pf.Proto), fmt.Sprintf("%d", pf.WANPort), "=>",
				pf.LANIP, fmt.Sprintf("%d", pf.LANPort))
			if i == t.cursor && !t.focusCT {
				rows = append(rows, selectedRowStyle.Render(row))
			} else {
				rows = append(rows, rowStyle.Render(row))
			}
		}
	}
	rows = append(rows, "")
	rows = append(rows, t.renderConntrack(innerW)...)
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// renderConntrack renders the live conntrack table below the port forwards:
// per-flow original/reply tuples (reply differs once NAT'd), state, bytes and
// timeout, plus a utilisation gauge. Selecting (c to focus) and F flush a
// stuck flow. Capped to the top rows by bytes so a busy router stays readable.
func (t *natTab) renderConntrack(innerW int) []string {
	nc := t.eng.Neigh()
	if nc == nil {
		return []string{dimStyle.Render("conntrack collector disabled")}
	}
	flows := nc.Conntrack()
	count, max := nc.ConntrackCounts()
	hdr := "Conntrack - live flows"
	if max > 0 {
		hdr += fmt.Sprintf(" · %d / %d entries (%.0f%% full)", count, max, float64(count)/float64(max)*100)
	}
	if t.focusCT {
		hdr += " · [focused] F=flush"
	} else {
		hdr += " · c=focus"
	}
	out := []string{headerStyle.Render(hdr)}
	if len(flows) == 0 {
		out = append(out, dimStyle.Render("  no live conntrack flows (needs CAP_NET_ADMIN on some kernels)"))
		return out
	}
	const maxShown = 100
	widths := []int{6, 26, 22, 13, 10, 7}
	out = append(out, renderTableRow(innerW, widths, "PROTO", "ORIGINAL", "REPLY (NAT)", "STATE", "BYTES", "TMO"))
	if t.ctCursor >= len(flows) {
		t.ctCursor = len(flows) - 1
	}
	for i, f := range flows {
		if i >= maxShown {
			out = append(out, dimStyle.Render(fmt.Sprintf("  … %d more flows (capped)", len(flows)-maxShown)))
			break
		}
		orig := fmt.Sprintf("%s:%d>%s:%d", f.OrigSrc, f.OrigSport, f.OrigDst, f.OrigDport)
		reply := dimStyle.Render("-")
		if f.NATed {
			reply = warnStyle.Render(fmt.Sprintf("%s>%s", f.ReplySrc, f.ReplyDst))
		}
		row := renderTableRow(innerW, widths,
			strings.ToUpper(f.Proto), orig, reply, f.State, fmtBytes(f.Bytes),
			fmt.Sprintf("%ds", f.TimeoutSec))
		if t.focusCT && i == t.ctCursor {
			out = append(out, selectedRowStyle.Render(row))
		} else {
			out = append(out, rowStyle.Render(row))
		}
	}
	return out
}

// ---- Alerts ----

type alertsTab struct {
	app *App
}

func newAlertsTab(app *App) *alertsTab { return &alertsTab{app: app} }

func (t *alertsTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "/", Desc: "filter alerts by substring"},
	}
}
func (t *alertsTab) Title() string    { return "Alerts" }
func (t *alertsTab) ShortKey() string { return "0" }
func (t *alertsTab) Init() tea.Cmd    { return nil }
func (t *alertsTab) Update(_ tea.Msg) tea.Cmd {
	return nil // alerts read from app.anomalies; no per-tab state
}
func (t *alertsTab) View(w, h int) string {
	rows := []string{headerStyle.Render(fmt.Sprintf("Alerts - %d events", len(t.app.anomalies)))}
	if len(t.app.anomalies) == 0 {
		rows = append(rows, subtitleStyle.Render("  no anomalies detected"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	// Newest at top.
	for i := len(t.app.anomalies) - 1; i >= 0; i-- {
		a := t.app.anomalies[i]
		sev := severityStyle(a.severity).Render(fmt.Sprintf("%-8s", a.severity))
		rows = append(rows, fmt.Sprintf("  %s  %s  %s",
			subtitleStyle.Render(a.ts.Format("15:04:05")), sev, a.text))
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// ---- Settings ----

type settingsTab struct {
	eng    *engine.Engine
	app    *App
	cursor int
}

type thresholdRow struct {
	label     string
	value     float64
	unit      string
	stepBig   float64
	stepSmall float64
	apply     func(*config.Thresholds, float64)
	// isBool renders the value as ON/OFF rather than a number, and the
	// +/- handler treats any change as a flip. After the apply hook runs,
	// settingsTab.afterApply lets the tab push the new bool into live
	// runtime state (e.g. mutate the netops Writer).
	isBool     bool
	afterApply func(*settingsTab, float64)

	// String rows render their value as a quoted string and open a
	// FormModal on Enter for editing. applyString is the persistence hook;
	// afterApplyString runs side-effects like re-initialising Sentry.
	isString         bool
	stringValue      string
	stringHint       string // shown as the form-field hint
	applyString      func(*config.Thresholds, string)
	afterApplyString func(*settingsTab, string)

	// Action rows render a "[run]" value and fire `action` on enter/space.
	// Used for one-shot operations (e.g. reset learned baselines) rather than
	// editable values. Write-gated rows set requireWrite.
	isAction     bool
	requireWrite bool
	action       func(*settingsTab) tea.Cmd
}

func newSettingsTab(eng *engine.Engine, app *App) *settingsTab {
	return &settingsTab{eng: eng, app: app}
}
func (t *settingsTab) Title() string    { return "Settings" }
func (t *settingsTab) ShortKey() string { return "" } // jump via `:set`; no numeric shortcut after TCPDump landed
func (t *settingsTab) Init() tea.Cmd    { return nil }
func (t *settingsTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select setting"},
		{Key: "+ / =", Desc: "increase selected"},
		{Key: "- / _", Desc: "decrease selected"},
		{Key: "space · enter", Desc: "toggle boolean / edit string"},
		{Key: "s", Desc: "save settings to disk"},
	}
}
func (t *settingsTab) rows() []thresholdRow {
	th := t.eng.Settings().Snapshot()
	bool01 := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	return []thresholdRow{
		{label: "Packet loss threshold", value: th.PacketLossPct, unit: "%", stepBig: 1, stepSmall: 0.1,
			apply: func(t *config.Thresholds, v float64) { t.PacketLossPct = v }},
		{label: "DNS latency threshold", value: th.DNSLatencyMs, unit: "ms", stepBig: 10, stepSmall: 1,
			apply: func(t *config.Thresholds, v float64) { t.DNSLatencyMs = v }},
		{label: "Jitter threshold", value: th.JitterMs, unit: "ms", stepBig: 5, stepSmall: 1,
			apply: func(t *config.Thresholds, v float64) { t.JitterMs = v }},
		{label: "RTT threshold", value: th.RTTMs, unit: "ms", stepBig: 10, stepSmall: 1,
			apply: func(t *config.Thresholds, v float64) { t.RTTMs = v }},
		{label: "Retransmissions threshold", value: th.RetransmissionsPct, unit: "%", stepBig: 1, stepSmall: 0.1,
			apply: func(t *config.Thresholds, v float64) { t.RetransmissionsPct = v }},
		{label: "Incident cooldown", value: th.IncidentCooldown.Seconds(), unit: "s", stepBig: 30, stepSmall: 5,
			apply: func(t *config.Thresholds, v float64) { t.IncidentCooldown = time.Duration(v * float64(time.Second)) }},
		{label: "Allow netops writes", value: bool01(th.AllowNetopsWrite), unit: "", isBool: true,
			apply: func(t *config.Thresholds, v float64) { t.AllowNetopsWrite = v != 0 },
			afterApply: func(s *settingsTab, v float64) {
				// Push the new value into the live netops.Writer so the
				// next iface/route/NAT keypress sees it without restart.
				if nw := s.eng.Netops(); nw != nil {
					nw.AllowWrites = v != 0
				}
			}},
		{label: "Sentry DSN", isString: true, stringValue: th.SentryDSN,
			stringHint:  "blank disables; full DSN re-initialises on save",
			applyString: func(t *config.Thresholds, v string) { t.SentryDSN = v },
			afterApplyString: func(s *settingsTab, v string) {
				// Re-init Sentry. Empty DSN deactivates; non-empty rotates the client.
				_ = sentryx.Init(v, "testudo")
			}},
		{label: "Guacamole URL", isString: true, stringValue: th.GuacamoleURL,
			stringHint:  "base URL, e.g. https://guac.example.com",
			applyString: func(t *config.Thresholds, v string) { t.GuacamoleURL = v }},
		{label: "Guacamole conn ID", isString: true, stringValue: th.GuacamoleConnID,
			stringHint:  "Guacamole connection identifier",
			applyString: func(t *config.Thresholds, v string) { t.GuacamoleConnID = v }},
		{label: "Connect URL template", isString: true, stringValue: th.GuacamoleTemplate,
			stringHint:  "uses {host}/{proto}/{port}; blank = native ssh:// rdp:// vnc:// URI handlers",
			applyString: func(t *config.Thresholds, v string) { t.GuacamoleTemplate = v }},
		// --- IPFIX flow export ------------------------------------------
		{label: "IPFIX flow export", value: bool01(th.IPFIXEnabled), unit: "", isBool: true,
			apply: func(t *config.Thresholds, v float64) { t.IPFIXEnabled = v != 0 }},
		{label: "IPFIX collector endpoint", isString: true, stringValue: th.IPFIXEndpoint,
			stringHint:  "host:port (UDP); e.g. ipfix.opsanio-customer-domain.exanio.net",
			applyString: func(t *config.Thresholds, v string) { t.IPFIXEndpoint = v }},
		{label: "IPFIX export interval", value: float64(th.IPFIXIntervalSec), unit: "s", stepBig: 30, stepSmall: 5,
			apply: func(t *config.Thresholds, v float64) {
				if v < 1 {
					v = 1
				}
				t.IPFIXIntervalSec = int(v)
			}},
		{label: "IPFIX observation domain", value: float64(th.IPFIXDomainID), unit: "", stepBig: 10, stepSmall: 1,
			apply: func(t *config.Thresholds, v float64) {
				if v < 0 {
					v = 0
				}
				t.IPFIXDomainID = uint32(v)
			}},
		// --- Per-flow TCP telemetry -------------------------------------
		{label: "Per-flow RTX alert threshold", value: th.FlowRetransPct, unit: "%", stepBig: 1, stepSmall: 0.1,
			apply: func(t *config.Thresholds, v float64) {
				if v < 0 {
					v = 0
				}
				t.FlowRetransPct = v
			}},
		{label: "Enable eBPF telemetry backend", value: bool01(th.EBPFEnabled), unit: "", isBool: true,
			apply: func(t *config.Thresholds, v float64) { t.EBPFEnabled = v != 0 }},
		// --- Baseline maintenance ---------------------------------------
		{label: "Reset learned baselines", isAction: true, requireWrite: true,
			action: func(s *settingsTab) tea.Cmd { return s.resetBaselines() }},
	}
}

// resetBaselines clears the persisted (target, dow, hour) rollup for every
// real probe target - used when the network legitimately changed (new ISP,
// moved desk) so a stale baseline stops dragging the grade.
func (t *settingsTab) resetBaselines() tea.Cmd {
	targets := t.eng.Aggregator().SnapshotTargets()
	ctx := context.Background()
	n := 0
	for _, ts := range targets {
		if strings.Contains(ts.Target, ":") {
			continue // skip synthetic trace:/bufferbloat: targets
		}
		if err := t.eng.ResetBaseline(ctx, ts.Target); err == nil {
			n++
		}
	}
	count := n
	return func() tea.Msg {
		return statusMessageMsg(fmt.Sprintf("baseline reset for %d target(s)", count))
	}
}
func (t *settingsTab) Update(msg tea.Msg) tea.Cmd {
	m, ok := msg.(tea.KeyMsg)
	if !ok {
		return nil
	}
	rows := t.rows()
	mutate := func(newV float64) {
		r := rows[t.cursor]
		_ = t.eng.Settings().Update(func(th *config.Thresholds) { r.apply(th, newV) })
		if r.afterApply != nil {
			r.afterApply(t, newV)
		}
	}
	switch m.String() {
	case "up", "k":
		if t.cursor > 0 {
			t.cursor--
		}
	case "down", "j":
		if t.cursor < len(rows)-1 {
			t.cursor++
		}
	case "+", "=", "shift++":
		r := rows[t.cursor]
		if r.isString {
			return t.openStringEditor(r)
		}
		if r.isBool {
			mutate(1)
			return func() tea.Msg { return statusMessageMsg(r.label + ": ON") }
		}
		step := r.stepSmall
		if m.String() != "+" {
			step = r.stepBig
		}
		mutate(r.value + step)
	case "-", "_":
		r := rows[t.cursor]
		if r.isString {
			// Quick-clear path for string rows: -/_ wipes the value.
			_ = t.eng.Settings().Update(func(th *config.Thresholds) { r.applyString(th, "") })
			if r.afterApplyString != nil {
				r.afterApplyString(t, "")
			}
			return func() tea.Msg { return statusMessageMsg(r.label + ": cleared") }
		}
		if r.isBool {
			mutate(0)
			return func() tea.Msg { return statusMessageMsg(r.label + ": OFF") }
		}
		step := r.stepSmall
		if m.String() == "_" {
			step = r.stepBig
		}
		newV := r.value - step
		if newV < 0 {
			newV = 0
		}
		mutate(newV)
	case " ", "enter":
		r := rows[t.cursor]
		if r.isAction {
			if r.requireWrite && !t.eng.Settings().Snapshot().AllowNetopsWrite {
				return func() tea.Msg { return statusMessageMsg(r.label + ": enable \"Allow netops writes\" first") }
			}
			if r.action != nil {
				return r.action(t)
			}
			return nil
		}
		if r.isString {
			return t.openStringEditor(r)
		}
		if r.isBool {
			newV := 1.0
			label := "ON"
			if r.value != 0 {
				newV = 0
				label = "OFF"
			}
			mutate(newV)
			return func() tea.Msg { return statusMessageMsg(r.label + ": " + label) }
		}
	case "s":
		return func() tea.Msg { return statusMessageMsg("settings saved to disk") }
	}
	return nil
}

func (t *settingsTab) openStringEditor(r thresholdRow) tea.Cmd {
	row := r // captured by the closure; rebuilds happen on Snapshot()
	modal := NewFormModal("Edit "+r.label,
		[]FormField{
			{Label: "value", Value: r.stringValue, Hint: r.stringHint},
		},
		func(values map[string]string) error {
			v := strings.TrimSpace(values["value"])
			_ = t.eng.Settings().Update(func(th *config.Thresholds) { row.applyString(th, v) })
			if row.afterApplyString != nil {
				row.afterApplyString(t, v)
			}
			return nil
		},
	)
	return t.app.SetModal(modal)
}
func (t *settingsTab) View(w, h int) string {
	rows := []string{
		headerStyle.Render("Settings - ↑/↓ row · +/- adjust · enter/space edit · auto-saves"),
	}
	// innerW: inside boxStyle (border 2 + pad 2 = 4) without a row indent.
	innerW := w - 4
	widths := []int{28, 36, 8}
	rows = append(rows, renderTableRow(innerW, widths, "SETTING", "VALUE", "UNIT"))
	thRows := t.rows()
	for i, r := range thRows {
		var valStr string
		switch {
		case r.isAction:
			valStr = okStyle.Render("[run]")
		case r.isString:
			if r.stringValue == "" {
				valStr = dimStyle.Render("(unset)")
			} else {
				v := r.stringValue
				if len(v) > 33 {
					v = v[:30] + "…"
				}
				valStr = v
			}
		case r.isBool:
			if r.value != 0 {
				valStr = okStyle.Render("ON")
			} else {
				valStr = errStyle.Render("OFF")
			}
		default:
			valStr = fmt.Sprintf("%.2f", r.value)
		}
		row := renderTableRow(innerW, widths, r.label, valStr, r.unit)
		if i == t.cursor {
			rows = append(rows, selectedRowStyle.Render(row))
		} else {
			rows = append(rows, rowStyle.Render(row))
		}
	}
	rows = append(rows, "")
	rows = append(rows, dimStyle.Render("  Threshold changes take effect on the next analyzer cycle."))
	rows = append(rows, dimStyle.Render("  Netops toggle applies immediately to subsequent iface/route/NAT actions."))
	rows = append(rows, dimStyle.Render("  Sentry DSN re-initialises on save; blank disables."))
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// Used by ifacesTab to format active ifaces deterministically.
var _ = sort.Slice

// ---- Devices ----

type devicesTab struct {
	eng     *engine.Engine
	app     *App
	devices []discovery.Device
	cursor  int

	// showNeigh switches the pane from the discovery device list to the
	// full kernel neighbour (ARP/NDP) table; neighFamily filters it.
	showNeigh   bool
	neighFamily string // "" = all, "ipv4", "ipv6"
	neighCursor int
}

func newDevicesTab(eng *engine.Engine, app *App) *devicesTab {
	return &devicesTab{eng: eng, app: app}
}
func (t *devicesTab) Title() string    { return "Devices" }
func (t *devicesTab) ShortKey() string { return "3" }
func (t *devicesTab) Init() tea.Cmd    { return nil }
func (t *devicesTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select row"},
		{Key: "n", Desc: "toggle neighbour (ARP/NDP) table"},
		{Key: "f", Desc: "filter neighbour family (all / ipv4 / ipv6)"},
		{Key: "s", Desc: "scan selected device (SSH / RDP / VNC / Telnet / HTTP / HTTPS)"},
		{Key: "c", Desc: "show connect URLs for the selected device"},
		{Key: "g", Desc: "Guacamole SSH launch (legacy quick-key)"},
		{Key: "G", Desc: "Guacamole RDP launch (legacy quick-key)"},
	}
}
func (t *devicesTab) Update(msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case slowTickMsg:
		if inv := t.eng.Inventory(); inv != nil {
			t.devices = inv.Snapshot()
		}
	case tea.KeyMsg:
		switch m.String() {
		case "n":
			t.showNeigh = !t.showNeigh
			return nil
		case "f":
			if t.showNeigh {
				switch t.neighFamily {
				case "":
					t.neighFamily = "ipv4"
				case "ipv4":
					t.neighFamily = "ipv6"
				default:
					t.neighFamily = ""
				}
				t.neighCursor = 0
			}
			return nil
		case "up", "k":
			if t.showNeigh {
				if t.neighCursor > 0 {
					t.neighCursor--
				}
			} else if t.cursor > 0 {
				t.cursor--
			}
		case "down", "j":
			if t.showNeigh {
				if t.neighCursor < len(t.filteredNeighbours())-1 {
					t.neighCursor++
				}
			} else if t.cursor < len(t.devices)-1 {
				t.cursor++
			}
		case "s":
			return t.scanSelected()
		case "c":
			return t.openConnectModal()
		case "g":
			return t.openGuacamoleLaunch("ssh")
		case "G":
			return t.openGuacamoleLaunch("rdp")
		}
	}
	return nil
}

// filteredNeighbours returns the cached neighbour table filtered by the
// current family selection.
func (t *devicesTab) filteredNeighbours() []netops.Neighbour {
	nc := t.eng.Neigh()
	if nc == nil {
		return nil
	}
	all := nc.Neighbours()
	if t.neighFamily == "" {
		return all
	}
	out := make([]netops.Neighbour, 0, len(all))
	for _, n := range all {
		if n.Family == t.neighFamily {
			out = append(out, n)
		}
	}
	return out
}

// conflictIPs returns the set of IPs currently in a duplicate-IP conflict.
func (t *devicesTab) conflictIPs() map[string]bool {
	m := map[string]bool{}
	if nc := t.eng.Neigh(); nc != nil {
		for _, c := range nc.Conflicts() {
			m[c.IP] = true
		}
	}
	return m
}

// scanSelected runs an on-demand connection-port scan against the
// currently selected device and surfaces the result via the status bar.
// The inventory is updated in place; the next slow-tick refresh will
// re-render the row with the discovered ports.
func (t *devicesTab) scanSelected() tea.Cmd {
	if t.cursor < 0 || t.cursor >= len(t.devices) {
		return nil
	}
	ip := t.devices[t.cursor].IP
	go func() {
		// Reuse the engine's inventory so the result is visible in the
		// table on the next slow-tick redraw. The scan is bounded to 6s
		// internally by ScanHost's per-port timeout × concurrency.
		scanner := &discovery.Scanner{Inventory: t.eng.Inventory()}
		_ = scanner.ScanHost(context.Background(), ip)
	}()
	return statusCmd("scanning " + ip + " - refresh in ~5s")
}

// openConnectModal lists every connection option detected on the selected
// device and shows the resolved URL for each. The URL honours the
// configured Connect Template (Guacamole-style {host}/{proto}/{port}) and
// falls back to native ssh:// / rdp:// / vnc:// schemes when no template
// is set.
func (t *devicesTab) openConnectModal() tea.Cmd {
	if t.cursor < 0 || t.cursor >= len(t.devices) {
		return nil
	}
	d := t.devices[t.cursor]
	th := t.eng.Settings().Snapshot()
	protos := discovery.ProtocolsForPorts(d.OpenPorts)
	if len(protos) == 0 {
		return statusCmd("no connectable ports known - press 's' to scan " + d.IP)
	}
	fields := make([]FormField, 0, len(protos))
	for _, p := range protos {
		port := preferredPort(p, d.OpenPorts)
		url := buildTUIConnectURL(th.GuacamoleTemplate, d.IP, string(p), port)
		fields = append(fields, FormField{
			Label: strings.ToUpper(string(p)),
			Value: url,
			Hint:  "open this URL in your browser - Esc to close",
		})
	}
	modal := NewFormModal("Connect to "+d.IP, fields, nil)
	return t.app.SetModal(modal)
}

// preferredPort returns the canonical port that's actually open for a
// protocol on this device. When the device has no port in the protocol's
// well-known set we return "" and let the URL builder use its default.
func preferredPort(proto discovery.ConnectionProto, open []uint16) string {
	candidates := map[discovery.ConnectionProto][]uint16{
		discovery.ProtoSSH:    {22},
		discovery.ProtoTelnet: {23},
		discovery.ProtoRDP:    {3389, 3390},
		discovery.ProtoVNC:    {5900, 5901, 5800},
		discovery.ProtoHTTP:   {80, 8080, 8081},
		discovery.ProtoHTTPS:  {443, 8443},
	}[proto]
	openSet := map[uint16]bool{}
	for _, p := range open {
		openSet[p] = true
	}
	for _, c := range candidates {
		if openSet[c] {
			return fmt.Sprintf("%d", c)
		}
	}
	return ""
}

// buildTUIConnectURL mirrors the logic in internal/web/connect.go so the
// TUI shows the exact same URL the web "Connect" button would launch.
func buildTUIConnectURL(template, host, proto, port string) string {
	if t := strings.TrimSpace(template); t != "" {
		out := strings.ReplaceAll(t, "{host}", host)
		out = strings.ReplaceAll(out, "{proto}", proto)
		out = strings.ReplaceAll(out, "{port}", port)
		return out
	}
	defaults := map[string]string{
		"http":   "80",
		"https":  "443",
		"ssh":    "22",
		"rdp":    "3389",
		"vnc":    "5900",
		"telnet": "23",
	}
	if port == "" {
		port = defaults[proto]
	}
	switch proto {
	case "http", "https":
		if port == defaults[proto] {
			return proto + "://" + host + "/"
		}
		return fmt.Sprintf("%s://%s:%s/", proto, host, port)
	case "ssh", "rdp", "vnc", "telnet":
		if port == defaults[proto] {
			return proto + "://" + host
		}
		return fmt.Sprintf("%s://%s:%s", proto, host, port)
	}
	return ""
}

// openGuacamoleLaunch builds a deep-link URL into the operator's Guacamole
// instance for the selected device and surfaces it via a modal so the
// operator can copy/click it. Configuration lives in the Settings tab.
func (t *devicesTab) openGuacamoleLaunch(proto string) tea.Cmd {
	if t.cursor < 0 || t.cursor >= len(t.devices) {
		return nil
	}
	d := t.devices[t.cursor]
	th := t.eng.Settings().Snapshot()
	if th.GuacamoleURL == "" {
		return func() tea.Msg {
			return statusMessageMsg("Guacamole URL not configured - set it in Settings")
		}
	}
	spec := guacamole.LaunchSpec{Protocol: proto, Host: d.IP}
	url, err := guacamole.BuildURL(th.GuacamoleURL, th.GuacamoleConnID, spec)
	if err != nil {
		return func() tea.Msg { return statusMessageMsg("guacamole: " + err.Error()) }
	}
	modal := NewFormModal(fmt.Sprintf("Guacamole %s launch - %s", strings.ToUpper(proto), d.IP),
		[]FormField{
			{Label: "url", Value: url, Hint: "open in browser (read-only); Esc to close"},
		},
		nil,
	)
	return t.app.SetModal(modal)
}

func (t *devicesTab) View(w, h int) string {
	if t.showNeigh {
		return t.renderNeighView(w, h)
	}
	conflicts := t.conflictIPs()
	neighByIP := map[string]netops.Neighbour{}
	if nc := t.eng.Neigh(); nc != nil {
		for _, n := range nc.Neighbours() {
			if _, seen := neighByIP[n.IP]; !seen {
				neighByIP[n.IP] = n
			}
		}
	}
	rows := []string{headerStyle.Render(fmt.Sprintf(
		"Devices - %d on local network · n=neighbours · s=scan · c=connect · g/G=guac legacy",
		len(t.devices)))}
	if len(conflicts) > 0 {
		rows = append(rows, errStyle.Render(fmt.Sprintf("  ⚠ %d duplicate-IP conflict(s) on the LAN - press 'n' for the neighbour table", len(conflicts))))
	}
	if len(t.devices) == 0 {
		rows = append(rows, subtitleStyle.Render("  no devices yet - enable active discovery (--discover-active) or press 's' on a known IP"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	// innerW: inside boxStyle (border 2 + pad 2 = 4) without a row indent.
	innerW := w - 4
	widths := []int{16, 9, 18, 10, 16, 18, 14, 8}
	rows = append(rows, renderTableRow(innerW, widths,
		"IP", "SCOPE", "HOSTNAME", "TYPE", "VENDOR", "PROTOCOLS", "BW (10m TX)", "LAST"))
	bw := t.eng.DeviceBandwidth()
	for i, d := range t.devices {
		age := time.Since(d.LastSeen).Truncate(time.Second)
		protos := discovery.ProtocolsForPorts(d.OpenPorts)
		protoStrs := make([]string, len(protos))
		for j, p := range protos {
			protoStrs[j] = strings.ToUpper(string(p))
		}
		protoCell := strings.Join(protoStrs, " ")
		if protoCell == "" {
			protoCell = dimStyle.Render("press 's' to scan")
		} else {
			protoCell = okStyle.Render(protoCell)
		}
		bwCell := dimStyle.Render("-")
		if bw != nil {
			s := bw.Snapshot(d.IP)
			if s.TotalTX > 0 || s.TotalRX > 0 {
				vals := make([]float64, len(s.TX))
				for k, v := range s.TX {
					vals[k] = float64(v)
				}
				bwCell = sparkline(vals, 12)
			}
		}
		ipCell := d.IP
		if conflicts[d.IP] {
			ipCell = d.IP + " ⚠DUP"
		}
		row := renderTableRow(innerW, widths,
			ipCell, scopeTag(d.IP), dashIfEmpty(d.Hostname), dashIfEmpty(d.DeviceType),
			dashIfEmpty(d.Vendor), protoCell, bwCell,
			fmt.Sprintf("%s ago", age))
		switch {
		case i == t.cursor:
			rows = append(rows, selectedRowStyle.Render(row))
		case conflicts[d.IP]:
			rows = append(rows, errStyle.Render(row))
		default:
			rows = append(rows, rowStyle.Render(row))
		}
	}
	// Detail pane for the selected device - surfaces LLDP/SNMP fields
	// that don't fit in a row. Empty fields are omitted so the pane
	// stays compact when there's nothing to show.
	if t.cursor >= 0 && t.cursor < len(t.devices) {
		rows = append(rows, "")
		rows = append(rows, renderDeviceDetail(t.devices[t.cursor]))
		if n, ok := neighByIP[t.devices[t.cursor].IP]; ok {
			line := fmt.Sprintf("  %-14s %s / %s (%s)", "Neighbour:", n.MAC, n.State, n.Family)
			if conflicts[n.IP] {
				line = errStyle.Render(line + "  ⚠ duplicate IP")
			}
			rows = append(rows, line)
		}
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// renderNeighView lists the full kernel neighbour table (ARP/NDP) with
// resolution state, filterable by family. Duplicate-IP rows are highlighted
// red. Reached via 'n' from the Devices tab; 'f' cycles the family filter.
func (t *devicesTab) renderNeighView(w, h int) string {
	conflicts := t.conflictIPs()
	ns := t.filteredNeighbours()
	fam := t.neighFamily
	if fam == "" {
		fam = "all"
	}
	rows := []string{headerStyle.Render(fmt.Sprintf(
		"Neighbours (ARP/NDP) - %d entries · family=%s · n=back to devices · f=cycle family",
		len(ns), fam))}
	if nc := t.eng.Neigh(); nc == nil {
		rows = append(rows, subtitleStyle.Render("  neighbour collector disabled"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	if len(ns) == 0 {
		rows = append(rows, subtitleStyle.Render("  no neighbours - needs CAP_NET_ADMIN, or none learned yet"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	innerW := w - 4
	widths := []int{24, 20, 10, 8, 14}
	rows = append(rows, renderTableRow(innerW, widths, "IP", "MAC", "DEV", "FAMILY", "STATE"))
	if t.neighCursor >= len(ns) {
		t.neighCursor = len(ns) - 1
	}
	for i, n := range ns {
		ipCell := n.IP
		if n.Router {
			ipCell += " (router)"
		}
		if conflicts[n.IP] {
			ipCell += " ⚠DUP"
		}
		row := renderTableRow(innerW, widths,
			ipCell, dashIfEmpty(n.MAC), dashIfEmpty(n.Dev), n.Family, n.State)
		switch {
		case i == t.neighCursor:
			rows = append(rows, selectedRowStyle.Render(row))
		case conflicts[n.IP] || n.State == "FAILED" || n.State == "INCOMPLETE":
			rows = append(rows, errStyle.Render(row))
		default:
			rows = append(rows, rowStyle.Render(row))
		}
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// renderDeviceDetail produces the per-device detail pane shown below the
// devices list. Surfaces SNMP sys-* fields and LLDP neighbour info when
// the device has been positively identified by either protocol.
func renderDeviceDetail(d discovery.Device) string {
	lines := []string{subtitleStyle.Render("─── selected: " + d.IP + " ───")}
	add := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		lines = append(lines, fmt.Sprintf("  %-14s %s", label+":", value))
	}
	add("MAC", d.MAC)
	add("Source", d.Source)
	add("Hostname", d.Hostname)
	add("Vendor", d.Vendor)
	add("Device type", d.DeviceType)
	add("SNMP sysName", d.SysName)
	add("SNMP sysDescr", d.SysDescr)
	add("SNMP location", d.SysLocation)
	add("SNMP contact", d.SysContact)
	add("SNMP uptime", d.SysUptime)
	add("SNMP objectID", d.SysObjectID)
	if d.IfCount > 0 {
		add("SNMP ifCount", fmt.Sprintf("%d", d.IfCount))
	}
	add("LLDP chassis", d.LLDPChassisID)
	add("LLDP port", d.LLDPPortID)
	add("LLDP port-desc", d.LLDPPortDesc)
	if len(d.LLDPMgmtAddrs) > 0 {
		add("LLDP mgmt", strings.Join(d.LLDPMgmtAddrs, ", "))
	}
	if len(d.LLDPCapabilities) > 0 {
		add("LLDP caps", strings.Join(d.LLDPCapabilities, ", "))
	}
	add("LLDP local-if", d.LLDPLocalIface)
	if len(d.OpenPorts) > 0 {
		parts := make([]string, len(d.OpenPorts))
		for i, p := range d.OpenPorts {
			parts[i] = fmt.Sprintf("%d", p)
		}
		add("Open ports", strings.Join(parts, ", "))
	}
	if len(lines) == 1 {
		lines = append(lines, dimStyle.Render("  no extended info - press 's' to scan, or enable LLDP/SNMP"))
	}
	return strings.Join(lines, "\n")
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---- Probes ----

type probesTab struct {
	eng     *engine.Engine
	cursor  int
	target  string
	port    string
	results []probeResult
	running bool
}

type probeResult struct {
	ts      time.Time
	kind    string
	target  string
	ok      bool
	latency time.Duration
	detail  string
}

func newProbesTab(eng *engine.Engine) *probesTab {
	return &probesTab{eng: eng, target: "1.1.1.1", port: "443"}
}
func (t *probesTab) Title() string    { return "Probes" }
func (t *probesTab) ShortKey() string { return "9" }
func (t *probesTab) Init() tea.Cmd    { return nil }
func (t *probesTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "k", Desc: "cycle probe kind (icmp / tcp / udp / dns / throughput / traceroute)"},
		{Key: "t", Desc: "edit target host or IP"},
		{Key: "p", Desc: "edit port"},
		{Key: "enter", Desc: "run probe"},
		{Key: "↑/↓", Desc: "scroll past results"},
		{Key: "g / G", Desc: "jump to top / bottom of results"},
	}
}

var probeKinds = []string{"icmp", "tcp", "udp", "dns", "throughput", "traceroute"}

func (t *probesTab) Update(msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case probeFinishedMsg:
		t.running = false
		t.results = append([]probeResult{m.result}, t.results...)
		if len(t.results) > 12 {
			t.results = t.results[:12]
		}
	case tea.KeyMsg:
		s := m.String()
		switch s {
		case "up", "k":
			if t.cursor > 0 {
				t.cursor--
			}
		case "down", "j":
			if t.cursor < len(probeKinds)-1 {
				t.cursor++
			}
		case "t":
			return func() tea.Msg {
				// inline mini-modal: open a form to edit target+port
				return openProbeTargetModalMsg{}
			}
		case "enter":
			if t.running {
				return nil
			}
			t.running = true
			kind := probeKinds[t.cursor]
			return runProbeCmd(kind, t.target, t.port)
		}
	}
	return nil
}

func (t *probesTab) View(w, h int) string {
	// innerW: inside boxStyle (border 2 + pad 2 = 4) without a row indent.
	innerW := w - 4
	var rows []string
	rows = append(rows, headerStyle.Render("Probes - ↑/↓ select · enter run · t edit target"))
	rows = append(rows, dimStyle.Render(fmt.Sprintf("  target: %s   port: %s", t.target, t.port)))
	rows = append(rows, "")
	for i, k := range probeKinds {
		line := fmt.Sprintf("  %-12s", k)
		if i == t.cursor {
			rows = append(rows, selectedRowStyle.Render(line))
		} else {
			rows = append(rows, rowStyle.Render(line))
		}
	}
	rows = append(rows, "")
	if t.running {
		rows = append(rows, warnStyle.Render("  running…"))
	}
	rows = append(rows, headerStyle.Render("Recent results"))
	if len(t.results) == 0 {
		rows = append(rows, subtitleStyle.Render("  no results yet"))
	} else {
		widths := []int{10, 12, 22, 8, 12, 40}
		rows = append(rows, renderTableRow(innerW, widths, "TIME", "KIND", "TARGET", "OK", "LATENCY", "DETAIL"))
		for _, r := range t.results {
			ok := okStyle.Render("yes")
			if !r.ok {
				ok = errStyle.Render("no")
			}
			rows = append(rows, renderTableRow(innerW, widths,
				r.ts.Format("15:04:05"), r.kind, r.target, ok,
				r.latency.Truncate(time.Microsecond).String(), r.detail))
		}
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

type probeFinishedMsg struct{ result probeResult }
type openProbeTargetModalMsg struct{}

func runProbeCmd(kind, target, port string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		req := probes.Request{Kind: probes.Kind(kind), Target: target, Timeout: 4 * time.Second}
		if port != "" {
			if p, err := parseUint16(port); err == nil {
				req.Port = p
			}
		}
		res, err := probes.Run(ctx, req)
		out := probeResult{ts: time.Now(), kind: kind, target: target}
		if err != nil {
			out.detail = err.Error()
			return probeFinishedMsg{result: out}
		}
		out.ok = res.OK
		out.latency = res.Latency
		out.detail = res.Detail
		if !out.ok && out.detail == "" && res.Err != "" {
			out.detail = res.Err
		}
		return probeFinishedMsg{result: out}
	}
}
