package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/netops"
)

// healthTab is the operational view for the new probe collectors. Every
// section reads from a different data source - ProbeState for the
// latency-bearing probes (top-talkers, internal-dns, http, traceroute,
// bufferbloat, wifi), the App's anomaly buffer for TLS expiry (which
// only emits anomalies), and netops.ListIfaces for live interface
// counters. Updates on slowTickMsg so the tab is light on CPU.
type healthTab struct {
	eng    *engine.Engine
	app    *App
	ifaces []netops.IfaceInfo
	wifi   []collectors.WiFiSnapshot
}

func newHealthTab(eng *engine.Engine, app *App) *healthTab {
	return &healthTab{eng: eng, app: app}
}

func (t *healthTab) Title() string    { return "Health" }
func (t *healthTab) ShortKey() string { return "" }
func (t *healthTab) Init() tea.Cmd    { return nil }
func (t *healthTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "PgUp/PgDn", Desc: "scroll between sections"},
	}
}

func (t *healthTab) Update(msg tea.Msg) tea.Cmd {
	switch msg.(type) {
	case slowTickMsg, tickMsg:
		if nw := t.eng.Netops(); nw != nil {
			t.ifaces, _ = nw.ListIfaces()
		}
		if wc := t.eng.WiFi(); wc != nil {
			t.wifi = wc.Snapshot()
		}
	}
	return nil
}

func (t *healthTab) View(w, h int) string {
	state := t.app.probes
	if state == nil {
		return boxStyle.Render(subtitleStyle.Render(" probe state not initialised "))
	}

	// innerW: View() wraps with boxStyle (border 2 + pad 2 = 4) and each
	// section row is prefixed with "  " (a 2-char indent), so the actual
	// table width is w - 6.
	innerW := w - 6

	var b strings.Builder
	b.WriteString(headerStyle.Render("Health · live results from probe collectors"))
	b.WriteString("\n\n")

	renderProbeSection(&b, innerW, "Top Talkers · ICMP+TCP to busiest LAN hosts",
		state.BySource("top-talkers"),
		"no data yet · start flow capture (Flows tab → 's') so LAN talkers can be ranked")
	b.WriteString("\n")
	renderDNSSection(&b, innerW, "Internal DNS · per-resolver",
		state.BySource("internal-dns"))
	b.WriteString("\n")
	renderProbeSection(&b, innerW, "HTTP Endpoints · TTFB", state.BySource("http"),
		"no data yet · add URLs via HTTPEndpoints in config (e.g. https://internal.api/healthz)")
	b.WriteString("\n")
	renderTLSSection(&b, t.app.anomalies)
	b.WriteString("\n")
	renderTracerouteSection(&b, innerW, state.BySource("traceroute"))
	b.WriteString("\n")
	renderBufferbloatSection(&b, innerW, state.BySource("bufferbloat"))
	b.WriteString("\n")
	renderWiFiSection(&b, innerW, t.wifi)
	b.WriteString("\n")
	renderIfaceSection(&b, innerW, t.ifaces, t.wifi)

	return boxStyle.Render(b.String())
}

// renderProbeSection draws a generic table of (target, status, RTT, age)
// rows. emptyHint is shown when there are no rows - use it to point the
// operator at the config knob that would populate this section.
func renderProbeSection(b *strings.Builder, innerW int, title string, rows []ProbeResult, emptyHint string) {
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n")
	if len(rows) == 0 {
		if emptyHint == "" {
			emptyHint = "no data yet"
		}
		b.WriteString(subtitleStyle.Render("  " + emptyHint))
		b.WriteString("\n")
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Target < rows[j].Target })
	widths := []int{38, 8, 10, 10}
	b.WriteString("  " + dimStyle.Render(renderTableRow(innerW, widths,
		"TARGET", "STATUS", "RTT", "AGE")))
	b.WriteString("\n")
	for _, r := range rows {
		status := okStyle.Render("OK")
		if !r.OK {
			status = errStyle.Render("DOWN")
		}
		b.WriteString("  " + renderTableRow(innerW, widths,
			truncTarget(r.Target, 36),
			status,
			rttCell(r),
			fmtAgo(r.Time)))
		b.WriteString("\n")
	}
}

// renderDNSSection draws (server, name, RTT, age) per resolver. The
// per-server dimension is the whole point of the internal-DNS probe -
// the same name slow on one resolver but fast on another is the
// signal we'd otherwise lose.
func renderDNSSection(b *strings.Builder, innerW int, title string, rows []ProbeResult) {
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n")
	if len(rows) == 0 {
		b.WriteString(subtitleStyle.Render("  no data yet · no LAN resolver found in /etc/resolv.conf or /run/systemd/resolve/resolv.conf · set DNSInternalServers to override"))
		b.WriteString("\n")
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Server != rows[j].Server {
			return rows[i].Server < rows[j].Server
		}
		return rows[i].Target < rows[j].Target
	})
	widths := []int{18, 26, 8, 10, 10}
	b.WriteString("  " + dimStyle.Render(renderTableRow(innerW, widths,
		"RESOLVER", "NAME", "STATUS", "LATENCY", "AGE")))
	b.WriteString("\n")
	for _, r := range rows {
		status := okStyle.Render("OK")
		if !r.OK {
			status = errStyle.Render("FAIL")
		}
		b.WriteString("  " + renderTableRow(innerW, widths,
			r.Server, truncTarget(r.Target, 24), status,
			rttCell(r), fmtAgo(r.Time)))
		b.WriteString("\n")
	}
}

// renderTLSSection filters the app's recent-anomalies buffer to the
// tls-cert collector. The collector only emits anomalies (no latency),
// so this is the only place to surface its data. Latest entry per
// target wins.
func renderTLSSection(b *strings.Builder, anomalies []anomalyMsg) {
	b.WriteString(titleStyle.Render("TLS Certificates · expiry watch"))
	b.WriteString("\n")
	latest := map[string]anomalyMsg{}
	for _, a := range anomalies {
		if a.source != "tls-cert" {
			continue
		}
		// Use the message itself as the dedup key. The TLS collector
		// emits one message per (target, severity) tick; that's
		// granular enough for display.
		latest[a.text] = a
	}
	if len(latest) == 0 {
		b.WriteString(subtitleStyle.Render("  no cert warnings · either nothing configured, or all certs healthy"))
		b.WriteString("\n")
		return
	}
	ordered := make([]anomalyMsg, 0, len(latest))
	for _, v := range latest {
		ordered = append(ordered, v)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ts.After(ordered[j].ts) })
	for _, a := range ordered {
		b.WriteString("  ")
		b.WriteString(severityStyle(a.severity).Render(fmt.Sprintf("[%s]", a.severity)))
		b.WriteString(" " + a.text + " " + dimStyle.Render("("+fmtAgo(a.ts)+")"))
		b.WriteString("\n")
	}
}

func renderTracerouteSection(b *strings.Builder, innerW int, rows []ProbeResult) {
	b.WriteString(titleStyle.Render("Traceroute · end-to-end RTT per target"))
	b.WriteString("\n")
	// Only show end-to-end "trace:<dest>" rows; per-hop rows are kept
	// in the cache but would explode the table.
	var endToEnd []ProbeResult
	for _, r := range rows {
		if strings.HasPrefix(r.Target, "trace:") && !strings.Contains(r.Target[6:], ":hop") {
			endToEnd = append(endToEnd, r)
		}
	}
	if len(endToEnd) == 0 {
		b.WriteString(subtitleStyle.Render("  no data yet · enable with TracerouteEnabled=true"))
		b.WriteString("\n")
		return
	}
	sort.Slice(endToEnd, func(i, j int) bool { return endToEnd[i].Target < endToEnd[j].Target })
	widths := []int{30, 10, 10}
	b.WriteString("  " + dimStyle.Render(renderTableRow(innerW, widths, "DEST", "RTT", "AGE")))
	b.WriteString("\n")
	for _, r := range endToEnd {
		dest := strings.TrimPrefix(r.Target, "trace:")
		b.WriteString("  " + renderTableRow(innerW, widths, dest, rttCell(r), fmtAgo(r.Time)))
		b.WriteString("\n")
	}
}

// renderBufferbloatSection pairs the idle/loaded entries the collector
// emits per target into one row showing the delta.
func renderBufferbloatSection(b *strings.Builder, innerW int, rows []ProbeResult) {
	b.WriteString(titleStyle.Render("Bufferbloat · idle vs loaded RTT"))
	b.WriteString("\n")
	type pair struct {
		idle, loaded ProbeResult
	}
	byTarget := map[string]*pair{}
	for _, r := range rows {
		switch {
		case strings.HasPrefix(r.Target, "bufferbloat:idle:"):
			target := strings.TrimPrefix(r.Target, "bufferbloat:idle:")
			p := byTarget[target]
			if p == nil {
				p = &pair{}
				byTarget[target] = p
			}
			p.idle = r
		case strings.HasPrefix(r.Target, "bufferbloat:loaded:"):
			target := strings.TrimPrefix(r.Target, "bufferbloat:loaded:")
			p := byTarget[target]
			if p == nil {
				p = &pair{}
				byTarget[target] = p
			}
			p.loaded = r
		}
	}
	if len(byTarget) == 0 {
		b.WriteString(subtitleStyle.Render("  no data yet · enable with BufferbloatEnabled=true (heavy probe)"))
		b.WriteString("\n")
		return
	}
	targets := make([]string, 0, len(byTarget))
	for t := range byTarget {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	widths := []int{20, 10, 10, 10, 10}
	b.WriteString("  " + dimStyle.Render(renderTableRow(innerW, widths,
		"TARGET", "IDLE", "LOADED", "DELTA", "AGE")))
	b.WriteString("\n")
	for _, t := range targets {
		p := byTarget[t]
		delta := p.loaded.RTT - p.idle.RTT
		deltaStr := fmtRTT(delta)
		switch {
		case delta >= 300*time.Millisecond:
			deltaStr = errStyle.Render(deltaStr)
		case delta >= 100*time.Millisecond:
			deltaStr = warnStyle.Render(deltaStr)
		case delta >= 30*time.Millisecond:
			deltaStr = okStyle.Render(deltaStr)
		default:
			deltaStr = dimStyle.Render(deltaStr)
		}
		b.WriteString("  " + renderTableRow(innerW, widths,
			t, fmtRTT(p.idle.RTT), fmtRTT(p.loaded.RTT), deltaStr,
			fmtAgo(latestOf(p.idle.Time, p.loaded.Time))))
		b.WriteString("\n")
	}
}

// renderWiFiSection draws a dedicated block per associated wireless
// interface: SSID, BSSID, channel/freq/band, signal+noise, TX/RX
// bitrate, TX power, connected time. Unassociated wireless interfaces
// are listed underneath so the operator can see the radio exists
// without inferring its presence from the iface section below.
//
// Source attribution ("iw" vs "proc") is rendered next to the title so
// the operator knows whether to install the `iw` package for richer
// data when only legacy fields are populated.
func renderWiFiSection(b *strings.Builder, innerW int, snaps []collectors.WiFiSnapshot) {
	b.WriteString(titleStyle.Render("WiFi · associated radios"))
	b.WriteString("\n")
	if len(snaps) == 0 {
		b.WriteString(subtitleStyle.Render("  no wireless interfaces found in /sys/class/net (no NICs registered as wifi)"))
		b.WriteString("\n")
		return
	}
	// Split associated vs unassociated so the operator's eye lands on
	// the active radio first.
	associated := snaps[:0:0]
	idle := snaps[:0:0]
	anyData := false
	for _, s := range snaps {
		if s.Source != "" && s.Source != "none" {
			anyData = true
		}
		if s.Associated {
			associated = append(associated, s)
		} else {
			idle = append(idle, s)
		}
	}
	if !anyData {
		b.WriteString(subtitleStyle.Render("  no wifi backend reachable — nl80211 needs CAP_NET_ADMIN; run testudo with sudo or grant the binary `setcap cap_net_admin+ep`"))
		b.WriteString("\n")
	}

	for _, s := range associated {
		renderWiFiCard(b, innerW, s)
		b.WriteString("\n")
	}
	if len(associated) == 0 {
		b.WriteString(subtitleStyle.Render("  no associated radios · all wireless NICs are unassociated"))
		b.WriteString("\n")
	}

	if len(idle) > 0 {
		b.WriteString("  " + dimStyle.Render("unassociated radios: "))
		names := make([]string, 0, len(idle))
		for _, s := range idle {
			names = append(names, s.Iface)
		}
		b.WriteString(warnStyle.Render(strings.Join(names, ", ")))
		b.WriteString("\n")
	}
}

// renderWiFiCard draws a single associated radio's rich state. Width
// is split into a label column + value column with widths derived from
// innerW so the layout adapts to narrow / wide TUIs.
func renderWiFiCard(b *strings.Builder, innerW int, s collectors.WiFiSnapshot) {
	header := fmt.Sprintf("  %s · %s",
		titleStyle.Render(s.Iface),
		dimStyle.Render(s.HWAddr))
	if s.Source != "" {
		header += " " + dimStyle.Render("("+s.Source+")")
	}
	b.WriteString(header + "\n")

	widths := []int{12, innerW - 14}
	row := func(k, v string) {
		b.WriteString("  " + renderTableRow(innerW, widths,
			dimStyle.Render(k), v) + "\n")
	}

	ssid := s.SSID
	if ssid == "" {
		ssid = dimStyle.Render("(unknown)")
	}
	row("SSID", ssid)
	bss := s.BSSID
	if bss == "" {
		bss = dimStyle.Render("-")
	}
	row("BSSID", bss)
	if s.Frequency > 0 {
		band := s.Band
		ch := fmt.Sprintf("%d", s.Channel)
		if s.ChannelWMHz > 0 {
			ch = fmt.Sprintf("%d (%d MHz wide)", s.Channel, s.ChannelWMHz)
		}
		row("Channel", fmt.Sprintf("%s · %d MHz · %s", ch, s.Frequency, band))
	} else {
		row("Channel", dimStyle.Render("-"))
	}
	row("Signal", wifiSignalCell(s.Signal, s.SignalAvg, s.Noise))
	if s.TXBitrateM > 0 || s.RXBitrateM > 0 {
		row("Bitrate", fmt.Sprintf("tx %.1f Mbit/s · rx %.1f Mbit/s",
			s.TXBitrateM, s.RXBitrateM))
	} else {
		row("Bitrate", dimStyle.Render("-"))
	}
	if s.TXPower > 0 {
		row("TX power", fmt.Sprintf("%.1f dBm", s.TXPower))
	}
	if s.LinkQuality > 0 {
		row("Quality", wifiQualityCell(s.LinkQuality, s.LinkMax))
	}
	counters := fmt.Sprintf("retries %d · tx-failed %d · beacon-loss %d",
		s.Retries, s.TxFailed, s.BeaconLoss)
	if s.TxFailed > 0 || s.BeaconLoss > 0 {
		counters = warnStyle.Render(counters)
	}
	row("Errors", counters)
	if s.RxBytes+s.TxBytes > 0 {
		row("Station", fmt.Sprintf("rx %s (%d pkts) · tx %s (%d pkts)",
			fmtBytes(s.RxBytes), s.RxPackets,
			fmtBytes(s.TxBytes), s.TxPackets))
	}
	if !s.ConnectedAt.IsZero() {
		row("Up since", fmt.Sprintf("%s ago",
			time.Since(s.ConnectedAt).Truncate(time.Second)))
	}
}

// wifiSignalCell formats the headline signal level with the optional
// averaged level and noise floor when the driver provides them. Colour
// gradient mirrors the rules already in renderIfaceSection.
func wifiSignalCell(signal, avg, noise float64) string {
	if signal == 0 {
		return warnStyle.Render("unassociated")
	}
	cell := fmt.Sprintf("%.0f dBm", signal)
	switch {
	case signal < -85:
		cell = errStyle.Render(cell)
	case signal < -75:
		cell = warnStyle.Render(cell)
	default:
		cell = okStyle.Render(cell)
	}
	extras := []string{}
	if avg != 0 && avg != signal {
		extras = append(extras, fmt.Sprintf("avg %.0f", avg))
	}
	if noise != 0 {
		extras = append(extras, fmt.Sprintf("noise %.0f dBm · SNR %.0f dB",
			noise, signal-noise))
	}
	if len(extras) > 0 {
		cell += " " + dimStyle.Render("· "+strings.Join(extras, " · "))
	}
	return cell
}

// wifiQualityCell renders the driver's link-quality score as a
// percentage of its max so different chipsets (Intel: /70, Atheros:
// /100) all read consistently.
func wifiQualityCell(quality float64, max int) string {
	if max == 0 {
		max = 70
	}
	pct := quality / float64(max) * 100
	cell := fmt.Sprintf("%.0f/%d (%.0f%%)", quality, max, pct)
	switch {
	case pct >= 70:
		return okStyle.Render(cell)
	case pct >= 40:
		return warnStyle.Render(cell)
	default:
		return errStyle.Render(cell)
	}
}

// renderIfaceSection draws one row per kernel interface with link
// state, MTU, MAC, primary address, error / drop counters, and a
// short wifi summary so the operator can spot wireless interfaces at
// a glance. Lo is skipped; everything else is shown so the user can
// confirm "every interface is monitored" - which they explicitly
// asked for in the last operator brief.
func renderIfaceSection(b *strings.Builder, innerW int, ifs []netops.IfaceInfo, wifi []collectors.WiFiSnapshot) {
	b.WriteString(titleStyle.Render("Interfaces · live kernel state"))
	b.WriteString("\n")
	if len(ifs) == 0 {
		b.WriteString(subtitleStyle.Render("  no interfaces visible"))
		b.WriteString("\n")
		return
	}
	wifiByIface := map[string]collectors.WiFiSnapshot{}
	for _, w := range wifi {
		wifiByIface[w.Iface] = w
	}
	widths := []int{12, 5, 7, 18, 18, 7, 7, 7, 12}
	b.WriteString("  " + dimStyle.Render(renderTableRow(innerW, widths,
		"NAME", "UP", "MTU", "MAC", "ADDR", "RX ERR", "TX ERR", "DROPS", "WIFI")))
	b.WriteString("\n")
	sort.Slice(ifs, func(i, j int) bool { return ifs[i].Name < ifs[j].Name })
	for _, ifi := range ifs {
		if ifi.Name == "lo" {
			continue
		}
		upCell := okStyle.Render("yes")
		if !ifi.Up || !ifi.Running {
			upCell = errStyle.Render("NO")
		}
		errCell := fmt.Sprintf("%d", ifi.RxErrors)
		if ifi.RxErrors > 0 {
			errCell = warnStyle.Render(errCell)
		}
		txErrCell := fmt.Sprintf("%d", ifi.TxErrors)
		if ifi.TxErrors > 0 {
			txErrCell = warnStyle.Render(txErrCell)
		}
		dropCell := fmt.Sprintf("%d", ifi.RxDropped+ifi.TxDropped)
		if ifi.RxDropped+ifi.TxDropped > 0 {
			dropCell = warnStyle.Render(dropCell)
		}
		addrCell := "-"
		if len(ifi.Addrs) > 0 {
			addrCell = ifi.Addrs[0]
		}
		hw := ifi.HWAddr
		if hw == "" {
			hw = dimStyle.Render("-")
		}
		wifiCell := dimStyle.Render("-")
		if w, ok := wifiByIface[ifi.Name]; ok {
			switch {
			case !w.Associated:
				wifiCell = warnStyle.Render("unassoc")
			case w.Signal == 0:
				wifiCell = dimStyle.Render("assoc")
			default:
				cell := fmt.Sprintf("%.0fdBm", w.Signal)
				switch {
				case w.Signal < -85:
					cell = errStyle.Render(cell)
				case w.Signal < -75:
					cell = warnStyle.Render(cell)
				default:
					cell = okStyle.Render(cell)
				}
				wifiCell = cell
			}
		}
		b.WriteString("  " + renderTableRow(innerW, widths,
			ifi.Name, upCell, fmt.Sprintf("%d", ifi.MTU),
			truncTarget(hw, 17), truncTarget(addrCell, 17),
			errCell, txErrCell, dropCell, wifiCell))
		b.WriteString("\n")
	}
}

// rttCell formats a ProbeResult's RTT, dimming when the probe failed
// (there's no useful RTT for a timeout, but we still render the column
// so rows line up).
func rttCell(r ProbeResult) string {
	if !r.OK {
		return dimStyle.Render("-")
	}
	return fmtRTT(r.RTT)
}

func truncTarget(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// fmtAgo renders the age of an event as a short human string. The
// existing fmtDuration helper would format `1s` as `1s` but `0s` as
// `0ms`, which reads oddly for a freshness column - so we floor to
// seconds and never go below 1s.
func fmtAgo(ts time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	d := time.Since(ts).Truncate(time.Second)
	if d < time.Second {
		d = time.Second
	}
	return d.String() + " ago"
}

func latestOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
