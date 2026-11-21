package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/wireguard"
)

// wireguardTab renders live WireGuard devices and peers - handshake age,
// RX/TX, and a throughput sparkline - and drives the "Add Peer" wizard and
// per-peer deprovision. It mirrors the Web UI's WireGuard section from the same
// collector + netops backend. WireGuard's truth is that a tunnel can be UP with
// a dead peer, so the handshake column is severity-coloured.
type wireguardTab struct {
	eng    *engine.Engine
	app    *App
	snap   wireguard.Snapshot
	avail  bool
	err    error
	cursor int
}

func newWireGuardTab(eng *engine.Engine, app *App) *wireguardTab {
	return &wireguardTab{eng: eng, app: app}
}

func (t *wireguardTab) Title() string    { return "WireGuard" }
func (t *wireguardTab) ShortKey() string { return "" } // reached via :wg / tab cycle
func (t *wireguardTab) Init() tea.Cmd    { return nil }

func (t *wireguardTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select peer"},
		{Key: "r", Desc: "refresh"},
	}
}

// peerRow is one navigable peer, carrying its device name for actions.
type peerRow struct {
	device string
	peer   wireguard.Peer
}

func (t *wireguardTab) rows() []peerRow {
	var out []peerRow
	for _, d := range t.snap.Devices {
		for _, p := range d.Peers {
			out = append(out, peerRow{device: d.Name, peer: p})
		}
	}
	return out
}

func (t *wireguardTab) refresh() {
	wc := t.eng.WireGuard()
	if wc == nil {
		t.avail = false
		t.err = fmt.Errorf("WireGuard monitoring is disabled")
		return
	}
	snap, ok := wc.Snapshot()
	t.avail = ok
	if !ok {
		t.err = wc.LastErr()
		if t.err == nil {
			t.err = fmt.Errorf("WireGuard state not available yet")
		}
		return
	}
	t.err = nil
	t.snap = snap
}

func (t *wireguardTab) Update(msg tea.Msg) tea.Cmd {
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
		case "a", "e", "x":
			return statusCmd("tunnels and peers are changed in the configuration: the console's WireGuard section or testudo config")
		}
	}
	return nil
}

func (t *wireguardTab) View(w, h int) string {
	out := []string{headerStyle.Render(
		"WireGuard - ↑/↓ select · r=refresh · tunnels and peers are changed in the configuration")}

	if t.err != nil {
		out = append(out, netopsErrLines(t.err)...)
		out = append(out, subtitleStyle.Render(
			"  reading WireGuard state needs CAP_NET_ADMIN; a tunnel may still be up."))
		return boxStyle.Render(strings.Join(out, "\n"))
	}
	if len(t.snap.Devices) == 0 {
		out = append(out, subtitleStyle.Render("  no WireGuard devices found (nothing to show)"))
		return boxStyle.Render(strings.Join(out, "\n"))
	}

	innerW := w - 6
	widths := []int{14, 8, 20, 11, 8, 8, 11}
	all := t.rows()
	rowIdx := 0
	for _, d := range t.snap.Devices {
		out = append(out, "")
		title := "wg " + d.Name
		if d.Label != "" {
			title = d.Label + " (" + d.Name + ")"
		}
		out = append(out, headerStyle.Render(fmt.Sprintf(
			"%s   listen :%d   peers %d", title, d.ListenPort, len(d.Peers))))
		out = append(out, "  "+wgDeviceHealthLine(d))
		out = append(out, "  "+renderTableRow(innerW, widths,
			"PEER", "HEALTH", "ENDPOINT", "HANDSHAKE", "RX", "TX", "TXBPS"))
		for range d.Peers {
			r := all[rowIdx]
			p := r.peer
			hs := wgSeverityStyle(p.Severity).Render(p.HandshakeLabel())
			health := wgSeverityStyle(p.Health).Render(string(p.Health))
			spark := sparkline(p.TXHistory, 10)
			rendered := renderTableRow(innerW, widths,
				p.PeerDisplayName(),
				health,
				orDash(p.Endpoint),
				hs,
				fmtBytes(uint64(nonNeg64(p.ReceiveBytes))),
				fmtBytes(uint64(nonNeg64(p.TransmitBytes))),
				spark,
			)
			marker := "  "
			if rowIdx == t.cursor {
				marker = "▸ "
			}
			if rowIdx == t.cursor {
				out = append(out, selectedRowStyle.Render(marker+rendered))
			} else {
				out = append(out, rowStyle.Render(marker+rendered))
			}
			if len(p.AllowedIPs) > 0 {
				out = append(out, dimStyle.Render("     allowed: "+strings.Join(p.AllowedIPs, ", ")))
			}
			if drift := wgDriftLabel(p.Drift); drift != "" {
				out = append(out, warnStyle.Render("     ⚠ "+drift))
			}
			rowIdx++
		}
	}
	return boxStyle.Render(strings.Join(out, "\n"))
}

// wgDriftLabel renders a human note for a peer's live-vs-netplan drift.
func wgDriftLabel(d wireguard.Drift) string {
	switch d {
	case wireguard.DriftNotPersistent:
		return "live but not in netplan (lost on next apply/reboot)"
	case wireguard.DriftConfigOnly:
		return "configured in netplan, not up on the device"
	case wireguard.DriftConfig:
		return "AllowedIPs differ live vs netplan (config drift)"
	}
	return ""
}

// wgDeviceHealthLine renders the device's link + tx/rx-error health summary.
func wgDeviceHealthLine(d wireguard.Device) string {
	link := okStyle.Render("UP")
	if !d.Up {
		link = errStyle.Render("DOWN")
	} else if !d.Running {
		link = warnStyle.Render("UP (no carrier)")
	}
	health := wgSeverityStyle(d.Health).Render("health " + string(d.Health))
	errs := fmt.Sprintf("err %d", d.RxErrors+d.TxErrors)
	if d.ErrDelta > 0 {
		errs = errStyle.Render(fmt.Sprintf("err %d ▲+%d", d.RxErrors+d.TxErrors, d.ErrDelta))
	}
	drops := fmt.Sprintf("drop %d", d.RxDropped+d.TxDropped)
	if d.DropDelta > 0 {
		drops = warnStyle.Render(fmt.Sprintf("drop %d ▲+%d", d.RxDropped+d.TxDropped, d.DropDelta))
	}
	sep := dimStyle.Render(" · ")
	tail := dimStyle.Render(fmt.Sprintf("mtu %d/txq %d · rx %s / tx %s", d.MTU, d.TxQLen, fmtBytes(d.RxBytes), fmtBytes(d.TxBytes)))
	np := okStyle.Render("netplan in sync")
	switch {
	case !d.NetplanKnown:
		np = dimStyle.Render("no netplan")
	case d.DriftCount > 0:
		np = warnStyle.Render(fmt.Sprintf("drift %d", d.DriftCount))
	}
	return link + sep + health + sep + np + sep + errs + sep + drops + sep + tail
}

// wgSeverityStyle maps a peer handshake severity to a lipgloss style.
func wgSeverityStyle(s wireguard.Severity) lipgloss.Style {
	switch s {
	case wireguard.SevWarn:
		return warnStyle
	case wireguard.SevError, wireguard.SevCritical:
		return errStyle
	default:
		return okStyle
	}
}

func nonNeg64(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}
