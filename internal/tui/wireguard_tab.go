package tui

import (
	"fmt"
	"strconv"
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
		{Key: "a", Desc: "add peer (name / preset / keygen mode / fixed IP)"},
		{Key: "e", Desc: "edit peer (endpoint / allowed IPs / keepalive / preset)"},
		{Key: "x", Desc: "deprovision the selected peer (peer + route + firewall + IP)"},
		{Key: "n", Desc: "name the interface of the selected peer"},
		{Key: "R", Desc: "restart the interface (link down/up)"},
		{Key: "t", Desc: "tune the interface for max performance (MTU/txqueuelen/buffers)"},
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
		case "a":
			return t.openAddModal()
		case "e":
			if t.cursor >= 0 && t.cursor < len(rows) {
				return t.openEditModal(rows[t.cursor])
			}
			return statusCmd("no peer selected")
		case "x":
			if t.cursor >= 0 && t.cursor < len(rows) {
				return t.deprovision(rows[t.cursor])
			}
			return statusCmd("no peer selected")
		case "n":
			return t.openRenameModal(t.selectedDevice(rows))
		case "R":
			return t.restartInterface(t.selectedDevice(rows))
		case "t":
			return t.openTuneModal(t.selectedDevice(rows))
		}
	}
	return nil
}

func (t *wireguardTab) openAddModal() tea.Cmd {
	modal := NewFormModal("Add WireGuard Peer",
		[]FormField{
			{Label: "name", Value: "", Hint: "human label for the peer (phone, laptop…)"},
			{Label: "preset", Value: "split", Hint: "full / split / isolated routing preset"},
			{Label: "keygen", Value: "server", Hint: "server = render config once · client = paste public key"},
			{Label: "public_key", Value: "", Hint: "peer's base64 public key (client keygen only)"},
			{Label: "fixed_ip", Value: "", Hint: "optional fixed tunnel IP; blank = next free"},
		},
		func(values map[string]string) error {
			preset := wireguard.FirewallPreset(strings.TrimSpace(values["preset"]))
			if !preset.Valid() {
				return fmt.Errorf("preset must be full / split / isolated")
			}
			serverKeygen := strings.TrimSpace(values["keygen"]) != "client"
			pub := strings.TrimSpace(values["public_key"])
			if !serverKeygen && pub == "" {
				return fmt.Errorf("client keygen needs the peer's public key")
			}
			res, err := t.eng.ProvisionWireGuardPeer(
				strings.TrimSpace(values["name"]), preset, serverKeygen, pub,
				strings.TrimSpace(values["fixed_ip"]))
			if err != nil {
				return err
			}
			t.refresh()
			// Server-side keygen returns a one-shot config containing the private
			// key. Surface it once in a modal; it is never persisted or logged.
			if res.ClientConfig != "" {
				t.app.SetModal(newWireGuardConfigModal(res.AssignedIP, res.ClientConfig))
			}
			return nil
		},
	)
	return t.app.SetModal(modal)
}

func (t *wireguardTab) openEditModal(r peerRow) tea.Cmd {
	kaVal := "-1"
	if int(r.peer.PersistentKeepalive.Seconds()) > 0 {
		kaVal = fmt.Sprintf("%d", int(r.peer.PersistentKeepalive.Seconds()))
	}
	modal := NewFormModal(
		fmt.Sprintf("Edit peer %s on %s", r.peer.PeerDisplayName(), r.device),
		[]FormField{
			{Label: "endpoint", Value: r.peer.Endpoint, Hint: "host:port; blank clears the stored endpoint"},
			{Label: "allowed_ips", Value: strings.Join(r.peer.AllowedIPs, ", "), Hint: "comma-separated CIDRs; blank keeps current"},
			{Label: "keepalive", Value: kaVal, Hint: "persistent-keepalive seconds: -1 leave, 0 off, e.g. 25"},
			{Label: "preset", Value: "split", Hint: "full / split / isolated firewall preset"},
		},
		func(values map[string]string) error {
			preset := wireguard.FirewallPreset(strings.TrimSpace(values["preset"]))
			if !preset.Valid() {
				return fmt.Errorf("preset must be full / split / isolated")
			}
			var allowed []string
			for _, s := range strings.Split(values["allowed_ips"], ",") {
				if s = strings.TrimSpace(s); s != "" {
					allowed = append(allowed, s)
				}
			}
			keepalive := -1
			if v := strings.TrimSpace(values["keepalive"]); v != "" {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("keepalive must be an integer (seconds)")
				}
				keepalive = n
			}
			if err := t.eng.UpdateWireGuardPeer(r.peer.PublicKey, strings.TrimSpace(values["endpoint"]), allowed, keepalive, preset); err != nil {
				return err
			}
			t.refresh()
			return nil
		},
	)
	return t.app.SetModal(modal)
}

// selectedDevice returns the device of the peer under the cursor, or the first
// device when the cursor isn't on a peer row.
func (t *wireguardTab) selectedDevice(rows []peerRow) string {
	if t.cursor >= 0 && t.cursor < len(rows) {
		return rows[t.cursor].device
	}
	if len(t.snap.Devices) > 0 {
		return t.snap.Devices[0].Name
	}
	return ""
}

func (t *wireguardTab) openRenameModal(device string) tea.Cmd {
	if device == "" {
		return statusCmd("no interface to name")
	}
	var cur string
	for _, d := range t.snap.Devices {
		if d.Name == device {
			cur = d.Label
		}
	}
	modal := NewFormModal(
		fmt.Sprintf("Name interface %s", device),
		[]FormField{{Label: "name", Value: cur, Hint: "human label for this wg interface"}},
		func(values map[string]string) error {
			if err := t.eng.SetWireGuardInterfaceName(device, strings.TrimSpace(values["name"])); err != nil {
				return err
			}
			t.refresh()
			return nil
		},
	)
	return t.app.SetModal(modal)
}

func (t *wireguardTab) openTuneModal(device string) tea.Cmd {
	if device == "" {
		return statusCmd("no interface to tune")
	}
	modal := NewFormModal(
		fmt.Sprintf("Tune %s for performance", device),
		[]FormField{
			{Label: "mtu", Value: "1420", Hint: "1420 default; try 1380/1280 if tx/rx errors persist; 0 = leave"},
			{Label: "txqueuelen", Value: "1000", Hint: "transmit queue length; 0 = leave"},
			{Label: "socket_buffers", Value: "yes", Hint: "yes = enlarge UDP socket buffers (system-wide sysctls)"},
		},
		func(values map[string]string) error {
			mtu, _ := strconv.Atoi(strings.TrimSpace(values["mtu"]))
			txq, _ := strconv.Atoi(strings.TrimSpace(values["txqueuelen"]))
			bufs := strings.EqualFold(strings.TrimSpace(values["socket_buffers"]), "yes")
			if err := t.eng.TuneWireGuardInterface(device, engine.TuneParams{
				MTU: mtu, TxQueueLen: txq, SocketBuffers: bufs,
			}); err != nil {
				return err
			}
			t.refresh()
			return nil
		},
	)
	return t.app.SetModal(modal)
}

func (t *wireguardTab) restartInterface(device string) tea.Cmd {
	if device == "" {
		return statusCmd("no interface to restart")
	}
	modal := NewFormModal(
		fmt.Sprintf("Restart interface %s?", device),
		[]FormField{{Label: "confirm", Value: "no", Hint: "type 'yes' to bounce the link (down/up); the tunnel drops briefly"}},
		func(values map[string]string) error {
			if strings.TrimSpace(values["confirm"]) != "yes" {
				return fmt.Errorf("cancelled")
			}
			if err := t.eng.RestartWireGuardInterface(device); err != nil {
				return err
			}
			t.refresh()
			return nil
		},
	)
	return t.app.SetModal(modal)
}

func (t *wireguardTab) deprovision(r peerRow) tea.Cmd {
	modal := NewFormModal(
		fmt.Sprintf("Deprovision peer %s on %s?", r.peer.PeerName(), r.device),
		[]FormField{{Label: "confirm", Value: "no", Hint: "type 'yes' to remove peer + route + firewall rules + free IP"}},
		func(values map[string]string) error {
			if strings.TrimSpace(values["confirm"]) != "yes" {
				return fmt.Errorf("cancelled")
			}
			if err := t.eng.DeprovisionWireGuardPeer(r.peer.PublicKey); err != nil {
				return err
			}
			t.refresh()
			return nil
		},
	)
	return t.app.SetModal(modal)
}

func (t *wireguardTab) View(w, h int) string {
	out := []string{headerStyle.Render(
		"WireGuard - ↑/↓ select · a=add peer · x=deprovision · r=refresh")}

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

// wireguardConfigModal shows a one-shot server-side-keygen client config,
// including its PRIVATE key, exactly once. The config is held only in this
// modal's memory and is never persisted or logged; dismiss it after copying.
// (In the browser, the equivalent flow generates the QR client-side.)
type wireguardConfigModal struct {
	ip     string
	config string
	done   bool
}

func newWireGuardConfigModal(ip, config string) *wireguardConfigModal {
	return &wireguardConfigModal{ip: ip, config: config}
}

func (m *wireguardConfigModal) Title() string { return "WireGuard client config" }
func (m *wireguardConfigModal) Init() tea.Cmd { return nil }
func (m *wireguardConfigModal) Done() bool    { return m.done }
func (m *wireguardConfigModal) Result() any   { return nil }

func (m *wireguardConfigModal) Update(msg tea.Msg) tea.Cmd {
	if _, ok := msg.(tea.KeyMsg); ok {
		// Wipe the secret from memory on dismiss.
		m.config = ""
		m.done = true
	}
	return nil
}

func (m *wireguardConfigModal) View() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("WireGuard client config (" + m.ip + ")"))
	b.WriteString("\n")
	b.WriteString(warnStyle.Render("Shown once - contains a PRIVATE key. Copy it now; it is never stored."))
	b.WriteString("\n\n")
	b.WriteString(m.config)
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("press any key to dismiss (wipes it from memory)"))
	return modalFrame.Render(b.String())
}
