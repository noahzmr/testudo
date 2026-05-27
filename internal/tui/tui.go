// Package tui renders the operational Testudo console with Bubble Tea +
// Lip Gloss. The App is a tabbed shell; each tab is a Tab implementation
// that owns its own state and rendering.
//
// The chrome around the tab body - top info panels, `:` command bar, `/`
// filter bar, `?` help overlay, breadcrumb, footer - is inspired by k9s
// and lives in chrome.go. The App owns the mode state machine that decides
// which on-screen editor (if any) receives a given keypress.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/netops"
)

// Tab is one screen within the app. Each implementation owns its data and
// any per-tab tickers / commands.
type Tab interface {
	Title() string
	ShortKey() string // single-character hotkey shown in the tab bar
	Init() tea.Cmd
	Update(msg tea.Msg) tea.Cmd
	View(width, height int) string
}

// App is the root Bubble Tea model. It dispatches messages to the active
// tab and renders the chrome (header, tab bar, breadcrumb, footer).
type App struct {
	eng       *engine.Engine
	tabs      []Tab
	activeIdx int
	modal     Modal // when non-nil, eats key events until Modal.Done()

	// anomalySub is a single long-lived subscription. listenAnomalies()
	// re-runs as a tea.Cmd per message but always reads from this channel -
	// never call bus.Subscribe() inside a tea.Cmd factory: each call adds a
	// permanent dead subscriber to the bus's fan-out loop.
	anomalySub *events.Subscription

	// probes caches the latest latency / loss / DNS result per
	// (source, target). Fed by a single bus subscription started in NewApp;
	// the Health tab reads snapshots on every render. Lives for the
	// lifetime of the App and is closed in Close().
	probes *ProbeState

	// mode + cmdBuf hold the chrome's input-mode state machine. Only one
	// editor (command bar, filter bar, help overlay) is active at a time.
	mode   inputMode
	cmdBuf string
	filter string // last applied filter pattern; forwarded to Filterable tabs

	anomalies []anomalyMsg
	width     int
	height    int
	startedAt time.Time
	statusMsg string

	// grade is the latest network-quality summary rendered in the header.
	// Refreshed on slowTick so every tab (not just Dashboard) sees a
	// current letter/score without each one recomputing it on every frame.
	grade NetworkGrade

	// bodyScroll is the vertical offset applied to the active tab's
	// rendered body. Driven by PgUp/PgDn/Home/End/Ctrl-U/Ctrl-D in the
	// chrome so every tab gets scrolling without per-tab plumbing. Reset
	// to 0 whenever the active tab changes.
	bodyScroll int
}

// SetModal installs a modal overlay. Subsequent key events go to the modal
// until its Done() returns true, at which point the modal is closed.
func (a *App) SetModal(m Modal) tea.Cmd { a.modal = m; return m.Init() }

type anomalyMsg struct {
	ts       time.Time
	severity string
	text     string
	source   string
}

func NewApp(eng *engine.Engine) *App {
	app := &App{
		eng:        eng,
		startedAt:  time.Now(),
		anomalySub: eng.Bus().SubscribeKinds(events.KindAnomaly),
		probes:     NewProbeState(eng.Bus()),
	}
	app.refreshGrade() // populate before the first frame
	app.tabs = []Tab{
		newDashboardTab(eng),
		newFlowsTab(eng, app),
		newDevicesTab(eng, app),
		newIfacesTab(eng, app),
		newRoutesTab(eng, app),
		newFirewallTab(eng, app),
		newNATTab(eng, app),
		newTCPDumpTab(eng, app),
		newTalkersTab(eng),
		newProbesTab(eng),
		newAlertsTab(app),
		newHistoryTab(eng, app),
		newSettingsTab(eng, app),
		newHealthTab(eng, app),
	}
	return app
}

func (a *App) Init() tea.Cmd {
	// App owns exactly one dashTick and one slowTick at any moment. Tabs
	// must never return tick commands from their Update - see the comment
	// at the top of tabs.go for the geometric-blowup story behind that rule.
	cmds := []tea.Cmd{a.waitAnomaly(), dashTick(), slowTick()}
	if cmd := a.refreshActive(); cmd != nil {
		cmds = append(cmds, cmd)
	}
	for _, t := range a.tabs {
		if c := t.Init(); c != nil {
			cmds = append(cmds, c)
		}
	}
	return tea.Batch(cmds...)
}

// refreshGrade recomputes the cached network-quality grade from the
// aggregator's latest snapshots. Called on slowTick (3s) and once at
// startup so the header always shows a current score without each tab
// recomputing it on every frame.
func (a *App) refreshGrade() {
	targets := a.eng.Aggregator().SnapshotTargets()
	dns := a.eng.Aggregator().SnapshotDNS()
	var ifaces []netops.IfaceInfo
	if nw := a.eng.Netops(); nw != nil {
		ifaces, _ = nw.ListIfaces()
	}
	var wifi []collectors.WiFiSnapshot
	if wc := a.eng.WiFi(); wc != nil {
		wifi = wc.Snapshot()
	}
	fwRate, fwHas := a.eng.FirewallSignal()
	a.grade = ComputeGrade(targets, dns, ifaces, wifi, fwRate, fwHas, l3InputFrom(a.eng.Neigh(), a.eng.NetlinkWatch()), a.eng.Settings().Snapshot())
}

// refreshActive triggers an immediate one-shot slow-refresh of the
// currently-active tab. Used at startup and on every tab switch so the
// netlink-querying tabs (Devices, Ifaces, Routes, Firewall, NAT) get fresh
// data when the user lands on them, without keeping per-tab timers alive.
func (a *App) refreshActive() tea.Cmd {
	if a.activeIdx < 0 || a.activeIdx >= len(a.tabs) {
		return nil
	}
	a.tabs[a.activeIdx].Update(slowTickMsg{at: time.Now()})
	a.tabs[a.activeIdx].Update(tickMsg{at: time.Now()})
	return nil
}

// waitAnomaly returns a tea.Cmd that blocks until the next anomaly arrives
// on the shared subscription.
func (a *App) waitAnomaly() tea.Cmd {
	ch := a.anomalySub.C()
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		p, ok := ev.Payload.(events.AnomalyPayload)
		if !ok {
			return nil
		}
		return anomalyMsg{ts: ev.Time, severity: p.Severity, text: p.Message, source: ev.Source}
	}
}

// statusMessageMsg is a global toast set by tabs (e.g. "writes disabled").
type statusMessageMsg string

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tickMsg:
		_ = a.tabs[a.activeIdx].Update(m)
		return a, dashTick()
	case slowTickMsg:
		a.refreshGrade()
		_ = a.tabs[a.activeIdx].Update(m)
		return a, slowTick()
	case anomalyMsg:
		a.anomalies = append(a.anomalies, m)
		if len(a.anomalies) > 100 {
			a.anomalies = a.anomalies[len(a.anomalies)-100:]
		}
		return a, a.waitAnomaly()
	case statusMessageMsg:
		a.statusMsg = string(m)
		return a, clearStatusAfter(3 * time.Second)
	case clearStatusMsg:
		a.statusMsg = ""
		return a, nil
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		for _, t := range a.tabs {
			_ = t.Update(m)
		}
		return a, nil
	case tea.KeyMsg:
		return a.handleKey(m)
	}
	// Unknown message kinds: send only to the active tab so we never trip
	// a hidden broadcast amplification path again.
	return a, a.tabs[a.activeIdx].Update(msg)
}

// handleKey routes key events through the mode state machine. Order matters:
// modals first, then mode-specific editors, then the global navigation set,
// and finally the active tab.
func (a *App) handleKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.modal != nil {
		cmd := a.modal.Update(m)
		if a.modal.Done() {
			a.modal = nil
		}
		return a, cmd
	}

	switch a.mode {
	case modeCommand:
		return a, a.updateCommandMode(m)
	case modeFilter:
		return a, a.updateFilterMode(m)
	case modeHelp:
		// Any key closes help; swallow it so we don't accidentally trigger a
		// tab switch with the same press.
		a.mode = modeNormal
		return a, nil
	}

	// Normal mode - chrome bindings first, then global nav, then forward.
	switch m.String() {
	case ":":
		a.mode = modeCommand
		a.cmdBuf = ""
		return a, nil
	case "/":
		a.mode = modeFilter
		a.cmdBuf = a.filter
		return a, nil
	case "?":
		a.mode = modeHelp
		return a, nil
	case "esc":
		// Esc in normal mode clears any active filter.
		if a.filter != "" {
			a.setFilter("")
		}
		return a, nil
	case "ctrl+c", "q":
		return a, tea.Quit
	case "tab", "right":
		a.activeIdx = (a.activeIdx + 1) % len(a.tabs)
		a.bodyScroll = 0
		a.refreshActive()
		return a, nil
	case "shift+tab", "left":
		a.activeIdx = (a.activeIdx - 1 + len(a.tabs)) % len(a.tabs)
		a.bodyScroll = 0
		a.refreshActive()
		return a, nil
	case "pgup":
		a.bodyScroll -= a.bodyHeight() - 2
		if a.bodyScroll < 0 {
			a.bodyScroll = 0
		}
		return a, nil
	case "pgdown":
		a.bodyScroll += a.bodyHeight() - 2
		return a, nil
	case "ctrl+u":
		a.bodyScroll -= a.bodyHeight() / 2
		if a.bodyScroll < 0 {
			a.bodyScroll = 0
		}
		return a, nil
	case "ctrl+d":
		a.bodyScroll += a.bodyHeight() / 2
		return a, nil
	case "home":
		a.bodyScroll = 0
		return a, nil
	case "end":
		// scrollClip clamps this to the true max on the next render.
		a.bodyScroll = 1 << 30
		return a, nil
	}
	// Numeric hotkeys: 1..9 pick the first nine tabs; "0" picks the tenth
	// (Settings) so every tab has a single-keystroke shortcut.
	if s := m.String(); len(s) == 1 {
		var idx = -1
		switch {
		case s[0] >= '1' && s[0] <= '9':
			idx = int(s[0] - '1')
		case s[0] == '0':
			idx = 9
		}
		if idx >= 0 && idx < len(a.tabs) {
			a.activeIdx = idx
			a.bodyScroll = 0
			a.refreshActive()
			return a, nil
		}
	}
	// Otherwise forward to active tab only.
	return a, a.tabs[a.activeIdx].Update(m)
}

// updateCommandMode handles edits to the `:`-prompt buffer.
func (a *App) updateCommandMode(m tea.KeyMsg) tea.Cmd {
	switch m.String() {
	case "esc", "ctrl+c":
		a.mode = modeNormal
		a.cmdBuf = ""
	case "enter":
		idx, quit := a.resolveCommand(a.cmdBuf)
		a.mode = modeNormal
		a.cmdBuf = ""
		if quit {
			return tea.Quit
		}
		if idx >= 0 {
			a.activeIdx = idx
			a.bodyScroll = 0
			a.refreshActive()
		} else {
			a.statusMsg = "unknown command - try `:flows`, `:firewall`, `:q`"
			return clearStatusAfter(3 * time.Second)
		}
	case "tab":
		if c := completeCommand(a.cmdBuf); c != "" {
			a.cmdBuf = c
		}
	case "backspace":
		if len(a.cmdBuf) > 0 {
			a.cmdBuf = a.cmdBuf[:len(a.cmdBuf)-1]
		}
	default:
		s := m.String()
		if len(s) == 1 {
			a.cmdBuf += s
		} else if s == "space" {
			a.cmdBuf += " "
		}
	}
	return nil
}

// updateFilterMode handles edits to the `/`-prompt buffer. Filter is applied
// live as the user types so they can see the effect immediately; Enter just
// dismisses the prompt while keeping the filter in place. Esc cancels and
// reverts to whatever the previously-applied filter was.
func (a *App) updateFilterMode(m tea.KeyMsg) tea.Cmd {
	switch m.String() {
	case "esc", "ctrl+c":
		a.mode = modeNormal
		a.cmdBuf = ""
	case "enter":
		a.setFilter(a.cmdBuf)
		a.mode = modeNormal
	case "backspace":
		if len(a.cmdBuf) > 0 {
			a.cmdBuf = a.cmdBuf[:len(a.cmdBuf)-1]
		}
		a.setFilter(a.cmdBuf)
	default:
		s := m.String()
		if len(s) == 1 {
			a.cmdBuf += s
			a.setFilter(a.cmdBuf)
		} else if s == "space" {
			a.cmdBuf += " "
			a.setFilter(a.cmdBuf)
		}
	}
	return nil
}

// setFilter records the pattern on the App and pushes it into the active
// tab when that tab implements Filterable.
func (a *App) setFilter(pat string) {
	a.filter = pat
	if a.activeIdx < 0 || a.activeIdx >= len(a.tabs) {
		return
	}
	if f, ok := a.tabs[a.activeIdx].(Filterable); ok {
		f.SetFilter(pat)
	}
}

// uptime returns a truncated uptime string for the header panel.
func (a *App) uptime() string {
	return time.Since(a.startedAt).Truncate(time.Second).String()
}

type clearStatusMsg struct{}

func clearStatusAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return clearStatusMsg{} })
}

func (a *App) View() string {
	width := a.width
	if width <= 0 {
		width = 80
	}

	header := a.renderHeader(width)
	tabBar := a.renderTabBar(width)
	bodyH := a.bodyHeight()
	body := a.tabs[a.activeIdx].View(width, bodyH)
	bottom := a.renderCommandBar(width)

	if a.modal != nil {
		// Centre the modal over the body region so it's always visible -
		// appending below the tab body pushes it off the viewport on full-
		// height tabs (Firewall, NAT, Routes).
		body = lipgloss.Place(width, bodyH,
			lipgloss.Center, lipgloss.Center, a.modal.View())
	}

	// Tabs currently ignore the height parameter, so a long table would
	// overflow the body region and push the footer off the bottom of the
	// terminal. scrollClip windows the body using a.bodyScroll (driven by
	// PgUp/PgDn/Home/End/Ctrl-U/Ctrl-D in handleKey) so the chrome stays
	// anchored and the operator can reach hidden rows.
	body = a.scrollClip(body, bodyH)

	main := strings.Join([]string{header, tabBar, body, bottom}, "\n")

	if a.mode == modeHelp {
		// Overlay the help screen over the entire frame. lipgloss.Place
		// centres the help box within the terminal viewport.
		return a.renderHelp(width, a.heightOr(24))
	}
	return main
}

// bodyHeight reserves space for the chrome around the tab body. The
// header panels are 8 rows tall (6 content lines + rounded border top &
// bottom). The footer is multi-line and width-dependent, so we measure it
// instead of guessing.
func (a *App) bodyHeight() int {
	if a.height <= 0 {
		return 24
	}
	chromeRows := 8 // bordered header panels (6 content + 2 border)
	chromeRows += 1 // tab bar
	chromeRows += a.footerRows()
	h := a.height - chromeRows
	if h < 5 {
		return 5
	}
	return h
}

// scrollClip windows the rendered body string so it fits within h screen
// lines. When the body is taller than h, the last line is replaced with a
// dim status line showing the current scroll position and bindings. The
// scroll offset is clamped against the actual line count so PgDn/End never
// overshoot.
func (a *App) scrollClip(s string, h int) string {
	if h <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= h {
		// Body fits - keep scroll at 0 so resizing back up doesn't leave
		// a stale offset that re-applies the next time content grows.
		a.bodyScroll = 0
		return s
	}
	// Reserve the bottom line for the scroll indicator.
	visibleH := h - 1
	if visibleH < 1 {
		visibleH = 1
	}
	maxScroll := len(lines) - visibleH
	if a.bodyScroll > maxScroll {
		a.bodyScroll = maxScroll
	}
	if a.bodyScroll < 0 {
		a.bodyScroll = 0
	}
	end := a.bodyScroll + visibleH
	if end > len(lines) {
		end = len(lines)
	}
	window := make([]string, 0, h)
	window = append(window, lines[a.bodyScroll:end]...)
	indicator := dimStyle.Render(fmt.Sprintf(
		"lines %d–%d of %d  ·  PgUp/PgDn · Home/End · Ctrl-U/Ctrl-D",
		a.bodyScroll+1, end, len(lines)))
	window = append(window, indicator)
	return strings.Join(window, "\n")
}

// footerRows counts the rendered lines the footer block currently occupies.
// We render once and count newlines - cheaper than re-implementing the wrap
// logic, and guaranteed to match what View() will produce.
func (a *App) footerRows() int {
	w := a.width
	if w <= 0 {
		w = 80
	}
	rendered := a.renderCommandBar(w)
	return strings.Count(rendered, "\n") + 1
}

func (a *App) heightOr(def int) int {
	if a.height <= 0 {
		return def
	}
	return a.height
}

// Close releases bus subscriptions held by the app. Call once after Run
// returns, or rely on the deferred Close in Run().
func (a *App) Close() {
	if a.anomalySub != nil {
		a.anomalySub.Close()
		a.anomalySub = nil
	}
	if a.probes != nil {
		a.probes.Close()
		a.probes = nil
	}
}

// Run launches the Bubble Tea program and blocks until the user quits.
func Run(ctx context.Context, app *App) error {
	defer app.Close()
	p := tea.NewProgram(app, tea.WithAltScreen())
	go func() {
		<-ctx.Done()
		p.Quit()
	}()
	_, err := p.Run()
	return err
}
