package tui

// k9s-inspired chrome: top info panels, `:` command bar, `/` filter bar,
// `?` help overlay, breadcrumb, and footer hints. The chrome lives in the
// App; tabs stay agnostic except for an optional Filterable hook.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// inputMode tracks which on-screen single-line editor (if any) currently
// owns key events. Modal overlays still take precedence over all of these.
type inputMode int

const (
	modeNormal inputMode = iota
	modeCommand
	modeFilter
	modeHelp
)

// Filterable is implemented by tabs that accept a free-text filter string
// applied to their rendered rows. Tabs that don't implement it just ignore
// the filter bar — the App still tracks the pattern but the tab is free to
// render normally.
type Filterable interface {
	SetFilter(string)
}

// KeyHint pairs a key label with what that key does on the current tab.
// Used by both the help overlay (full list) and the footer (top picks).
type KeyHint struct {
	Key  string
	Desc string
}

// HelpProvider is implemented by tabs that want their bindings to appear in
// the `?` help overlay and the bottom footer. Returning an empty slice is
// fine — the chrome will still show global keys.
type HelpProvider interface {
	HelpHints() []KeyHint
}

// commandAliases maps `:name` strings to the canonical tab title used in
// App.tabs lookup. Multiple aliases per tab are allowed; the lookup is
// case-insensitive. `:q` / `:quit` short-circuit to a quit signal.
var commandAliases = map[string]string{
	"dash":       "Dashboard",
	"dashboard":  "Dashboard",
	"flow":       "Flows",
	"flows":      "Flows",
	"dev":        "Devices",
	"devices":    "Devices",
	"if":         "Interfaces",
	"iface":      "Interfaces",
	"ifaces":     "Interfaces",
	"interfaces": "Interfaces",
	"route":      "Routes",
	"routes":     "Routes",
	"fw":         "Firewall",
	"firewall":   "Firewall",
	"nat":        "NAT",
	"tcpdump":    "TCPDump",
	"pcap":       "TCPDump",
	"dump":       "TCPDump",
	"talk":       "Talkers",
	"talkers":    "Talkers",
	"top":        "Talkers",
	"probe":      "Probes",
	"probes":     "Probes",
	"alert":      "Alerts",
	"alerts":     "Alerts",
	"set":        "Settings",
	"settings":   "Settings",
}

// resolveCommand returns the tab index for a `:name` input, or (-1, true)
// for quit, or (-1, false) for "no match".
func (a *App) resolveCommand(name string) (idx int, quit bool) {
	n := strings.TrimSpace(strings.ToLower(name))
	if n == "" {
		return -1, false
	}
	if n == "q" || n == "quit" || n == "exit" {
		return -1, true
	}
	title, ok := commandAliases[n]
	if !ok {
		return -1, false
	}
	for i, t := range a.tabs {
		if strings.EqualFold(t.Title(), title) {
			return i, false
		}
	}
	return -1, false
}

// completeCommand returns the alphabetically-first alias whose prefix matches
// the current input. Empty string when nothing matches. Used to render the
// inline tab-completion hint in the command bar.
func completeCommand(input string) string {
	in := strings.ToLower(strings.TrimSpace(input))
	if in == "" {
		return ""
	}
	keys := make([]string, 0, len(commandAliases))
	for k := range commandAliases {
		keys = append(keys, k)
	}
	keys = append(keys, "quit")
	sort.Strings(keys)
	for _, k := range keys {
		if strings.HasPrefix(k, in) && k != in {
			return k
		}
	}
	return ""
}

// ---- chrome styles ----

var (
	panelBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(0, 1)

	panelLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("99")).Bold(true)
	panelKey   = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	panelVal   = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))

	crumbStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
			Padding(0, 2)

	crumbDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("244")).
			Padding(0, 1)

	cmdPromptStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("33")).
			Padding(0, 1)

	cmdInputStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("236")).
			Padding(0, 1)

	cmdHintStyle = lipgloss.NewStyle().
			Faint(true).
			Foreground(lipgloss.Color("244"))

	filterPromptStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("231")).
				Background(lipgloss.Color("166")).
				Padding(0, 1)

	filterActiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("214")).
				Bold(true)

	footerKey = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("220"))

	footerLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	helpKey   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")).Width(14)
	helpDesc  = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	helpGroup = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")).MarginTop(1)
)

// renderHeader builds the 3-column top panel. Width is split roughly into
// thirds; if the terminal is too narrow we collapse the right (logo) panel
// first, then the middle (keys) panel, and finally render a single-line
// compact summary for very narrow terminals.
func (a *App) renderHeader(width int) string {
	if width <= 0 {
		width = 80
	}

	activeTitle := "—"
	if a.activeIdx >= 0 && a.activeIdx < len(a.tabs) {
		activeTitle = a.tabs[a.activeIdx].Title()
	}
	filterLine := panelVal.Render("—")
	if a.filter != "" {
		filterLine = filterActiveStyle.Render(a.filter)
	}

	leftLines := []string{
		panelLabel.Render("Testudo"),
		panelLabel.Render("Session: ") + panelVal.Render(shortID(a.eng.SessionID())),
		panelLabel.Render("Uptime:  ") + panelVal.Render(a.uptime()),
		panelLabel.Render("View:    ") + panelVal.Render(activeTitle),
		panelLabel.Render("Filter:  ") + filterLine,
	}
	keysLines := []string{
		panelLabel.Render("Navigation"),
		panelKey.Render(" <:>") + footerLabel.Render(" command"),
		panelKey.Render(" </>") + footerLabel.Render(" filter"),
		panelKey.Render(" <?>") + footerLabel.Render(" help"),
		panelKey.Render(" <1-9>") + footerLabel.Render(" jump · ") + panelKey.Render("<q>") + footerLabel.Render(" quit"),
	}
	logoLines := strings.Split(tuiBanner, "\n")
	logoStyled := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render(strings.Join(logoLines, "\n"))

	left := panelBox.Render(strings.Join(leftLines, "\n"))
	mid := panelBox.Render(strings.Join(keysLines, "\n"))
	right := panelBox.Render(logoStyled)

	// Compose: drop panels if width is tight. Each panel has its own border
	// and padding, so lipgloss.Width gives the actual rendered cells.
	switch {
	case lipgloss.Width(left)+lipgloss.Width(mid)+lipgloss.Width(right)+2 <= width:
		return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", mid, " ", right)
	case lipgloss.Width(left)+lipgloss.Width(mid)+1 <= width:
		return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", mid)
	case lipgloss.Width(left) <= width:
		return left
	default:
		// Very narrow: a single line that still surfaces what matters.
		return panelLabel.Render("Testudo") + " · " +
			panelVal.Render(activeTitle) + " · " +
			panelLabel.Render("filter:") + " " + filterLine
	}
}

// renderTabBar produces a tab strip that adapts to width. Three layouts:
//
//   - wide   ≥ N + total(label widths):  full names for every tab
//   - medium: full name for the active tab, numbers only for the rest
//   - narrow: only the active tab's name + (idx/total) badge
//
// The active tab always shows its full name; the user always knows where
// they are.
func (a *App) renderTabBar(width int) string {
	if width <= 0 {
		width = 80
	}
	full := func(i int, t Tab) string {
		return fmt.Sprintf(" %d %s ", i+1, t.Title())
	}
	numeric := func(i int) string {
		return fmt.Sprintf(" %d ", i+1)
	}

	// Try full layout.
	totalFull := 0
	for i, t := range a.tabs {
		totalFull += lipgloss.Width(full(i, t)) + 1 // +1 for active marker
	}
	if totalFull <= width {
		var bar strings.Builder
		for i, t := range a.tabs {
			label := full(i, t)
			if i == a.activeIdx {
				bar.WriteString(tabActive.Render("●" + label))
			} else {
				bar.WriteString(tabInactive.Render(" " + label))
			}
		}
		return bar.String()
	}

	// Medium layout: full title for the active tab, numbers elsewhere.
	totalMedium := 0
	for i, t := range a.tabs {
		if i == a.activeIdx {
			totalMedium += lipgloss.Width(full(i, t)) + 1
		} else {
			totalMedium += lipgloss.Width(numeric(i)) + 1
		}
	}
	if totalMedium <= width {
		var bar strings.Builder
		for i, t := range a.tabs {
			if i == a.activeIdx {
				bar.WriteString(tabActive.Render("●" + full(i, t)))
				continue
			}
			bar.WriteString(tabInactive.Render(numeric(i)))
		}
		return bar.String()
	}

	// Narrow layout: just the active tab's badge.
	title := "—"
	if a.activeIdx >= 0 && a.activeIdx < len(a.tabs) {
		title = a.tabs[a.activeIdx].Title()
	}
	return tabActive.Render(fmt.Sprintf(" %d / %d  %s ",
		a.activeIdx+1, len(a.tabs), title))
}

// renderBreadcrumb is the k9s "<0> resource" line below the tab bar.
func (a *App) renderBreadcrumb() string {
	if a.activeIdx < 0 || a.activeIdx >= len(a.tabs) {
		return ""
	}
	title := a.tabs[a.activeIdx].Title()
	crumb := crumbStyle.Render(fmt.Sprintf(" %d / %d ", a.activeIdx+1, len(a.tabs)))
	name := crumbDim.Render(strings.ToLower(title))
	hint := ""
	if a.filter != "" {
		hint = " " + filterActiveStyle.Render("/"+a.filter)
	}
	return crumb + name + hint
}

// renderCommandBar renders the bottom-of-screen single-line input shown
// while modeCommand or modeFilter is active. For modeNormal it returns the
// regular footer hints block (which may span multiple lines on narrow
// terminals).
func (a *App) renderCommandBar(width int) string {
	switch a.mode {
	case modeCommand:
		hint := completeCommand(a.cmdBuf)
		input := a.cmdBuf
		if hint != "" {
			input = a.cmdBuf + cmdHintStyle.Render(hint[len(a.cmdBuf):])
		}
		return cmdPromptStyle.Render(" : ") + cmdInputStyle.Render(" "+input+"_ ")
	case modeFilter:
		return filterPromptStyle.Render(" / ") + cmdInputStyle.Render(" "+a.cmdBuf+"_ ")
	default:
		return a.renderFooter(width)
	}
}

// renderFooter packs the chrome hint set onto line 1 and the active tab's
// HelpHints into one or more lines beneath, packing items left-to-right
// until they don't fit, then wrapping. This keeps every binding readable
// at any terminal width — the lines just stack rather than overflowing.
func (a *App) renderFooter(width int) string {
	if width <= 0 {
		width = 80
	}
	chrome := []string{
		footerKey.Render("?") + footerLabel.Render(" help"),
		footerKey.Render(":") + footerLabel.Render(" cmd"),
		footerKey.Render("/") + footerLabel.Render(" filter"),
		footerKey.Render("Tab") + footerLabel.Render(" next"),
		footerKey.Render("q") + footerLabel.Render(" quit"),
	}
	var rendered []string
	rendered = append(rendered, packHints(chrome, width)...)
	if hints := a.activeTabHints(); len(hints) > 0 {
		items := make([]string, len(hints))
		for i, h := range hints {
			items[i] = footerKey.Render(h.Key) + footerLabel.Render(" "+h.Desc)
		}
		// Visible separator between chrome and tab keys.
		rendered = append(rendered, dimStyle.Render(strings.Repeat("·", min(width, 40))))
		rendered = append(rendered, packHints(items, width)...)
	}
	line := strings.Join(rendered, "\n")
	if a.statusMsg != "" {
		line += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(a.statusMsg)
	}
	return line
}

// packHints arranges items left-to-right into lines no wider than width,
// returning the rendered lines. lipgloss.Width is used to measure ANSI-
// stripped width, which is what the terminal actually sees.
func packHints(items []string, width int) []string {
	if width <= 0 {
		return []string{strings.Join(items, "  ")}
	}
	var lines []string
	var cur string
	curW := 0
	const sep = "  "
	sepW := lipgloss.Width(sep)
	for _, item := range items {
		w := lipgloss.Width(item)
		switch {
		case cur == "":
			cur = item
			curW = w
		case curW+sepW+w <= width:
			cur += sep + item
			curW += sepW + w
		default:
			lines = append(lines, cur)
			cur = item
			curW = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// activeTabHints returns the active tab's per-tab key list, or nil.
func (a *App) activeTabHints() []KeyHint {
	if a.activeIdx < 0 || a.activeIdx >= len(a.tabs) {
		return nil
	}
	hp, ok := a.tabs[a.activeIdx].(HelpProvider)
	if !ok {
		return nil
	}
	return hp.HelpHints()
}

// renderHelp is the overlay shown while modeHelp is active. It floats over
// the tab body and lists every chrome-level binding, the active tab's
// per-tab bindings, plus a short description of every registered command
// alias.
func (a *App) renderHelp(width, height int) string {
	groups := [][2]string{
		{":", "open command bar — try :flows, :firewall, :q"},
		{"/", "filter active view (Enter to apply, Esc to clear)"},
		{"?", "toggle this help"},
		{"Tab / Shift-Tab", "next / previous view"},
		{"1 .. 9", "jump directly to view N"},
		{"0", "jump to Settings"},
		{"↑ ↓ / k j", "scroll within view"},
		{"q / Ctrl-C", "quit"},
	}
	var lines []string
	lines = append(lines, titleStyle.Render("Testudo — Keyboard Reference"))
	lines = append(lines, helpGroup.Render("Chrome"))
	for _, g := range groups {
		lines = append(lines, helpKey.Render(g[0])+helpDesc.Render(g[1]))
	}

	// Active-tab specific bindings. Falls back silently if the tab doesn't
	// implement HelpProvider.
	if a.activeIdx >= 0 && a.activeIdx < len(a.tabs) {
		title := a.tabs[a.activeIdx].Title()
		if tabHints := a.activeTabHints(); len(tabHints) > 0 {
			lines = append(lines, helpGroup.Render(title+" tab"))
			for _, h := range tabHints {
				lines = append(lines, helpKey.Render(h.Key)+helpDesc.Render(h.Desc))
			}
		}
	}

	lines = append(lines, helpGroup.Render("Commands (after `:`)"))

	// Sort aliases by their target tab for a stable, readable list.
	seen := make(map[string][]string)
	for alias, title := range commandAliases {
		seen[title] = append(seen[title], alias)
	}
	titles := make([]string, 0, len(seen))
	for k := range seen {
		titles = append(titles, k)
	}
	sort.Strings(titles)
	for _, title := range titles {
		al := seen[title]
		sort.Strings(al)
		lines = append(lines, helpKey.Render(":"+al[0])+helpDesc.Render("→ "+title+"  ("+strings.Join(al, ", ")+")"))
	}
	lines = append(lines, helpKey.Render(":q")+helpDesc.Render("quit"))
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("press any key to close"))

	body := strings.Join(lines, "\n")
	box := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("214")).
		Padding(1, 3)
	rendered := box.Render(body)
	if width <= 0 || height <= 0 {
		return rendered
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, rendered)
}

// shortID trims a long session UUID for the header.
func shortID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…"
}
