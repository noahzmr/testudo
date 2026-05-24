package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/flows"
)

// talkersTab presents three sniffnet-style rollups in one place:
//
//	1. Top hosts        — who am I talking to, how much, LAN or WAN
//	2. Top processes    — which programs generate the traffic
//	3. Top services     — which upper-layer protocols dominate
//
// All three update on every dashboard tick; cursor selects the section
// (hosts / processes / services) so the user can flip between them with
// ←/→ without leaving the tab.
type talkersTab struct {
	eng     *engine.Engine
	rows    []flows.FlowStats
	section int // 0=hosts, 1=processes, 2=services
}

func newTalkersTab(eng *engine.Engine) *talkersTab { return &talkersTab{eng: eng} }

func (t *talkersTab) Title() string    { return "Talkers" }
func (t *talkersTab) ShortKey() string { return "" } // accessed via `:talk`; numeric keys are full
func (t *talkersTab) Init() tea.Cmd    { return nil }
func (t *talkersTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "←/→ · h/l", Desc: "switch between hosts / processes / services"},
		{Key: "1 · 2 · 3", Desc: "jump directly to a section"},
	}
}

func (t *talkersTab) Update(msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case tickMsg:
		t.rows = t.eng.DecoratedFlows(500)
	case tea.KeyMsg:
		switch m.String() {
		case "left", "h":
			if t.section > 0 {
				t.section--
			}
		case "right", "l":
			if t.section < 2 {
				t.section++
			}
		case "1":
			t.section = 0
		case "2":
			t.section = 1
		case "3":
			t.section = 2
		}
	}
	return nil
}

func (t *talkersTab) View(w, h int) string {
	var b strings.Builder
	hosts := flows.TopHosts(t.rows, 20)
	procs := flows.TopProcesses(t.rows, 20)
	svcs := flows.TopServices(t.rows, 20)

	hostsActive := t.section == 0
	procsActive := t.section == 1
	svcsActive := t.section == 2

	hdr := []string{
		sectionLabel("Hosts", len(hosts), hostsActive),
		sectionLabel("Processes", len(procs), procsActive),
		sectionLabel("Services", len(svcs), svcsActive),
	}
	b.WriteString(headerStyle.Render("Top talkers — ←/→ switch · 1 hosts · 2 processes · 3 services"))
	b.WriteString("\n  ")
	b.WriteString(strings.Join(hdr, "    "))
	b.WriteString("\n\n")

	switch t.section {
	case 0:
		b.WriteString(renderTopHosts(hosts))
	case 1:
		b.WriteString(renderTopProcs(procs))
	case 2:
		b.WriteString(renderTopServices(svcs))
	}
	return boxStyle.Render(b.String())
}

func sectionLabel(name string, count int, active bool) string {
	s := fmt.Sprintf("%s (%d)", name, count)
	if active {
		return selectedRowStyle.Render(" " + s + " ")
	}
	return dimStyle.Render(" " + s + " ")
}

func renderTopHosts(rows []flows.HostRollup) string {
	if len(rows) == 0 {
		return subtitleStyle.Render("  no flows yet — start capture (Flows tab → 's')")
	}
	widths := []int{4, 30, 8, 12, 10, 8}
	out := []string{"  " + renderRowWidths(widths,
		"#", "HOST / DNS", "ZONE", "BYTES", "PACKETS", "FLOWS")}
	for i, r := range rows {
		zone := okStyle.Render("WAN")
		if r.IsLAN {
			zone = dimStyle.Render("LAN")
		}
		host := r.Host
		if r.DNS != "" && r.DNS != r.Host {
			host = r.DNS
		}
		row := renderRowWidths(widths,
			fmt.Sprintf("%d", i+1), host, zone,
			fmtBytes(r.Bytes), fmt.Sprintf("%d", r.Packets), fmt.Sprintf("%d", r.Flows))
		out = append(out, rowStyle.Render("  "+row))
	}
	return strings.Join(out, "\n")
}

func renderTopProcs(rows []flows.ProcessRollup) string {
	if len(rows) == 0 {
		return subtitleStyle.Render("  no flows with process info — capture must run as a user that can read /proc/*/fd")
	}
	widths := []int{4, 28, 12, 12, 8}
	out := []string{"  " + renderRowWidths(widths,
		"#", "PROCESS", "BYTES", "PACKETS", "FLOWS")}
	for i, r := range rows {
		out = append(out, rowStyle.Render("  "+renderRowWidths(widths,
			fmt.Sprintf("%d", i+1), r.Process,
			fmtBytes(r.Bytes), fmt.Sprintf("%d", r.Packets), fmt.Sprintf("%d", r.Flows))))
	}
	return strings.Join(out, "\n")
}

func renderTopServices(rows []flows.ServiceRollup) string {
	if len(rows) == 0 {
		return subtitleStyle.Render("  no services classified yet")
	}
	widths := []int{4, 16, 6, 8, 12, 12, 8}
	out := []string{"  " + renderRowWidths(widths,
		"#", "SERVICE", "PROTO", "PORT", "BYTES", "PACKETS", "FLOWS")}
	for i, r := range rows {
		out = append(out, rowStyle.Render("  "+renderRowWidths(widths,
			fmt.Sprintf("%d", i+1), r.Service,
			strings.ToUpper(r.Proto), fmt.Sprintf("%d", r.Port),
			fmtBytes(r.Bytes), fmt.Sprintf("%d", r.Packets), fmt.Sprintf("%d", r.Flows))))
	}
	return strings.Join(out, "\n")
}
