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
//  1. Top hosts        - who am I talking to, how much, LAN or WAN
//  2. Top processes    - which programs generate the traffic
//  3. Top services     - which upper-layer protocols dominate
//
// All three update on every dashboard tick; cursor selects the section
// (hosts / processes / services) so the user can flip between them with
// ←/=> without leaving the tab.
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
		{Key: "←/=> · h/l", Desc: "switch between hosts / processes / services"},
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
			if t.section < 3 {
				t.section++
			}
		case "1":
			t.section = 0
		case "2":
			t.section = 1
		case "3":
			t.section = 2
		case "4":
			t.section = 3
		}
	}
	return nil
}

func (t *talkersTab) View(w, h int) string {
	var b strings.Builder
	hosts := flows.TopHosts(t.rows, 20)
	procs := flows.TopProcesses(t.rows, 20)
	svcs := flows.TopServices(t.rows, 20)
	matrix := flows.LANMatrix(t.rows, 20)

	hdr := []string{
		sectionLabel("Hosts", len(hosts), t.section == 0),
		sectionLabel("Processes", len(procs), t.section == 1),
		sectionLabel("Services", len(svcs), t.section == 2),
		sectionLabel("LAN matrix", len(matrix), t.section == 3),
	}
	b.WriteString(headerStyle.Render("Top talkers - ←/=> switch · 1 hosts · 2 processes · 3 services · 4 LAN matrix"))
	b.WriteString("\n  ")
	b.WriteString(strings.Join(hdr, "    "))
	b.WriteString("\n\n")

	// innerW: inside boxStyle (border 2 + pad 2 = 4) and the rows have a
	// further "  " indent, so the actual table width is w - 6.
	innerW := w - 6

	switch t.section {
	case 0:
		b.WriteString(renderTopHosts(innerW, hosts))
	case 1:
		b.WriteString(renderTopProcs(innerW, procs))
	case 2:
		b.WriteString(renderTopServices(innerW, svcs))
	case 3:
		b.WriteString(renderLANMatrix(innerW, matrix))
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

func renderTopHosts(innerW int, rows []flows.HostRollup) string {
	if len(rows) == 0 {
		return subtitleStyle.Render("  no flows yet - start capture (Flows tab => 's')")
	}
	widths := []int{4, 18, 26, 6, 11, 9, 7}
	out := []string{"  " + renderTableRow(innerW, widths,
		"#", "IP", "DNS", "ZONE", "BYTES", "PACKETS", "FLOWS")}
	for i, r := range rows {
		zone := okStyle.Render("WAN")
		if r.IsLAN {
			zone = dimStyle.Render("LAN")
		}
		dns := r.DNS
		if dns == "" || dns == r.Host {
			dns = dimStyle.Render("-")
		}
		row := renderTableRow(innerW, widths,
			fmt.Sprintf("%d", i+1), r.Host, dns, zone,
			fmtBytes(r.Bytes), fmt.Sprintf("%d", r.Packets), fmt.Sprintf("%d", r.Flows))
		out = append(out, rowStyle.Render("  "+row))
	}
	return strings.Join(out, "\n")
}

func renderTopProcs(innerW int, rows []flows.ProcessRollup) string {
	if len(rows) == 0 {
		return subtitleStyle.Render("  no flows with process info - capture must run as a user that can read /proc/*/fd")
	}
	widths := []int{4, 28, 12, 12, 8}
	out := []string{"  " + renderTableRow(innerW, widths,
		"#", "PROCESS", "BYTES", "PACKETS", "FLOWS")}
	for i, r := range rows {
		out = append(out, rowStyle.Render("  "+renderTableRow(innerW, widths,
			fmt.Sprintf("%d", i+1), r.Process,
			fmtBytes(r.Bytes), fmt.Sprintf("%d", r.Packets), fmt.Sprintf("%d", r.Flows))))
	}
	return strings.Join(out, "\n")
}

func renderLANMatrix(innerW int, rows []flows.LANPair) string {
	if len(rows) == 0 {
		return subtitleStyle.Render("  no LAN-to-LAN flows yet · capture must be running and at least one host must be talking to another LAN host")
	}
	widths := []int{4, 22, 22, 12, 10, 8}
	out := []string{"  " + renderTableRow(innerW, widths,
		"#", "A", "B", "BYTES", "PACKETS", "FLOWS")}
	for i, r := range rows {
		out = append(out, rowStyle.Render("  "+renderTableRow(innerW, widths,
			fmt.Sprintf("%d", i+1), r.A, r.B,
			fmtBytes(r.Bytes), fmt.Sprintf("%d", r.Packets), fmt.Sprintf("%d", r.Flows))))
	}
	return strings.Join(out, "\n")
}

func renderTopServices(innerW int, rows []flows.ServiceRollup) string {
	if len(rows) == 0 {
		return subtitleStyle.Render("  no services classified yet")
	}
	widths := []int{4, 16, 6, 8, 12, 12, 8}
	out := []string{"  " + renderTableRow(innerW, widths,
		"#", "SERVICE", "PROTO", "PORT", "BYTES", "PACKETS", "FLOWS")}
	for i, r := range rows {
		out = append(out, rowStyle.Render("  "+renderTableRow(innerW, widths,
			fmt.Sprintf("%d", i+1), r.Service,
			strings.ToUpper(r.Proto), fmt.Sprintf("%d", r.Port),
			fmtBytes(r.Bytes), fmt.Sprintf("%d", r.Packets), fmt.Sprintf("%d", r.Flows))))
	}
	return strings.Join(out, "\n")
}
