package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/engine"
)

// tcpdumpTab drives the tcpdump capture subsystem from the TUI.
//
// Each row in the table is one capture job — either currently running or
// finished. Adding a capture opens a guided "filter wizard" modal where
// every field is optional; the BPF expression is assembled from the
// structured inputs, and a "raw" pass-through field lets power users
// supply their own expression.
type tcpdumpTab struct {
	eng    *engine.Engine
	app    *App
	jobs   []capture.TCPDumpJob
	cursor int
	err    error
}

func newTCPDumpTab(eng *engine.Engine, app *App) *tcpdumpTab {
	return &tcpdumpTab{eng: eng, app: app}
}

func (t *tcpdumpTab) Title() string    { return "TCPDump" }
func (t *tcpdumpTab) ShortKey() string { return "8" }
func (t *tcpdumpTab) Init() tea.Cmd    { return nil }
func (t *tcpdumpTab) HelpHints() []KeyHint {
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select capture"},
		{Key: "a", Desc: "new capture (with filter wizard)"},
		{Key: "x", Desc: "stop / remove the selected capture"},
		{Key: "o", Desc: "show full output path of selected capture"},
		{Key: "r", Desc: "refresh"},
	}
}

func (t *tcpdumpTab) refresh() {
	t.jobs = t.eng.TCPDump().List()
	if t.cursor >= len(t.jobs) {
		t.cursor = len(t.jobs) - 1
	}
	if t.cursor < 0 {
		t.cursor = 0
	}
}

func (t *tcpdumpTab) Update(msg tea.Msg) tea.Cmd {
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
			if t.cursor < len(t.jobs)-1 {
				t.cursor++
			}
		case "a":
			return t.openAddModal()
		case "x":
			return t.removeSelected()
		case "o":
			return t.showSelectedPath()
		case "r":
			t.refresh()
		}
	}
	return nil
}

// openAddModal is both "new capture" and "filter wizard" — every wizard
// field maps onto a FilterSpec component, plus the run-time knobs
// (interface, name, size cap, duration) live in the same form.
func (t *tcpdumpTab) openAddModal() tea.Cmd {
	if !capture.TCPDumpAvailable() {
		return statusCmd("tcpdump binary not found — install it first (apt install tcpdump)")
	}
	defaultIface := ""
	if names, err := capture.AutoDiscover(nil); err == nil && len(names) > 0 {
		defaultIface = names[0]
	}
	modal := NewFormModal("New TCPDump capture",
		[]FormField{
			// Runtime knobs
			{Label: "iface", Value: defaultIface, Hint: "interface name; blank uses tcpdump's default"},
			{Label: "name", Value: "", Hint: "label for the file (optional)"},
			{Label: "max_size_mb", Value: "64", Hint: "rotate when file reaches N MiB; 0 = no limit"},
			{Label: "duration_s", Value: "0", Hint: "auto-stop after N seconds; 0 = run until you stop"},
			// Filter wizard fields — each one optional
			{Label: "proto", Value: "", Hint: "tcp / udp / icmp / blank=any"},
			{Label: "src_host", Value: "", Hint: "source IP or hostname; blank=any"},
			{Label: "dst_host", Value: "", Hint: "destination IP or hostname; blank=any"},
			{Label: "src_port", Value: "", Hint: "source port; blank=any"},
			{Label: "dst_port", Value: "", Hint: "destination port; blank=any"},
			{Label: "raw_filter", Value: "", Hint: "extra raw BPF appended; blank=none"},
		},
		func(values map[string]string) error {
			maxSize, err := parseNonNegInt(values["max_size_mb"], 64)
			if err != nil {
				return fmt.Errorf("max_size_mb: %w", err)
			}
			durSec, err := parseNonNegInt(values["duration_s"], 0)
			if err != nil {
				return fmt.Errorf("duration_s: %w", err)
			}
			spec := capture.FilterSpec{
				Proto:     strings.TrimSpace(values["proto"]),
				SrcHost:   strings.TrimSpace(values["src_host"]),
				DstHost:   strings.TrimSpace(values["dst_host"]),
				SrcPort:   strings.TrimSpace(values["src_port"]),
				DstPort:   strings.TrimSpace(values["dst_port"]),
				RawAppend: strings.TrimSpace(values["raw_filter"]),
			}
			bpf := spec.Build()
			_, err = t.eng.TCPDump().Start(
				strings.TrimSpace(values["iface"]),
				strings.TrimSpace(values["name"]),
				bpf,
				maxSize,
				time.Duration(durSec)*time.Second,
			)
			return err
		},
	)
	return t.app.SetModal(modal)
}

func (t *tcpdumpTab) removeSelected() tea.Cmd {
	if t.cursor < 0 || t.cursor >= len(t.jobs) {
		return nil
	}
	j := t.jobs[t.cursor]
	if j.State == "running" {
		if err := t.eng.TCPDump().Stop(j.ID); err != nil {
			return statusCmd("stop failed: " + err.Error())
		}
		return statusCmd("stopping " + j.ID + "…")
	}
	if err := t.eng.TCPDump().Remove(j.ID); err != nil {
		return statusCmd("remove failed: " + err.Error())
	}
	return statusCmd("removed " + j.ID + " (file deleted)")
}

func (t *tcpdumpTab) showSelectedPath() tea.Cmd {
	if t.cursor < 0 || t.cursor >= len(t.jobs) {
		return nil
	}
	return statusCmd(t.jobs[t.cursor].OutputPath)
}

func (t *tcpdumpTab) View(w, h int) string {
	rows := []string{headerStyle.Render(fmt.Sprintf(
		"TCPDump — %d capture(s) · a=new · x=stop/remove · o=path · r=refresh",
		len(t.jobs)))}
	if t.err != nil {
		rows = append(rows, netopsErrLines(t.err)...)
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	if !capture.TCPDumpAvailable() {
		rows = append(rows,
			warnStyle.Render("  tcpdump binary missing — install it to use this tab"),
			dimStyle.Render("    Debian/Ubuntu:  sudo apt install tcpdump"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	if len(t.jobs) == 0 {
		rows = append(rows, subtitleStyle.Render(
			"  no captures yet — press 'a' to start a new tcpdump"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}

	widths := []int{8, 9, 10, 10, 28, 36}
	rows = append(rows, "  "+renderRowWidths(widths,
		"ID", "STATE", "IFACE", "SIZE", "FILTER", "FILE"))
	for i, j := range t.jobs {
		state := stateStyleFor(j.State).Render(j.State)
		fileShort := shortenMid(j.OutputPath, 36)
		filterShort := orDash(shortenMid(j.Filter, 28))
		row := renderRowWidths(widths,
			j.ID, state, j.Iface, fmtBytes(uint64(j.Bytes)),
			filterShort, fileShort)
		marker := "  "
		if i == t.cursor {
			marker = "▸ "
		}
		if i == t.cursor {
			rows = append(rows, selectedRowStyle.Render(marker+row))
		} else {
			rows = append(rows, rowStyle.Render(marker+row))
		}
	}
	// Footer: show the selected job's full filter + path on a second line so
	// the cursor row stays compact in the table.
	if t.cursor >= 0 && t.cursor < len(t.jobs) {
		sel := t.jobs[t.cursor]
		rows = append(rows, "")
		rows = append(rows, dimStyle.Render(fmt.Sprintf("  filter: %s", orDash(sel.Filter))))
		rows = append(rows, dimStyle.Render(fmt.Sprintf("  file:   %s", sel.OutputPath)))
		if sel.ExitErr != "" {
			rows = append(rows, errStyle.Render("  error:  "+sel.ExitErr))
		}
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

func stateStyleFor(state string) lipgloss.Style {
	switch state {
	case "running":
		return okStyle
	case "stopped":
		return rowStyle
	case "failed":
		return errStyle
	}
	return rowStyle
}

// parseNonNegInt parses s as a non-negative integer. Empty string returns
// the supplied default.
func parseNonNegInt(s string, def int) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a number: %q", s)
	}
	if v < 0 {
		return 0, fmt.Errorf("must be ≥ 0")
	}
	return v, nil
}

// shortenMid trims the middle of s with an ellipsis so the ends remain
// visible. Useful for long paths.
func shortenMid(s string, max int) string {
	if max <= 3 || len(s) <= max {
		return s
	}
	keep := (max - 1) / 2
	return s[:keep] + "…" + s[len(s)-(max-1-keep):]
}
