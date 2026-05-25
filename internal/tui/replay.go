package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/noahzmr/testudo/internal/metrics"
	"github.com/noahzmr/testudo/internal/replay"
	"github.com/noahzmr/testudo/internal/storage"
)

// ReplayModel renders a static summary plus a scrollable chronological log
// of samples and anomalies for a single past session.
type ReplayModel struct {
	store     *storage.Store
	sessionID string

	loaded    bool
	loadErr   error
	agg       *metrics.Aggregator
	timeline  []timelineRow
	anomalies []storage.AnomalyRow
	flows     []storage.FlowRow

	cursor int
	height int
	width  int
}

type timelineRow struct {
	ts    time.Time
	kind  string
	label string
	text  string
	fail  bool
}

func NewReplay(store *storage.Store, sessionID string) ReplayModel {
	return ReplayModel{store: store, sessionID: sessionID}
}

type replayLoadedMsg struct {
	agg       *metrics.Aggregator
	timeline  []timelineRow
	anomalies []storage.AnomalyRow
	flows     []storage.FlowRow
	err       error
}

func (m ReplayModel) Init() tea.Cmd {
	return loadReplayCmd(m.store, m.sessionID)
}

func loadReplayCmd(store *storage.Store, sessionID string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		agg := metrics.NewAggregator()
		if err := replay.LoadIntoAggregator(ctx, store, sessionID, agg); err != nil {
			return replayLoadedMsg{err: err}
		}
		samples, err := store.SamplesBySession(ctx, sessionID)
		if err != nil {
			return replayLoadedMsg{err: err}
		}
		anomalies, err := store.AnomaliesBySession(ctx, sessionID)
		if err != nil {
			return replayLoadedMsg{err: err}
		}
		fs, _ := store.FlowsBySession(ctx, sessionID, 200)

		timeline := make([]timelineRow, 0, len(samples)+len(anomalies))
		for _, sm := range samples {
			row := timelineRow{ts: sm.TS, kind: kindDisplay(sm.Kind), label: sm.Label, fail: sm.Failed}
			switch sm.Kind {
			case "latency":
				row.text = fmt.Sprintf("%.1fms", sm.Value/1000.0)
			case "packet_loss":
				row.text = "LOST"
				row.fail = true
			case "dns":
				if sm.Failed {
					row.text = "FAIL"
				} else {
					row.text = fmt.Sprintf("%.1fms", sm.Value/1000.0)
				}
			default:
				row.text = fmt.Sprintf("%.0f", sm.Value)
			}
			timeline = append(timeline, row)
		}
		for _, a := range anomalies {
			timeline = append(timeline, timelineRow{
				ts: a.TS, kind: "anomaly", label: a.Severity, text: a.Message, fail: a.Severity == "error",
			})
		}
		// Already chronological by construction (samples then anomalies),
		// but interleave them by timestamp for a true timeline.
		sortByTime(timeline)
		return replayLoadedMsg{agg: agg, timeline: timeline, anomalies: anomalies, flows: fs}
	}
}

func sortByTime(rows []timelineRow) {
	// Insertion sort is fine here: timelines are typically short, and the
	// input is already mostly-ordered (samples block then anomalies block).
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && rows[j-1].ts.After(rows[j].ts) {
			rows[j-1], rows[j] = rows[j], rows[j-1]
			j--
		}
	}
}

func (m ReplayModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case replayLoadedMsg:
		m.loaded = true
		m.loadErr = msg.err
		m.agg = msg.agg
		m.timeline = msg.timeline
		m.anomalies = msg.anomalies
		m.flows = msg.flows
		return m, nil
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.timeline)-1 {
				m.cursor++
			}
		case "pgup":
			m.cursor -= 10
			if m.cursor < 0 {
				m.cursor = 0
			}
		case "pgdown":
			m.cursor += 10
			if m.cursor >= len(m.timeline) {
				m.cursor = len(m.timeline) - 1
			}
		case "g", "home":
			m.cursor = 0
		case "G", "end":
			if len(m.timeline) > 0 {
				m.cursor = len(m.timeline) - 1
			}
		}
	}
	return m, nil
}

func (m ReplayModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Testudo - Replay"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render(fmt.Sprintf("session %s · ↑/↓ scroll · pgup/pgdn · q quit", m.sessionID)))
	b.WriteString("\n\n")

	if !m.loaded {
		b.WriteString(subtitleStyle.Render("loading…"))
		return b.String()
	}
	if m.loadErr != nil {
		b.WriteString(errStyle.Render("replay failed: " + m.loadErr.Error()))
		return b.String()
	}

	b.WriteString(boxStyle.Render(m.renderSummary()))
	b.WriteString("\n")
	b.WriteString(boxStyle.Render(m.renderFlowsBox()))
	b.WriteString("\n")
	b.WriteString(boxStyle.Render(m.renderTimeline()))
	return b.String()
}

func (m ReplayModel) renderSummary() string {
	var rows []string
	rows = append(rows, headerStyle.Render("Targets - aggregated stats"))
	rows = append(rows, renderRow("TARGET", "SENT", "LOSS%", "AVG", "P95", "MIN", "MAX"))
	if m.agg == nil {
		return strings.Join(rows, "\n")
	}
	for _, t := range m.agg.SnapshotTargets() {
		rows = append(rows, renderRow(
			t.Target,
			fmt.Sprintf("%d", t.Sent),
			fmt.Sprintf("%.1f%%", t.LossPct),
			fmtRTT(t.AvgRTT), fmtRTT(t.P95RTT),
			fmtRTT(t.MinRTT), fmtRTT(t.MaxRTT),
		))
	}
	rows = append(rows, "")
	rows = append(rows, headerStyle.Render("DNS - aggregated stats"))
	rows = append(rows, renderRow("NAME", "QUERIES", "FAILURES", "AVG"))
	for _, d := range m.agg.SnapshotDNS() {
		rows = append(rows, renderRow(
			d.Name,
			fmt.Sprintf("%d", d.Queries),
			fmt.Sprintf("%d", d.Failures),
			fmtRTT(d.AvgLatency),
		))
	}
	return strings.Join(rows, "\n")
}

func (m ReplayModel) renderFlowsBox() string {
	var rows []string
	rows = append(rows, headerStyle.Render(fmt.Sprintf("Flows - %d captured", len(m.flows))))
	if len(m.flows) == 0 {
		rows = append(rows, subtitleStyle.Render("  (capture was not enabled for this session)"))
		return strings.Join(rows, "\n")
	}
	rows = append(rows, renderRow("PROTO", "A", "B", "PKTS", "BYTES", "A→B", "B→A"))
	limit := 8
	if len(m.flows) < limit {
		limit = len(m.flows)
	}
	for i := 0; i < limit; i++ {
		f := m.flows[i]
		a := fmt.Sprintf("%s:%d", f.AIP, f.APort)
		bSide := fmt.Sprintf("%s:%d", f.BIP, f.BPort)
		rows = append(rows, renderRow(
			strings.ToUpper(f.Proto),
			a, bSide,
			fmt.Sprintf("%d", f.Packets),
			fmtBytes(f.Bytes),
			fmtBytes(f.BytesAtoB),
			fmtBytes(f.BytesBtoA),
		))
	}
	if len(m.flows) > limit {
		rows = append(rows, dimStyle.Render(fmt.Sprintf("  … %d more flows", len(m.flows)-limit)))
	}
	return strings.Join(rows, "\n")
}

func (m ReplayModel) renderTimeline() string {
	var rows []string
	rows = append(rows, headerStyle.Render(fmt.Sprintf("Timeline - %d events", len(m.timeline))))
	if len(m.timeline) == 0 {
		rows = append(rows, subtitleStyle.Render("  (no samples recorded)"))
		return strings.Join(rows, "\n")
	}

	// Window the timeline around the cursor so the visible region tracks it.
	winSize := 12
	start := m.cursor - winSize/2
	if start < 0 {
		start = 0
	}
	end := start + winSize
	if end > len(m.timeline) {
		end = len(m.timeline)
		start = end - winSize
		if start < 0 {
			start = 0
		}
	}
	for i := start; i < end; i++ {
		r := m.timeline[i]
		ts := r.ts.Local().Format("15:04:05.000")
		line := fmt.Sprintf("  %s  %-12s  %-20s  %s", ts, r.kind, r.label, r.text)
		style := rowStyle
		if r.fail {
			style = errStyle
		} else if r.kind == "anomaly" {
			style = warnStyle
		}
		if i == m.cursor {
			rows = append(rows, selectedRowStyle.Render(line))
		} else {
			rows = append(rows, style.Render(line))
		}
	}
	rows = append(rows, dimStyle.Render(fmt.Sprintf("\n  showing %d–%d of %d", start+1, end, len(m.timeline))))
	return strings.Join(rows, "\n")
}

func kindDisplay(kind string) string {
	switch kind {
	case "latency":
		return "latency"
	case "packet_loss":
		return "loss"
	case "dns":
		return "dns"
	default:
		return kind
	}
}

// RunReplay launches the replay TUI and blocks until the user quits.
func RunReplay(ctx context.Context, m ReplayModel) error {
	p := tea.NewProgram(m, tea.WithAltScreen())
	go func() {
		<-ctx.Done()
		p.Quit()
	}()
	_, err := p.Run()
	return err
}
