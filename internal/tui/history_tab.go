// history_tab.go - read-only browsing of past sessions and the snapshots
// captured during them. The tab has three modes:
//
//   list    - newest-first session table; ↑/↓/j/k + Enter to drill in.
//   detail  - picked session's anomaly timeline + snapshot index;
//             cursor + Enter on a snapshot row to inspect.
//   inspect - pretty-printed JSON of one snapshot, scrolled by the chrome.
//
// Backwards navigation is Esc / Backspace; the cursor on each level is
// preserved so returning from a detail view lands on the same session row.

package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/storage"
)

type historyMode int

const (
	historyModeList historyMode = iota
	historyModeDetail
	historyModeInspect
)

type historyTab struct {
	eng *engine.Engine
	app *App

	mode historyMode

	// list state
	sessions []storage.SessionRecord
	cursor   int
	filter   string // case-insensitive substring against id / target list
	listErr  error

	// detail state (set when entering historyModeDetail)
	selected   *storage.SessionRecord
	anomalies  []storage.AnomalyRow
	snapIndex  []storage.SnapshotIndexEntry
	snapCursor int
	detailErr  error

	// inspect state (set when entering historyModeInspect)
	inspectRow  *storage.SnapshotRow
	inspectJSON string
	inspectErr  error
}

func newHistoryTab(eng *engine.Engine, app *App) *historyTab {
	return &historyTab{eng: eng, app: app}
}

func (t *historyTab) Title() string    { return "History" }
func (t *historyTab) ShortKey() string { return "" }

func (t *historyTab) Init() tea.Cmd { return t.loadListCmd() }

func (t *historyTab) HelpHints() []KeyHint {
	switch t.mode {
	case historyModeDetail:
		return []KeyHint{
			{Key: "↑/↓ · j/k", Desc: "select snapshot row"},
			{Key: "enter", Desc: "inspect snapshot JSON"},
			{Key: "esc · backspace", Desc: "back to session list"},
			{Key: "r", Desc: "reload"},
		}
	case historyModeInspect:
		return []KeyHint{
			{Key: "PgUp/PgDn", Desc: "scroll JSON payload"},
			{Key: "esc · backspace", Desc: "back to session detail"},
		}
	}
	return []KeyHint{
		{Key: "↑/↓ · j/k", Desc: "select session"},
		{Key: "enter", Desc: "open session detail"},
		{Key: "/", Desc: "filter by id or target"},
		{Key: "r", Desc: "reload"},
	}
}

// SetFilter implements Filterable. Only meaningful on the list view; we keep
// it stored so users can switch in/out of detail and find the same filter.
func (t *historyTab) SetFilter(s string) {
	t.filter = strings.ToLower(s)
	t.cursor = 0
}

// ---- messages produced by background loads ----

type historyListLoadedMsg struct {
	sessions []storage.SessionRecord
	err      error
}
type historyDetailLoadedMsg struct {
	sessionID string
	anomalies []storage.AnomalyRow
	snapIndex []storage.SnapshotIndexEntry
	err       error
}
type historySnapshotLoadedMsg struct {
	row    storage.SnapshotRow
	pretty string
	err    error
}

func (t *historyTab) loadListCmd() tea.Cmd {
	store := t.eng.Store()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		recs, err := store.ListSessions(ctx, 100)
		return historyListLoadedMsg{sessions: recs, err: err}
	}
}

func (t *historyTab) loadDetailCmd(sessionID string) tea.Cmd {
	store := t.eng.Store()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		anomalies, err := store.AnomaliesBySession(ctx, sessionID)
		if err != nil {
			return historyDetailLoadedMsg{sessionID: sessionID, err: err}
		}
		snapIdx, err := store.SnapshotIndexBySession(ctx, sessionID)
		return historyDetailLoadedMsg{
			sessionID: sessionID, anomalies: anomalies, snapIndex: snapIdx, err: err,
		}
	}
}

func (t *historyTab) loadSnapshotCmd(id int64) tea.Cmd {
	store := t.eng.Store()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		row, err := store.SnapshotByID(ctx, id)
		if err != nil {
			return historySnapshotLoadedMsg{err: err}
		}
		var pretty bytes.Buffer
		if jerr := json.Indent(&pretty, row.PayloadRaw, "", "  "); jerr != nil {
			// Payload exists but isn't JSON - show it verbatim so the user
			// can still see what was stored. This shouldn't happen with the
			// current snapshotter, but the storage layer is schema-agnostic.
			return historySnapshotLoadedMsg{row: row, pretty: string(row.PayloadRaw)}
		}
		return historySnapshotLoadedMsg{row: row, pretty: pretty.String()}
	}
}

// ---- Update ----

func (t *historyTab) Update(msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case slowTickMsg:
		// Auto-refresh only the list - detail/inspect are point-in-time
		// reads the user explicitly drilled into.
		if t.mode == historyModeList {
			return t.loadListCmd()
		}
	case historyListLoadedMsg:
		t.sessions = m.sessions
		t.listErr = m.err
		if t.cursor >= len(t.sessions) {
			t.cursor = max(0, len(t.sessions)-1)
		}
	case historyDetailLoadedMsg:
		// Stale guard: a fast user could have hit Esc before the result
		// arrived. Only apply if we still want this session's detail.
		if t.selected == nil || t.selected.ID != m.sessionID {
			return nil
		}
		t.anomalies = m.anomalies
		t.snapIndex = m.snapIndex
		t.detailErr = m.err
		if t.snapCursor >= len(t.snapIndex) {
			t.snapCursor = max(0, len(t.snapIndex)-1)
		}
	case historySnapshotLoadedMsg:
		t.inspectRow = &m.row
		t.inspectJSON = m.pretty
		t.inspectErr = m.err
		t.app.bodyScroll = 0 // start at top of the JSON payload
	case tea.KeyMsg:
		return t.handleKey(m)
	}
	return nil
}

func (t *historyTab) handleKey(m tea.KeyMsg) tea.Cmd {
	switch t.mode {
	case historyModeList:
		return t.handleListKey(m)
	case historyModeDetail:
		return t.handleDetailKey(m)
	case historyModeInspect:
		return t.handleInspectKey(m)
	}
	return nil
}

func (t *historyTab) handleListKey(m tea.KeyMsg) tea.Cmd {
	visible := t.visibleSessions()
	switch m.String() {
	case "up", "k":
		if t.cursor > 0 {
			t.cursor--
		}
	case "down", "j":
		if t.cursor < len(visible)-1 {
			t.cursor++
		}
	case "r":
		return t.loadListCmd()
	case "enter":
		if t.cursor < 0 || t.cursor >= len(visible) {
			return nil
		}
		sel := visible[t.cursor]
		t.selected = &sel
		t.anomalies = nil
		t.snapIndex = nil
		t.snapCursor = 0
		t.detailErr = nil
		t.mode = historyModeDetail
		t.app.bodyScroll = 0
		return t.loadDetailCmd(sel.ID)
	}
	return nil
}

func (t *historyTab) handleDetailKey(m tea.KeyMsg) tea.Cmd {
	switch m.String() {
	case "esc", "backspace":
		t.mode = historyModeList
		t.selected = nil
		t.app.bodyScroll = 0
		return nil
	case "up", "k":
		if t.snapCursor > 0 {
			t.snapCursor--
		}
	case "down", "j":
		if t.snapCursor < len(t.snapIndex)-1 {
			t.snapCursor++
		}
	case "r":
		if t.selected != nil {
			return t.loadDetailCmd(t.selected.ID)
		}
	case "enter":
		if t.snapCursor < 0 || t.snapCursor >= len(t.snapIndex) {
			return nil
		}
		entry := t.snapIndex[t.snapCursor]
		t.inspectRow = nil
		t.inspectJSON = ""
		t.inspectErr = nil
		t.mode = historyModeInspect
		t.app.bodyScroll = 0
		return t.loadSnapshotCmd(entry.ID)
	}
	return nil
}

func (t *historyTab) handleInspectKey(m tea.KeyMsg) tea.Cmd {
	switch m.String() {
	case "esc", "backspace":
		t.mode = historyModeDetail
		t.inspectRow = nil
		t.inspectJSON = ""
		t.inspectErr = nil
		t.app.bodyScroll = 0
	}
	return nil
}

// visibleSessions applies the case-insensitive filter to t.sessions. Match
// is against id or any target string. Filter is normalized in SetFilter.
func (t *historyTab) visibleSessions() []storage.SessionRecord {
	if t.filter == "" {
		return t.sessions
	}
	out := make([]storage.SessionRecord, 0, len(t.sessions))
	for _, s := range t.sessions {
		if strings.Contains(strings.ToLower(s.ID), t.filter) {
			out = append(out, s)
			continue
		}
		for _, tgt := range s.Targets {
			if strings.Contains(strings.ToLower(tgt), t.filter) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// ---- View ----

func (t *historyTab) View(w, h int) string {
	switch t.mode {
	case historyModeDetail:
		return t.viewDetail(w)
	case historyModeInspect:
		return t.viewInspect(w)
	}
	return t.viewList(w)
}

func (t *historyTab) viewList(w int) string {
	visible := t.visibleSessions()
	title := fmt.Sprintf("History - %d session(s)", len(t.sessions))
	if t.filter != "" {
		title = fmt.Sprintf("History - %d / %d match `%s`",
			len(visible), len(t.sessions), t.filter)
	}
	rows := []string{
		headerStyle.Render(title),
		renderRowWidths([]int{16, 21, 21, 12, 28},
			"ID", "STARTED", "ENDED", "DURATION", "TARGETS"),
	}
	if t.listErr != nil {
		rows = append(rows, errStyle.Render("  load failed: "+t.listErr.Error()))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	if len(t.sessions) == 0 {
		rows = append(rows, subtitleStyle.Render(
			"  no sessions persisted yet - sessions are written on engine start"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	if len(visible) == 0 {
		rows = append(rows, subtitleStyle.Render("  no session matches the active filter"))
		return boxStyle.Render(strings.Join(rows, "\n"))
	}
	for i, s := range visible {
		ended := "-"
		dur := "running"
		if s.EndedAt != nil {
			ended = s.EndedAt.Local().Format("2006-01-02 15:04:05")
			dur = s.EndedAt.Sub(s.StartedAt).Truncate(time.Second).String()
		}
		row := renderRowWidths([]int{16, 21, 21, 12, 28},
			shortID(s.ID),
			s.StartedAt.Local().Format("2006-01-02 15:04:05"),
			ended, dur, strings.Join(s.Targets, ", "))
		if i == t.cursor {
			rows = append(rows, selectedRowStyle.Render(row))
		} else {
			rows = append(rows, rowStyle.Render(row))
		}
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

func (t *historyTab) viewDetail(w int) string {
	if t.selected == nil {
		return boxStyle.Render(errStyle.Render("no session selected"))
	}
	s := t.selected
	var b strings.Builder

	// --- header summary ---
	summary := []string{
		headerStyle.Render("Session " + s.ID),
		fmt.Sprintf("  started : %s", s.StartedAt.Local().Format(time.RFC3339)),
	}
	if s.EndedAt != nil {
		summary = append(summary,
			fmt.Sprintf("  ended   : %s", s.EndedAt.Local().Format(time.RFC3339)),
			fmt.Sprintf("  duration: %s", s.EndedAt.Sub(s.StartedAt).Truncate(time.Second)))
	} else {
		summary = append(summary, "  ended   : (still running)")
	}
	if len(s.Targets) > 0 {
		summary = append(summary, "  targets : "+strings.Join(s.Targets, ", "))
	}
	if s.Note != "" {
		summary = append(summary, "  note    : "+s.Note)
	}
	summary = append(summary,
		fmt.Sprintf("  counts  : %d anomalies · %d snapshots",
			len(t.anomalies), len(t.snapIndex)))
	b.WriteString(boxStyle.Render(strings.Join(summary, "\n")))
	b.WriteString("\n")

	if t.detailErr != nil {
		b.WriteString(boxStyle.Render(errStyle.Render("load failed: " + t.detailErr.Error())))
		return b.String()
	}

	// --- anomaly timeline ---
	aRows := []string{headerStyle.Render(fmt.Sprintf("Anomaly timeline (%d)", len(t.anomalies)))}
	if len(t.anomalies) == 0 {
		aRows = append(aRows, subtitleStyle.Render("  no anomalies recorded for this session"))
	} else {
		for _, a := range t.anomalies {
			sev := severityStyle(a.Severity).Render(fmt.Sprintf("%-8s", a.Severity))
			aRows = append(aRows, fmt.Sprintf("  %s  %s  %s",
				subtitleStyle.Render(a.TS.Local().Format("15:04:05")), sev, a.Message))
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(aRows, "\n")))
	b.WriteString("\n")

	// --- snapshot index ---
	sRows := []string{
		headerStyle.Render(fmt.Sprintf("Snapshots (%d) - Enter to inspect", len(t.snapIndex))),
		renderRowWidths([]int{8, 14, 24}, "#", "KIND", "TIMESTAMP"),
	}
	if len(t.snapIndex) == 0 {
		sRows = append(sRows, subtitleStyle.Render(
			"  no snapshots captured - netops snapshotter may have been disabled"))
	} else {
		for i, e := range t.snapIndex {
			row := renderRowWidths([]int{8, 14, 24},
				fmt.Sprintf("%d", e.ID), e.Kind,
				e.TS.Local().Format("2006-01-02 15:04:05"))
			if i == t.snapCursor {
				sRows = append(sRows, selectedRowStyle.Render(row))
			} else {
				sRows = append(sRows, rowStyle.Render(row))
			}
		}
	}
	b.WriteString(boxStyle.Render(strings.Join(sRows, "\n")))
	return b.String()
}

func (t *historyTab) viewInspect(w int) string {
	var b strings.Builder
	hdr := "Snapshot - loading…"
	if t.inspectRow != nil {
		hdr = fmt.Sprintf("Snapshot #%d · %s · %s",
			t.inspectRow.ID, t.inspectRow.Kind,
			t.inspectRow.TS.Local().Format(time.RFC3339))
	}
	b.WriteString(headerStyle.Render(hdr))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("esc / backspace to go back · PgUp/PgDn to scroll"))
	b.WriteString("\n\n")

	if t.inspectErr != nil {
		b.WriteString(errStyle.Render("load failed: " + t.inspectErr.Error()))
		return boxStyle.Render(b.String())
	}
	if t.inspectJSON == "" {
		b.WriteString(subtitleStyle.Render("  …loading payload"))
		return boxStyle.Render(b.String())
	}
	b.WriteString(t.inspectJSON)
	return boxStyle.Render(b.String())
}
