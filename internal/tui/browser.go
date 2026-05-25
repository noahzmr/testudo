package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/noahzmr/testudo/internal/replay"
	"github.com/noahzmr/testudo/internal/storage"
)

// BrowserModel is an interactive list of past sessions.
type BrowserModel struct {
	store     *storage.Store
	sessions  []replay.SessionSummary
	cursor    int
	pageSize  int
	width     int
	height    int
	loadErr   error
	openInTUI bool   // set true when user picks a session to replay
	picked    string // selected session id
	statusMsg string
}

func NewBrowser(store *storage.Store) BrowserModel {
	return BrowserModel{store: store, pageSize: 20}
}

func (m BrowserModel) Init() tea.Cmd {
	return loadSessionsCmd(m.store)
}

type sessionsLoadedMsg struct {
	sessions []replay.SessionSummary
	err      error
}

func loadSessionsCmd(store *storage.Store) tea.Cmd {
	return func() tea.Msg {
		s, err := replay.List(context.Background(), store, 200)
		return sessionsLoadedMsg{sessions: s, err: err}
	}
}

func (m BrowserModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case sessionsLoadedMsg:
		m.sessions, m.loadErr = msg.sessions, msg.err
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
			if m.cursor < len(m.sessions)-1 {
				m.cursor++
			}
		case "g", "home":
			m.cursor = 0
		case "G", "end":
			if len(m.sessions) > 0 {
				m.cursor = len(m.sessions) - 1
			}
		case "enter":
			if len(m.sessions) > 0 {
				m.picked = m.sessions[m.cursor].ID
				m.openInTUI = true
				return m, tea.Quit
			}
		case "r":
			return m, loadSessionsCmd(m.store)
		}
	}
	return m, nil
}

// Picked reports the session id the user selected with Enter, or "" if
// they quit without selecting.
func (m BrowserModel) Picked() string { return m.picked }

func (m BrowserModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Testudo - Session Browser"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("↑/↓ navigate · enter replay · r refresh · q quit"))
	b.WriteString("\n\n")

	if m.loadErr != nil {
		b.WriteString(errStyle.Render("error loading sessions: " + m.loadErr.Error()))
		return b.String()
	}
	if len(m.sessions) == 0 {
		b.WriteString(subtitleStyle.Render("no sessions recorded yet - run `testudo live` first"))
		return b.String()
	}

	header := renderRow("ID", "STARTED", "DURATION", "TARGETS")
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")

	for i, s := range m.sessions {
		dur := "live"
		if s.EndedAt != nil {
			dur = s.Duration.Truncate(time.Second).String()
		}
		row := renderRow(
			s.ID,
			s.StartedAt.Local().Format("2006-01-02 15:04"),
			dur,
			strings.Join(s.Targets, ","),
		)
		if i == m.cursor {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(rowStyle.Render(row))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	if m.statusMsg != "" {
		b.WriteString(dimStyle.Render(m.statusMsg))
	} else {
		b.WriteString(dimStyle.Render(fmt.Sprintf("%d sessions", len(m.sessions))))
	}
	return b.String()
}

// RunBrowser blocks until the user quits or selects a session. Returns the
// selected session ID (empty if none).
func RunBrowser(ctx context.Context, m BrowserModel) (string, error) {
	p := tea.NewProgram(m, tea.WithAltScreen())
	go func() {
		<-ctx.Done()
		p.Quit()
	}()
	final, err := p.Run()
	if err != nil {
		return "", err
	}
	if bm, ok := final.(BrowserModel); ok {
		return bm.Picked(), nil
	}
	return "", nil
}
