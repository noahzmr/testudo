package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Modal is a transient input overlay rendered on top of the active tab.
// It owns its own focus and consumes key events until Done returns true.
type Modal interface {
	Title() string
	Init() tea.Cmd
	Update(msg tea.Msg) tea.Cmd
	View() string
	Done() bool // when true, the App closes the modal
	Result() any
}

// modalFrame wraps any modal content in a bordered box. Padding/margin are
// kept modest so the modal still fits inside a 60-column terminal once the
// app centres it via lipgloss.Place.
var modalFrame = lipgloss.NewStyle().
	Border(lipgloss.DoubleBorder()).
	BorderForeground(lipgloss.Color("214")).
	Padding(0, 2).
	Margin(0, 0)

// FormField represents one editable field in a generic Form modal.
type FormField struct {
	Label    string
	Value    string
	Hint     string // shown beneath the field when focused
	Validate func(string) error
}

// FormModal collects N text fields then returns them as Result()-of-map.
// It's the workhorse for "Add NAT rule" / "Add Route" / similar wizards.
type FormModal struct {
	heading  string
	fields   []FormField
	cursor   int
	done     bool
	cancel   bool
	errMsg   string
	submitFn func(values map[string]string) error
}

func NewFormModal(heading string, fields []FormField, submit func(map[string]string) error) *FormModal {
	return &FormModal{heading: heading, fields: fields, submitFn: submit}
}

func (m *FormModal) Title() string { return m.heading }
func (m *FormModal) Init() tea.Cmd { return nil }
func (m *FormModal) Done() bool    { return m.done }
func (m *FormModal) Result() any {
	if m.cancel {
		return nil
	}
	values := make(map[string]string, len(m.fields))
	for _, f := range m.fields {
		values[f.Label] = f.Value
	}
	return values
}

func (m *FormModal) Update(msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return nil
	}
	switch key.String() {
	case "esc":
		m.cancel = true
		m.done = true
	case "tab", "down":
		if m.cursor < len(m.fields)-1 {
			m.cursor++
		}
	case "shift+tab", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "enter":
		// Validate all fields, then submit.
		for _, f := range m.fields {
			if f.Validate == nil {
				continue
			}
			if err := f.Validate(f.Value); err != nil {
				m.errMsg = f.Label + ": " + err.Error()
				return nil
			}
		}
		if m.submitFn != nil {
			values := make(map[string]string, len(m.fields))
			for _, f := range m.fields {
				values[f.Label] = f.Value
			}
			if err := m.submitFn(values); err != nil {
				m.errMsg = err.Error()
				return nil
			}
		}
		m.done = true
	case "backspace":
		if len(m.fields[m.cursor].Value) > 0 {
			v := m.fields[m.cursor].Value
			m.fields[m.cursor].Value = v[:len(v)-1]
		}
	default:
		// Treat single-rune key presses as character input.
		s := key.String()
		if len(s) == 1 || s == "space" {
			ch := s
			if s == "space" {
				ch = " "
			}
			m.fields[m.cursor].Value += ch
		}
	}
	return nil
}

func (m *FormModal) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.heading))
	b.WriteString("\n\n")
	// Label column width keyed off the longest label so labels still align
	// without forcing a fixed 22-char gutter on narrow terminals.
	labelW := 6
	for _, f := range m.fields {
		if w := lipgloss.Width(f.Label); w > labelW {
			labelW = w
		}
	}
	for i, f := range m.fields {
		marker := "  "
		if i == m.cursor {
			marker = "▸ "
		}
		val := f.Value
		if i == m.cursor {
			val += "█"
		}
		row := fmt.Sprintf("%s%-*s %s", marker, labelW+1, f.Label+":", val)
		if i == m.cursor {
			b.WriteString(headerStyle.Render(row))
		} else {
			b.WriteString(rowStyle.Render(row))
		}
		b.WriteString("\n")
		if i == m.cursor && f.Hint != "" {
			b.WriteString(dimStyle.Render("    " + f.Hint))
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	if m.errMsg != "" {
		// Reuse the same EPERM / writes-disabled hint pipeline the tabs
		// use, so operators see the same actionable line in both places.
		errOnly := fmt.Errorf("%s", m.errMsg)
		for _, line := range netopsErrLines(errOnly) {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	b.WriteString(subtitleStyle.Render("  tab next · shift+tab prev · enter submit · esc cancel"))
	return modalFrame.Render(b.String())
}
