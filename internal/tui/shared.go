package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Shared styles. Bumping any of these globally re-skins the whole TUI.
var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	subtitleStyle = lipgloss.NewStyle().Faint(true)
	headerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	rowStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))

	tabActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("63")).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Padding(0, 1)

	selectedRowStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("63"))

	okStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	critStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("196"))

	cellStyle = lipgloss.NewStyle().PaddingRight(2)
	boxStyle  = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(0, 1)
)

// severityStyle picks a colour for a 4-level severity string.
func severityStyle(s string) lipgloss.Style {
	switch s {
	case "INFO":
		return okStyle
	case "WARN":
		return warnStyle
	case "ERROR":
		return errStyle
	case "CRITICAL":
		return critStyle
	}
	return rowStyle
}

func renderRow(cells ...string) string {
	out := make([]string, len(cells))
	widths := []int{8, 24, 24, 8, 12, 12, 12, 14, 8}
	for i, c := range cells {
		w := 10
		if i < len(widths) {
			w = widths[i]
		}
		out[i] = cellStyle.Render(padOrTrim(c, w))
	}
	return strings.Join(out, "")
}

func renderRowWidths(widths []int, cells ...string) string {
	out := make([]string, len(cells))
	for i, c := range cells {
		w := 10
		if i < len(widths) {
			w = widths[i]
		}
		out[i] = cellStyle.Render(padOrTrim(c, w))
	}
	return strings.Join(out, "")
}

func padOrTrim(s string, w int) string {
	visible := lipgloss.Width(s)
	if visible >= w {
		return s
	}
	return s + strings.Repeat(" ", w-visible)
}

func fmtRTT(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000.0)
}

func fmtBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return d.Truncate(time.Second).String()
}

// orDash returns "-" for an empty string, otherwise the input. Used by the
// firewall row renderer where most columns are optional ("any") and a dash
// reads better than blank cells in a fixed-width table.
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// portOrAny returns the port as a string, or empty when port == 0 so that
// orDash can collapse it into "-".
func portOrAny(p uint16) string {
	if p == 0 {
		return ""
	}
	return fmt.Sprintf("%d", p)
}

// netopsErrLines turns a netops/netlink error into one or more user-facing
// lines. The kernel reports "operation not permitted" / "permission denied"
// for callers without CAP_NET_ADMIN - when we recognise that, we append a
// concrete hint instead of leaving the operator to guess what went wrong.
func netopsErrLines(err error) []string {
	if err == nil {
		return nil
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	out := []string{errStyle.Render("  " + msg)}
	if strings.Contains(low, "not permitted") ||
		strings.Contains(low, "permission denied") ||
		strings.Contains(low, "eperm") {
		out = append(out,
			warnStyle.Render("  ↳ needs CAP_NET_ADMIN. Run as root, or:"),
			dimStyle.Render("    sudo setcap cap_net_raw,cap_net_admin=eip ./testudo"),
		)
	}
	if strings.Contains(low, "writes are disabled") {
		out = append(out,
			warnStyle.Render("  ↳ start with --allow-netops-write, or toggle in Settings tab"),
		)
	}
	return out
}

const tuiBanner = `      ___
 ,,  // \\
(_,\/ \_/ \
  \ \_/_\_/>
  /_/  /_/`
