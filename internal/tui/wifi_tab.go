package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/engine"
)

// wifiTab is the dedicated wireless view: one rich card per radio with a
// computed link-quality grade, a signal-history sparkline, and the full set of
// nl80211/iw counters. It exists so wireless health is a first-class surface
// rather than a strip on the Dashboard / a section buried in Health.
type wifiTab struct {
	eng  *engine.Engine
	wifi []collectors.WiFiSnapshot
}

func newWiFiTab(eng *engine.Engine) *wifiTab { return &wifiTab{eng: eng} }

func (t *wifiTab) Title() string    { return "WiFi" }
func (t *wifiTab) ShortKey() string { return "" } // jump via `:wifi`
func (t *wifiTab) Init() tea.Cmd    { return nil }
func (t *wifiTab) HelpHints() []KeyHint {
	return []KeyHint{{Key: "PgUp/PgDn", Desc: "scroll radios"}}
}

func (t *wifiTab) Update(msg tea.Msg) tea.Cmd {
	switch msg.(type) {
	case slowTickMsg, tickMsg:
		if wc := t.eng.WiFi(); wc != nil {
			t.wifi = wc.Snapshot()
		}
	}
	return nil
}

func (t *wifiTab) View(w, h int) string {
	innerW := w - 6
	var b strings.Builder
	b.WriteString(headerStyle.Render("WiFi · wireless link quality"))
	b.WriteString("\n\n")

	if len(t.wifi) == 0 {
		b.WriteString(subtitleStyle.Render("  no wireless interfaces found in /sys/class/net (no NICs registered as wifi)"))
		return boxStyle.Render(b.String())
	}

	associated := t.wifi[:0:0]
	idle := t.wifi[:0:0]
	anyData := false
	for _, s := range t.wifi {
		if s.Source != "" && s.Source != "none" {
			anyData = true
		}
		if s.Associated {
			associated = append(associated, s)
		} else {
			idle = append(idle, s)
		}
	}
	if !anyData {
		b.WriteString(subtitleStyle.Render("  no wifi backend reachable - nl80211 needs CAP_NET_ADMIN; run testudo with sudo or grant `setcap cap_net_admin+ep`"))
		b.WriteString("\n\n")
	}

	for _, s := range associated {
		renderWiFiCard(&b, innerW, s)
		// Computed link-quality grade (RSSI + SNR + TX-failure blend) - the same
		// signal that feeds the Network Quality grade, surfaced per radio.
		score := scoreWiFi([]collectors.WiFiSnapshot{s}).Score
		letter, verdict := letterAndVerdict(score)
		col := gradeColor(score)
		grade := lipgloss.NewStyle().Bold(true).Foreground(col).
			Render(fmt.Sprintf("%d/100 (%s)", score, letter))
		b.WriteString("  " + dimStyle.Render("Quality") + "      " + grade +
			"  " + dimStyle.Render("· "+verdict) + "\n")
		// Signal-history sparkline from the metrics aggregator (samples encode
		// -dBm; we shift to a higher-is-better magnitude for the plot).
		if samples := t.eng.Aggregator().LatencySamples("wifi:signal:" + s.Iface); len(samples) > 1 {
			vals := make([]float64, len(samples))
			for i, d := range samples {
				ms := float64(d.Microseconds()) / 1000.0 // == -dBm
				vals[i] = 100 - ms                       // -60dBm -> 40, higher is better
			}
			plotW := innerW - 18
			if plotW < 8 {
				plotW = 8
			}
			spark := sparkline(vals, plotW)
			b.WriteString("  " + dimStyle.Render("Signal·hist") + " " +
				rowStyle.Render(spark) + "\n")
		}
		b.WriteString("\n")
	}
	if len(associated) == 0 {
		b.WriteString(subtitleStyle.Render("  no associated radios · all wireless NICs are unassociated"))
		b.WriteString("\n")
	}

	if len(idle) > 0 {
		names := make([]string, 0, len(idle))
		for _, s := range idle {
			names = append(names, s.Iface)
		}
		b.WriteString("  " + dimStyle.Render("unassociated radios: ") +
			warnStyle.Render(strings.Join(names, ", ")) + "\n")
	}

	return boxStyle.Render(b.String())
}
