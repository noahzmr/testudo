package tui

import (
	"fmt"
	"strings"
	"time"
)

// sparkBlocks is the Unicode "lower one-eighth block" ladder, used to
// render a series of normalised values 0..1 as a single line of glyphs.
var sparkBlocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// sparkline renders a value series as Unicode block characters. Empty
// series renders as a row of dashes. Out-of-range values are clamped.
func sparkline(values []float64, width int) string {
	if width <= 0 {
		width = 40
	}
	if len(values) == 0 {
		return strings.Repeat("─", width)
	}
	// Downsample / pad to the requested width.
	resampled := resample(values, width)
	max := 0.0
	for _, v := range resampled {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		return strings.Repeat("─", width)
	}
	var b strings.Builder
	for _, v := range resampled {
		norm := v / max
		if norm < 0 {
			norm = 0
		}
		if norm > 1 {
			norm = 1
		}
		idx := int(norm * float64(len(sparkBlocks)-1))
		b.WriteRune(sparkBlocks[idx])
	}
	return b.String()
}

// resample stretches/compresses src to length width with linear bucketing.
func resample(src []float64, width int) []float64 {
	if len(src) == width {
		return src
	}
	out := make([]float64, width)
	if len(src) == 0 {
		return out
	}
	step := float64(len(src)) / float64(width)
	for i := 0; i < width; i++ {
		startF := float64(i) * step
		endF := float64(i+1) * step
		start := int(startF)
		end := int(endF)
		if end >= len(src) {
			end = len(src) - 1
		}
		if start > end {
			start = end
		}
		var sum float64
		var n int
		for j := start; j <= end; j++ {
			sum += src[j]
			n++
		}
		if n > 0 {
			out[i] = sum / float64(n)
		}
	}
	return out
}

// barChart renders horizontal bars labelled with their values. Cap at 12
// rows to keep the dashboard tight.
func barChart(labels []string, values []float64, width int) string {
	if len(labels) == 0 {
		return ""
	}
	if width <= 0 {
		width = 30
	}
	max := 0.0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		max = 1
	}
	var b strings.Builder
	limit := len(labels)
	if limit > 12 {
		limit = 12
	}
	for i := 0; i < limit; i++ {
		fill := int(values[i] / max * float64(width))
		if fill < 0 {
			fill = 0
		}
		if fill > width {
			fill = width
		}
		bar := strings.Repeat("█", fill) + strings.Repeat("░", width-fill)
		b.WriteString(fmt.Sprintf("  %-20s %s  %.1f\n", labels[i], bar, values[i]))
	}
	return b.String()
}

// heatmapShades is the ramp used by the packet-loss heatmap: light => dark
// as loss climbs from 0% => 100%. Picked from Unicode shading blocks so the
// glyphs line up with sparkline().
var heatmapShades = []rune{' ', '░', '▒', '▓', '█'}

// packetLossHeatmap renders a 2D heatmap: each row is one target, each
// column is one time bucket, and the glyph at (row, col) represents loss
// intensity for that target in that bucket.
//
// values[row][col] is expected in 0..1. Empty rows render as a row of dashes.
// labelWidth controls the left-hand label column.
func packetLossHeatmap(labels []string, values [][]float64, labelWidth, plotWidth int) string {
	if len(labels) == 0 || plotWidth <= 0 {
		return ""
	}
	if labelWidth < 6 {
		labelWidth = 6
	}
	maxRow := 16
	if len(labels) < maxRow {
		maxRow = len(labels)
	}
	var b strings.Builder
	for i := 0; i < maxRow; i++ {
		label := labels[i]
		if len(label) > labelWidth {
			label = label[:labelWidth]
		}
		row := values[i]
		bucket := resample(row, plotWidth)
		b.WriteString(fmt.Sprintf("  %-*s ", labelWidth, label))
		if len(bucket) == 0 {
			b.WriteString(strings.Repeat("─", plotWidth))
			b.WriteByte('\n')
			continue
		}
		for _, v := range bucket {
			if v < 0 {
				v = 0
			}
			if v > 1 {
				v = 1
			}
			idx := int(v * float64(len(heatmapShades)-1))
			b.WriteRune(heatmapShades[idx])
		}
		b.WriteByte('\n')
	}
	// Legend showing the loss ramp.
	b.WriteString(fmt.Sprintf("  %*s 0%% ", labelWidth, ""))
	for _, r := range heatmapShades {
		b.WriteRune(r)
	}
	b.WriteString(" 100%\n")
	return b.String()
}

// timeAxis renders a width-wide "axis" label spanning from t0..t1.
func timeAxis(t0, t1 time.Time, width int) string {
	if width < 10 {
		return ""
	}
	left := t0.Format("15:04:05")
	right := t1.Format("15:04:05")
	gap := width - len(left) - len(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}
