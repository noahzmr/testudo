// Package promtext writes metrics in the Prometheus text exposition format
// (version 0.0.4). It is the few lines the /metrics endpoint needs, without
// a client library and its global registry.
package promtext

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// ContentType is the media type of the output.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Sample is one value of a metric.
type Sample struct {
	Name   string
	Help   string
	Type   string // gauge or counter
	Labels map[string]string
	Value  float64
}

// Gauge and Counter build samples; labels are name, value pairs.
func Gauge(name, help string, v float64, labels ...string) Sample {
	return Sample{Name: name, Help: help, Type: "gauge", Labels: pairs(labels), Value: v}
}

func Counter(name, help string, v float64, labels ...string) Sample {
	return Sample{Name: name, Help: help, Type: "counter", Labels: pairs(labels), Value: v}
}

// Bool is 1 for true and 0 for false.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func pairs(kv []string) map[string]string {
	if len(kv) == 0 {
		return nil
	}
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// Write prints the samples grouped by metric, each metric with its HELP
// and TYPE once, in a stable order.
func Write(w io.Writer, samples []Sample) error {
	sort.SliceStable(samples, func(i, j int) bool { return samples[i].Name < samples[j].Name })
	var b strings.Builder
	last := ""
	for _, s := range samples {
		if s.Name != last {
			last = s.Name
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", s.Name, escapeHelp(s.Help), s.Name, s.Type)
		}
		b.WriteString(s.Name)
		if len(s.Labels) > 0 {
			keys := make([]string, 0, len(s.Labels))
			for k := range s.Labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, "%s=\"%s\"", k, escapeLabel(s.Labels[k]))
			}
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(value(s.Value))
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func value(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}
