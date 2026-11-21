// Package pathmon measures the fabric's tunnels (latency, jitter, loss)
// and decides, per peer node, which color traffic should prefer. A path
// has to be clearly better for a while before traffic moves to it, so a
// single slow probe does not move anything back and forth; a path that
// stops answering is left at once.
package pathmon

import (
	"context"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Target is one tunnel to measure: its device and the peer's address on it.
type Target struct {
	Device   string `json:"device"`
	Peer     string `json:"peer"`
	PeerNode string `json:"peer_node"`
	Slot     int    `json:"slot"`
	Color    string `json:"color"`
}

// Stats is what is known about one tunnel.
type Stats struct {
	Target
	LatencyMs float64 `json:"latency_ms"`
	JitterMs  float64 `json:"jitter_ms"`
	Loss      float64 `json:"loss"` // 0..1 over the window
	Samples   int     `json:"samples"`
	Down      bool    `json:"down"`
	Preferred bool    `json:"preferred"`
}

// Criteria the monitor ranks paths by.
const (
	LowestLatency = "lowest_latency"
	LowestLoss    = "lowest_loss"
)

const (
	window   = 20 // probes per path that count
	downRun  = 3  // lost probes in a row that make a path down
	minReady = 3  // probes before a path takes part in choosing
)

type path struct {
	t       Target
	results []float64 // RTT in ms, or -1 for a lost probe; newest last
	lostRun int
}

func (p *path) stats() Stats {
	s := Stats{Target: p.t, Samples: len(p.results), Down: p.lostRun >= downRun}
	var sum, jit float64
	n, lost := 0, 0
	prev := -1.0
	for _, r := range p.results {
		if r < 0 {
			lost++
			continue
		}
		sum += r
		if prev >= 0 {
			jit += math.Abs(r - prev)
		}
		prev = r
		n++
	}
	if len(p.results) > 0 {
		s.Loss = float64(lost) / float64(len(p.results))
	}
	if n > 0 {
		s.LatencyMs = sum / float64(n)
	}
	if n > 1 {
		s.JitterMs = jit / float64(n-1)
	}
	return s
}

type choice struct {
	color     string
	candidate string
	since     time.Time // when the candidate started to be better
}

// Monitor holds the measurements and the choices.
type Monitor struct {
	// Probe measures one round trip to addr; nil uses an ICMP echo.
	Probe func(ctx context.Context, addr string) (time.Duration, error)
	// Margin and Hold: a path is preferred over the current one when it is
	// better by Margin (and by a fifth) for Hold. Defaults 10 ms and 15 s.
	Margin, Hold time.Duration

	mu      sync.Mutex
	paths   map[string]*path
	choices map[string]*choice // peerNode/slot/criterion
}

func (m *Monitor) margin() time.Duration {
	if m.Margin > 0 {
		return m.Margin
	}
	return 10 * time.Millisecond
}

func (m *Monitor) hold() time.Duration {
	if m.Hold > 0 {
		return m.Hold
	}
	return 15 * time.Second
}

// Check probes every target once, in parallel, and works out the choices
// again. It reports whether a choice or a path's up/down state changed.
func (m *Monitor) Check(ctx context.Context, targets []Target, now time.Time) bool {
	results := make([]float64, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			probe := m.Probe
			if probe == nil {
				probe = Ping
			}
			rtt, err := probe(pctx, t.Peer)
			if err != nil {
				results[i] = -1
				return
			}
			results[i] = float64(rtt) / float64(time.Millisecond)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.paths == nil {
		m.paths, m.choices = map[string]*path{}, map[string]*choice{}
	}
	changed := false
	live := map[string]bool{}
	for i, t := range targets {
		live[t.Device] = true
		p := m.paths[t.Device]
		if p == nil {
			p = &path{t: t}
			m.paths[t.Device] = p
		}
		p.t = t
		wasDown := p.lostRun >= downRun
		if results[i] < 0 {
			p.lostRun++
		} else {
			p.lostRun = 0
		}
		p.results = append(p.results, results[i])
		if len(p.results) > window {
			p.results = p.results[len(p.results)-window:]
		}
		changed = changed || wasDown != (p.lostRun >= downRun)
	}
	for dev := range m.paths {
		if !live[dev] {
			delete(m.paths, dev)
		}
	}
	for _, crit := range []string{LowestLatency, LowestLoss} {
		for key, group := range m.groups() {
			if m.decide(key+"/"+crit, group, crit, now) {
				changed = true
			}
		}
	}
	return changed
}

// groups collects the paths to each peer node and slot.
func (m *Monitor) groups() map[string][]Stats {
	out := map[string][]Stats{}
	for _, p := range m.paths {
		k := key(p.t.PeerNode, p.t.Slot)
		out[k] = append(out[k], p.stats())
	}
	for _, g := range out {
		sort.Slice(g, func(i, j int) bool { return g[i].Color < g[j].Color })
	}
	return out
}

func key(peer string, slot int) string { return peer + "/" + string(rune('0'+slot)) }

// better reports whether a is clearly better than b by the criterion.
func (m *Monitor) better(a, b Stats, crit string) bool {
	if crit == LowestLoss && a.Loss+0.02 <= b.Loss {
		return true
	}
	if crit == LowestLoss && math.Abs(a.Loss-b.Loss) > 0.02 {
		return false
	}
	d := b.LatencyMs - a.LatencyMs
	return d >= float64(m.margin())/float64(time.Millisecond) && d >= b.LatencyMs/5
}

func (m *Monitor) best(group []Stats, crit string) (Stats, bool) {
	var best Stats
	found := false
	for _, s := range group {
		if s.Down || s.Samples < minReady {
			continue
		}
		if !found || m.better(s, best, crit) || (!m.better(best, s, crit) && s.LatencyMs < best.LatencyMs) {
			best, found = s, true
		}
	}
	return best, found
}

func (m *Monitor) decide(k string, group []Stats, crit string, now time.Time) bool {
	c := m.choices[k]
	if c == nil {
		c = &choice{}
		m.choices[k] = c
	}
	best, ok := m.best(group, crit)
	if !ok {
		return false // nothing measured yet, or everything down: keep what is there
	}
	var cur *Stats
	for i := range group {
		if group[i].Color == c.color {
			cur = &group[i]
		}
	}
	switch {
	case c.color == "", cur == nil, cur.Down:
		// Nothing chosen yet, or the chosen path is gone: move at once.
		moved := c.color != best.Color
		c.color, c.candidate = best.Color, ""
		return moved
	case best.Color == c.color || !m.better(best, *cur, crit):
		c.candidate = ""
		return false
	case c.candidate != best.Color:
		c.candidate, c.since = best.Color, now
		return false
	case now.Sub(c.since) >= m.hold():
		c.color, c.candidate = best.Color, ""
		return true
	}
	return false
}

// Preferred returns the color to prefer towards peerNode in slot, or "".
func (m *Monitor) Preferred(peerNode string, slot int, crit string) string {
	if crit != LowestLoss {
		crit = LowestLatency
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.choices[key(peerNode, slot)+"/"+crit]; c != nil {
		return c.color
	}
	return ""
}

// Down reports whether a tunnel stopped answering.
func (m *Monitor) Down(device string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.paths[device]
	return p != nil && p.lostRun >= downRun
}

// Status returns every tunnel's numbers, marking the preferred ones.
func (m *Monitor) Status() []Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Stats
	for _, p := range m.paths {
		s := p.stats()
		if c := m.choices[key(p.t.PeerNode, p.t.Slot)+"/"+LowestLatency]; c != nil && c.color == p.t.Color {
			s.Preferred = true
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out
}

// Ping measures one ICMP echo round trip to an IPv4 address, with the
// unprivileged ICMP socket.
func Ping(ctx context.Context, addr string) (time.Duration, error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return 0, &net.ParseError{Type: "IPv4 address", Text: addr}
	}
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	msg, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1, Seq: 1, Data: []byte("testudo-path")}}).Marshal(nil)
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	start := time.Now()
	if _, err := conn.WriteTo(msg, &net.UDPAddr{IP: ip}); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		if reply, err := icmp.ParseMessage(1, buf[:n]); err == nil && reply.Type == ipv4.ICMPTypeEchoReply {
			return time.Since(start), nil
		}
	}
}
