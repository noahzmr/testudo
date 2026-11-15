// Package gwmon watches gateways. A gateway with a monitor address is probed
// regularly; it counts as down after several probes in a row fail and as up
// again after several in a row succeed, so a single lost packet or a flapping
// link does not move routes back and forth.
package gwmon

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/noahzmr/testudo/internal/model"
)

// Threshold is how many probes in a row change a gateway's state.
const Threshold = 3

// Status is what is known about one gateway.
type Status struct {
	Monitor string    `json:"monitor"`
	Down    bool      `json:"down"`
	Since   time.Time `json:"since"`
	// Error is set when probing itself is impossible; such a gateway is
	// treated as up, because nothing is known against it.
	Error string `json:"error,omitempty"`
}

type state struct {
	Status
	streak int // consecutive results contradicting the current state
}

// Monitor holds the health of every monitored gateway.
type Monitor struct {
	// Probe reports whether addr answered. Nil uses an ICMP echo.
	Probe func(ctx context.Context, addr string) (ok bool, err error)

	mu    sync.Mutex
	gates map[string]*state
}

// Down returns the ids of the gateways that are currently down.
func (m *Monitor) Down() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for id, s := range m.gates {
		if s.Down {
			out[id] = true
		}
	}
	return out
}

// Status returns the state of every monitored gateway by id.
func (m *Monitor) Status() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.gates))
	for id, s := range m.gates {
		out[id] = s.Status
	}
	return out
}

// Check probes every monitored gateway once and reports whether any gateway
// changed between up and down. Gateways that are gone or no longer monitored
// are forgotten.
func (m *Monitor) Check(ctx context.Context, gateways []*model.Gateway, now time.Time) (changed bool) {
	probe := m.Probe
	if probe == nil {
		probe = Ping
	}
	type result struct {
		id, addr string
		ok       bool
		err      error
	}
	var wg sync.WaitGroup
	results := make(chan result, len(gateways))
	live := map[string]bool{}
	for _, g := range gateways {
		if !g.Enabled || g.Monitor == "" {
			continue
		}
		live[g.ID] = true
		wg.Add(1)
		go func(id, addr string) {
			defer wg.Done()
			ok, err := probe(ctx, addr)
			results <- result{id, addr, ok, err}
		}(g.ID, g.Monitor)
	}
	wg.Wait()
	close(results)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gates == nil {
		m.gates = map[string]*state{}
	}
	for id, s := range m.gates {
		if !live[id] {
			delete(m.gates, id)
			changed = changed || s.Down
		}
	}
	for r := range results {
		s := m.gates[r.id]
		if s == nil {
			s = &state{Status: Status{Since: now}}
			m.gates[r.id] = s
		}
		s.Monitor = r.addr
		if r.err != nil {
			// Not being able to probe says nothing about the gateway.
			s.Error = r.err.Error()
			s.streak = 0
			continue
		}
		s.Error = ""
		if r.ok == !s.Down {
			s.streak = 0
			continue
		}
		if s.streak++; s.streak >= Threshold {
			s.Down, s.Since, s.streak = !s.Down, now, 0
			changed = true
		}
	}
	return changed
}

// Ping sends one ICMP echo request and waits up to a second for the reply.
// It uses the unprivileged ICMP socket, which needs the process's group to
// be inside net.ipv4.ping_group_range; when that is not allowed it returns
// an error rather than a verdict.
func Ping(ctx context.Context, addr string) (bool, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false, &net.ParseError{Type: "IP address", Text: addr}
	}
	network, listen, proto := "udp4", "0.0.0.0", 1
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if ip.To4() == nil {
		network, listen, proto, typ = "udp6", "::", 58, ipv6.ICMPTypeEchoRequest
	}
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	msg, err := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("testudo-gw")}}).Marshal(nil)
	if err != nil {
		return false, err
	}
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.WriteTo(msg, &net.UDPAddr{IP: ip}); err != nil {
		return false, nil // unreachable right now: that is a failed probe
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return false, nil // timeout
		}
		if reply, err := icmp.ParseMessage(proto, buf[:n]); err == nil &&
			(reply.Type == ipv4.ICMPTypeEchoReply || reply.Type == ipv6.ICMPTypeEchoReply) {
			return true, nil
		}
	}
}
