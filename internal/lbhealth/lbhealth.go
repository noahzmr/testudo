// Package lbhealth checks the backends of services that are balanced in the
// packet filter. The proxy checks its own backends; the kernel cannot, so
// this monitor does it and the packet-filter stage leaves out what is down.
//
// A backend changes state after Threshold results in a row, so one lost
// probe does not move traffic.
package lbhealth

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/model"
)

// Threshold is how many probes in a row change a backend's state.
const Threshold = 2

// Status is what is known about one backend.
type Status struct {
	Down  bool      `json:"down"`
	Since time.Time `json:"since"`
	Error string    `json:"error,omitempty"`
}

type state struct {
	Status
	streak int
}

// Monitor holds the health of every checked backend, by "host:port".
type Monitor struct {
	// Probe reports whether a backend passed its pool's check. Nil uses a
	// TCP connect or an HTTP GET, as the check says.
	Probe func(ctx context.Context, addr string, hc model.LBHealthCheck) error

	mu       sync.Mutex
	backends map[string]*state
}

// Down returns the backends that are currently down.
func (m *Monitor) Down() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for addr, s := range m.backends {
		if s.Down {
			out[addr] = true
		}
	}
	return out
}

// Status returns a copy of every backend's state.
func (m *Monitor) Status() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.backends))
	for addr, s := range m.backends {
		out[addr] = s.Status
	}
	return out
}

func probe(ctx context.Context, addr string, hc model.LBHealthCheck) error {
	if hc.Type == "http" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+hc.Path, nil)
		if err != nil {
			return err
		}
		res, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()
		if res.StatusCode >= 400 {
			return &statusError{res.Status}
		}
		return nil
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

type statusError struct{ status string }

func (e *statusError) Error() string { return "answered " + e.status }

// Check probes every backend of the given pools once, in parallel, and
// reports whether any backend changed state. Backends of pools without a
// check, and backends no pool names any more, are forgotten.
func (m *Monitor) Check(ctx context.Context, pools map[string]*model.LBBackendPool, now time.Time) (changed bool) {
	type job struct {
		addr string
		hc   model.LBHealthCheck
	}
	var jobs []job
	seen := map[string]bool{}
	for _, p := range pools {
		if p.HealthCheck.Type == "none" || p.HealthCheck.Type == "" {
			continue
		}
		for _, b := range p.Backends {
			if !seen[b.Address] {
				seen[b.Address] = true
				jobs = append(jobs, job{b.Address, p.HealthCheck})
			}
		}
	}
	results := make([]error, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			timeout := 2 * time.Second
			if d, err := time.ParseDuration(j.hc.Timeout); err == nil && d > 0 {
				timeout = d
			}
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			p := m.Probe
			if p == nil {
				p = probe
			}
			results[i] = p(pctx, j.addr, j.hc)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backends == nil {
		m.backends = map[string]*state{}
	}
	for addr, s := range m.backends {
		if !seen[addr] {
			delete(m.backends, addr)
			changed = changed || s.Down
		}
	}
	for i, j := range jobs {
		s := m.backends[j.addr]
		if s == nil {
			s = &state{Status: Status{Since: now}}
			m.backends[j.addr] = s
		}
		failed := results[i] != nil
		s.Error = ""
		if failed {
			s.Error = results[i].Error()
		}
		if failed == s.Down {
			s.streak = 0
			continue
		}
		if s.streak++; s.streak >= Threshold {
			s.Down, s.Since, s.streak = failed, now, 0
			changed = true
		}
	}
	return changed
}
