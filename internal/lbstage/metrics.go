package lbstage

import (
	"bufio"
	"context"
	"regexp"
	"strconv"
	"strings"
)

// PoolState is what the proxy reports about one backend pool.
type PoolState struct {
	Requests uint64 `json:"requests"`
	Errors   uint64 `json:"errors"` // answers with status 5xx
	// AvgMillis is the mean time to answer over all requests so far.
	AvgMillis float64 `json:"avg_ms"`
	// Backends maps a backend address to "UP" or "DOWN" where the proxy
	// checks health.
	Backends map[string]string `json:"backends,omitempty"`
}

var metricRe = regexp.MustCompile(`^(traefik_service_requests_total|traefik_service_request_duration_seconds_sum)\{([^}]*)\} ([0-9.e+]+)$`)

func label(labels, key string) string {
	for _, part := range strings.Split(labels, ",") {
		if k, v, ok := strings.Cut(part, "="); ok && k == key {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// State reads the proxy's metrics and backend health and reports them per
// backend pool, by model id.
func (s *Stage) State(ctx context.Context) (map[string]PoolState, error) {
	s.mu.Lock()
	res := s.applied
	s.mu.Unlock()
	out := map[string]PoolState{}
	if res.Empty || len(res.Pools) == 0 {
		return out, nil
	}
	var text string
	if err := s.get(ctx, "/metrics", &text); err != nil {
		return nil, err
	}
	seconds := map[string]float64{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		m := metricRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		id, ok := res.Pools[strings.TrimSuffix(label(m[2], "service"), "@file")]
		if !ok {
			continue
		}
		v, _ := strconv.ParseFloat(m[3], 64)
		st := out[id]
		if m[1] == "traefik_service_requests_total" {
			st.Requests += uint64(v)
			if strings.HasPrefix(label(m[2], "code"), "5") {
				st.Errors += uint64(v)
			}
		} else {
			seconds[id] += v
		}
		out[id] = st
	}
	for id, st := range out {
		if st.Requests > 0 {
			st.AvgMillis = seconds[id] / float64(st.Requests) * 1000
			out[id] = st
		}
	}
	var services []struct {
		Name         string            `json:"name"`
		ServerStatus map[string]string `json:"serverStatus"`
	}
	if err := s.get(ctx, "/api/http/services", &services); err == nil {
		for _, svc := range services {
			id, ok := res.Pools[strings.TrimSuffix(svc.Name, "@file")]
			if !ok || len(svc.ServerStatus) == 0 {
				continue
			}
			st := out[id]
			st.Backends = map[string]string{}
			for url, status := range svc.ServerStatus {
				st.Backends[strings.TrimPrefix(url, "http://")] = status
			}
			out[id] = st
		}
	}
	return out, nil
}
