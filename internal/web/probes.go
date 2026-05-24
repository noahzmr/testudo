package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/noahzmr/testudo/internal/probes"
	"github.com/noahzmr/testudo/internal/replay"
)

// handleProbe accepts a JSON POST and runs a single one-shot probe,
// mirroring the TUI's Probes tab so operators with web-only access can run
// the same diagnostics. The response shape stays close to probes.Result so
// the frontend can render the same fields.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Kind   string `json:"kind"`
		Target string `json:"target"`
		Port   uint16 `json:"port"`
		Bytes  int    `json:"bytes"`
		Hops   int    `json:"hops"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Bound the worst case so a runaway DNS resolver or unreachable host
	// can't tie up a web worker indefinitely.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	res, err := probes.Run(ctx, probes.Request{
		Kind:    probes.Kind(body.Kind),
		Target:  body.Target,
		Port:    body.Port,
		Bytes:   body.Bytes,
		Hops:    body.Hops,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	type hopView struct {
		TTL     int    `json:"ttl"`
		IP      string `json:"ip"`
		LatMs   int64  `json:"latency_ms"`
	}
	out := struct {
		Kind     string    `json:"kind"`
		OK       bool      `json:"ok"`
		LatMs    int64     `json:"latency_ms"`
		Detail   string    `json:"detail"`
		Mbps     float64   `json:"mbps"`
		Err      string    `json:"err"`
		Hops     []hopView `json:"hops,omitempty"`
	}{
		Kind:   string(res.Kind),
		OK:     res.OK,
		LatMs:  res.Latency.Milliseconds(),
		Detail: res.Detail,
		Mbps:   res.Mbps,
		Err:    res.Err,
	}
	for _, h := range res.Hops {
		out.Hops = append(out.Hops, hopView{TTL: h.TTL, IP: h.IP, LatMs: h.Latency.Milliseconds()})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleSessions returns a list of past sessions stored in SQLite plus the
// IDs needed to /api/replay them. Phase 1 surface — replay scrubbing is on
// the roadmap.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	recs, err := replay.List(ctx, s.Engine.Store(), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type sessionView struct {
		ID         string   `json:"id"`
		StartedAt  string   `json:"started_at"`
		EndedAt    string   `json:"ended_at"`
		Targets    []string `json:"targets"`
		DurationMs int64    `json:"duration_ms"`
	}
	out := make([]sessionView, 0, len(recs))
	for _, rec := range recs {
		v := sessionView{
			ID:        rec.ID,
			StartedAt: rec.StartedAt.Format(time.RFC3339),
			Targets:   rec.Targets,
		}
		if rec.EndedAt != nil {
			v.EndedAt = rec.EndedAt.Format(time.RFC3339)
		}
		v.DurationMs = rec.Duration.Milliseconds()
		out = append(out, v)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
