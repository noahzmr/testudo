package web

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
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

// handleSessionDetail returns a single session's metadata together with the
// anomaly timeline and the snapshot index (id + kind + ts, no payload). The
// SPA calls this when a row in the History tab is clicked.
//
//	GET /api/session/detail?id=<session-id>
func (s *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	store := s.Engine.Store()

	// We don't have a "session by id" lookup, so pull a bounded slice and
	// pick the matching row. ListSessions returns newest-first.
	recs, err := store.ListSessions(ctx, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var found bool
	var rec replay.SessionSummary
	for _, r0 := range recs {
		if r0.ID != id {
			continue
		}
		rec.ID = r0.ID
		rec.StartedAt = r0.StartedAt
		rec.EndedAt = r0.EndedAt
		rec.Targets = r0.Targets
		if r0.EndedAt != nil {
			rec.Duration = r0.EndedAt.Sub(r0.StartedAt)
		}
		found = true
		break
	}
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	anomalies, err := store.AnomaliesBySession(ctx, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	snapIdx, err := store.SnapshotIndexBySession(ctx, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type anomalyView struct {
		TS       string `json:"ts"`
		Severity string `json:"severity"`
		Message  string `json:"message"`
	}
	type snapshotIndexView struct {
		ID   int64  `json:"id"`
		Kind string `json:"kind"`
		TS   string `json:"ts"`
	}
	type sessionDetail struct {
		ID         string              `json:"id"`
		StartedAt  string              `json:"started_at"`
		EndedAt    string              `json:"ended_at"`
		DurationMs int64               `json:"duration_ms"`
		Targets    []string            `json:"targets"`
		Anomalies  []anomalyView       `json:"anomalies"`
		Snapshots  []snapshotIndexView `json:"snapshots"`
	}

	out := sessionDetail{
		ID:         rec.ID,
		StartedAt:  rec.StartedAt.Format(time.RFC3339),
		DurationMs: rec.Duration.Milliseconds(),
		Targets:    rec.Targets,
		Anomalies:  make([]anomalyView, 0, len(anomalies)),
		Snapshots:  make([]snapshotIndexView, 0, len(snapIdx)),
	}
	if rec.EndedAt != nil {
		out.EndedAt = rec.EndedAt.Format(time.RFC3339)
	}
	for _, a := range anomalies {
		out.Anomalies = append(out.Anomalies, anomalyView{
			TS: a.TS.Format(time.RFC3339), Severity: a.Severity, Message: a.Message,
		})
	}
	for _, e := range snapIdx {
		out.Snapshots = append(out.Snapshots, snapshotIndexView{
			ID: e.ID, Kind: e.Kind, TS: e.TS.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleSnapshotPayload returns the pretty-printed JSON payload of one
// snapshot row. The SPA opens this when a row in the snapshot index is
// clicked. The payload column is itself JSON; we re-indent before sending
// so the frontend doesn't have to parse-then-stringify in JS.
//
//	GET /api/session/snapshot?id=<snapshot-id>
func (s *Server) handleSnapshotPayload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw := r.URL.Query().Get("id")
	if raw == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	row, err := s.Engine.Store().SnapshotByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "snapshot not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var pretty bytes.Buffer
	if jerr := json.Indent(&pretty, row.PayloadRaw, "", "  "); jerr != nil {
		pretty.Write(row.PayloadRaw) // not JSON — return verbatim
	}
	out := struct {
		ID        int64  `json:"id"`
		SessionID string `json:"session_id"`
		Kind      string `json:"kind"`
		TS        string `json:"ts"`
		Payload   string `json:"payload"`
	}{
		ID: row.ID, SessionID: row.SessionID, Kind: row.Kind,
		TS: row.TS.Format(time.RFC3339), Payload: pretty.String(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
