package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
)

// The console's live views are pushed, not polled. One builder makes the
// snapshot for every open console on this member, at most every
// liveMinInterval when the engine has news and at least every
// liveMaxInterval for what is only read, never announced (counters,
// conntrack). Each viewer gets the whole snapshot once and then only the
// parts that changed. An alert, a link or route change or a change of
// access goes out without waiting for the next round.

const (
	liveMinInterval = 1 * time.Second
	liveMaxInterval = 5 * time.Second
	// liveUrgentDelay gathers a burst of urgent events into one push.
	liveUrgentDelay = 150 * time.Millisecond
	// liveKeepAlive keeps proxies from closing a quiet stream.
	liveKeepAlive = 15 * time.Second
	// liveSessionCheck is how often a stream checks that its session is
	// still good; a logout on another member ends it within this time.
	liveSessionCheck = 5 * time.Second
	// liveBacklog is how many pushes a slow viewer may fall behind before
	// its stream is ended; the browser reconnects and starts afresh.
	liveBacklog = 8
)

// urgentKinds are the events a viewer should see without delay.
var urgentKinds = map[events.Kind]bool{
	events.KindAnomaly:           true,
	events.KindIncident:          true,
	events.KindLinkStateChange:   true,
	events.KindAddrChange:        true,
	events.KindRouteChange:       true,
	events.KindSubsystemDegraded: true,
	events.KindDuplicateIP:       true,
}

// liveHub builds the snapshot while anyone watches and fans it out.
type liveHub struct {
	// snapshot builds the console's snapshot; bus brings the engine's
	// news; modelRev names the model's current record.
	snapshot func() any
	bus      func() *events.Bus
	modelRev func() string

	mu      sync.Mutex
	subs    map[chan []byte]struct{}
	parts   map[string]json.RawMessage // the last snapshot, by top-level key
	running bool
	stop    context.CancelFunc
	access  uint64 // counts access events; part of "access_rev"
}

// livePatch is what one push carries: the top-level keys of the snapshot
// that changed, a removed key as null.
type livePatch map[string]json.RawMessage

func newLiveHub(s *Server) *liveHub {
	return &liveHub{
		snapshot: func() any { return s.buildSnapshot() },
		bus:      func() *events.Bus { return s.Engine.Bus() },
		modelRev: func() string {
			if st := s.modelState(); st != nil {
				return strconv.FormatInt(st.Index(), 10)
			}
			return ""
		},
		subs: map[chan []byte]struct{}{},
	}
}

// subscribe registers a viewer and returns its channel and the whole
// snapshot to start from.
func (h *liveHub) subscribe() (chan []byte, []byte) {
	ch := make(chan []byte, liveBacklog)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs[ch] = struct{}{}
	if !h.running {
		h.running = true
		ctx, cancel := context.WithCancel(context.Background())
		h.stop = cancel
		h.parts = nil
		// Listen before the first build, so no news falls between them.
		sub := h.bus().Subscribe()
		h.buildLocked()
		go h.run(ctx, sub)
	}
	return ch, h.fullLocked()
}

// unsubscribe removes a viewer; the builder stops with the last one.
func (h *liveHub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[ch]; !ok {
		return
	}
	delete(h.subs, ch)
	close(ch)
	if len(h.subs) == 0 && h.running {
		h.running = false
		h.stop()
	}
}

func (h *liveHub) run(ctx context.Context, sub *events.Subscription) {
	defer sub.Close()
	tick := time.NewTicker(liveMinInterval)
	defer tick.Stop()
	urgent := time.NewTimer(time.Hour)
	urgent.Stop()
	dirty, urgentArmed := false, false
	last := time.Now()
	push := func() {
		h.mu.Lock()
		h.pushLocked()
		h.mu.Unlock()
		dirty, urgentArmed, last = false, false, time.Now()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.C():
			if !ok {
				return
			}
			dirty = true
			if ev.Source == "pam" {
				h.mu.Lock()
				h.access++
				h.mu.Unlock()
			}
			if urgentKinds[ev.Kind] && !urgentArmed {
				urgentArmed = true
				urgent.Reset(liveUrgentDelay)
			}
		case <-urgent.C:
			push()
		case now := <-tick.C:
			if dirty || now.Sub(last) >= liveMaxInterval {
				push()
			}
		}
	}
}

// buildLocked makes a new snapshot and returns the keys that changed since
// the last one. The uptime alone is no change, but rides along with one.
func (h *liveHub) buildLocked() livePatch {
	raw, err := json.Marshal(h.snapshot())
	if err != nil {
		return nil
	}
	var parts map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil
	}
	rev := strconv.FormatUint(h.access, 10) + "." + h.modelRev()
	parts["access_rev"] = json.RawMessage(strconv.Quote(rev))

	patch := livePatch{}
	for k, v := range parts {
		if old, ok := h.parts[k]; !ok || !bytes.Equal(old, v) {
			patch[k] = v
		}
	}
	for k := range h.parts {
		if _, ok := parts[k]; !ok {
			patch[k] = json.RawMessage("null")
		}
	}
	h.parts = parts
	if len(patch) == 0 || (len(patch) == 1 && patch["uptime"] != nil) {
		return nil
	}
	return patch
}

// pushLocked builds and sends the changes to every viewer. A viewer that
// cannot keep up is dropped.
func (h *liveHub) pushLocked() {
	patch := h.buildLocked()
	if patch == nil {
		return
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return
	}
	msg := sseMessage("patch", data)
	for ch := range h.subs {
		select {
		case ch <- msg:
		default:
			delete(h.subs, ch)
			close(ch)
		}
	}
	if len(h.subs) == 0 && h.running {
		h.running = false
		h.stop()
	}
}

func (h *liveHub) fullLocked() []byte {
	data, _ := json.Marshal(h.parts)
	return sseMessage("snapshot", data)
}

func sseMessage(event string, data []byte) []byte {
	return fmt.Appendf(nil, "event: %s\ndata: %s\n\n", event, data)
}

// handleLive streams the console's snapshot: a "snapshot" event with all of
// it, then "patch" events with the parts that changed. The stream ends with
// an "end" event when the session does, and when the server stops.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch, first := s.live.subscribe()
	defer s.live.unsubscribe(ch)
	write := func(b []byte) bool {
		if _, err := w.Write(b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write(first) {
		return
	}
	keep := time.NewTicker(liveKeepAlive)
	defer keep.Stop()
	check := time.NewTicker(liveSessionCheck)
	defer check.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.stopping:
			return
		case msg, ok := <-ch:
			if !ok || !write(msg) {
				return
			}
		case <-keep.C:
			if !write([]byte(": keep-alive\n\n")) {
				return
			}
		case <-check.C:
			if s.session(r) == nil {
				write(sseMessage("end", []byte(`{"reason":"session ended"}`)))
				return
			}
		}
	}
}
