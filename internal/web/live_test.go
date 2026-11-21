package web

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/events"
)

// fakeSource is a snapshot that tests change by hand.
type fakeSource struct {
	mu   sync.Mutex
	snap map[string]any
	n    int
}

func (f *fakeSource) get() any {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	out := map[string]any{}
	for k, v := range f.snap {
		out[k] = v
	}
	return out
}

func (f *fakeSource) set(k string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v == nil {
		delete(f.snap, k)
	} else {
		f.snap[k] = v
	}
}

func (f *fakeSource) builds() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

func testHub(src *fakeSource, bus *events.Bus) *liveHub {
	return &liveHub{
		snapshot: src.get,
		bus:      func() *events.Bus { return bus },
		modelRev: func() string { return "7" },
		subs:     map[chan []byte]struct{}{},
	}
}

// event reads the next server-sent event from ch.
func event(t *testing.T, ch <-chan []byte, within time.Duration) (string, map[string]json.RawMessage) {
	t.Helper()
	select {
	case msg, ok := <-ch:
		if !ok {
			t.Fatal("stream ended")
		}
		return parseSSE(t, string(msg))
	case <-time.After(within):
		t.Fatalf("nothing pushed within %s", within)
	}
	return "", nil
}

func parseSSE(t *testing.T, msg string) (string, map[string]json.RawMessage) {
	t.Helper()
	var name, data string
	for _, line := range strings.Split(msg, "\n") {
		if v, ok := strings.CutPrefix(line, "event: "); ok {
			name = v
		}
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			data = v
		}
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &body); err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
	return name, body
}

func TestLiveSendsOnlyWhatChanged(t *testing.T) {
	bus := events.NewBus(16)
	src := &fakeSource{snap: map[string]any{"uptime": "1s", "flows": []int{1}, "routes": []int{2}}}
	h := testHub(src, bus)

	ch, first := h.subscribe()
	defer h.unsubscribe(ch)
	name, full := parseSSE(t, string(first))
	if name != "snapshot" || string(full["flows"]) != "[1]" || string(full["routes"]) != "[2]" || string(full["access_rev"]) != `"0.7"` {
		t.Fatalf("first event %s: %v", name, full)
	}

	// Only the uptime moves: nothing is pushed.
	src.set("uptime", "2s")
	time.Sleep(liveMaxInterval + 500*time.Millisecond)
	select {
	case msg := <-ch:
		t.Fatalf("pushed although nothing changed: %s", msg)
	default:
	}

	// A flow changes and a route goes away: the patch has both and the
	// uptime, not what stayed.
	src.set("flows", []int{1, 3})
	src.set("routes", nil)
	src.set("uptime", "3s")
	bus.Publish(events.Event{Kind: events.KindFlowUpdate})
	name, patch := event(t, ch, 2*liveMinInterval+time.Second)
	if name != "patch" || string(patch["flows"]) != "[1,3]" || string(patch["routes"]) != "null" || string(patch["uptime"]) != `"3s"` {
		t.Fatalf("patch %s: %v", name, patch)
	}
	if _, ok := patch["access_rev"]; ok {
		t.Errorf("access_rev sent although unchanged")
	}
}

func TestLivePushesUrgentNewsAtOnce(t *testing.T) {
	bus := events.NewBus(16)
	src := &fakeSource{snap: map[string]any{"anomalies": []string{}}}
	h := testHub(src, bus)
	ch, _ := h.subscribe()
	defer h.unsubscribe(ch)

	src.set("anomalies", []string{"packet loss"})
	start := time.Now()
	bus.Publish(events.Event{Kind: events.KindAnomaly, Source: "pam"})
	_, patch := event(t, ch, liveMinInterval)
	if d := time.Since(start); d >= liveMinInterval {
		t.Errorf("an alert took %s", d)
	}
	if string(patch["anomalies"]) != `["packet loss"]` {
		t.Errorf("patch: %v", patch)
	}
	// An access event changes the access revision.
	if string(patch["access_rev"]) != `"1.7"` {
		t.Errorf("access_rev: %s", patch["access_rev"])
	}
}

func TestLiveBuildsOnceForAllViewersAndStopsWithTheLast(t *testing.T) {
	bus := events.NewBus(16)
	src := &fakeSource{snap: map[string]any{"n": 0}}
	h := testHub(src, bus)
	a, _ := h.subscribe()
	b, _ := h.subscribe()
	src.set("n", 1)
	bus.Publish(events.Event{Kind: events.KindAnomaly})
	event(t, a, time.Second)
	event(t, b, time.Second)
	if n := src.builds(); n != 2 {
		t.Errorf("%d snapshots built for two viewers and one change, want 2", n)
	}
	h.unsubscribe(a)
	h.unsubscribe(b)
	time.Sleep(50 * time.Millisecond)
	if bus.SubscriberCount() != 0 {
		t.Errorf("the builder still listens with nobody watching")
	}
	n := src.builds()
	time.Sleep(liveMaxInterval + time.Second)
	if src.builds() != n {
		t.Errorf("snapshots built with nobody watching")
	}
}

func TestLiveDropsAViewerThatFallsBehind(t *testing.T) {
	bus := events.NewBus(16)
	src := &fakeSource{snap: map[string]any{"n": 0}}
	h := testHub(src, bus)
	slow, _ := h.subscribe()
	defer h.unsubscribe(slow)
	for i := 1; i <= liveBacklog+1; i++ {
		src.set("n", i)
		h.mu.Lock()
		h.pushLocked()
		h.mu.Unlock()
	}
	n := 0
	for range slow {
		n++
	}
	if n != liveBacklog {
		t.Errorf("%d pushes queued before the stream ended, want %d", n, liveBacklog)
	}
}

// TestLiveStreamEndsWithTheSession: the handler sends the snapshot, then
// ends the stream once the session is gone.
func TestLiveStreamEndsWithTheSession(t *testing.T) {
	bus := events.NewBus(16)
	src := &fakeSource{snap: map[string]any{"flows": []int{}}}
	s := &Server{sessions: map[string]*sessionRecord{}, shared: &shared{}}
	s.live = testHub(src, bus)
	sid := strings.Repeat("a", 32)
	rec := &sessionRecord{user: "u", expiresAt: time.Now().Add(time.Hour)}
	if err := s.saveSession(sid, rec); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(s.handleLive))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*liveSessionCheck)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var names []string
	go func() { time.Sleep(200 * time.Millisecond); s.endSession(sid) }()
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
			names = append(names, v)
		}
	}
	if strings.Join(names, ",") != "snapshot,end" {
		t.Errorf("events %v, want snapshot then end", names)
	}
}
