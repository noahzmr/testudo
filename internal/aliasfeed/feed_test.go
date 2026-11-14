package aliasfeed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/model"
)

func TestParseList(t *testing.T) {
	got, err := ParseList(strings.NewReader("# header\n192.0.2.1\n 10.0.0.0/8  ; rfc1918\n\n2001:db8::/32 some label\n192.0.2.1\n10.1.2.3/8\n"))
	want := []string{"10.0.0.0/8", "192.0.2.1", "2001:db8::/32"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("got %v, %v", got, err)
	}
	// A page that is not a list must not turn into an empty set.
	if _, err := ParseList(strings.NewReader("<html><body>404</body></html>\n")); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("html accepted: %v", err)
	}
}

func TestRefreshCachesKeepsAndForgets(t *testing.T) {
	body, status, hits := "192.0.2.1\n", 200, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "cache", "aliases.json")
	f := New(path)
	a := &model.Alias{Meta: model.Meta{ID: "a1", Name: "list"}, Type: "url_table", URL: srv.URL, Refresh: "10m"}
	static := &model.Alias{Meta: model.Meta{ID: "s1", Name: "static"}, Type: "host", Entries: []string{"10.0.0.1"}}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()

	if !f.Refresh(ctx, []*model.Alias{a, static}, now) || !slices.Equal(f.Snapshot()["a1"], []string{"192.0.2.1"}) {
		t.Fatalf("first refresh: %v", f.Snapshot())
	}
	if _, ok := f.Snapshot()["s1"]; ok {
		t.Error("a static alias got run-time content")
	}
	// Not due yet: no request, no change.
	if f.Refresh(ctx, []*model.Alias{a}, now.Add(5*time.Minute)) || hits != 1 {
		t.Errorf("refreshed before the interval (hits=%d)", hits)
	}
	// Due, new content.
	body = "192.0.2.1\n192.0.2.2\n"
	if !f.Refresh(ctx, []*model.Alias{a}, now.Add(11*time.Minute)) || len(f.Snapshot()["a1"]) != 2 {
		t.Errorf("content change not picked up: %v", f.Snapshot())
	}
	// The source breaks: the content stays, the error is visible.
	status = 500
	if f.Refresh(ctx, []*model.Alias{a}, now.Add(30*time.Minute)) {
		t.Error("a failing source reported a change")
	}
	if st := f.StatusOf()["a1"]; st.Entries != 2 || !strings.Contains(st.Error, "500") {
		t.Errorf("status after failure: %+v", st)
	}
	// A restart reads the cache.
	if got := New(path).Snapshot()["a1"]; len(got) != 2 {
		t.Errorf("cache after restart: %v", got)
	}
	// A changed URL is fetched at once, not after the interval.
	status, body = 200, "198.51.100.0/24\n"
	a.URL = srv.URL + "/other"
	if !f.Refresh(ctx, []*model.Alias{a}, now.Add(31*time.Minute)) || f.Snapshot()["a1"][0] != "198.51.100.0/24" {
		t.Errorf("changed source: %v", f.Snapshot())
	}
	// A deleted alias is forgotten.
	if !f.Refresh(ctx, nil, now.Add(32*time.Minute)) || len(f.Snapshot()) != 0 {
		t.Errorf("deleted alias kept: %v", f.Snapshot())
	}
}

func TestGeoIPWithoutDatabaseSaysSo(t *testing.T) {
	f := New("")
	a := &model.Alias{Meta: model.Meta{ID: "g1", Name: "geo"}, Type: "geoip", Entries: []string{"de"}}
	f.Refresh(context.Background(), []*model.Alias{a}, time.Now())
	if st := f.StatusOf()["g1"]; !strings.Contains(st.Error, "no GeoIP database") {
		t.Errorf("status: %+v", st)
	}
	f.GeoDBDir = func() string { return t.TempDir() }
	f.Refresh(context.Background(), []*model.Alias{{Meta: model.Meta{ID: "g2"}, Type: "geoip", Entries: []string{"de"}}}, time.Now())
	if st := f.StatusOf()["g2"]; !strings.Contains(st.Error, "no country or city database") {
		t.Errorf("status: %+v", st)
	}
}
