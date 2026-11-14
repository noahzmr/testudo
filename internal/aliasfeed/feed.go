// Package aliasfeed keeps the content of aliases that are filled at run
// time: URL tables (a list of addresses and networks fetched over HTTP) and
// GeoIP aliases (the networks of a set of countries, from a MaxMind
// database). The packet filter renders that content into its named sets.
//
// Content is cached on disk, so a restart or a full reload of the ruleset
// does not leave the sets empty while the sources are unreachable.
package aliasfeed

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/noahzmr/testudo/internal/model"
)

const (
	maxListBytes   = 16 << 20
	maxListEntries = 500_000
	// DefaultRefresh applies to a URL table without an interval of its own.
	DefaultRefresh = time.Hour
	// MinRefresh keeps a misconfigured alias from hammering its source.
	MinRefresh = time.Minute
	geoRefresh = 24 * time.Hour
)

// Status is what is known about one alias's content.
type Status struct {
	Entries   int       `json:"entries"`
	Refreshed time.Time `json:"refreshed"`
	Error     string    `json:"error,omitempty"`
}

type entry struct {
	Elements []string `json:"elements"`
	Source   string   `json:"source"` // what the elements were built from
	Status
}

// Feed holds the content of every run-time alias.
type Feed struct {
	// Path is the cache file (written 0600). Empty disables the cache.
	Path string
	// GeoDBDir returns the directory with the MaxMind country or city
	// database. Nil or an empty result makes GeoIP aliases report an error.
	GeoDBDir func() string
	Client   *http.Client

	mu   sync.Mutex
	data map[string]*entry
}

// New loads the cache.
func New(path string) *Feed {
	f := &Feed{Path: path, data: map[string]*entry{},
		Client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
				return http.ErrUseLastResponse
			}
			return nil
		}}}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &f.data)
	}
	return f
}

// Snapshot returns the elements of every alias, by alias id.
func (f *Feed) Snapshot() map[string][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string][]string, len(f.data))
	for id, e := range f.data {
		out[id] = slices.Clone(e.Elements)
	}
	return out
}

// StatusOf returns what is known about each alias.
func (f *Feed) StatusOf() map[string]Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]Status, len(f.data))
	for id, e := range f.data {
		out[id] = e.Status
	}
	return out
}

func source(a *model.Alias) string {
	if a.Type == "geoip" {
		c := slices.Clone(a.Entries)
		sort.Strings(c)
		return "geoip:" + strings.ToUpper(strings.Join(c, ","))
	}
	return "url:" + a.URL
}

func interval(a *model.Alias) time.Duration {
	if a.Type == "geoip" {
		return geoRefresh
	}
	d, err := time.ParseDuration(a.Refresh)
	if err != nil || d <= 0 {
		return DefaultRefresh
	}
	return max(d, MinRefresh)
}

// Refresh updates every alias that is due and forgets aliases that no longer
// exist. It reports whether any content changed. A source that fails keeps
// its previous content; the error is recorded in the status.
func (f *Feed) Refresh(ctx context.Context, aliases []*model.Alias, now time.Time) (changed bool) {
	live := map[string]bool{}
	for _, a := range aliases {
		if a.Type != "url_table" && a.Type != "geoip" {
			continue
		}
		live[a.ID] = true
		f.mu.Lock()
		cur := f.data[a.ID]
		f.mu.Unlock()
		src := source(a)
		if cur != nil && cur.Source == src && now.Sub(cur.Refreshed) < interval(a) {
			continue
		}
		var elems []string
		var err error
		if a.Type == "geoip" {
			elems, err = f.countries(a.Entries)
		} else {
			elems, err = f.fetch(ctx, a.URL)
		}
		next := &entry{Source: src, Status: Status{Refreshed: now}}
		if err != nil {
			next.Error = err.Error()
			if cur != nil && cur.Source == src {
				next.Elements = cur.Elements // keep what we had
			}
		} else {
			next.Elements = elems
		}
		next.Entries = len(next.Elements)
		if cur == nil || !slices.Equal(cur.Elements, next.Elements) {
			changed = true
		}
		f.mu.Lock()
		f.data[a.ID] = next
		f.mu.Unlock()
	}
	f.mu.Lock()
	for id := range f.data {
		if !live[id] {
			delete(f.data, id)
			changed = true
		}
	}
	raw, _ := json.Marshal(f.data)
	f.mu.Unlock()
	if f.Path != "" {
		_ = os.MkdirAll(filepath.Dir(f.Path), 0o700)
		tmp := f.Path + ".tmp"
		if os.WriteFile(tmp, raw, 0o600) == nil {
			_ = os.Rename(tmp, f.Path)
		}
	}
	return changed
}

func (f *Feed) fetch(ctx context.Context, url string) ([]string, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("only http and https sources are supported")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source answered %s", res.Status)
	}
	return ParseList(io.LimitReader(res.Body, maxListBytes))
}

// ParseList reads one address or network per line. Blank lines, comments
// (# or ;) and trailing text after the first field are ignored; a line that
// is not an address is an error, so a wrong URL cannot quietly produce an
// empty or partial list.
func ParseList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		e, ok := normalise(fields[0])
		if !ok {
			return nil, fmt.Errorf("line %d: %q is not an address or network", n, fields[0])
		}
		if out = append(out, e); len(out) > maxListEntries {
			return nil, fmt.Errorf("more than %d entries", maxListEntries)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return slices.Compact(out), nil
}

func normalise(s string) (string, bool) {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String(), true
	}
	return "", false
}

// countries returns the networks registered to the given ISO country codes.
func (f *Feed) countries(codes []string) ([]string, error) {
	dir := ""
	if f.GeoDBDir != nil {
		dir = f.GeoDBDir()
	}
	if dir == "" {
		return nil, fmt.Errorf("no GeoIP database directory is configured")
	}
	var db *maxminddb.Reader
	for _, name := range []string{"GeoLite2-Country.mmdb", "GeoIP2-Country.mmdb", "GeoLite2-City.mmdb", "GeoIP2-City.mmdb"} {
		if r, err := maxminddb.Open(filepath.Join(dir, name)); err == nil {
			db = r
			break
		}
	}
	if db == nil {
		return nil, fmt.Errorf("no country or city database found in %s", dir)
	}
	defer db.Close()
	want := map[string]bool{}
	for _, c := range codes {
		want[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	var out []string
	var rec struct {
		Country struct {
			ISO string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	nets := db.Networks(maxminddb.SkipAliasedNetworks)
	for nets.Next() {
		rec.Country.ISO = ""
		n, err := nets.Network(&rec)
		if err != nil {
			return nil, err
		}
		if want[rec.Country.ISO] {
			out = append(out, n.String())
		}
	}
	if err := nets.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the database has no networks for %s", strings.Join(codes, ", "))
	}
	sort.Strings(out)
	return out, nil
}
