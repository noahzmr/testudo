// Package maxmind enriches observed IPs with country / ASN / anonymity
// signals from MaxMind GeoLite2 / GeoIP2 .mmdb databases.
//
// The package is a no-op when no database directory is configured, so callers
// can wire it unconditionally. Lookups are served from a process-local LRU
// cache plus an optional SQLite-backed cache so repeated sightings of the
// same IP never re-read the .mmdb file. New IPs flow through an asynchronous
// queue; the live capture path never blocks on a lookup.
//
// Supported editions (any subset can be installed):
//
//   - GeoLite2-Country / GeoIP2-Country  -> Country / IsoCode
//   - GeoLite2-City    / GeoIP2-City     -> Country + City + lat/lon
//   - GeoLite2-ASN     / GeoIP2-ISP      -> ASN + Organisation
//   - GeoIP2-Anonymous-IP                -> proxy / VPN / Tor / hosting flags
//     (this is the closest thing MaxMind ships to "threat intel")
package maxmind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// Result is the enriched view of one IP. All fields are best-effort; empty
// values mean either the database isn't configured or the address wasn't
// found in it.
type Result struct {
	IP            string    `json:"ip"`
	CountryISO    string    `json:"country_iso,omitempty"`
	CountryName   string    `json:"country_name,omitempty"`
	City          string    `json:"city,omitempty"`
	Latitude      float64   `json:"latitude,omitempty"`
	Longitude     float64   `json:"longitude,omitempty"`
	ASN           uint      `json:"asn,omitempty"`
	ASOrg         string    `json:"as_org,omitempty"`
	IsAnonymous   bool      `json:"is_anonymous,omitempty"`
	IsVPN         bool      `json:"is_vpn,omitempty"`
	IsTor         bool      `json:"is_tor,omitempty"`
	IsHosting     bool      `json:"is_hosting,omitempty"`
	IsPublicProxy bool      `json:"is_public_proxy,omitempty"`
	IsResidProxy  bool      `json:"is_residential_proxy,omitempty"`
	ThreatLevel   string    `json:"threat_level,omitempty"` // "", "low", "medium", "high"
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// Empty reports whether r carries no signal worth showing.
func (r Result) Empty() bool {
	return r.CountryISO == "" && r.ASN == 0 && r.ASOrg == "" &&
		!r.IsAnonymous && !r.IsVPN && !r.IsTor && !r.IsHosting &&
		!r.IsPublicProxy && !r.IsResidProxy
}

// Config is the runtime configuration the Enricher reads. It is a snapshot
// of the user-facing settings; the engine reconciles changes by calling
// Reload with the new values.
type Config struct {
	Enabled bool // master switch; false => no-op everywhere

	// ServerURL points at an adulau/mmdb-server instance (or any compatible
	// HTTP front-end that exposes GET /geolookup/{ip}). Recommended path:
	// run the server alongside Testudo with the .mmdb files of your choice
	// and let Testudo speak HTTP to it. Empty falls back to local-file mode.
	ServerURL     string
	ServerTimeout time.Duration

	// Local-file mode (used when ServerURL is empty). Kept for operators who
	// don't want to run a sidecar - the geoip2-golang reader opens the
	// .mmdb files directly.
	DBDir         string
	CountryDB     string
	CityDB        string
	ASNDB         string
	AnonymousIPDB string
	LicenseKey    string   // for auto-update; empty disables updates
	AccountID     string   // optional; required for some commercial editions
	EditionIDs    []string // editions to download when auto-update fires
	AutoUpdate    bool
	RefreshEvery  time.Duration

	CacheTTL time.Duration // per-IP cache TTL; defaults to 24h
}

// Defaults returns a Config with sensible filenames + free-tier editions.
func Defaults() Config {
	return Config{
		CountryDB:     "GeoLite2-Country.mmdb",
		CityDB:        "GeoLite2-City.mmdb",
		ASNDB:         "GeoLite2-ASN.mmdb",
		AnonymousIPDB: "GeoIP2-Anonymous-IP.mmdb",
		EditionIDs:    []string{"GeoLite2-Country", "GeoLite2-City", "GeoLite2-ASN"},
		RefreshEvery:  7 * 24 * time.Hour,
		CacheTTL:      24 * time.Hour,
	}
}

// Cache abstracts the persistent enrichment cache (see storage.Store).
// The Enricher consults the cache before opening a reader, and writes back
// every successful lookup. An interface keeps the maxmind package free of
// SQLite imports - the engine wires concrete storage.
type Cache interface {
	Get(ip string) (Result, bool)
	Put(r Result)
}

// Enricher is the singleton service. Methods are safe for concurrent use.
type Enricher struct {
	mu      sync.RWMutex
	cfg     Config
	country *geoip2.Reader
	city    *geoip2.Reader
	asn     *geoip2.Reader
	anon    *geoip2.Reader
	remote  *remoteClient // mmdb-server HTTP client; non-nil in server mode
	mem     map[string]memEntry
	queue   chan string
	cache   Cache

	// loaded flips true once at least one .mmdb file opens successfully so
	// callers can show a "geoip database missing" hint when it stays false.
	loaded bool
	status string // human-readable load status for the Settings UI
}

type memEntry struct {
	r        Result
	deadline time.Time
}

// New constructs an Enricher. Reload() must be called once before lookups
// will resolve anything; Run() drives the async queue + auto-update.
func New(cache Cache) *Enricher {
	return &Enricher{
		mem:   make(map[string]memEntry, 4096),
		queue: make(chan string, 1024),
		cache: cache,
	}
}

// Status returns a one-line human-readable load status for the Settings UI.
func (e *Enricher) Status() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.status == "" {
		return "disabled"
	}
	return e.status
}

// Loaded reports whether at least one .mmdb file is open.
func (e *Enricher) Loaded() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.loaded
}

// Reload (re-)opens the .mmdb files described by cfg. Safe to call at any
// time - the previous readers are closed under the write lock.
func (e *Enricher) Reload(cfg Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.closeAllLocked()
	e.cfg = applyDefaults(cfg)
	e.mem = make(map[string]memEntry, 4096)
	e.loaded = false
	e.status = ""

	if !cfg.Enabled {
		e.status = "disabled"
		return nil
	}

	// Server mode wins when a URL is configured. The HTTP client never
	// "fails to load" the way a missing .mmdb file does - reachability is
	// only known at lookup time - so we optimistically flip `loaded` and
	// let Lookup surface transport errors as empty results.
	if strings.TrimSpace(cfg.ServerURL) != "" {
		e.remote = newRemoteClient(cfg.ServerURL, cfg.ServerTimeout)
		e.loaded = true
		e.status = "mmdb-server: " + cfg.ServerURL
		return nil
	}

	if cfg.DBDir == "" {
		e.status = "disabled (no server URL, no DB dir)"
		return nil
	}

	open := func(filename string) *geoip2.Reader {
		if filename == "" {
			return nil
		}
		path := filepath.Join(cfg.DBDir, filename)
		if _, err := os.Stat(path); err != nil {
			return nil
		}
		r, err := geoip2.Open(path)
		if err != nil {
			return nil
		}
		return r
	}

	e.country = open(e.cfg.CountryDB)
	e.city = open(e.cfg.CityDB)
	e.asn = open(e.cfg.ASNDB)
	e.anon = open(e.cfg.AnonymousIPDB)

	loaded := []string{}
	if e.country != nil {
		loaded = append(loaded, "country")
	}
	if e.city != nil {
		loaded = append(loaded, "city")
	}
	if e.asn != nil {
		loaded = append(loaded, "asn")
	}
	if e.anon != nil {
		loaded = append(loaded, "anonymous-ip")
	}
	if len(loaded) == 0 {
		e.status = fmt.Sprintf("no .mmdb files in %s", cfg.DBDir)
		return errors.New(e.status)
	}
	e.loaded = true
	e.status = fmt.Sprintf("loaded: %v", loaded)
	return nil
}

func (e *Enricher) closeAllLocked() {
	for _, r := range []**geoip2.Reader{&e.country, &e.city, &e.asn, &e.anon} {
		if *r != nil {
			_ = (*r).Close()
			*r = nil
		}
	}
	e.remote = nil
}

// Close releases the open readers. Idempotent.
func (e *Enricher) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closeAllLocked()
	e.loaded = false
}

// Lookup returns the enriched view of ip. Returns (zero, false) when the
// service is disabled or no database is loaded.
//
// Resolution order:
//  1. process-local LRU cache (hot path - no allocs after the first miss)
//  2. persistent Cache (survives restarts; populated on first miss)
//  3. .mmdb readers (the slow path; one shared rwlock read)
//
// Private / loopback / link-local addresses short-circuit to an empty
// Result with ok=true so callers don't repeatedly probe internal IPs.
func (e *Enricher) Lookup(ip string) (Result, bool) {
	if ip == "" {
		return Result{}, false
	}
	if isPrivate(ip) {
		return Result{IP: ip}, true
	}

	e.mu.RLock()
	if entry, ok := e.mem[ip]; ok && time.Now().Before(entry.deadline) {
		e.mu.RUnlock()
		return entry.r, true
	}
	loaded := e.loaded
	ttl := e.cfg.CacheTTL
	e.mu.RUnlock()

	if e.cache != nil {
		if r, ok := e.cache.Get(ip); ok {
			e.memPut(ip, r, ttl)
			return r, true
		}
	}
	if !loaded {
		return Result{}, false
	}

	r := e.resolve(ip)
	e.memPut(ip, r, ttl)
	if e.cache != nil && !r.Empty() {
		e.cache.Put(r)
	}
	return r, true
}

// Peek returns the enriched view of ip from the in-process memory cache only.
// It never touches the .mmdb readers, the persistent cache, or the network,
// so it is safe to call from a render loop. Returns (zero, false) on a miss;
// callers should Enqueue(ip) to schedule asynchronous resolution and pick the
// result up on a later tick. Private addresses always miss.
func (e *Enricher) Peek(ip string) (Result, bool) {
	if ip == "" || isPrivate(ip) {
		return Result{}, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if entry, ok := e.mem[ip]; ok && time.Now().Before(entry.deadline) {
		return entry.r, true
	}
	return Result{}, false
}

func (e *Enricher) memPut(ip string, r Result, ttl time.Duration) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	e.mu.Lock()
	if len(e.mem) > 16384 {
		// crude bound: drop the whole map rather than implement true LRU.
		// At ~16k entries the lookup map is large enough to be worth
		// dropping but small enough that re-warming is cheap.
		e.mem = make(map[string]memEntry, 4096)
	}
	e.mem[ip] = memEntry{r: r, deadline: time.Now().Add(ttl)}
	e.mu.Unlock()
}

// resolve performs the actual .mmdb reads. Caller holds no lock; we grab a
// read lock for the duration of the lookup so Reload can't yank a reader
// out from under us.
func (e *Enricher) resolve(ip string) Result {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Server mode: ask the mmdb-server sidecar over HTTP. Transport errors
	// surface as an empty Result (ok=true at the Lookup layer) so we don't
	// hammer a flaky server for the same IP every render tick.
	if e.remote != nil {
		timeout := e.cfg.ServerTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if r, err := e.remote.Lookup(ctx, ip); err == nil {
			return r
		}
		return Result{IP: ip, UpdatedAt: time.Now()}
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		return Result{IP: ip}
	}
	r := Result{IP: ip, UpdatedAt: time.Now()}

	if e.city != nil {
		if rec, err := e.city.City(addr); err == nil {
			r.CountryISO = rec.Country.IsoCode
			r.CountryName = rec.Country.Names["en"]
			r.City = rec.City.Names["en"]
			r.Latitude = rec.Location.Latitude
			r.Longitude = rec.Location.Longitude
		}
	} else if e.country != nil {
		if rec, err := e.country.Country(addr); err == nil {
			r.CountryISO = rec.Country.IsoCode
			r.CountryName = rec.Country.Names["en"]
		}
	}
	if e.asn != nil {
		if rec, err := e.asn.ASN(addr); err == nil {
			r.ASN = rec.AutonomousSystemNumber
			r.ASOrg = rec.AutonomousSystemOrganization
		}
	}
	if e.anon != nil {
		if rec, err := e.anon.AnonymousIP(addr); err == nil {
			r.IsAnonymous = rec.IsAnonymous
			r.IsVPN = rec.IsAnonymousVPN
			r.IsTor = rec.IsTorExitNode
			r.IsHosting = rec.IsHostingProvider
			r.IsPublicProxy = rec.IsPublicProxy
			r.IsResidProxy = rec.IsResidentialProxy
		}
	}
	r.ThreatLevel = classifyThreat(r)
	return r
}

// classifyThreat assigns a coarse severity based on the anonymity flags.
// "high" = Tor or residential proxy (often abused); "medium" = VPN /
// public proxy / generic anonymous; "low" = hosting only; "" = nothing.
func classifyThreat(r Result) string {
	switch {
	case r.IsTor, r.IsResidProxy:
		return "high"
	case r.IsVPN, r.IsPublicProxy, r.IsAnonymous:
		return "medium"
	case r.IsHosting:
		return "low"
	}
	return ""
}

// Enqueue schedules ip for asynchronous resolution. Non-blocking; drops the
// request when the queue is saturated rather than stalling the caller.
// Already-cached IPs are skipped to keep the queue useful.
func (e *Enricher) Enqueue(ip string) {
	if ip == "" || isPrivate(ip) {
		return
	}
	e.mu.RLock()
	if _, ok := e.mem[ip]; ok {
		e.mu.RUnlock()
		return
	}
	e.mu.RUnlock()
	select {
	case e.queue <- ip:
	default:
	}
}

// Run drives the async queue and (when enabled) the background updater.
// Returns when ctx is cancelled.
func (e *Enricher) Run(ctx context.Context) error {
	refreshTick := time.NewTicker(time.Hour)
	defer refreshTick.Stop()
	for {
		select {
		case <-ctx.Done():
			e.Close()
			return ctx.Err()
		case ip := <-e.queue:
			_, _ = e.Lookup(ip)
		case <-refreshTick.C:
			e.mu.RLock()
			cfg := e.cfg
			e.mu.RUnlock()
			if cfg.AutoUpdate && cfg.LicenseKey != "" && cfg.DBDir != "" {
				if dur := time.Since(lastUpdateOf(cfg.DBDir, cfg.EditionIDs)); dur >= cfg.RefreshEvery {
					_ = UpdateAll(ctx, cfg)
					// Re-open readers against the freshly-downloaded files.
					_ = e.Reload(cfg)
				}
			}
		}
	}
}

func applyDefaults(cfg Config) Config {
	d := Defaults()
	if cfg.CountryDB == "" {
		cfg.CountryDB = d.CountryDB
	}
	if cfg.CityDB == "" {
		cfg.CityDB = d.CityDB
	}
	if cfg.ASNDB == "" {
		cfg.ASNDB = d.ASNDB
	}
	if cfg.AnonymousIPDB == "" {
		cfg.AnonymousIPDB = d.AnonymousIPDB
	}
	if len(cfg.EditionIDs) == 0 {
		cfg.EditionIDs = d.EditionIDs
	}
	if cfg.RefreshEvery <= 0 {
		cfg.RefreshEvery = d.RefreshEvery
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = d.CacheTTL
	}
	return cfg
}

// isPrivate reports whether ip is an address we shouldn't bother looking up
// (RFC1918, loopback, link-local, multicast, ULA, unspecified). Mirrors the
// rule used by the flow rollup so the two views stay in sync.
func isPrivate(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10,
			v4[0] == 172 && v4[1]&0xF0 == 16,
			v4[0] == 192 && v4[1] == 168,
			v4[0] == 169 && v4[1] == 254,
			v4[0] == 100 && v4[1]&0xC0 == 64: // CGNAT 100.64/10
			return true
		}
		return false
	}
	if len(ip) == 16 && ip[0]&0xFE == 0xFC {
		return true
	}
	return false
}
