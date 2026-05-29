package engine

import (
	"context"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/integrations/maxmind"
	"github.com/noahzmr/testudo/internal/storage"
)

// geoipCacheAdapter bridges storage.Store to maxmind.Cache. Kept out of the
// maxmind package so that package stays free of SQLite imports.
type geoipCacheAdapter struct {
	store *storage.Store
}

func (a geoipCacheAdapter) Get(ip string) (maxmind.Result, bool) {
	if a.store == nil {
		return maxmind.Result{}, false
	}
	row, ok := a.store.GetGeoIP(context.Background(), ip)
	if !ok {
		return maxmind.Result{}, false
	}
	return maxmind.Result{
		IP:            row.IP,
		CountryISO:    row.CountryISO,
		CountryName:   row.CountryName,
		City:          row.City,
		Latitude:      row.Latitude,
		Longitude:     row.Longitude,
		ASN:           row.ASN,
		ASOrg:         row.ASOrg,
		IsAnonymous:   row.IsAnonymous,
		IsVPN:         row.IsVPN,
		IsTor:         row.IsTor,
		IsHosting:     row.IsHosting,
		IsPublicProxy: row.IsPublicProxy,
		IsResidProxy:  row.IsResidProxy,
		ThreatLevel:   row.ThreatLevel,
		UpdatedAt:     row.UpdatedAt,
	}, true
}

func (a geoipCacheAdapter) Put(r maxmind.Result) {
	if a.store == nil {
		return
	}
	_ = a.store.PutGeoIP(context.Background(), storage.GeoIPRow{
		IP:            r.IP,
		CountryISO:    r.CountryISO,
		CountryName:   r.CountryName,
		City:          r.City,
		Latitude:      r.Latitude,
		Longitude:     r.Longitude,
		ASN:           r.ASN,
		ASOrg:         r.ASOrg,
		IsAnonymous:   r.IsAnonymous,
		IsVPN:         r.IsVPN,
		IsTor:         r.IsTor,
		IsHosting:     r.IsHosting,
		IsPublicProxy: r.IsPublicProxy,
		IsResidProxy:  r.IsResidProxy,
		ThreatLevel:   r.ThreatLevel,
		UpdatedAt:     r.UpdatedAt,
	})
}

// maxmindConfigFrom projects the live Thresholds snapshot into a maxmind.Config.
// Splits the comma-separated edition list into the slice the enricher wants.
func maxmindConfigFrom(t config.Thresholds) maxmind.Config {
	editions := []string{}
	for _, raw := range strings.Split(t.MaxMindEditions, ",") {
		if e := strings.TrimSpace(raw); e != "" {
			editions = append(editions, e)
		}
	}
	refresh := time.Duration(t.MaxMindRefreshHours) * time.Hour
	return maxmind.Config{
		Enabled:      t.MaxMindEnabled && t.MaxMindDBDir != "",
		DBDir:        t.MaxMindDBDir,
		AccountID:    t.MaxMindAccountID,
		LicenseKey:   t.MaxMindLicenseKey,
		EditionIDs:   editions,
		AutoUpdate:   t.MaxMindAutoUpdate,
		RefreshEvery: refresh,
	}
}

// startMaxMind constructs the enricher, opens any .mmdb files already on
// disk, and launches its background loop. Settings changes are picked up
// the next time Reload is called (see ReloadMaxMind).
func (e *Engine) startMaxMind(ctx context.Context) {
	e.maxmind = maxmind.New(geoipCacheAdapter{store: e.store})
	cfg := maxmindConfigFrom(e.settings.Snapshot())
	_ = e.maxmind.Reload(cfg)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		_ = e.maxmind.Run(ctx)
	}()
	// Watch the settings store for changes and reload the enricher when
	// MaxMind-related fields move. Cheap: one snapshot per second.
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		prev := cfg
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				next := maxmindConfigFrom(e.settings.Snapshot())
				if !maxmindConfigEqual(prev, next) {
					_ = e.maxmind.Reload(next)
					prev = next
				}
			}
		}
	}()
}

func maxmindConfigEqual(a, b maxmind.Config) bool {
	if a.Enabled != b.Enabled || a.DBDir != b.DBDir ||
		a.AccountID != b.AccountID || a.LicenseKey != b.LicenseKey ||
		a.AutoUpdate != b.AutoUpdate || a.RefreshEvery != b.RefreshEvery {
		return false
	}
	if len(a.EditionIDs) != len(b.EditionIDs) {
		return false
	}
	for i := range a.EditionIDs {
		if a.EditionIDs[i] != b.EditionIDs[i] {
			return false
		}
	}
	return true
}

// MaxMind returns the live enricher so the TUI / web layers can pull
// per-IP results out-of-band (e.g. for the /api/ip/{addr} endpoint and
// the device-detail panel). Returns nil before Start has run.
func (e *Engine) MaxMind() *maxmind.Enricher { return e.maxmind }

// enrichDevicesAndHosts pulls cached enrichment onto the inventory + the
// most recently observed remote hosts so the Devices and Flows tabs show
// country/ASN columns immediately when the cache already has the answer.
// Called on a slow tick from the engine; the enricher's background queue
// fills cache misses, and the next tick picks them up.
func (e *Engine) enrichDevicesAndHosts() {
	if e.maxmind == nil || !e.maxmind.Loaded() {
		return
	}
	if e.inventory != nil {
		for _, d := range e.inventory.Snapshot() {
			r, ok := e.maxmind.Lookup(d.IP)
			if !ok || r.Empty() {
				e.maxmind.Enqueue(d.IP)
				continue
			}
			e.inventory.AnnotateGeo(d.IP, discovery.GeoAnnotation{
				CountryISO:    r.CountryISO,
				CountryName:   r.CountryName,
				ASN:           r.ASN,
				ASOrg:         r.ASOrg,
				IsAnonymous:   r.IsAnonymous,
				IsVPN:         r.IsVPN,
				IsTor:         r.IsTor,
				IsHosting:     r.IsHosting,
				IsPublicProxy: r.IsPublicProxy,
				IsResidProxy:  r.IsResidProxy,
				ThreatLevel:   r.ThreatLevel,
			})
		}
	}
}

// startMaxMindAnnotator runs enrichDevicesAndHosts on a slow tick so the
// cached results land in the inventory without the render path having to
// look them up itself. 5s is plenty - enrichment is essentially static.
func (e *Engine) startMaxMindAnnotator(ctx context.Context) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.enrichDevicesAndHosts()
			}
		}
	}()
}
