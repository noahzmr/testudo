package storage

import (
	"context"
	"database/sql"
	"time"
)

// GeoIPRow mirrors the geoip_cache table. Times are stored as unix-milli ints
// in SQLite so they sort naturally; the API exposes time.Time.
type GeoIPRow struct {
	IP            string
	CountryISO    string
	CountryName   string
	City          string
	Latitude      float64
	Longitude     float64
	ASN           uint
	ASOrg         string
	IsAnonymous   bool
	IsVPN         bool
	IsTor         bool
	IsHosting     bool
	IsPublicProxy bool
	IsResidProxy  bool
	ThreatLevel   string
	UpdatedAt     time.Time
}

// GetGeoIP returns the cached enrichment for ip, or (zero, false) when
// nothing has been stored yet. The maxmind package layers a TTL check on
// top so stale rows don't need to be deleted from SQL eagerly.
func (s *Store) GetGeoIP(ctx context.Context, ip string) (GeoIPRow, bool) {
	row := s.db.QueryRowContext(ctx, `
		SELECT ip, country_iso, country_name, city, latitude, longitude,
		       asn, as_org, is_anonymous, is_vpn, is_tor, is_hosting,
		       is_pub_proxy, is_res_proxy, threat_level, updated_at
		  FROM geoip_cache WHERE ip = ?`, ip)

	var (
		r       GeoIPRow
		ms      int64
		anon    int
		vpn     int
		tor     int
		host    int
		pproxy  int
		rproxy  int
		country sql.NullString
		cname   sql.NullString
		city    sql.NullString
		asorg   sql.NullString
		threat  sql.NullString
	)
	err := row.Scan(&r.IP, &country, &cname, &city, &r.Latitude, &r.Longitude,
		&r.ASN, &asorg, &anon, &vpn, &tor, &host, &pproxy, &rproxy, &threat, &ms)
	if err != nil {
		return GeoIPRow{}, false
	}
	r.CountryISO = country.String
	r.CountryName = cname.String
	r.City = city.String
	r.ASOrg = asorg.String
	r.ThreatLevel = threat.String
	r.IsAnonymous = anon == 1
	r.IsVPN = vpn == 1
	r.IsTor = tor == 1
	r.IsHosting = host == 1
	r.IsPublicProxy = pproxy == 1
	r.IsResidProxy = rproxy == 1
	r.UpdatedAt = time.UnixMilli(ms)
	return r, true
}

// PutGeoIP upserts the cache row. Counter-style accumulation isn't needed -
// enrichment is a snapshot, not a tally.
func (s *Store) PutGeoIP(ctx context.Context, r GeoIPRow) error {
	ts := r.UpdatedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO geoip_cache (ip, country_iso, country_name, city, latitude, longitude,
		                         asn, as_org, is_anonymous, is_vpn, is_tor, is_hosting,
		                         is_pub_proxy, is_res_proxy, threat_level, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
		  country_iso  = excluded.country_iso,
		  country_name = excluded.country_name,
		  city         = excluded.city,
		  latitude     = excluded.latitude,
		  longitude    = excluded.longitude,
		  asn          = excluded.asn,
		  as_org       = excluded.as_org,
		  is_anonymous = excluded.is_anonymous,
		  is_vpn       = excluded.is_vpn,
		  is_tor       = excluded.is_tor,
		  is_hosting   = excluded.is_hosting,
		  is_pub_proxy = excluded.is_pub_proxy,
		  is_res_proxy = excluded.is_res_proxy,
		  threat_level = excluded.threat_level,
		  updated_at   = excluded.updated_at
		`,
		r.IP, r.CountryISO, r.CountryName, r.City, r.Latitude, r.Longitude,
		r.ASN, r.ASOrg, b(r.IsAnonymous), b(r.IsVPN), b(r.IsTor), b(r.IsHosting),
		b(r.IsPublicProxy), b(r.IsResidProxy), r.ThreatLevel, ts.UnixMilli(),
	)
	return err
}
