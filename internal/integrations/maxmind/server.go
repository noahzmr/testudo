package maxmind

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// remoteClient is the HTTP client for an adulau/mmdb-server instance
// (https://github.com/adulau/mmdb-server). It speaks the public API:
//
//	GET /geolookup/{ip}
//
// which returns a JSON array of per-database records. Each record carries
// the DB's metadata, the queried IP, and a flattened MMDB row in the
// `country` field. We merge across the array so callers see a single
// Result regardless of how many DBs the operator loaded into the server.
type remoteClient struct {
	baseURL string
	http    *http.Client
}

func newRemoteClient(baseURL string, timeout time.Duration) *remoteClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &remoteClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
	}
}

// geolookupResponse is the JSON shape mmdb-server returns. We tolerate
// extra fields - operators can serve any .mmdb file (anonymity, ISP, etc.)
// so the record body is intentionally open.
type geolookupResponse struct {
	IP          string                 `json:"ip"`
	Country     map[string]any         `json:"country"`
	CountryInfo map[string]string      `json:"country_info"`
	Meta        map[string]any         `json:"meta"`
	Extra       map[string]any         `json:"-"` // anything else
	Raw         map[string]any         `json:"-"`
}

// Lookup queries the mmdb-server for ip and folds every record in the
// response array into one Result. Returns (zero, err) on any transport
// failure so callers can fall back to local resolution or just skip the IP.
func (c *remoteClient) Lookup(ctx context.Context, ip string) (Result, error) {
	url := c.baseURL + "/geolookup/" + ip
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Result{}, fmt.Errorf("mmdb-server %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var records []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return Result{}, fmt.Errorf("mmdb-server decode: %w", err)
	}
	r := Result{IP: ip, UpdatedAt: time.Now()}
	for _, rec := range records {
		mergeRecord(&r, rec)
	}
	r.ThreatLevel = classifyThreat(r)
	return r, nil
}

// mergeRecord folds one mmdb-server array entry into r. Each entry carries
// one .mmdb's view of the IP; later records win for fields they fill in,
// so loading GeoOpen-Country-ASN after GeoOpen-Country adds the ASN without
// erasing the country. Field names follow the conventions used by the
// upstream MaxMind databases (iso_code, AutonomousSystemNumber, etc.).
func mergeRecord(r *Result, rec map[string]any) {
	country, _ := rec["country"].(map[string]any)
	info, _ := rec["country_info"].(map[string]string)
	if info == nil {
		// country_info comes back as map[string]any in some server builds.
		if anyInfo, ok := rec["country_info"].(map[string]any); ok {
			info = map[string]string{}
			for k, v := range anyInfo {
				if s, ok := v.(string); ok {
					info[k] = s
				}
			}
		}
	}
	city, _ := rec["city"].(map[string]any)
	traits, _ := rec["traits"].(map[string]any)

	// Country / ASN come from the `country` blob (mmdb-server flattens the
	// MMDB record there - so both GeoOpen-Country and GeoOpen-Country-ASN
	// land in the same map with different keys populated).
	if r.CountryISO == "" {
		r.CountryISO = stringAt(country, "iso_code")
	}
	if r.CountryName == "" {
		// Prefer English name; some DBs ship a names map.
		if names, ok := country["names"].(map[string]any); ok {
			r.CountryName = stringAt(names, "en")
		}
		if r.CountryName == "" {
			r.CountryName = info["Country"]
		}
	}
	if r.ASN == 0 {
		// JSON numbers decode as float64; some server builds emit strings.
		switch v := country["AutonomousSystemNumber"].(type) {
		case float64:
			r.ASN = uint(v)
		case string:
			r.ASN = uintFromString(v)
		}
	}
	if r.ASOrg == "" {
		r.ASOrg = stringAt(country, "AutonomousSystemOrganization")
	}
	// City / coords if a City DB is loaded.
	if r.City == "" && city != nil {
		if names, ok := city["names"].(map[string]any); ok {
			r.City = stringAt(names, "en")
		}
	}
	if r.Latitude == 0 {
		if loc, ok := rec["location"].(map[string]any); ok {
			if v, ok := loc["latitude"].(float64); ok {
				r.Latitude = v
			}
			if v, ok := loc["longitude"].(float64); ok {
				r.Longitude = v
			}
		}
		if r.Latitude == 0 && info["Latitude (average)"] != "" {
			// String coords from GeoOpen's country_info fallback.
			r.Latitude = parseFloat(info["Latitude (average)"])
			r.Longitude = parseFloat(info["Longitude (average)"])
		}
	}
	// Anonymity flags if a GeoIP2-Anonymous-IP-style DB is loaded behind
	// mmdb-server. The fields land either in `country` (flattened) or
	// `traits` depending on the database; check both.
	for _, m := range []map[string]any{country, traits} {
		if m == nil {
			continue
		}
		if b, ok := m["is_anonymous"].(bool); ok && b {
			r.IsAnonymous = true
		}
		if b, ok := m["is_anonymous_vpn"].(bool); ok && b {
			r.IsVPN = true
		}
		if b, ok := m["is_tor_exit_node"].(bool); ok && b {
			r.IsTor = true
		}
		if b, ok := m["is_hosting_provider"].(bool); ok && b {
			r.IsHosting = true
		}
		if b, ok := m["is_public_proxy"].(bool); ok && b {
			r.IsPublicProxy = true
		}
		if b, ok := m["is_residential_proxy"].(bool); ok && b {
			r.IsResidProxy = true
		}
	}
}

func stringAt(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func uintFromString(s string) uint {
	var n uint
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint(c-'0')
	}
	return n
}

func parseFloat(s string) float64 {
	// Minimal parser - the server emits plain decimals like "50.8333".
	var (
		f      float64
		neg    bool
		frac   float64 = 0.1
		inFrac bool
	)
	for i, c := range s {
		switch {
		case i == 0 && c == '-':
			neg = true
		case c == '.':
			inFrac = true
		case c >= '0' && c <= '9':
			if inFrac {
				f += float64(c-'0') * frac
				frac *= 0.1
			} else {
				f = f*10 + float64(c-'0')
			}
		default:
			return 0
		}
	}
	if neg {
		f = -f
	}
	return f
}
