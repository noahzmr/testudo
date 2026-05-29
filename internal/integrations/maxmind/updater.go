package maxmind

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// downloadEndpoint is the MaxMind permalink for direct .mmdb downloads.
// It works for both GeoLite2 (free, requires a free account + license key)
// and the commercial GeoIP2 editions.
const downloadEndpoint = "https://download.maxmind.com/app/geoip_download"

// UpdateAll downloads every edition in cfg.EditionIDs and extracts the
// .mmdb file from each tar.gz into cfg.DBDir. Existing files are
// overwritten atomically (write tmp + rename). Errors are best-effort -
// one failed edition doesn't abort the rest.
func UpdateAll(ctx context.Context, cfg Config) error {
	if cfg.DBDir == "" || cfg.LicenseKey == "" {
		return fmt.Errorf("maxmind: DBDir and LicenseKey required for update")
	}
	if err := os.MkdirAll(cfg.DBDir, 0o755); err != nil {
		return fmt.Errorf("maxmind: mkdir %s: %w", cfg.DBDir, err)
	}
	var firstErr error
	for _, edition := range cfg.EditionIDs {
		if err := downloadEdition(ctx, cfg, edition); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// downloadEdition fetches a single tar.gz from MaxMind's permalink and
// writes the embedded .mmdb to cfg.DBDir/<EditionID>.mmdb.
func downloadEdition(ctx context.Context, cfg Config, editionID string) error {
	u, _ := url.Parse(downloadEndpoint)
	q := u.Query()
	q.Set("edition_id", editionID)
	q.Set("license_key", cfg.LicenseKey)
	q.Set("suffix", "tar.gz")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("maxmind %s: build request: %w", editionID, err)
	}
	if cfg.AccountID != "" {
		req.SetBasicAuth(cfg.AccountID, cfg.LicenseKey)
	}
	cl := &http.Client{Timeout: 5 * time.Minute}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("maxmind %s: get: %w", editionID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("maxmind %s: http %s", editionID, resp.Status)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("maxmind %s: gunzip: %w", editionID, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("maxmind %s: tar: %w", editionID, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		out := filepath.Join(cfg.DBDir, editionID+".mmdb")
		if err := atomicWrite(out, tr, hdr.Size); err != nil {
			return fmt.Errorf("maxmind %s: write %s: %w", editionID, out, err)
		}
	}
	return nil
}

// atomicWrite copies up to n bytes from src into path via a tmp file +
// rename so partial writes never leave a corrupted .mmdb on disk.
func atomicWrite(path string, src io.Reader, n int64) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mmdb-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.CopyN(tmp, src, n); err != nil && err != io.EOF {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// lastUpdateOf reports the most-recent modtime among the .mmdb files for the
// given editions. Returns the zero time when none exist, so the first call
// after enabling auto-update kicks off an immediate refresh.
func lastUpdateOf(dir string, editions []string) time.Time {
	var latest time.Time
	for _, ed := range editions {
		fi, err := os.Stat(filepath.Join(dir, ed+".mmdb"))
		if err != nil {
			continue
		}
		if fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}
	}
	return latest
}

// dbHash returns a short hex hash of a .mmdb file, suitable for surfacing
// in the Settings UI as a freshness fingerprint. Empty string on error.
func dbHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
