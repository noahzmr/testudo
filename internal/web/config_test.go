package web

import (
	"io/fs"
	"regexp"
	"testing"
)

// The configuration page must change its ETag whenever one of its assets
// changes; otherwise browsers revalidate to the page of the previous build.
func TestConfigPageReferencesVersionedAssets(t *testing.T) {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		t.Fatal(err)
	}
	set, err := newStaticSet(sub)
	if err != nil {
		t.Fatal(err)
	}
	page, err := assetsFS.ReadFile("assets/config.html")
	if err != nil {
		t.Fatal(err)
	}
	out := string(set.Version(page))
	for _, asset := range []string{"config.js", "config.css", "app.css"} {
		if !regexp.MustCompile(`/static/` + regexp.QuoteMeta(asset) + `\?v=[0-9a-f]{12}"`).MatchString(out) {
			t.Errorf("config.html does not reference %s by content hash", asset)
		}
	}
}
