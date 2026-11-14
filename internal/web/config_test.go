package web

import (
	"io/fs"
	"regexp"
	"testing"
)

// The console references the configuration pane's assets by content hash,
// so a new build is picked up by browsers.
func TestConsoleReferencesConfigAssets(t *testing.T) {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		t.Fatal(err)
	}
	set, err := newStaticSet(sub)
	if err != nil {
		t.Fatal(err)
	}
	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	out := string(set.Version(page))
	for _, asset := range []string{"config.js", "config.css", "app.css"} {
		if !regexp.MustCompile(`/static/` + regexp.QuoteMeta(asset) + `\?v=[0-9a-f]{12}"`).MatchString(out) {
			t.Errorf("index.html does not reference %s by content hash", asset)
		}
	}
}
