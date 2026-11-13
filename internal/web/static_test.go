package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func testStatic(t *testing.T) *staticSet {
	t.Helper()
	big := strings.Repeat("body { color: red; }\n", 100)
	set, err := newStaticSet(fstest.MapFS{
		"app.css":        {Data: []byte(`@font-face { src: url("/static/fonts/a.woff2") }` + "\n" + big)},
		"app.js":         {Data: []byte(strings.Repeat("console.log(1);\n", 100))},
		"fonts/a.woff2":  {Data: []byte("wOF2 binary")},
		"index.html":     {Data: []byte("<html></html>")},
		"vendor/tiny.js": {Data: []byte("x")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func get(h http.Handler, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStaticVersionRewritesKnownRefsOnly(t *testing.T) {
	set := testStatic(t)
	out := string(set.Version([]byte(`<link href="/static/app.css"><script src="/static/app.js"></script><img src="/static/missing.png">`)))
	if !strings.Contains(out, `/static/app.css?v=`+set.files["app.css"].hash+`"`) {
		t.Fatalf("css not versioned: %s", out)
	}
	if !strings.Contains(out, `/static/app.js?v=`+set.files["app.js"].hash+`"`) {
		t.Fatalf("js not versioned: %s", out)
	}
	if !strings.Contains(out, `/static/missing.png"`) {
		t.Fatalf("unknown ref changed: %s", out)
	}
	// Stylesheets carry versioned font URLs, so a font change re-versions them.
	if !bytes.Contains(set.files["app.css"].body, []byte(`/static/fonts/a.woff2?v=`+set.files["fonts/a.woff2"].hash+`"`)) {
		t.Fatal("font reference inside css not versioned")
	}
}

func TestStaticCachingAndCompression(t *testing.T) {
	set := testStatic(t)
	h := http.StripPrefix("/static", set)
	js := set.files["app.js"]

	cur := get(h, "/static/app.js?v="+js.hash, map[string]string{"Accept-Encoding": "gzip"})
	if cur.Code != 200 || cur.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("current hash: code %d cache %q", cur.Code, cur.Header().Get("Cache-Control"))
	}
	if cur.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("app.js not gzipped")
	}
	zr, err := gzip.NewReader(cur.Body)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	if !bytes.Equal(plain, js.body) {
		t.Fatal("gzip body does not decode to the asset")
	}

	stale := get(h, "/static/app.js?v=old", nil)
	if stale.Header().Get("Cache-Control") != "no-cache" || stale.Header().Get("Content-Encoding") != "" {
		t.Fatalf("stale hash: cache %q enc %q", stale.Header().Get("Cache-Control"), stale.Header().Get("Content-Encoding"))
	}

	nm := get(h, "/static/app.js", map[string]string{"If-None-Match": `W/"` + js.hash + `"`})
	if nm.Code != http.StatusNotModified || nm.Body.Len() != 0 {
		t.Fatalf("If-None-Match: code %d body %d", nm.Code, nm.Body.Len())
	}

	font := get(h, "/static/fonts/a.woff2", map[string]string{"Accept-Encoding": "gzip"})
	if font.Header().Get("Content-Encoding") != "" {
		t.Fatal("woff2 must not be gzipped")
	}
	if get(h, "/static/index.html", nil).Code != http.StatusNotFound {
		t.Fatal("raw index.html must not be served from /static/")
	}
	if get(h, "/static/nope.js", nil).Code != http.StatusNotFound {
		t.Fatal("unknown asset must 404")
	}
}

func TestAcceptsGzip(t *testing.T) {
	cases := map[string]bool{
		"":                      false,
		"gzip":                  true,
		"br, gzip;q=0.8":        true,
		"gzip;q=0":              false,
		"gzip; q=0.0, identity": false,
		"deflate":               false,
	}
	for hdr, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept-Encoding", hdr)
		if got := acceptsGzip(r); got != want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", hdr, got, want)
		}
	}
}

func TestTransportGzipsJSONAndSetsHeaders(t *testing.T) {
	s := &Server{}
	payload := `{"k":"` + strings.Repeat("v", 4000) + `"}`
	mux := http.NewServeMux()
	mux.HandleFunc("/api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, payload)
	})
	mux.HandleFunc("/api/empty", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := s.withTransport(mux)

	rec := get(h, "/api/snapshot", map[string]string{"Accept-Encoding": "gzip"})
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("json not gzipped")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("api response must be no-store")
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal("missing CSP")
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != payload {
		t.Fatal("gzip round trip mismatch")
	}

	plain := get(h, "/api/snapshot", nil)
	if plain.Header().Get("Content-Encoding") != "" || plain.Body.String() != payload {
		t.Fatal("client without gzip must get plain JSON")
	}
	if e := get(h, "/api/empty", map[string]string{"Accept-Encoding": "gzip"}); e.Code != http.StatusNoContent || e.Header().Get("Content-Encoding") != "" {
		t.Fatalf("204 must stay uncompressed: %d %q", e.Code, e.Header().Get("Content-Encoding"))
	}
}

// The real embedded tree: every page reference resolves to a vendored asset
// (no CDN), and every reference gets versioned.
func TestEmbeddedPagesReferenceOnlyLocalAssets(t *testing.T) {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		t.Fatal(err)
	}
	set, err := newStaticSet(sub)
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"index.html", "login.html"} {
		b, _ := fs.ReadFile(sub, page)
		out := string(set.Version(b))
		for _, bad := range []string{"https://", "http://"} {
			for _, attr := range []string{`src="` + bad, `href="` + bad, `content="` + bad} {
				if strings.Contains(out, attr) {
					t.Errorf("%s loads a remote resource (%s)", page, attr)
				}
			}
		}
		for _, m := range staticRef.FindAllStringSubmatch(out, -1) {
			t.Errorf("%s: unversioned or missing asset /static/%s", page, m[1])
		}
	}
}
