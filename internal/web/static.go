package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// staticAsset is one embedded file prepared once at startup: its bytes, a
// gzip copy when compressing pays off, and a content hash that doubles as
// ETag and cache-busting version.
type staticAsset struct {
	body  []byte
	gz    []byte // nil when the type is already compressed (woff2) or tiny
	hash  string // first 12 hex chars of sha256(body)
	ctype string
}

// staticSet serves the embedded assets.
//
//   - Pages reference every asset as /static/<path>?v=<hash>. A request that
//     carries the current hash is immutable for a year; anything else is
//     revalidated (ETag → 304). A new build changes the hash, so browsers
//     never run a stale app.js against a new API, and never re-download an
//     unchanged one.
//   - Text assets are gzipped once at startup at the best level instead of
//     per request.
type staticSet struct {
	files map[string]*staticAsset // keyed by path below assets/
}

// staticRef matches an asset reference inside HTML/CSS: /static/<path>
// followed by the closing quote or paren.
var staticRef = regexp.MustCompile(`/static/([A-Za-z0-9._/-]+)(["')])`)

func newStaticSet(root fs.FS) (*staticSet, error) {
	set := &staticSet{files: map[string]*staticAsset{}}
	var names []string
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(root, p)
		if err != nil {
			return err
		}
		ctype := mime.TypeByExtension(path.Ext(p))
		if ctype == "" {
			ctype = http.DetectContentType(b)
		}
		set.files[p] = &staticAsset{body: b, ctype: ctype}
		names = append(names, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Hash leaf assets first, then stylesheets (they reference fonts), so a
	// font change also changes the stylesheet's version.
	sort.SliceStable(names, func(i, j int) bool {
		return !strings.HasSuffix(names[i], ".css") && strings.HasSuffix(names[j], ".css")
	})
	for _, p := range names {
		a := set.files[p]
		if strings.HasSuffix(p, ".css") {
			a.body = set.Version(a.body)
		}
		sum := sha256.Sum256(a.body)
		a.hash = hex.EncodeToString(sum[:])[:12]
		if compressible(a.ctype) && len(a.body) > 512 {
			gz, err := gzipBytes(a.body)
			if err != nil {
				return nil, fmt.Errorf("gzip %s: %w", p, err)
			}
			if len(gz) < len(a.body) {
				a.gz = gz
			}
		}
	}
	return set, nil
}

// Version rewrites every /static/<path> reference in an HTML or CSS document
// to /static/<path>?v=<hash>. Unknown paths are left alone.
func (s *staticSet) Version(doc []byte) []byte {
	return staticRef.ReplaceAllFunc(doc, func(m []byte) []byte {
		sub := staticRef.FindSubmatch(m)
		a, ok := s.files[string(sub[1])]
		if !ok || a.hash == "" {
			return m
		}
		return []byte("/static/" + string(sub[1]) + "?v=" + a.hash + string(sub[2]))
	})
}

// ServeHTTP serves /static/<path> (prefix already stripped).
func (s *staticSet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a, ok := s.files[strings.TrimPrefix(r.URL.Path, "/")]
	if !ok || strings.HasSuffix(r.URL.Path, ".html") {
		// The HTML pages are served by their own handlers (index is behind
		// auth, login is a template) - never raw from /static/.
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("v") == a.hash {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	a.write(w, r)
}

// write sends the asset with its ETag, answering a matching If-None-Match
// with 304 and a gzip-accepting client with the precompressed body.
func (a *staticAsset) write(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	etag := `"` + a.hash + `"`
	h.Set("ETag", etag)
	h.Set("Content-Type", a.ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	if a.gz != nil {
		h.Add("Vary", "Accept-Encoding")
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatch(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := a.body
	if a.gz != nil && acceptsGzip(r) {
		body = a.gz
		h.Set("Content-Encoding", "gzip")
	}
	h.Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func etagMatch(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "W/"))
		if t == etag || t == "*" {
			return true
		}
	}
	return false
}

// acceptsGzip reports whether the client accepts gzip (an explicit q=0
// refuses it).
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(enc), "gzip") {
			continue
		}
		for _, p := range strings.Split(params, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.EqualFold(k, "q") {
				if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q == 0 {
					return false
				}
			}
		}
		return true
	}
	return false
}

func compressible(ctype string) bool {
	ct, _, _ := strings.Cut(ctype, ";")
	ct = strings.TrimSpace(ct)
	return strings.HasPrefix(ct, "text/") || ct == "application/json" ||
		ct == "application/javascript" || ct == "text/javascript" || ct == "image/svg+xml"
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- dynamic responses ----

// gzipPool reuses compressors across requests; the 2 s snapshot poll would
// otherwise allocate a fresh ~800 KB deflate state every time.
var gzipPool = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return zw
}}

// gzipWriter compresses a dynamic response when its Content-Type turns out to
// be compressible. The decision is made at WriteHeader time, so handlers
// that redirect, return 204/304 or stream binary are left untouched.
type gzipWriter struct {
	http.ResponseWriter
	r       *http.Request
	zw      *gzip.Writer
	decided bool
}

func (g *gzipWriter) WriteHeader(code int) {
	if !g.decided {
		g.decided = true
		h := g.Header()
		if code != http.StatusNoContent && code != http.StatusNotModified &&
			code >= 200 && h.Get("Content-Encoding") == "" && h.Get("Content-Range") == "" &&
			compressible(h.Get("Content-Type")) && acceptsGzip(g.r) {
			h.Set("Content-Encoding", "gzip")
			h.Del("Content-Length")
			h.Add("Vary", "Accept-Encoding")
			g.zw = gzipPool.Get().(*gzip.Writer)
			g.zw.Reset(g.ResponseWriter)
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(p []byte) (int, error) {
	if !g.decided {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(p))
		}
		g.WriteHeader(http.StatusOK)
	}
	if g.zw != nil {
		return g.zw.Write(p)
	}
	return g.ResponseWriter.Write(p)
}

func (g *gzipWriter) close() {
	if g.zw != nil {
		_ = g.zw.Close()
		g.zw.Reset(io.Discard)
		gzipPool.Put(g.zw)
		g.zw = nil
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// contentSecurityPolicy pins every script, style, font and fetch to this
// origin: the console loads nothing from third parties, and an injected
// script tag pointing elsewhere does not run. Inline style attributes stay
// allowed (the markup uses them); inline scripts do not.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; " +
	"base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// withTransport wraps the whole mux: security headers on every response,
// no-store on API responses (snapshots carry addresses, keys' fingerprints and
// audit rows - they must not land in a disk cache), and gzip for dynamic
// text responses. /static/ serves its own precompressed bytes.
func (s *Server) withTransport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		gw := &gzipWriter{ResponseWriter: w, r: r}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}
