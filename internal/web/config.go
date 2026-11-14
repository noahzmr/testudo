package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/noahzmr/testudo/internal/confapi"
)

// mountConfig serves the configuration model: the versioned API below
// /api/v1/ and the schema-driven page at /config.
//
// The API does its own authorisation per object kind, so it is not wrapped
// in protect (whose rules are per URL prefix). This wrapper only establishes
// who is calling and rejects cross-origin writes.
func (s *Server) mountConfig(mux *http.ServeMux) error {
	page, err := assetsFS.ReadFile("assets/config.html")
	if err != nil {
		return fmt.Errorf("read config.html: %w", err)
	}
	configPage := &staticAsset{body: s.static.Version(page), ctype: "text/html; charset=utf-8"}
	// The hash is the page's ETag. Without it every build would answer a
	// revalidation with "not modified" and browsers would keep the old page,
	// and through it the old script.
	sum := sha256.Sum256(configPage.body)
	configPage.hash = hex.EncodeToString(sum[:])[:12]
	mux.HandleFunc("/config", s.protect(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-cache")
		configPage.write(w, r)
	}))

	if s.Engine.ConfigStore() == nil {
		mux.HandleFunc("/api/v1/", s.protect(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, fmt.Sprintf("configuration model unavailable: %v", s.Engine.ConfigError()), http.StatusServiceUnavailable)
		}))
		return nil
	}
	api := &confapi.Server{
		Store:  s.Engine.ConfigStore(),
		Engine: s.Engine.ConfigApply(),
		Done:   s.stopping,
		Identify: func(r *http.Request) (confapi.Identity, bool) {
			rec, ok := r.Context().Value(sessionCtxKey).(*sessionRecord)
			if !ok || rec == nil {
				return confapi.Identity{}, false
			}
			return confapi.Identity{Name: rec.user, Permissions: confapi.RolePermissions(string(rec.role))}, true
		},
	}
	s.Engine.SetConfigNotify(api.Notice)
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		rec := s.session(r)
		if rec == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		api.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, rec)))
	})
	return nil
}
