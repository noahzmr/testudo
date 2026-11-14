package web

import (
	"context"
	"fmt"
	"net/http"

	"github.com/noahzmr/testudo/internal/confapi"
)

// mountConfig serves the configuration model's versioned API below /api/v1/.
// Its screens are tabs inside the console's sections (index.html, config.js).
//
// The API does its own authorisation per object kind, so it is not wrapped
// in protect (whose rules are per URL prefix). This wrapper only establishes
// who is calling and rejects cross-origin writes.
func (s *Server) mountConfig(mux *http.ServeMux) error {
	// The model's screens are part of the console. The old address keeps
	// working.
	mux.HandleFunc("/config", s.protect(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/#/filter-rules", http.StatusFound)
	}))

	if s.Engine.ConfigStore() == nil {
		mux.HandleFunc("/api/v1/", s.protect(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, fmt.Sprintf("configuration model unavailable: %v", s.Engine.ConfigError()), http.StatusServiceUnavailable)
		}))
		return nil
	}
	api := &confapi.Server{
		Store:   s.Engine.ConfigStore(),
		Engine:  s.Engine.ConfigApply(),
		Done:    s.stopping,
		Runtime: s.Engine.ConfigRuntime,
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
