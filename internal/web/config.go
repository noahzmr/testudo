package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/noahzmr/testudo/internal/confapi"
	"github.com/noahzmr/testudo/internal/identity"
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
		Keys:    s.Engine,
		Certs:   s.Engine,
		Secrets: s.Engine,
		Cluster: s.Engine,
		Audit: func(ctx context.Context, limit int) ([]confapi.AuditRow, error) {
			entries, err := s.Engine.RecentAudit(ctx, limit)
			rows := make([]confapi.AuditRow, 0, len(entries))
			for _, e := range entries {
				rows = append(rows, confapi.AuditRow{Time: e.TS, Actor: e.Actor, Op: e.Op, Detail: e.Args, Result: e.Result, PeerUID: e.PeerUID})
			}
			return rows, err
		},
		Identify: func(r *http.Request) (confapi.Identity, bool) {
			rec, ok := r.Context().Value(sessionCtxKey).(*sessionRecord)
			if !ok || rec == nil {
				return confapi.Identity{}, false
			}
			return apiIdentity(rec), true
		},
	}
	s.Engine.SetConfigNotify(api.Notice)
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		rec := s.session(r)
		if rec == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			// In a cluster a change is decided by the leader. A member
			// that does not lead passes the request on, with who is asking.
			// What concerns this member alone stays here.
			if _, forward := s.Engine.ClusterWritable(); forward && !localOnly(r.URL.Path) {
				id, _ := json.Marshal(apiIdentity(rec))
				s.Engine.Cluster().Forward(w, r, string(id))
				return
			}
		}
		api.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, rec)))
	})
	// The other side of that: requests members pass on to this one. Only
	// members can reach the endpoint, so the identity they name is the one
	// they authenticated.
	s.Engine.SetClusterForwarded(func(w http.ResponseWriter, r *http.Request, id string) {
		var who confapi.Identity
		if json.Unmarshal([]byte(id), &who) != nil || who.Name == "" {
			http.Error(w, "no identity", http.StatusBadRequest)
			return
		}
		p := identity.Principal{Name: who.Name, Source: "cluster", Permissions: who.Permissions, BreakGlass: who.BreakGlass}
		if who.Token {
			p.Source = identity.SourceToken
		}
		rec := &sessionRecord{user: who.Name, role: p.LegacyRole(), principal: p}
		api.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, rec)))
	})
	return nil
}

// apiIdentity is a session as the API sees it.
func apiIdentity(rec *sessionRecord) confapi.Identity {
	p := rec.principal
	return confapi.Identity{Name: rec.user, Permissions: p.Permissions, Token: p.Source == identity.SourceToken,
		// The built-in administrator and the host's break-glass group may
		// act when the cluster cannot.
		BreakGlass: p.BreakGlass || (p.Source == identity.SourceLocal && p.Can("*", "write"))}
}

// localOnly reports whether a write concerns this member alone and is
// never passed on to the leader.
func localOnly(path string) bool {
	switch path {
	case "/api/v1/cluster/init", "/api/v1/cluster/join", "/api/v1/cluster/override":
		return true
	}
	return false
}
