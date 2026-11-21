package engine

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/secrets"
	"github.com/noahzmr/testudo/internal/storage"
)

// Access requests are shared by the members of a cluster: each is an entry
// of the secret store, which the cluster replicates, so a request made on
// one member can be decided, revoked and seen on every other. The access
// log stays each member's own hash chain of what it did; the view merges
// the logs of all members, fetched member to member.

const requestEntry = "access-r-"

// requestRetention is how long an ended request stays in the shared store.
const requestRetention = 30 * 24 * time.Hour

// kv is the part of the secret store the requests use.
type kv interface {
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Delete(name string) error
	List() ([]string, error)
}

// sharedAccess implements pam.Store.
type sharedAccess struct {
	local *storage.Store
	kv    kv
	// member names this member in a merged log; remote returns the other
	// members' logs.
	member string
	remote func(ctx context.Context) []storage.AccessEvent
}

func (s sharedAccess) UpsertPAMGrant(_ context.Context, g storage.PAMGrant) error {
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	return s.kv.Put(requestEntry+g.ID, b)
}

func (s sharedAccess) GetPAMGrant(ctx context.Context, id string) (storage.PAMGrant, error) {
	var g storage.PAMGrant
	b, err := s.kv.Get(requestEntry + id)
	if err == nil {
		return g, json.Unmarshal(b, &g)
	}
	// A request from before the store was shared.
	return s.local.GetPAMGrant(ctx, id)
}

func (s sharedAccess) ListPAMGrants(ctx context.Context, states []string, limit int) ([]storage.PAMGrant, error) {
	want := map[string]bool{}
	for _, st := range states {
		want[st] = true
	}
	seen := map[string]bool{}
	var out []storage.PAMGrant
	names, err := s.kv.List()
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		if !strings.HasPrefix(n, requestEntry) {
			continue
		}
		b, err := s.kv.Get(n)
		var g storage.PAMGrant
		if err != nil || json.Unmarshal(b, &g) != nil {
			continue
		}
		seen[g.ID] = true
		if len(want) == 0 || want[g.State] {
			out = append(out, g)
		}
	}
	old, err := s.local.ListPAMGrants(ctx, states, limit)
	if err != nil {
		return nil, err
	}
	for _, g := range old {
		if !seen[g.ID] {
			out = append(out, g)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s sharedAccess) AppendAccessEvent(ctx context.Context, e storage.AccessEvent) (storage.AccessEvent, error) {
	return s.local.AppendAccessEvent(ctx, e)
}

func (s sharedAccess) ListAccessEvents(ctx context.Context, limit int) ([]storage.AccessEvent, error) {
	evs, err := s.local.ListAccessEvents(ctx, limit)
	if err != nil {
		return nil, err
	}
	if s.remote == nil {
		return evs, nil
	}
	for i := range evs {
		evs[i].Member = s.member
	}
	evs = append(evs, s.remote(ctx)...)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].TS.After(evs[j].TS) })
	if limit > 0 && len(evs) > limit {
		evs = evs[:limit]
	}
	return evs, nil
}

func (s sharedAccess) VerifyAccessEvents(ctx context.Context) (int, int64, error) {
	return s.local.VerifyAccessEvents(ctx)
}

// accessStore is the store of the access manager on this node.
func (e *Engine) accessStore() sharedAccess {
	s := sharedAccess{local: e.store, kv: e.conf.secrets, member: e.cfg.NodeName}
	if mgr := e.cluster.mgr; mgr != nil {
		s.remote = func(ctx context.Context) []storage.AccessEvent {
			if mgr.Node() == nil {
				return nil
			}
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			var out []storage.AccessEvent
			for id, res := range mgr.Gather(ctx, "/cluster/v1/access-events") {
				var evs []storage.AccessEvent
				if res.Err != "" || json.Unmarshal(res.Body, &evs) != nil {
					continue
				}
				for i := range evs {
					if evs[i].Member == "" {
						evs[i].Member = id
					}
				}
				out = append(out, evs...)
			}
			return out
		}
	}
	return s
}

// localAccessEvents is this member's access log for the others.
func (e *Engine) localAccessEvents() ([]byte, error) {
	if e.store == nil {
		return nil, errors.New("no database")
	}
	evs, err := e.store.ListAccessEvents(context.Background(), 200)
	if err != nil {
		return nil, err
	}
	for i := range evs {
		evs[i].Member = e.cfg.NodeName
	}
	return json.Marshal(evs)
}

// shareOpenRequests copies the requests this node still has open from its
// database into the shared store, once; ended ones stay where they are and
// are still listed.
func (e *Engine) shareOpenRequests(ctx context.Context, s sharedAccess) {
	open, err := e.store.ListPAMGrants(ctx, []string{"pending", "active"}, 1000)
	if err != nil {
		return
	}
	for _, g := range open {
		if _, err := s.kv.Get(requestEntry + g.ID); err == nil {
			continue
		}
		if err := s.UpsertPAMGrant(ctx, g); err != nil {
			log.Printf("access: sharing request %s: %v", g.ID, err)
		}
	}
}

// pruneRequests removes requests that ended more than requestRetention
// ago from the shared store. The access logs keep their history.
func pruneRequests(store kv, now time.Time) int {
	names, err := store.List()
	if err != nil {
		return 0
	}
	n := 0
	for _, name := range names {
		if !strings.HasPrefix(name, requestEntry) {
			continue
		}
		b, err := store.Get(name)
		var g storage.PAMGrant
		if err != nil || json.Unmarshal(b, &g) != nil {
			continue
		}
		ended := g.EndedAt
		if ended.IsZero() && g.State == "denied" {
			ended = g.DecidedAt
		}
		if !ended.IsZero() && now.Sub(ended) > requestRetention {
			if store.Delete(name) == nil {
				n++
			}
		}
	}
	return n
}

var _ kv = secrets.Store{}
