package confapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
)

// ClusterArea guards the cluster endpoints.
const ClusterArea = "cluster"

// ClusterAdmin is this node's cluster membership as the API uses it.
type ClusterAdmin interface {
	ClusterStatus() any
	ClusterInit(ctx context.Context) error
	ClusterJoin(ctx context.Context, token string) error
	ClusterToken(ttl time.Duration, voter bool) (string, error)
	ClusterMember(id, action string) error
	ClusterTransfer() error
	ClusterOverride(ctx context.Context, actor, reason string, ops []confstore.Op) (confapply.LocalOverride, error)
	ClusterResolveOverride(ctx context.Context, actor string) (confapply.LocalOverride, error)
}

func (s *Server) clusterWrite(w http.ResponseWriter, r *http.Request) bool {
	if s.Cluster == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "clustering is not available on this node")
		return false
	}
	if !who(r).Can(ClusterArea, "write") {
		fail(w, http.StatusForbidden, "forbidden", "needs cluster:write")
		return false
	}
	return true
}

func (s *Server) clusterDone(w http.ResponseWriter, err error) {
	if err != nil {
		fail(w, http.StatusConflict, "refused", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Cluster.ClusterStatus())
}

// clusterStatus describes the cluster as this member sees it: members and
// their roles, what each one applied, what is pending, whether there is a
// quorum, and the consensus numbers.
func (s *Server) clusterStatus(w http.ResponseWriter, r *http.Request) {
	if s.Cluster == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "member": false})
		return
	}
	if !who(r).Can(ClusterArea, "read") {
		fail(w, http.StatusForbidden, "forbidden", "needs cluster:read")
		return
	}
	writeJSON(w, http.StatusOK, s.Cluster.ClusterStatus())
}

func (s *Server) clusterInit(w http.ResponseWriter, r *http.Request) {
	if s.clusterWrite(w, r) {
		s.clusterDone(w, s.Cluster.ClusterInit(r.Context()))
	}
}

func (s *Server) clusterJoin(w http.ResponseWriter, r *http.Request) {
	if !s.clusterWrite(w, r) {
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	body, err := readBody(w, r, 1<<14)
	if err != nil || json.Unmarshal(body, &in) != nil || in.Token == "" {
		fail(w, http.StatusBadRequest, "bad_request", "give the join token")
		return
	}
	s.clusterDone(w, s.Cluster.ClusterJoin(r.Context(), in.Token))
}

// clusterToken issues a join token: good once, for a limited time, for a
// voter or for a member that only receives the model.
func (s *Server) clusterToken(w http.ResponseWriter, r *http.Request) {
	if !s.clusterWrite(w, r) {
		return
	}
	var in struct {
		TTLMinutes int  `json:"ttl_minutes"`
		Voter      bool `json:"voter"`
	}
	body, err := readBody(w, r, 1<<10)
	if err != nil || (len(body) > 0 && json.Unmarshal(body, &in) != nil) || in.TTLMinutes < 0 || in.TTLMinutes > 24*60 {
		fail(w, http.StatusBadRequest, "bad_request", "ttl_minutes must be between 1 and 1440")
		return
	}
	if in.TTLMinutes == 0 {
		in.TTLMinutes = 30
	}
	token, err := s.Cluster.ClusterToken(time.Duration(in.TTLMinutes)*time.Minute, in.Voter)
	if err != nil {
		fail(w, http.StatusConflict, "refused", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "voter": in.Voter, "expires_in_minutes": in.TTLMinutes})
}

func (s *Server) clusterMember(w http.ResponseWriter, r *http.Request) {
	if !s.clusterWrite(w, r) {
		return
	}
	action := r.PathValue("action")
	if r.Method == http.MethodDelete {
		action = "remove"
	}
	s.clusterDone(w, s.Cluster.ClusterMember(r.PathValue("id"), action))
}

func (s *Server) clusterTransfer(w http.ResponseWriter, r *http.Request) {
	if s.clusterWrite(w, r) {
		s.clusterDone(w, s.Cluster.ClusterTransfer())
	}
}

// clusterOverride changes what runs on this member only, while it is cut
// off from the cluster. It needs more than a permission: the caller has to
// be a break-glass administrator (the built-in account, or a host account
// in the break-glass group). The model is not touched; the override shows
// up for review when the member is back.
func (s *Server) clusterOverride(w http.ResponseWriter, r *http.Request) {
	if !s.clusterWrite(w, r) {
		return
	}
	id := who(r)
	if !id.BreakGlass {
		fail(w, http.StatusForbidden, "forbidden", "a local override needs a break-glass administrator: the built-in account or a host account in the break-glass group")
		return
	}
	var in struct {
		Reason string         `json:"reason"`
		Ops    []confstore.Op `json:"ops"`
	}
	body, err := readBody(w, r, 4<<20)
	if err != nil || json.Unmarshal(body, &in) != nil || in.Reason == "" || len(in.Ops) == 0 {
		fail(w, http.StatusBadRequest, "bad_request", "give a reason and the changes")
		return
	}
	o, err := s.Cluster.ClusterOverride(r.Context(), id.Name, in.Reason, in.Ops)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// clusterResolveOverride ends the local override and returns its changes,
// to be made again as an ordinary change or dropped.
func (s *Server) clusterResolveOverride(w http.ResponseWriter, r *http.Request) {
	if !s.clusterWrite(w, r) {
		return
	}
	o, err := s.Cluster.ClusterResolveOverride(r.Context(), who(r).Name)
	if err != nil {
		fail(w, http.StatusConflict, "refused", "no local override is in force")
		return
	}
	writeJSON(w, http.StatusOK, o)
}
