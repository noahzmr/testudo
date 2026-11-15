// Package confapi is the HTTP API over the configuration model: the paths
// described by the generated OpenAPI document plus change sets, plan, apply,
// history and a live event stream.
//
// Authentication is the caller's business: the package only asks an
// Identify function who is calling and with which permissions, and enforces
// those permissions per object kind on every request.
package confapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/cluster"
	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/model/schema"
)

// Identity is the authenticated caller. Permissions have the form
// "<area>:read" or "<area>:write", where area is the first segment of a
// kind's menu ("firewall", "routing", "vpn", …) or "*". Write implies read.
type Identity struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	// Token is set when the caller presented an API token, not a login.
	Token bool `json:"token,omitempty"`
	// BreakGlass is set for the built-in administrator and for host
	// accounts in the break-glass group: the ones who may act when the
	// cluster cannot.
	BreakGlass bool `json:"break_glass,omitempty"`
}

// Can reports whether the identity may read or write the area.
func (i Identity) Can(area, verb string) bool {
	for _, p := range i.Permissions {
		a, v, _ := strings.Cut(p, ":")
		if (a == "*" || a == area) && (v == verb || v == "write") {
			return true
		}
	}
	return false
}

// Area returns the permission area of a kind.
func Area(info model.KindInfo) string {
	area, _, _ := strings.Cut(info.Menu, "/")
	return area
}

// RolePermissions maps the four built-in roles of the existing user store
// onto permissions. Operators manage the network but not identities or the
// cluster; approvers decide on access requests.
func RolePermissions(role string) []string {
	switch role {
	case "admin":
		return []string{"*:write"}
	case "operator":
		return []string{"*:read", "firewall:write", "routing:write", "vpn:write", "loadbalancer:write",
			"interfaces:write", "access:write"}
	case "approver":
		return []string{"*:read", "access:write"}
	}
	return []string{"*:read"}
}

// SystemArea guards history revert, export and import.
const SystemArea = "system"

// Server implements http.Handler for everything below /api/v1/.
type Server struct {
	Store  *confstore.Store
	Engine *confapply.Engine
	// Identify returns the caller. A false result is answered with 401.
	Identify func(*http.Request) (Identity, bool)
	// Runtime, when set, reports what the model's objects are doing in the
	// running system (counters, alias refresh state). Served at /runtime.
	Runtime func() map[string]any
	// Keys creates WireGuard key material on the node; nil disables the
	// key endpoints.
	Keys KeyMaker
	// Certs issues and imports certificates on the node; nil disables the
	// certificate endpoints.
	Certs CertMaker
	// Secrets stores secrets on the node; nil disables the endpoints that
	// take one.
	Secrets SecretKeeper
	// Cluster is this node's cluster membership; nil disables clustering.
	Cluster ClusterAdmin
	// Audit reads the audit log; nil disables the endpoint.
	Audit AuditReader
	// Heartbeat is the interval of keep-alive comments on the event stream.
	Heartbeat time.Duration
	// Done, when closed, ends every open event stream. Set it to the
	// server's shutdown signal: a graceful shutdown waits for open requests
	// and an event stream never finishes by itself.
	Done <-chan struct{}

	once     sync.Once
	mux      *http.ServeMux
	patterns []string

	mu      sync.Mutex
	notices map[chan confapply.Notice]struct{}
}

// Notice forwards an apply outcome to the event stream. Wire it to the
// engine's Notify option.
func (s *Server) Notice(n confapply.Notice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.notices {
		select {
		case ch <- n:
		default:
		}
	}
}

type problem struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	// Details depend on Error; see the OpenAPI document.
	CurrentVersion int64                 `json:"current_version,omitempty"`
	Diff           []confstore.FieldDiff `json:"diff,omitempty"`
	Current        model.Entity          `json:"current,omitempty"`
	Fields         []model.FieldError    `json:"fields,omitempty"`
	Problems       []confstore.Problem   `json:"problems,omitempty"`
	UsedBy         []confstore.Use       `json:"used_by,omitempty"`
	Pending        *confapply.Pending    `json:"pending,omitempty"`
	Stage          string                `json:"stage,omitempty"`
	Phase          string                `json:"phase,omitempty"`
	RolledBack     bool                  `json:"rolled_back,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, problem{Error: code, Message: msg})
}

// writeErr maps every error the store and the engine return to a status and
// a machine-readable body.
func (s *Server) writeErr(w http.ResponseWriter, err error) {
	var (
		ve *model.ValidationError
		ce *confstore.ConflictError
		re *confstore.ReferencedError
		ie *confstore.IntegrityError
		se *confapply.StageError
	)
	switch {
	case errors.As(err, &ce):
		p := problem{Error: "conflict", Message: ce.Error(), CurrentVersion: ce.CurrentVersion, Diff: ce.Diff}
		if cur, ok := s.Store.Current().Get(ce.Kind, ce.ID); ok {
			p.Current = model.Mask(cur)
		}
		writeJSON(w, http.StatusConflict, p)
	case errors.As(err, &re):
		writeJSON(w, http.StatusConflict, problem{Error: "in_use", Message: re.Error(), UsedBy: re.UsedBy})
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, problem{Error: "invalid", Message: ve.Error(), Fields: ve.Fields})
	case errors.As(err, &ie):
		writeJSON(w, http.StatusUnprocessableEntity, problem{Error: "inconsistent", Message: ie.Error(), Problems: ie.Problems})
	case errors.As(err, &se):
		status := http.StatusUnprocessableEntity // render or dry run refused the change
		if se.Phase == "apply" || se.Phase == "health" || se.Phase == "rollback" {
			status = http.StatusBadGateway
		}
		writeJSON(w, status, problem{Error: "stage_failed", Message: err.Error(), Stage: se.Stage, Phase: se.Phase, RolledBack: se.RolledBack})
	case errors.Is(err, confapply.ErrPending):
		p := problem{Error: "pending", Message: "a change is waiting for confirmation; confirm it or roll it back first"}
		if pend, ok := s.Engine.Pending(); ok {
			p.Pending = &pend
		}
		writeJSON(w, http.StatusLocked, p)
	case errors.Is(err, cluster.ErrNoQuorum):
		fail(w, http.StatusServiceUnavailable, "no_quorum", "the cluster has no leader: this member is read-only until it can reach a majority")
	case errors.Is(err, confapply.ErrNotLeader), errors.Is(err, cluster.ErrNotLeader):
		fail(w, http.StatusServiceUnavailable, "not_leader", "this member does not lead the cluster; the change has to be made through the leader")
	case errors.Is(err, cluster.ErrGate):
		fail(w, http.StatusConflict, "upgrade_in_progress", err.Error())
	case errors.Is(err, cluster.ErrHalted):
		fail(w, http.StatusServiceUnavailable, "halted", err.Error())
	case errors.Is(err, confapply.ErrOverride):
		fail(w, http.StatusConflict, "override", "a local override is in force on this member; resolve it first")
	case errors.Is(err, confstore.ErrStale):
		fail(w, http.StatusConflict, "stale", "the model changed while the change was being agreed on; try again")
	case errors.Is(err, confapply.ErrNothingPending):
		fail(w, http.StatusConflict, "nothing_pending", "no change is waiting for confirmation")
	case errors.Is(err, confstore.ErrIfMatchNeeded):
		fail(w, http.StatusPreconditionRequired, "precondition_required", "If-Match with the object version is required")
	case errors.Is(err, confstore.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", err.Error())
	case errors.As(err, new(*http.MaxBytesError)):
		fail(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
	case errors.As(err, new(*badRequest)):
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		fail(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

type badRequest struct{ msg string }

func (b *badRequest) Error() string { return b.msg }
func bad(format string, a ...any) error {
	return &badRequest{fmt.Sprintf(format, a...)}
}

type ctxKey struct{}

func who(r *http.Request) Identity { return r.Context().Value(ctxKey{}).(Identity) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.once.Do(s.routes)
	id, ok := s.Identify(r)
	if !ok {
		fail(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
}

func (s *Server) routes() {
	if s.Heartbeat <= 0 {
		s.Heartbeat = 20 * time.Second
	}
	s.notices = map[chan confapply.Notice]struct{}{}
	m := &recordingMux{ServeMux: http.NewServeMux()}
	static := func(ctype string, body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(body)
		}
	}
	m.HandleFunc("GET /api/v1/schema/openapi.json", static("application/json", schema.OpenAPIJSON))
	m.HandleFunc("GET /api/v1/schema/ui.json", static("application/json", schema.UIJSON))
	m.HandleFunc("GET /api/v1/whoami", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, who(r)) })
	m.HandleFunc("GET /api/v1/events", s.events)
	m.HandleFunc("GET /api/v1/runtime", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{}
		if s.Runtime != nil && who(r).Can("firewall", "read") {
			out = s.Runtime()
		}
		writeJSON(w, http.StatusOK, out)
	})

	m.HandleFunc("POST /api/v1/wg/tunnel-key", s.wgTunnelKey)
	m.HandleFunc("POST /api/v1/wg/preshared-key", s.wgPresharedKey)
	m.HandleFunc("POST /api/v1/wg/client-keypair", s.wgClientKeypair)
	m.HandleFunc("GET /api/v1/wg-peers/{id}/client-config", s.wgClientConfig)
	m.HandleFunc("POST /api/v1/pki/issue", s.pkiIssue)
	m.HandleFunc("POST /api/v1/pki/import", s.pkiImport)
	m.HandleFunc("GET /api/v1/pki/ca", s.pkiCA)
	m.HandleFunc("GET /api/v1/lb/firewall-hints", s.lbFirewallHints)
	m.HandleFunc("POST /api/v1/oidc/client-secret", s.oidcClientSecret)
	m.HandleFunc("POST /api/v1/tokens", s.createToken)
	m.HandleFunc("GET /api/v1/audit", s.audit)
	m.HandleFunc("GET /api/v1/cluster", s.clusterStatus)
	m.HandleFunc("POST /api/v1/cluster/init", s.clusterInit)
	m.HandleFunc("POST /api/v1/cluster/join", s.clusterJoin)
	m.HandleFunc("POST /api/v1/cluster/token", s.clusterToken)
	m.HandleFunc("POST /api/v1/cluster/transfer", s.clusterTransfer)
	m.HandleFunc("POST /api/v1/cluster/members/{id}/{action}", s.clusterMember)
	m.HandleFunc("DELETE /api/v1/cluster/members/{id}", s.clusterMember)
	m.HandleFunc("POST /api/v1/cluster/override", s.clusterOverride)
	m.HandleFunc("DELETE /api/v1/cluster/override", s.clusterResolveOverride)
	m.HandleFunc("GET /api/v1/changesets", s.listChangeSets)
	m.HandleFunc("POST /api/v1/changesets", s.createChangeSet)
	m.HandleFunc("GET /api/v1/changesets/{id}", s.getChangeSet)
	m.HandleFunc("DELETE /api/v1/changesets/{id}", s.deleteChangeSet)
	m.HandleFunc("POST /api/v1/plan", s.plan)
	m.HandleFunc("GET /api/v1/apply", s.applyStatus)
	m.HandleFunc("POST /api/v1/apply", s.apply)
	m.HandleFunc("POST /api/v1/apply/confirm", s.confirm)
	m.HandleFunc("POST /api/v1/apply/rollback", s.rollback)
	m.HandleFunc("GET /api/v1/history", s.history)
	m.HandleFunc("POST /api/v1/history/{index}/revert", s.revert)
	m.HandleFunc("GET /api/v1/export", s.export)
	m.HandleFunc("POST /api/v1/import", s.importSnapshot)

	m.HandleFunc("GET /api/v1/{plural}", s.kind(s.list, "read"))
	m.HandleFunc("POST /api/v1/{plural}", s.kind(s.create, "write"))
	m.HandleFunc("GET /api/v1/{plural}/{id}", s.kind(s.get, "read"))
	m.HandleFunc("PUT /api/v1/{plural}/{id}", s.kind(s.update, "write"))
	m.HandleFunc("DELETE /api/v1/{plural}/{id}", s.kind(s.remove, "write"))
	m.HandleFunc("GET /api/v1/{plural}/{id}/used-by", s.kind(s.usedBy, "read"))
	m.HandleFunc("GET /api/v1/{plural}/{id}/effective", s.kind(s.effective, "read"))
	s.mux, s.patterns = m.ServeMux, m.patterns
}

// recordingMux remembers what was registered so a test can hold the
// generated OpenAPI document against the routes that really exist.
type recordingMux struct {
	*http.ServeMux
	patterns []string
}

func (m *recordingMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, h)
}

// kind resolves the URL segment and enforces the permission for its area.
func (s *Server) kind(h func(http.ResponseWriter, *http.Request, model.KindInfo), verb string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, ok := model.Lookup(r.PathValue("plural"))
		if !ok || info.Plural != r.PathValue("plural") {
			fail(w, http.StatusNotFound, "not_found", "unknown resource")
			return
		}
		if !who(r).Can(Area(info), verb) {
			fail(w, http.StatusForbidden, "forbidden", fmt.Sprintf("needs %s:%s", Area(info), verb))
			return
		}
		h(w, r, info)
	}
}

// authorize checks write permission for every kind a set of ops touches.
func authorize(id Identity, ops []confstore.Op) error {
	for _, op := range ops {
		info, ok := model.Lookup(string(op.Kind))
		if !ok {
			return bad("unknown kind %q", op.Kind)
		}
		if !id.Can(Area(info), "write") {
			return &forbidden{fmt.Sprintf("needs %s:write", Area(info))}
		}
	}
	return nil
}

type forbidden struct{ msg string }

func (f *forbidden) Error() string { return f.msg }

func (s *Server) deny(w http.ResponseWriter, err error) bool {
	var f *forbidden
	if errors.As(err, &f) {
		fail(w, http.StatusForbidden, "forbidden", f.msg)
		return true
	}
	if err != nil {
		s.writeErr(w, err)
		return true
	}
	return false
}

func etag(v int64) string { return `"` + strconv.FormatInt(v, 10) + `"` }

// ifMatch parses the If-Match header into a version; 0 means absent.
func ifMatch(r *http.Request) (int64, error) {
	h := strings.TrimSpace(r.Header.Get("If-Match"))
	if h == "" {
		return 0, nil
	}
	h = strings.Trim(strings.TrimPrefix(h, "W/"), `"`)
	v, err := strconv.ParseInt(h, 10, 64)
	if err != nil || v <= 0 {
		return 0, bad("If-Match must be the object version from ETag")
	}
	return v, nil
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}

func (s *Server) writeObject(w http.ResponseWriter, status int, e model.Entity) {
	w.Header().Set("ETag", etag(e.GetMeta().Version))
	writeJSON(w, status, model.Mask(e))
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, info model.KindInfo) {
	objs := s.Store.Current().List(info.Kind)
	out := make([]model.Entity, len(objs))
	for i, e := range objs {
		out[i] = model.Mask(e)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, info model.KindInfo) {
	e, ok := s.Store.Current().Get(info.Kind, r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such object")
		return
	}
	s.writeObject(w, http.StatusOK, e)
}

func (s *Server) usedBy(w http.ResponseWriter, r *http.Request, info model.KindInfo) {
	uses := s.Store.Current().UsedBy(info.Kind, r.PathValue("id"))
	if uses == nil {
		uses = []confstore.Use{}
	}
	writeJSON(w, http.StatusOK, uses)
}

// effective returns the object as one node sees it and where each
// overridden field comes from.
func (s *Server) effective(w http.ResponseWriter, r *http.Request, info model.KindInfo) {
	e, ok := s.Store.Current().Get(info.Kind, r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such object")
		return
	}
	site, node := r.URL.Query().Get("site"), r.URL.Query().Get("node")
	eff, origins, err := model.Effective(e, site, node)
	if err != nil {
		s.writeErr(w, bad("%v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": model.Mask(eff), "origins": origins,
		"base_scope": e.GetMeta().Scope, "applies": model.AppliesTo(e, site, node),
	})
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, info model.KindInfo) {
	body, err := readBody(w, r, 1<<20)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	e, err := model.Decode(info.Kind, body)
	if err != nil {
		s.writeErr(w, bad("%v", err))
		return
	}
	if e.GetMeta().ID == "" {
		e.GetMeta().ID = confstore.NewID()
	}
	obj, _ := json.Marshal(e)
	s.write(w, r, confstore.Op{Type: confstore.OpCreate, Kind: info.Kind, ID: e.GetMeta().ID, Object: obj}, http.StatusCreated)
}

func (s *Server) update(w http.ResponseWriter, r *http.Request, info model.KindInfo) {
	v, err := ifMatch(r)
	if err == nil && v == 0 {
		err = confstore.ErrIfMatchNeeded
	}
	if err != nil {
		s.writeErr(w, err)
		return
	}
	body, err := readBody(w, r, 1<<20)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	e, err := model.Decode(info.Kind, body)
	if err != nil {
		s.writeErr(w, bad("%v", err))
		return
	}
	id := r.PathValue("id")
	if e.GetMeta().ID != "" && e.GetMeta().ID != id {
		s.writeErr(w, bad("the id in the body does not match the URL"))
		return
	}
	e.GetMeta().ID = id
	// Restore masked secrets here so a draft never stores the mask.
	if cur, ok := s.Store.Current().Get(info.Kind, id); ok {
		model.KeepMaskedSecrets(e, cur)
	}
	obj, _ := json.Marshal(e)
	s.write(w, r, confstore.Op{Type: confstore.OpUpdate, Kind: info.Kind, ID: id, Object: obj, IfMatch: v}, http.StatusOK)
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request, info model.KindInfo) {
	v, err := ifMatch(r)
	if err == nil && v == 0 {
		err = confstore.ErrIfMatchNeeded
	}
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.write(w, r, confstore.Op{Type: confstore.OpDelete, Kind: info.Kind, ID: r.PathValue("id"), IfMatch: v}, http.StatusNoContent)
}

// write either records the op in a change set (?changeset=) or applies it
// right away, which opens the confirmation window.
func (s *Server) write(w http.ResponseWriter, r *http.Request, op confstore.Op, okStatus int) {
	id := who(r)
	if csID := r.URL.Query().Get("changeset"); csID != "" {
		cs, err := s.addToChangeSet(r.Context(), id, csID, op)
		if s.deny(w, err) {
			return
		}
		w.Header().Set("Testudo-Changeset", cs.ID)
		writeJSON(w, http.StatusAccepted, map[string]any{"changeset": cs.ID, "changeset_version": cs.Version, "ops": len(cs.Ops)})
		return
	}
	pend, err := s.Engine.Apply(r.Context(), id.Name, "", []confstore.Op{op})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	setPending(w, pend)
	if op.Type == confstore.OpDelete {
		w.WriteHeader(okStatus)
		return
	}
	e, _ := s.Store.Current().Get(op.Kind, op.ID)
	s.writeObject(w, okStatus, e)
}

// setPending tells the client that the change is live but unconfirmed.
func setPending(w http.ResponseWriter, p confapply.Pending) {
	w.Header().Set("Testudo-Pending", strconv.FormatInt(p.Index, 10))
	w.Header().Set("Testudo-Confirm-By", p.Deadline.Format(time.RFC3339))
}

// mergeOp folds a new op into a draft so that each object appears once.
func mergeOp(ops []confstore.Op, op confstore.Op) ([]confstore.Op, error) {
	i := slices.IndexFunc(ops, func(o confstore.Op) bool { return o.Kind == op.Kind && o.ID == op.ID })
	if i < 0 {
		return append(ops, op), nil
	}
	old := ops[i]
	switch {
	case old.Type == confstore.OpDelete:
		return nil, bad("the change set already deletes this object")
	case op.Type == confstore.OpCreate:
		return nil, bad("the change set already contains this object")
	case old.Type == confstore.OpCreate && op.Type == confstore.OpDelete:
		return slices.Delete(ops, i, i+1), nil // created and removed inside the draft
	case old.Type == confstore.OpCreate:
		ops[i].Object = op.Object // still a create, with the edited content
	default:
		// Keep the version the draft was first based on, so a change made
		// outside the draft in the meantime still surfaces as a conflict.
		op.IfMatch = old.IfMatch
		ops[i] = op
	}
	return ops, nil
}

func (s *Server) addToChangeSet(ctx context.Context, id Identity, csID string, op confstore.Op) (confstore.ChangeSet, error) {
	if err := authorize(id, []confstore.Op{op}); err != nil {
		return confstore.ChangeSet{}, err
	}
	for attempt := 0; ; attempt++ {
		cs, ok := s.Store.Current().ChangeSet(csID)
		if !ok {
			return cs, fmt.Errorf("%w: change set %s", confstore.ErrNotFound, csID)
		}
		if cs.Owner != id.Name && !id.Can(SystemArea, "write") {
			return cs, &forbidden{"only the owner may add to this change set"}
		}
		ops, err := mergeOp(slices.Clone(cs.Ops), op)
		if err != nil {
			return cs, err
		}
		// Reject what could never be applied, while the author is looking.
		if _, _, err := s.Store.Preview(id.Name, ops); err != nil {
			return cs, err
		}
		cs.Ops = ops
		out, err := s.Store.PutChangeSet(ctx, id.Name, cs, cs.Version)
		var ce *confstore.ConflictError
		if errors.As(err, &ce) && attempt < 3 {
			continue // someone else edited the draft; redo on the new version
		}
		return out, err
	}
}
