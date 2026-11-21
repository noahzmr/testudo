package confapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

func masked(changes []confstore.Change) []confstore.Change {
	out := make([]confstore.Change, len(changes))
	for i, c := range changes {
		out[i] = c.Masked()
	}
	return out
}

// changeSetView is a change set with the diff it would produce right now.
type changeSetView struct {
	confstore.ChangeSet
	Changes []confstore.Change `json:"changes"`
	// Problem is set when the change set no longer applies cleanly.
	Problem string `json:"problem,omitempty"`
}

func (s *Server) view(actor string, cs confstore.ChangeSet) changeSetView {
	v := changeSetView{ChangeSet: cs, Changes: []confstore.Change{}}
	// Stored ops may contain secrets; the view shows the masked diff only.
	v.Ops = nil
	_, changes, err := s.Store.Preview(actor, cs.Ops)
	if err != nil {
		v.Problem = err.Error()
		return v
	}
	v.Changes = masked(changes)
	return v
}

func (s *Server) listChangeSets(w http.ResponseWriter, r *http.Request) {
	type item struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Owner     string    `json:"owner"`
		Version   int64     `json:"version"`
		UpdatedAt time.Time `json:"updated_at"`
		Ops       int       `json:"ops"`
	}
	out := []item{}
	id := who(r)
	for _, cs := range s.Store.Current().ChangeSets() {
		if cs.Owner == id.Name || unlimitedReader(id) {
			out = append(out, item{cs.ID, cs.Name, cs.Owner, cs.Version, cs.UpdatedAt, len(cs.Ops)})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createChangeSet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	body, err := readBody(w, r, 1<<16)
	if err == nil && json.Unmarshal(body, &in) != nil {
		err = bad("body must be {\"name\": ...}")
	}
	if err == nil && (len(in.Name) == 0 || len(in.Name) > 80) {
		err = bad("a change set needs a name of at most 80 characters")
	}
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cs, err := s.Store.PutChangeSet(r.Context(), who(r).Name, confstore.ChangeSet{Name: in.Name}, 0)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.view(who(r).Name, cs))
}

func (s *Server) getChangeSet(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.Store.Current().ChangeSet(r.PathValue("id"))
	if !ok || (cs.Owner != who(r).Name && !unlimitedReader(who(r))) {
		fail(w, http.StatusNotFound, "not_found", "no such change set")
		return
	}
	writeJSON(w, http.StatusOK, s.view(who(r).Name, cs))
}

func (s *Server) deleteChangeSet(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	cs, ok := s.Store.Current().ChangeSet(r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such change set")
		return
	}
	if cs.Owner != id.Name && !id.Can(SystemArea, "write") {
		fail(w, http.StatusForbidden, "forbidden", "only the owner may discard this change set")
		return
	}
	if err := s.Store.DeleteChangeSet(r.Context(), id.Name, cs.ID); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type applyRequest struct {
	ChangeSets []string `json:"changesets"`
	Note       string   `json:"note"`
}

func (s *Server) applyInput(w http.ResponseWriter, r *http.Request) (applyRequest, []confstore.Op, bool) {
	var in applyRequest
	body, err := readBody(w, r, 1<<16)
	if err == nil && json.Unmarshal(body, &in) != nil {
		err = bad("body must be {\"changesets\": [...], \"note\": ...}")
	}
	if err == nil && len(in.ChangeSets) == 0 {
		err = bad("name at least one change set")
	}
	var ops []confstore.Op
	if err == nil {
		ops, err = s.Store.Combine(in.ChangeSets...)
	}
	if err == nil {
		err = authorize(who(r), s.Store.Current(), ops)
	}
	return in, ops, !s.deny(w, err)
}

// plan shows the combined diff of several change sets and what every stage
// would render, without committing.
func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	_, ops, ok := s.applyInput(w, r)
	if !ok {
		return
	}
	arts, changes, err := s.Engine.Plan(r.Context(), who(r).Name, ops)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// Stages hide what must not be shown (session passwords).
	writeJSON(w, http.StatusOK, map[string]any{"changes": masked(changes), "rendered": s.Engine.Display(arts)})
}

// apply commits and applies the change sets as one transaction.
func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	in, ops, ok := s.applyInput(w, r)
	if !ok {
		return
	}
	pend, err := s.Engine.Apply(r.Context(), who(r).Name, in.Note, ops, in.ChangeSets...)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	setPending(w, pend)
	writeJSON(w, http.StatusOK, map[string]any{"pending": pend})
}

func (s *Server) applyStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"pending": nil, "index": s.Store.Current().Index()}
	if p, ok := s.Engine.Pending(); ok {
		out["pending"] = p
	}
	writeJSON(w, http.StatusOK, out)
}

// canWriteAnything gates confirm and rollback: whoever may change some part
// of the configuration may settle a pending change.
func canWriteAnything(id Identity) bool {
	for _, info := range model.Kinds() {
		if id.CanAnywhere(Area(info), "write") {
			return true
		}
	}
	return false
}

// unlimitedReader reports whether the identity may read some area
// everywhere.
func unlimitedReader(id Identity) bool {
	for _, info := range model.Kinds() {
		if id.Can(Area(info), "read") {
			return true
		}
	}
	return false
}

// unlimitedWriter reports whether the identity may write some area
// everywhere.
func unlimitedWriter(id Identity) bool {
	for _, info := range model.Kinds() {
		if id.Can(Area(info), "write") {
			return true
		}
	}
	return false
}

// confirm keeps the pending change. Someone whose permissions are limited
// to a site or node confirms only their own change.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	if !canWriteAnything(id) {
		fail(w, http.StatusForbidden, "forbidden", "needs write permission")
		return
	}
	if p, pending := s.Engine.Pending(); pending && p.Actor != id.Name && !unlimitedWriter(id) {
		fail(w, http.StatusForbidden, "forbidden", "this change is "+p.Actor+"'s; it needs a permission that is not limited to a site or node")
		return
	}
	if err := s.Engine.Confirm(who(r).Name); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	if !canWriteAnything(who(r)) {
		fail(w, http.StatusForbidden, "forbidden", "needs write permission")
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if body, err := readBody(w, r, 1<<16); err == nil && len(body) > 0 {
		_ = json.Unmarshal(body, &in)
	}
	if in.Reason == "" {
		in.Reason = "rolled back by " + who(r).Name
	}
	if err := s.Engine.Rollback(r.Context(), who(r).Name, in.Reason); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// verifyHistory checks the hash chain of the configuration log.
func (s *Server) verifyHistory(w http.ResponseWriter, r *http.Request) {
	if !unlimitedReader(who(r)) {
		fail(w, http.StatusForbidden, "forbidden", "needs a read permission that is not limited to a site or node")
		return
	}
	checked, broken, err := s.Store.Verify()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checked": checked, "broken_at": broken, "intact": broken == 0})
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	// The history shows every object's values before and after: it is for
	// those who may read without a limit to a site or node.
	if !unlimitedReader(who(r)) {
		fail(w, http.StatusForbidden, "forbidden", "needs a read permission that is not limited to a site or node")
		return
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	recs, err := s.Store.History(before, limit)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	id := who(r)
	out := make([]confstore.Record, 0, len(recs))
	for _, rec := range recs {
		// Change-set bookkeeping carries unmasked ops; never expose it.
		rec.PutChangeSet = nil
		visible := rec.Changes[:0:0]
		for _, c := range rec.Changes {
			if info, ok := model.Lookup(string(c.Kind)); ok && id.Can(Area(info), "read") {
				visible = append(visible, c.Masked())
			}
		}
		rec.Changes = visible
		out = append(out, rec)
	}
	writeJSON(w, http.StatusOK, out)
}

// revert undoes one record through the normal apply path.
func (s *Server) revert(w http.ResponseWriter, r *http.Request) {
	index, err := strconv.ParseInt(r.PathValue("index"), 10, 64)
	if err != nil {
		s.writeErr(w, bad("bad record index"))
		return
	}
	ops, err := s.Store.InverseOps(index)
	if err == nil {
		err = authorize(who(r), s.Store.Current(), ops)
	}
	if err == nil && len(ops) == 0 {
		err = bad("record %d changed no objects", index)
	}
	if s.deny(w, err) {
		return
	}
	pend, err := s.Engine.Apply(r.Context(), who(r).Name, fmt.Sprintf("revert of record %d", index), ops)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	setPending(w, pend)
	writeJSON(w, http.StatusOK, map[string]any{"pending": pend})
}

// export returns the whole model including secrets. It is the backup format
// and therefore restricted to system:write.
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	if !who(r).Can(SystemArea, "write") {
		fail(w, http.StatusForbidden, "forbidden", "needs system:write")
		return
	}
	snap := s.Store.Current().Export()
	snap.ChangeSets = nil
	w.Header().Set("Content-Disposition", `attachment; filename="testudo-config.json"`)
	writeJSON(w, http.StatusOK, snap)
}

// importSnapshot replaces the model with a snapshot, as one transaction
// through the normal apply path. With ?dry_run=1 it only reports the diff.
func (s *Server) importSnapshot(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	if !id.Can(SystemArea, "write") {
		fail(w, http.StatusForbidden, "forbidden", "needs system:write")
		return
	}
	body, err := readBody(w, r, 64<<20)
	var snap confstore.Snapshot
	if err == nil && json.Unmarshal(body, &snap) != nil {
		err = bad("body is not a configuration snapshot")
	}
	var ops []confstore.Op
	if err == nil {
		if ops, err = s.Store.Current().ImportOps(snap); err != nil {
			err = bad("%v", err)
		}
	}
	if err == nil {
		err = authorize(id, s.Store.Current(), ops)
	}
	if s.deny(w, err) {
		return
	}
	if r.URL.Query().Get("dry_run") != "" || len(ops) == 0 {
		_, changes, err := s.Engine.Plan(r.Context(), id.Name, ops)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"changes": masked(changes)})
		return
	}
	pend, err := s.Engine.Apply(r.Context(), id.Name, "import", ops)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	setPending(w, pend)
	writeJSON(w, http.StatusOK, map[string]any{"pending": pend, "ops": len(ops)})
}

// events streams model changes and apply outcomes as server-sent events:
// "change" for every committed record, "apply" for applied, confirmed and
// rolled-back changes. Clients reload what they show when they see one.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	changes, cancel := s.Store.Subscribe(64)
	defer cancel()
	notices := make(chan confapply.Notice, 16)
	s.mu.Lock()
	s.notices[notices] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.notices, notices)
		s.mu.Unlock()
	}()

	id := who(r)
	send := func(event string, v any) bool {
		data, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	sendChange := func(ev confstore.Event) bool {
		// Only name the objects the caller may read.
		visible := ev.Changes[:0:0]
		for _, c := range ev.Changes {
			if info, ok := model.Lookup(string(c.Kind)); ok && id.Can(Area(info), "read") {
				visible = append(visible, c)
			}
		}
		ev.Changes = visible
		return send("change", ev)
	}
	if !send("hello", map[string]any{"index": s.Store.Current().Index()}) {
		return
	}
	tick := time.NewTicker(s.Heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.Done:
			return
		case ev := <-changes:
			if !sendChange(ev) {
				return
			}
		case n := <-notices:
			// A change comes before the outcome of applying it: send the
			// changes that are already waiting first.
			for drained := false; !drained; {
				select {
				case ev := <-changes:
					if !sendChange(ev) {
						return
					}
				default:
					drained = true
				}
			}
			out := map[string]any{"event": n.Event, "index": n.Index, "actor": n.Actor, "reason": n.Reason}
			if n.Err != nil {
				out["error"] = n.Err.Error()
			}
			if !send("apply", out) {
				return
			}
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}
