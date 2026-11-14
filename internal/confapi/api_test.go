package confapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

type rig struct {
	t     *testing.T
	srv   *httptest.Server
	store *confstore.Store
	eng   *confapply.Engine
}

var users = map[string]Identity{
	"admin":  {Name: "admin", Permissions: []string{"*:write"}},
	"alice":  {Name: "alice", Permissions: []string{"*:read", "firewall:write", "routing:write", "vpn:write"}},
	"bob":    {Name: "bob", Permissions: []string{"*:read", "firewall:write"}},
	"viewer": {Name: "viewer", Permissions: []string{"*:read"}},
	"fwonly": {Name: "fwonly", Permissions: []string{"firewall:read"}},
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	store, err := confstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	api := &Server{Store: store, Heartbeat: 50 * time.Millisecond,
		Identify: func(r *http.Request) (Identity, bool) { id, ok := users[r.Header.Get("X-User")]; return id, ok }}
	eng, err := confapply.New(store, confapply.Options{Dir: dir, Window: time.Hour, Notify: api.Notice})
	if err != nil {
		t.Fatal(err)
	}
	api.Engine = eng
	srv := httptest.NewServer(api)
	t.Cleanup(func() { srv.Close(); store.Close() })
	return &rig{t: t, srv: srv, store: store, eng: eng}
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("not a JSON object (%d): %s", r.status, r.body)
	}
	return m
}

// do sends a request as user. hdr are extra "Name: value" headers.
func (r *rig) do(user, method, path string, body any, hdr ...string) resp {
	r.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		js, _ := json.Marshal(b)
		rd = bytes.NewReader(js)
	}
	req, _ := http.NewRequest(method, r.srv.URL+path, rd)
	req.Header.Set("X-User", user)
	for _, h := range hdr {
		k, v, _ := strings.Cut(h, ": ")
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, data}
}

// settle confirms the pending change so the next write is accepted.
func (r *rig) settle() {
	r.t.Helper()
	if res := r.do("admin", "POST", "/api/v1/apply/confirm", nil); res.status != 204 {
		r.t.Fatalf("confirm: %d %s", res.status, res.body)
	}
}

func (r *rig) mustCreate(user, plural string, body any) map[string]any {
	r.t.Helper()
	res := r.do(user, "POST", "/api/v1/"+plural, body)
	if res.status != 201 {
		r.t.Fatalf("create %s: %d %s", plural, res.status, res.body)
	}
	r.settle()
	return res.json(r.t)
}

func TestCRUDWithETagAndIfMatch(t *testing.T) {
	r := newRig(t)
	if res := r.do("", "GET", "/api/v1/aliases", nil); res.status != 401 {
		t.Fatalf("anonymous: %d", res.status)
	}

	res := r.do("alice", "POST", "/api/v1/aliases", map[string]any{"name": "web", "type": "host", "entries": []string{"192.0.2.1"}})
	if res.status != 201 || res.header.Get("ETag") != `"1"` || res.header.Get("Testudo-Pending") != "1" ||
		res.header.Get("Testudo-Confirm-By") == "" {
		t.Fatalf("create: %d %v %s", res.status, res.header, res.body)
	}
	obj := res.json(t)
	id := obj["id"].(string)
	if obj["created_by"] != "alice" || obj["version"].(float64) != 1 || obj["scope"] != "global" {
		t.Errorf("created object: %v", obj)
	}
	// A second write is refused while the first awaits confirmation.
	if res := r.do("alice", "POST", "/api/v1/aliases", map[string]any{"name": "db", "type": "host"}); res.status != 423 ||
		res.json(t)["error"] != "pending" {
		t.Errorf("write during confirmation window: %d %s", res.status, res.body)
	}
	r.settle()

	if res := r.do("viewer", "GET", "/api/v1/aliases/"+id, nil); res.status != 200 || res.header.Get("ETag") != `"1"` {
		t.Errorf("get: %d %v", res.status, res.header)
	}
	obj["description"] = "edited"
	if res := r.do("alice", "PUT", "/api/v1/aliases/"+id, obj); res.status != 428 {
		t.Errorf("update without If-Match: %d", res.status)
	}
	res = r.do("alice", "PUT", "/api/v1/aliases/"+id, obj, `If-Match: "1"`)
	if res.status != 200 || res.header.Get("ETag") != `"2"` || res.json(t)["description"] != "edited" {
		t.Fatalf("update: %d %s", res.status, res.body)
	}
	r.settle()

	if res := r.do("alice", "DELETE", "/api/v1/aliases/"+id, nil, `If-Match: "2"`); res.status != 204 {
		t.Fatalf("delete: %d %s", res.status, res.body)
	}
	r.settle()
	if res := r.do("alice", "GET", "/api/v1/aliases/"+id, nil); res.status != 404 {
		t.Errorf("get after delete: %d", res.status)
	}
	for path, want := range map[string]int{"/api/v1/nonsense": 404, "/api/v1/alias": 404} {
		if res := r.do("alice", "GET", path, nil); res.status != want {
			t.Errorf("GET %s: %d", path, res.status)
		}
	}
}

func TestTwoAdminsGetACleanConflict(t *testing.T) {
	r := newRig(t)
	obj := r.mustCreate("alice", "aliases", map[string]any{"name": "web", "type": "host", "entries": []string{"192.0.2.1"}})
	id := obj["id"].(string)

	mine, theirs := map[string]any{}, map[string]any{}
	for k, v := range obj {
		mine[k], theirs[k] = v, v
	}
	theirs["entries"] = []string{"192.0.2.9"}
	if res := r.do("bob", "PUT", "/api/v1/aliases/"+id, theirs, `If-Match: "1"`); res.status != 200 {
		t.Fatalf("first writer: %d %s", res.status, res.body)
	}
	r.settle()

	mine["description"] = "mine"
	res := r.do("alice", "PUT", "/api/v1/aliases/"+id, mine, `If-Match: "1"`)
	if res.status != 409 {
		t.Fatalf("stale write: %d %s", res.status, res.body)
	}
	p := res.json(t)
	if p["error"] != "conflict" || p["current_version"].(float64) != 2 {
		t.Errorf("problem: %v", p)
	}
	fields := map[string]bool{}
	for _, d := range p["diff"].([]any) {
		fields[d.(map[string]any)["field"].(string)] = true
	}
	if len(fields) != 2 || !fields["entries"] || !fields["description"] {
		t.Errorf("diff fields: %v", fields)
	}
	if cur := p["current"].(map[string]any); cur["updated_by"] != "bob" {
		t.Errorf("current object not included: %v", cur)
	}
	got := r.do("alice", "GET", "/api/v1/aliases/"+id, nil).json(t)
	if got["description"] != nil || got["version"].(float64) != 2 {
		t.Errorf("the stale write changed the object: %v", got)
	}
}

func TestInUseValidationAndInlineReferences(t *testing.T) {
	r := newRig(t)
	alias := r.mustCreate("alice", "aliases", map[string]any{"name": "web", "type": "host"})
	rule := r.mustCreate("alice", "filter-rules", map[string]any{"name": "allow", "action": "accept", "direction": "in",
		"protocol": "tcp", "enabled": true, "destination": []string{alias["id"].(string)}})

	res := r.do("alice", "GET", "/api/v1/aliases/"+alias["id"].(string)+"/used-by", nil)
	var uses []map[string]any
	json.Unmarshal(res.body, &uses)
	if len(uses) != 1 || uses[0]["name"] != "allow" || uses[0]["field"] != "destination[0]" {
		t.Errorf("used-by: %s", res.body)
	}
	res = r.do("alice", "DELETE", "/api/v1/aliases/"+alias["id"].(string), nil, `If-Match: "1"`)
	if p := res.json(t); res.status != 409 || p["error"] != "in_use" || len(p["used_by"].([]any)) != 1 {
		t.Errorf("delete in use: %d %s", res.status, res.body)
	}

	res = r.do("alice", "POST", "/api/v1/aliases", map[string]any{"name": "bad name", "type": "nope"})
	if p := res.json(t); res.status != 422 || p["error"] != "invalid" || len(p["fields"].([]any)) != 2 {
		t.Errorf("invalid: %d %s", res.status, res.body)
	}
	res = r.do("alice", "POST", "/api/v1/aliases", `{"name":"x","type":"host","colour":"red"}`)
	if res.status != 400 {
		t.Errorf("unknown field: %d %s", res.status, res.body)
	}
	res = r.do("alice", "POST", "/api/v1/filter-rules", map[string]any{"name": "dangling", "action": "accept",
		"direction": "in", "protocol": "tcp", "source_zone": "99999999-9999-4999-8999-999999999999"})
	if p := res.json(t); res.status != 422 || p["error"] != "inconsistent" {
		t.Errorf("dangling reference: %d %s", res.status, res.body)
	}
	_ = rule
}

func TestPermissionsAreEnforcedPerKind(t *testing.T) {
	r := newRig(t)
	site := map[string]any{"name": "hq"}
	if res := r.do("alice", "POST", "/api/v1/sites", site); res.status != 403 {
		t.Errorf("operator creating a site: %d", res.status)
	}
	if res := r.do("viewer", "POST", "/api/v1/aliases", map[string]any{"name": "x", "type": "host"}); res.status != 403 {
		t.Errorf("viewer writing: %d", res.status)
	}
	if res := r.do("fwonly", "GET", "/api/v1/users", nil); res.status != 403 {
		t.Errorf("reading another area: %d", res.status)
	}
	if res := r.do("fwonly", "GET", "/api/v1/aliases", nil); res.status != 200 {
		t.Errorf("reading own area: %d", res.status)
	}
	for _, path := range []string{"/api/v1/export"} {
		if res := r.do("alice", "GET", path, nil); res.status != 403 {
			t.Errorf("%s as operator: %d", path, res.status)
		}
	}
	if res := r.do("viewer", "POST", "/api/v1/apply/confirm", nil); res.status != 403 {
		t.Errorf("viewer confirming: %d", res.status)
	}
	r.mustCreate("admin", "sites", site)
}

func TestChangeSetsReviewAndApplyAsOneTransaction(t *testing.T) {
	r := newRig(t)
	base := r.mustCreate("alice", "aliases", map[string]any{"name": "web", "type": "host"})

	csA := r.do("alice", "POST", "/api/v1/changesets", map[string]any{"name": "add db"}).json(t)["id"].(string)
	csB := r.do("bob", "POST", "/api/v1/changesets", map[string]any{"name": "grow web"}).json(t)["id"].(string)

	res := r.do("alice", "POST", "/api/v1/aliases?changeset="+csA, map[string]any{"name": "db", "type": "host"})
	if res.status != 202 || res.header.Get("Testudo-Pending") != "" {
		t.Fatalf("draft create: %d %s", res.status, res.body)
	}
	base["entries"] = []string{"192.0.2.7"}
	if res := r.do("bob", "PUT", "/api/v1/aliases/"+base["id"].(string)+"?changeset="+csB, base, `If-Match: "1"`); res.status != 202 {
		t.Fatalf("draft update: %d %s", res.status, res.body)
	}
	// Editing the same object again inside the draft keeps one op.
	base["description"] = "second edit"
	if res := r.do("bob", "PUT", "/api/v1/aliases/"+base["id"].(string)+"?changeset="+csB, base, `If-Match: "1"`); res.status != 202 || res.json(t)["ops"].(float64) != 1 {
		t.Fatalf("second draft edit: %d %s", res.status, res.body)
	}
	// Drafts change nothing live and cannot be edited by others.
	if n := len(r.store.Current().List(model.KindAlias)); n != 1 {
		t.Fatalf("draft changed the live model: %d aliases", n)
	}
	if res := r.do("bob", "POST", "/api/v1/aliases?changeset="+csA, map[string]any{"name": "x", "type": "host"}); res.status != 403 {
		t.Errorf("writing into someone else's draft: %d", res.status)
	}
	// An invalid op is refused when it is added, not at apply time.
	if res := r.do("alice", "POST", "/api/v1/aliases?changeset="+csA, map[string]any{"name": "db", "type": "host"}); res.status != 422 {
		t.Errorf("duplicate name inside a draft: %d %s", res.status, res.body)
	}

	view := r.do("alice", "GET", "/api/v1/changesets/"+csB, nil).json(t)
	if ch := view["changes"].([]any); len(ch) != 1 || ch[0].(map[string]any)["type"] != "update" || view["owner"] != "bob" {
		t.Errorf("draft view: %v", view)
	}

	body := map[string]any{"changesets": []string{csA, csB}, "note": "both"}
	beforePlan := r.store.Current().Index()
	plan := r.do("alice", "POST", "/api/v1/plan", body)
	if plan.status != 200 || len(plan.json(t)["changes"].([]any)) != 2 || r.store.Current().Index() != beforePlan {
		t.Fatalf("plan: %d %s (index %d)", plan.status, plan.body, r.store.Current().Index())
	}
	res = r.do("alice", "POST", "/api/v1/apply", body)
	if res.status != 200 || res.header.Get("Testudo-Pending") == "" {
		t.Fatalf("apply: %d %s", res.status, res.body)
	}
	st := r.do("alice", "GET", "/api/v1/apply", nil).json(t)
	if st["pending"] == nil {
		t.Errorf("status shows nothing pending: %v", st)
	}
	r.settle()

	var list []map[string]any
	json.Unmarshal(r.do("alice", "GET", "/api/v1/aliases", nil).body, &list)
	if len(list) != 2 || list[0]["version"] != list[1]["version"] || list[1]["description"] != "second edit" {
		t.Errorf("after apply: %v", list)
	}
	var sets []any
	json.Unmarshal(r.do("alice", "GET", "/api/v1/changesets", nil).body, &sets)
	if len(sets) != 0 {
		t.Errorf("change sets were not consumed: %v", sets)
	}

	hist := r.do("alice", "GET", "/api/v1/history?limit=1", nil)
	var recs []map[string]any
	json.Unmarshal(hist.body, &recs)
	if recs[0]["actor"] != "alice" || recs[0]["note"] != "both" || len(recs[0]["changes"].([]any)) != 2 {
		t.Errorf("history: %s", hist.body)
	}
}

func TestRollbackRevertAndImport(t *testing.T) {
	r := newRig(t)
	r.mustCreate("admin", "aliases", map[string]any{"name": "keep", "type": "host"})

	res := r.do("admin", "POST", "/api/v1/aliases", map[string]any{"name": "oops", "type": "host"})
	idx := res.header.Get("Testudo-Pending")
	if rb := r.do("admin", "POST", "/api/v1/apply/rollback", map[string]any{"reason": "typo"}); rb.status != 204 {
		t.Fatalf("rollback: %d %s", rb.status, rb.body)
	}
	if n := len(r.store.Current().List(model.KindAlias)); n != 1 {
		t.Errorf("after rollback: %d aliases", n)
	}
	if rb := r.do("admin", "POST", "/api/v1/apply/rollback", nil); rb.status != 409 {
		t.Errorf("second rollback: %d", rb.status)
	}
	_ = idx

	backup := r.do("admin", "GET", "/api/v1/export", nil)
	if backup.status != 200 {
		t.Fatalf("export: %d", backup.status)
	}
	r.mustCreate("admin", "aliases", map[string]any{"name": "later", "type": "host"})
	dry := r.do("admin", "POST", "/api/v1/import?dry_run=1", string(backup.body))
	if dry.status != 200 || len(dry.json(t)["changes"].([]any)) != 1 {
		t.Fatalf("import dry run: %d %s", dry.status, dry.body)
	}
	if imp := r.do("admin", "POST", "/api/v1/import", string(backup.body)); imp.status != 200 {
		t.Fatalf("import: %d %s", imp.status, imp.body)
	}
	r.settle()
	if n := len(r.store.Current().List(model.KindAlias)); n != 1 {
		t.Errorf("after import: %d aliases", n)
	}

	// Revert the import through the API: "later" comes back.
	last := r.store.Current().Index()
	if rv := r.do("admin", "POST", "/api/v1/history/"+itoa(last)+"/revert", nil); rv.status != 200 {
		t.Fatalf("revert: %d %s", rv.status, rv.body)
	}
	r.settle()
	if n := len(r.store.Current().List(model.KindAlias)); n != 2 {
		t.Errorf("after revert: %d aliases", n)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestSecretsNeverLeaveAndSurviveARoundTrip(t *testing.T) {
	r := newRig(t)
	site := r.mustCreate("admin", "sites", map[string]any{"name": "hq"})
	n := r.mustCreate("admin", "bgp-neighbors", map[string]any{"name": "peer", "scope": "site:" + site["id"].(string),
		"local_as": 65001, "remote_as": 65002, "address": "192.0.2.1", "session_secret": "hunter2", "enabled": true})
	if n["session_secret"] != model.SecretMask {
		t.Fatalf("create response shows the secret: %v", n["session_secret"])
	}
	n["bfd"] = true
	res := r.do("admin", "PUT", "/api/v1/bgp-neighbors/"+n["id"].(string), n, `If-Match: "`+itoa(int64(n["version"].(float64)))+`"`)
	if res.status != 200 {
		t.Fatalf("masked round trip: %d %s", res.status, res.body)
	}
	r.settle()
	cur, _ := r.store.Current().Get(model.KindBGPNeighbor, n["id"].(string))
	if cur.(*model.BGPNeighbor).SessionSecret != "hunter2" {
		t.Errorf("secret lost on round trip: %q", cur.(*model.BGPNeighbor).SessionSecret)
	}
	for _, path := range []string{"/api/v1/bgp-neighbors", "/api/v1/history"} {
		if body := r.do("admin", "GET", path, nil).body; bytes.Contains(body, []byte("hunter2")) {
			t.Errorf("%s leaks the secret", path)
		}
	}
	// The backup does contain it, which is why it needs system:write.
	if body := r.do("admin", "GET", "/api/v1/export", nil).body; !bytes.Contains(body, []byte("hunter2")) {
		t.Error("export lost the secret; a restore would break the session")
	}
}

func TestEffectiveShowsWhereAValueComesFrom(t *testing.T) {
	r := newRig(t)
	site := r.mustCreate("admin", "sites", map[string]any{"name": "branch"})["id"].(string)
	a := r.mustCreate("admin", "aliases", map[string]any{"name": "dns", "type": "host", "entries": []string{"192.0.2.53"},
		"overrides": []map[string]any{{"scope": "site:" + site, "values": map[string]any{"entries": []string{"198.51.100.53"}}}}})
	res := r.do("viewer", "GET", "/api/v1/aliases/"+a["id"].(string)+"/effective?site="+site, nil).json(t)
	if res["object"].(map[string]any)["entries"].([]any)[0] != "198.51.100.53" ||
		res["origins"].(map[string]any)["entries"] != "site:"+site || res["base_scope"] != "global" {
		t.Errorf("effective: %v", res)
	}
	res = r.do("viewer", "GET", "/api/v1/aliases/"+a["id"].(string)+"/effective", nil).json(t)
	if res["object"].(map[string]any)["entries"].([]any)[0] != "192.0.2.53" || len(res["origins"].(map[string]any)) != 0 {
		t.Errorf("effective without a site: %v", res)
	}
}

func TestEventStream(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", r.srv.URL+"/api/v1/events", nil)
	req.Header.Set("X-User", "fwonly")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	next := func(event string) map[string]any {
		t.Helper()
		seen := false
		for l := range lines {
			if l == "event: "+event {
				seen = true
			} else if seen && strings.HasPrefix(l, "data: ") {
				var m map[string]any
				json.Unmarshal([]byte(l[6:]), &m)
				return m
			}
		}
		t.Fatalf("stream ended before event %q", event)
		return nil
	}
	next("hello")

	r.do("admin", "POST", "/api/v1/aliases", map[string]any{"name": "web", "type": "host"})
	ev := next("change")
	ch := ev["changes"].([]any)[0].(map[string]any)
	if ev["actor"] != "admin" || ch["name"] != "web" || ch["type"] != "create" || ch["after"] != nil {
		t.Errorf("change event: %v", ev)
	}
	if ap := next("apply"); ap["event"] != "applied" {
		t.Errorf("apply event: %v", ap)
	}
	r.settle()
	if ap := next("apply"); ap["event"] != "confirmed" {
		t.Errorf("confirm event: %v", ap)
	}
	// Objects the subscriber may not read are not named.
	r.do("admin", "POST", "/api/v1/sites", map[string]any{"name": "hq"})
	if ev := next("change"); ev["changes"] != nil && len(ev["changes"].([]any)) != 0 {
		t.Errorf("event names an object outside the subscriber's areas: %v", ev)
	}
}
