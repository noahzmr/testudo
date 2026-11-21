package confapi

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

// TestPermissionsLimitedToASite: an operator of one branch changes that
// branch's objects and its nodes', reads what everyone shares, and neither
// sees nor touches another branch.
func TestPermissionsLimitedToASite(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	mk := func(e model.Entity) string {
		t.Helper()
		obj, err := r.store.Create(ctx, "admin", e)
		if err != nil {
			t.Fatal(err)
		}
		return obj.GetMeta().ID
	}
	siteA := mk(&model.Site{Meta: model.Meta{Name: "branch-a"}})
	siteB := mk(&model.Site{Meta: model.Meta{Name: "branch-b"}})
	nodeA := mk(&model.ClusterNode{Meta: model.Meta{Name: "fw-a"}, Site: model.Ref[model.Site]{ID: siteA}, Hostname: "fw-a", Address: "10.0.0.1"})
	users["branch"] = Identity{Name: "branch", Permissions: []string{"*:read@site:" + siteA, "firewall:write@site:" + siteA}}
	defer delete(users, "branch")

	zone := func(name string, scope model.Scope) map[string]any {
		return map[string]any{"name": name, "scope": scope, "default_action": "drop"}
	}
	mk(&model.Zone{Meta: model.Meta{Name: "shared", Scope: model.ScopeGlobal}, DefaultAction: "drop"})
	mk(&model.Zone{Meta: model.Meta{Name: "b-lan", Scope: model.SiteScope(siteB)}, DefaultAction: "drop"})

	for _, tc := range []struct {
		name  string
		scope model.Scope
		want  int
	}{
		{"a-lan", model.SiteScope(siteA), 201},
		{"a-node", model.NodeScope(nodeA), 201},
		{"b-dmz", model.SiteScope(siteB), 403},
		{"everyone", model.ScopeGlobal, 403},
	} {
		res := r.do("branch", "POST", "/api/v1/zones", zone(tc.name, tc.scope))
		if res.status != tc.want {
			t.Errorf("create %s at %s: %d %s", tc.name, tc.scope, res.status, res.body)
		}
		if res.status == 201 {
			if c := r.do("branch", "POST", "/api/v1/apply/confirm", nil); c.status != 204 {
				t.Fatalf("confirm own change: %d %s", c.status, c.body)
			}
		}
	}
	var listed []map[string]any
	res := r.do("branch", "GET", "/api/v1/zones", nil)
	if err := jsonUnmarshal(res.body, &listed); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, z := range listed {
		names[z["name"].(string)] = true
	}
	if !names["shared"] || !names["a-lan"] || !names["a-node"] || names["b-lan"] {
		t.Errorf("the branch sees: %v", names)
	}
	// Another branch's object is not there; moving one's own to everyone is refused.
	var bID, aID string
	for _, z := range r.store.Current().List(model.KindZone) {
		switch z.GetMeta().Name {
		case "b-lan":
			bID = z.GetMeta().ID
		case "a-lan":
			aID = z.GetMeta().ID
		}
	}
	if res := r.do("branch", "GET", "/api/v1/zones/"+bID, nil); res.status != 404 {
		t.Errorf("another branch's zone: %d", res.status)
	}
	a, _ := r.store.Current().Get(model.KindZone, aID)
	moved := zone("a-lan", model.ScopeGlobal)
	if res := r.do("branch", "PUT", "/api/v1/zones/"+aID, moved, fmt.Sprintf(`If-Match: "%d"`, a.GetMeta().Version)); res.status != 403 {
		t.Errorf("moving a zone to everyone: %d %s", res.status, res.body)
	}
	// Someone else's pending change is not the branch's to confirm.
	if res := r.do("admin", "POST", "/api/v1/zones", zone("by-admin", model.ScopeGlobal)); res.status != 201 {
		t.Fatalf("admin: %d", res.status)
	}
	if res := r.do("branch", "POST", "/api/v1/apply/confirm", nil); res.status != 403 {
		t.Errorf("the branch confirms the admin's change: %d", res.status)
	}
	if res := r.do("admin", "POST", "/api/v1/apply/confirm", nil); res.status != 204 {
		t.Fatalf("admin confirms: %d", res.status)
	}
	// Nothing that is not an object opens with a limited permission.
	if res := r.do("branch", "GET", "/api/v1/history", nil); res.status != 403 {
		t.Errorf("history: %d", res.status)
	}
	// Tokens carry no more than their holder.
	if res := r.do("branch", "POST", "/api/v1/tokens", map[string]any{"name": "t", "permissions": []string{"firewall:write"}}); res.status != 403 {
		t.Errorf("an unlimited token from a limited holder: %d", res.status)
	}
	if res := r.do("branch", "POST", "/api/v1/tokens", map[string]any{"name": "t", "permissions": []string{"firewall:read@node:" + nodeA}}); res.status != 201 {
		t.Errorf("a token within the holder's site: %d %s", res.status, res.body)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
