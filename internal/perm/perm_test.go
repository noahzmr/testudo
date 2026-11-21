package perm

import (
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

const (
	siteA = "00000000-0000-4000-8000-00000000000a"
	siteB = "00000000-0000-4000-8000-00000000000b"
	node1 = "00000000-0000-4000-8000-000000000001" // at site A
	node2 = "00000000-0000-4000-8000-000000000002" // at site B
)

func siteOf(n string) string { return map[string]string{node1: siteA, node2: siteB}[n] }

func TestParse(t *testing.T) {
	for s, ok := range map[string]bool{"firewall:write": true, "*:read": true, "firewall:write@site:" + siteA: true,
		"routing:read@node:" + node1: true, "firewall": false, "firewall:admin": false, "firewall:write@global": false,
		"firewall:write@rack:x": false, ":read": false} {
		if _, got := Parse(s); got != ok {
			t.Errorf("Parse(%q) = %v", s, got)
		}
	}
}

func TestScopes(t *testing.T) {
	branch := []string{"*:read@site:" + siteA, "firewall:write@site:" + siteA}
	nodeOp := []string{"firewall:write@node:" + node1}
	all := []string{"firewall:write"}
	g, sA, sB := model.ScopeGlobal, model.SiteScope(siteA), model.SiteScope(siteB)
	n1, n2 := model.NodeScope(node1), model.NodeScope(node2)
	for _, tc := range []struct {
		perms   []string
		verb    string
		obj     model.Scope
		want    bool
		comment string
	}{
		{branch, "write", sA, true, "own site"},
		{branch, "write", n1, true, "a node of the own site"},
		{branch, "write", sB, false, "another site"},
		{branch, "write", n2, false, "a node of another site"},
		{branch, "write", g, false, "global objects are shared"},
		{branch, "read", g, true, "global objects can be referred to"},
		{branch, "read", sB, false, "another site stays closed"},
		{nodeOp, "write", n1, true, "own node"},
		{nodeOp, "write", sA, false, "the node's site"},
		{nodeOp, "read", sA, true, "the node's site can be read"},
		{nodeOp, "read", sB, false, "another site"},
		{all, "write", sB, true, "unlimited"},
		{all, "write", g, true, "unlimited, global"},
	} {
		if got := HasAt(tc.perms, "firewall", tc.verb, tc.obj, siteOf); got != tc.want {
			t.Errorf("%s: %v", tc.comment, got)
		}
	}
	if Has(branch, "firewall", "write") || !HasAnywhere(branch, "firewall", "write") || Has(branch, "routing", "read") {
		t.Error("a limited permission counts where no object is involved")
	}
	if !Within(all, "firewall:write@site:"+siteA, siteOf) || !Within(branch, "firewall:write@node:"+node1, siteOf) ||
		Within(branch, "firewall:write", siteOf) || Within(branch, "firewall:write@site:"+siteB, siteOf) ||
		Within(branch, "*:write@site:"+siteA, siteOf) || !Within(branch, "*:read@site:"+siteA, siteOf) {
		t.Error("Within")
	}
}
