// Package perm decides what a list of permissions allows.
//
// A permission is "<area>:<verb>" (area may be *, verb is read or write,
// write includes read) and may be limited to a scope: "<area>:<verb>@site:<id>"
// or "@node:<id>". A limited permission covers the objects of that scope;
// one for a site also covers the objects of the site's nodes. Global
// objects, and for a node's permission also its site's objects, may be read
// with it but never written, so a branch operator can refer to the zones
// and aliases everyone shares without being able to change them.
// Everything that is not an object of the model (history, export, cluster,
// identity) needs a permission without a scope.
package perm

import (
	"strings"

	"github.com/noahzmr/testudo/internal/model"
)

// Perm is one parsed permission.
type Perm struct {
	Area, Verb string
	// Scope is "" for everywhere.
	Scope model.Scope
}

// Parse splits a permission; ok is false for a malformed one.
func Parse(s string) (Perm, bool) {
	body, scope, scoped := strings.Cut(s, "@")
	area, verb, ok := strings.Cut(body, ":")
	if !ok || area == "" || (verb != "read" && verb != "write") {
		return Perm{}, false
	}
	p := Perm{Area: area, Verb: verb}
	if scoped {
		sc := model.Scope(scope)
		if l := sc.Level(); l != "site" && l != "node" {
			return Perm{}, false
		}
		p.Scope = sc
	}
	return p, true
}

func (p Perm) covers(area, verb string) bool {
	return (p.Area == "*" || p.Area == area) && (p.Verb == verb || p.Verb == "write")
}

// Has reports whether perms allow area:verb everywhere, which is what
// everything that is not an object needs.
func Has(perms []string, area, verb string) bool {
	for _, s := range perms {
		if p, ok := Parse(s); ok && p.Scope == "" && p.covers(area, verb) {
			return true
		}
	}
	return false
}

// HasAnywhere reports whether perms allow area:verb on some objects.
func HasAnywhere(perms []string, area, verb string) bool {
	for _, s := range perms {
		if p, ok := Parse(s); ok && p.covers(area, verb) {
			return true
		}
	}
	return false
}

// SiteOf returns the site of a node, or "".
type SiteOf func(nodeID string) string

// HasAt reports whether perms allow area:verb on an object with scope obj.
func HasAt(perms []string, area, verb string, obj model.Scope, siteOf SiteOf) bool {
	for _, s := range perms {
		p, ok := Parse(s)
		if !ok || !p.covers(area, verb) {
			continue
		}
		if p.Scope == "" || p.Scope == obj {
			return true
		}
		if covered(p.Scope, obj, siteOf) {
			return true
		}
		// Reading upwards: what everyone shares, and a node's own site.
		if verb == "read" && (obj == model.ScopeGlobal || obj == "" || readsUp(p.Scope, obj, siteOf)) {
			return true
		}
	}
	return false
}

// covered reports whether a permission limited to scope reaches obj: a
// site's permission reaches its nodes' objects.
func covered(scope, obj model.Scope, siteOf SiteOf) bool {
	if scope.Level() != "site" || obj.Level() != "node" || siteOf == nil {
		return false
	}
	return siteOf(scopeID(obj)) == scopeID(scope) && scopeID(scope) != ""
}

func readsUp(scope, obj model.Scope, siteOf SiteOf) bool {
	return scope.Level() == "node" && obj.Level() == "site" && siteOf != nil && siteOf(scopeID(scope)) == scopeID(obj)
}

func scopeID(s model.Scope) string {
	_, id, _ := strings.Cut(string(s), ":")
	return id
}

// Within reports whether a permission want is no more than what have
// allow, for handing permissions on (tokens).
func Within(have []string, want string, siteOf SiteOf) bool {
	p, ok := Parse(want)
	if !ok {
		return false
	}
	if p.Scope == "" {
		return Has(have, p.Area, p.Verb)
	}
	area := p.Area
	if area == "*" {
		// A limited "everything" is only as wide as an unlimited one.
		return Has(have, "*", p.Verb) || HasAt(have, "*", p.Verb, p.Scope, siteOf)
	}
	return HasAt(have, area, p.Verb, p.Scope, siteOf)
}
