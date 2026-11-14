package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// RefUse is one reference found inside an object.
type RefUse struct {
	Field  string // JSON path of the referring field, e.g. "source[1]"
	Target Kind
	ID     string
}

var anyRefType = reflect.TypeOf((*AnyRef)(nil)).Elem()

// Refs returns every non-empty reference an object holds. Scope targets are
// included: a site- or node-scoped object depends on that site or node.
func Refs(e Entity) []RefUse {
	var out []RefUse
	walkRefs(reflect.ValueOf(e).Elem(), "", &out)
	m := e.GetMeta()
	scopes := []struct {
		path string
		s    Scope
	}{{"scope", m.Scope}}
	for i, o := range m.Overrides {
		scopes = append(scopes, struct {
			path string
			s    Scope
		}{fmt.Sprintf("overrides[%d].scope", i), o.Scope})
	}
	for _, sc := range scopes {
		switch sc.s.Level() {
		case "site":
			out = append(out, RefUse{Field: sc.path, Target: KindSite, ID: sc.s.Target()})
		case "node":
			out = append(out, RefUse{Field: sc.path, Target: KindClusterNode, ID: sc.s.Target()})
		}
	}
	return out
}

func walkRefs(v reflect.Value, path string, out *[]RefUse) {
	if v.Type().Implements(anyRefType) {
		r := v.Interface().(AnyRef)
		if r.TargetID() != "" {
			*out = append(*out, RefUse{Field: path, Target: r.TargetKind(), ID: r.TargetID()})
		}
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			walkRefs(v.Elem(), path, out)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			walkRefs(v.Index(i), fmt.Sprintf("%s[%d]", path, i), out)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			p := path
			if !f.Anonymous {
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				if p != "" {
					p += "."
				}
				p += name
			}
			walkRefs(v.Field(i), p, out)
		}
	}
}

// SecretMask replaces secret values in API output. Sending it back on an
// update means "leave the stored value unchanged".
const SecretMask = "********"

// Mask returns a copy with every non-empty secret field replaced by
// SecretMask. Use it for anything that leaves the process: API responses,
// logs, audit records, events.
func Mask(e Entity) Entity {
	c := Clone(e)
	visitSecrets(reflect.ValueOf(c).Elem(), reflect.Value{}, func(dst, _ reflect.Value) {
		if dst.String() != "" {
			dst.SetString(SecretMask)
		}
	})
	return c
}

// KeepMaskedSecrets copies secret values from prev into next wherever next
// carries SecretMask, so a client can round-trip a masked object.
func KeepMaskedSecrets(next, prev Entity) {
	if prev == nil || next.Kind() != prev.Kind() {
		return
	}
	visitSecrets(reflect.ValueOf(next).Elem(), reflect.ValueOf(prev).Elem(), func(dst, src reflect.Value) {
		if dst.String() == SecretMask && src.IsValid() {
			dst.SetString(src.String())
		}
	})
}

// visitSecrets calls fn for every string field tagged secret:"true". Secrets
// are only supported on string fields of the entity and of structs nested
// directly in it, which the tag lint enforces.
func visitSecrets(dst, src reflect.Value, fn func(dst, src reflect.Value)) {
	t := dst.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		var s reflect.Value
		if src.IsValid() {
			s = src.Field(i)
		}
		switch {
		case f.Tag.Get("secret") == "true" && f.Type.Kind() == reflect.String:
			fn(dst.Field(i), s)
		case f.Type.Kind() == reflect.Struct && !f.Type.Implements(anyRefType) && f.Type.PkgPath() == t.PkgPath():
			visitSecrets(dst.Field(i), s, fn)
		}
	}
}

// protectedFields can never be changed by a site or node override.
var protectedFields = []string{"id", "name", "version", "scope", "overrides",
	"created_at", "created_by", "updated_at", "updated_by"}

// Effective resolves an object for one node: the base object with the
// matching site override and then the matching node override applied. The
// returned origins map says, for every overridden field, which scope its
// value came from; fields that are absent from it come from the object's own
// scope.
func Effective(e Entity, siteID, nodeID string) (Entity, map[string]Scope, error) {
	origins := map[string]Scope{}
	m := e.GetMeta()
	if len(m.Overrides) == 0 {
		return Clone(e), origins, nil
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	for _, want := range []Scope{SiteScope(siteID), NodeScope(nodeID)} {
		for _, o := range m.Overrides {
			if o.Scope != want || want.Target() == "" {
				continue
			}
			for k, v := range o.Values {
				if slices.Contains(protectedFields, k) {
					return nil, nil, fmt.Errorf("model: override of protected field %q", k)
				}
				doc[k] = v
				origins[k] = o.Scope
			}
		}
	}
	merged, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	out, err := Decode(e.Kind(), merged)
	if err != nil {
		return nil, nil, fmt.Errorf("model: override does not fit %s: %w", e.Kind(), err)
	}
	return out, origins, nil
}

// AppliesTo reports whether an object is in effect on the given node.
func AppliesTo(e Entity, siteID, nodeID string) bool {
	s := e.GetMeta().Scope
	switch s.Level() {
	case "site":
		return s.Target() == siteID
	case "node":
		return s.Target() == nodeID
	}
	return true
}
