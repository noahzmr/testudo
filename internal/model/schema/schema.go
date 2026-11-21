// Package schema derives the OpenAPI document and the UI form description
// from the structs in internal/model. Both are committed next to this file
// (openapi.json, ui.json) and embedded; a test fails when they are stale.
//
// Regenerate with: go generate ./internal/model
package schema

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/model"
)

//go:embed openapi.json
var OpenAPIJSON []byte

//go:embed ui.json
var UIJSON []byte

//go:embed fingerprints.json
var FingerprintsJSON []byte

// ReleasedJSON maps a released schema version to the fingerprints it shipped
// with. It is maintained by hand: copy fingerprints.json into it when a
// release is cut. From then on that version's wire format is frozen.
//
//go:embed released.json
var ReleasedJSON []byte

// Fingerprints renders fingerprints.json: one hash per kind over its JSON
// Schema. A changed hash means the wire format of that kind changed.
func Fingerprints() ([]byte, error) {
	kinds := map[string]string{}
	for _, info := range model.Kinds() {
		s, _, err := build(reflect.TypeOf(info.New()).Elem())
		if err != nil {
			return nil, err
		}
		// Presentation does not affect the wire format.
		raw, err := json.Marshal(stripPresentation(s))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		kinds[string(info.Kind)] = hex.EncodeToString(sum[:])
	}
	return marshal(map[string]any{"schema_version": model.SchemaVersion, "kinds": kinds})
}

func stripPresentation(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if k == "title" || k == "description" {
				continue
			}
			out[k] = stripPresentation(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = stripPresentation(t[i])
		}
		return out
	}
	return v
}

var (
	anyRefType = reflect.TypeOf((*model.AnyRef)(nil)).Elem()
	timeType   = reflect.TypeOf(time.Time{})
)

// UITag is the parsed form of a `ui:"..."` struct tag.
type UITag struct {
	Label, Widget, Ref, Group, Help, Menu string
	Order                                 int
}

// ParseUITag parses "key=value,key=value". Values cannot contain commas.
func ParseUITag(tag string) (UITag, error) {
	var t UITag
	if tag == "" {
		return t, fmt.Errorf("empty ui tag")
	}
	for _, part := range strings.Split(tag, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || v == "" {
			return t, fmt.Errorf("ui tag entry %q is not key=value", part)
		}
		switch k {
		case "label":
			t.Label = v
		case "widget":
			t.Widget = v
		case "ref":
			t.Ref = v
		case "group":
			t.Group = v
		case "help":
			t.Help = v
		case "menu":
			t.Menu = v
		case "order":
			n, err := strconv.Atoi(v)
			if err != nil {
				return t, fmt.Errorf("ui tag order %q: %w", v, err)
			}
			t.Order = n
		default:
			return t, fmt.Errorf("ui tag has unknown key %q", k)
		}
	}
	if t.Label == "" {
		return t, fmt.Errorf("ui tag has no label")
	}
	return t, nil
}

// Field is one form field in ui.json.
type Field struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Widget   string   `json:"widget,omitempty"`
	Ref      string   `json:"ref,omitempty"`
	Group    string   `json:"group,omitempty"`
	Order    int      `json:"order"`
	Help     string   `json:"help,omitempty"`
	Required bool     `json:"required,omitempty"`
	Secret   bool     `json:"secret,omitempty"`
	List     bool     `json:"list,omitempty"`
	Enum     []string `json:"enum,omitempty"`
	Rules    []string `json:"rules,omitempty"`
	Fields   []Field  `json:"fields,omitempty"`
}

// Form is one entity in ui.json.
type Form struct {
	Kind   string   `json:"kind"`
	Plural string   `json:"plural"`
	Title  string   `json:"title"`
	Menu   string   `json:"menu"`
	Scopes []string `json:"scopes"`
	Fields []Field  `json:"fields"`
}

// rule is one entry of a validate tag.
type rule struct{ name, param string }

// splitRules separates a validate tag into the rules for the value itself
// and the rules for its elements (after "dive"). Map key rules are dropped.
func splitRules(tag string) (self, elem []rule) {
	if tag == "" || tag == "-" {
		return nil, nil
	}
	cur := &self
	inKeys := false
	for _, part := range strings.Split(tag, ",") {
		name, param, _ := strings.Cut(part, "=")
		switch {
		case name == "dive":
			cur = &elem
		case name == "keys":
			inKeys = true
		case name == "endkeys":
			inKeys = false
		case !inKeys:
			*cur = append(*cur, rule{name, param})
		}
	}
	return self, elem
}

// applyRules translates validate rules into JSON Schema keywords on s and
// reports whether the value is required. An unknown rule is an error so the
// schema can never silently promise less than the server enforces.
func applyRules(s map[string]any, rules []rule, t reflect.Type) (required bool, err error) {
	kind := t.Kind()
	for _, r := range rules {
		switch r.name {
		case "required":
			required = true
			if kind == reflect.String {
				s["minLength"] = 1
			}
		case "omitempty":
		case "min", "max":
			n, perr := strconv.ParseFloat(r.param, 64)
			if perr != nil {
				return false, fmt.Errorf("rule %s=%s: %w", r.name, r.param, perr)
			}
			key := map[string]string{"min": "minimum", "max": "maximum"}[r.name]
			switch kind {
			case reflect.String:
				key = map[string]string{"min": "minLength", "max": "maxLength"}[r.name]
			case reflect.Slice:
				key = map[string]string{"min": "minItems", "max": "maxItems"}[r.name]
			case reflect.Map:
				key = map[string]string{"min": "minProperties", "max": "maxProperties"}[r.name]
			}
			s[key] = n
		case "oneof":
			s["enum"] = strings.Fields(r.param)
		case "ne":
			s["not"] = map[string]any{"const": r.param}
		case "startswith":
			s["pattern"] = "^" + r.param
		case "uuid4":
			s["format"] = "uuid"
		case "cidr":
			s["format"] = "cidr"
		case "ip":
			s["format"] = "ip"
		case "url":
			s["format"] = "uri"
		case "email":
			s["format"] = "email"
		case "hostname_rfc1123":
			s["format"] = "hostname"
		case "hostname_port":
			s["format"] = "host-port"
		case "ipv4":
			s["format"] = "ipv4"
		case "required_if", "required_unless", "required_without", "excluded_with":
			// Conditional requirements are enforced by the server; the
			// extension lets the UI mirror them.
			s["x-"+strings.ReplaceAll(r.name, "_", "-")] = r.param
		default:
			custom, ok := model.CustomRules[r.name]
			if !ok {
				return false, fmt.Errorf("validate rule %q has no schema translation", r.name)
			}
			s["x-rule"] = r.name
			if custom.Pattern != "" {
				s["pattern"] = custom.Pattern
			}
			if _, has := s["description"]; !has {
				s["description"] = custom.Description
			}
		}
	}
	return required, nil
}

// build returns the JSON Schema and the form fields for a struct type.
func build(t reflect.Type) (map[string]any, []Field, error) {
	props := map[string]any{}
	var required []string
	var fields []Field
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		if f.Anonymous {
			sub, subFields, err := build(f.Type)
			if err != nil {
				return nil, nil, err
			}
			for k, v := range sub["properties"].(map[string]any) {
				props[k] = v
			}
			if r, ok := sub["required"].([]string); ok {
				required = append(required, r...)
			}
			fields = append(fields, subFields...)
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		ui, err := ParseUITag(f.Tag.Get("ui"))
		if err != nil {
			return nil, nil, fmt.Errorf("%s.%s: %w", t.Name(), f.Name, err)
		}
		self, elem := splitRules(f.Tag.Get("validate"))
		s, fld, err := typeSchema(f.Type, self, elem)
		if err != nil {
			return nil, nil, fmt.Errorf("%s.%s: %w", t.Name(), f.Name, err)
		}
		s["title"] = ui.Label
		if ui.Help != "" {
			s["description"] = ui.Help
		}
		if ui.Widget == "readonly" {
			s["readOnly"] = true
		}
		fld.Name, fld.Label, fld.Widget, fld.Ref = name, ui.Label, ui.Widget, ui.Ref
		fld.Group, fld.Order, fld.Help = ui.Group, ui.Order, ui.Help
		if f.Tag.Get("secret") == "true" {
			fld.Secret = true
			s["format"] = "password"
			s["x-secret"] = true
		}
		for _, r := range append(self, elem...) {
			if _, ok := model.CustomRules[r.name]; ok {
				fld.Rules = append(fld.Rules, r.name)
			}
		}
		if fld.Required {
			required = append(required, name)
		}
		props[name] = s
		fields = append(fields, fld)
	}
	sort.Strings(required)
	sort.SliceStable(fields, func(i, j int) bool { return fields[i].Order < fields[j].Order })
	out := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		out["required"] = required
	}
	return out, fields, nil
}

func typeSchema(t reflect.Type, self, elem []rule) (map[string]any, Field, error) {
	s := map[string]any{}
	var fld Field
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t.Implements(anyRefType):
		target := reflect.Zero(t).Interface().(model.AnyRef).TargetKind()
		s["type"], s["format"], s["x-ref"] = "string", "uuid", string(target)
		fld.Type = "ref"
	case t == timeType:
		s["type"], s["format"] = "string", "date-time"
		fld.Type = "datetime"
	case t.Kind() == reflect.String:
		s["type"] = "string"
		fld.Type = "string"
	case t.Kind() == reflect.Bool:
		s["type"] = "boolean"
		fld.Type = "boolean"
	case t.Kind() >= reflect.Int && t.Kind() <= reflect.Uint64:
		s["type"] = "integer"
		if t.Kind() >= reflect.Uint {
			s["minimum"] = 0.0
		}
		fld.Type = "integer"
	case t.Kind() == reflect.Slice:
		items, itemFld, err := typeSchema(t.Elem(), elem, nil)
		if err != nil {
			return nil, fld, err
		}
		s["type"], s["items"] = "array", items
		fld = itemFld
		fld.List, fld.Required = true, false
	case t.Kind() == reflect.Map:
		s["type"] = "object"
		if t.Elem().Kind() == reflect.String {
			s["additionalProperties"] = map[string]any{"type": "string"}
		}
		fld.Type = "map"
	case t.Kind() == reflect.Struct:
		sub, subFields, err := build(t)
		if err != nil {
			return nil, fld, err
		}
		s = sub
		fld.Type, fld.Fields = "object", subFields
	default:
		return nil, fld, fmt.Errorf("unsupported field type %s", t)
	}
	req, err := applyRules(s, self, t)
	if err != nil {
		return nil, fld, err
	}
	fld.Required = req
	if e, ok := s["enum"].([]string); ok {
		fld.Enum = e
	}
	return s, fld, nil
}

func typeName(info model.KindInfo) string {
	return reflect.TypeOf(info.New()).Elem().Name()
}

// UI renders ui.json.
func UI() ([]byte, error) {
	var forms []Form
	for _, info := range model.Kinds() {
		_, fields, err := build(reflect.TypeOf(info.New()).Elem())
		if err != nil {
			return nil, err
		}
		forms = append(forms, Form{Kind: string(info.Kind), Plural: info.Plural, Title: info.Title,
			Menu: info.Menu, Scopes: info.Scopes, Fields: fields})
	}
	return marshal(map[string]any{"secret_mask": model.SecretMask, "forms": forms})
}

// OpenAPI renders openapi.json.
func OpenAPI() ([]byte, error) {
	schemas := map[string]any{
		"Problem": obj(map[string]any{
			"error":   map[string]any{"type": "string"},
			"message": map[string]any{"type": "string"},
		}, "error", "message"),
		"FieldError": obj(map[string]any{
			"field":   map[string]any{"type": "string"},
			"rule":    map[string]any{"type": "string"},
			"message": map[string]any{"type": "string"},
		}, "field", "rule", "message"),
		"FieldDiff": obj(map[string]any{
			"field":   map[string]any{"type": "string"},
			"yours":   map[string]any{},
			"current": map[string]any{},
		}, "field"),
		"UsedBy": obj(map[string]any{
			"kind":  map[string]any{"type": "string"},
			"id":    map[string]any{"type": "string", "format": "uuid"},
			"name":  map[string]any{"type": "string"},
			"field": map[string]any{"type": "string"},
		}, "kind", "id", "name", "field"),
	}
	ref := func(name string) map[string]any { return map[string]any{"$ref": "#/components/schemas/" + name} }
	jsonBody := func(s map[string]any) map[string]any {
		return map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": s}}}
	}
	resp := func(desc string, s map[string]any) map[string]any {
		r := map[string]any{"description": desc}
		if s != nil {
			r["content"] = jsonBody(s)["content"]
		}
		return r
	}
	problem := func(desc string, extra map[string]any) map[string]any {
		s := ref("Problem")
		if extra != nil {
			s = map[string]any{"allOf": []any{ref("Problem"), map[string]any{"type": "object", "properties": extra}}}
		}
		return resp(desc, s)
	}
	conflict := problem("The object changed since the version in If-Match.", map[string]any{
		"current_version": map[string]any{"type": "integer"},
		"diff":            map[string]any{"type": "array", "items": ref("FieldDiff")},
	})
	invalid := problem("Validation failed.", map[string]any{
		"fields": map[string]any{"type": "array", "items": ref("FieldError")},
	})
	inUse := problem("The object is referenced by others.", map[string]any{
		"used_by": map[string]any{"type": "array", "items": ref("UsedBy")},
	})
	responses := map[string]any{
		"NotFound":             problem("Not found.", nil),
		"PreconditionRequired": problem("If-Match is missing.", nil),
		"Conflict":             conflict,
		"Invalid":              invalid,
		"ConflictOrInUse": map[string]any{"description": "Version conflict, or the object is still referenced.",
			"content": jsonBody(map[string]any{"oneOf": []any{
				conflict["content"].(map[string]any)["application/json"].(map[string]any)["schema"],
				inUse["content"].(map[string]any)["application/json"].(map[string]any)["schema"]}})["content"]},
		"UsedBy": resp("Referrers", map[string]any{"type": "array", "items": ref("UsedBy")}),
	}
	parameters := map[string]any{
		"id": map[string]any{"name": "id", "in": "path", "required": true,
			"schema": map[string]any{"type": "string", "format": "uuid"}},
		"ifMatch": map[string]any{"name": "If-Match", "in": "header", "required": true,
			"description": "The object version this change is based on, as returned in ETag.",
			"schema":      map[string]any{"type": "string"}},
		"changeset": map[string]any{"name": "changeset", "in": "query", "required": false,
			"description": "Record the change in this change set instead of applying it immediately.",
			"schema":      map[string]any{"type": "string", "format": "uuid"}},
	}
	rr := func(name string) map[string]any { return map[string]any{"$ref": "#/components/responses/" + name} }
	pr := func(name string) map[string]any { return map[string]any{"$ref": "#/components/parameters/" + name} }
	etag := map[string]any{"ETag": map[string]any{"schema": map[string]any{"type": "string"}}}

	paths := map[string]any{}
	for _, info := range model.Kinds() {
		name := typeName(info)
		s, _, err := build(reflect.TypeOf(info.New()).Elem())
		if err != nil {
			return nil, err
		}
		s["x-kind"], s["x-menu"], s["x-scopes"] = string(info.Kind), info.Menu, info.Scopes
		schemas[name] = s
		tag := []string{info.Menu[:strings.Index(info.Menu, "/")]}
		one := resp(info.Title, ref(name))
		one["headers"] = etag
		paths["/api/v1/"+info.Plural] = map[string]any{
			"get": map[string]any{"operationId": "list_" + string(info.Kind), "tags": tag,
				"summary": "List " + info.Title + " objects",
				"responses": map[string]any{"200": resp("List",
					map[string]any{"type": "array", "items": ref(name)})}},
			"post": map[string]any{"operationId": "create_" + string(info.Kind), "tags": tag,
				"summary": "Create a " + info.Title, "parameters": []any{pr("changeset")},
				"requestBody": jsonBody(ref(name)),
				"responses":   map[string]any{"201": one, "422": rr("Invalid")}},
		}
		paths["/api/v1/"+info.Plural+"/{id}"] = map[string]any{
			"parameters": []any{pr("id")},
			"get": map[string]any{"operationId": "get_" + string(info.Kind), "tags": tag,
				"summary":   "Read a " + info.Title,
				"responses": map[string]any{"200": one, "404": rr("NotFound")}},
			"put": map[string]any{"operationId": "update_" + string(info.Kind), "tags": tag,
				"summary": "Replace a " + info.Title, "parameters": []any{pr("ifMatch"), pr("changeset")},
				"requestBody": jsonBody(ref(name)),
				"responses": map[string]any{"200": one, "404": rr("NotFound"),
					"409": rr("Conflict"), "422": rr("Invalid"), "428": rr("PreconditionRequired")}},
			"delete": map[string]any{"operationId": "delete_" + string(info.Kind), "tags": tag,
				"summary": "Delete a " + info.Title, "parameters": []any{pr("ifMatch"), pr("changeset")},
				"responses": map[string]any{"204": resp("Deleted", nil), "404": rr("NotFound"),
					"409": rr("ConflictOrInUse"), "428": rr("PreconditionRequired")}},
		}
		paths["/api/v1/"+info.Plural+"/{id}/effective"] = map[string]any{
			"parameters": []any{pr("id"),
				map[string]any{"name": "site", "in": "query", "schema": map[string]any{"type": "string", "format": "uuid"}},
				map[string]any{"name": "node", "in": "query", "schema": map[string]any{"type": "string", "format": "uuid"}}},
			"get": map[string]any{"operationId": "effective_" + string(info.Kind), "tags": tag,
				"summary": "The " + info.Title + " as one site or node sees it, with the origin of every overridden field",
				"responses": map[string]any{"200": resp("Effective object", obj(map[string]any{
					"object":     ref(name),
					"origins":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
					"base_scope": map[string]any{"type": "string"},
					"applies":    map[string]any{"type": "boolean"},
				}, "object", "origins")), "404": rr("NotFound")}},
		}
		paths["/api/v1/"+info.Plural+"/{id}/used-by"] = map[string]any{
			"parameters": []any{pr("id")},
			"get": map[string]any{"operationId": "used_by_" + string(info.Kind), "tags": tag,
				"summary":   "List the objects that reference this " + info.Title,
				"responses": map[string]any{"200": rr("UsedBy")}},
		}
	}
	// Operations that are not about one kind.
	schemas["Change"] = obj(map[string]any{
		"type": map[string]any{"enum": []string{"create", "update", "delete"}}, "kind": map[string]any{"type": "string"},
		"id": map[string]any{"type": "string"}, "name": map[string]any{"type": "string"},
		"before": map[string]any{"type": "object"}, "after": map[string]any{"type": "object"},
	}, "type", "kind", "id", "name")
	schemas["Pending"] = obj(map[string]any{
		"index": map[string]any{"type": "integer"}, "actor": map[string]any{"type": "string"},
		"note": map[string]any{"type": "string"}, "deadline": map[string]any{"type": "string", "format": "date-time"},
	}, "index", "actor", "deadline")
	changes := map[string]any{"type": "array", "items": ref("Change")}
	pending := resp("The change is live and waits for confirmation until the deadline.",
		obj(map[string]any{"pending": ref("Pending")}, "pending"))
	responses["Pending"] = problem("Another change is waiting for confirmation.", map[string]any{"pending": ref("Pending")})
	responses["StageFailed"] = problem("A stage refused the change (422) or failed while applying it (502).", map[string]any{
		"stage": map[string]any{"type": "string"}, "phase": map[string]any{"type": "string"}, "rolled_back": map[string]any{"type": "boolean"}})
	sets := jsonBody(obj(map[string]any{
		"changesets": map[string]any{"type": "array", "items": map[string]any{"type": "string", "format": "uuid"}},
		"note":       map[string]any{"type": "string"}}, "changesets"))
	op := func(id, summary string, responses map[string]any, extra ...map[string]any) map[string]any {
		o := map[string]any{"operationId": id, "tags": []string{"changes"}, "summary": summary, "responses": responses}
		for _, e := range extra {
			for k, v := range e {
				o[k] = v
			}
		}
		return o
	}
	ok := func(desc string, s map[string]any) map[string]any { return map[string]any{"200": resp(desc, s)} }
	none := map[string]any{"204": resp("Done", nil), "409": problem("Nothing is waiting for confirmation.", nil)}
	applied := map[string]any{"200": pending, "409": rr("Conflict"), "422": rr("Invalid"), "423": rr("Pending"), "502": rr("StageFailed")}
	paths["/api/v1/whoami"] = map[string]any{"get": op("whoami", "The caller and their permissions", ok("Identity", obj(map[string]any{
		"name": map[string]any{"type": "string"}, "permissions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "name", "permissions")))}
	paths["/api/v1/schema/openapi.json"] = map[string]any{"get": op("schema_openapi", "This document", ok("OpenAPI document", map[string]any{"type": "object"}))}
	paths["/api/v1/schema/ui.json"] = map[string]any{"get": op("schema_ui", "Form descriptions for every kind", ok("UI schema", map[string]any{"type": "object"}))}
	paths["/api/v1/events"] = map[string]any{"get": op("events", "Server-sent events: 'change' per committed record, 'apply' per apply outcome",
		map[string]any{"200": map[string]any{"description": "Event stream", "content": map[string]any{"text/event-stream": map[string]any{"schema": map[string]any{"type": "string"}}}}})}
	paths["/api/v1/runtime"] = map[string]any{"get": op("runtime", "What the model's objects do in the running system: packet-filter path, per-object counters, state of run-time aliases", ok("Runtime state", map[string]any{"type": "object"}))}
	strs := func(names ...string) map[string]any {
		props := map[string]any{}
		for _, n := range names {
			props[n] = map[string]any{"type": "string"}
		}
		return obj(props, names...)
	}
	vpn := func(id, summary string, body map[string]any) map[string]any {
		o := op(id, summary, map[string]any{"201": resp("Created", body)})
		o["tags"] = []string{"vpn"}
		return map[string]any{"post": o}
	}
	paths["/api/v1/wg/tunnel-key"] = vpn("wg_tunnel_key", "Create a tunnel's private key in the node's secret store; returns the entry name and the public key", strs("key_ref", "public_key"))
	paths["/api/v1/wg/preshared-key"] = vpn("wg_preshared_key", "Create a preshared key in the node's secret store; the key is returned this one time", strs("preshared_ref", "preshared_key"))
	paths["/api/v1/wg/client-keypair"] = vpn("wg_client_keypair", "Create a key pair for a client device; nothing is stored", strs("private_key", "public_key"))
	paths["/api/v1/wg-peers/{id}/client-config"] = map[string]any{"parameters": []any{pr("id")},
		"get": op("wg_client_config", "A peer's client configuration, with placeholders where its two secrets go",
			map[string]any{"200": resp("Configuration", strs("config", "private_key_placeholder", "preshared_key_placeholder")), "404": rr("NotFound")})}
	tagged := func(o map[string]any, tag string) map[string]any { o["tags"] = []string{tag}; return o }
	certFields := obj(map[string]any{"source": map[string]any{"type": "string"}, "chain_pem": map[string]any{"type": "string"},
		"key_ref": map[string]any{"type": "string"}, "not_after": map[string]any{"type": "string", "format": "date-time"},
		"domains": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "source", "chain_pem", "key_ref", "not_after")
	paths["/api/v1/pki/issue"] = map[string]any{"post": tagged(op("pki_issue", "Issue a certificate from the internal authority; the key stays in the node's secret store and the answer holds the fields of a certificate object",
		map[string]any{"201": resp("Certificate fields", certFields), "422": rr("Invalid")},
		map[string]any{"requestBody": jsonBody(obj(map[string]any{"domains": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "domains"))}), "certificates")}
	paths["/api/v1/pki/import"] = map[string]any{"post": tagged(op("pki_import", "Store the private key of a certificate issued elsewhere, after checking that it belongs to the certificate; the key is never returned",
		map[string]any{"201": resp("Certificate fields", certFields), "422": rr("Invalid")},
		map[string]any{"requestBody": jsonBody(strs("chain_pem", "key_pem"))}), "certificates")}
	paths["/api/v1/pki/ca"] = map[string]any{"get": tagged(op("pki_ca", "The internal authority's certificate in PEM, for clients to trust",
		map[string]any{"200": map[string]any{"description": "PEM certificate", "content": map[string]any{"application/x-pem-file": map[string]any{"schema": map[string]any{"type": "string"}}}}}), "certificates")}
	paths["/api/v1/lb/firewall-hints"] = map[string]any{"get": tagged(op("lb_firewall_hints", "Per load-balancer service: whether a filter rule lets clients in, and the rule that would; nothing is created",
		ok("Hints", map[string]any{"type": "array", "items": obj(map[string]any{"service": map[string]any{"type": "string"}, "name": map[string]any{"type": "string"},
			"covered": map[string]any{"type": "boolean"}, "rule": map[string]any{"type": "object"}}, "service", "name", "covered")})), "loadbalancer")}
	paths["/api/v1/oidc/client-secret"] = map[string]any{"post": tagged(op("oidc_client_secret", "Store the identity provider's client secret on the node; returns the entry name for the provider object",
		map[string]any{"201": resp("Entry name", strs("client_secret_ref"))}, map[string]any{"requestBody": jsonBody(strs("secret"))}), "identity")}
	clusterStatus := map[string]any{"type": "object", "description": "Members with role and last apply report, leader, quorum, pending change, rollout, consensus numbers, local override"}
	cl := func(id, summary string, extra ...map[string]any) map[string]any {
		return tagged(op(id, summary, map[string]any{"200": resp("Cluster status", clusterStatus), "409": problem("Refused; the message says why.", nil)}, extra...), "cluster")
	}
	paths["/api/v1/cluster"] = map[string]any{"get": tagged(op("cluster_status", "The cluster as this member sees it", ok("Cluster status", clusterStatus)), "cluster")}
	paths["/api/v1/flows/sites"] = map[string]any{"get": tagged(op("site_flows", "Connections seen at more than one member, with where, over which tunnel and path; query all=1 adds the rest",
		ok("Correlated connections", map[string]any{"type": "object"})), "cluster")}
	paths["/api/v1/dhcp/leases"] = map[string]any{"get": tagged(op("dhcp_leases", "The addresses this node's DHCP servers handed out, newest expiry first",
		ok("Leases", map[string]any{"type": "array", "items": map[string]any{"type": "object"}})), "services")}
	paths["/api/v1/cluster/init"] = map[string]any{"post": cl("cluster_init", "Make this node the first member of a new cluster; its model becomes the cluster's")}
	paths["/api/v1/cluster/join"] = map[string]any{"post": cl("cluster_join", "Make this node a member of the cluster a join token is for; the node has to be empty",
		map[string]any{"requestBody": jsonBody(strs("token"))})}
	paths["/api/v1/cluster/token"] = map[string]any{"post": tagged(op("cluster_token", "Issue a join token: good once, for a limited time",
		map[string]any{"201": resp("Token", obj(map[string]any{"token": map[string]any{"type": "string"}, "voter": map[string]any{"type": "boolean"},
			"expires_in_minutes": map[string]any{"type": "integer"}}, "token", "voter", "expires_in_minutes")), "409": problem("Refused.", nil)},
		map[string]any{"requestBody": jsonBody(obj(map[string]any{"ttl_minutes": map[string]any{"type": "integer"}, "voter": map[string]any{"type": "boolean"}}))}), "cluster")}
	paths["/api/v1/cluster/transfer"] = map[string]any{"post": cl("cluster_transfer", "Hand leadership to another voter")}
	paths["/api/v1/cluster/members/{id}"] = map[string]any{"parameters": []any{pr("id")},
		"delete": cl("cluster_remove_member", "Remove a member and revoke its certificate")}
	paths["/api/v1/cluster/members/{id}/{action}"] = map[string]any{"parameters": []any{pr("id"), pr("action")},
		"post": cl("cluster_member_action", "promote a member to voter or demote it")}
	paths["/api/v1/cluster/override"] = map[string]any{
		"post": tagged(op("cluster_override", "Change what runs on this member only while it is cut off; break-glass administrators only; the model is not touched",
			map[string]any{"200": resp("The override in force", map[string]any{"type": "object"}), "403": problem("Not a break-glass administrator.", nil)},
			map[string]any{"requestBody": jsonBody(obj(map[string]any{"reason": map[string]any{"type": "string"}, "ops": map[string]any{"type": "array", "items": map[string]any{"type": "object"}}}, "reason", "ops"))}), "cluster"),
		"delete": tagged(op("cluster_resolve_override", "End the local override; returns its changes for review",
			map[string]any{"200": resp("The override that was in force", map[string]any{"type": "object"}), "409": problem("No override is in force.", nil)}), "cluster"),
	}
	paths["/api/v1/audit"] = map[string]any{"get": tagged(op("audit", "The newest audit rows: logins, configuration changes, applies, rollbacks and privileged operations. Query: limit, op (prefix)",
		ok("Rows", map[string]any{"type": "array", "items": obj(map[string]any{"time": map[string]any{"type": "string", "format": "date-time"},
			"actor": map[string]any{"type": "string"}, "op": map[string]any{"type": "string"}, "detail": map[string]any{"type": "string"},
			"result": map[string]any{"type": "string"}, "peer_uid": map[string]any{"type": "integer"}}, "time", "actor", "op", "detail", "result")})), "identity")}
	paths["/api/v1/tokens"] = map[string]any{"post": tagged(op("create_token", "Create an API token for the caller with some of the caller's own permissions; the token is returned this one time",
		map[string]any{"201": resp("Token", obj(map[string]any{"id": map[string]any{"type": "string"}, "name": map[string]any{"type": "string"}, "token": map[string]any{"type": "string"},
			"permissions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "expires_at": map[string]any{"type": "string", "format": "date-time"}}, "id", "name", "token", "permissions")),
			"403": problem("The token would carry a permission the caller does not hold.", nil)},
		map[string]any{"requestBody": jsonBody(obj(map[string]any{"name": map[string]any{"type": "string"}, "ttl_hours": map[string]any{"type": "integer"},
			"permissions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "name", "permissions"))}), "identity")}
	paths["/api/v1/changesets"] = map[string]any{
		"get": op("list_changesets", "List change sets", ok("Change sets", map[string]any{"type": "array", "items": map[string]any{"type": "object"}})),
		"post": op("create_changeset", "Create an empty change set", map[string]any{"201": resp("Change set", map[string]any{"type": "object"})},
			map[string]any{"requestBody": jsonBody(obj(map[string]any{"name": map[string]any{"type": "string"}}, "name"))}),
	}
	paths["/api/v1/changesets/{id}"] = map[string]any{"parameters": []any{pr("id")},
		"get":    op("get_changeset", "A change set with the diff it would produce now", map[string]any{"200": resp("Change set", obj(map[string]any{"changes": changes, "problem": map[string]any{"type": "string"}}, "changes")), "404": rr("NotFound")}),
		"delete": op("delete_changeset", "Discard a change set", map[string]any{"204": resp("Discarded", nil), "404": rr("NotFound")}),
	}
	paths["/api/v1/plan"] = map[string]any{"post": op("plan", "Combined diff and rendered output of several change sets, without committing",
		map[string]any{"200": resp("Plan", obj(map[string]any{"changes": changes, "rendered": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}}, "changes", "rendered")),
			"409": rr("Conflict"), "422": rr("Invalid")}, map[string]any{"requestBody": sets})}
	paths["/api/v1/apply"] = map[string]any{
		"get":  op("apply_status", "The change waiting for confirmation, if any", ok("Status", obj(map[string]any{"pending": map[string]any{"oneOf": []any{ref("Pending"), map[string]any{"type": "null"}}}, "index": map[string]any{"type": "integer"}}, "index", "pending"))),
		"post": op("apply", "Commit and apply several change sets as one transaction", applied, map[string]any{"requestBody": sets}),
	}
	paths["/api/v1/apply/confirm"] = map[string]any{"post": op("confirm", "Keep the pending change", none)}
	paths["/api/v1/apply/rollback"] = map[string]any{"post": op("rollback", "Take the pending change back now", none,
		map[string]any{"requestBody": jsonBody(obj(map[string]any{"reason": map[string]any{"type": "string"}}))})}
	paths["/api/v1/history"] = map[string]any{"get": op("history", "Committed records, newest first, with before and after per object",
		ok("Records", map[string]any{"type": "array", "items": map[string]any{"type": "object"}}), map[string]any{"parameters": []any{
			map[string]any{"name": "before", "in": "query", "schema": map[string]any{"type": "integer"}},
			map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer"}}}})}
	paths["/api/v1/history/{index}/revert"] = map[string]any{
		"parameters": []any{map[string]any{"name": "index", "in": "path", "required": true, "schema": map[string]any{"type": "integer"}}},
		"post":       op("revert", "Undo one record through the normal apply path", applied)}
	paths["/api/v1/export"] = map[string]any{"get": op("export", "The whole model including secrets (backup); needs system:write", ok("Snapshot", map[string]any{"type": "object"}))}
	paths["/api/v1/import"] = map[string]any{"post": op("import", "Replace the model with a snapshot as one transaction; dry_run=1 only reports the diff", applied,
		map[string]any{"requestBody": jsonBody(map[string]any{"type": "object"}),
			"parameters": []any{map[string]any{"name": "dry_run", "in": "query", "schema": map[string]any{"type": "string"}}}})}

	return marshal(map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{"title": "Testudo configuration API", "version": "1",
			"description": "Derived from the structs in internal/model. Do not edit by hand."},
		"paths":      paths,
		"components": map[string]any{"schemas": schemas, "responses": responses, "parameters": parameters},
	})
}

func obj(props map[string]any, required ...string) map[string]any {
	slices.Sort(required)
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
