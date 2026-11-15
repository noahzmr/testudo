package model

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	idA = "11111111-1111-4111-8111-111111111111"
	idB = "22222222-2222-4222-8222-222222222222"
	idC = "33333333-3333-4333-8333-333333333333"
)

var snakeRe = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// TestTagLint fails the build when a model field is missing one of the tags
// that the wire format, validation and the generators depend on.
func TestTagLint(t *testing.T) {
	seenKind, seenPlural := map[Kind]bool{}, map[string]bool{}
	for _, info := range Kinds() {
		if seenKind[info.Kind] || seenPlural[info.Plural] {
			t.Errorf("%s: kind or plural registered twice", info.Kind)
		}
		seenKind[info.Kind], seenPlural[info.Plural] = true, true
		if !snakeRe.MatchString(string(info.Kind)) || !strings.Contains(info.Menu, "/") || len(info.Scopes) == 0 {
			t.Errorf("%s: bad registration %+v", info.Kind, info)
		}
		lintStruct(t, reflect.TypeOf(info.New()).Elem(), true)
	}
}

func lintStruct(t *testing.T, st reflect.Type, top bool) {
	t.Helper()
	names := map[string]bool{}
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		where := st.Name() + "." + f.Name
		if !f.IsExported() {
			t.Errorf("%s: unexported field in a model struct", where)
			continue
		}
		if f.Anonymous {
			if f.Type != reflect.TypeOf(Meta{}) || !top {
				t.Errorf("%s: only Meta may be embedded, and only in an entity", where)
			}
			if f.Tag.Get("yaml") != ",inline" {
				t.Errorf("%s: embedded Meta needs yaml:\",inline\"", where)
			}
			lintStruct(t, f.Type, false)
			continue
		}
		jsonName, jsonOpts, _ := strings.Cut(f.Tag.Get("json"), ",")
		yamlName, yamlOpts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		switch {
		case jsonName == "" || yamlName == "":
			t.Errorf("%s: needs json and yaml tags", where)
		case jsonName != yamlName:
			t.Errorf("%s: json name %q differs from yaml name %q", where, jsonName, yamlName)
		case !snakeRe.MatchString(jsonName):
			t.Errorf("%s: wire name %q is not snake_case", where, jsonName)
		case names[jsonName]:
			t.Errorf("%s: duplicate wire name %q", where, jsonName)
		}
		names[jsonName] = true
		if (jsonOpts != "") != (yamlOpts != "") {
			t.Errorf("%s: optional in one of json/yaml but not the other (%q vs %q)", where, jsonOpts, yamlOpts)
		}
		if _, ok := f.Tag.Lookup("validate"); !ok {
			t.Errorf("%s: needs a validate tag (use \"-\" when nothing applies)", where)
		}
		ui := f.Tag.Get("ui")
		if !strings.Contains(ui, "label=") || !strings.Contains(ui, "order=") {
			t.Errorf("%s: ui tag needs label and order", where)
		}

		ft := f.Type
		for ft.Kind() == reflect.Slice || ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Implements(anyRefType) {
			target := reflect.Zero(ft).Interface().(AnyRef).TargetKind()
			if _, ok := Lookup(string(target)); !ok {
				t.Errorf("%s: references unregistered kind %q", where, target)
			}
			if !strings.Contains(ui, "ref="+string(target)) || !strings.Contains(ui, "widget=ref-picker") {
				t.Errorf("%s: ui tag must carry widget=ref-picker and ref=%s", where, target)
			}
			if f.Type.Kind() != reflect.Slice && jsonOpts != "" && jsonOpts != "omitzero" {
				t.Errorf("%s: an optional single reference uses json omitzero", where)
			}
		} else if ft.Kind() == reflect.Struct && ft.PkgPath() == st.PkgPath() {
			lintStruct(t, ft, false)
		}
		if f.Tag.Get("secret") != "" {
			if f.Tag.Get("secret") != "true" || f.Type.Kind() != reflect.String {
				t.Errorf("%s: secret must be \"true\" on a string field", where)
			}
		}
	}
}

func validAlias() *Alias {
	return &Alias{Meta: Meta{ID: idA, Name: "web-servers", Scope: ScopeGlobal},
		Type: "host", Entries: []string{"192.0.2.10"}}
}

func fieldRules(t *testing.T, err error) map[string]string {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %v", err)
	}
	out := map[string]string{}
	for _, f := range ve.Fields {
		out[f.Field] = f.Rule
	}
	return out
}

func TestValidate(t *testing.T) {
	if err := Validate(validAlias()); err != nil {
		t.Fatalf("valid alias rejected: %v", err)
	}

	a := validAlias()
	a.ID, a.Name, a.Type, a.Scope = "not-a-uuid", "has space", "url_table", "site:nope"
	got := fieldRules(t, Validate(a))
	want := map[string]string{"id": "uuid4", "name": "objname", "url": "required_if", "scope": "scope"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("field errors = %v, want %v", got, want)
	}

	// Nested and list fields are addressed by their JSON path.
	p := &LBBackendPool{Meta: Meta{ID: idA, Name: "pool", Scope: ScopeGlobal}, Algorithm: "weighted_round_robin",
		Backends:    []LBBackend{{Address: "10.0.0.1:80"}, {Address: "no-port"}},
		HealthCheck: LBHealthCheck{Type: "http"}}
	got = fieldRules(t, Validate(p))
	want = map[string]string{"backends[1].address": "hostport", "health_check.path": "required_if"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("field errors = %v, want %v", got, want)
	}

	// A kind restricted to node scope rejects a global object.
	ifc := &Interface{Meta: Meta{ID: idA, Name: "wan", Scope: ScopeGlobal}, Device: "eth0"}
	if got := fieldRules(t, Validate(ifc)); got["scope"] != "scope_level" {
		t.Errorf("global interface: %v", got)
	}
	ifc.Scope = NodeScope(idB)
	if err := Validate(ifc); err != nil {
		t.Errorf("node-scoped interface rejected: %v", err)
	}
}

func TestCustomRules(t *testing.T) {
	cases := map[string]struct{ good, bad []string }{
		"portrange":        {[]string{"1", "443", "1000-2000", "65535"}, []string{"0", "65536", "20-10", "http", "1-"}},
		"wgkey":            {[]string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, []string{"short", "AAAA"}},
		"fqdn_or_wildcard": {[]string{"example.com", "*.example.com", "a-b.example"}, []string{"", "*.", "a..b", "-x.com", "ex*mple.com"}},
		"cidr_or_ip":       {[]string{"10.0.0.1", "10.0.0.0/8", "2001:db8::/32", "::1"}, []string{"10.0.0", "10.0.0.0/33", "host"}},
		"duration":         {[]string{"30s", "5m", "1h30m"}, []string{"0s", "-1s", "5", "soon"}},
		"scope":            {[]string{"global", "site:" + idA, "node:" + idA}, []string{"", "site:", "site:x", "rack:" + idA}},
		"hostport":         {[]string{"example.com:443", "10.0.0.2:80", "[2001:db8::1]:8080", "backend-1:9000"}, []string{"", "example.com", "10.0.0.2", "2001:db8::1:80", "[10.0.0.2]:80", "host:0", "host:70000", "*.x.com:80"}},
		"ospfarea":         {[]string{"0", "0.0.0.0", "51"}, []string{"backbone", "::1", "-1"}},
		"permission":       {[]string{"firewall:write", "*:read"}, []string{"firewall", "firewall:admin", "Fire:read"}},
		"ratelimit":        {[]string{"10/second", "1/day"}, []string{"0/second", "10/fortnight", "ten/second"}},
		"community":        {[]string{"65000:100", "65000:1:2", "no-export"}, []string{"65000", "a:b"}},
		"ifname":           {[]string{"eth0", "wg0", "br-lan.10"}, []string{"", "averyveryverylongname", "bad name"}},
		"objname":          {[]string{"a", "web-servers_1.x"}, []string{"", "-a", "a b", strings.Repeat("a", 64)}},
	}
	for name, rule := range CustomRules {
		c, ok := cases[name]
		if !ok {
			t.Errorf("custom rule %q has no test cases", name)
			continue
		}
		for _, s := range c.good {
			if !rule.check(s) {
				t.Errorf("%s rejects %q", name, s)
			}
		}
		for _, s := range c.bad {
			if rule.check(s) {
				t.Errorf("%s accepts %q", name, s)
			}
		}
		if rule.Pattern != "" {
			re := regexp.MustCompile(rule.Pattern)
			for _, s := range c.good {
				if !re.MatchString(s) {
					t.Errorf("%s: schema pattern rejects valid %q", name, s)
				}
			}
		}
	}
}

func TestRefWireFormatAndRoundTrip(t *testing.T) {
	r := &FilterRule{Meta: Meta{ID: idA, Name: "allow-web", Scope: ScopeGlobal}, Action: "accept",
		Direction: "forward", Protocol: "tcp", SourceZone: Ref[Zone]{ID: idB},
		Source: []Ref[Alias]{{ID: idC}}, Ports: []string{"443"}}

	js, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(js, &doc)
	if doc["source_zone"] != idB || !reflect.DeepEqual(doc["source"], []any{idC}) {
		t.Errorf("references are not plain UUID strings: %s", js)
	}
	if _, present := doc["destination_zone"]; present {
		t.Errorf("empty reference was not omitted: %s", js)
	}
	back, err := Decode(KindFilterRule, js)
	if err != nil || !reflect.DeepEqual(back, r) {
		t.Errorf("json round trip: err=%v\n got %+v\nwant %+v", err, back, r)
	}

	ys, err := yaml.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ys), "destination_zone") || !strings.Contains(string(ys), "source_zone: "+idB) {
		t.Errorf("yaml form:\n%s", ys)
	}
	var fromYAML FilterRule
	if err := yaml.Unmarshal(ys, &fromYAML); err != nil || !reflect.DeepEqual(&fromYAML, r) {
		t.Errorf("yaml round trip: err=%v\n got %+v\nwant %+v", err, &fromYAML, r)
	}

	if _, err := Decode(KindFilterRule, []byte(`{"id":"`+idA+`","nmae":"typo"}`)); err == nil {
		t.Error("unknown field was accepted")
	}
}

func TestRefs(t *testing.T) {
	r := &FilterRule{Meta: Meta{ID: idA, Name: "r", Scope: SiteScope(idB)},
		SourceZone: Ref[Zone]{ID: idC}, Source: []Ref[Alias]{{ID: idA}, {ID: idB}}}
	got := Refs(r)
	want := []RefUse{
		{Field: "source_zone", Target: KindZone, ID: idC},
		{Field: "source[0]", Target: KindAlias, ID: idA},
		{Field: "source[1]", Target: KindAlias, ID: idB},
		{Field: "scope", Target: KindSite, ID: idB},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Refs = %+v\nwant   %+v", got, want)
	}

	pool := &LBBackendPool{Backends: []LBBackend{{Site: Ref[Site]{ID: idC}}}}
	if got := Refs(pool); len(got) != 1 || got[0].Field != "backends[0].site" || got[0].Target != KindSite {
		t.Errorf("nested Refs = %+v", got)
	}
}

func TestMaskAndKeepSecrets(t *testing.T) {
	n := &BGPNeighbor{Meta: Meta{ID: idA, Name: "peer"}, SessionSecret: "hunter2"}
	masked := Mask(n).(*BGPNeighbor)
	if masked.SessionSecret != SecretMask || n.SessionSecret != "hunter2" {
		t.Fatalf("Mask: masked=%q original=%q", masked.SessionSecret, n.SessionSecret)
	}
	if js, _ := json.Marshal(masked); strings.Contains(string(js), "hunter2") {
		t.Fatalf("secret leaked: %s", js)
	}
	// A client sends the masked object back with another field changed.
	masked.Address = "192.0.2.1"
	KeepMaskedSecrets(masked, n)
	if masked.SessionSecret != "hunter2" {
		t.Errorf("masked secret was not restored: %q", masked.SessionSecret)
	}
	// An explicit new value wins; an empty one stays empty when masked.
	masked.SessionSecret = "new"
	KeepMaskedSecrets(masked, n)
	if masked.SessionSecret != "new" {
		t.Errorf("new secret overwritten: %q", masked.SessionSecret)
	}
	if Mask(&BGPNeighbor{}).(*BGPNeighbor).SessionSecret != "" {
		t.Error("empty secret was masked")
	}
}

func TestEffectiveOverrides(t *testing.T) {
	a := validAlias()
	a.Overrides = []Override{
		{Scope: SiteScope(idB), Values: map[string]any{"entries": []any{"198.51.100.1"}, "description": "site"}},
		{Scope: NodeScope(idC), Values: map[string]any{"description": "node"}},
	}
	if err := Validate(a); err != nil {
		t.Fatalf("alias with overrides rejected: %v", err)
	}

	eff, origins, err := Effective(a, idB, idC)
	if err != nil {
		t.Fatal(err)
	}
	got := eff.(*Alias)
	if !slices.Equal(got.Entries, []string{"198.51.100.1"}) || got.Description != "node" {
		t.Errorf("effective = %+v", got)
	}
	if origins["entries"] != SiteScope(idB) || origins["description"] != NodeScope(idC) || len(origins) != 2 {
		t.Errorf("origins = %v", origins)
	}

	// Another site sees the base value and no origins.
	eff, origins, _ = Effective(a, idA, idA)
	if !slices.Equal(eff.(*Alias).Entries, []string{"192.0.2.10"}) || len(origins) != 0 {
		t.Errorf("other site: %+v %v", eff, origins)
	}

	a.Overrides[0].Values["name"] = "renamed"
	if got := fieldRules(t, Validate(a)); got["overrides[0].values.name"] != "override_protected" {
		t.Errorf("protected override not rejected: %v", got)
	}
	if _, _, err := Effective(a, idB, idC); err == nil {
		t.Error("Effective applied a protected override")
	}

	a.Overrides = []Override{{Scope: SiteScope(idB), Values: map[string]any{"entries": "not-a-list"}}}
	if _, _, err := Effective(a, idB, idC); err == nil {
		t.Error("override with the wrong type was accepted")
	}
}

func TestAppliesTo(t *testing.T) {
	a := validAlias()
	for scope, want := range map[Scope]bool{ScopeGlobal: true, SiteScope(idB): true, SiteScope(idA): false,
		NodeScope(idC): true, NodeScope(idA): false} {
		a.Scope = scope
		if got := AppliesTo(a, idB, idC); got != want {
			t.Errorf("AppliesTo(%s) = %v, want %v", scope, got, want)
		}
	}
}
