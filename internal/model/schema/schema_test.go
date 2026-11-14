package schema

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

// TestGeneratedFilesAreCurrent fails when a model change was not followed by
// `go generate ./internal/model`.
func TestGeneratedFilesAreCurrent(t *testing.T) {
	for name, c := range map[string]struct {
		gen       func() ([]byte, error)
		committed []byte
	}{
		"openapi.json":      {OpenAPI, OpenAPIJSON},
		"ui.json":           {UI, UIJSON},
		"fingerprints.json": {Fingerprints, FingerprintsJSON},
	} {
		want, err := c.gen()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(want, c.committed) {
			t.Errorf("%s is stale: run `go generate ./internal/model` and commit the result", name)
		}
		again, _ := c.gen()
		if !bytes.Equal(want, again) {
			t.Errorf("%s: generation is not deterministic", name)
		}
	}
}

func TestOpenAPICoversEveryKind(t *testing.T) {
	var doc struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
				Kind       string                    `json:"x-kind"`
			} `json:"schemas"`
		} `json:"components"`
	}
	data, err := OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, info := range model.Kinds() {
		name := reflect.TypeOf(info.New()).Elem().Name()
		s, ok := doc.Components.Schemas[name]
		if !ok || s.Kind != string(info.Kind) {
			t.Errorf("%s: schema missing", name)
			continue
		}
		for _, f := range []string{"id", "name", "version", "scope"} {
			if _, ok := s.Properties[f]; !ok {
				t.Errorf("%s: Meta field %q missing from schema", name, f)
			}
		}
		for _, p := range []string{"", "/{id}", "/{id}/used-by"} {
			if _, ok := doc.Paths["/api/v1/"+info.Plural+p]; !ok {
				t.Errorf("%s: path %s missing", name, p)
			}
		}
	}

	rule := doc.Components.Schemas["FilterRule"]
	if got := rule.Properties["source_zone"]; got["x-ref"] != "zone" || got["format"] != "uuid" {
		t.Errorf("reference schema = %v", got)
	}
	if got := rule.Properties["action"]["enum"]; !reflect.DeepEqual(got, []any{"accept", "drop", "reject"}) {
		t.Errorf("enum = %v", got)
	}
	if got := rule.Properties["ports"]["items"].(map[string]any); got["x-rule"] != "portrange" {
		t.Errorf("list item rule = %v", got)
	}
	if got := doc.Components.Schemas["BGPNeighbor"].Properties["session_secret"]; got["x-secret"] != true {
		t.Errorf("secret schema = %v", got)
	}
	if got := doc.Components.Schemas["Alias"].Properties["version"]; got["readOnly"] != true {
		t.Errorf("version is not read-only: %v", got)
	}
}

func TestUIForms(t *testing.T) {
	var doc struct {
		Forms []Form `json:"forms"`
	}
	data, err := UI()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Forms) != len(model.Kinds()) {
		t.Fatalf("%d forms for %d kinds", len(doc.Forms), len(model.Kinds()))
	}
	for _, form := range doc.Forms {
		last := -1
		for _, f := range form.Fields {
			if f.Order < last {
				t.Errorf("%s: fields are not sorted by order at %q", form.Kind, f.Name)
			}
			last = f.Order
			if f.Label == "" || f.Type == "" {
				t.Errorf("%s.%s: incomplete field %+v", form.Kind, f.Name, f)
			}
			if f.Type == "ref" && f.Ref == "" {
				t.Errorf("%s.%s: reference without a target", form.Kind, f.Name)
			}
		}
		if form.Kind == "lb_backend_pool" {
			for _, f := range form.Fields {
				if f.Name == "backends" && (!f.List || len(f.Fields) == 0) {
					t.Errorf("nested table field has no sub-fields: %+v", f)
				}
			}
		}
	}
}

func TestParseUITag(t *testing.T) {
	got, err := ParseUITag("label=Source,widget=ref-picker,ref=alias,group=Match,order=70,help=Who sends")
	want := UITag{Label: "Source", Widget: "ref-picker", Ref: "alias", Group: "Match", Order: 70, Help: "Who sends"}
	if err != nil || got != want {
		t.Errorf("got %+v, %v", got, err)
	}
	for _, bad := range []string{"", "order=1", "label=x,colour=red", "label=x,order=first", "label"} {
		if _, err := ParseUITag(bad); err == nil {
			t.Errorf("ParseUITag(%q) accepted", bad)
		}
	}
}

func TestUnknownValidateRuleIsAnError(t *testing.T) {
	_, err := applyRules(map[string]any{}, []rule{{name: "iscolor"}}, reflect.TypeOf(""))
	if err == nil || !strings.Contains(err.Error(), "iscolor") {
		t.Errorf("unknown rule: err = %v", err)
	}
}

// TestReleasedSchemaIsFrozen fails when the wire format of a released schema
// version changes. The fix is to bump model.SchemaVersion and register a
// migration in internal/confstore, not to edit released.json.
func TestReleasedSchemaIsFrozen(t *testing.T) {
	var released map[string]map[string]string
	if err := json.Unmarshal(ReleasedJSON, &released); err != nil {
		t.Fatalf("released.json: %v", err)
	}
	var current struct {
		Version int               `json:"schema_version"`
		Kinds   map[string]string `json:"kinds"`
	}
	data, err := Fingerprints()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &current); err != nil {
		t.Fatal(err)
	}
	frozen, ok := released[strconv.Itoa(current.Version)]
	if !ok {
		return // the current version has not been released yet
	}
	for kind, want := range frozen {
		if got := current.Kinds[kind]; got != want {
			t.Errorf("%s: wire format changed in released schema version %d; bump model.SchemaVersion and add a migration", kind, current.Version)
		}
	}
}

func TestFingerprintIgnoresLabelsButSeesFields(t *testing.T) {
	a := map[string]any{"type": "object", "title": "A", "properties": map[string]any{"x": map[string]any{"type": "string", "description": "d"}}}
	b := map[string]any{"type": "object", "title": "B", "properties": map[string]any{"x": map[string]any{"type": "string"}}}
	c := map[string]any{"type": "object", "properties": map[string]any{"y": map[string]any{"type": "string"}}}
	ja, _ := json.Marshal(stripPresentation(a))
	jb, _ := json.Marshal(stripPresentation(b))
	jc, _ := json.Marshal(stripPresentation(c))
	if string(ja) != string(jb) || string(ja) == string(jc) {
		t.Errorf("a=%s b=%s c=%s", ja, jb, jc)
	}
}
