// Package model is the single source of truth for everything the appliance
// can be configured to do. Every entity is a struct whose tags drive the wire
// format (json/yaml), validation (validate), the generated UI forms and
// OpenAPI schema (ui) and masking of secrets (secret).
//
// Nothing here talks to the kernel or to a daemon. Renderers elsewhere turn a
// consistent set of these objects into nftables, FRR, WireGuard and proxy
// configuration.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

//go:generate go run ./gen

// SchemaVersion is the version of the wire format of the entities. Bump it
// together with a migration registered in internal/confstore whenever a
// change is not purely additive (a field renamed, removed or reinterpreted).
const SchemaVersion = 1

// Kind names an entity type on the wire, in URLs and in references.
type Kind string

// Scope says where an object applies: everywhere, at one site or on one node.
// The wire form is "global", "site:<uuid>" or "node:<uuid>".
type Scope string

const ScopeGlobal Scope = "global"

// SiteScope returns the scope of one site.
func SiteScope(id string) Scope { return Scope("site:" + id) }

// NodeScope returns the scope of one node.
func NodeScope(id string) Scope { return Scope("node:" + id) }

// Level is "global", "site" or "node"; Target is the site or node UUID (empty
// for global).
func (s Scope) Level() string {
	if s == "" || s == ScopeGlobal {
		return "global"
	}
	level, _, _ := strings.Cut(string(s), ":")
	return level
}

func (s Scope) Target() string {
	_, id, _ := strings.Cut(string(s), ":")
	return id
}

// Override replaces top-level fields of an object for one site or node.
type Override struct {
	Scope  Scope          `json:"scope" yaml:"scope" validate:"required,scope,ne=global" ui:"label=Applies to,widget=scope-picker,order=1"`
	Values map[string]any `json:"values" yaml:"values" validate:"required,min=1" ui:"label=Values,widget=override-editor,order=2"`
}

// Meta is embedded in every entity.
type Meta struct {
	ID          string            `json:"id" yaml:"id" validate:"required,uuid4" ui:"label=ID,widget=readonly,group=Meta,order=900"`
	Name        string            `json:"name" yaml:"name" validate:"required,objname" ui:"label=Name,order=1,help=Unique per type; letters digits dot dash underscore"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty" validate:"max=512" ui:"label=Description,widget=textarea,order=2"`
	Version     int64             `json:"version" yaml:"version" validate:"min=0" ui:"label=Version,widget=readonly,group=Meta,order=901"`
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at" validate:"-" ui:"label=Created,widget=readonly,group=Meta,order=902"`
	CreatedBy   string            `json:"created_by,omitempty" yaml:"created_by,omitempty" validate:"-" ui:"label=Created by,widget=readonly,group=Meta,order=903"`
	UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at" validate:"-" ui:"label=Updated,widget=readonly,group=Meta,order=904"`
	UpdatedBy   string            `json:"updated_by,omitempty" yaml:"updated_by,omitempty" validate:"-" ui:"label=Updated by,widget=readonly,group=Meta,order=905"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty" validate:"max=32,dive,keys,objname,endkeys,max=128" ui:"label=Labels,widget=key-value,group=Meta,order=906"`
	Scope       Scope             `json:"scope" yaml:"scope" validate:"required,scope" ui:"label=Scope,widget=scope-picker,group=Scope,order=800,help=global or one site or one node"`
	Overrides   []Override        `json:"overrides,omitempty" yaml:"overrides,omitempty" validate:"dive" ui:"label=Overrides,widget=override-list,group=Scope,order=801"`
}

// GetMeta gives generic code access to the embedded Meta.
func (m *Meta) GetMeta() *Meta { return m }

// Entity is implemented by a pointer to every model struct.
type Entity interface {
	Kind() Kind
	GetMeta() *Meta
}

// kinded is the constraint for reference targets: the struct type itself.
type kinded interface{ Kind() Kind }

// Ref is a typed reference to another object. It is stored by UUID, never by
// name, so renaming the target never breaks the referrer.
type Ref[T kinded] struct{ ID string }

// AnyRef is the non-generic view of a Ref, used by the reference index.
type AnyRef interface {
	TargetKind() Kind
	TargetID() string
}

func (r Ref[T]) TargetKind() Kind { var z T; return z.Kind() }
func (r Ref[T]) TargetID() string { return r.ID }
func (r Ref[T]) IsZero() bool     { return r.ID == "" }

func (r Ref[T]) MarshalJSON() ([]byte, error) { return json.Marshal(r.ID) }
func (r *Ref[T]) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		r.ID = ""
		return nil
	}
	return json.Unmarshal(b, &r.ID)
}
func (r Ref[T]) MarshalYAML() (any, error) { return r.ID, nil }
func (r *Ref[T]) UnmarshalYAML(unmarshal func(any) error) error {
	return unmarshal(&r.ID)
}

// KindInfo describes an entity type to the generators and the API.
type KindInfo struct {
	Kind   Kind
	Plural string // URL segment, e.g. "filter-rules"
	Title  string
	Menu   string // UI location, e.g. "firewall/rules"
	// Scopes lists the levels an object of this kind may have.
	Scopes []string
	New    func() Entity
}

var (
	allLevels = []string{"global", "site", "node"}
	nodeOnly  = []string{"node"}
	globalOny = []string{"global"}
)

var registry []KindInfo

func register(plural, title, menu string, scopes []string, mk func() Entity) {
	registry = append(registry, KindInfo{
		Kind: mk().Kind(), Plural: plural, Title: title, Menu: menu, Scopes: scopes, New: mk,
	})
}

// Kinds returns every registered entity type in registration order.
func Kinds() []KindInfo { return append([]KindInfo(nil), registry...) }

// Lookup finds a kind by its name or its plural URL segment.
func Lookup(name string) (KindInfo, bool) {
	for _, k := range registry {
		if string(k.Kind) == name || k.Plural == name {
			return k, true
		}
	}
	return KindInfo{}, false
}

// Decode parses the JSON form of one object of the given kind. Unknown
// fields are rejected so a typo never silently drops configuration.
func Decode(kind Kind, data []byte) (Entity, error) {
	info, ok := Lookup(string(kind))
	if !ok {
		return nil, fmt.Errorf("model: unknown kind %q", kind)
	}
	e := info.New()
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(e); err != nil {
		return nil, fmt.Errorf("model: decode %s: %w", kind, err)
	}
	return e, nil
}

// Clone returns a deep copy.
func Clone(e Entity) Entity {
	b, err := json.Marshal(e)
	if err != nil {
		panic(fmt.Sprintf("model: clone %s: %v", e.Kind(), err))
	}
	c, err := Decode(e.Kind(), b)
	if err != nil {
		panic(fmt.Sprintf("model: clone %s: %v", e.Kind(), err))
	}
	return c
}
