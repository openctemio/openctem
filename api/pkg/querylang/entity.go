package querylang

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// Entity is one queryable entity: its filterspec registry (the only
// allowlist of fields, operators and SQL), its read permission, the paths
// the language accepts, what the pipeline may group, aggregate and bucket
// by, and the filters the server always adds.
type Entity struct {
	// Name is the entity word of the language ("findings").
	Name string
	// Noun is the plural noun used in explanations.
	Noun string
	// Permission is needed to query the entity at all.
	Permission string
	// Registry is the filterspec allowlist. Its tenant predicate, data
	// scope column and member visibility rule apply to every query.
	Registry *filterspec.Registry

	// paths maps a language path to a registry field ("asset.type" ->
	// "asset_type"); a registry field without an entry is its own path.
	paths map[string]string
	// internal are registry fields only the server's mandatory filters may
	// use; to a query they are unknown.
	internal map[string]bool
	// dims are the group-by paths, measures the numeric aggregate paths,
	// times the bucket paths. Each names a registry field (for its
	// permission) and is rendered by the executor's own binding.
	dims     map[string]string
	measures map[string]string
	times    map[string]string
	// text is the internal contains-field behind `text ~ "..."`.
	text string
	// mandatory are leaves ANDed to every query (exclusions the language
	// cannot override), with a plain description each.
	mandatory []Mandatory
}

// Mandatory is a server-side filter of an entity.
type Mandatory struct {
	Leaf *filterspec.Leaf
	// Why is the plain description shown in Explain.
	Why string
}

// EntityDef declares an entity (see Entity).
type EntityDef struct {
	Name, Noun, Permission string
	Registry               *filterspec.Registry
	Paths                  map[string]string
	Internal               []string
	Dimensions             []string
	Measures               []string
	Times                  []string
	Mandatory              []Mandatory
	// TextField is the internal registry field (a contains template over
	// the entity's search columns) that `text ~ "..."` compiles to; empty
	// when the entity has no text search.
	TextField string
}

// NewEntity validates a declaration: every path, dimension, measure and
// time names a registry field of the right type, and mandatory leaves
// compile. An invalid entity is a programming error.
func NewEntity(d EntityDef) (*Entity, error) {
	if d.Name == "" || d.Permission == "" || d.Registry == nil {
		return nil, fmt.Errorf("querylang: entity needs Name, Permission and Registry")
	}
	e := &Entity{Name: d.Name, Noun: d.Noun, Permission: d.Permission, Registry: d.Registry,
		paths: map[string]string{}, internal: map[string]bool{},
		dims: map[string]string{}, measures: map[string]string{}, times: map[string]string{},
		mandatory: d.Mandatory, text: d.TextField}
	if err := e.declareFields(d); err != nil {
		return nil, err
	}
	add := func(kind string, dst map[string]string, list []string, ok func(*filterspec.Field) bool) error {
		for _, p := range list {
			f := e.fieldName(p)
			fd, found := d.Registry.Field(f)
			if !found || e.internal[f] || !ok(fd) {
				return fmt.Errorf("querylang: %s: %s %q is not a suitable registry field", d.Name, kind, p)
			}
			dst[p] = f
		}
		return nil
	}
	if err := add("dimension", e.dims, d.Dimensions, func(f *filterspec.Field) bool {
		return f.Type == filterspec.TypeEnum || f.Type == filterspec.TypeString || f.Type == filterspec.TypeBool || f.Type == filterspec.TypeID
	}); err != nil {
		return nil, err
	}
	if err := add("measure", e.measures, d.Measures, func(f *filterspec.Field) bool {
		return f.Type == filterspec.TypeInt || f.Type == filterspec.TypeNumber
	}); err != nil {
		return nil, err
	}
	if err := add("time", e.times, d.Times, func(f *filterspec.Field) bool { return f.Type == filterspec.TypeTime }); err != nil {
		return nil, err
	}
	for _, m := range d.Mandatory {
		if m.Leaf == nil || m.Why == "" {
			return nil, fmt.Errorf("querylang: %s: mandatory filter needs a leaf and a description", d.Name)
		}
		if _, ok := d.Registry.Field(m.Leaf.Field); !ok {
			return nil, fmt.Errorf("querylang: %s: mandatory filter on unknown field %q", d.Name, m.Leaf.Field)
		}
	}
	// The mandatory leaves must compile for the most and the least
	// privileged caller alike.
	spec := &filterspec.Spec{Root: e.mandatoryNode()}
	checker, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: shared.MustIDFromString(checkTenant)})
	if err != nil {
		return nil, err
	}
	if _, err := filterspec.Compile(spec, d.Registry, checker); err != nil {
		return nil, fmt.Errorf("querylang: %s: mandatory filters do not compile: %w", d.Name, err)
	}
	return e, nil
}

// declareFields records the internal fields, the text field and the
// relation paths, checking each against the registry.
func (e *Entity) declareFields(d EntityDef) error {
	for _, n := range d.Internal {
		if _, ok := d.Registry.Field(n); !ok {
			return fmt.Errorf("querylang: %s: internal field %q not in the registry", d.Name, n)
		}
		e.internal[n] = true
	}
	if d.TextField != "" {
		f, ok := d.Registry.Field(d.TextField)
		if !ok || !e.internal[d.TextField] || f.Type != filterspec.TypeString || len(f.Ops) != 1 || f.Ops[0] != filterspec.OpContains {
			return fmt.Errorf("querylang: %s: text field must be an internal contains-only string field", d.Name)
		}
	}
	for p, f := range d.Paths {
		if _, ok := d.Registry.Field(f); !ok || e.internal[f] || !strings.Contains(p, ".") {
			return fmt.Errorf("querylang: %s: path %q must be relation.field over a registry field", d.Name, p)
		}
		e.paths[p] = f
	}
	return nil
}

// checkTenant is a placeholder tenant for compiling the declaration once.
const checkTenant = "00000000-0000-0000-0000-000000000001"

// MustEntity is NewEntity that panics on an invalid declaration.
func MustEntity(d EntityDef) *Entity {
	e, err := NewEntity(d)
	if err != nil {
		panic(err)
	}
	return e
}

// fieldName maps a language path to its registry field name.
func (e *Entity) fieldName(path string) string {
	if f, ok := e.paths[path]; ok {
		return f
	}
	if strings.Contains(path, ".") {
		return ""
	}
	return path
}

// pathOf maps a registry field name back to its language path.
func (e *Entity) pathOf(field string) string {
	for p, f := range e.paths {
		if f == field {
			return p
		}
	}
	return field
}

// field resolves a language path for a caller: the registry field, or
// false when it does not exist, is internal, is the target of a relation
// path (relation fields are named only by their path), or needs a
// permission the caller lacks. The three cases are indistinguishable to
// the caller.
func (e *Entity) field(path string, may func(string) bool) (*filterspec.Field, bool) {
	name := e.fieldName(path)
	if name == "" || e.internal[name] {
		return nil, false
	}
	if !strings.Contains(path, ".") && e.pathOf(name) != name {
		return nil, false
	}
	f, ok := e.Registry.Field(name)
	if !ok || (f.Permission != "" && !may(f.Permission)) {
		return nil, false
	}
	return f, true
}

// Dimension, Measure and Time return the registry field name of a path of
// that kind ("" when the path is not one).
func (e *Entity) Dimension(path string) string { return e.dims[path] }

// Measure returns the registry field of a measure path.
func (e *Entity) Measure(path string) string { return e.measures[path] }

// Time returns the registry field of a time path.
func (e *Entity) Time(path string) string { return e.times[path] }

// Dimensions, Measures and Times list the paths of each kind, sorted.
func (e *Entity) Dimensions() []string { return sortedKeys(e.dims) }

// Measures lists the measure paths.
func (e *Entity) Measures() []string { return sortedKeys(e.measures) }

// Times lists the time paths.
func (e *Entity) Times() []string { return sortedKeys(e.times) }

// MandatoryFilters returns the server-side filters with their descriptions.
func (e *Entity) MandatoryFilters() []Mandatory { return append([]Mandatory(nil), e.mandatory...) }

func (e *Entity) mandatoryNode() *filterspec.Node {
	if len(e.mandatory) == 0 {
		return nil
	}
	kids := make([]*filterspec.Node, 0, len(e.mandatory))
	for _, m := range e.mandatory {
		l := *m.Leaf
		l.Values = append([]any(nil), m.Leaf.Values...)
		kids = append(kids, &filterspec.Node{Leaf: &l})
	}
	return &filterspec.Node{All: kids}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FieldInfo describes one path of an entity for the editor.
type FieldInfo struct {
	Path      string   `json:"path"`
	Type      string   `json:"type"`
	Operators []string `json:"operators"`
	Enum      []string `json:"enum,omitempty"`
	GroupBy   bool     `json:"group_by,omitempty"`
	Aggregate bool     `json:"aggregate,omitempty"`
	Bucket    bool     `json:"bucket,omitempty"`
}

// Schema is what a caller may use in queries on an entity.
type Schema struct {
	Entity     string      `json:"entity"`
	Fields     []FieldInfo `json:"fields"`
	TextSearch bool        `json:"text_search"`
}

// Schema returns the entity's paths the caller may use: fields that need a
// permission the caller lacks and internal fields are left out, exactly as
// Build treats them as unknown.
func (e *Entity) Schema(has func(string) bool) Schema {
	may := func(p string) bool { return has != nil && has(p) }
	s := Schema{Entity: e.Name, TextSearch: e.text != ""}
	for _, f := range e.Registry.Fields() {
		path := e.pathOf(f.Name)
		if _, ok := e.field(path, may); !ok {
			continue
		}
		fi := FieldInfo{Path: path, Type: f.Type.String(), Enum: append([]string(nil), f.Enum...),
			GroupBy: e.dims[path] != "", Aggregate: e.measures[path] != "", Bucket: e.times[path] != ""}
		fi.Operators = textOperators(f)
		s.Fields = append(s.Fields, fi)
	}
	return s
}

// textOperators lists the text operators a field accepts.
func textOperators(f *filterspec.Field) []string {
	has := map[filterspec.Op]bool{}
	for _, o := range f.Ops {
		has[o] = true
	}
	var out []string
	if has[filterspec.OpEq] || has[filterspec.OpIn] {
		out = append(out, "=")
	}
	if has[filterspec.OpNe] || has[filterspec.OpNotIn] || (has[filterspec.OpEq] && f.Type == filterspec.TypeBool) {
		out = append(out, "!=")
	}
	for _, p := range []struct {
		op filterspec.Op
		s  string
	}{{filterspec.OpGt, ">"}, {filterspec.OpGte, ">="}, {filterspec.OpLt, "<"}, {filterspec.OpLte, "<="}} {
		if has[p.op] {
			out = append(out, p.s)
		}
	}
	if has[filterspec.OpGte] && has[filterspec.OpLte] {
		out = append(out, "between")
	}
	if has[filterspec.OpContains] {
		out = append(out, "~")
	}
	if has[filterspec.OpIn] {
		out = append(out, "in")
	}
	if has[filterspec.OpNotIn] {
		out = append(out, "not in")
	}
	if has[filterspec.OpIsNull] {
		out = append(out, "is empty", "is not empty")
	}
	return out
}
