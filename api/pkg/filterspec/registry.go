// Package filterspec is the one filter model for list, stats, groups, search
// and export endpoints: a per-resource field registry, two decoders (flat
// query params and a JSON FilterDocument) that produce one AST, and a
// compiler that turns the AST into parameterised SQL with the tenant and
// data-scope predicates always included.
//
// Design, threat model and owner decisions: docs/rfcs/RFC-048-list-query-contract.md.
// How to add a field: docs/architecture/list-query-contract.md.
//
// Security properties the package guarantees (each has a test):
//
//   - Field names, operators and sort keys come only from the registry. The
//     SQL for a leaf is the registry's constant template; request values are
//     always bound parameters and never appear in the SQL text.
//   - Compile cannot run without an Actor. Every compiled WHERE starts with
//     the tenant predicate; a restricted actor also gets the data-scope
//     predicate. Only SystemActor skips the scope predicate, never the tenant.
//   - A field that needs a permission the actor lacks is reported as an
//     unknown field, so the error does not reveal that it exists.
//   - Hard limits on leaves, depth, list sizes, value lengths and body size.
package filterspec

import (
	"fmt"
	"regexp"
	"strings"
)

// Type is the value type of a field.
type Type int

const (
	// TypeEnum is a string from a fixed set (Field.Enum).
	TypeEnum Type = iota + 1
	// TypeString is a free string compared exactly (rule ids, tool names).
	TypeString
	// TypeID is a UUID.
	TypeID
	// TypeInt is a 64-bit integer.
	TypeInt
	// TypeNumber is a finite float.
	TypeNumber
	// TypeBool is true or false.
	TypeBool
	// TypeTime is an instant (RFC 3339, a date, or a negative ISO 8601
	// duration relative to now).
	TypeTime
)

func (t Type) String() string {
	switch t {
	case TypeEnum:
		return "enum"
	case TypeString:
		return "string"
	case TypeID:
		return "id"
	case TypeInt:
		return "integer"
	case TypeNumber:
		return "number"
	case TypeBool:
		return "boolean"
	case TypeTime:
		return "date-time"
	}
	return "unknown"
}

// Op is a filter operator.
type Op string

// Operators. The GET suffix of each is in suffixOps.
const (
	OpEq       Op = "eq"
	OpNe       Op = "ne"
	OpIn       Op = "in"
	OpNotIn    Op = "not_in"
	OpGte      Op = "gte"
	OpGt       Op = "gt"
	OpLte      Op = "lte"
	OpLt       Op = "lt"
	OpIsNull   Op = "is_null"
	OpContains Op = "contains"
)

// suffixOps maps a GET param suffix to its operator. The order is the
// matching order: longer suffixes first, so "_gte" is never read as "_gt".
var suffixOps = []struct {
	suffix string
	op     Op
}{
	{"_contains", OpContains},
	{"_null", OpIsNull},
	{"_not", OpNotIn},
	{"_gte", OpGte},
	{"_lte", OpLte},
	{"_gt", OpGt},
	{"_lt", OpLt},
}

// Template tokens. Compile replaces every occurrence of a token with the
// same bound placeholder:
//   - ArgToken: the leaf's value (or array of values);
//   - TenantToken: the actor's tenant;
//   - UserToken: the acting user (::uuid), for user-relative fields and the
//     member visibility rule.
const (
	ArgToken    = "{arg}"
	TenantToken = "{tenant}"
	UserToken   = "{user}"
)

// Limits (RFC-048 §3.7).
const (
	MaxLeaves         = 50
	MaxDepth          = 3
	MaxValues         = 100
	MaxValuesDocument = 500
	MaxValueLen       = 200
	MaxQLen           = 255
	MaxBodyBytes      = 32 << 10
	MaxSortKeys       = 5
	MaxErrorDetails   = 20
	DefaultMaxOffset  = 10000
)

// Field is one filterable (and optionally sortable) field of a resource.
type Field struct {
	// Name is the param and document name: singular snake_case, equal to the
	// response JSON field. It must not end in an operator suffix.
	Name string
	Type Type
	// Ops are the operators the field accepts.
	Ops []Op
	// SQL is the constant column or expression the default templates compare
	// against, for example "f.severity". Never built from input.
	SQL string
	// Templates override the SQL of an operator. Each must contain ArgToken
	// (except OpIsNull, which takes none: the template is the "is null"
	// predicate and its negation is generated). A template that reads another
	// table must carry its own tenant predicate.
	Templates map[Op]string
	// BoolTemplate, for a TypeBool field with OpEq, is the constant predicate
	// for "true"; "false" compiles to its negation (a NULL counts as false).
	// It binds no value, so a partial index on the predicate can serve it.
	BoolTemplate string
	// Enum is the allowed set for TypeEnum.
	Enum []string
	// Nullable makes not-in and ne also match NULL, and allows OpIsNull.
	Nullable bool
	// Indexed records that an index backs range and in filters on large
	// tables. A registry test checks it against the database.
	Indexed bool
	// Permission, when set, is required to filter or sort by the field.
	Permission string
	// Sortable allows the field in sort; SortSQL overrides SQL for ordering.
	Sortable bool
	SortSQL  string
	// MaxValues caps an in/not_in list in GET (default MaxValues).
	// MaxValuesDocument caps it in a FilterDocument (default MaxValues; at
	// most MaxValuesDocument).
	MaxValues         int
	MaxValuesDocument int
	// FreeText marks a value that is user free text (contains): never
	// echoed in errors and never split on commas.
	FreeText bool
}

func (f *Field) allows(op Op) bool {
	for _, o := range f.Ops {
		if o == op {
			return true
		}
	}
	return false
}

// Alias maps a deprecated param name to its replacement.
type Alias struct {
	// To is the canonical flat param name ("status_not", "epss_score_gte").
	To string
	// Value optionally rewrites the value ("assigned_to_me=true" →
	// "related_to=me"). Returning ok=false drops the param (for example
	// "assigned_to_me=false", which meant "no filter").
	Value func(v string) (string, bool)
}

// Search is the resource's full-text predicate for q.
type Search struct {
	// Template contains ArgToken one or more times.
	Template string
	// Pattern binds the value as an ILIKE pattern %value% with LIKE
	// metacharacters escaped (use ESCAPE '\' in the template).
	Pattern bool
}

// Registry is the allowlist of one resource.
type Registry struct {
	// Name is the resource name, used in errors and metrics ("findings").
	Name string
	// TenantSQL is the tenant column of the main table, e.g. "f.tenant_id".
	TenantSQL string
	// ScopeAssetSQL is the asset column the data scope applies to, e.g.
	// "f.asset_id". Empty only with Unscoped set.
	ScopeAssetSQL string
	// Unscoped explains why the resource has no data scope (tenant
	// configuration). It must be set when ScopeAssetSQL is empty.
	Unscoped string
	// IDSQL is the primary key, the final sort tiebreaker.
	IDSQL string
	// MemberVisibility is a constant predicate ANDed for every request caller
	// that is not an administrator (never for SystemActor), on top of the data
	// scope: for findings, "pentest findings only for campaign members". It may
	// use TenantToken and UserToken.
	MemberVisibility string
	// DefaultSort applies when the request names no sort.
	DefaultSort []SortKey
	Search      *Search
	Aliases     map[string]Alias

	fields map[string]*Field
	order  []string
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}[a-z0-9]$`)

// reserved are the params every list endpoint reads outside the filter.
var reserved = map[string]bool{
	"q": true, "sort": true, "page": true, "per_page": true, "cursor": true,
	"fields": true, "view": true,
}

// NewRegistry validates and builds a registry. An invalid registry is a
// programming error; MustRegistry panics on it at init.
func NewRegistry(r Registry, fields ...Field) (*Registry, error) {
	if r.Name == "" || r.TenantSQL == "" || r.IDSQL == "" {
		return nil, fmt.Errorf("filterspec: registry needs Name, TenantSQL and IDSQL")
	}
	if r.ScopeAssetSQL == "" && strings.TrimSpace(r.Unscoped) == "" {
		return nil, fmt.Errorf("filterspec: registry %s: ScopeAssetSQL is required unless Unscoped explains why", r.Name)
	}
	if r.Search != nil && !strings.Contains(r.Search.Template, ArgToken) {
		return nil, fmt.Errorf("filterspec: registry %s: search template has no %s", r.Name, ArgToken)
	}
	r.fields = make(map[string]*Field, len(fields))
	for i := range fields {
		f := fields[i]
		if err := validateField(&f); err != nil {
			return nil, fmt.Errorf("filterspec: registry %s: %w", r.Name, err)
		}
		if _, dup := r.fields[f.Name]; dup {
			return nil, fmt.Errorf("filterspec: registry %s: duplicate field %q", r.Name, f.Name)
		}
		r.fields[f.Name] = &f
		r.order = append(r.order, f.Name)
	}
	for _, k := range r.DefaultSort {
		f, ok := r.fields[k.Field]
		if !ok || !f.Sortable {
			return nil, fmt.Errorf("filterspec: registry %s: default sort %q is not a sortable field", r.Name, k.Field)
		}
	}
	for old, a := range r.Aliases {
		if _, clash := r.fields[old]; clash || reserved[old] {
			return nil, fmt.Errorf("filterspec: registry %s: alias %q shadows a field or reserved param", r.Name, old)
		}
		if !reserved[a.To] {
			if _, _, err := r.resolveParam(a.To); err != nil {
				return nil, fmt.Errorf("filterspec: registry %s: alias %q targets unknown param %q", r.Name, old, a.To)
			}
		}
	}
	return &r, nil
}

// MustRegistry is NewRegistry that panics on an invalid registry.
func MustRegistry(r Registry, fields ...Field) *Registry {
	reg, err := NewRegistry(r, fields...)
	if err != nil {
		panic(err)
	}
	return reg
}

func validateField(f *Field) error {
	if !nameRE.MatchString(f.Name) {
		return fmt.Errorf("field %q: name must be snake_case", f.Name)
	}
	if reserved[f.Name] || f.Name == "filter" || f.Name == "filters" {
		return fmt.Errorf("field %q: reserved name", f.Name)
	}
	for _, s := range suffixOps {
		if strings.HasSuffix(f.Name, s.suffix) {
			return fmt.Errorf("field %q: name ends in operator suffix %q", f.Name, s.suffix)
		}
	}
	if f.SQL == "" {
		return fmt.Errorf("field %q: SQL is required", f.Name)
	}
	if len(f.Ops) == 0 && !f.Sortable {
		return fmt.Errorf("field %q: no operators and not sortable", f.Name)
	}
	if f.Type == TypeEnum && len(f.Enum) == 0 {
		return fmt.Errorf("field %q: enum field without Enum", f.Name)
	}
	if f.MaxValues <= 0 {
		f.MaxValues = MaxValues
	}
	if f.MaxValues > MaxValues {
		return fmt.Errorf("field %q: MaxValues above %d", f.Name, MaxValues)
	}
	if f.MaxValuesDocument <= 0 {
		f.MaxValuesDocument = f.MaxValues
	}
	if f.MaxValuesDocument > MaxValuesDocument {
		return fmt.Errorf("field %q: MaxValuesDocument above %d", f.Name, MaxValuesDocument)
	}
	for _, op := range f.Ops {
		if err := opFitsType(op, f); err != nil {
			return fmt.Errorf("field %q: %w", f.Name, err)
		}
	}
	return validateTemplates(f)
}

// validateTemplates checks a field's SQL templates and BoolTemplate.
func validateTemplates(f *Field) error {
	if f.BoolTemplate != "" {
		if f.Type != TypeBool || !f.allows(OpEq) || strings.Contains(f.BoolTemplate, ArgToken) || f.Templates[OpEq] != "" {
			return fmt.Errorf("field %q: BoolTemplate needs a boolean eq field, no %s and no eq template", f.Name, ArgToken)
		}
	}
	for op, tpl := range f.Templates {
		if !f.allows(op) {
			return fmt.Errorf("field %q: template for operator %s it does not allow", f.Name, op)
		}
		has := strings.Contains(tpl, ArgToken)
		if op == OpIsNull && has {
			return fmt.Errorf("field %q: is_null template must not bind a value", f.Name)
		}
		if op != OpIsNull && !has && !(strings.Contains(tpl, UserToken) && f.Type == TypeEnum && len(f.Enum) == 1) {
			// Only a one-value enum ("related_to=me") may ignore its value.
			return fmt.Errorf("field %q: template for %s has no %s", f.Name, op, ArgToken)
		}
	}
	return nil
}

func opFitsType(op Op, f *Field) error {
	switch op {
	case OpEq, OpIn:
		return nil
	case OpNe, OpNotIn:
		if f.Type == TypeBool {
			return fmt.Errorf("operator %s on a boolean (use eq)", op)
		}
	case OpGte, OpGt, OpLte, OpLt:
		if f.Type != TypeInt && f.Type != TypeNumber && f.Type != TypeTime {
			return fmt.Errorf("range operator %s on a %s", op, f.Type)
		}
	case OpIsNull:
		if !f.Nullable {
			return fmt.Errorf("is_null on a non-nullable field")
		}
	case OpContains:
		if f.Type != TypeString {
			return fmt.Errorf("contains on a %s", f.Type)
		}
		f.FreeText = true
	default:
		return fmt.Errorf("unknown operator %q", op)
	}
	return nil
}

// Rebase returns a copy of the registry whose SQL qualifies columns with
// alias instead of table ("findings." becomes "f."), for queries that read
// the same table under an alias. Only whole-word qualifiers are replaced.
func (r *Registry) Rebase(table, alias string) *Registry {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(table) + `\.`)
	sub := func(s string) string { return re.ReplaceAllString(s, alias+".") }
	cp := *r
	cp.TenantSQL, cp.ScopeAssetSQL, cp.IDSQL = sub(r.TenantSQL), sub(r.ScopeAssetSQL), sub(r.IDSQL)
	cp.MemberVisibility = sub(r.MemberVisibility)
	if r.Search != nil {
		srch := *r.Search
		srch.Template = sub(srch.Template)
		cp.Search = &srch
	}
	cp.fields = make(map[string]*Field, len(r.fields))
	for name, f := range r.fields {
		nf := *f
		nf.SQL, nf.SortSQL, nf.BoolTemplate = sub(f.SQL), sub(f.SortSQL), sub(f.BoolTemplate)
		if f.Templates != nil {
			nf.Templates = make(map[Op]string, len(f.Templates))
			for op, tpl := range f.Templates {
				nf.Templates[op] = sub(tpl)
			}
		}
		cp.fields[name] = &nf
	}
	cp.order = append([]string(nil), r.order...)
	return &cp
}

// Field returns a field by name.
func (r *Registry) Field(name string) (*Field, bool) {
	f, ok := r.fields[name]
	return f, ok
}

// Fields returns the fields in declaration order.
func (r *Registry) Fields() []*Field {
	out := make([]*Field, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.fields[n])
	}
	return out
}

// Params returns every flat param name the registry accepts: each field
// with each of its operators' suffixes, the reserved params and the aliases.
// It is the source for the OpenAPI drift check.
func (r *Registry) Params() []string {
	out := []string{"q", "sort", "page", "per_page"}
	for _, n := range r.order {
		f := r.fields[n]
		if f.allows(OpIn) || f.allows(OpEq) || f.allows(OpContains) {
			out = append(out, f.Name)
		}
		for _, s := range suffixOps {
			if f.allows(s.op) || (s.op == OpNotIn && f.allows(OpNe)) {
				out = append(out, f.Name+s.suffix)
			}
		}
	}
	for old := range r.Aliases {
		out = append(out, old)
	}
	return out
}

// resolveParam maps a flat param name to its field and operator.
func (r *Registry) resolveParam(name string) (*Field, Op, error) {
	if f, ok := r.fields[name]; ok {
		switch {
		case f.allows(OpIn):
			return f, OpIn, nil
		case f.allows(OpEq):
			return f, OpEq, nil
		case f.allows(OpContains):
			return f, OpContains, nil
		}
		return nil, "", errUnknownParam
	}
	for _, s := range suffixOps {
		base, ok := strings.CutSuffix(name, s.suffix)
		if !ok {
			continue
		}
		f, ok := r.fields[base]
		if !ok {
			continue
		}
		op := s.op
		if op == OpNotIn && !f.allows(OpNotIn) && f.allows(OpNe) {
			op = OpNe
		}
		if !f.allows(op) {
			return nil, "", errUnknownParam
		}
		return f, op, nil
	}
	return nil, "", errUnknownParam
}

// FieldDescription is one field of a registry as clients see it
// (GET /api/v1/meta/filters/{resource}).
type FieldDescription struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Ops      []Op     `json:"ops"`
	Params   []string `json:"params"`
	Enum     []string `json:"enum,omitempty"`
	Sortable bool     `json:"sortable"`
	Nullable bool     `json:"nullable,omitempty"`
}

// Description is the machine-readable filter contract of one resource.
type Description struct {
	Resource    string             `json:"resource"`
	Fields      []FieldDescription `json:"fields"`
	Reserved    []string           `json:"reserved"`
	Aliases     map[string]string  `json:"aliases,omitempty"`
	DefaultSort []string           `json:"default_sort"`
	Search      bool               `json:"search"`
	Limits      map[string]int     `json:"limits"`
}

// Describe returns the registry's contract as seen by a caller: fields that
// need a permission the caller lacks (has returns false, or has is nil) are
// left out, exactly as the compiler treats them as unknown.
func (r *Registry) Describe(has func(permission string) bool) Description {
	d := Description{
		Resource: r.Name,
		Reserved: []string{"q", "sort", "page", "per_page"},
		Search:   r.Search != nil,
		Limits: map[string]int{
			"leaves": MaxLeaves, "depth": MaxDepth, "values": MaxValues,
			"values_document": MaxValuesDocument, "value_length": MaxValueLen,
			"q_length": MaxQLen, "body_bytes": MaxBodyBytes, "sort_keys": MaxSortKeys,
			"max_offset": DefaultMaxOffset,
		},
	}
	for _, n := range r.order {
		f := r.fields[n]
		if f.Permission != "" && (has == nil || !has(f.Permission)) {
			continue
		}
		fd := FieldDescription{Name: f.Name, Type: f.Type.String(), Ops: append([]Op(nil), f.Ops...),
			Enum: append([]string(nil), f.Enum...), Sortable: f.Sortable, Nullable: f.Nullable}
		if f.allows(OpIn) || f.allows(OpEq) || f.allows(OpContains) {
			fd.Params = append(fd.Params, f.Name)
		}
		for _, s := range suffixOps {
			if f.allows(s.op) || (s.op == OpNotIn && f.allows(OpNe)) {
				fd.Params = append(fd.Params, f.Name+s.suffix)
			}
		}
		d.Fields = append(d.Fields, fd)
	}
	for _, k := range r.DefaultSort {
		if k.Desc {
			d.DefaultSort = append(d.DefaultSort, "-"+k.Field)
		} else {
			d.DefaultSort = append(d.DefaultSort, k.Field)
		}
	}
	if len(r.Aliases) > 0 {
		d.Aliases = make(map[string]string, len(r.Aliases))
		for old, a := range r.Aliases {
			d.Aliases[old] = a.To
		}
	}
	return d
}
