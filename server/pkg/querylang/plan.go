package querylang

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// Pipeline and cost limits.
const (
	MaxStages     = 6
	MaxDimensions = 2
	MaxAggs       = 5
	MaxSortKeys   = 3
	MaxTop        = 100
	// MaxGroups bounds the rows of any result.
	MaxGroups = 1000
	// MaxScore bounds the complexity score.
	MaxScore = 100
)

// Principal is who a query runs as, resolved by the server from the
// authenticated request, never from the query.
type Principal struct {
	TenantID shared.ID
	// UserID is the acting user; zero for a user-less API key.
	UserID shared.ID
	// Admin is the request's owner/admin decision.
	Admin bool
	// Scope is the data scope (datascope.Enforcer); nil only for an
	// unrestricted caller with no hidden assets.
	Scope *shared.DataScope
	// Has reports the caller's permissions; nil denies all.
	Has func(permission string) bool
}

func (p Principal) may(perm string) bool {
	return p.Admin || (p.Has != nil && p.Has(perm))
}

// BuildOptions tune Build.
type BuildOptions struct {
	// Now is the clock for relative times (default time.Now).
	Now func() time.Time
}

// ColumnKind says what an output column holds.
type ColumnKind string

// Column kinds.
const (
	ColumnTime      ColumnKind = "time"
	ColumnDimension ColumnKind = "dimension"
	ColumnMeasure   ColumnKind = "measure"
)

// Column is one output column.
type Column struct {
	Name string     `json:"name"`
	Kind ColumnKind `json:"kind"`
}

// DimRef is a group-by dimension: its path and registry field.
type DimRef struct {
	Path, Field string
}

// BucketRef is the time bucket.
type BucketRef struct {
	Path, Field string
	Interval    Interval
}

// AggRef is an aggregate: its function, the path and registry field it
// reads (none for count) and its output name.
type AggRef struct {
	Func        AggFunc
	Path, Field string
	Name        string
}

// OrderRef orders by an output column index.
type OrderRef struct {
	Column int
	Desc   bool
}

// Plan is a checked query, ready for an executor. It holds the security
// context: the tenant, the data scope and member rule (through the
// filterspec actor), the entity's mandatory filters and the field
// permission checks already applied. Executors read it through its
// methods and cannot build one themselves.
type Plan struct {
	entity    *Entity
	query     *Query
	principal Principal
	actor     filterspec.Actor
	filter    *filterspec.Spec
	effective *filterspec.Spec
	// raw is the caller's filter as a version 1 document with relative
	// times as written (FilterDocument).
	raw map[string]any

	// Bucket is the time bucket, or nil.
	Bucket *BucketRef
	// Dims are the group-by dimensions in output order (after Bucket).
	Dims []DimRef
	// Aggs are the aggregates in output order (after the dimensions).
	Aggs []AggRef
	// Columns are the output columns: bucket, dimensions, aggregates.
	Columns []Column
	// Order is the result order.
	Order []OrderRef
	// Limit is the row cap (at most MaxGroups).
	Limit int
	// Score is the complexity score (at most MaxScore).
	Score int
}

// Entity returns the plan's entity.
func (p *Plan) Entity() *Entity { return p.entity }

// Query returns the parsed query.
func (p *Plan) Query() *Query { return p.query }

// Actor returns the filterspec actor every compilation of the plan must
// use: tenant, data scope and member visibility.
func (p *Plan) Actor() filterspec.Actor { return p.actor }

// Principal returns who the plan runs as.
func (p *Plan) Principal() Principal { return p.principal }

// UserFilter returns the caller's filter alone (for documents and
// explanations), never for execution.
func (p *Plan) UserFilter() *filterspec.Spec { cp := *p.filter; return &cp }

// EffectiveFilter is the filter to execute: the caller's filter ANDed with
// the entity's mandatory filters. The tenant, data scope and member rule
// are added when it is compiled with Actor.
func (p *Plan) EffectiveFilter() *filterspec.Spec { cp := *p.effective; return &cp }

// FilterDocument returns the caller's filter as a version 1 FilterDocument
// ({"v":1,"filter":...,"q":...}) with relative times kept relative
// ("-P7D"), the form a list endpoint, a saved view or a link stores.
func (p *Plan) FilterDocument() map[string]any {
	out := make(map[string]any, len(p.raw))
	for k, v := range p.raw {
		out[k] = v
	}
	return out
}

// Restricted reports whether the caller's data scope narrows the rows.
func (p *Plan) Restricted() bool { return p.principal.Scope.Restricted() }

// MemberRule reports whether the registry's member visibility rule (on
// findings: pentest findings only for campaign members) applies.
func (p *Plan) MemberRule() bool {
	return p.entity.Registry.MemberVisibility != "" && !p.principal.Admin
}

// Build checks a parsed query against its entity for a principal and
// returns the plan. src is the query text (for error positions). Every
// problem is an *Error with positions; an error about the principal is a
// plain error.
func Build(q *Query, src string, pr Principal, opts BuildOptions) (*Plan, error) {
	if q == nil {
		return nil, errors.New("querylang: nil query")
	}
	if pr.TenantID.IsZero() {
		return nil, errors.New("querylang: principal without a tenant")
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	var el errList
	ent, ok := Lookup(q.Entity)
	if !ok {
		el.add(q.EntitySpan, "unknown entity (one of: "+strings.Join(EntityNames(), ", ")+")")
		return nil, el.err(src)
	}
	if !pr.may(ent.Permission) {
		el.add(q.EntitySpan, "you do not have permission to query "+ent.Name+" (needs "+ent.Permission+")")
		return nil, el.err(src)
	}
	actor, err := filterspec.UserActor(filterspec.UserActorInput{
		TenantID: pr.TenantID, UserID: pr.UserID, IsAdmin: pr.Admin, Scope: pr.Scope, Has: pr.may,
	})
	if err != nil {
		return nil, err
	}
	p := &Plan{entity: ent, query: q, principal: pr, actor: actor}

	// Filter: text -> FilterDocument -> filterspec (its parser does the
	// typing, enums and limits) with positions mapped back.
	db := &docBuilder{ent: ent, may: pr.may, spans: map[string]Span{}, errs: &el}
	doc := map[string]any{"v": filterspec.DocumentVersion}
	if q.Where != nil {
		doc = db.build(q.Where)
	}
	if len(el.d) > 0 {
		return nil, el.err(src)
	}
	spec, err := filterspec.ParseDocumentValue(doc, ent.Registry, filterspec.Options{Unknown: filterspec.UnknownStrict, Now: now})
	if err != nil {
		db.mapError(err, q)
		return nil, el.err(src)
	}
	liftText(spec, ent)
	p.filter = spec
	p.raw = liftTextDoc(doc, ent)
	eff := *spec
	if m := ent.mandatoryNode(); m != nil {
		if spec.Root == nil {
			eff.Root = m
		} else {
			eff.Root = &filterspec.Node{All: []*filterspec.Node{spec.Root, m}}
		}
	}
	p.effective = &eff
	// Compile once as the caller: the same check every executor repeats.
	if _, err := filterspec.Compile(p.effective, ent.Registry, actor); err != nil {
		db.mapError(err, q)
		return nil, el.err(src)
	}

	pb := &pipelineBuilder{p: p, ent: ent, may: pr.may, errs: &el}
	pb.build(q.Pipeline)
	if len(el.d) > 0 {
		return nil, el.err(src)
	}
	p.Score = score(p, len(spec.Leaves()))
	if p.Score > MaxScore {
		el.addc(Span{0, len(src)}, CodeTooComplex, "the query is too complex (score "+strconv.Itoa(p.Score)+", max "+strconv.Itoa(MaxScore)+"): use fewer conditions, relations or groups", nil)
		return nil, el.err(src)
	}
	return p, nil
}

// Compile parses and builds in one step.
func Compile(src string, pr Principal, opts BuildOptions) (*Plan, error) {
	q, err := Parse(src)
	if err != nil {
		return nil, err
	}
	return Build(q, src, pr, opts)
}

// score is the complexity score: every condition, relation, group,
// aggregate and stage costs; relations and percentiles cost more.
func score(p *Plan, leaves int) int {
	s := 1 + leaves
	for _, l := range p.filter.Leaves() {
		if f, ok := p.entity.Registry.Field(l.Field); ok && isRelation(f) {
			s += 2
		}
		if l.Field == p.entity.text {
			s += 3
		}
	}
	if p.Bucket != nil {
		s += 2
	}
	for _, d := range p.Dims {
		s += 2
		if strings.Contains(d.Path, ".") {
			s += 3
		}
	}
	for _, a := range p.Aggs {
		s++
		switch a.Func {
		case AggMedian, AggP90, AggDistinct:
			s += 2
		}
	}
	return s + len(p.query.Pipeline)
}

// isRelation reports whether a field reads another table.
func isRelation(f *filterspec.Field) bool {
	if strings.Contains(f.BoolTemplate, "SELECT") {
		return true
	}
	for _, t := range f.Templates {
		if strings.Contains(t, "SELECT") {
			return true
		}
	}
	return false
}

// docBuilder turns the filter expression into a FilterDocument and
// remembers which text each document path came from.
type docBuilder struct {
	ent   *Entity
	may   func(string) bool
	spans map[string]Span
	errs  *errList
	where Span
}

func (b *docBuilder) build(x Expr) map[string]any {
	b.where = x.exprSpan()
	doc := map[string]any{"v": filterspec.DocumentVersion}
	b.spans["filter"] = x.exprSpan()
	if f := b.node(x, "filter"); f != nil {
		doc["filter"] = f
	}
	return doc
}

// text compiles `text ~ "..."` to the entity's internal text field.
func (b *docBuilder) text(t *Text, path string) map[string]any {
	if b.ent.text == "" {
		b.errs.add(t.Span, b.ent.Name+" have no text search")
		return nil
	}
	if strings.TrimSpace(t.Value.Text) == "" {
		b.errs.add(t.Value.Span, "text search needs some text")
		return nil
	}
	f, _ := b.ent.Registry.Field(b.ent.text)
	return b.leaf(path, f, filterspec.OpContains, t.Value.Text, t, Path{Span: t.Span}, t.Span, []Value{t.Value})
}

func (b *docBuilder) node(x Expr, path string) map[string]any {
	b.spans[path] = x.exprSpan()
	switch n := x.(type) {
	case *Logic:
		key := "any"
		if n.Kind == And {
			key = "all"
		}
		kids := make([]any, 0, len(n.Terms))
		for _, t := range n.Terms {
			if bt, ok := t.(*Between); ok && n.Kind == And {
				// Splice lo/hi into this "all" instead of nesting a group.
				lo, hi := b.between(bt, path+"."+key+"["+strconv.Itoa(len(kids))+"]", path+"."+key+"["+strconv.Itoa(len(kids)+1)+"]")
				if lo != nil {
					kids = append(kids, lo, hi)
				}
				continue
			}
			if c := b.node(t, path+"."+key+"["+strconv.Itoa(len(kids))+"]"); c != nil {
				kids = append(kids, c)
			}
		}
		if len(kids) == 0 {
			return nil
		}
		return map[string]any{key: kids}
	case *Not:
		c := b.node(n.X, path+".not")
		if c == nil {
			return nil
		}
		return map[string]any{"not": c}
	case *Text:
		return b.text(n, path)
	case *Between:
		lo, hi := b.between(n, path+".all[0]", path+".all[1]")
		if lo == nil {
			return nil
		}
		return map[string]any{"all": []any{lo, hi}}
	case *Compare:
		return b.compare(n, path)
	case *In:
		return b.in(n, path)
	case *IsEmpty:
		return b.isEmpty(n, path)
	}
	return nil
}

// resolve returns the field of a path, or records "unknown field".
func (b *docBuilder) resolve(p Path) (*filterspec.Field, bool) {
	f, ok := b.ent.field(p.Name, b.may)
	if !ok {
		msg := "unknown field"
		if len(p.Name) <= 64 {
			msg += ` "` + p.Name + `"`
		}
		b.errs.addc(p.Span, CodeUnknownField, msg+" on "+b.ent.Name, b.ent.SuggestFields(p.Name, b.may))
	}
	return f, ok
}

func allows(f *filterspec.Field, op filterspec.Op) bool {
	for _, o := range f.Ops {
		if o == op {
			return true
		}
	}
	return false
}

func (b *docBuilder) leaf(path string, f *filterspec.Field, op filterspec.Op, value any, term Expr, p Path, opSpan Span, vals []Value) map[string]any {
	b.spans[path] = term.exprSpan()
	b.spans[path+".field"] = p.Span
	b.spans[path+".op"] = opSpan
	if len(vals) > 0 {
		b.spans[path+".value"] = Span{vals[0].Span.Start, vals[len(vals)-1].Span.End}
		for i, v := range vals {
			b.spans[path+".value["+strconv.Itoa(i)+"]"] = v.Span
		}
	} else {
		b.spans[path+".value"] = opSpan
	}
	return map[string]any{"field": f.Name, "op": string(op), "value": value}
}

func (b *docBuilder) opError(s Span, op string, p Path) {
	var allowed []string
	if f, ok := b.ent.field(p.Name, b.may); ok {
		allowed = textOperators(f)
	}
	b.errs.addc(s, CodeOperator, `"`+op+`" is not allowed on `+b.ent.Canonical(p.Name), allowed)
}

func (b *docBuilder) compare(n *Compare, path string) map[string]any {
	if n.Implicit {
		if _, ok := b.ent.field(n.Path.Name, b.may); !ok {
			// A bare address or CVE id on a field the caller may not use is
			// what it always was: text.
			return b.text(&Text{Value: Value{Kind: ValString, Text: n.Value.Text, Span: n.Span}, Span: n.Span, Bare: true}, path)
		}
	}
	f, ok := b.resolve(n.Path)
	if !ok {
		return nil
	}
	if n.Value.Kind == ValAge && f.Type == filterspec.TypeTime {
		return b.age(n, f, path)
	}
	if f.Ordered && isRange(n.Op) {
		return b.ordered(n, f, path)
	}
	if !b.valueOK(f, n.Value) {
		return nil
	}
	var op filterspec.Op
	v := b.value(f, n.Value)
	switch n.Op {
	case OpEq:
		switch {
		case allows(f, filterspec.OpEq):
			op = filterspec.OpEq
		case allows(f, filterspec.OpIn):
			op = filterspec.OpIn
		}
	case OpNe:
		switch {
		case f.Type == filterspec.TypeBool && allows(f, filterspec.OpEq):
			bv, isBool := v.(bool)
			if !isBool {
				b.errs.addc(n.Value.Span, CodeBadValue, "must be true or false", []string{litTrue, litFalse})
				return nil
			}
			op, v = filterspec.OpEq, !bv
		case f.EnumTemplates != nil && allows(f, filterspec.OpEq):
			// A named set (the state lens) has no "not equal" of its own: the
			// negation wraps the same equality leaf, so it compiles to the
			// same constant predicate under NOT.
			leaf := b.leaf(path+".not", f, filterspec.OpEq, v, n, n.Path, n.OpPos, []Value{n.Value})
			return map[string]any{"not": leaf}
		case allows(f, filterspec.OpNe):
			op = filterspec.OpNe
		case allows(f, filterspec.OpNotIn):
			op = filterspec.OpNotIn
		}
	case OpGt:
		op = filterspec.OpGt
	case OpGte:
		op = filterspec.OpGte
	case OpLt:
		op = filterspec.OpLt
	case OpLte:
		op = filterspec.OpLte
	case OpContains:
		op = filterspec.OpContains
		if utf8.RuneCountInString(strings.TrimSpace(n.Value.Text)) < minContainsRunes {
			b.errs.addc(n.Value.Span, CodeBadValue, `"~" needs at least 3 characters`, nil)
			return nil
		}
	}
	if op == "" || !allows(f, op) {
		b.opError(n.OpPos, string(n.Op), n.Path)
		return nil
	}
	return b.leaf(path, f, op, v, n, n.Path, n.OpPos, []Value{n.Value})
}

func isRange(op CompareOp) bool {
	return op == OpGt || op == OpGte || op == OpLt || op == OpLte
}

var rangeOps = map[CompareOp]filterspec.Op{OpGt: filterspec.OpGt, OpGte: filterspec.OpGte, OpLt: filterspec.OpLt, OpLte: filterspec.OpLte}

// ageOps maps an age comparison to the comparison of the time with "now
// minus the age": less than 7 days old is after 7 days ago.
var ageOps = map[CompareOp]filterspec.Op{OpLt: filterspec.OpGt, OpLte: filterspec.OpGte, OpGt: filterspec.OpLt, OpGte: filterspec.OpLte}

// age compiles "time < 7d" (an age) to "time > now - 7d".
func (b *docBuilder) age(n *Compare, f *filterspec.Field, path string) map[string]any {
	op, ok := ageOps[n.Op]
	if !ok {
		b.errs.addc(n.OpPos, CodeOperator, "an age takes <, <=, > or >= (last_seen_at<7d: seen in the last 7 days)", []string{"<", "<=", ">", ">="})
		return nil
	}
	iso, ok := relativeISO("-" + n.Value.Text)
	if !ok {
		b.errs.addc(n.Value.Span, CodeBadValue, "an age is at most ten years", nil)
		return nil
	}
	if !allows(f, op) {
		b.opError(n.OpPos, string(n.Op), n.Path)
		return nil
	}
	return b.leaf(path, f, op, iso, n, n.Path, n.OpPos, []Value{n.Value})
}

// ordered compiles "severity >= high" on an ordered enum to the list of
// the values at least high.
func (b *docBuilder) ordered(n *Compare, f *filterspec.Field, path string) map[string]any {
	vals, ok := f.OrderedValues(rangeOps[n.Op], n.Value.Text)
	if !ok {
		b.unknownValue(f, n.Value)
		return nil
	}
	if len(vals) == 0 {
		b.errs.addc(n.Span, CodeBadValue, "no value is "+map[CompareOp]string{OpGt: "above", OpLt: "below"}[n.Op]+" this one", nil)
		return nil
	}
	if !allows(f, filterspec.OpIn) {
		b.opError(n.OpPos, string(n.Op), n.Path)
		return nil
	}
	list := make([]any, len(vals))
	for i, v := range vals {
		list[i] = v
	}
	return b.leaf(path, f, filterspec.OpIn, list, n, n.Path, n.OpPos, []Value{n.Value})
}

// valueOK checks what filterspec cannot see: an enum value it does not know
// (with the closest values as fixes) and a pattern on a field that matches
// exact values.
func (b *docBuilder) valueOK(f *filterspec.Field, v Value) bool {
	switch {
	case f.Type == filterspec.TypeEnum && (v.Kind == ValIdent || v.Kind == ValString || v.Kind == ValWord):
		for _, e := range f.Enum {
			if strings.EqualFold(e, v.Text) {
				return true
			}
		}
		if _, retired := f.EnumRetired[strings.ToLower(v.Text)]; retired {
			return true // filterspec says what replaces it
		}
		b.unknownValue(f, v)
		return false
	case f.Type == filterspec.TypeString && !f.Glob && v.Kind == ValWord && strings.ContainsAny(v.Text, "*?"):
		msg := "this field matches exact values; quote the value to match * or ? literally"
		var fix []string
		if allows(f, filterspec.OpContains) {
			msg = "this field matches exact values; use ~ to search inside it"
			fix = []string{"~"}
		}
		b.errs.addc(v.Span, CodePattern, msg, fix)
		return false
	}
	return true
}

func (b *docBuilder) unknownValue(f *filterspec.Field, v Value) {
	b.errs.addc(v.Span, CodeUnknownValue, "must be one of: "+strings.Join(f.Enum, ", "), closest(strings.ToLower(v.Text), f.Enum, 10))
}

func (b *docBuilder) in(n *In, path string) map[string]any {
	f, ok := b.resolve(n.Path)
	if !ok {
		return nil
	}
	op, word := filterspec.OpIn, "in"
	if n.Negate {
		op, word = filterspec.OpNotIn, "not in"
	}
	if !allows(f, op) {
		b.opError(n.OpPos, word, n.Path)
		return nil
	}
	vals := make([]any, 0, len(n.Values))
	for _, v := range n.Values {
		if !b.valueOK(f, v) {
			return nil
		}
		vals = append(vals, b.value(f, v))
	}
	return b.leaf(path, f, op, vals, n, n.Path, n.OpPos, n.Values)
}

func (b *docBuilder) isEmpty(n *IsEmpty, path string) map[string]any {
	f, ok := b.resolve(n.Path)
	if !ok {
		return nil
	}
	if !allows(f, filterspec.OpIsNull) {
		b.opError(n.OpPos, "is empty", n.Path)
		return nil
	}
	return b.leaf(path, f, filterspec.OpIsNull, !n.Negate, n, n.Path, n.OpPos, nil)
}

func (b *docBuilder) between(n *Between, loPath, hiPath string) (lo, hi map[string]any) {
	f, ok := b.resolve(n.Path)
	if !ok {
		return nil, nil
	}
	if !allows(f, filterspec.OpGte) || !allows(f, filterspec.OpLte) {
		b.opError(n.OpPos, "between", n.Path)
		return nil, nil
	}
	lo = b.leaf(loPath, f, filterspec.OpGte, b.value(f, n.Lo), n, n.Path, n.OpPos, []Value{n.Lo})
	hi = b.leaf(hiPath, f, filterspec.OpLte, b.value(f, n.Hi), n, n.Path, n.OpPos, []Value{n.Hi})
	return lo, hi
}

// value converts a literal to the JSON scalar the FilterDocument parser
// expects for the field's type; the parser does the real typing.
func (b *docBuilder) value(f *filterspec.Field, v Value) any {
	if f.Type == filterspec.TypeEnum {
		for _, e := range f.Enum {
			if strings.EqualFold(e, v.Text) {
				return e // the registry's spelling
			}
		}
	}
	switch v.Kind {
	case ValBool:
		return v.Text == litTrue
	case ValNumber:
		if f.Type == filterspec.TypeInt || f.Type == filterspec.TypeNumber {
			return json.Number(v.Text)
		}
	case ValRelative:
		if f.Type == filterspec.TypeTime {
			iso, ok := relativeISO(v.Text)
			if !ok {
				b.errs.add(v.Span, "relative time is longer than ten years")
				return ""
			}
			return iso
		}
	}
	return v.Text
}

// maxRelativeDays is ten years, the filterspec bound.
const maxRelativeDays = 3660

// relativeISO converts "-14d" to "-P14D" (mo = 30 days, y = 365 days).
func relativeISO(s string) (string, bool) {
	i := 1
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	n, err := strconv.Atoi(s[1:i])
	u, ok := relativeUnits[s[i:]]
	if err != nil || !ok {
		return "", false
	}
	n *= u.mul
	if u.time {
		limit := maxRelativeDays * 24
		if u.des == "M" {
			limit *= 60
		}
		if n > limit {
			return "", false
		}
		return "-PT" + strconv.Itoa(n) + u.des, true
	}
	days := n
	if u.des == "W" {
		days = n * 7
	}
	if days > maxRelativeDays {
		return "", false
	}
	return "-P" + strconv.Itoa(n) + u.des, true
}

// mapError attaches each filterspec error detail to the text it came from.
func (b *docBuilder) mapError(err error, q *Query) {
	fe, ok := filterspec.AsError(err)
	if !ok {
		b.errs.add(b.where, "the filter is not valid")
		return
	}
	for _, d := range fe.Details {
		path := d.Path
		if path == "" {
			path = d.Param
		}
		b.errs.addc(b.spanOf(path, q), CodeBadValue, d.Reason, nil)
	}
}

func (b *docBuilder) spanOf(path string, q *Query) Span {
	for path != "" {
		if s, ok := b.spans[path]; ok {
			return s
		}
		i := strings.LastIndexAny(path, ".[")
		if i <= 0 {
			break
		}
		path = path[:i]
	}
	if q.Where != nil {
		return q.Where.exprSpan()
	}
	return q.EntitySpan
}

// liftText moves a top-level text search condition into the spec's q, the
// form version 1 documents (saved views) use. Both compile to the same
// search predicate.
func liftText(spec *filterspec.Spec, ent *Entity) {
	if ent.text == "" || spec.Root == nil || spec.Q != "" {
		return
	}
	isText := func(n *filterspec.Node) (string, bool) {
		if n.Leaf != nil && n.Leaf.Field == ent.text && n.Leaf.Op == filterspec.OpContains {
			v, ok := n.Leaf.Values[0].(string)
			return v, ok && v != ""
		}
		return "", false
	}
	if v, ok := isText(spec.Root); ok {
		spec.Root, spec.Q = nil, v
		return
	}
	if spec.Root.All == nil {
		return
	}
	idx := -1
	for i, c := range spec.Root.All {
		if _, ok := isText(c); ok {
			if idx >= 0 {
				return // two text searches stay conditions
			}
			idx = i
		}
	}
	if idx < 0 {
		return
	}
	spec.Q, _ = isText(spec.Root.All[idx])
	kids := append(append([]*filterspec.Node(nil), spec.Root.All[:idx]...), spec.Root.All[idx+1:]...)
	switch len(kids) {
	case 0:
		spec.Root = nil
	default:
		spec.Root = &filterspec.Node{All: kids}
	}
}

// liftTextDoc is liftText on the raw document: a top-level text search
// becomes the document's q.
func liftTextDoc(doc map[string]any, ent *Entity) map[string]any {
	out := map[string]any{"v": filterspec.DocumentVersion}
	f, ok := doc["filter"].(map[string]any)
	if !ok {
		return out
	}
	out["filter"] = f
	if ent.text == "" {
		return out
	}
	textOf := func(n any) (string, bool) {
		m, ok := n.(map[string]any)
		if !ok || m["field"] != ent.text || m["op"] != string(filterspec.OpContains) {
			return "", false
		}
		s, ok := m["value"].(string)
		return s, ok && strings.TrimSpace(s) != ""
	}
	if s, ok := textOf(f); ok {
		delete(out, "filter")
		out["q"] = strings.TrimSpace(s)
		return out
	}
	kids, ok := f["all"].([]any)
	if !ok {
		return out
	}
	idx := -1
	for i, k := range kids {
		if _, ok := textOf(k); ok {
			if idx >= 0 {
				return out // two text searches stay conditions
			}
			idx = i
		}
	}
	if idx < 0 {
		return out
	}
	s, _ := textOf(kids[idx])
	out["q"] = strings.TrimSpace(s)
	rest := append(append([]any(nil), kids[:idx]...), kids[idx+1:]...)
	switch len(rest) {
	case 0:
		delete(out, "filter")
	case 1:
		out["filter"] = rest[0]
	default:
		out["filter"] = map[string]any{"all": rest}
	}
	return out
}
