package querylang

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
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
		el.add(Span{0, len(src)}, "the query is too complex (score "+strconv.Itoa(p.Score)+", max "+strconv.Itoa(MaxScore)+"): use fewer conditions, relations or groups")
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
		b.errs.add(p.Span, msg+" on "+b.ent.Name)
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
	b.errs.add(s, `"`+op+`" is not allowed on `+p.Name)
}

func (b *docBuilder) compare(n *Compare, path string) map[string]any {
	f, ok := b.resolve(n.Path)
	if !ok {
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
				b.errs.add(n.Value.Span, "must be true or false")
				return nil
			}
			op, v = filterspec.OpEq, !bv
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
		if strings.TrimSpace(n.Value.Text) == "" {
			b.errs.add(n.Value.Span, `"~" needs some text`)
			return nil
		}
	}
	if op == "" || !allows(f, op) {
		b.opError(n.OpPos, string(n.Op), n.Path)
		return nil
	}
	return b.leaf(path, f, op, v, n, n.Path, n.OpPos, []Value{n.Value})
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
		if n > maxRelativeDays*24 {
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
		b.errs.add(b.spanOf(path, q), d.Reason)
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
