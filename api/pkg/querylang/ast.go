package querylang

// Query is a parsed query: one entity, an optional filter and a pipeline.
// Spans point into the source text; Equal ignores them.
type Query struct {
	Entity     string
	EntitySpan Span
	// Where is the filter; nil means none.
	Where    Expr
	Pipeline []Stage
}

// Expr is a filter expression node.
type Expr interface {
	exprSpan() Span
}

// BoolKind is the connective of a Logic node.
type BoolKind int

// Connectives.
const (
	And BoolKind = iota + 1
	Or
)

// Logic is an n-ary and/or (the parser flattens chains of one connective,
// so "a or (b or c)" and "a or b or c" are the same node).
type Logic struct {
	Kind  BoolKind
	Terms []Expr
	Span  Span
}

// Not negates an expression.
type Not struct {
	X    Expr
	Span Span
}

// CompareOp is a comparison operator of the text form.
type CompareOp string

// Comparison operators.
const (
	OpEq       CompareOp = "="
	OpNe       CompareOp = "!="
	OpGt       CompareOp = ">"
	OpGte      CompareOp = ">="
	OpLt       CompareOp = "<"
	OpLte      CompareOp = "<="
	OpContains CompareOp = "~"
)

// ValueKind is the lexical kind of a value.
type ValueKind int

// Value kinds.
const (
	ValString   ValueKind = iota + 1 // "quoted"
	ValIdent                         // bare word: an enum value, me
	ValNumber                        // 12, -1.5
	ValBool                          // true, false
	ValRelative                      // -14d
)

// Value is a literal as written. Typing happens against the field when
// the query is built.
type Value struct {
	Kind ValueKind
	Text string
	Span Span
}

// Path names a field ("severity") or a curated relation's field
// ("asset.type").
type Path struct {
	Name string
	Span Span
}

// Compare is "path op value".
type Compare struct {
	Path  Path
	Op    CompareOp
	OpPos Span
	Value Value
	Span  Span
}

// In is "path [not] in (v, ...)".
type In struct {
	Path   Path
	Negate bool
	OpPos  Span
	Values []Value
	Span   Span
}

// Between is "path between lo and hi" (inclusive).
type Between struct {
	Path   Path
	OpPos  Span
	Lo, Hi Value
	Span   Span
}

// IsEmpty is "path is [not] empty".
type IsEmpty struct {
	Path   Path
	Negate bool
	OpPos  Span
	Span   Span
}

// Text is `text ~ "words"`: the entity's text search.
type Text struct {
	Value Value
	Span  Span
}

func (e *Logic) exprSpan() Span   { return e.Span }
func (e *Not) exprSpan() Span     { return e.Span }
func (e *Compare) exprSpan() Span { return e.Span }
func (e *In) exprSpan() Span      { return e.Span }
func (e *Between) exprSpan() Span { return e.Span }
func (e *IsEmpty) exprSpan() Span { return e.Span }
func (e *Text) exprSpan() Span    { return e.Span }

// StageKind is a pipeline stage.
type StageKind string

// Pipeline stages.
const (
	StageCount  StageKind = "count"
	StageStats  StageKind = "stats"
	StageBucket StageKind = "bucket"
	StageTop    StageKind = "top"
	StageSort   StageKind = "sort"
	StageLimit  StageKind = "limit"
)

// AggFunc is an aggregate function of stats.
type AggFunc string

// Aggregates. count takes no field; distinct counts distinct values of a
// dimension; the others need a numeric (measure) field.
const (
	AggCount    AggFunc = "count"
	AggDistinct AggFunc = "distinct"
	AggSum      AggFunc = "sum"
	AggAvg      AggFunc = "avg"
	AggMin      AggFunc = "min"
	AggMax      AggFunc = "max"
	AggMedian   AggFunc = "median"
	AggP90      AggFunc = "p90"
)

// Agg is one aggregate of a stats stage.
type Agg struct {
	Func AggFunc
	// Field is empty for count.
	Field Path
	// As is the output name; empty means the default (count, avg_cvss_score).
	As   string
	Span Span
}

// Interval is a time bucket width.
type Interval string

// Bucket widths.
const (
	IntervalDay   Interval = "day"
	IntervalWeek  Interval = "week"
	IntervalMonth Interval = "month"
)

// SortKey is one key of a sort stage: an output column name.
type SortKey struct {
	Name Path
	Desc bool
}

// Stage is one pipeline stage. Which fields are set depends on Kind:
//   - count: By (count by p1, p2; empty is a plain count);
//   - stats: Aggs and By;
//   - bucket: Field and Interval;
//   - top: N and Keys[0];
//   - sort: Keys;
//   - limit: N.
type Stage struct {
	Kind     StageKind
	By       []Path
	Aggs     []Agg
	Field    Path
	Interval Interval
	N        int
	Keys     []SortKey
	Span     Span
}
