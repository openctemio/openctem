package querylang

import (
	"regexp"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// DocumentVersion is the query document version: a filterspec
// FilterDocument (version 1) plus the entity and the pipeline.
const DocumentVersion = 2

// Document returns the plan as a query document:
//
//	{"v":2, "entity":"findings", "filter":{...}, "q":"...", "pipeline":[...]}
//
// filter and q are exactly the version 1 FilterDocument of the caller's
// filter (relative times resolved). The pipeline is listed stage by stage.
func (p *Plan) Document() map[string]any {
	doc := p.filter.Document()
	doc["v"] = DocumentVersion
	doc["entity"] = p.entity.Name
	delete(doc, "sort")
	stages := make([]any, 0, len(p.query.Pipeline))
	for _, st := range p.query.Pipeline {
		stages = append(stages, stageDocument(st))
	}
	doc["pipeline"] = stages
	return doc
}

func pathNames(ps []Path) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func stageDocument(st Stage) map[string]any {
	switch st.Kind {
	case StageCount:
		return map[string]any{"count": map[string]any{"by": pathNames(st.By)}}
	case StageStats:
		aggs := make([]any, 0, len(st.Aggs))
		for _, a := range st.Aggs {
			m := map[string]any{"fn": string(a.Func)}
			if a.Field.Name != "" {
				m["field"] = a.Field.Name
			}
			if a.As != "" {
				m["as"] = a.As
			}
			aggs = append(aggs, m)
		}
		return map[string]any{"stats": map[string]any{"aggs": aggs, "by": pathNames(st.By)}}
	case StageBucket:
		return map[string]any{"bucket": map[string]any{"field": st.Field.Name, "by": string(st.Interval)}}
	case StageTop:
		return map[string]any{"top": map[string]any{"n": st.N, "by": st.Keys[0].Name.Name}}
	case StageSort:
		keys := make([]any, 0, len(st.Keys))
		for _, k := range st.Keys {
			keys = append(keys, map[string]any{"key": k.Name.Name, "desc": k.Desc})
		}
		return map[string]any{"sort": keys}
	case StageLimit:
		return map[string]any{"limit": st.N}
	}
	return map[string]any{}
}

// bareValue is a value that prints without quotes as an enum word.
var bareValue = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// FromSpec renders a filterspec filter (a stored version 1 document, as
// parsed by filterspec) as a query on ent, so a builder's document opens
// in the text editor. Building the result gives the same filter back.
func FromSpec(ent *Entity, spec *filterspec.Spec) *Query {
	q := &Query{Entity: ent.Name}
	var terms []Expr
	if spec.Root != nil {
		terms = append(terms, fromNode(ent, spec.Root))
	}
	if spec.Q != "" {
		terms = append(terms, &Text{Value: Value{Kind: ValString, Text: spec.Q}})
	}
	switch len(terms) {
	case 1:
		q.Where = terms[0]
	case 2:
		q.Where = &Logic{Kind: And, Terms: flattenInto(flattenInto(nil, And, terms[0]), And, terms[1])}
	}
	return q
}

func fromNode(ent *Entity, n *filterspec.Node) Expr {
	switch {
	case n.Leaf != nil:
		return fromLeaf(ent, n.Leaf)
	case n.Not != nil:
		return &Not{X: fromNode(ent, n.Not)}
	}
	kind, kids := And, n.All
	if n.Any != nil {
		kind, kids = Or, n.Any
	}
	if len(kids) == 1 {
		return fromNode(ent, kids[0])
	}
	var terms []Expr
	for _, k := range kids {
		terms = flattenInto(terms, kind, fromNode(ent, k))
	}
	return &Logic{Kind: kind, Terms: terms}
}

func fromLeaf(ent *Entity, l *filterspec.Leaf) Expr {
	if l.Field == ent.text && ent.text != "" {
		v, _ := l.Values[0].(string)
		return &Text{Value: Value{Kind: ValString, Text: v}}
	}
	path := Path{Name: ent.pathOf(l.Field)}
	f, _ := ent.Registry.Field(l.Field)
	vals := make([]Value, 0, len(l.Values))
	for _, v := range l.Values {
		vals = append(vals, fromValue(f, v))
	}
	switch l.Op {
	case filterspec.OpIsNull:
		isNull, _ := l.Values[0].(bool)
		return &IsEmpty{Path: path, Negate: !isNull}
	case filterspec.OpIn, filterspec.OpNotIn:
		if len(vals) == 1 {
			op := OpEq
			if l.Op == filterspec.OpNotIn {
				op = OpNe
			}
			return &Compare{Path: path, Op: op, Value: vals[0]}
		}
		return &In{Path: path, Negate: l.Op == filterspec.OpNotIn, Values: vals}
	}
	op := map[filterspec.Op]CompareOp{
		filterspec.OpEq: OpEq, filterspec.OpNe: OpNe, filterspec.OpGt: OpGt, filterspec.OpGte: OpGte,
		filterspec.OpLt: OpLt, filterspec.OpLte: OpLte, filterspec.OpContains: OpContains,
	}[l.Op]
	return &Compare{Path: path, Op: op, Value: vals[0]}
}

func fromValue(f *filterspec.Field, v any) Value {
	switch x := v.(type) {
	case bool:
		return Value{Kind: ValBool, Text: strconv.FormatBool(x)}
	case int64:
		return Value{Kind: ValNumber, Text: strconv.FormatInt(x, 10)}
	case float64:
		return Value{Kind: ValNumber, Text: strconv.FormatFloat(x, 'f', -1, 64)}
	case time.Time:
		return Value{Kind: ValString, Text: x.UTC().Format(time.RFC3339Nano)}
	case string:
		if f != nil && f.Type == filterspec.TypeEnum && bareValue.MatchString(x) && !reserved[x] && x != litTrue && x != litFalse {
			return Value{Kind: ValIdent, Text: x}
		}
		return Value{Kind: ValString, Text: x}
	}
	return Value{Kind: ValString}
}
