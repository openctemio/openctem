package querylang

import (
	"strconv"
	"strings"
)

// Boolean literals.
const (
	litTrue  = "true"
	litFalse = "false"
)

// DefaultEntity is the entity of a query that starts with "where".
const DefaultEntity = "findings"

// reserved are words that cannot be bare values or names (quote them).
var reserved = map[string]bool{
	"where": true, "and": true, "or": true, "not": true, "in": true, "between": true,
	"is": true, "empty": true, "by": true, "as": true,
}

// maxStageNumber bounds a number in top or limit before validation (the
// real caps are lower and checked when the query is built).
const maxStageNumber = 1_000_000

// Parse parses query text. It checks syntax only; fields, values and
// limits are checked by Build against an entity. An error is an *Error
// with positions.
func Parse(src string) (*Query, error) {
	toks, err := lex(src)
	if err != nil {
		qe, _ := AsError(err)
		locate(qe, src)
		return nil, qe
	}
	p := &parser{toks: toks, src: src}
	q := p.query()
	if p.failed != nil {
		locate(p.failed, src)
		return nil, p.failed
	}
	return q, nil
}

type parser struct {
	toks   []token
	pos    int
	src    string
	depth  int
	failed *Error
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tokEOF {
		p.pos++
	}
	return t
}

// fail records the first error; parsing stops at it.
func (p *parser) fail(s Span, msg string) {
	if p.failed == nil {
		p.failed = newError(s, msg)
	}
	// Jump to EOF so every loop ends.
	p.pos = len(p.toks) - 1
}

func (p *parser) isWord(w string) bool {
	t := p.peek()
	return t.kind == tokIdent && strings.EqualFold(t.text, w)
}

func (p *parser) expectWord(w string) (token, bool) {
	if !p.isWord(w) {
		t := p.peek()
		p.fail(t.span, `expected "`+w+`", found `+describe(t))
		return t, false
	}
	return p.next(), true
}

func (p *parser) expect(k tokKind) (token, bool) {
	t := p.peek()
	if t.kind != k {
		p.fail(t.span, "expected "+k.String()+", found "+describe(t))
		return t, false
	}
	return p.next(), true
}

// describe names a token for an error without echoing free text.
func describe(t token) string {
	switch t.kind {
	case tokIdent:
		if reserved[strings.ToLower(t.text)] || len(t.text) <= 32 {
			return `"` + t.text + `"`
		}
		return "a name"
	case tokOp:
		return `"` + t.text + `"`
	}
	return t.kind.String()
}

func (p *parser) query() *Query {
	q := &Query{}
	t := p.peek()
	switch {
	case t.kind == tokEOF:
		p.fail(t.span, "the query is empty: start with an entity such as findings")
		return nil
	case p.isWord("where"):
		q.Entity, q.EntitySpan = DefaultEntity, Span{t.span.Start, t.span.Start}
	case t.kind == tokIdent && !reserved[strings.ToLower(t.text)]:
		p.next()
		q.Entity, q.EntitySpan = strings.ToLower(t.text), t.span
	default:
		p.fail(t.span, "a query starts with an entity such as findings, found "+describe(t))
		return nil
	}
	if p.isWord("where") {
		p.next()
		q.Where = p.orExpr()
	}
	for p.failed == nil && p.peek().kind == tokPipe {
		p.next()
		if st, ok := p.stage(); ok {
			q.Pipeline = append(q.Pipeline, st)
		}
	}
	if t := p.peek(); p.failed == nil && t.kind != tokEOF {
		msg := "unexpected " + describe(t)
		if t.kind == tokIdent && q.Where == nil && len(q.Pipeline) == 0 {
			msg += ` (a filter starts with "where")`
		} else {
			msg += ` (join conditions with "and" or "or", stages with "|")`
		}
		p.fail(t.span, msg)
	}
	return q
}

func (p *parser) enter(s Span) bool {
	p.depth++
	if p.depth > MaxNesting {
		p.fail(s, "nested too deep")
		return false
	}
	return true
}

func (p *parser) orExpr() Expr { return p.logic(Or) }

// logic parses a chain of one connective, flattening nested chains of the
// same connective.
func (p *parser) logic(kind BoolKind) Expr {
	word, sub := "or", func() Expr { return p.logic(And) }
	if kind == And {
		word, sub = "and", p.unary
	}
	first := sub()
	if p.failed != nil || !p.isWord(word) {
		return first
	}
	terms := flattenInto(nil, kind, first)
	for p.failed == nil && p.isWord(word) {
		p.next()
		x := sub()
		if p.failed != nil {
			return nil
		}
		terms = flattenInto(terms, kind, x)
	}
	return &Logic{Kind: kind, Terms: terms, Span: Span{terms[0].exprSpan().Start, terms[len(terms)-1].exprSpan().End}}
}

func flattenInto(dst []Expr, kind BoolKind, x Expr) []Expr {
	if l, ok := x.(*Logic); ok && l.Kind == kind {
		return append(dst, l.Terms...)
	}
	return append(dst, x)
}

func (p *parser) unary() Expr {
	if p.isWord("not") {
		t := p.next()
		if !p.enter(t.span) {
			return nil
		}
		x := p.unary()
		p.depth--
		if p.failed != nil {
			return nil
		}
		return &Not{X: x, Span: Span{t.span.Start, x.exprSpan().End}}
	}
	return p.primary()
}

func (p *parser) primary() Expr {
	t := p.peek()
	if t.kind == tokLParen {
		p.next()
		if !p.enter(t.span) {
			return nil
		}
		x := p.orExpr()
		p.depth--
		if p.failed != nil {
			return nil
		}
		if _, ok := p.expect(tokRParen); !ok {
			return nil
		}
		// The parentheses are not kept: the tree says what they grouped.
		return x
	}
	return p.term()
}

func (p *parser) term() Expr {
	t := p.peek()
	if t.kind == tokIdent && strings.EqualFold(t.text, "text") && p.toks[p.pos+1].kind == tokOp && p.toks[p.pos+1].text == "~" {
		p.next()
		p.next()
		v, ok := p.value()
		if !ok {
			return nil
		}
		if v.Kind != ValString {
			p.fail(v.Span, `text search takes a quoted string: text ~ "words"`)
			return nil
		}
		return &Text{Value: v, Span: Span{t.span.Start, v.Span.End}}
	}
	path, ok := p.path()
	if !ok {
		return nil
	}
	op := p.peek()
	switch {
	case op.kind == tokOp:
		p.next()
		v, ok := p.value()
		if !ok {
			return nil
		}
		return &Compare{Path: path, Op: CompareOp(op.text), OpPos: op.span, Value: v, Span: Span{path.Span.Start, v.Span.End}}
	case p.isWord("in"):
		p.next()
		return p.inList(path, false, op.span)
	case p.isWord("not"):
		p.next()
		in, ok := p.expectWord("in")
		if !ok {
			return nil
		}
		return p.inList(path, true, Span{op.span.Start, in.span.End})
	case p.isWord("between"):
		p.next()
		lo, ok := p.value()
		if !ok {
			return nil
		}
		if _, ok := p.expectWord("and"); !ok {
			return nil
		}
		hi, ok := p.value()
		if !ok {
			return nil
		}
		return &Between{Path: path, OpPos: op.span, Lo: lo, Hi: hi, Span: Span{path.Span.Start, hi.Span.End}}
	case p.isWord("is"):
		p.next()
		neg := false
		if p.isWord("not") {
			p.next()
			neg = true
		}
		e, ok := p.expectWord("empty")
		if !ok {
			return nil
		}
		return &IsEmpty{Path: path, Negate: neg, OpPos: Span{op.span.Start, e.span.End}, Span: Span{path.Span.Start, e.span.End}}
	}
	p.fail(op.span, "expected an operator (= != > >= < <= ~ in, not in, between, is empty) after the field, found "+describe(op))
	return nil
}

func (p *parser) inList(path Path, neg bool, opSpan Span) Expr {
	if _, ok := p.expect(tokLParen); !ok {
		return nil
	}
	var vals []Value
	for {
		v, ok := p.value()
		if !ok {
			return nil
		}
		vals = append(vals, v)
		if p.peek().kind != tokComma {
			break
		}
		p.next()
	}
	end, ok := p.expect(tokRParen)
	if !ok {
		return nil
	}
	return &In{Path: path, Negate: neg, OpPos: opSpan, Values: vals, Span: Span{path.Span.Start, end.span.End}}
}

// path is a name, or relation.name.
func (p *parser) path() (Path, bool) {
	t := p.peek()
	if t.kind != tokIdent || reserved[strings.ToLower(t.text)] {
		p.fail(t.span, "expected a field name, found "+describe(t))
		return Path{}, false
	}
	p.next()
	name, span := strings.ToLower(t.text), t.span
	if p.peek().kind == tokDot {
		p.next()
		f, ok := p.expect(tokIdent)
		if !ok {
			return Path{}, false
		}
		name += "." + strings.ToLower(f.text)
		span.End = f.span.End
		if p.peek().kind == tokDot {
			p.fail(p.peek().span, "a path has at most one relation (relation.field)")
			return Path{}, false
		}
	}
	return Path{Name: name, Span: span}, true
}

func (p *parser) value() (Value, bool) {
	t := p.peek()
	switch t.kind {
	case tokString:
		p.next()
		return Value{Kind: ValString, Text: t.text, Span: t.span}, true
	case tokNumber:
		p.next()
		return Value{Kind: ValNumber, Text: t.text, Span: t.span}, true
	case tokRelative:
		p.next()
		return Value{Kind: ValRelative, Text: t.text, Span: t.span}, true
	case tokIdent:
		w := strings.ToLower(t.text)
		if reserved[w] {
			break
		}
		p.next()
		if w == litTrue || w == litFalse {
			return Value{Kind: ValBool, Text: w, Span: t.span}, true
		}
		return Value{Kind: ValIdent, Text: t.text, Span: t.span}, true
	}
	p.fail(t.span, "expected a value, found "+describe(t)+` (quote values that are keywords)`)
	return Value{}, false
}

// stage parses one pipeline stage after "|".
func (p *parser) stage() (Stage, bool) {
	t := p.peek()
	if t.kind != tokIdent {
		p.fail(t.span, "expected a stage (count, stats, bucket, top, sort, limit), found "+describe(t))
		return Stage{}, false
	}
	p.next()
	st := Stage{Span: t.span}
	switch strings.ToLower(t.text) {
	case "count":
		st.Kind = StageCount
		if p.isWord("by") {
			p.next()
			st.By = p.pathList()
		}
	case "stats":
		st.Kind = StageStats
		st.Aggs = p.aggList()
		if p.failed == nil && p.isWord("by") {
			p.next()
			st.By = p.pathList()
		}
	case "bucket":
		st.Kind = StageBucket
		f, ok := p.path()
		if !ok {
			return st, false
		}
		st.Field = f
		if _, ok := p.expectWord("by"); !ok {
			return st, false
		}
		iv, ok := p.expect(tokIdent)
		if !ok {
			return st, false
		}
		switch Interval(strings.ToLower(iv.text)) {
		case IntervalDay, IntervalWeek, IntervalMonth:
			st.Interval = Interval(strings.ToLower(iv.text))
		default:
			p.fail(iv.span, "a bucket is by day, week or month")
			return st, false
		}
	case "top":
		st.Kind = StageTop
		st.N = p.stageNumber()
		if _, ok := p.expectWord("by"); !ok {
			return st, false
		}
		k, ok := p.path()
		if !ok {
			return st, false
		}
		st.Keys = []SortKey{{Name: k, Desc: true}}
	case "sort":
		st.Kind = StageSort
		for {
			k, ok := p.path()
			if !ok {
				return st, false
			}
			key := SortKey{Name: k}
			if p.isWord("desc") {
				p.next()
				key.Desc = true
			} else if p.isWord("asc") {
				p.next()
			}
			st.Keys = append(st.Keys, key)
			if p.peek().kind != tokComma {
				break
			}
			p.next()
		}
	case "limit":
		st.Kind = StageLimit
		st.N = p.stageNumber()
	default:
		p.fail(t.span, "unknown stage "+describe(t)+" (count, stats, bucket, top, sort, limit)")
		return st, false
	}
	if p.failed != nil {
		return st, false
	}
	st.Span.End = p.toks[p.pos-1].span.End
	return st, true
}

func (p *parser) pathList() []Path {
	var out []Path
	for {
		pa, ok := p.path()
		if !ok {
			return nil
		}
		out = append(out, pa)
		if p.peek().kind != tokComma {
			return out
		}
		p.next()
	}
}

func (p *parser) aggList() []Agg {
	var out []Agg
	for {
		fn, ok := p.expect(tokIdent)
		if !ok {
			return nil
		}
		a := Agg{Func: AggFunc(strings.ToLower(fn.text)), Span: fn.span}
		switch a.Func {
		case AggCount, AggDistinct, AggSum, AggAvg, AggMin, AggMax, AggMedian, AggP90:
		default:
			p.fail(fn.span, "unknown aggregate (count, distinct, sum, avg, min, max, median, p90)")
			return nil
		}
		if _, ok := p.expect(tokLParen); !ok {
			return nil
		}
		if p.peek().kind != tokRParen {
			f, ok := p.path()
			if !ok {
				return nil
			}
			a.Field = f
		}
		end, ok := p.expect(tokRParen)
		if !ok {
			return nil
		}
		a.Span.End = end.span.End
		if p.isWord("as") {
			p.next()
			n, ok := p.expect(tokIdent)
			if !ok {
				return nil
			}
			if reserved[strings.ToLower(n.text)] {
				p.fail(n.span, "a reserved word cannot be a name")
				return nil
			}
			a.As = strings.ToLower(n.text)
			a.Span.End = n.span.End
		}
		out = append(out, a)
		if p.peek().kind != tokComma {
			return out
		}
		p.next()
	}
}

func (p *parser) stageNumber() int {
	t := p.peek()
	if t.kind != tokNumber || strings.ContainsAny(t.text, ".-") {
		p.fail(t.span, "expected a whole number")
		return 0
	}
	p.next()
	n, err := strconv.Atoi(t.text)
	if err != nil || n > maxStageNumber {
		p.fail(t.span, "number too large")
		return 0
	}
	return n
}
