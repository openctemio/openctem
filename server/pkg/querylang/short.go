package querylang

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// The short form of a filter: what people type in a search box.
//
//	severity>=high kev=true -status:accepted asset.domain=*.example.com log4j
//
// It is a second spelling of the filter part of the language and parses
// to the same AST, so Build, the plan layer and the executors treat it
// exactly like the long form. Grammar and rules:
// docs/architecture/query-language.md, "Short form".

// Form is how a search box text was written.
type Form string

// Forms.
const (
	FormShort Form = "short"
	FormLong  Form = "long"
)

// Error codes of query problems. Clients translate the code; the message
// is the English text.
const (
	CodeSyntax       = "syntax"
	CodeUnknownField = "unknown_field"
	CodeOperator     = "operator_not_allowed"
	CodeBadValue     = "bad_value"
	CodeUnknownValue = "unknown_value"
	CodePattern      = "pattern_not_allowed"
	CodeWrongEntity  = "wrong_entity"
	CodePipeline     = "pipeline_not_allowed"
	CodeTooComplex   = "too_complex"
	CodeInvalid      = "invalid"
)

// Short form tokens and limits.
const (
	minContainsRunes    = 3
	maxBareWordBytes    = 256
	shortKeywordAnd     = "and"
	shortKeywordOr      = "or"
	shortKeywordNot     = "not"
	shortKeywordIs      = "is"
	shortKeywordEmpty   = "empty"
	shortRangeSeparator = ".."
	shortListSeparator  = ','
	shortNegationPrefix = '-'
	shortQuote          = '"'
	shortOpenParen      = '('
	shortCloseParen     = ')'
)

var (
	shortNumberRE = regexp.MustCompile(`^-?[0-9]{1,18}(\.[0-9]{1,6})?$`)
	shortAgeRE    = regexp.MustCompile(`^[0-9]{1,6}(m|h|d|w|mo|y)$`)
	shortRelRE    = regexp.MustCompile(`^-[0-9]{1,6}(m|h|d|w|mo|y)$`)
	shortIdentRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	cveRE         = regexp.MustCompile(`^(?i)CVE-[0-9]{4}-[0-9]{4,7}$`)
)

// ParseFilter parses the text of a search box on ent: the short form, or
// the long form when the text starts with an entity name or "where". The
// result is a Query on ent with no pipeline. Errors are *Error with codes
// and positions.
func ParseFilter(ent *Entity, src string) (*Query, Form, error) {
	if isLongForm(src) {
		q, err := Parse(src)
		if err != nil {
			return nil, FormLong, err
		}
		var el errList
		switch {
		case q.Entity != ent.Name:
			el.addc(q.EntitySpan, CodeWrongEntity, "this search box searches "+ent.Name, nil)
		case len(q.Pipeline) > 0:
			el.addc(Span{max(0, strings.LastIndex(src[:q.Pipeline[0].Span.Start], "|")), len(src)}, CodePipeline, `a search box takes a filter; "|" stages run in a query`, nil)
		}
		if err := el.err(src); err != nil {
			return nil, FormLong, err
		}
		return q, FormLong, nil
	}
	q, err := ParseShort(ent, src)
	return q, FormShort, err
}

// isLongForm reports whether src starts with an entity name or "where"
// (followed by a space or the end).
func isLongForm(src string) bool {
	s := strings.TrimLeft(src, " \t\r\n")
	i := 0
	for i < len(s) && isIdentPart(s[i]) {
		i++
	}
	if i == 0 || (i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r') {
		return false
	}
	w := strings.ToLower(s[:i])
	if w == "where" {
		return true
	}
	_, ok := entities[w]
	return ok
}

// ParseShort parses the short form of a filter on ent. Empty text is a
// query with no filter.
func ParseShort(ent *Entity, src string) (*Query, error) {
	if len(src) > MaxQueryBytes {
		return nil, locatedErr(src, Span{0, len(src)}, CodeSyntax, "the query is too long")
	}
	if !utf8.ValidString(src) {
		return nil, locatedErr(src, Span{0, len(src)}, CodeSyntax, "the query is not valid UTF-8")
	}
	for i := 0; i < len(src); i++ {
		if c := src[i]; (c < 0x20 && c != ' ' && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return nil, locatedErr(src, Span{i, i + 1}, CodeSyntax, "control characters are not allowed")
		}
	}
	p := &shortParser{src: src, ent: ent}
	q := &Query{Entity: ent.Name}
	p.skipWS()
	if p.atEnd() {
		return q, nil
	}
	q.Where = p.orExpr()
	if p.failed == nil {
		p.skipWS()
		if !p.atEnd() {
			p.fail(Span{p.pos, p.pos + 1}, `unexpected ")"`)
		}
	}
	if p.failed != nil {
		locate(p.failed, src)
		return nil, p.failed
	}
	return q, nil
}

func locatedErr(src string, s Span, code, msg string) *Error {
	e := &Error{Details: []ErrorDetail{{Code: code, Message: msg, Span: s}}}
	locate(e, src)
	return e
}

type shortParser struct {
	src    string
	pos    int
	ent    *Entity
	depth  int
	terms  int
	failed *Error
}

func (p *shortParser) fail(s Span, msg string) {
	if p.failed == nil {
		p.failed = &Error{Details: []ErrorDetail{{Code: CodeSyntax, Message: msg, Span: s}}}
	}
	p.pos = len(p.src)
}

func (p *shortParser) atEnd() bool { return p.pos >= len(p.src) }

func (p *shortParser) skipWS() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

// keyword reports whether the word w (any case) starts at the position
// and ends at a space, a parenthesis or the end.
func (p *shortParser) keyword(w string) bool {
	end := p.pos + len(w)
	if end > len(p.src) || !strings.EqualFold(p.src[p.pos:end], w) {
		return false
	}
	return end == len(p.src) || isBoundary(p.src[end])
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isBoundary(c byte) bool {
	return isSpace(c) || c == shortOpenParen || c == shortCloseParen
}

func (p *shortParser) enter() bool {
	p.depth++
	if p.depth > MaxNesting {
		p.fail(Span{p.pos, p.pos + 1}, "nested too deep")
		return false
	}
	return true
}

func (p *shortParser) orExpr() Expr {
	terms := []Expr{p.andExpr()}
	for p.failed == nil {
		p.skipWS()
		if !p.keyword(shortKeywordOr) {
			break
		}
		kw := Span{p.pos, p.pos + 2}
		p.pos += 2
		p.skipWS()
		if p.atEnd() || p.src[p.pos] == shortCloseParen {
			p.fail(kw, "OR needs a condition after it")
			return nil
		}
		x := p.andExpr()
		if p.failed != nil {
			return nil
		}
		if x == nil {
			p.fail(kw, "OR needs a condition after it")
			return nil
		}
		terms = flattenInto(terms, Or, x)
	}
	if p.failed != nil || terms[0] == nil {
		return nil
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return &Logic{Kind: Or, Terms: flattenInto(nil, Or, &Logic{Kind: Or, Terms: terms}), Span: Span{terms[0].exprSpan().Start, terms[len(terms)-1].exprSpan().End}}
}

// andExpr reads conditions until the end, ")" or OR. Juxtaposition and
// AND both join with and; adjacent bare words are one text search.
func (p *shortParser) andExpr() Expr {
	var terms []Expr
	for p.failed == nil {
		p.skipWS()
		if p.atEnd() || p.src[p.pos] == shortCloseParen || p.keyword(shortKeywordOr) {
			break
		}
		if p.keyword(shortKeywordAnd) {
			kw := Span{p.pos, p.pos + 3}
			p.pos += 3
			p.skipWS()
			if p.atEnd() || p.src[p.pos] == shortCloseParen || p.keyword(shortKeywordOr) || len(terms) == 0 {
				p.fail(kw, "AND needs a condition on each side")
				return nil
			}
			continue
		}
		x := p.unary()
		if p.failed != nil {
			return nil
		}
		terms = append(terms, x)
	}
	if p.failed != nil {
		return nil
	}
	terms = mergeText(terms)
	switch len(terms) {
	case 0:
		if p.atEnd() || p.src[p.pos] == shortCloseParen {
			p.fail(Span{p.pos, min(p.pos+1, len(p.src))}, "expected a condition")
		} else {
			p.fail(Span{p.pos, min(p.pos+2, len(p.src))}, "expected a condition before OR")
		}
		return nil
	case 1:
		return terms[0]
	}
	return &Logic{Kind: And, Terms: flattenInto(nil, And, &Logic{Kind: And, Terms: terms}), Span: Span{terms[0].exprSpan().Start, terms[len(terms)-1].exprSpan().End}}
}

// mergeText joins the bare words of one AND group into one text search
// at the place of the first, the way the search box has always read plain
// text ("log4j severity=high apache" searches "log4j apache").
func mergeText(terms []Expr) []Expr {
	out := make([]Expr, 0, len(terms))
	first := -1
	for _, t := range terms {
		cur, ok := t.(*Text)
		if !ok || !cur.Bare {
			out = append(out, t)
			continue
		}
		if first < 0 {
			first = len(out)
			c := *cur
			out = append(out, &c)
			continue
		}
		m := out[first].(*Text)
		m.Value.Text += " " + cur.Value.Text
		m.Value.Span.End = cur.Value.Span.End
		m.Span.End = cur.Span.End
	}
	return out
}

func (p *shortParser) unary() Expr {
	start := p.pos
	negate := false
	switch {
	case p.src[p.pos] == shortNegationPrefix && p.pos+1 < len(p.src) && !isSpace(p.src[p.pos+1]):
		p.pos++
		negate = true
	case p.keyword(shortKeywordNot):
		p.pos += 3
		p.skipWS()
		if p.atEnd() {
			p.fail(Span{start, p.pos}, "NOT needs a condition after it")
			return nil
		}
		negate = true
	}
	if !negate {
		return p.primary()
	}
	if !p.enter() {
		return nil
	}
	p.skipWS()
	grouped := !p.atEnd() && p.src[p.pos] == shortOpenParen
	x := p.unary()
	p.depth--
	if p.failed != nil {
		return nil
	}
	if grouped {
		// -(...) is kept as written: a negated group.
		return &Not{X: x, Span: Span{start, x.exprSpan().End}}
	}
	return negateExpr(x, Span{start, x.exprSpan().End})
}

// negateExpr negates x, keeping a negated condition a single condition
// where one exists (not equal, not in, is not empty), so it stays a chip.
func negateExpr(x Expr, s Span) Expr {
	switch n := x.(type) {
	case *Compare:
		if n.Op == OpEq && !n.Implicit {
			c := *n
			c.Op, c.Span = OpNe, s
			return &c
		}
	case *In:
		c := *n
		c.Negate, c.Span = !n.Negate, s
		return &c
	case *IsEmpty:
		c := *n
		c.Negate, c.Span = !n.Negate, s
		return &c
	case *Not:
		return n.X
	}
	return &Not{X: x, Span: s}
}

func (p *shortParser) primary() Expr {
	c := p.src[p.pos]
	switch c {
	case shortOpenParen:
		open := p.pos
		p.pos++
		if !p.enter() {
			return nil
		}
		x := p.orExpr()
		p.depth--
		if p.failed != nil {
			return nil
		}
		p.skipWS()
		if p.atEnd() || p.src[p.pos] != shortCloseParen {
			p.fail(Span{open, open + 1}, `"(" is not closed`)
			return nil
		}
		p.pos++
		return x
	case shortCloseParen:
		p.fail(Span{p.pos, p.pos + 1}, `unexpected ")"`)
		return nil
	case shortQuote:
		v, ok := p.quoted()
		if !ok {
			return nil
		}
		return p.count(&Text{Value: v, Span: v.Span})
	}
	// An address ("fe80::1") is a bare word even though it looks like
	// "name:value".
	if _, _, typed := p.ent.typeBare(p.peekBare(), Span{}); !typed {
		if x, ok := p.condition(); ok || p.failed != nil {
			return p.count(x)
		}
	}
	return p.count(p.bare())
}

// count bounds the conditions of one search (filterspec bounds the leaves
// again after Build).
func (p *shortParser) count(x Expr) Expr {
	if x == nil {
		return nil
	}
	p.terms++
	if p.terms > filterspec.MaxLeaves {
		p.fail(x.exprSpan(), "too many conditions")
		return nil
	}
	return x
}

func (p *shortParser) quoted() (Value, bool) {
	s, n, err := lexString(p.src, p.pos)
	if err != nil {
		qe, _ := AsError(err)
		p.fail(qe.Details[0].Span, qe.Details[0].Message)
		return Value{}, false
	}
	v := Value{Kind: ValString, Text: s, Span: Span{p.pos, n}}
	p.pos = n
	return v, true
}

// readPath reads name or relation.name at the position.
func (p *shortParser) readPath() (Path, bool) {
	start, i := p.pos, p.pos
	readIdent := func() bool {
		if i >= len(p.src) || !isIdentStart(p.src[i]) {
			return false
		}
		for i < len(p.src) && isIdentPart(p.src[i]) {
			i++
		}
		return true
	}
	if !readIdent() {
		return Path{}, false
	}
	if i+1 < len(p.src) && p.src[i] == '.' && isIdentStart(p.src[i+1]) {
		i++
		readIdent()
	}
	if i-start > 64 {
		return Path{}, false
	}
	return Path{Name: strings.ToLower(p.src[start:i]), Span: Span{start, i}}, true
}

var shortOps = []struct {
	text string
	op   CompareOp
}{{">=", OpGte}, {"<=", OpLte}, {"!=", OpNe}, {">", OpGt}, {"<", OpLt}, {"=", OpEq}, {":", OpEq}, {"~", OpContains}}

// condition reads "path op values" or "path is [not] empty". ok is false
// (and the position unchanged) when the text there is not a condition.
func (p *shortParser) condition() (Expr, bool) {
	start := p.pos
	path, ok := p.readPath()
	if !ok {
		return nil, false
	}
	p.pos = path.Span.End
	p.skipWS()
	if p.keyword(shortKeywordIs) {
		return p.isEmpty(path)
	}
	for _, o := range shortOps {
		if strings.HasPrefix(p.src[p.pos:], o.text) {
			opSpan := Span{p.pos, p.pos + len(o.text)}
			p.pos = opSpan.End
			return p.values(path, o.op, o.text == ":" || o.text == "=" || o.text == "!=", opSpan), true
		}
	}
	p.pos = start
	return nil, false
}

func (p *shortParser) isEmpty(path Path) (Expr, bool) {
	opStart := p.pos
	p.pos += 2
	p.skipWS()
	neg := false
	if p.keyword(shortKeywordNot) {
		p.pos += 3
		p.skipWS()
		neg = true
	}
	if !p.keyword(shortKeywordEmpty) {
		// "name is ..." that is not "is empty": not a condition.
		p.pos = path.Span.Start
		return nil, false
	}
	p.pos += len(shortKeywordEmpty)
	return &IsEmpty{Path: path, Negate: neg, OpPos: Span{opStart, p.pos}, Span: Span{path.Span.Start, p.pos}}, true
}

// values reads the value(s) after an operator: a comma list for the
// equality operators, a range lo..hi for = and :, one value otherwise.
func (p *shortParser) values(path Path, op CompareOp, list bool, opSpan Span) Expr {
	p.skipWS()
	var vals []Value
	for {
		v, ok := p.value(opSpan)
		if !ok {
			return nil
		}
		vals = append(vals, v)
		if p.pos >= len(p.src) || p.src[p.pos] != shortListSeparator {
			break
		}
		if !list {
			p.fail(Span{p.pos, p.pos + 1}, "a list of values takes = or :")
			return nil
		}
		p.pos++
		if len(vals) >= filterspec.MaxValuesDocument {
			p.fail(Span{p.pos - 1, p.pos}, "too many values")
			return nil
		}
	}
	span := Span{path.Span.Start, vals[len(vals)-1].Span.End}
	if len(vals) == 1 && vals[0].Kind != ValString && op == OpEq {
		if lo, hi, isRange := splitRange(vals[0]); isRange {
			return p.rangeExpr(path, opSpan, lo, hi, span)
		}
	}
	for _, v := range vals {
		if v.Kind != ValString && strings.Contains(v.Text, shortRangeSeparator) && len(vals) > 1 {
			p.fail(v.Span, "a range (lo..hi) cannot be part of a list")
			return nil
		}
	}
	switch {
	case len(vals) == 1:
		return &Compare{Path: path, Op: op, OpPos: opSpan, Value: vals[0], Span: span}
	case op == OpNe:
		return &In{Path: path, Negate: true, OpPos: opSpan, Values: vals, Span: span}
	}
	return &In{Path: path, OpPos: opSpan, Values: vals, Span: span}
}

func (p *shortParser) rangeExpr(path Path, opSpan Span, lo, hi Value, span Span) Expr {
	switch {
	case lo.Text == "" && hi.Text == "":
		p.fail(span, "a range needs a low or a high end (lo..hi)")
		return nil
	case lo.Text == "":
		return &Compare{Path: path, Op: OpLte, OpPos: opSpan, Value: hi, Span: span}
	case hi.Text == "":
		return &Compare{Path: path, Op: OpGte, OpPos: opSpan, Value: lo, Span: span}
	}
	return &Between{Path: path, OpPos: opSpan, Lo: lo, Hi: hi, Span: span}
}

// splitRange splits a bare "lo..hi" value.
func splitRange(v Value) (lo, hi Value, ok bool) {
	i := strings.Index(v.Text, shortRangeSeparator)
	if i < 0 {
		return Value{}, Value{}, false
	}
	l, h := v.Text[:i], v.Text[i+len(shortRangeSeparator):]
	if strings.Contains(h, shortRangeSeparator) {
		return Value{}, Value{}, false
	}
	lo = classifyWord(l, Span{v.Span.Start, v.Span.Start + i})
	hi = classifyWord(h, Span{v.Span.Start + i + len(shortRangeSeparator), v.Span.End})
	return lo, hi, true
}

// value reads one quoted or bare value.
func (p *shortParser) value(opSpan Span) (Value, bool) {
	if p.pos < len(p.src) && p.src[p.pos] == shortQuote {
		return p.quoted()
	}
	start := p.pos
	for p.pos < len(p.src) && !isBoundary(p.src[p.pos]) && p.src[p.pos] != shortListSeparator && p.src[p.pos] != shortQuote {
		p.pos++
	}
	if p.pos == start {
		p.fail(Span{opSpan.Start, opSpan.End}, "expected a value after the operator")
		return Value{}, false
	}
	if p.pos-start > maxBareWordBytes {
		p.fail(Span{start, p.pos}, "value too long")
		return Value{}, false
	}
	return classifyWord(p.src[start:p.pos], Span{start, p.pos}), true
}

// classifyWord gives a bare value its lexical kind.
func classifyWord(w string, s Span) Value {
	lw := strings.ToLower(w)
	switch {
	case w == "":
		return Value{Kind: ValWord, Span: s}
	case lw == litTrue || lw == litFalse:
		return Value{Kind: ValBool, Text: lw, Span: s}
	case shortNumberRE.MatchString(w):
		return Value{Kind: ValNumber, Text: w, Span: s}
	case shortAgeRE.MatchString(lw):
		return Value{Kind: ValAge, Text: lw, Span: s}
	case shortRelRE.MatchString(lw):
		return Value{Kind: ValRelative, Text: lw, Span: s}
	case shortIdentRE.MatchString(w) && !reserved[lw]:
		return Value{Kind: ValIdent, Text: w, Span: s}
	}
	return Value{Kind: ValWord, Text: w, Span: s}
}

// peekBare returns the bare word at the position without consuming it.
func (p *shortParser) peekBare() string {
	i := p.pos
	for i < len(p.src) && !isBoundary(p.src[i]) && p.src[i] != shortQuote {
		i++
	}
	return p.src[p.pos:i]
}

// bare reads a bare word: a typed condition when it is an address, a
// range or a CVE id and the entity types those, a text search otherwise.
func (p *shortParser) bare() Expr {
	start := p.pos
	for p.pos < len(p.src) && !isBoundary(p.src[p.pos]) && p.src[p.pos] != shortQuote {
		p.pos++
	}
	w := p.src[start:p.pos]
	s := Span{start, p.pos}
	if len(w) > maxBareWordBytes {
		p.fail(s, "word too long")
		return nil
	}
	if path, v, ok := p.ent.typeBare(w, s); ok {
		return &Compare{Path: path, Op: OpEq, OpPos: s, Value: v, Span: s, Implicit: true}
	}
	return &Text{Value: Value{Kind: ValString, Text: w, Span: s}, Span: s, Bare: true}
}

// typeBare types a bare word: an IP address or CIDR range is the entity's
// address path, a CVE id its CVE path.
func (e *Entity) typeBare(w string, s Span) (Path, Value, bool) {
	if e.bareIP != "" && strings.ContainsAny(w, ".:") {
		if canon, err := filterspec.ParseInet(w); err == nil {
			return Path{Name: e.bareIP, Span: s}, Value{Kind: ValWord, Text: canon, Span: s}, true
		}
	}
	if e.bareCVE != "" && cveRE.MatchString(w) {
		return Path{Name: e.bareCVE, Span: s}, Value{Kind: ValWord, Text: strings.ToUpper(w), Span: s}, true
	}
	return Path{}, Value{}, false
}
