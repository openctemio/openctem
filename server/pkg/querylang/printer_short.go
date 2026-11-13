package querylang

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// FormatShort renders the filter of q in the canonical short form:
// canonical paths, "=" for one value and ":" for a list, ages for relative
// times ("last_seen_at<7d"), "field>=high" for an ordered enum list that is
// a top or bottom run of its values, "-" for negation, OR in capitals and
// the fewest parentheses. ParseShort of the result builds the same filter
// document.
func FormatShort(ent *Entity, q *Query) string {
	if q == nil || q.Where == nil {
		return ""
	}
	w := &shortWriter{ent: ent}
	w.expr(q.Where, 0)
	return w.b.String()
}

type shortWriter struct {
	ent *Entity
	b   strings.Builder
}

// Precedence: OR 1, AND 2, negation and terms 3.
func shortPrec(e Expr) int {
	if l, ok := e.(*Logic); ok {
		if l.Kind == Or {
			return 1
		}
		return 2
	}
	return 3
}

func (w *shortWriter) expr(e Expr, parent int) {
	paren := shortPrec(e) <= parent
	if paren {
		w.b.WriteByte('(')
	}
	switch x := e.(type) {
	case *Logic:
		sep := " "
		if x.Kind == Or {
			sep = " OR "
		}
		texts := 0
		for _, t := range x.Terms {
			if _, ok := t.(*Text); ok {
				texts++
			}
		}
		for i, t := range x.Terms {
			if i > 0 {
				w.b.WriteString(sep)
			}
			if tx, ok := t.(*Text); ok && x.Kind == And && texts > 1 {
				// Two text searches side by side would read back as one.
				w.b.WriteString(Quote(tx.Value.Text))
				continue
			}
			w.expr(t, shortPrec(e))
		}
	case *Not:
		// "-(...)" always: a bare "-" would fold into the condition.
		w.b.WriteString("-(")
		w.expr(x.X, 0)
		w.b.WriteByte(')')
	case *Text:
		w.text(x.Value.Text)
	case *Compare:
		w.compare(x)
	case *In:
		w.in(x)
	case *Between:
		f := w.field(x.Path.Name)
		w.b.WriteString(w.path(x.Path.Name) + ":" + w.value(f, x.Lo) + shortRangeSeparator + w.value(f, x.Hi))
	case *IsEmpty:
		w.b.WriteString(w.path(x.Path.Name) + " is ")
		if x.Negate {
			w.b.WriteString("not ")
		}
		w.b.WriteString("empty")
	}
	if paren {
		w.b.WriteByte(')')
	}
}

func (w *shortWriter) path(p string) string {
	c := w.ent.Canonical(p)
	if name := w.ent.fieldName(c); name != "" {
		return w.ent.pathOf(name)
	}
	return c
}

func (w *shortWriter) field(p string) *filterspec.Field {
	f, _ := w.ent.Registry.Field(w.ent.fieldName(w.ent.Canonical(p)))
	return f
}

// flipAge maps a comparison of a time with an instant "now - d" to the
// comparison of the age with d: "after 7 days ago" is "less than 7 days old".
var flipAge = map[CompareOp]CompareOp{OpGt: OpLt, OpGte: OpLte, OpLt: OpGt, OpLte: OpGte}

func (w *shortWriter) compare(x *Compare) {
	f := w.field(x.Path.Name)
	path := w.path(x.Path.Name)
	if f != nil && f.Type == filterspec.TypeTime {
		if age, ok := relativeAge(x.Value); ok {
			if op, flips := flipAge[x.Op]; flips {
				w.b.WriteString(path + string(op) + age)
				return
			}
		}
	}
	w.b.WriteString(path + string(x.Op) + w.value(f, x.Value))
}

func (w *shortWriter) in(x *In) {
	f := w.field(x.Path.Name)
	path := w.path(x.Path.Name)
	if !x.Negate && f != nil && f.Ordered && len(x.Values) < len(f.Enum) {
		if op, v, ok := orderedRun(f, x.Values); ok {
			w.b.WriteString(path + op + v)
			return
		}
	}
	if x.Negate {
		w.b.WriteByte('-')
	}
	w.b.WriteString(path + ":")
	for i, v := range x.Values {
		if i > 0 {
			w.b.WriteByte(shortListSeparator)
		}
		w.b.WriteString(w.value(f, v))
	}
}

// orderedRun returns ">=" v when vals are exactly the values from the
// highest down to v, "<=" v when they are v and every lower value.
func orderedRun(f *filterspec.Field, vals []Value) (string, string, bool) {
	set := make(map[string]bool, len(vals))
	for _, v := range vals {
		set[strings.ToLower(v.Text)] = true
	}
	if len(set) != len(vals) || len(vals) == 0 {
		return "", "", false
	}
	n := len(vals)
	match := func(run []string) bool {
		for _, e := range run {
			if !set[strings.ToLower(e)] {
				return false
			}
		}
		return true
	}
	if match(f.Enum[:n]) {
		return ">=", f.Enum[n-1], true
	}
	if match(f.Enum[len(f.Enum)-n:]) {
		return "<=", f.Enum[len(f.Enum)-n], true
	}
	return "", "", false
}

var isoAgeRE = regexp.MustCompile(`^-P(?:([0-9]{1,6})([DW])|T([0-9]{1,7})([HM]))$`)

// relativeAge returns the age form ("7d") of a relative time value: the
// short form "-7d" or the document form "-P7D".
func relativeAge(v Value) (string, bool) {
	if v.Kind == ValRelative {
		return strings.TrimPrefix(v.Text, "-"), true
	}
	if v.Kind == ValAge {
		return v.Text, false
	}
	m := isoAgeRE.FindStringSubmatch(v.Text)
	if m == nil {
		return "", false
	}
	if m[1] != "" {
		return m[1] + strings.ToLower(m[2]), true
	}
	return m[3] + strings.ToLower(m[4]), true
}

// value prints a value bare when it reads back as the same value, quoted
// otherwise.
func (w *shortWriter) value(f *filterspec.Field, v Value) string {
	switch v.Kind {
	case ValBool, ValNumber, ValAge, ValRelative:
		return v.Text
	}
	if bareSafe(f, v.Text) {
		return v.Text
	}
	return Quote(v.Text)
}

func bareSafe(f *filterspec.Field, s string) bool {
	if s == "" || len(s) > maxBareWordBytes || s[0] == shortNegationPrefix || strings.Contains(s, shortRangeSeparator) ||
		strings.ContainsAny(s, " \t\r\n\"(),\\") {
		return false
	}
	if strings.ContainsAny(s, "*?") && (f == nil || !f.Glob) {
		return false
	}
	switch classifyWord(s, Span{}).Kind {
	case ValBool:
		return f != nil && f.Type == filterspec.TypeBool
	case ValAge, ValRelative:
		return f == nil || f.Type != filterspec.TypeTime
	}
	return true
}

// text prints a text search bare when every word reads back as text.
func (w *shortWriter) text(s string) {
	words := strings.Fields(s)
	ok := len(words) > 0 && strings.Join(words, " ") == s
	for _, word := range words {
		if !ok {
			break
		}
		lw := strings.ToLower(word)
		if lw == shortKeywordAnd || lw == shortKeywordOr || lw == shortKeywordNot || word[0] == shortNegationPrefix ||
			strings.ContainsAny(word, "\"():=<>!~,") || len(word) > maxBareWordBytes {
			ok = false
			break
		}
		if _, _, typed := w.ent.typeBare(word, Span{}); typed {
			ok = false
		}
	}
	if ok {
		w.b.WriteString(s)
		return
	}
	w.b.WriteString(Quote(s))
}

// FromDocument returns the query on ent of a version 1 filter document as
// stored or sent ({"v":1,"filter":...,"q":...}): relative times stay
// relative. The document is checked with filterspec first (strict); sort
// and page are ignored.
func FromDocument(ent *Entity, doc map[string]any) (*Query, error) {
	clean := map[string]any{"v": filterspec.DocumentVersion}
	if f, ok := doc["filter"]; ok && f != nil {
		clean["filter"] = f
	}
	if q, ok := doc["q"]; ok {
		clean["q"] = q
	}
	spec, err := filterspec.ParseDocumentValue(clean, ent.Registry, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		return nil, err
	}
	q := &Query{Entity: ent.Name}
	var terms []Expr
	if raw, ok := clean["filter"].(map[string]any); ok && isNodeDoc(raw) {
		terms = append(terms, rawNode(ent, raw))
	} else if spec.Root != nil {
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
	return q, nil
}

// Document node keys.
const (
	docAll   = "all"
	docAny   = "any"
	docNot   = "not"
	docField = "field"
)

func isNodeDoc(m map[string]any) bool {
	for _, k := range []string{docAll, docAny, docNot, docField} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// rawNode converts a checked document node, keeping values as written.
func rawNode(ent *Entity, m map[string]any) Expr {
	if x, ok := m[docNot].(map[string]any); ok {
		return &Not{X: rawNode(ent, x)}
	}
	kind, kids := And, m[docAll]
	if a, ok := m[docAny]; ok {
		kind, kids = Or, a
	}
	if list, ok := kids.([]any); ok {
		var terms []Expr
		for _, k := range list {
			if km, ok := k.(map[string]any); ok {
				terms = flattenInto(terms, kind, rawNode(ent, km))
			}
		}
		if len(terms) == 1 {
			return terms[0]
		}
		return &Logic{Kind: kind, Terms: terms}
	}
	field, _ := m[docField].(string)
	op, _ := m["op"].(string)
	var vals []any
	switch v := m["value"].(type) {
	case []any:
		vals = v
	default:
		vals = []any{v}
	}
	for i, v := range vals {
		if n, ok := v.(json.Number); ok {
			if iv, err := strconv.ParseInt(n.String(), 10, 64); err == nil {
				vals[i] = iv
			} else if fv, err := n.Float64(); err == nil {
				vals[i] = fv
			}
		}
	}
	return fromLeaf(ent, &filterspec.Leaf{Field: field, Op: filterspec.Op(op), Values: vals})
}
