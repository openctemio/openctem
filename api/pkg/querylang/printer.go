package querylang

import (
	"strconv"
	"strings"
)

// Format renders a query in canonical form: lower-case keywords, single
// spaces, minimal parentheses, strings double-quoted. Parse(Format(q))
// equals q (ignoring spans), so a builder and a text editor can share one
// document.
func Format(q *Query) string {
	var b strings.Builder
	b.WriteString(q.Entity)
	if q.Where != nil {
		b.WriteString(" where ")
		writeExpr(&b, q.Where, 0)
	}
	for _, st := range q.Pipeline {
		b.WriteString(" | ")
		writeStage(&b, st)
	}
	return b.String()
}

// precedence: or 1, and 2, not 3, terms 4.
func precOf(e Expr) int {
	switch x := e.(type) {
	case *Logic:
		if x.Kind == Or {
			return 1
		}
		return 2
	case *Not:
		return 3
	}
	return 4
}

func writeExpr(b *strings.Builder, e Expr, parent int) {
	paren := precOf(e) <= parent
	if paren {
		b.WriteByte('(')
	}
	switch x := e.(type) {
	case *Logic:
		word := " and "
		if x.Kind == Or {
			word = " or "
		}
		for i, t := range x.Terms {
			if i > 0 {
				b.WriteString(word)
			}
			writeExpr(b, t, precOf(e))
		}
	case *Not:
		b.WriteString("not ")
		// A not over a not or a term needs no parentheses.
		writeExpr(b, x.X, 2)
	case *Compare:
		b.WriteString(x.Path.Name + " " + string(x.Op) + " ")
		writeValue(b, x.Value)
	case *In:
		b.WriteString(x.Path.Name)
		if x.Negate {
			b.WriteString(" not")
		}
		b.WriteString(" in (")
		for i, v := range x.Values {
			if i > 0 {
				b.WriteString(", ")
			}
			writeValue(b, v)
		}
		b.WriteByte(')')
	case *Between:
		b.WriteString(x.Path.Name + " between ")
		writeValue(b, x.Lo)
		b.WriteString(" and ")
		writeValue(b, x.Hi)
	case *IsEmpty:
		b.WriteString(x.Path.Name + " is ")
		if x.Negate {
			b.WriteString("not ")
		}
		b.WriteString("empty")
	case *Text:
		b.WriteString("text ~ ")
		writeValue(b, x.Value)
	}
	if paren {
		b.WriteByte(')')
	}
}

func writeValue(b *strings.Builder, v Value) {
	switch v.Kind {
	case ValString:
		b.WriteString(Quote(v.Text))
	default:
		b.WriteString(v.Text)
	}
}

// Quote double-quotes s with the language's two escapes.
func Quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func writePaths(b *strings.Builder, ps []Path) {
	for i, p := range ps {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(p.Name)
	}
}

func writeStage(b *strings.Builder, st Stage) {
	switch st.Kind {
	case StageCount:
		b.WriteString("count")
		if len(st.By) > 0 {
			b.WriteString(" by ")
			writePaths(b, st.By)
		}
	case StageStats:
		b.WriteString("stats ")
		for i, a := range st.Aggs {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(string(a.Func) + "(" + a.Field.Name + ")")
			if a.As != "" {
				b.WriteString(" as " + a.As)
			}
		}
		if len(st.By) > 0 {
			b.WriteString(" by ")
			writePaths(b, st.By)
		}
	case StageBucket:
		b.WriteString("bucket " + st.Field.Name + " by " + string(st.Interval))
	case StageTop:
		b.WriteString("top " + strconv.Itoa(st.N) + " by ")
		if len(st.Keys) > 0 {
			b.WriteString(st.Keys[0].Name.Name)
		}
	case StageSort:
		b.WriteString("sort ")
		for i, k := range st.Keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(k.Name.Name)
			if k.Desc {
				b.WriteString(" desc")
			}
		}
	case StageLimit:
		b.WriteString("limit " + strconv.Itoa(st.N))
	}
}
