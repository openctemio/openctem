package querylang

import "strings"

// RedactedValue stands in for a literal Redact hides.
const RedactedValue = "***"

// Redact returns a stored query with the literals a reader outside its
// author's data scope must not learn replaced by RedactedValue: names,
// addresses, ids, free text and any other quoted or bare word. The entity,
// the field paths, the operators, the pipeline, how many values a list
// holds, and the values that name nothing (numbers, booleans, relative
// times and ages, "me", and the members of an enum field) are kept, so the
// query still reads as what it selects. The result parses.
//
// ok is false when src does not parse: the caller then shows no text at
// all (fail closed).
func Redact(src string) (string, bool) {
	q, err := Parse(src)
	if err != nil {
		return "", false
	}
	ent, _ := Lookup(q.Entity)
	q.Where = redactExpr(ent, q.Where)
	return Format(q), true
}

func redactExpr(ent *Entity, e Expr) Expr {
	switch x := e.(type) {
	case *Logic:
		for i, t := range x.Terms {
			x.Terms[i] = redactExpr(ent, t)
		}
	case *Not:
		x.X = redactExpr(ent, x.X)
	case *Compare:
		x.Value = redactValue(ent, x.Path, x.Value)
	case *In:
		for i, v := range x.Values {
			x.Values[i] = redactValue(ent, x.Path, v)
		}
	case *Between:
		x.Lo = redactValue(ent, x.Path, x.Lo)
		x.Hi = redactValue(ent, x.Path, x.Hi)
	case *Text:
		x.Value = Value{Kind: ValString, Text: RedactedValue}
	}
	return e
}

func redactValue(ent *Entity, p Path, v Value) Value {
	switch v.Kind {
	case ValNumber, ValBool, ValRelative, ValAge:
		return v
	case ValIdent:
		if strings.EqualFold(v.Text, "me") || isEnumMember(ent, p, v.Text) {
			return v
		}
	}
	return Value{Kind: ValString, Text: RedactedValue}
}

// isEnumMember reports whether text is one of the fixed values of the enum
// field at path (a severity, a status): such a value names nothing.
func isEnumMember(ent *Entity, p Path, text string) bool {
	if ent == nil {
		return false
	}
	f, ok := ent.field(strings.ToLower(p.Name), func(string) bool { return true })
	if !ok || len(f.Enum) == 0 {
		return false
	}
	for _, m := range f.Enum {
		if strings.EqualFold(m, text) {
			return true
		}
	}
	return false
}
