package ticketmap

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The template language is deliberately tiny: text with {{ path | filter }}
// placeholders. Paths come only from the attribute catalog of the profile's
// object kind; filters come from a fixed list. There are no loops,
// conditionals, function calls, includes or variables, so a template can
// only read the values the caller already put in front of it.

// Template is a parsed template.
type Template struct {
	parts []tmplPart
}

type tmplPart struct {
	text    string // literal text (when path == "")
	path    string
	filters []tmplFilter
}

type tmplFilter struct {
	name string
	arg  string
}

// Filters is the fixed filter list (documented in the RFC and the editor).
var Filters = []string{"join", "truncate", "date", "default", "upper", "lower", "first", "count"}

func knownFilter(n string) bool {
	for _, f := range Filters {
		if f == n {
			return true
		}
	}
	return false
}

// ParseTemplate parses a template and checks every path against the catalog
// of kind and every filter against the fixed list.
func ParseTemplate(kind ObjectKind, src string) (*Template, error) {
	if utf8.RuneCountInString(src) > MaxTemplateRunes {
		return nil, fmt.Errorf("%w: template too long", shared.ErrValidation)
	}
	t := &Template{}
	rest := src
	for {
		i := strings.Index(rest, "{{")
		if i < 0 {
			if rest != "" {
				t.parts = append(t.parts, tmplPart{text: rest})
			}
			break
		}
		if i > 0 {
			t.parts = append(t.parts, tmplPart{text: rest[:i]})
		}
		j := strings.Index(rest[i:], "}}")
		if j < 0 {
			return nil, fmt.Errorf("%w: unclosed {{ in template", shared.ErrValidation)
		}
		expr := strings.TrimSpace(rest[i+2 : i+j])
		p, err := parseExpr(kind, expr)
		if err != nil {
			return nil, err
		}
		t.parts = append(t.parts, p)
		rest = rest[i+j+2:]
	}
	return t, nil
}

func parseExpr(kind ObjectKind, expr string) (tmplPart, error) {
	segs := splitPipes(expr)
	path := strings.TrimSpace(segs[0])
	attr, ok := LookupAttr(kind, path)
	if !ok {
		return tmplPart{}, fmt.Errorf("%w: unknown attribute %q in template", shared.ErrValidation, path)
	}
	p := tmplPart{path: attr.Path}
	for _, s := range segs[1:] {
		s = strings.TrimSpace(s)
		name, arg := s, ""
		if k := strings.Index(s, ":"); k >= 0 {
			name = strings.TrimSpace(s[:k])
			a := strings.TrimSpace(s[k+1:])
			if uq, err := strconv.Unquote(a); err == nil {
				a = uq
			}
			arg = a
		}
		if !knownFilter(name) {
			return tmplPart{}, fmt.Errorf("%w: unknown filter %q in template", shared.ErrValidation, name)
		}
		if name == "truncate" {
			if n, err := strconv.Atoi(arg); err != nil || n < 1 || n > 32767 {
				return tmplPart{}, fmt.Errorf("%w: truncate needs a length from 1 to 32767", shared.ErrValidation)
			}
		}
		p.filters = append(p.filters, tmplFilter{name: name, arg: arg})
	}
	return p, nil
}

// splitPipes splits on | outside double quotes.
func splitPipes(s string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && (i == 0 || s[i-1] != '\\'):
			inQ = !inQ
			b.WriteByte(c)
		case c == '|' && !inQ:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	return append(out, b.String())
}

// Paths returns the attribute paths the template reads.
func (t *Template) Paths() []string {
	var out []string
	for _, p := range t.parts {
		if p.path != "" {
			out = append(out, p.path)
		}
	}
	return out
}

// Render renders the template over values. Values the caller did not supply
// render empty (or their default filter).
func (t *Template) Render(values Values) string {
	var b strings.Builder
	for _, p := range t.parts {
		if p.path == "" {
			b.WriteString(p.text)
			continue
		}
		b.WriteString(applyFilters(values[p.path], p.filters))
	}
	return b.String()
}

func applyFilters(v Value, filters []tmplFilter) string {
	cur := v
	for _, f := range filters {
		switch f.name {
		case "join":
			sep := f.arg
			if sep == "" {
				sep = ", "
			}
			cur = Text(strings.Join(cur.Strings(), sep))
		case "first":
			if l := cur.Strings(); len(l) > 0 {
				cur = Text(l[0])
			} else {
				cur = Value{}
			}
		case "count":
			cur = Number(float64(len(cur.Strings())))
		case "truncate":
			n, _ := strconv.Atoi(f.arg)
			cur = Text(truncateRunes(cur.String(), n))
		case "date":
			layout := f.arg
			if layout == "" {
				layout = "2006-01-02"
			}
			if cur.Time != nil {
				cur = Text(cur.Time.UTC().Format(layout))
			}
		case "default":
			if cur.IsEmpty() {
				cur = Text(f.arg)
			}
		case "upper":
			cur = Text(strings.ToUpper(cur.String()))
		case "lower":
			cur = Text(strings.ToLower(cur.String()))
		}
	}
	return cur.String()
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// Value is one attribute value: exactly one of the fields is set.
type Value struct {
	Str   *string
	Num   *float64
	Bool  *bool
	Time  *time.Time
	List  []string
	Table *Table
	// User is an OpenCTEM user (for user transforms).
	User *UserRef
}

// UserRef identifies an OpenCTEM user for a user transform.
type UserRef struct {
	ID    string
	Email string
	Name  string
}

// Table is a rendered block (e.g. a task's findings).
type Table struct {
	Header []string
	Rows   [][]string
	// More is the number of rows left out (the issue links back).
	More int
}

// Values maps attribute paths to values for one object.
type Values map[string]Value

// Text, Number, Bool, Date and List build values.
func Text(s string) Value       { return Value{Str: &s} }
func Number(f float64) Value    { return Value{Num: &f} }
func Bool(b bool) Value         { return Value{Bool: &b} }
func Date(t time.Time) Value    { return Value{Time: &t} }
func List(l ...string) Value    { return Value{List: l} }
func UserValue(u UserRef) Value { return Value{User: &u} }

// IsEmpty reports whether the value carries nothing.
func (v Value) IsEmpty() bool {
	switch {
	case v.Str != nil:
		return *v.Str == ""
	case v.Num != nil, v.Bool != nil, v.Time != nil, v.User != nil:
		return false
	case v.Table != nil:
		return len(v.Table.Rows) == 0
	}
	return len(v.List) == 0
}

// String renders a value as text.
func (v Value) String() string {
	switch {
	case v.Str != nil:
		return *v.Str
	case v.Num != nil:
		return strconv.FormatFloat(*v.Num, 'f', -1, 64)
	case v.Bool != nil:
		if *v.Bool {
			return "yes"
		}
		return "no"
	case v.Time != nil:
		return v.Time.UTC().Format("2006-01-02")
	case v.User != nil:
		if v.User.Name != "" {
			return v.User.Name
		}
		return v.User.Email
	case v.Table != nil:
		return v.Table.plain()
	}
	return strings.Join(v.List, ", ")
}

// Strings renders a value as a list.
func (v Value) Strings() []string {
	if v.List != nil {
		return v.List
	}
	if v.IsEmpty() {
		return nil
	}
	return []string{v.String()}
}

func (t *Table) plain() string {
	var b strings.Builder
	b.WriteString(strings.Join(t.Header, " | "))
	for _, r := range t.Rows {
		b.WriteString("\n")
		b.WriteString(strings.Join(r, " | "))
	}
	if t.More > 0 {
		fmt.Fprintf(&b, "\n… and %d more", t.More)
	}
	return b.String()
}
