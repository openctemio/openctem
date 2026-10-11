package docx

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Data is the value tree a template reads: nested map[string]any with
// string, bool, integer, float, []string, []map[string]any and map values.
type Data = map[string]any

const (
	maxIterations = 200_000 // section repetitions per render
)

type renderer struct {
	out        strings.Builder
	maxOut     int
	iterations int
	strict     bool // record lookups that find nothing
	missing    map[string]bool
}

func (r *renderer) checkSize() error {
	if r.out.Len() > r.maxOut {
		return ErrOutputTooLarge
	}
	return nil
}

func (r *renderer) render(n *node, scopes []any) error {
	switch n.kind {
	case kindRaw:
		r.out.WriteString(n.raw)
	case kindElem:
		return r.renderElem(n, scopes)
	case kindTag:
		r.renderValue(n, scopes)
	case kindMarkdown:
		v, _ := r.lookup(scopes, n.tag.path)
		r.out.WriteString(markdownToOOXML(toText(v), n.pPr, n.rPr))
	case kindSection:
		return r.renderSection(n, scopes)
	}
	return r.checkSize()
}

func (r *renderer) renderElem(n *node, scopes []any) error {
	if n.self {
		r.out.WriteString(n.open)
		return nil
	}
	start := r.out.Len()
	r.out.WriteString(n.open)
	bodyStart := r.out.Len()
	for _, c := range n.children {
		if err := r.render(c, scopes); err != nil {
			return err
		}
	}
	body := r.out.String()[bodyStart:]
	switch n.name {
	case "w:tc":
		// A table cell must hold a paragraph: a section or Markdown value that
		// rendered nothing would otherwise leave a cell Word refuses to open.
		if !strings.Contains(body, "<w:p>") && !strings.Contains(body, "<w:p ") && !strings.Contains(body, "<w:p/>") {
			r.out.WriteString("<w:p/>")
		}
	case "w:tbl":
		// A table whose rows were all repeated zero times is left out.
		if !strings.Contains(body, "<w:tr>") && !strings.Contains(body, "<w:tr ") {
			s := r.out.String()[:start]
			r.out.Reset()
			r.out.WriteString(s)
			return nil
		}
	}
	r.out.WriteString(n.close)
	return nil
}

func (r *renderer) renderValue(n *node, scopes []any) {
	v, _ := r.lookup(scopes, n.tag.path)
	text := toText(v)
	if text == "" {
		return
	}
	r.out.WriteString("<w:r>")
	r.out.WriteString(n.rPr)
	writeTextRuns(&r.out, text)
	r.out.WriteString("</w:r>")
}

// writeTextRuns writes text as w:t elements, line breaks as w:br.
func writeTextRuns(b *strings.Builder, text string) {
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if i > 0 {
			b.WriteString("<w:br/>")
		}
		if line == "" {
			continue
		}
		b.WriteString(`<w:t xml:space="preserve">`)
		b.WriteString(escapeText(line))
		b.WriteString("</w:t>")
	}
}

func (r *renderer) renderSection(n *node, scopes []any) error {
	v, _ := r.lookup(scopes, n.tag.path)
	if n.tag.kind == tagInverted {
		if truthy(v) {
			return nil
		}
		return r.renderChildren(n, scopes)
	}
	switch items := v.(type) {
	case []map[string]any:
		for _, it := range items {
			if err := r.iterate(n, append(scopes, it)); err != nil {
				return err
			}
		}
		return nil
	case []string:
		for _, it := range items {
			if err := r.iterate(n, append(scopes, it)); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for _, it := range items {
			if err := r.iterate(n, append(scopes, it)); err != nil {
				return err
			}
		}
		return nil
	}
	if !truthy(v) {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return r.renderChildren(n, append(scopes, m))
	}
	return r.renderChildren(n, scopes)
}

func (r *renderer) iterate(n *node, scopes []any) error {
	r.iterations++
	if r.iterations > maxIterations {
		return fmt.Errorf("%w: more than %d section repetitions", ErrOutputTooLarge, maxIterations)
	}
	return r.renderChildren(n, scopes)
}

func (r *renderer) renderChildren(n *node, scopes []any) error {
	for _, c := range n.children {
		if err := r.render(c, scopes); err != nil {
			return err
		}
	}
	return nil
}

// lookup resolves a dotted path: the first segment in the innermost scope
// that has it, then down through maps. "." is the current item.
func (r *renderer) lookup(scopes []any, path string) (any, bool) {
	if path == "." {
		if len(scopes) == 0 {
			return nil, false
		}
		return scopes[len(scopes)-1], true
	}
	segs := strings.Split(path, ".")
	for i := len(scopes) - 1; i >= 0; i-- {
		m, ok := scopes[i].(map[string]any)
		if !ok {
			continue
		}
		v, ok := m[segs[0]]
		if !ok {
			continue
		}
		for _, s := range segs[1:] {
			mm, ok := v.(map[string]any)
			if !ok {
				r.miss(path)
				return nil, false
			}
			if v, ok = mm[s]; !ok {
				r.miss(path)
				return nil, false
			}
		}
		return v, true
	}
	r.miss(path)
	return nil, false
}

func (r *renderer) miss(path string) {
	if r.strict {
		r.missing[path] = true
	}
}

func (r *renderer) missingPaths() []string {
	out := make([]string, 0, len(r.missing))
	for p := range r.missing {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []map[string]any:
		return len(x) > 0
	case []string:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

func toText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		if x == math.Trunc(x) {
			return strconv.FormatFloat(x, 'f', 0, 64)
		}
		return strconv.FormatFloat(x, 'f', 1, 64)
	case []string:
		return strings.Join(x, ", ")
	default:
		return ""
	}
}

var textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

// escapeText escapes a value for XML character data and drops characters
// XML 1.0 does not allow (control characters other than tab).
func escapeText(s string) string {
	clean := strings.Map(func(r rune) rune {
		if r == '\t' || r >= 0x20 && r != 0xFFFE && r != 0xFFFF {
			return r
		}
		return -1
	}, s)
	return textEscaper.Replace(clean)
}
