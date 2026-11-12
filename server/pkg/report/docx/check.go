package docx

import (
	"fmt"
	"html"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// Template checks. Every problem in a template is reported as an Issue that
// says where it is (the part and the text of the paragraph) and how to fix
// it, so the author can correct the whole file in one pass. Errors make the
// template unusable; warnings render but probably not as intended.

// Issue levels.
const (
	LevelError   = "error"
	LevelWarning = "warning"
)

// Issue codes. The web console translates each code; Message is the English
// text for other clients.
const (
	CodeUnclosedSection  = "unclosed_section"   // {#x} without {/x}
	CodeStrayClose       = "stray_close"        // {/x} without {#x}
	CodeMismatchedClose  = "mismatched_close"   // {#a} … {/b}
	CodeSectionPlacement = "section_placement"  // open and close in incompatible places
	CodeNestingTooDeep   = "nesting_too_deep"   // more than maxSectionDepth levels
	CodeMarkdownNotAlone = "markdown_not_alone" // {@x} shares its paragraph
	CodeImageTag         = "image_tag"          // {%x} is reserved
	CodeLiteralBrace     = "literal_brace"      // braces that are not a tag
	CodeUnclosedBrace    = "unclosed_brace"     // a { with no } in its paragraph
	CodeTrackedChanges   = "tracked_changes"    // w:ins / w:del in the part
	CodeUnknownTag       = "unknown_tag"        // path not in the data model
	CodeFieldOutsideList = "field_outside_list" // item field used outside its loop
	CodeMarkdownAsText   = "markdown_as_text"   // {x} on a Markdown field
	CodeListAsValue      = "list_as_value"      // {x} on a list or group
	CodeItemOutsideList  = "item_outside_list"  // {.} outside a list of text
	CodeInvalidFile      = "invalid_file"       // the package itself is refused (not a .docx, macros, external links…)
	CodeRenderFailed     = "render_failed"      // the sample render failed
)

// Issue is one problem found in a template.
type Issue struct {
	Level      string `json:"level"`
	Code       string `json:"code"`
	Tag        string `json:"tag,omitempty"`        // the tag (or text) concerned
	Part       string `json:"part"`                 // body, header, footer, footnotes, endnotes
	Context    string `json:"context,omitempty"`    // text of the paragraph, shortened
	Suggestion string `json:"suggestion,omitempty"` // a tag to use instead, or the missing tag
	Within     string `json:"within,omitempty"`     // field_outside_list: the list that has the field
	Message    string `json:"message"`
}

// Kind is the type of a value in the report data.
type Kind string

// Value kinds.
const (
	KindText     Kind = "text"
	KindMarkdown Kind = "markdown"
	KindNumber   Kind = "number"
	KindBool     Kind = "boolean"
	KindObject   Kind = "object"    // a group of named fields
	KindList     Kind = "list"      // a list of objects (Fields: each item's fields)
	KindTextList Kind = "text_list" // a list of text, read with {.}
)

// Schema describes the data a template reads, for the static tag checks.
// The root is a KindObject.
type Schema struct {
	Kind   Kind
	Fields map[string]*Schema // KindObject: its fields; KindList: each item's fields
}

// checker collects the issues of one part.
type checker struct {
	part   string
	schema *Schema
	issues []Issue
}

func newChecker(partName string, schema *Schema) *checker {
	return &checker{part: partLabel(partName), schema: schema}
}

// partLabel names a package part the way an author sees it in Word.
func partLabel(name string) string {
	base := strings.TrimSuffix(path.Base(name), ".xml")
	switch {
	case base == "document":
		return "body"
	case strings.HasPrefix(base, "header"):
		return "header"
	case strings.HasPrefix(base, "footer"):
		return "footer"
	}
	return base
}

func (c *checker) add(is Issue) {
	is.Part = c.part
	for _, e := range c.issues {
		if e.Code == is.Code && e.Tag == is.Tag && e.Context == is.Context {
			return
		}
	}
	c.issues = append(c.issues, is)
}

func (c *checker) firstError() error {
	for _, is := range c.issues {
		if is.Level == LevelError {
			return fmt.Errorf("%w: %s", ErrInvalidTemplate, is.Message)
		}
	}
	return nil
}

const maxContext = 80

// shorten trims s to maxContext characters.
func shorten(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= maxContext {
		return s
	}
	r := []rune(s)
	return string(r[:maxContext-1]) + "…"
}

// paragraphContext is the visible text of the paragraph holding n, with
// tags written as typed.
func paragraphContext(n *node) string {
	p := n
	if !n.isElem("w:p") {
		p = ancestor(n, "w:p")
	}
	if p == nil {
		return ""
	}
	var b strings.Builder
	walk(p, func(x *node) {
		switch {
		case x.kind == kindTag:
			b.WriteString(x.tag.String())
		case x.isElem("w:t"):
			b.WriteString(html.UnescapeString(textOf(x)))
		}
	})
	return shorten(b.String())
}

// checkTrackedChanges warns once per part with tracked insertions or
// deletions: the renderer reads the text as if every change were accepted,
// and the change marks stay in the report.
func (c *checker) checkTrackedChanges(root *node) {
	found := false
	walk(root, func(n *node) {
		if n.isElem("w:ins") || n.isElem("w:del") || n.isElem("w:moveFrom") || n.isElem("w:moveTo") {
			found = true
		}
	})
	if found {
		c.add(Issue{Level: LevelWarning, Code: CodeTrackedChanges,
			Message: "the file has tracked changes; accept or reject them all (Review > Accept all changes) and turn off Track Changes before uploading, or the change marks appear in every report"})
	}
}

// --- static check of tag paths against the schema ---

type tagRef struct {
	tag     tagInfo
	context string
}

// checkPaths walks the tags in document order with the scopes the renderer
// would have, and reports paths the data does not have, fields used outside
// their list, and tags of the wrong form for their value.
func (c *checker) checkPaths(tags []tagRef) {
	if c.schema == nil {
		return
	}
	type frame struct {
		path   string
		pushed bool
	}
	scopes := []*Schema{c.schema}
	var frames []frame
	for _, t := range tags {
		switch t.tag.kind {
		case tagOpen:
			v := c.resolveOrReport(scopes, t)
			f := frame{path: t.tag.path}
			if v != nil {
				switch v.Kind {
				case KindList:
					scopes = append(scopes, &Schema{Kind: KindObject, Fields: v.Fields})
					f.pushed = true
				case KindTextList:
					scopes = append(scopes, &Schema{Kind: KindText})
					f.pushed = true
				case KindObject:
					scopes = append(scopes, v)
					f.pushed = true
				}
			}
			frames = append(frames, f)
		case tagInverted:
			c.resolveOrReport(scopes, t)
			frames = append(frames, frame{path: t.tag.path})
		case tagClose:
			for i := len(frames) - 1; i >= 0; i-- {
				if frames[i].path != t.tag.path {
					continue
				}
				for _, f := range frames[i:] {
					if f.pushed {
						scopes = scopes[:len(scopes)-1]
					}
				}
				frames = frames[:i]
				break
			}
		case tagValue, tagMarkdown:
			if t.tag.path == "." {
				if scopes[len(scopes)-1].Kind != KindText {
					c.add(Issue{Level: LevelWarning, Code: CodeItemOutsideList, Tag: t.tag.String(), Context: t.context,
						Message: fmt.Sprintf("%s (the current item) is only meaningful inside a list of text such as {#steps}{.}{/steps}; here it renders empty", t.tag)})
				}
				continue
			}
			v := c.resolveOrReport(scopes, t)
			if v == nil {
				continue
			}
			switch {
			case v.Kind == KindList || v.Kind == KindObject:
				sugg := "{#" + t.tag.path + "}…{/" + t.tag.path + "}"
				msg := fmt.Sprintf("%s is a list; repeat content for each item with %s", t.tag, sugg)
				if v.Kind == KindObject {
					sugg = ""
					msg = fmt.Sprintf("%s is a group of fields and renders empty; use one of its fields, such as {%s.%s}", t.tag, t.tag.path, firstField(v))
				}
				c.add(Issue{Level: LevelWarning, Code: CodeListAsValue, Tag: t.tag.String(), Context: t.context, Suggestion: sugg, Message: msg})
			case v.Kind == KindMarkdown && t.tag.kind == tagValue:
				sugg := "{@" + t.tag.path + "}"
				c.add(Issue{Level: LevelWarning, Code: CodeMarkdownAsText, Tag: t.tag.String(), Context: t.context, Suggestion: sugg,
					Message: fmt.Sprintf("%s holds Markdown and prints its markup as plain text; put %s alone in its own paragraph to render headings, lists, code and evidence screenshots", t.tag, sugg)})
			}
		}
	}
}

func firstField(s *Schema) string {
	names := make([]string, 0, len(s.Fields))
	for n := range s.Fields {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "name"
	}
	return names[0]
}

// resolveOrReport resolves a tag path like the renderer does: the first
// segment in the innermost scope that has it, then down through groups.
func (c *checker) resolveOrReport(scopes []*Schema, t tagRef) *Schema {
	segs := strings.Split(t.tag.path, ".")
	for i := len(scopes) - 1; i >= 0; i-- {
		s := scopes[i]
		if s.Kind != KindObject {
			continue
		}
		v, ok := s.Fields[segs[0]]
		if !ok {
			continue
		}
		for _, seg := range segs[1:] {
			if v.Kind != KindObject {
				v = nil
				break
			}
			if v = v.Fields[seg]; v == nil {
				break
			}
		}
		if v != nil {
			return v
		}
		break // the renderer does not look further out once the first segment matched
	}
	c.reportUnknown(scopes, t)
	return nil
}

func (c *checker) reportUnknown(scopes []*Schema, t tagRef) {
	// A field of a list's items used outside the loop over that list.
	if list := c.listHaving(t.tag.path); list != "" {
		c.add(Issue{Level: LevelWarning, Code: CodeFieldOutsideList, Tag: t.tag.String(), Context: t.context, Within: list,
			Suggestion: "{#" + list + "}",
			Message:    fmt.Sprintf("%s is a field of each item of %s; place it between {#%s} and {/%s}, otherwise it renders empty", t.tag, list, list, list)})
		return
	}
	sugg := ""
	if best := closest(t.tag.path, visiblePaths(scopes)); best != "" {
		sugg = tagInfo{kind: t.tag.kind, path: best}.String()
	}
	msg := fmt.Sprintf("%s is not in the report data and renders empty", t.tag)
	if sugg != "" {
		msg += fmt.Sprintf("; did you mean %s?", sugg)
	}
	c.add(Issue{Level: LevelWarning, Code: CodeUnknownTag, Tag: t.tag.String(), Context: t.context, Suggestion: sugg, Message: msg})
}

// listHaving returns the path of the shortest-named top-level list whose
// items have the field path ("" if none).
func (c *checker) listHaving(p string) string {
	var lists []string
	var visit func(prefix string, s *Schema)
	visit = func(prefix string, s *Schema) {
		for name, f := range s.Fields {
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			switch f.Kind {
			case KindObject:
				visit(full, f)
			case KindList:
				if resolvePath(f, p) != nil {
					lists = append(lists, full)
				}
			}
		}
	}
	visit("", c.schema)
	sort.Slice(lists, func(i, j int) bool {
		if len(lists[i]) != len(lists[j]) {
			return len(lists[i]) < len(lists[j])
		}
		return lists[i] < lists[j]
	})
	if len(lists) == 0 {
		return ""
	}
	return lists[0]
}

func resolvePath(s *Schema, p string) *Schema {
	v := s
	for _, seg := range strings.Split(p, ".") {
		if v.Kind != KindObject && v.Kind != KindList {
			return nil
		}
		if v = v.Fields[seg]; v == nil {
			return nil
		}
	}
	return v
}

// visiblePaths lists every path a tag can read from these scopes.
func visiblePaths(scopes []*Schema) []string {
	var out []string
	var visit func(prefix string, s *Schema)
	visit = func(prefix string, s *Schema) {
		for name, f := range s.Fields {
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			out = append(out, full)
			if f.Kind == KindObject {
				visit(full, f)
			}
		}
	}
	for _, s := range scopes {
		if s.Kind == KindObject {
			visit("", s)
		}
	}
	sort.Strings(out)
	return out
}

// closest returns the candidate nearest to p by edit distance, when it is
// near enough to be a likely typo.
func closest(p string, candidates []string) string {
	norm := strings.ToLower(p)
	best, bestD := "", 1<<30
	for _, cand := range candidates {
		d := editDistance(norm, strings.ToLower(cand))
		if d < bestD {
			best, bestD = cand, d
		}
	}
	limit := len(p) / 3
	if limit < 2 {
		limit = 2
	}
	if bestD > limit {
		return ""
	}
	return best
}

// editDistance is the Levenshtein distance (inputs are short tag paths).
func editDistance(a, b string) int {
	if len(a) > maxTagLen || len(b) > maxTagLen {
		return 1 << 30
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// literalSuggestion proposes a tag for text that looks like a mistyped tag:
// "{campaign name}", "{ Campaign-Name }", "{{campaign.name}}".
func (c *checker) literalSuggestion(text string) string {
	inner := strings.Trim(text, "{} ")
	if inner == "" || strings.ContainsAny(inner, "{}") {
		return ""
	}
	prefix := ""
	if strings.ContainsAny(inner[:1], "#^/@") {
		prefix, inner = inner[:1], strings.TrimSpace(inner[1:])
	}
	repl := strings.NewReplacer(" ", "_", "-", "_")
	candidate := strings.ToLower(repl.Replace(inner))
	if c.schema != nil {
		all := visiblePaths([]*Schema{c.schema})
		var items []string
		var visit func(s *Schema)
		visit = func(s *Schema) {
			for _, f := range s.Fields {
				switch f.Kind {
				case KindList:
					items = append(items, visiblePaths([]*Schema{{Kind: KindObject, Fields: f.Fields}})...)
				case KindObject:
					visit(f)
				}
			}
		}
		visit(c.schema)
		if best := closest(candidate, append(all, items...)); best != "" {
			return "{" + prefix + best + "}"
		}
		return ""
	}
	if tagRe.MatchString("{" + prefix + candidate + "}") {
		return "{" + prefix + candidate + "}"
	}
	return ""
}
