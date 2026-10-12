package docx

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"
)

// Tag grammar (the whole template language):
//
//	{path}     value: text of the value at path
//	{#path}    section: repeat for each item of a list, or show once when the
//	           value is true / non-empty; ends at {/path}
//	{^path}    inverted section: show once when the value is false / empty
//	{/path}    end of a section
//	{@path}    Markdown block: the paragraph holding it becomes the Markdown
//	           value rendered as paragraphs
//	{.}        the current list item (lists of text)
//
// path is a dotted name (letters, digits, underscore). There are no
// expressions, function calls or filters: a template can only read the data
// it is given.

type tagKind byte

const (
	tagValue    tagKind = 0
	tagOpen     tagKind = '#'
	tagInverted tagKind = '^'
	tagClose    tagKind = '/'
	tagMarkdown tagKind = '@'
	tagImage    tagKind = '%'
)

type tagInfo struct {
	kind tagKind
	path string
}

func (t tagInfo) String() string {
	if t.kind == tagValue {
		return "{" + t.path + "}"
	}
	return "{" + string(t.kind) + t.path + "}"
}

const maxTagLen = 200

var tagRe = regexp.MustCompile(`^\{([#^/@%]?)\s*(\.|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*\}$`)

type tagSpan struct {
	start, end int // byte offsets in the paragraph text, end exclusive
	tag        tagInfo
}

// literalHit is text with a brace that is not a well-formed tag.
type literalHit struct {
	text     string
	unclosed bool   // a '{' with no '}' after it in the paragraph
	context  string // the paragraph's text
}

// findTags returns the tags in a paragraph's text. A '{' that does not start
// a well-formed tag is literal text; it is reported so the template author
// can see a likely typo.
func findTags(text string) (spans []tagSpan, literal []literalHit) {
	for i := 0; i < len(text); i++ {
		if text[i] != '{' {
			continue
		}
		j := strings.IndexByte(text[i+1:], '}')
		k := strings.IndexByte(text[i+1:], '{')
		if j < 0 {
			literal = append(literal, literalHit{text: snippet(text, i), unclosed: true})
			continue
		}
		if (k >= 0 && k < j) || j+2 > maxTagLen {
			literal = append(literal, literalHit{text: snippet(text, i)})
			continue
		}
		candidate := text[i : i+j+2]
		m := tagRe.FindStringSubmatch(candidate)
		if m == nil {
			literal = append(literal, literalHit{text: candidate})
			i += j + 1
			continue
		}
		kind := tagValue
		if m[1] != "" {
			kind = tagKind(m[1][0])
		}
		spans = append(spans, tagSpan{start: i, end: i + j + 2, tag: tagInfo{kind: kind, path: m[2]}})
		i += j + 1
	}
	return spans, literal
}

func snippet(s string, i int) string {
	end := i + 20
	if end > len(s) {
		end = len(s)
	}
	return s[i:end]
}

// prepare turns a parsed part into the renderable tree: tags split across
// runs are merged, every tag gets a run of its own, sections are matched and
// wrapped, and Markdown paragraphs are marked. Every problem is recorded in
// c (the tree is only renderable when c holds no error). It returns the tags
// found, in document order.
func prepare(root *node, c *checker) []tagInfo {
	c.checkTrackedChanges(root)
	for _, l := range mergeSplitTags(root) {
		if l.unclosed {
			c.add(Issue{Level: LevelWarning, Code: CodeUnclosedBrace, Tag: l.text, Context: l.context,
				Message: fmt.Sprintf("%q opens a brace that is not closed in the same paragraph; a tag must be typed whole within one paragraph", l.text)})
			continue
		}
		sugg := c.literalSuggestion(l.text)
		msg := fmt.Sprintf("%q is not a template tag and prints as typed", l.text)
		if sugg != "" {
			msg += fmt.Sprintf("; did you mean %s?", sugg)
		}
		c.add(Issue{Level: LevelWarning, Code: CodeLiteralBrace, Tag: l.text, Context: l.context, Suggestion: sugg, Message: msg})
	}
	tagNodes := isolateTags(root)
	refs := make([]tagRef, 0, len(tagNodes))
	tags := make([]tagInfo, 0, len(tagNodes))
	for _, t := range tagNodes {
		refs = append(refs, tagRef{tag: t.tag, context: paragraphContext(t)})
		tags = append(tags, t.tag)
		if t.tag.kind == tagImage {
			c.add(Issue{Level: LevelError, Code: CodeImageTag, Tag: t.tag.String(), Context: paragraphContext(t),
				Message: fmt.Sprintf("image tags such as %s are not supported; insert a fixed picture (a logo) in Word, and evidence screenshots through the finding's Markdown fields", t.tag)})
		}
	}
	markMarkdown(tagNodes, c)
	buildSections(tagNodes, c)
	c.checkPaths(refs)
	return tags
}

// paragraphTexts groups the w:t elements of each innermost paragraph.
func paragraphTexts(root *node) [][]*node {
	var order []*node
	groups := map[*node][]*node{}
	walk(root, func(n *node) {
		if !n.isElem("w:t") {
			return
		}
		p := ancestor(n, "w:p")
		if p == nil {
			return
		}
		if _, seen := groups[p]; !seen {
			order = append(order, p)
		}
		groups[p] = append(groups[p], n)
	})
	out := make([][]*node, 0, len(order))
	for _, p := range order {
		out = append(out, groups[p])
	}
	return out
}

// mergeSplitTags moves each tag that Word split over several w:t elements
// (spell check, edits, formatting changes) into the first of them, so every
// tag sits whole in one w:t. Returns literal-brace snippets.
func mergeSplitTags(root *node) (literal []literalHit) {
	for _, ts := range paragraphTexts(root) {
		texts := make([]string, len(ts))
		offsets := make([]int, len(ts))
		var all strings.Builder
		for i, t := range ts {
			offsets[i] = all.Len()
			texts[i] = textOf(t)
			all.WriteString(texts[i])
		}
		spans, lit := findTags(all.String())
		for _, l := range lit {
			l.text = html.UnescapeString(l.text)
			l.context = shorten(html.UnescapeString(all.String()))
			literal = append(literal, l)
		}
		if len(spans) == 0 {
			continue
		}
		joined := all.String()
		for i, t := range ts {
			start, end := offsets[i], offsets[i]+len(texts[i])
			var b strings.Builder
			changed := false
			for pos := start; pos < end; {
				sp := spanAt(spans, pos)
				switch {
				case sp == nil:
					b.WriteByte(joined[pos])
					pos++
				case sp.start == pos:
					b.WriteString(joined[sp.start:sp.end])
					if sp.end > end {
						changed = true
					}
					pos = minInt(sp.end, end)
				default: // inside a tag that started in an earlier w:t
					changed = true
					pos = minInt(sp.end, end)
				}
			}
			if changed {
				setText(t, b.String())
			}
		}
	}
	return literal
}

func spanAt(spans []tagSpan, pos int) *tagSpan {
	i := sort.Search(len(spans), func(i int) bool { return spans[i].end > pos })
	if i < len(spans) && spans[i].start <= pos {
		return &spans[i]
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isolateTags splits every run holding tags so that each tag becomes a node
// of its own (kindTag) keeping the run's formatting, and returns the tag
// nodes in document order.
func isolateTags(root *node) []*node {
	var runs []*node
	walk(root, func(n *node) {
		if !n.isElem("w:r") {
			return
		}
		for _, c := range n.children {
			if c.isElem("w:t") {
				if spans, _ := findTags(textOf(c)); len(spans) > 0 {
					runs = append(runs, n)
					return
				}
			}
		}
	})
	for _, r := range runs {
		splitRun(r)
	}
	var tags []*node
	walk(root, func(n *node) {
		if n.kind == kindTag {
			tags = append(tags, n)
		}
	})
	return tags
}

func splitRun(r *node) {
	parent := r.parent
	idx := indexOf(parent, r)
	if idx < 0 {
		return
	}
	rPrNode := childElem(r, "w:rPr")
	rPr := serializeOrEmpty(rPrNode)
	newRun := func() *node {
		n := &node{kind: kindElem, name: r.name, open: r.open, close: r.close, parent: parent}
		if rPrNode != nil {
			c := *rPrNode
			c.parent = n
			n.children = append(n.children, &c)
		}
		return n
	}
	hasContent := func(n *node) bool { return len(n.children) > 0 && !(len(n.children) == 1 && rPrNode != nil) }

	var out []*node
	cur := newRun()
	for _, c := range r.children {
		if c == rPrNode {
			continue
		}
		if !c.isElem("w:t") {
			c.parent = cur
			cur.children = append(cur.children, c)
			continue
		}
		text := textOf(c)
		spans, _ := findTags(text)
		if len(spans) == 0 {
			c.parent = cur
			cur.children = append(cur.children, c)
			continue
		}
		pos := 0
		for _, sp := range spans {
			if sp.start > pos {
				cur.children = append(cur.children, textElem(c, text[pos:sp.start], cur))
			}
			if hasContent(cur) {
				out = append(out, cur)
			}
			out = append(out, &node{kind: kindTag, tag: sp.tag, rPr: rPr, parent: parent})
			cur = newRun()
			pos = sp.end
		}
		if pos < len(text) {
			cur.children = append(cur.children, textElem(c, text[pos:], cur))
		}
	}
	if hasContent(cur) {
		out = append(out, cur)
	}
	children := append([]*node{}, parent.children[:idx]...)
	children = append(children, out...)
	children = append(children, parent.children[idx+1:]...)
	parent.children = children
}

func textElem(proto *node, text string, parent *node) *node {
	n := &node{kind: kindElem, name: proto.name, open: proto.open, close: proto.close, self: proto.self, parent: parent}
	setText(n, text)
	return n
}

// soleTagInParagraph reports whether t is the only visible content of its
// paragraph (other runs carry no text).
func soleTagInParagraph(t *node) (*node, bool) {
	p := ancestor(t, "w:p")
	if p == nil {
		return nil, false
	}
	sole := true
	walk(p, func(n *node) {
		switch {
		case n.kind == kindTag && n != t:
			sole = false
		case n.isElem("w:t") && strings.TrimSpace(textOf(n)) != "":
			sole = false
		}
	})
	return p, sole
}

// markMarkdown replaces each paragraph holding a {@path} tag with a Markdown
// node. The tag must be the paragraph's only content.
func markMarkdown(tags []*node, c *checker) {
	for _, t := range tags {
		if t.tag.kind != tagMarkdown {
			continue
		}
		p, sole := soleTagInParagraph(t)
		if !sole {
			c.add(Issue{Level: LevelError, Code: CodeMarkdownNotAlone, Tag: t.tag.String(), Context: paragraphContext(t),
				Message: fmt.Sprintf("%s must be alone in its paragraph: it becomes several paragraphs; move other text to a paragraph before or after it", t.tag)})
			continue
		}
		md := &node{kind: kindMarkdown, tag: t.tag, rPr: t.rPr, pPr: serializeOrEmpty(childElem(p, "w:pPr")), parent: p.parent}
		i := indexOf(p.parent, p)
		p.parent.children[i] = md
	}
}

// maxSectionDepth bounds section nesting.
const maxSectionDepth = 8

// buildSections matches {#x}/{^x} with {/x} and wraps what they enclose in a
// section node:
//   - both tags in the same run container (same paragraph): the runs between;
//   - each tag alone in its paragraph, paragraphs of the same level: the
//     paragraphs and tables between;
//   - both tags in the same table row: the row.
func buildSections(tags []*node, c *checker) {
	var stack []*node
	var pairs [][2]*node
	tooDeep := false
	for _, t := range tags {
		switch t.tag.kind {
		case tagOpen, tagInverted:
			stack = append(stack, t)
			if len(stack) > maxSectionDepth && !tooDeep {
				tooDeep = true
				c.add(Issue{Level: LevelError, Code: CodeNestingTooDeep, Tag: t.tag.String(), Context: paragraphContext(t),
					Message: fmt.Sprintf("sections are nested more than %d deep at %s", maxSectionDepth, t.tag)})
			}
		case tagClose:
			match := -1
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].tag.path == t.tag.path {
					match = i
					break
				}
			}
			switch {
			case match < 0 && len(stack) == 0:
				c.add(Issue{Level: LevelError, Code: CodeStrayClose, Tag: t.tag.String(), Context: paragraphContext(t),
					Suggestion: "{#" + t.tag.path + "}",
					Message:    fmt.Sprintf("%s closes a section that was never opened; add {#%s} before it or delete it", t.tag, t.tag.path)})
			case match < 0:
				open := stack[len(stack)-1]
				c.add(Issue{Level: LevelError, Code: CodeMismatchedClose, Tag: t.tag.String(), Context: paragraphContext(t),
					Suggestion: "{/" + open.tag.path + "}",
					Message:    fmt.Sprintf("%s does not match the open section %s; did you mean {/%s}?", t.tag, open.tag, open.tag.path)})
			default:
				for _, open := range stack[match+1:] {
					reportUnclosed(c, open)
				}
				pairs = append(pairs, [2]*node{stack[match], t}) // inner pairs first
				stack = stack[:match]
			}
		}
	}
	for _, open := range stack {
		reportUnclosed(c, open)
	}
	contexts := make([]string, len(pairs))
	for i, p := range pairs {
		contexts[i] = paragraphContext(p[0])
	}
	for i, p := range pairs {
		if err := wrapSection(p[0], p[1]); err != nil {
			c.add(Issue{Level: LevelError, Code: CodeSectionPlacement, Tag: p[0].tag.String(), Context: contexts[i],
				Suggestion: "{/" + p[0].tag.path + "}", Message: err.Error()})
		}
	}
}

func reportUnclosed(c *checker, open *node) {
	c.add(Issue{Level: LevelError, Code: CodeUnclosedSection, Tag: open.tag.String(), Context: paragraphContext(open),
		Suggestion: "{/" + open.tag.path + "}",
		Message:    fmt.Sprintf("%s is never closed; add {/%s} where the repeated or conditional content ends", open.tag, open.tag.path)})
}

func wrapSection(open, closeTag *node) error {
	section := &node{kind: kindSection, tag: open.tag}
	// Inline: same container.
	if open.parent == closeTag.parent {
		parent := open.parent
		i, j := indexOf(parent, open), indexOf(parent, closeTag)
		replaceRange(parent, i, j, section)
		return nil
	}
	// Paragraph block: each tag alone in its paragraph, same level.
	po, soleO := soleTagInParagraph(open)
	pc, soleC := soleTagInParagraph(closeTag)
	if soleO && soleC && po != pc && po.parent == pc.parent {
		parent := po.parent
		i, j := indexOf(parent, po), indexOf(parent, pc)
		if i < j {
			replaceRange(parent, i, j, section)
			return nil
		}
	}
	// Table row.
	if ro, rc := ancestor(open, "w:tr"), ancestor(closeTag, "w:tr"); ro != nil && ro == rc {
		removeNode(open)
		removeNode(closeTag)
		parent := ro.parent
		i := indexOf(parent, ro)
		section.parent = parent
		section.children = []*node{ro}
		ro.parent = section
		parent.children[i] = section
		return nil
	}
	hint := "put {#x} and {/x} each alone in its own paragraph at the same level (not one inside a table and the other outside), both in the same table row, or both in the same paragraph"
	switch {
	case soleO && soleC && po != nil && pc != nil && po.parent != pc.parent:
		hint = "one is inside a table (or text box) and the other is not; move both into the body, or both into the same table row"
	case !soleO || !soleC:
		hint = "when the section spans several paragraphs, each of the two tags must be alone in its paragraph; move the other text to a separate paragraph"
	}
	return fmt.Errorf("%s and %s cannot enclose this content: %s", open.tag, closeTag.tag, strings.NewReplacer("{#x}", open.tag.String(), "{/x}", closeTag.tag.String()).Replace(hint))
}

// replaceRange replaces parent.children[i..j] (inclusive, the two tag
// holders) with section, moving the children strictly between into it.
func replaceRange(parent *node, i, j int, section *node) {
	inner := append([]*node{}, parent.children[i+1:j]...)
	for _, c := range inner {
		c.parent = section
	}
	section.children = inner
	section.parent = parent
	children := append([]*node{}, parent.children[:i]...)
	children = append(children, section)
	children = append(children, parent.children[j+1:]...)
	parent.children = children
}

func removeNode(n *node) {
	p := n.parent
	if i := indexOf(p, n); i >= 0 {
		p.children = append(p.children[:i], p.children[i+1:]...)
	}
}
