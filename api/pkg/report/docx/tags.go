package docx

import (
	"fmt"
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

// findTags returns the tags in a paragraph's text. A '{' that does not start
// a well-formed tag is literal text; it is reported so the template author
// can see a likely typo.
func findTags(text string) (spans []tagSpan, literal []string) {
	for i := 0; i < len(text); i++ {
		if text[i] != '{' {
			continue
		}
		j := strings.IndexByte(text[i+1:], '}')
		k := strings.IndexByte(text[i+1:], '{')
		if j < 0 || (k >= 0 && k < j) || j+2 > maxTagLen {
			literal = append(literal, snippet(text, i))
			continue
		}
		candidate := text[i : i+j+2]
		m := tagRe.FindStringSubmatch(candidate)
		if m == nil {
			literal = append(literal, candidate)
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
// wrapped, and Markdown paragraphs are marked. It returns the tags found and
// warnings about literal braces.
func prepare(root *node) (tags []tagInfo, warnings []string, err error) {
	literal := mergeSplitTags(root)
	for _, l := range literal {
		warnings = append(warnings, fmt.Sprintf("text %q contains a brace that is not a template tag", l))
	}
	tagNodes, err := isolateTags(root)
	if err != nil {
		return nil, nil, err
	}
	for _, t := range tagNodes {
		tags = append(tags, t.tag)
		if t.tag.kind == tagImage {
			return nil, nil, fmt.Errorf("%w: image tags such as %s are not supported yet", ErrInvalidTemplate, t.tag)
		}
	}
	if err := markMarkdown(tagNodes); err != nil {
		return nil, nil, err
	}
	if err := buildSections(tagNodes); err != nil {
		return nil, nil, err
	}
	return tags, warnings, nil
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
func mergeSplitTags(root *node) (literal []string) {
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
		literal = append(literal, lit...)
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
func isolateTags(root *node) ([]*node, error) {
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
		if err := splitRun(r); err != nil {
			return nil, err
		}
	}
	var tags []*node
	walk(root, func(n *node) {
		if n.kind == kindTag {
			tags = append(tags, n)
		}
	})
	return tags, nil
}

func splitRun(r *node) error {
	parent := r.parent
	idx := indexOf(parent, r)
	if idx < 0 {
		return fmt.Errorf("%w: internal: run not in its parent", ErrInvalidTemplate)
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
	return nil
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
func markMarkdown(tags []*node) error {
	for _, t := range tags {
		if t.tag.kind != tagMarkdown {
			continue
		}
		p, sole := soleTagInParagraph(t)
		if !sole {
			return fmt.Errorf("%w: %s must be alone in its paragraph", ErrInvalidTemplate, t.tag)
		}
		md := &node{kind: kindMarkdown, tag: t.tag, rPr: t.rPr, pPr: serializeOrEmpty(childElem(p, "w:pPr")), parent: p.parent}
		i := indexOf(p.parent, p)
		p.parent.children[i] = md
	}
	return nil
}

// maxSectionDepth bounds section nesting.
const maxSectionDepth = 8

// buildSections matches {#x}/{^x} with {/x} and wraps what they enclose in a
// section node:
//   - both tags in the same run container (same paragraph): the runs between;
//   - each tag alone in its paragraph, paragraphs of the same level: the
//     paragraphs and tables between;
//   - both tags in the same table row: the row.
func buildSections(tags []*node) error {
	var stack []*node
	var pairs [][2]*node
	for _, t := range tags {
		switch t.tag.kind {
		case tagOpen, tagInverted:
			stack = append(stack, t)
			if len(stack) > maxSectionDepth {
				return fmt.Errorf("%w: sections are nested deeper than %d", ErrInvalidTemplate, maxSectionDepth)
			}
		case tagClose:
			if len(stack) == 0 {
				return fmt.Errorf("%w: %s has no matching opening tag", ErrInvalidTemplate, t.tag)
			}
			open := stack[len(stack)-1]
			if open.tag.path != t.tag.path {
				return fmt.Errorf("%w: %s is closed by %s", ErrInvalidTemplate, open.tag, t.tag)
			}
			stack = stack[:len(stack)-1]
			pairs = append(pairs, [2]*node{open, t}) // inner pairs first
		}
	}
	if len(stack) > 0 {
		return fmt.Errorf("%w: %s is not closed", ErrInvalidTemplate, stack[len(stack)-1].tag)
	}
	for _, p := range pairs {
		if err := wrapSection(p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
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
	return fmt.Errorf("%w: %s must open and close in the same paragraph, each alone in a paragraph of the same level, or in the same table row", ErrInvalidTemplate, open.tag)
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
