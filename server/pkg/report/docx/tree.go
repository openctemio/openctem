package docx

import (
	"fmt"
	"strings"
)

// The renderer works on a light tree built from the part's XML bytes. It
// keeps every tag exactly as written (namespaces, attribute order, entities),
// so parts round-trip byte for byte except where a template tag is replaced.
// encoding/xml is not used for rewriting because re-encoding renames
// namespace prefixes, which Word refuses.

type nodeKind int

const (
	kindElem     nodeKind = iota // element with children (or self-closing)
	kindRaw                      // character data or a PI/comment, written as is
	kindTag                      // a run holding exactly one template tag
	kindSection                  // a loop/condition block (built from {#x}..{/x})
	kindMarkdown                 // a paragraph replaced by rendered Markdown ({@x})
)

type node struct {
	kind     nodeKind
	name     string // element qualified name, e.g. "w:p"
	open     string // raw start tag (or whole element when selfClose)
	close    string // raw end tag
	self     bool   // self-closing element
	raw      string // kindRaw: raw bytes
	children []*node
	parent   *node

	// kindTag / kindSection / kindMarkdown
	tag tagInfo
	rPr string // run properties of the run the tag was in
	pPr string // kindMarkdown: paragraph properties of the paragraph
}

func (n *node) isElem(name string) bool { return n.kind == kindElem && n.name == name }

// parseXML builds the tree of one XML part. It rejects a DOCTYPE or ENTITY
// declaration (no external entities can be declared at all) and unbalanced
// markup.
func parseXML(src string) (*node, error) {
	root := &node{kind: kindElem, name: ""}
	cur := root
	i := 0
	for i < len(src) {
		if src[i] != '<' {
			j := strings.IndexByte(src[i:], '<')
			if j < 0 {
				j = len(src) - i
			}
			cur.children = append(cur.children, &node{kind: kindRaw, raw: src[i : i+j], parent: cur})
			i += j
			continue
		}
		switch {
		case strings.HasPrefix(src[i:], "<!--"):
			j := strings.Index(src[i:], "-->")
			if j < 0 {
				return nil, fmt.Errorf("%w: unterminated comment", ErrInvalidTemplate)
			}
			cur.children = append(cur.children, &node{kind: kindRaw, raw: src[i : i+j+3], parent: cur})
			i += j + 3
			continue
		case strings.HasPrefix(src[i:], "<?"):
			j := strings.Index(src[i:], "?>")
			if j < 0 {
				return nil, fmt.Errorf("%w: unterminated processing instruction", ErrInvalidTemplate)
			}
			cur.children = append(cur.children, &node{kind: kindRaw, raw: src[i : i+j+2], parent: cur})
			i += j + 2
			continue
		case strings.HasPrefix(src[i:], "<!"):
			// DOCTYPE, ENTITY or CDATA: none belong in an Office part.
			return nil, fmt.Errorf("%w: DOCTYPE, ENTITY and CDATA declarations are not allowed", ErrInvalidTemplate)
		}
		end := tagEnd(src, i)
		if end < 0 {
			return nil, fmt.Errorf("%w: unterminated tag", ErrInvalidTemplate)
		}
		raw := src[i : end+1]
		if strings.HasPrefix(raw, "</") {
			name := strings.TrimSpace(raw[2 : len(raw)-1])
			if cur == root || cur.name != name {
				return nil, fmt.Errorf("%w: unexpected end tag %q", ErrInvalidTemplate, name)
			}
			cur.close = raw
			cur = cur.parent
			i = end + 1
			continue
		}
		name := elemName(raw)
		if name == "" {
			return nil, fmt.Errorf("%w: malformed tag", ErrInvalidTemplate)
		}
		n := &node{kind: kindElem, name: name, open: raw, parent: cur}
		cur.children = append(cur.children, n)
		if strings.HasSuffix(raw, "/>") {
			n.self = true
		} else {
			cur = n
		}
		i = end + 1
	}
	if cur != root {
		return nil, fmt.Errorf("%w: element %q is not closed", ErrInvalidTemplate, cur.name)
	}
	return root, nil
}

// tagEnd returns the index of the '>' closing the tag that starts at i,
// skipping '>' inside quoted attribute values.
func tagEnd(src string, i int) int {
	var quote byte
	for j := i + 1; j < len(src); j++ {
		c := src[j]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return j
		}
	}
	return -1
}

func elemName(raw string) string {
	s := strings.TrimPrefix(raw, "<")
	end := strings.IndexAny(s, " \t\r\n/>")
	if end <= 0 {
		return ""
	}
	return s[:end]
}

// textOf returns the raw (escaped) character data directly inside n.
func textOf(n *node) string {
	var b strings.Builder
	for _, c := range n.children {
		if c.kind == kindRaw && !strings.HasPrefix(c.raw, "<") {
			b.WriteString(c.raw)
		}
	}
	return b.String()
}

func setText(n *node, text string) {
	kept := n.children[:0]
	for _, c := range n.children {
		if c.kind == kindRaw && !strings.HasPrefix(c.raw, "<") {
			continue
		}
		kept = append(kept, c)
	}
	n.children = kept
	if text != "" {
		n.children = append(n.children, &node{kind: kindRaw, raw: text, parent: n})
	}
	if n.self {
		// <w:t/> receiving text becomes <w:t>…</w:t>.
		n.self = false
		n.open = strings.TrimSuffix(strings.TrimSuffix(n.open, "/>"), " ") + ">"
		n.close = "</" + n.name + ">"
	}
	if !strings.Contains(n.open, "xml:space") {
		n.open = strings.TrimSuffix(n.open, ">") + ` xml:space="preserve">`
	}
}

// ancestor returns the nearest ancestor element named name, or nil.
func ancestor(n *node, name string) *node {
	for p := n.parent; p != nil; p = p.parent {
		if p.isElem(name) {
			return p
		}
	}
	return nil
}

func indexOf(parent, child *node) int {
	for i, c := range parent.children {
		if c == child {
			return i
		}
	}
	return -1
}

// walk visits n and its descendants in document order.
func walk(n *node, fn func(*node)) {
	fn(n)
	for _, c := range n.children {
		walk(c, fn)
	}
}

// serialize writes the subtree back as XML.
func serialize(n *node, b *strings.Builder) {
	switch n.kind {
	case kindRaw:
		b.WriteString(n.raw)
	case kindElem:
		b.WriteString(n.open)
		if n.self {
			return
		}
		for _, c := range n.children {
			serialize(c, b)
		}
		b.WriteString(n.close)
	}
}

// childElem returns the first child element named name, or nil.
func childElem(n *node, name string) *node {
	for _, c := range n.children {
		if c.isElem(name) {
			return c
		}
	}
	return nil
}

func serializeOrEmpty(n *node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	serialize(n, &b)
	return b.String()
}
