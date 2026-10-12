package docx

import (
	"regexp"
	"strings"
)

// markdownToOOXML renders the Markdown that findings are written in as Word
// paragraphs carrying the template paragraph's and run's formatting:
// paragraphs and line breaks, headings (bold), bullet and numbered lists,
// block quotes (italic), fenced code blocks (monospace), and inline bold,
// italic, code and links. Images are written as their alt text in brackets.
// Raw HTML is written as text. Empty input still yields one empty paragraph,
// so a table cell never ends up without one.
func markdownToOOXML(md, pPr, rPr string) string {
	var b strings.Builder
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var para []string
	flush := func() {
		if len(para) == 0 {
			return
		}
		writeParagraph(&b, pPr, rPr, strings.Join(para, "\n"))
		para = nil
	}
	inCode := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			flush()
			inCode = !inCode
			continue
		}
		if inCode {
			writeCodeParagraph(&b, pPr, rPr, line)
			continue
		}
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "#"):
			flush()
			writeParagraph(&b, pPr, withProp(rPr, "<w:b/>"), strings.TrimSpace(strings.TrimLeft(trimmed, "#")))
		case bulletRe.MatchString(trimmed):
			flush()
			writeParagraph(&b, pPr, rPr, "• "+bulletRe.ReplaceAllString(trimmed, ""))
		case numberRe.MatchString(trimmed):
			flush()
			writeParagraph(&b, pPr, rPr, trimmed)
		case strings.HasPrefix(trimmed, ">"):
			flush()
			writeParagraph(&b, pPr, withProp(rPr, "<w:i/>"), strings.TrimSpace(strings.TrimPrefix(trimmed, ">")))
		default:
			para = append(para, trimmed)
		}
	}
	flush()
	if b.Len() == 0 {
		b.WriteString("<w:p>" + pPr + "</w:p>")
	}
	return b.String()
}

var (
	bulletRe = regexp.MustCompile(`^[-*+]\s+`)
	numberRe = regexp.MustCompile(`^\d+[.)]\s+`)
)

func writeParagraph(b *strings.Builder, pPr, rPr, text string) {
	b.WriteString("<w:p>")
	b.WriteString(pPr)
	for _, seg := range inlineSegments(text) {
		props := rPr
		if seg.bold {
			props = withProp(props, "<w:b/>")
		}
		if seg.italic {
			props = withProp(props, "<w:i/>")
		}
		if seg.code {
			props = withProp(props, monoFont)
		}
		b.WriteString("<w:r>")
		b.WriteString(props)
		writeTextRuns(b, seg.text)
		b.WriteString("</w:r>")
	}
	b.WriteString("</w:p>")
}

func writeCodeParagraph(b *strings.Builder, pPr, rPr, line string) {
	b.WriteString("<w:p>")
	b.WriteString(pPr)
	if line != "" {
		b.WriteString("<w:r>")
		b.WriteString(withProp(rPr, monoFont))
		b.WriteString(`<w:t xml:space="preserve">`)
		b.WriteString(escapeText(line))
		b.WriteString("</w:t></w:r>")
	}
	b.WriteString("</w:p>")
}

const monoFont = `<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>`

// withProp adds one run property to a w:rPr (creating it when empty).
func withProp(rPr, prop string) string {
	if rPr == "" {
		return "<w:rPr>" + prop + "</w:rPr>"
	}
	if strings.HasSuffix(rPr, "/>") && strings.HasPrefix(rPr, "<w:rPr") {
		return "<w:rPr>" + prop + "</w:rPr>"
	}
	i := strings.Index(rPr, ">")
	if i < 0 {
		return rPr
	}
	return rPr[:i+1] + prop + rPr[i+1:]
}

type inlineSeg struct {
	text               string
	bold, italic, code bool
}

var (
	imageRe = regexp.MustCompile(`!\[([^\]]*)\]\([^)]*\)`)
	linkRe  = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
)

// inlineSegments splits a line on **bold**, *italic* / _italic_ and `code`.
func inlineSegments(text string) []inlineSeg {
	text = imageRe.ReplaceAllString(text, "[$1]")
	text = linkRe.ReplaceAllString(text, "$1 ($2)")
	var out []inlineSeg
	var cur strings.Builder
	bold, italic := false, false
	emit := func(code bool) {
		if cur.Len() > 0 {
			out = append(out, inlineSeg{text: cur.String(), bold: bold, italic: italic, code: code})
			cur.Reset()
		}
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '`':
			if j := strings.IndexByte(text[i+1:], '`'); j >= 0 {
				emit(false)
				cur.WriteString(text[i+1 : i+1+j])
				emit(true)
				i += j + 1
				continue
			}
			cur.WriteByte(c)
		case c == '*' && i+1 < len(text) && text[i+1] == '*':
			emit(false)
			bold = !bold
			i++
		case (c == '*' || c == '_') && emphasisBoundary(text, i):
			emit(false)
			italic = !italic
		default:
			cur.WriteByte(c)
		}
	}
	emit(false)
	return out
}

// emphasisBoundary reports whether a single * or _ at i toggles italic: it
// must touch a word on one side and not sit inside a word (snake_case stays).
func emphasisBoundary(s string, i int) bool {
	before := i > 0 && isWordByte(s[i-1])
	after := i+1 < len(s) && isWordByte(s[i+1])
	return before != after
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}
