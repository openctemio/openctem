// Package markdown parses the Markdown that pentest findings are written in
// into a small block/inline tree that the report renderers (HTML, PDF) turn
// into output. It is a deliberately small subset: paragraphs and line breaks,
// headings, bullet and numbered lists, block quotes, fenced code blocks, and
// inline bold, italic, code, links and images. Raw HTML is plain text: the
// renderers escape everything, so finding text can never inject markup.
package markdown

import (
	"regexp"
	"strings"
)

// BlockKind is the kind of a block.
type BlockKind int

const (
	Paragraph BlockKind = iota
	Heading
	Bullet
	Numbered
	Quote
	Code
)

// Block is one paragraph-level element.
type Block struct {
	Kind    BlockKind
	Inlines []Inline // all kinds but Code
	Text    string   // Code: the code; Numbered: the number label ("3.")
}

// Inline is a run of text with its emphasis, or an image.
type Inline struct {
	Text   string
	Bold   bool
	Italic bool
	Code   bool
	Link   string // the URL of a link (Text is its label)
	Image  string // the URL of an image (Text is its alt text)
	Break  bool   // a line break inside a paragraph
}

var (
	bulletRe = regexp.MustCompile(`^[-*+]\s+`)
	numberRe = regexp.MustCompile(`^(\d+[.)])\s+`)
	imageRe  = regexp.MustCompile(`!\[([^\]]*)\]\(([^)\s]+)\)`)
	linkRe   = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
)

// Parse splits Markdown into blocks.
func Parse(md string) []Block {
	var blocks []Block
	var para []string
	flush := func() {
		if len(para) == 0 {
			return
		}
		var in []Inline
		for i, line := range para {
			if i > 0 {
				in = append(in, Inline{Break: true})
			}
			in = append(in, ParseInline(line)...)
		}
		blocks = append(blocks, Block{Kind: Paragraph, Inlines: in})
		para = nil
	}
	var code []string
	inCode := false
	for _, line := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			if inCode {
				blocks = append(blocks, Block{Kind: Code, Text: strings.Join(code, "\n")})
				code = nil
			} else {
				flush()
			}
			inCode = !inCode
			continue
		}
		if inCode {
			code = append(code, line)
			continue
		}
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "#"):
			flush()
			blocks = append(blocks, Block{Kind: Heading, Inlines: ParseInline(strings.TrimSpace(strings.TrimLeft(trimmed, "#")))})
		case bulletRe.MatchString(trimmed):
			flush()
			blocks = append(blocks, Block{Kind: Bullet, Inlines: ParseInline(bulletRe.ReplaceAllString(trimmed, ""))})
		case numberRe.MatchString(trimmed):
			flush()
			m := numberRe.FindStringSubmatch(trimmed)
			blocks = append(blocks, Block{Kind: Numbered, Text: m[1], Inlines: ParseInline(numberRe.ReplaceAllString(trimmed, ""))})
		case strings.HasPrefix(trimmed, ">"):
			flush()
			blocks = append(blocks, Block{Kind: Quote, Inlines: ParseInline(strings.TrimSpace(strings.TrimPrefix(trimmed, ">")))})
		default:
			para = append(para, trimmed)
		}
	}
	if inCode && len(code) > 0 {
		blocks = append(blocks, Block{Kind: Code, Text: strings.Join(code, "\n")})
	}
	flush()
	return blocks
}

// ParseInline splits one line on images, links, **bold**, *italic* /
// _italic_ and `code`.
func ParseInline(text string) []Inline {
	var out []Inline
	for text != "" {
		img := imageRe.FindStringSubmatchIndex(text)
		lnk := linkRe.FindStringSubmatchIndex(text)
		switch {
		case len(img) >= 6 && (len(lnk) < 6 || img[0] <= lnk[0]):
			out = append(out, emphasis(text[:img[0]])...)
			out = append(out, Inline{Image: text[img[4]:img[5]], Text: text[img[2]:img[3]]})
			text = text[img[1]:]
		case len(lnk) >= 6:
			out = append(out, emphasis(text[:lnk[0]])...)
			out = append(out, Inline{Link: text[lnk[4]:lnk[5]], Text: text[lnk[2]:lnk[3]]})
			text = text[lnk[1]:]
		default:
			out = append(out, emphasis(text)...)
			text = ""
		}
	}
	return out
}

func emphasis(text string) []Inline {
	var out []Inline
	var cur strings.Builder
	bold, italic := false, false
	emit := func(code bool) {
		if cur.Len() > 0 {
			out = append(out, Inline{Text: cur.String(), Bold: bold, Italic: italic, Code: code})
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
		case (c == '*' || c == '_') && boundary(text, i):
			emit(false)
			italic = !italic
		default:
			cur.WriteByte(c)
		}
	}
	emit(false)
	return out
}

// boundary: a single * or _ toggles italic only next to a word on exactly
// one side (snake_case and 2 * 3 stay text).
func boundary(s string, i int) bool {
	before := i > 0 && isWord(s[i-1])
	after := i+1 < len(s) && isWord(s[i+1])
	return before != after
}

func isWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}

// ImageURLs returns the image URLs a Markdown text references, in order,
// without duplicates.
func ImageURLs(md string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range imageRe.FindAllStringSubmatch(md, -1) {
		if !seen[m[2]] {
			seen[m[2]] = true
			out = append(out, m[2])
		}
	}
	return out
}

// SafeLink reports whether a link URL may be rendered as a link: http(s) or
// mailto only. Other links render as their text.
func SafeLink(u string) bool {
	l := strings.ToLower(strings.TrimSpace(u))
	return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "mailto:")
}
