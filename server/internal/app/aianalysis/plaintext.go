package aianalysis

import "strings"

// plainText makes model text safe to store in a comment or a request that
// the console renders as markdown: every character markdown or HTML gives a
// meaning (links, images, raw HTML, entities, emphasis, code, tables,
// headings, quotes) is backslash-escaped, so the text reads exactly as
// written and nothing in it renders as a link, an image or markup. Bare
// addresses are broken too ("https\://", "www\."), so the renderer does not
// turn them into links. Model and worker output is untrusted data.
func plainText(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '<', '>', '#', '+', '!', '|', '~', '&', '"':
			b.WriteByte('\\')
		case ':':
			if strings.HasPrefix(s[i:], "://") {
				b.WriteByte('\\')
			}
		case '.':
			if i >= 3 && strings.EqualFold(s[i-3:i], "www") {
				b.WriteByte('\\')
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}
