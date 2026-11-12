package markdown

import (
	"encoding/base64"
	"html"
	"strings"
)

// Image is an evidence image a report embeds. Only PNG, JPEG and GIF are
// accepted by the loader; Width and Height are in pixels.
type Image struct {
	ContentType string
	Data        []byte
	Width       int
	Height      int
}

// HTML renders Markdown as HTML. Every text is escaped; links are kept only
// for http(s) and mailto; images are embedded as data URIs when the report
// resolved them (evidence of the same finding) and shown as their alt text
// otherwise, so a report never loads anything from the network.
func HTML(md string, images map[string]Image) string {
	var b strings.Builder
	var list string // "ul" or "ol" while inside a list
	closeList := func() {
		if list != "" {
			b.WriteString("</" + list + ">")
			list = ""
		}
	}
	for _, blk := range Parse(md) {
		switch blk.Kind {
		case Bullet, Numbered:
			want := "ul"
			if blk.Kind == Numbered {
				want = "ol"
			}
			if list != want {
				closeList()
				b.WriteString("<" + want + ">")
				list = want
			}
			b.WriteString("<li>")
			inlineHTML(&b, blk.Inlines, images)
			b.WriteString("</li>")
			continue
		}
		closeList()
		switch blk.Kind {
		case Heading:
			b.WriteString("<p><strong>")
			inlineHTML(&b, blk.Inlines, images)
			b.WriteString("</strong></p>")
		case Quote:
			b.WriteString("<blockquote>")
			inlineHTML(&b, blk.Inlines, images)
			b.WriteString("</blockquote>")
		case Code:
			b.WriteString("<pre><code>")
			b.WriteString(html.EscapeString(blk.Text))
			b.WriteString("</code></pre>")
		default:
			b.WriteString("<p>")
			inlineHTML(&b, blk.Inlines, images)
			b.WriteString("</p>")
		}
	}
	closeList()
	return b.String()
}

func inlineHTML(b *strings.Builder, in []Inline, images map[string]Image) {
	for _, s := range in {
		switch {
		case s.Break:
			b.WriteString("<br>")
		case s.Image != "":
			if img, ok := images[s.Image]; ok && len(img.Data) > 0 {
				b.WriteString(`<img class="evidence" alt="`)
				b.WriteString(html.EscapeString(s.Text))
				b.WriteString(`" src="data:`)
				b.WriteString(html.EscapeString(img.ContentType))
				b.WriteString(`;base64,`)
				b.WriteString(base64.StdEncoding.EncodeToString(img.Data))
				b.WriteString(`">`)
			} else {
				b.WriteString("[" + html.EscapeString(s.Text) + "]")
			}
		case s.Link != "":
			if SafeLink(s.Link) {
				b.WriteString(`<a href="` + html.EscapeString(s.Link) + `" rel="noopener noreferrer">`)
				b.WriteString(html.EscapeString(s.Text))
				b.WriteString("</a>")
			} else {
				b.WriteString(html.EscapeString(s.Text))
			}
		default:
			t := html.EscapeString(s.Text)
			if s.Code {
				t = "<code>" + t + "</code>"
			}
			if s.Italic {
				t = "<em>" + t + "</em>"
			}
			if s.Bold {
				t = "<strong>" + t + "</strong>"
			}
			b.WriteString(t)
		}
	}
}
