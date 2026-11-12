package docx

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/report/markdown"
)

// markdownToOOXML renders the Markdown that findings are written in as Word
// paragraphs carrying the template paragraph's and run's formatting:
// paragraphs and line breaks, headings (bold), bullet and numbered lists,
// block quotes (italic), fenced code blocks (monospace), inline bold, italic,
// code and links, and evidence images the report resolved (others show their
// alt text). Raw HTML is written as text. Empty input still yields one empty
// paragraph, so a table cell never ends up without one.
func markdownToOOXML(md, pPr, rPr string, media *mediaSink) string {
	var b strings.Builder
	for _, blk := range markdown.Parse(md) {
		switch blk.Kind {
		case markdown.Code:
			for _, line := range strings.Split(blk.Text, "\n") {
				writeCodeParagraph(&b, pPr, rPr, line)
			}
		case markdown.Heading:
			writeParagraph(&b, pPr, withProp(rPr, "<w:b/>"), "", blk.Inlines, media)
		case markdown.Bullet:
			writeParagraph(&b, pPr, rPr, "• ", blk.Inlines, media)
		case markdown.Numbered:
			writeParagraph(&b, pPr, rPr, blk.Text+" ", blk.Inlines, media)
		case markdown.Quote:
			writeParagraph(&b, pPr, withProp(rPr, "<w:i/>"), "", blk.Inlines, media)
		default:
			writeParagraph(&b, pPr, rPr, "", blk.Inlines, media)
		}
	}
	if b.Len() == 0 {
		b.WriteString("<w:p>" + pPr + "</w:p>")
	}
	return b.String()
}

func writeParagraph(b *strings.Builder, pPr, rPr, prefix string, in []markdown.Inline, media *mediaSink) {
	b.WriteString("<w:p>")
	b.WriteString(pPr)
	if prefix != "" {
		writeRun(b, rPr, prefix)
	}
	for _, s := range in {
		switch {
		case s.Break:
			b.WriteString("<w:r>" + rPr + "<w:br/></w:r>")
		case s.Image != "":
			if drawing, ok := media.drawing(s.Image, s.Text); ok {
				b.WriteString("<w:r>" + rPr + drawing + "</w:r>")
			} else {
				writeRun(b, rPr, "["+s.Text+"]")
			}
		case s.Link != "":
			text := s.Text
			if markdown.SafeLink(s.Link) && s.Link != s.Text {
				text += " (" + s.Link + ")"
			}
			writeRun(b, rPr, text)
		default:
			props := rPr
			if s.Bold {
				props = withProp(props, "<w:b/>")
			}
			if s.Italic {
				props = withProp(props, "<w:i/>")
			}
			if s.Code {
				props = withProp(props, monoFont)
			}
			writeRun(b, props, s.Text)
		}
	}
	b.WriteString("</w:p>")
}

func writeRun(b *strings.Builder, rPr, text string) {
	b.WriteString("<w:r>")
	b.WriteString(rPr)
	writeTextRuns(b, text)
	b.WriteString("</w:r>")
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

// mediaSink collects the evidence images a document part embeds. A nil sink
// (headers, footers, or a report without images) embeds nothing.
type mediaSink struct {
	images map[string]markdown.Image
	used   []mediaFile
	byURL  map[string]int
}

type mediaFile struct {
	relID  string
	name   string // word/media/<name>
	ext    string
	img    markdown.Image
	docPr  int
	widthE int64 // EMU
	heighE int64
}

const (
	emuPerPixel   = 9525    // 96 dpi
	maxImageWidth = 5486400 // 6 inches
)

func newMediaSink(images map[string]markdown.Image) *mediaSink {
	if len(images) == 0 {
		return nil
	}
	return &mediaSink{images: images, byURL: map[string]int{}}
}

// drawing returns the inline drawing for an image URL the report resolved.
func (m *mediaSink) drawing(url, alt string) (string, bool) {
	if m == nil {
		return "", false
	}
	img, ok := m.images[url]
	if !ok || len(img.Data) == 0 || img.Width <= 0 || img.Height <= 0 {
		return "", false
	}
	ext := map[string]string{"image/png": "png", "image/jpeg": "jpeg", "image/gif": "gif"}[img.ContentType]
	if ext == "" {
		return "", false
	}
	idx, seen := m.byURL[url]
	if !seen {
		n := len(m.used) + 1
		w := int64(img.Width) * emuPerPixel
		h := int64(img.Height) * emuPerPixel
		if w > maxImageWidth {
			h = h * maxImageWidth / w
			w = maxImageWidth
		}
		m.used = append(m.used, mediaFile{
			relID: "rIdEvidence" + strconv.Itoa(n), name: fmt.Sprintf("evidence-%d.%s", n, ext), ext: ext,
			img: img, docPr: 9000 + n, widthE: w, heighE: h,
		})
		idx = len(m.used) - 1
		m.byURL[url] = idx
	}
	f := m.used[idx]
	return fmt.Sprintf(`<w:drawing><wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" distT="0" distB="0" distL="0" distR="0">`+
		`<wp:extent cx="%d" cy="%d"/><wp:docPr id="%d" name="Evidence %d" descr="%s"/>`+
		`<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">`+
		`<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="%d" name="%s"/><pic:cNvPicPr/></pic:nvPicPr>`+
		`<pic:blipFill><a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:embed="%s"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>`+
		`<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>`+
		`</a:graphicData></a:graphic></wp:inline></w:drawing>`,
		f.widthE, f.heighE, f.docPr, f.docPr, escapeText(alt), f.docPr, f.name, f.relID, f.widthE, f.heighE), true
}
