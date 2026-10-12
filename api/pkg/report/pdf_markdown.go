package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/go-pdf/fpdf"

	"github.com/openctemio/openctem/api/pkg/report/markdown"
)

// PDF rendering of finding Markdown: paragraphs, headings, lists, quotes,
// code blocks, bold/italic/code and evidence images. The current font family
// is kept (only style and size change), so this works with whichever font the
// report is set in.

const mdLineHeight = 5.0

// markdownField writes a labeled Markdown section, like findingField.
func markdownField(pdf *fpdf.Fpdf, tr translator, label, value string, images map[string]markdown.Image) {
	if strings.TrimSpace(value) == "" {
		return
	}
	pdf.SetFontStyle("B")
	pdf.SetFontSize(10)
	pdf.SetTextColor(80, 80, 80)
	pdf.CellFormat(0, 6, tr(label), "", 1, "L", false, 0, "")
	writeMarkdown(pdf, tr, value, images)
}

// writeMarkdown writes Markdown as body text.
func writeMarkdown(pdf *fpdf.Fpdf, tr translator, md string, images map[string]markdown.Image) {
	pdf.SetFontSize(10)
	pdf.SetTextColor(40, 40, 40)
	for _, blk := range markdown.Parse(md) {
		pdf.SetFontStyle("")
		switch blk.Kind {
		case markdown.Code:
			pdf.SetFillColor(243, 244, 246)
			pdf.SetFontSize(9)
			pdf.MultiCell(0, mdLineHeight, tr(blk.Text), "", "L", true)
			pdf.SetFontSize(10)
			continue
		case markdown.Heading:
			writeInlines(pdf, tr, blk.Inlines, images, "B")
		case markdown.Bullet:
			pdf.Write(mdLineHeight, tr("•  "))
			writeInlines(pdf, tr, blk.Inlines, images, "")
		case markdown.Numbered:
			pdf.Write(mdLineHeight, tr(blk.Text+"  "))
			writeInlines(pdf, tr, blk.Inlines, images, "")
		case markdown.Quote:
			writeInlines(pdf, tr, blk.Inlines, images, "I")
		default:
			writeInlines(pdf, tr, blk.Inlines, images, "")
		}
		pdf.Ln(mdLineHeight + 1)
	}
	pdf.SetFontStyle("")
}

func writeInlines(pdf *fpdf.Fpdf, tr translator, in []markdown.Inline, images map[string]markdown.Image, baseStyle string) {
	for _, s := range in {
		switch {
		case s.Break:
			pdf.Ln(mdLineHeight)
		case s.Image != "":
			if img, ok := images[s.Image]; ok && len(img.Data) > 0 {
				writeImage(pdf, img)
			} else {
				pdf.SetFontStyle(baseStyle)
				pdf.Write(mdLineHeight, tr("["+s.Text+"]"))
			}
		case s.Link != "":
			pdf.SetFontStyle(baseStyle)
			text := s.Text
			if markdown.SafeLink(s.Link) && s.Link != s.Text {
				text += " (" + s.Link + ")"
			}
			pdf.Write(mdLineHeight, tr(text))
		default:
			// The embedded font has regular, bold and italic: bold wins.
			style := baseStyle
			switch {
			case s.Bold:
				style = "B"
			case s.Italic && style == "":
				style = "I"
			}
			pdf.SetFontStyle(style)
			if s.Code {
				pdf.SetTextColor(150, 30, 60)
			}
			pdf.Write(mdLineHeight, tr(s.Text))
			if s.Code {
				pdf.SetTextColor(40, 40, 40)
			}
		}
	}
	pdf.SetFontStyle("")
}

// writeImage places an evidence image on its own line, scaled to the content
// width (96 dpi natural size), on a new page when it does not fit.
func writeImage(pdf *fpdf.Fpdf, img markdown.Image) {
	imageType := map[string]string{"image/png": "PNG", "image/jpeg": "JPG", "image/gif": "GIF"}[img.ContentType]
	if imageType == "" || img.Width <= 0 || img.Height <= 0 {
		return
	}
	left, _, right, bottom := pdf.GetMargins()
	pageW, pageH := pdf.GetPageSize()
	maxW := pageW - left - right
	w := float64(img.Width) * 25.4 / 96
	if w > maxW {
		w = maxW
	}
	h := w * float64(img.Height) / float64(img.Width)
	if maxH := pageH * 0.6; h > maxH {
		h = maxH
		w = h * float64(img.Width) / float64(img.Height)
	}
	if pdf.GetX() > left+0.1 {
		pdf.Ln(mdLineHeight)
	}
	if pdf.GetY()+h > pageH-bottom {
		pdf.AddPage()
	}
	sum := sha256.Sum256(img.Data)
	name := "evidence-" + hex.EncodeToString(sum[:8])
	opts := fpdf.ImageOptions{ImageType: imageType}
	if info := pdf.GetImageInfo(name); info == nil {
		pdf.RegisterImageOptionsReader(name, opts, bytes.NewReader(img.Data))
	}
	if pdf.Err() {
		// A corrupt image must not fail the whole report.
		pdf.ClearError()
		return
	}
	pdf.ImageOptions(name, left, pdf.GetY(), w, h, true, opts, 0, "")
	pdf.Ln(1)
}
