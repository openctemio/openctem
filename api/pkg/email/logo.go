package email

import (
	_ "embed" // the logo image ships inside the binary
	"html/template"
	"strings"

	"github.com/openctemio/openctem/api/pkg/brand"
)

// logoPNG is the OpenCTEM lockup (ink, teal marker) at 280 x 43 px, shown at
// 140 x 22. It is generated from the brand SVGs (web/scripts/brand-gen.mjs).
//
//go:embed assets/logo@2x.png
var logoPNG []byte

// logoCID is the Content-ID the header image is attached under. The image is
// part of the message: no remote URL, so nothing is fetched when the mail is
// opened (no tracking pixel) and it shows offline.
const logoCID = "logo"

// InlineImage is an image attached to the message and referenced from the
// HTML body as cid:<CID>.
type InlineImage struct {
	CID         string
	ContentType string
	Data        []byte
}

// brandHeader is the header of every template. For the OpenCTEM brand it is
// the embedded lockup, with the name as alt text for clients that block
// images. An operator's brand gets its name in brand ink (their own logo is
// never fetched into mail), escaped.
func brandHeader(appName string) template.HTML {
	if appName == brand.DefaultName {
		return template.HTML(`<img src="cid:` + logoCID + `" width="140" height="22" alt="` + //nolint:gosec // constants only
			template.HTMLEscapeString(appName) + `" style="display:block;margin:0 auto;border:0;height:22px;width:140px;">`)
	}
	return template.HTML(`<div class="logo">` + template.HTMLEscapeString(appName) + `</div>`) //nolint:gosec // escaped
}

// bodyTemplate parses an HTML email body with the shared header function and
// any extra functions the template needs.
func bodyTemplate(name, text string, extra ...template.FuncMap) *template.Template {
	t := template.New(name).Funcs(template.FuncMap{"brandHeader": brandHeader})
	for _, f := range extra {
		t = t.Funcs(f)
	}
	return template.Must(t.Parse(text))
}

// usesLogo reports whether a rendered body references the embedded logo.
func usesLogo(body string) bool {
	return strings.Contains(body, `src="cid:`+logoCID+`"`)
}
