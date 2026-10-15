package brand

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func TestDefaultIsTodaysBrand(t *testing.T) {
	b := Default()
	if err := b.Validate(); err != nil {
		t.Fatalf("default brand invalid: %v", err)
	}
	p := b.Public()
	if p.Name != "OpenCTEM" || p.ShortName != "OpenCTEM" || p.DocsURL != "https://docs.openctem.io" {
		t.Fatalf("default public brand = %+v", p)
	}
	if p.PoweredBy {
		t.Error("the default brand must not credit itself")
	}
	if p.LogoLightURL != "" || p.LogoDarkURL != "" || p.FaviconURL != "" {
		t.Error("the default brand keeps the built-in images")
	}
}

func TestPublicReflectsConfig(t *testing.T) {
	b := Default()
	b.Name = "Acme Exposure"
	b.ShortName = ""
	b.DocsURL = "https://help.example.com/"
	a, err := NewAsset([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>`))
	if err != nil {
		t.Fatal(err)
	}
	b.Assets = map[AssetKind]Asset{AssetLogoLight: a}
	p := b.Public()
	if p.Name != "Acme Exposure" || p.ShortName != "Acme Exposure" {
		t.Errorf("names = %q / %q", p.Name, p.ShortName)
	}
	if !p.PoweredBy {
		t.Error("a renamed brand shows the credit by default")
	}
	if p.DocsURL != "https://help.example.com" {
		t.Errorf("docs = %q", p.DocsURL)
	}
	want := AssetPath + "logo-light?v=" + a.ETag
	if p.LogoLightURL != want || p.LogoDarkURL != want {
		t.Errorf("logo URLs = %q / %q, want %q (dark falls back to light)", p.LogoLightURL, p.LogoDarkURL, want)
	}
	if got := b.DocsLink("https://docs.openctem.io/sensors/#x"); got != "https://help.example.com/sensors/#x" {
		t.Errorf("DocsLink = %q", got)
	}
	if got := b.DocsLink("https://docs.openctem.io.evil.example/x"); got != "https://docs.openctem.io.evil.example/x" {
		t.Errorf("DocsLink rewrote another host: %q", got)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Brand){
		"empty name":       func(b *Brand) { b.Name = "" },
		"markup in name":   func(b *Brand) { b.Name = "<b>x</b>" },
		"placeholder":      func(b *Brand) { b.Name = "x {account}" },
		"control char":     func(b *Brand) { b.Name = "a\nb" },
		"long name":        func(b *Brand) { b.Name = strings.Repeat("a", 65) },
		"http docs":        func(b *Brand) { b.DocsURL = "http://docs.example.com" },
		"javascript url":   func(b *Brand) { b.SupportURL = "javascript:alert(1)" },
		"data url":         func(b *Brand) { b.TermsURL = "data:text/html,x" },
		"credentials":      func(b *Brand) { b.PrivacyURL = "https://u:p@example.com" },
		"relative url":     func(b *Brand) { b.WebsiteURL = "/x" },
		"bad color":        func(b *Brand) { b.PrimaryColor = "red" },
		"named email":      func(b *Brand) { b.SupportEmail = "Support <s@example.com>" },
		"footer control":   func(b *Brand) { b.EmailFooter = "a\x00b" },
		"footer too long":  func(b *Brand) { b.EmailFooter = strings.Repeat("a", 501) },
		"space in url":     func(b *Brand) { b.SupportURL = "https://example.com/a b" },
		"short name brace": func(b *Brand) { b.ShortName = "{x}" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			b := Default()
			mut(&b)
			if err := b.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	ok := Default()
	ok.Name, ok.PrimaryColor, ok.SupportURL = "Acme Exposure Cloud", "#0A7B83", "https://support.example.com/help?x=1"
	ok.EmailFooter = "Acme Ltd.\nExample Street 1"
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid brand refused: %v", err)
	}
}

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.Black)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestNewAsset(t *testing.T) {
	a, err := NewAsset(pngBytes(t, 8, 8))
	if err != nil || a.ContentType != TypePNG || a.ETag == "" {
		t.Fatalf("png: %+v %v", a.ContentType, err)
	}
	if _, err := NewAsset(pngBytes(t, 4097, 1)); err == nil {
		t.Error("oversized dimensions accepted")
	}
	big := append(pngBytes(t, 1, 1), make([]byte, MaxAssetBytes)...)
	if _, err := NewAsset(big); !errors.Is(err, ErrAssetTooLarge) {
		t.Errorf("size limit: %v", err)
	}
	if _, err := NewAsset(nil); err == nil {
		t.Error("empty accepted")
	}
	// A file named .png that is really HTML is identified by content.
	if _, err := NewAsset([]byte("<html><script>alert(1)</script></html>")); err == nil {
		t.Error("HTML accepted as an image")
	}
	if _, err := NewAsset([]byte("GIF89a....")); err == nil {
		t.Error("GIF is not on the allow list")
	}
}

func TestSanitizeSVGRefusesActiveContent(t *testing.T) {
	refuse := map[string]string{
		"script":          `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		"onload":          `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>`,
		"ONCLICK":         `<svg xmlns="http://www.w3.org/2000/svg"><rect ONCLICK="x()"/></svg>`,
		"foreignObject":   `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject></svg>`,
		"external use":    `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="https://evil.example/x.svg#a"/></svg>`,
		"javascript href": `<svg xmlns="http://www.w3.org/2000/svg"><use href="javascript:alert(1)"/></svg>`,
		"image":           `<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.example/t.png"/></svg>`,
		"anchor":          `<svg xmlns="http://www.w3.org/2000/svg"><a href="#x"><rect/></a></svg>`,
		"animate":         `<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="href" to="javascript:x"/></svg>`,
		"doctype entity":  `<!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>`,
		"style import":    `<svg xmlns="http://www.w3.org/2000/svg"><style>@import url(https://evil.example/a.css);</style></svg>`,
		"style url":       `<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url( 'https://evil.example/p')"/></svg>`,
		"style js":        `<svg xmlns="http://www.w3.org/2000/svg"><rect style="background:java script:x"/></svg>`,
		"css escape":      `<svg xmlns="http://www.w3.org/2000/svg"><style>.a{fill:\75 rl(https://evil.example/p)}</style></svg>`,
		"attr css escape": `<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:\75 rl(https://evil.example/p)"/></svg>`,
		"not svg":         `<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>`,
		"broken":          `<svg xmlns="http://www.w3.org/2000/svg"><rect></svg>`,
		"nested script":   `<svg xmlns="http://www.w3.org/2000/svg"><metadata><script>x</script></metadata></svg>`,
	}
	for name, in := range refuse {
		t.Run(name, func(t *testing.T) {
			if out, err := SanitizeSVG([]byte(in)); err == nil {
				t.Fatalf("accepted: %s", out)
			}
		})
	}
}

func TestSanitizeSVGKeepsDrawing(t *testing.T) {
	in := `<?xml version="1.0"?>
<!-- exported -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10" inkscape:version="1">
  <metadata><rdf>x</rdf></metadata>
  <defs><linearGradient id="g"><stop offset="0" stop-color="#000"/></linearGradient></defs>
  <style>.a{fill:url(#g)}</style>
  <title>Acme &amp; Co</title>
  <g class="a"><path d="M0 0L10 10" fill="url(#g)"/><use xlink:href="#g"/></g>
</svg>`
	out, err := SanitizeSVG([]byte(in))
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	s := string(out)
	for _, want := range []string{`<svg xmlns="http://www.w3.org/2000/svg"`, `viewBox="0 0 10 10"`, `<path d="M0 0L10 10" fill="url(#g)">`, `xlink:href="#g"`, `Acme &amp; Co`, `.a{fill:url(#g)}`} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	for _, gone := range []string{"metadata", "rdf", "inkscape", "<!--", "<?xml"} {
		if strings.Contains(s, gone) {
			t.Errorf("output keeps %q:\n%s", gone, s)
		}
	}
	// The output is itself accepted (idempotent).
	if _, err := SanitizeSVG(out); err != nil {
		t.Errorf("sanitized output refused: %v", err)
	}
}
