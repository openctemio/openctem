package email

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/brand"
)

func TestBrandingFooter(t *testing.T) {
	e := NewTemplateEngine()
	data := WelcomeData{UserName: "A", Email: "a@example.com", LoginURL: "https://ctem.example.com", AppName: "OpenCTEM"}
	_, body, err := e.Render(TemplateWelcome, data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "Powered by") || !strings.Contains(body, "https://docs.openctem.io/") {
		t.Errorf("default email changed")
	}

	b := brand.Default()
	b.Name, b.DocsURL = "Example Exposure", "https://docs.example.com"
	brand.SetInstance(b)
	t.Cleanup(func() { brand.SetInstance(brand.Default()) })
	data.AppName = b.Name
	data.Branding = Branding{FooterText: "Example Ltd.\n<b>1 Example Street</b>", PoweredBy: b.ShowPoweredBy()}
	subject, body, err := e.Render(TemplateWelcome, data)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Welcome to Example Exposure" {
		t.Errorf("subject = %q", subject)
	}
	for _, want := range []string{"Example Ltd.<br>&lt;b&gt;1 Example Street&lt;/b&gt;", "Powered by OpenCTEM", "https://docs.example.com/"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	if strings.Contains(body, "docs.openctem.io") {
		t.Error("body still links the default documentation")
	}
}
