package notifier

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/brand"
)

func TestFactoryNamesTheBrand(t *testing.T) {
	cfg := Config{Provider: ProviderEmail, Email: &EmailConfig{SMTPHost: "smtp.example.com", SMTPPort: 587, FromEmail: "n@example.com", ToEmails: []string{"t@example.com"}}}

	c, err := NewEmailClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	html, err := c.buildHTMLEmail(Message{Title: "t"})
	if err != nil || !strings.Contains(html, "Sent by OpenCTEM at") {
		t.Fatalf("default footer changed: %v", err)
	}

	f := NewClientFactory()
	b := brand.Default()
	b.Name, b.WebsiteURL = "Example Exposure", "https://example.com"
	f.SetBrand(b)
	client, err := f.CreateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ec := client.(cleaningClient).Client.(*EmailClient)
	if ec.product != "Example Exposure" {
		t.Errorf("product = %q", ec.product)
	}
	html, err = ec.buildHTMLEmail(Message{Title: "t"})
	if err != nil || !strings.Contains(html, `Sent by <a href="https://example.com">Example Exposure</a>`) {
		t.Errorf("footer does not name the brand: %v", err)
	}
}
