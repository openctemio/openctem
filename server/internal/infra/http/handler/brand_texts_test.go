package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/brand"
)

// Pages the API renders itself name the brand, escaped.
func TestAPIPagesNameTheBrand(t *testing.T) {
	rec := httptest.NewRecorder()
	serveDocsPage(rec, "/openapi.yaml", "no-store")
	if !strings.Contains(rec.Body.String(), "<title>OpenCTEM API Documentation</title>") {
		t.Fatal("default docs title changed")
	}

	b := brand.Default()
	b.Name = `Example's "Exposure" & Co`
	brand.SetInstance(b)
	t.Cleanup(func() { brand.SetInstance(brand.Default()) })

	rec = httptest.NewRecorder()
	serveDocsPage(rec, "/openapi.yaml", "no-store")
	page := rec.Body.String()
	if !strings.Contains(page, "<title>Example&#39;s &#34;Exposure&#34; &amp; Co API Documentation</title>") {
		t.Errorf("docs title not branded or not escaped")
	}
	if !strings.Contains(page, `"title": &#34;Example&#39;s \&#34;Exposure\&#34; \u0026 Co API&#34;`) {
		t.Errorf("docs configuration title not JSON-then-HTML escaped")
	}
	if strings.Contains(page, "OpenCTEM") {
		t.Error("docs page still names OpenCTEM")
	}

	rec = httptest.NewRecorder()
	writeOAuthErrorPage(rec, "invalid_client")
	if !strings.Contains(rec.Body.String(), "connect to Example&#39;s &#34;Exposure&#34; &amp; Co in a way") {
		t.Errorf("OAuth error page not branded or not escaped")
	}
}
