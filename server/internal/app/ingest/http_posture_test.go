package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/webendpoint"
)

func originWithHeaders(id, value string, h *ctis.SecurityHeaders) ctis.Asset {
	a := ctis.Asset{ID: id, Type: ctis.AssetTypeWebOrigin, Value: value}
	if h != nil {
		a.Technical = &ctis.AssetTechnical{HTTP: &ctis.HTTPTechnical{SecurityHeaders: h}}
	}
	return a
}

// The posture is derived from technical.http.security_headers: flags and
// enums only, never a header or cookie value; a producer's own
// properties.http_posture is dropped (properties carry no meaning).
func TestSanitizeHTTPPosture(t *testing.T) {
	r := &ctis.Report{Assets: []ctis.Asset{
		originWithHeaders("a1", "https://a.example.com", &ctis.SecurityHeaders{
			StrictTransportSecurity: "max-age=31536000; includeSubDomains",
			ContentSecurityPolicy:   "default-src 'self' 'unsafe-inline' https://SECRET.example",
			XFrameOptions:           "DENY",
			Cookies:                 []ctis.CookieFlags{{Name: "sid", IsSecure: true, IsHTTPOnly: true}},
		}),
		originWithHeaders("a2", "https://b.example.com", &ctis.SecurityHeaders{}),
		originWithHeaders("a3", "https://c.example.com", nil), // an older producer: no headers
		{ID: "a4", Type: ctis.AssetTypeDomainName, Value: "example.com", Properties: ctis.Properties{webendpoint.PostureKey: map[string]any{"hsts": true}}},
		{ID: "a5", Type: ctis.AssetTypeWebOrigin, Value: "https://d.example.com", Properties: ctis.Properties{
			webendpoint.PostureKey: map[string]any{"hsts": true, "set_cookie": "sid=SECRET"}}}, // producer posture dropped
	}}
	sanitizeHTTPPosture(r, nil)

	var props []ctis.Properties
	for i := range r.Assets {
		props = append(props, r.Assets[i].Properties)
	}
	b, _ := json.Marshal(props)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "default-src") || strings.Contains(string(b), "sid=") {
		t.Fatalf("a header or cookie value was kept in the stored properties: %s", b)
	}
	p, ok := r.Assets[0].Properties[webendpoint.PostureKey].(map[string]any)
	if !ok {
		t.Fatalf("posture missing: %s", b)
	}
	if p["hsts"] != true || p["hsts_include_subdomains"] != true || p["csp"] != true || p["csp_unsafe_inline"] != true || p["frame_options"] != "deny" {
		t.Fatalf("flags = %v", p)
	}
	for _, i := range []int{2, 3, 4} {
		if _, ok := r.Assets[i].Properties[webendpoint.PostureKey]; ok {
			t.Fatalf("asset %d kept a posture it must not", i)
		}
	}
	if r.Assets[2].Properties != nil {
		t.Fatal("absence must change nothing")
	}
	sanitizeHTTPPosture(nil, nil)
}
