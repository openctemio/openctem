package ingest

import (
	"testing"

	"github.com/openctemio/ctis/v2"

	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
)

func TestFindingEvidenceFromEvidenceItems(t *testing.T) {
	cf := &ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		RuleID:   "wordpress-click2shell",
		RuleRef:  "r1",
		Location: &ctis.FindingLocation{Path: "https://shop.example.com/wp-admin/js/theme.js"},
		EvidenceItems: []ctis.EvidenceItem{
			{Kind: ctis.EvidenceKindHTTPExchange, Label: "nuclei wordpress-click2shell", HTTP: &ctis.EvidenceHTTP{
				Request:  &ctis.EvidenceRequest{Method: "GET", URL: "https://shop.example.com/wp-admin/js/theme.js"},
				Response: &ctis.EvidenceResponse{Status: 200, Body: "slug + '\"]' ).trigger( 'click' );"},
			}},
			{Kind: ctis.EvidenceKindCurl, Text: "curl 'https://shop.example.com/wp-admin/js/theme.js'"},
		},
		// properties carry no meaning: these produce no evidence.
		Properties: ctis.Properties{"request": "GET / HTTP/1.1\r\n\r\n", "curl_command": "curl x"},
	}
	report := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"}, Rules: []ctis.Rule{{ID: "r1", RuleID: "wordpress-click2shell", ContentSHA256: hexDigest("a")}}}
	d, ok := findingEvidence("fp1", cf, report)
	if !ok || d.Fingerprint != "fp1" || len(d.Items) != 2 {
		t.Fatalf("detection = %+v %v", d, ok)
	}
	ex := d.Items[0]
	if ex.Kind != evidencedom.KindHTTPExchange || ex.HTTP.Request.URL != "https://shop.example.com/wp-admin/js/theme.js" ||
		ex.HTTP.Response.Status != 200 || ex.Label != "nuclei wordpress-click2shell" {
		t.Errorf("exchange = %+v", ex)
	}
	if d.Items[1].Kind != evidencedom.KindCurl || d.Meta.ToolName != "nuclei" || d.Meta.RuleID != "wordpress-click2shell" || d.Meta.TemplateDigest == "" {
		t.Errorf("curl/meta = %+v %+v", d.Items[1], d.Meta)
	}
}

func TestFindingEvidenceSkipsSecretsAndEmpty(t *testing.T) {
	secret := &ctis.Finding{Type: ctis.FindingTypeSecret, EvidenceItems: []ctis.EvidenceItem{{Kind: ctis.EvidenceKindRawText, Text: "leaked"}}}
	if _, ok := findingEvidence("fp", secret, nil); ok {
		t.Error("a secret finding must keep no evidence (its evidence is the leaked value)")
	}
	if _, ok := findingEvidence("fp", &ctis.Finding{Type: ctis.FindingTypeVulnerability}, nil); ok {
		t.Error("no evidence items, no evidence")
	}
	if _, ok := findingEvidence("fp", &ctis.Finding{Type: ctis.FindingTypeVulnerability, Properties: ctis.Properties{"cvss": 5}}, nil); ok {
		t.Error("properties alone are no evidence")
	}
}

func TestWebLocationFallback(t *testing.T) {
	f := &ctis.Finding{Web: &ctis.WebLocation{URL: "https://h.example/wp-admin/js/theme.js"}}
	webLocationFallback(f)
	if f.Location == nil || f.Location.Path != "https://h.example/wp-admin/js/theme.js" {
		t.Fatalf("location = %+v", f.Location)
	}
	// A location the report set wins.
	g := &ctis.Finding{Web: &ctis.WebLocation{URL: "https://h.example/a"}, Location: &ctis.FindingLocation{Path: "src/a.go"}}
	webLocationFallback(g)
	if g.Location.Path != "src/a.go" {
		t.Fatalf("location overwritten: %q", g.Location.Path)
	}
	webLocationFallback(&ctis.Finding{})
}
