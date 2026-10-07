package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
)

func TestFindingEvidenceFromNucleiProperties(t *testing.T) {
	cf := &ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		RuleID:   "wordpress-click2shell",
		Location: &ctis.FindingLocation{Path: "https://shop.example.com/wp-admin/js/theme.js"},
		Properties: ctis.Properties{
			"request":         "GET /wp-admin/js/theme.js HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
			"response":        "HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n\r\nslug + '\"]' ).trigger( 'click' );",
			"curl_command":    "curl 'https://shop.example.com/wp-admin/js/theme.js'",
			"matcher_name":    "word-1",
			"template_digest": "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12",
		},
	}
	d, ok := findingEvidence("fp1", cf, &ctis.Tool{Name: "nuclei"})
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
	secret := &ctis.Finding{Type: ctis.FindingTypeSecret, Properties: ctis.Properties{"request": "GET / HTTP/1.1\r\n\r\n"}}
	if _, ok := findingEvidence("fp", secret, nil); ok {
		t.Error("a secret finding must keep no evidence (its evidence is the leaked value)")
	}
	if _, ok := findingEvidence("fp", &ctis.Finding{Type: ctis.FindingTypeVulnerability}, nil); ok {
		t.Error("no properties, no evidence")
	}
	if _, ok := findingEvidence("fp", &ctis.Finding{Type: ctis.FindingTypeVulnerability, Properties: ctis.Properties{"cvss": 5}}, nil); ok {
		t.Error("properties without an exchange, no evidence")
	}
}
