package ingest

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"

	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
)

// fullAddress matches an e-mail address with a visible local part.
var fullAddress = regexp.MustCompile(`[A-Za-z0-9._%+-]+(@|%40)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

func requireNoAddress(t *testing.T, what string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	// JSON escapes nothing in an address, so the encoded form shows it as is.
	if m := fullAddress.FindString(string(raw)); m != "" {
		t.Fatalf("%s still holds an e-mail address %q", what, m)
	}
}

// PRIVACY (research/292): a real nuclei v3.11.1 email-extractor run
// (templates v10.4.9, the sensor image, a local page listing three
// addresses), imported through the ctis nuclei importer: after
// maskReportEmails no finding member and no evidence item holds an address,
// the domains stay, and the platform's evidence masking stores none either.
func TestMaskReportEmails_RealNucleiEmailExtractor(t *testing.T) {
	f, err := os.Open("testdata/nuclei_email_extractor.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := importer.Parse(context.Background(), f, importer.Options{Format: importer.FormatNuclei})
	if err != nil {
		t.Fatal(err)
	}
	report := res.Report
	var extractor *ctis.Finding
	for i := range report.Findings {
		if report.Findings[i].RuleID == "email-extractor" {
			extractor = &report.Findings[i]
		}
	}
	if extractor == nil {
		t.Fatal("fixture has no email-extractor finding")
	}
	raw, _ := json.Marshal(extractor)
	if !strings.Contains(string(raw), "jane.doe@example.com") {
		t.Fatalf("fixture lost its addresses before masking: %s", raw)
	}
	assetRefs := map[int]string{}
	for i := range report.Findings {
		assetRefs[i] = report.Findings[i].AssetRef
	}

	if n := maskReportEmails(report); n == 0 {
		t.Fatal("nothing masked")
	}
	for i := range report.Findings {
		requireNoAddress(t, "finding "+report.Findings[i].RuleID, report.Findings[i])
		if report.Findings[i].AssetRef != assetRefs[i] {
			t.Fatalf("asset ref changed: %q", report.Findings[i].AssetRef)
		}
	}
	raw, _ = json.Marshal(extractor)
	for _, keep := range []string{"***@example.com", "***@example.net"} {
		if !strings.Contains(string(raw), keep) {
			t.Errorf("masked finding lost %q: %s", keep, raw)
		}
	}
	// Idempotent.
	if n := maskReportEmails(report); n != 0 {
		t.Fatalf("second pass changed %d strings", n)
	}

	d, ok := findingEvidence("fp", extractor, report)
	if !ok || len(d.Items) == 0 {
		t.Fatal("no evidence read")
	}
	for _, it := range d.Items {
		norm, ok := evidencedom.Normalize(it)
		if !ok {
			continue
		}
		masked, secrets := evidencedom.Mask(norm)
		requireNoAddress(t, "stored evidence", masked)
		requireNoAddress(t, "evidence secrets", secrets)
	}
}

// Every tool, not only nuclei: a CTIS report of another scanner with
// addresses in the free text, the properties, the tags, the source extras,
// the remediation and the evidence. Identifiers are left alone, and a marked
// sensitive span still marks its secret after the text before it shrank.
func TestMaskReportEmails_EveryMemberOfAnyTool(t *testing.T) {
	const secret = "s3cr3t-T0ken-value-0123456789"
	body := "owner: jane.doe@example.com token=" + secret + " cc a.b+c@mail.example.org"
	start := strings.Index(body, secret)
	end := start + len(secret)
	reqLine := "/reset?email=jane%40example.com"
	report := &ctis.Report{
		Version: ctis.SchemaVersion,
		Tool:    &ctis.Tool{Name: "zap", Techniques: []ctis.Technique{ctis.TechniqueDAST}},
		Assets:  []ctis.Asset{{ID: "web@example.com", Type: ctis.AssetTypeDomainName, Value: "example.com"}},
		Findings: []ctis.Finding{{
			ID: "id-jane@example.com", Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityMedium,
			RuleID: "10023", AssetRef: "web@example.com", Fingerprint: "fp-jane@example.com",
			PartialFingerprints: map[string]string{"k": "jane@example.com"},
			Title:               "Address jane.doe@example.com disclosed", Description: "Contact JANE@EXAMPLE.COM",
			Message: "see mailto:john@example.net", Tags: []string{"leak-x@y.example.com"},
			Remediation: &ctis.Remediation{Recommendation: "remove admin@example.com"},
			Web:         &ctis.WebLocation{URL: "https://example.com" + reqLine},
			SourceExtra: map[string]string{"extracted_results": "jane.doe@example.com,bob@example.com"},
			Properties:  ctis.Properties{"nested": map[string]any{"list": []any{"x@example.com"}}},
			EvidenceItems: []ctis.EvidenceItem{{
				Kind: "http_exchange", Extracted: []string{"jane.doe@example.com"},
				HTTP: &ctis.EvidenceHTTP{
					Request:  &ctis.EvidenceRequest{Method: "GET", URL: "https://example.com" + reqLine},
					Response: &ctis.EvidenceResponse{Status: 200, Body: body},
				},
				Sensitive: []ctis.SensitiveSpan{{Pointer: "/http/response/body", Start: &start, End: &end, Kind: "token"}},
				Match:     []ctis.EvidenceMatch{{Location: "response", Part: "body", Start: &start, End: &end}},
				Data:      map[string]any{"who": "jane@example.com"},
			}},
		}},
	}
	maskReportEmails(report)
	f := report.Findings[0]
	if f.ID != "id-jane@example.com" || f.AssetRef != "web@example.com" || f.Fingerprint != "fp-jane@example.com" ||
		f.PartialFingerprints["k"] != "jane@example.com" {
		t.Fatalf("identifiers changed: %q %q %q %v", f.ID, f.AssetRef, f.Fingerprint, f.PartialFingerprints)
	}
	f.ID, f.AssetRef, f.Fingerprint, f.PartialFingerprints = "", "", "", nil
	requireNoAddress(t, "finding", f)
	if f.Title != "Address ***@example.com disclosed" || f.Description != "Contact ***@EXAMPLE.COM" ||
		!strings.Contains(f.Web.URL, "email=***%40example.com") {
		t.Fatalf("masked: %q %q %q", f.Title, f.Description, f.Web.URL)
	}
	it := f.EvidenceItems[0]
	got := it.HTTP.Response.Body
	sp := it.Sensitive[0]
	if got[*sp.Start:*sp.End] != secret {
		t.Fatalf("span lost its secret: %q", got[*sp.Start:*sp.End])
	}
	if m := it.Match[0]; got[*m.Start:*m.End] != secret {
		t.Fatalf("match range moved off its text: %q", got[*m.Start:*m.End])
	}
	// The platform's evidence masking then takes the secret out by its span.
	norm, ok := evidencedom.Normalize(typedEvidence(f.EvidenceItems)[0])
	if !ok {
		t.Fatal("normalize dropped the item")
	}
	masked, secrets := evidencedom.Mask(norm)
	if strings.Contains(masked.HTTP.Response.Body, secret) || len(secrets) == 0 {
		t.Fatalf("secret not masked after the address shrank: %q", masked.HTTP.Response.Body)
	}
}

// A quarantined report is stored as is: its addresses are masked first.
func TestMaskReportEmails_NilAndEmpty(t *testing.T) {
	if maskReportEmails(nil) != 0 || maskReportEmails(&ctis.Report{}) != 0 {
		t.Fatal("nil or empty report")
	}
}
