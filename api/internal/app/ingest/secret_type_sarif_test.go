package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// betterleaksSARIF is the shape betterleaks writes with --report-format sarif.
const betterleaksSARIF = `{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {"driver": {"name": "betterleaks", "rules": [{"id": "github-pat", "shortDescription": {"text": "GitHub Personal Access Token"}}]}},
    "results": [{
      "ruleId": "github-pat",
      "message": {"text": "github-pat has detected secret for file config.yml."},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "config.yml"}, "region": {"startLine": 3}}}]
    }]
  }]
}`

// A betterleaks SARIF report goes through ctis.FromSARIF, which does not
// recognize betterleaks as a secret scanner and writes the generic type
// "vulnerability". The finding used to be stored as a vulnerability and skip
// the secret handling (snippet redaction included); on live 13 of the 14
// betterleaks findings were typed vulnerability.
func TestBetterleaksSARIF_IsTypedSecret(t *testing.T) {
	report, err := ctis.FromSARIF([]byte(betterleaksSARIF), nil)
	if err != nil {
		t.Fatalf("FromSARIF: %v", err)
	}
	if len(report.Findings) != 1 || report.Tool == nil {
		t.Fatalf("want 1 finding and a tool, got %d findings, tool %v", len(report.Findings), report.Tool)
	}
	source := detectFindingSource(report.Tool.Name, report.Tool.Capabilities)
	if source != vulnerability.FindingSourceSecret {
		t.Fatalf("source %q, want secret", source)
	}
	got := (&FindingProcessor{}).inferFindingType(source, &report.Findings[0])
	if got != vulnerability.FindingTypeSecret {
		t.Fatalf("finding type %q (ctis type %q), want secret", got, report.Findings[0].Type)
	}
}
