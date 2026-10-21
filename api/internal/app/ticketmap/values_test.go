package ticketmap

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestFindingValues_TitleFallsBackToMessageAndSecretsStayMasked(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSecret, "gitleaks", vulnerability.SeverityHigh, "AWS key in config")
	if err != nil {
		t.Fatal(err)
	}
	f.SetDescription("key=AKIAABCDEFGHIJKLMNOP")
	v := FindingValues(f, nil, nil, "https://app.example.test/")
	if got := v["finding.title"].String(); got != "AWS key in config" {
		t.Fatalf("title: %q", got)
	}
	if d := v["finding.description"].String(); strings.Contains(d, "AKIA") {
		t.Fatalf("secret finding description leaked: %q", d)
	}
	if u := v["finding.url"].String(); u != "https://app.example.test/findings/"+f.ID().String() {
		t.Fatalf("url: %q", u)
	}
}

// The outbound gate's content rules hold in mapping profiles too: a secret
// finding exposes no preview, a finding that exposes data no free text.
func TestFindingValues_EgressContentRules(t *testing.T) {
	sec, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSecret, "betterleaks", vulnerability.SeverityHigh, "AWS key")
	if err != nil {
		t.Fatal(err)
	}
	sec.SetSecretMaskedValue("AKIA****MPLE")
	sec.SetSnippet("aws_key = AKIAIOSFODNN7EXAMPLE")
	for k, v := range FindingValues(sec, nil, nil, "https://app.example.test") {
		if s := v.String(); strings.Contains(s, "AKIA") {
			t.Fatalf("secret value %s carries %q", k, s)
		}
	}

	pii, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceDAST, "zap", vulnerability.SeverityMedium, "records")
	if err != nil {
		t.Fatal(err)
	}
	pii.SetTitle("Customer list exposes jane@example.com")
	pii.SetDescription("rows: jane@example.com")
	if err := pii.SetDataExposureRisk(vulnerability.DataExposureRiskHigh); err != nil {
		t.Fatal(err)
	}
	for k, v := range FindingValues(pii, nil, nil, "https://app.example.test") {
		if s := v.String(); strings.Contains(s, "jane@") {
			t.Fatalf("data exposure value %s carries %q", k, s)
		}
	}
}
