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
