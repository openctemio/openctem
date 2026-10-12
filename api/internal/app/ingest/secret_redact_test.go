package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func TestRedactReportSecrets(t *testing.T) {
	token := "ghp_" + "9fK2xLq7RzT4mWv8Np3Yb6Hc"
	rep := &ctis.Report{
		Tool: &ctis.Tool{Name: "betterleaks"},
		Findings: []ctis.Finding{
			{Type: ctis.FindingTypeSecret, Title: "token " + token, Location: &ctis.FindingLocation{Snippet: "t=" + token}},
			// Typed generically by a converter: a secret by its tool.
			{Type: ctis.FindingTypeVulnerability, Title: "found " + token, Location: &ctis.FindingLocation{Snippet: token}},
			// Already masked by the producer: kept as sent.
			{Type: ctis.FindingTypeSecret, Title: "token ghp_****Hc", Location: &ctis.FindingLocation{Snippet: "t=ghp_****Hc"},
				Secret: &ctis.SecretDetails{MaskedValue: "gh****Hc"}},
		},
	}
	redactReportSecrets(rep)
	b, _ := json.Marshal(rep)
	if strings.Contains(string(b), token) {
		t.Fatalf("raw secret left: %s", b)
	}
	if rep.Findings[1].Type != ctis.FindingTypeVulnerability {
		t.Errorf("type changed to %q; inferFindingType decides it", rep.Findings[1].Type)
	}
	if f := rep.Findings[2]; f.Title != "token ghp_****Hc" || f.Location.Snippet != "t=ghp_****Hc" || f.Secret.MaskedValue != "gh****Hc" {
		t.Errorf("a masked finding changed: %+v", f)
	}
}

// A code finding of another tool keeps its snippet: only secret findings
// are taken to carry a secret.
func TestRedactReportSecrets_CodeFindingUntouched(t *testing.T) {
	rep := &ctis.Report{Tool: &ctis.Tool{Name: "semgrep"}, Findings: []ctis.Finding{
		{Type: ctis.FindingTypeVulnerability, Title: "use of md5 in hash2023.go", Location: &ctis.FindingLocation{Snippet: "h := md5.New() // hash2023"}},
	}}
	redactReportSecrets(rep)
	if f := rep.Findings[0]; f.Title != "use of md5 in hash2023.go" || f.Location.Snippet != "h := md5.New() // hash2023" {
		t.Fatalf("code finding changed: %+v", f)
	}
}
