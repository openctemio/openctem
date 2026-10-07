package ingest

import (
	"testing"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A report bound to a capability takes its technique from it: a third-party
// tool needs no name-table entry.
func TestReportFindingSourceByCapability(t *testing.T) {
	r := &ctis.Report{Tool: &ctis.Tool{Name: "acme-leaks"}, Metadata: ctis.ReportMetadata{Capability: "secrets.code@1"}}
	if got := reportFindingSource(r); got != vulnerability.FindingSourceSecret {
		t.Fatalf("source %s", got)
	}
	r.Metadata.Capability = "" // unbound: the name rules apply
	r.Tool.Name = "semgrep"
	if got := reportFindingSource(r); got != vulnerability.FindingSourceSAST {
		t.Fatalf("name fallback %s", got)
	}
	if got := reportFindingSource(&ctis.Report{Metadata: ctis.ReportMetadata{Capability: "sast.code@1"}}); got != vulnerability.FindingSourceSAST {
		t.Fatalf("toolless bound report %s", got)
	}
	if reportFindingSource(nil) != detectFindingSource("", nil) {
		t.Fatal("nil report")
	}
	// Every routed capability that emits findings has a technique.
	for _, c := range capability.All() {
		if c.MayEmit("finding:vulnerability") || c.MayEmit("finding:secret") || c.MayEmit("finding:misconfiguration") {
			if _, ok := capabilitySource[c.ID]; !ok && c.ID != "verify.finding" && c.Status != capability.StatusLater {
				t.Errorf("%s emits findings but has no technique", c.ID)
			}
		}
	}
}

// SECURITY: a bound secrets.code report is masked as a secret scan even
// when its tool name is unknown.
func TestBoundSecretsReportIsRedacted(t *testing.T) {
	raw := "ghp_0123456789abcdefghijABCDEFGHIJ0123456"
	r := &ctis.Report{Tool: &ctis.Tool{Name: "acme-leaks"}, Metadata: ctis.ReportMetadata{Capability: "secrets.code@1"},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "token " + raw,
			Location: &ctis.FindingLocation{Path: "a.env", Snippet: raw}}}}
	redactReportSecrets(r)
	if r.Findings[0].Location.Snippet == raw {
		t.Fatal("the snippet of a bound secret scan was kept")
	}
}
