package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A report's work_item_uris never become the finding's ticket links: the
// ticket sync acts on those links, so a sensor or an imported file could
// otherwise point a finding at any issue of the tenant's tracker.
func TestSetFindingSARIFFields_IgnoresReportedTicketLinks(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatal(err)
	}
	p := &FindingProcessor{}
	p.setFindingSARIFFields(f, &ctis.Finding{
		WorkItemURIs:    []string{"https://acme.atlassian.net/browse/PAY-1"},
		HostedViewerURI: "https://viewer.example.test/r/1",
	})
	if got := f.WorkItemURIs(); len(got) != 0 {
		t.Fatalf("reported ticket links were stored: %v", got)
	}
	if f.HostedViewerURI() == "" {
		t.Fatal("other SARIF fields must still map")
	}
}
