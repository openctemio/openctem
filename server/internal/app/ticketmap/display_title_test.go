package ticketmap

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// finding.display_title names the issue and the target; with no readable
// asset it is the title alone.
func TestFindingValues_DisplayTitle(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceDAST, "nuclei", vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	f.SetTitle("CVE-2019-9516 in nginx 1.15.5")
	f.SetNetwork(vulnerability.NetworkLocation{Port: 443})
	v := FindingValues(f, &AssetInfo{Name: "10.20.30.41"}, nil, "https://app.example")
	if got := v["finding.display_title"].String(); got != "CVE-2019-9516 in nginx 1.15.5 on 10.20.30.41:443" {
		t.Fatalf("got %q", got)
	}
	if got := FindingValues(f, nil, nil, "")["finding.display_title"].String(); got != "CVE-2019-9516 in nginx 1.15.5" {
		t.Fatalf("no asset: %q", got)
	}
}
