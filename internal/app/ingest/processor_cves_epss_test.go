package ingest

import (
	"math"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// CTIS producers disagree on the EPSS percentile scale: nuclei and the sdk-go
// EPSS enricher send FIRST's 0-1 fraction, the CTIS schema says 0-100. Both
// must land in the catalog on the canonical 0-100 scale.
func TestFillFromCTIS_NormalizesEPSSPercentile(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   float64
		want float64
	}{
		{"fraction (nuclei / FIRST)", 0.99947, 99.947},
		{"0-100 (CTIS schema)", 87.3, 87.3},
		{"top CVE fraction 1.0", 1.0, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := vulnerability.NewVulnerability("CVE-2022-22965", "spring4shell", vulnerability.SeverityCritical)
			if err != nil {
				t.Fatal(err)
			}
			fillFromCTIS(v, &ctis.Finding{Vulnerability: &ctis.VulnerabilityDetails{
				CVEID: "CVE-2022-22965", EPSSScore: 0.97443, EPSSPercentile: tc.in,
			}})
			if v.EPSSPercentile() == nil || math.Abs(*v.EPSSPercentile()-tc.want) > 1e-9 {
				t.Errorf("stored percentile %v, want %v", v.EPSSPercentile(), tc.want)
			}
		})
	}
}
