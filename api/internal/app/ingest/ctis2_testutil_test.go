package ingest

import (
	"github.com/openctemio/ctis/v2"
)

// testReportID is a fixed, valid CTIS 2.0 report id (lower-case UUIDv7).
const testReportID = "01936f4e-7b8c-7d4e-9f00-0123456789ab"

// cveIDs is vulnerability.ids[] holding the given CVEs.
func cveIDs(cves ...string) []ctis.VulnerabilityID {
	out := make([]ctis.VulnerabilityID, 0, len(cves))
	for _, c := range cves {
		out = append(out, ctis.VulnerabilityID{Type: ctis.VulnerabilityIDCVE, ID: c})
	}
	return out
}

// cveVuln is a vulnerability naming the given CVEs.
func cveVuln(cves ...string) *ctis.VulnerabilityDetails {
	return &ctis.VulnerabilityDetails{IDs: cveIDs(cves...)}
}

// cvssScore is a CVSS score entry.
func cvssScore(version, vector string, value float64, source string) ctis.Score {
	v := value
	return ctis.Score{System: ctis.ScoreSystemCVSS, Version: version, Vector: vector, Value: &v, Source: source}
}

// withCapability records a bound capability on the report (the output
// binding's job in production) and returns it.
func withCapability(r *ctis.Report, ref string) *ctis.Report {
	setReportCapability(r, ref)
	return r
}

func ptrF(v float64) *float64 { return &v }

// minimalDoc is the smallest valid CTIS 2.0 document (a tool, no assets).
const minimalDoc = `{"version":"2.0","metadata":{"id":"` + testReportID + `","generated_at":"2026-10-01T12:00:00Z"},"tool":{"name":"trivy"}}`
