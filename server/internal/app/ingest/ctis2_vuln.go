package ingest

// CVE accessors over CTIS 2.0 vulnerability.ids[] (the single list that
// replaced cve_id and cve_ids; docs/architecture/ctis-receiver.md).

import (
	"github.com/openctemio/ctis/v2"
)

// primaryCVE is the CVE a finding is keyed on: the preferred vulnerability
// id when it is a CVE (the numerically smallest), else "". A finding that
// names several CVEs is split per CVE first (splitMultiCVEFinding), so after
// the split this is its only CVE.
func primaryCVE(v *ctis.VulnerabilityDetails) string {
	if v == nil {
		return ""
	}
	if p, ok := ctis.PreferredVulnerabilityID(v); ok && p.Type == ctis.VulnerabilityIDCVE {
		return p.ID
	}
	return ""
}

// findingCVEs is every CVE a finding names, canonical and deduplicated, in
// document order.
func findingCVEs(v *ctis.VulnerabilityDetails) []string {
	if v == nil {
		return nil
	}
	return ctis.CVEs(v)
}

// withOnlyCVE returns v's ids with cve as the one CVE: the other CVEs are
// dropped and every non-CVE id (GHSA, OSV, vendor) is kept.
func withOnlyCVE(ids []ctis.VulnerabilityID, cve string) []ctis.VulnerabilityID {
	out := make([]ctis.VulnerabilityID, 0, len(ids))
	added := false
	for _, id := range ids {
		if id.Type != ctis.VulnerabilityIDCVE {
			out = append(out, id)
			continue
		}
		if id.ID == cve && !added {
			out = append(out, id)
			added = true
		}
	}
	if !added {
		out = append(out, ctis.VulnerabilityID{Type: ctis.VulnerabilityIDCVE, ID: cve})
	}
	return out
}
