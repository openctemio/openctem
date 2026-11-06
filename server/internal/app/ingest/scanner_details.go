package ingest

import (
	"context"
	"strings"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// setFindingScannerDetails keeps the scanner facts ingest used to drop
// (research 17 R2): the rule family, the exploit verdict, the vendor score
// (VPR; display only), the CVSS version, every CVE named on the finding and
// the patch publication date. None of them feeds the fingerprint or the
// priority classifier.
func setFindingScannerDetails(f *vulnerability.Finding, cf *ctis.Finding) {
	d := vulnerability.ScannerDetails{Family: cf.Category}
	if v := cf.Vulnerability; v != nil {
		d.ExploitAvailable = ctis.HasThreatSignal(v, ctis.ThreatSignalPublicExploit,
			ctis.ThreatSignalWeaponized, ctis.ThreatSignalExploitedInWild)
		d.CVEIDs = findingCVEs(v)
	}
	if vpr, ok := vendorScore(cf.Scores, "tenable"); ok {
		d.VPRScore = &vpr
	}
	if s, ok := ctis.PrimaryCVSS(cf); ok && s.Value != nil && *s.Value > 0 {
		d.CVSSVersion = s.Version
	}
	if cf.Remediation != nil {
		d.PatchPublishedAt = cf.Remediation.PatchPublishedAt
	}
	f.SetScannerDetails(d)
}

// vendorScore is the value of a vendor score system from source (VPR is
// system vendor, source tenable).
func vendorScore(scores []ctis.Score, source string) (float64, bool) {
	for _, s := range scores {
		if s.System == ctis.ScoreSystemVendor && strings.EqualFold(s.Source, source) && s.Value != nil && *s.Value > 0 {
			return *s.Value, true
		}
	}
	return 0, false
}

// cvssVector is the vector of the first CVSS score of major version major
// ("2", "3", "4").
func cvssVector(scores []ctis.Score, major string) string {
	for _, s := range scores {
		if s.System == ctis.ScoreSystemCVSS && strings.HasPrefix(s.Version, major) && s.Vector != "" {
			return s.Vector
		}
	}
	return ""
}

// rawTextEvidence is the scanner output of a finding: the text of its
// raw_text evidence items, joined (CTIS 2.0 has no free evidence string).
func rawTextEvidence(items []ctis.EvidenceItem) string {
	var parts []string
	for i := range items {
		if items[i].Kind == ctis.EvidenceKindRawText && strings.TrimSpace(items[i].Text) != "" {
			parts = append(parts, items[i].Text)
		}
	}
	return strings.Join(parts, "\n")
}

// scannerEvidenceWriter stores scanner output and CVSS vectors by
// fingerprint (postgres.FindingRepository). Optional: a repository without
// it simply keeps none.
type scannerEvidenceWriter interface {
	UpdateScannerEvidenceBatch(ctx context.Context, tenantID shared.ID, updates []vulnerability.ScannerEvidenceUpdate) (int64, error)
}

// scannerEvidenceUpdate is a sighting's scanner output (research 24 P0-2,
// owner decision C9) and both CVSS vectors. A secret finding keeps no
// output: a secret scanner's evidence is the leaked value itself.
func scannerEvidenceUpdate(fingerprint string, cf *ctis.Finding) vulnerability.ScannerEvidenceUpdate {
	u := vulnerability.ScannerEvidenceUpdate{Fingerprint: fingerprint}
	if cf.Type != ctis.FindingTypeSecret && cf.Secret == nil {
		u.Output = vulnerability.SanitizeScannerOutput(rawTextEvidence(cf.EvidenceItems))
	}
	u.CVSSv2Vector = vulnerability.NormalizeCVSSv2Vector(cvssVector(cf.Scores, "2"))
	u.CVSSv3Vector = vulnerability.NormalizeCVSSv3Vector(cvssVector(cf.Scores, "3"))
	return u
}
