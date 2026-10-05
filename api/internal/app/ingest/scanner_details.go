package ingest

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// patchDateProperties are the finding property keys a patch publication date
// arrives under: the CTIS-neutral name, the Nessus converter's and the
// Tenable.sc connector's (RFC-047).
var patchDateProperties = []string{"patch_published_at", "patch_publication_date", "tenable_patch_pub_date"}

// setFindingScannerDetails keeps the scanner facts ingest used to drop
// (research 17 R2): the rule family, the exploit verdict, VPR (display only),
// the CVSS version, every CVE named on the finding and the patch publication
// date. None of them feeds the fingerprint or the priority classifier.
func setFindingScannerDetails(f *vulnerability.Finding, cf *ctis.Finding) {
	d := vulnerability.ScannerDetails{Family: cf.Category}
	if v := cf.Vulnerability; v != nil {
		d.ExploitAvailable = v.ExploitAvailable
		if v.VPRScore > 0 {
			vpr := v.VPRScore
			d.VPRScore = &vpr
		}
		if v.CVSSScore > 0 {
			d.CVSSVersion = v.CVSSVersion
		}
		d.CVEIDs = append([]string{v.CVEID}, v.CVEIDs...)
	}
	d.PatchPublishedAt = patchPublishedAt(cf.Properties)
	f.SetScannerDetails(d)
}

// patchPublishedAt reads the patch publication date from the finding
// properties: RFC 3339, YYYY-MM-DD or Nessus's YYYY/MM/DD.
func patchPublishedAt(props ctis.Properties) *time.Time {
	for _, k := range patchDateProperties {
		raw, ok := props[k].(string)
		if !ok {
			continue
		}
		raw = strings.TrimSpace(raw)
		for _, layout := range []string{time.RFC3339, time.DateOnly, "2006/01/02"} {
			if t, err := time.Parse(layout, raw); err == nil {
				return &t
			}
		}
	}
	return nil
}

// scannerEvidenceWriter stores scanner output and CVSS vectors by
// fingerprint (postgres.FindingRepository). Optional: a repository without
// it simply keeps none.
type scannerEvidenceWriter interface {
	UpdateScannerEvidenceBatch(ctx context.Context, tenantID shared.ID, updates []vulnerability.ScannerEvidenceUpdate) (int64, error)
}

// cvssVectorProperties are the finding property keys a scanner names each
// CVSS vector under (the Nessus converter, the Tenable.sc connector).
var (
	cvssV2VectorProperties = []string{"cvss_v2_vector", "cvss2_vector"}
	cvssV3VectorProperties = []string{"cvss_v3_vector", "cvss3_vector"}
)

// scannerEvidenceUpdate is a sighting's scanner output (research 24 P0-2,
// owner decision C9) and both CVSS vectors. A secret finding keeps no
// output: a secret scanner's evidence is the leaked value itself.
func scannerEvidenceUpdate(fingerprint string, cf *ctis.Finding) vulnerability.ScannerEvidenceUpdate {
	u := vulnerability.ScannerEvidenceUpdate{Fingerprint: fingerprint}
	if cf.Type != ctis.FindingTypeSecret && cf.Secret == nil {
		u.Output = vulnerability.SanitizeScannerOutput(cf.Evidence)
	}
	u.CVSSv2Vector = vulnerability.NormalizeCVSSv2Vector(stringProperty(cf.Properties, cvssV2VectorProperties))
	u.CVSSv3Vector = vulnerability.NormalizeCVSSv3Vector(stringProperty(cf.Properties, cvssV3VectorProperties))
	// The one vector of the CVSS block fills whichever version it is.
	if v := cf.Vulnerability; v != nil && v.CVSSVector != "" {
		if u.CVSSv3Vector == "" {
			u.CVSSv3Vector = vulnerability.NormalizeCVSSv3Vector(v.CVSSVector)
		}
		if u.CVSSv2Vector == "" {
			u.CVSSv2Vector = vulnerability.NormalizeCVSSv2Vector(v.CVSSVector)
		}
	}
	return u
}

func stringProperty(props ctis.Properties, keys []string) string {
	for _, k := range keys {
		if s, ok := props[k].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
