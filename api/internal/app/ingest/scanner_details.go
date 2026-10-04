package ingest

import (
	"strings"
	"time"

	"github.com/openctemio/ctis"

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
