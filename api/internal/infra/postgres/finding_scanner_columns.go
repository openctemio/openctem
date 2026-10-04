package postgres

import (
	"database/sql"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The scanner-detail columns of the findings table (migration 000660):
// family, exploit verdict, VPR, CVSS version, every CVE and the patch
// publication date (research 17 R2). Ingest parsed them and dropped them.
//
// Not fingerprint inputs. Order matters: findingScannerColumnsSQL,
// findingScannerArgs and findingScannerScan.dests list the columns in the
// same order.
const findingScannerColumnsSQL = `family, exploit_available, vpr_score, cvss_version, cve_ids, patch_published_at`

// findingScannerColumnCount is the number of columns in findingScannerColumnsSQL.
const findingScannerColumnCount = 6

func findingScannerArgs(f *vulnerability.Finding) []any {
	d := f.ScannerDetails()
	var vpr sql.NullFloat64
	if d.VPRScore != nil {
		vpr = sql.NullFloat64{Float64: *d.VPRScore, Valid: true}
	}
	var cves any
	if len(d.CVEIDs) > 0 {
		cves = pq.Array(d.CVEIDs)
	}
	return []any{nullString(d.Family), d.ExploitAvailable, vpr, nullString(d.CVSSVersion), cves, nullTime(d.PatchPublishedAt)}
}

// findingScannerConflictSQL is the ON CONFLICT ... DO UPDATE part, with the
// enrich path's rules (Finding.enrichScannerDetails): family and patch date
// first writer wins, exploit verdict sticky, VPR and CVSS version latest
// wins, CVEs the ordered union capped at vulnerability.MaxFindingCVEIDs.
func findingScannerConflictSQL() string {
	return `,
			family = COALESCE(findings.family, EXCLUDED.family),
			exploit_available = findings.exploit_available OR EXCLUDED.exploit_available,
			vpr_score = COALESCE(EXCLUDED.vpr_score, findings.vpr_score),
			cvss_version = COALESCE(EXCLUDED.cvss_version, findings.cvss_version),
			cve_ids = CASE WHEN EXCLUDED.cve_ids IS NULL THEN findings.cve_ids ELSE ARRAY(
				SELECT c FROM unnest(COALESCE(findings.cve_ids, '{}') || EXCLUDED.cve_ids) WITH ORDINALITY AS u(c, o)
				GROUP BY c ORDER BY MIN(o) LIMIT ` + itoa(vulnerability.MaxFindingCVEIDs) + `) END,
			patch_published_at = COALESCE(findings.patch_published_at, EXCLUDED.patch_published_at)`
}

// findingScannerScan receives the scanner-detail columns of a SELECT.
type findingScannerScan struct {
	family      sql.NullString
	exploit     sql.NullBool
	vpr         sql.NullFloat64
	cvssVersion sql.NullString
	cveIDs      pq.StringArray
	patchPub    sql.NullTime
}

func (s *findingScannerScan) dests() []any {
	return []any{&s.family, &s.exploit, &s.vpr, &s.cvssVersion, &s.cveIDs, &s.patchPub}
}

func (s *findingScannerScan) details() vulnerability.ScannerDetails {
	d := vulnerability.ScannerDetails{
		Family:           s.family.String,
		ExploitAvailable: s.exploit.Bool,
		CVSSVersion:      s.cvssVersion.String,
	}
	if s.vpr.Valid {
		v := s.vpr.Float64
		d.VPRScore = &v
	}
	if len(s.cveIDs) > 0 {
		d.CVEIDs = []string(s.cveIDs)
	}
	if s.patchPub.Valid {
		t := s.patchPub.Time
		d.PatchPublishedAt = &t
	}
	return d
}

// findingScannerPlaceholders is ", $first, …" for the scanner-detail columns
// of a hand-numbered single-row INSERT.
func findingScannerPlaceholders(first int) string {
	out := ""
	for i := 0; i < findingScannerColumnCount; i++ {
		out += ", " + placeholder(first+i)
	}
	return out
}
