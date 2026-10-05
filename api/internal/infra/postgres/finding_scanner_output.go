package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Scanner output and CVSS vectors (migration 000947, research 24 P0-2).
// They are written and read here only, never by the generic finding SELECT,
// so the list, the export and every Finding-based path (tickets,
// notifications) cannot carry the output.

// maxScannerEvidenceBatch bounds one UPDATE (rows per statement).
const maxScannerEvidenceBatch = 1000

// UpdateScannerEvidenceBatch stores each sighting's scanner output and
// vectors on the tenant's finding with that fingerprint. An empty value
// keeps the stored one; a new output replaces the old one and stamps
// scanner_output_at. Values are sanitized again here (defense in depth).
func (r *FindingRepository) UpdateScannerEvidenceBatch(ctx context.Context, tenantID shared.ID, updates []vulnerability.ScannerEvidenceUpdate) (int64, error) {
	var total int64
	for start := 0; start < len(updates); start += maxScannerEvidenceBatch {
		end := min(start+maxScannerEvidenceBatch, len(updates))
		fps := make([]string, 0, end-start)
		outs := make([]sql.NullString, 0, end-start)
		v2s := make([]sql.NullString, 0, end-start)
		v3s := make([]sql.NullString, 0, end-start)
		for _, u := range updates[start:end] {
			u.Output = vulnerability.SanitizeScannerOutput(u.Output)
			u.CVSSv2Vector = vulnerability.NormalizeCVSSv2Vector(u.CVSSv2Vector)
			u.CVSSv3Vector = vulnerability.NormalizeCVSSv3Vector(u.CVSSv3Vector)
			if u.Fingerprint == "" || u.IsEmpty() {
				continue
			}
			fps = append(fps, u.Fingerprint)
			outs = append(outs, nullString(u.Output))
			v2s = append(v2s, nullString(u.CVSSv2Vector))
			v3s = append(v3s, nullString(u.CVSSv3Vector))
		}
		if len(fps) == 0 {
			continue
		}
		res, err := r.db.ExecContext(ctx, `
			UPDATE findings AS f SET
				scanner_output = COALESCE(d.output, f.scanner_output),
				scanner_output_at = CASE WHEN d.output IS NOT NULL THEN now() ELSE f.scanner_output_at END,
				cvss_v2_vector = COALESCE(d.v2, f.cvss_v2_vector),
				cvss_v3_vector = COALESCE(d.v3, f.cvss_v3_vector)
			FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS d(fingerprint, output, v2, v3)
			WHERE f.tenant_id = $1 AND f.fingerprint = d.fingerprint`,
			tenantID.String(), pq.Array(fps), pq.Array(outs), pq.Array(v2s), pq.Array(v3s))
		if err != nil {
			return total, fmt.Errorf("update scanner evidence: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// GetScannerEvidence returns the scanner output and vectors of one finding
// of the tenant. The caller has already authorized the finding (tenant,
// data scope, pentest membership); a missing finding is ErrNotFound.
func (r *FindingRepository) GetScannerEvidence(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.ScannerEvidence, error) {
	var out, v2, v3 sql.NullString
	var at sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT scanner_output, scanner_output_at, cvss_v2_vector, cvss_v3_vector
		FROM findings WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), findingID.String()).Scan(&out, &at, &v2, &v3)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get scanner evidence: %w", err)
	}
	ev := &vulnerability.ScannerEvidence{Output: out.String, CVSSv2Vector: v2.String, CVSSv3Vector: v3.String}
	if at.Valid {
		t := at.Time
		ev.OutputAt = &t
	}
	return ev, nil
}

// ClearScannerOutputClosedBefore drops the scanner output of findings closed
// (fixed or dispositioned) before the cutoff, at most limit rows (owner
// decision C9: kept 365 days after close). It is a platform sweep over every
// tenant, like the other retention jobs; it only nulls the output column.
func (r *FindingRepository) ClearScannerOutputClosedBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	closed := vulnerability.ClosedFindingStatuses()
	sts := make([]string, len(closed))
	for i, s := range closed {
		sts[i] = s.String()
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE findings SET scanner_output = NULL, scanner_output_at = NULL
		WHERE id IN (
			SELECT id FROM findings
			WHERE scanner_output IS NOT NULL AND resolved_at < $1 AND status = ANY($2)
			LIMIT $3
		)`, before, pq.Array(sts), limit)
	if err != nil {
		return 0, fmt.Errorf("clear expired scanner output: %w", err)
	}
	return res.RowsAffected()
}
