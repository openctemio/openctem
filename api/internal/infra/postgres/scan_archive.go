package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ArchiveNeverRunOneOffs archives up to limit ad-hoc scans created before
// olderThan ago that never had a run: archived_at is set, the scan is
// disabled and its next run cleared. Archived, never deleted. Returns the
// archived scans, for the audit trail. Runs across tenants (a system job);
// each scan's run check reads only its own tenant's runs.
func (r *ScanRepository) ArchiveNeverRunOneOffs(ctx context.Context, olderThan time.Duration, limit int) ([]scan.ArchivedScan, error) {
	const query = `
		WITH stale AS (
			SELECT s.id
			FROM scans s
			WHERE s.ad_hoc = true
			  AND s.archived_at IS NULL
			  AND s.created_at < NOW() - make_interval(secs => $1)
			  AND NOT EXISTS (
			        SELECT 1 FROM pipeline_runs pr
			        WHERE pr.tenant_id = s.tenant_id AND pr.scan_id = s.id)
			ORDER BY s.created_at
			LIMIT $2
			FOR UPDATE OF s SKIP LOCKED
		)
		UPDATE scans s
		SET archived_at = NOW(), status = 'disabled', next_run_at = NULL, updated_at = NOW()
		FROM stale
		WHERE s.id = stale.id
		RETURNING s.tenant_id, s.id, s.name
	`
	rows, err := r.db.QueryContext(ctx, query, olderThan.Seconds(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to archive one-off scans: %w", err)
	}
	defer rows.Close()
	var out []scan.ArchivedScan
	for rows.Next() {
		var tenantID, id string
		var a scan.ArchivedScan
		if err := rows.Scan(&tenantID, &id, &a.Name); err != nil {
			return nil, fmt.Errorf("failed to read archived scan: %w", err)
		}
		a.TenantID, _ = shared.IDFromString(tenantID)
		a.ID, _ = shared.IDFromString(id)
		out = append(out, a)
	}
	return out, rows.Err()
}
