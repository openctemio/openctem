package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// Holding the findings of a throttled run (docs/architecture/held-findings.md).

// holdGapFindingsSQL holds the findings a command's reports sighted first,
// on assets whose host (asset.HostOf, assetHostSQL) is in $3: unchecked, open-branch rows only (a held
// sighting never downgrades a finding that was already there or checked).
// Tenant-pinned on every table; $4 narrows to one report (NULL: every
// report of the command). Returns the rows it changed.
var holdGapFindingsSQL = `
	UPDATE findings f
	SET verification_state = 'held', hold_reasons = $5::text[], updated_at = NOW()
	FROM ingest_reports ir, assets a
	WHERE ir.tenant_id = $1 AND ir.command_id = $2
		AND ($4::uuid IS NULL OR ir.report_id = $4::uuid)
		AND f.tenant_id = $1 AND f.scan_id = ir.report_id::text
		AND f.first_detected_at >= ir.received_at
		AND f.verification_state = 'unchecked'
		AND f.branch_id IS NULL
		AND a.tenant_id = $1 AND a.id = f.asset_id
		AND ` + assetHostSQL("a") + ` = ANY($3::text[])
	RETURNING f.id, f.severity`

// HoldGapFindings holds, for one command of the tenant, the findings its
// reports sighted first on the given hosts, for the given reasons, and
// returns the findings it changed (a second call changes nothing).
func (r *FindingRepository) HoldGapFindings(ctx context.Context, tenantID, commandID shared.ID, reportID string, hosts []string, reasons []string) ([]vulnerability.HeldFinding, error) {
	if tenantID.IsZero() || commandID.IsZero() || len(hosts) == 0 || len(reasons) == 0 {
		return nil, nil
	}
	var report any
	if reportID != "" {
		if _, err := shared.IDFromString(reportID); err != nil {
			return nil, nil //nolint:nilerr // a report id that is not a UUID names no report
		}
		report = reportID
	}
	rows, err := r.db.QueryContext(ctx, holdGapFindingsSQL,
		tenantID.String(), commandID.String(), pq.Array(hosts), report, pq.Array(reasons))
	if err != nil {
		return nil, fmt.Errorf("hold findings of a throttled run: %w", err)
	}
	defer rows.Close()
	var out []vulnerability.HeldFinding
	for rows.Next() {
		var id, sev string
		if err := rows.Scan(&id, &sev); err != nil {
			return nil, fmt.Errorf("scan held finding: %w", err)
		}
		fid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		out = append(out, vulnerability.HeldFinding{ID: fid, Severity: sev})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hold findings of a throttled run: %w", err)
	}
	return out, nil
}

// releaseRunFindingsSQL releases the held findings a command's reports
// sighted (scan_id: the last report that saw the finding, written by every
// sighting path: insert, enrichment, sighting-only update) on assets whose
// host is NOT in $3, the hosts the command's result names as throttled.
// Only holds whose every reason is in $4 (the run-level reasons) are
// released: a hold that came from the matched response itself stays until
// that response is checked. Tenant-pinned on every table. Returns the rows
// it changed.
var releaseRunFindingsSQL = `
	UPDATE findings f
	SET verification_state = 'unchecked', hold_reasons = '{}', updated_at = NOW()
	FROM ingest_reports ir, assets a
	WHERE ir.tenant_id = $1 AND ir.command_id = $2
		AND f.tenant_id = $1 AND f.scan_id = ir.report_id::text
		AND f.verification_state = 'held'
		AND f.hold_reasons <@ $4::text[]
		AND f.branch_id IS NULL
		AND a.tenant_id = $1 AND a.id = f.asset_id
		AND (` + assetHostSQL("a") + ` = ANY($3::text[])) IS NOT TRUE
	RETURNING f.id`

// ReleaseRunFindings releases, for one command of the tenant, the held
// findings its reports sighted on hosts other than gapHosts (none: every
// host), when every hold reason is one of reasons. It returns the ids it
// changed (a second call changes nothing).
func (r *FindingRepository) ReleaseRunFindings(ctx context.Context, tenantID, commandID shared.ID, gapHosts []string, reasons []string) ([]shared.ID, error) {
	if tenantID.IsZero() || commandID.IsZero() || len(reasons) == 0 {
		return nil, nil
	}
	if gapHosts == nil {
		gapHosts = []string{}
	}
	rows, err := r.db.QueryContext(ctx, releaseRunFindingsSQL,
		tenantID.String(), commandID.String(), pq.Array(gapHosts), pq.Array(reasons))
	if err != nil {
		return nil, fmt.Errorf("release held findings of a run: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan released finding: %w", err)
		}
		if fid, err := shared.IDFromString(id); err == nil {
			out = append(out, fid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("release held findings of a run: %w", err)
	}
	return out, nil
}

// OnceHeldNotice runs send in a transaction, unless the tenant's command
// already has a notice of eventType (notification_outbox, aggregate scan,
// aggregate id the command). A transaction-scoped advisory lock on the
// tenant, command and event type serializes concurrent callers (the reports
// of one command are ingested in parallel), so exactly one of them sends. It
// reports whether send ran.
func (r *FindingRepository) OnceHeldNotice(ctx context.Context, tenantID, commandID shared.ID, eventType string, send func(tx *sql.Tx) error) (bool, error) {
	if tenantID.IsZero() || commandID.IsZero() || eventType == "" || send == nil {
		return false, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("held notice: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"held-notice:"+tenantID.String()+":"+commandID.String()+":"+eventType); err != nil {
		return false, fmt.Errorf("held notice: lock: %w", err)
	}
	var sent bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM notification_outbox
		WHERE aggregate_type = 'scan' AND aggregate_id = $2 AND tenant_id = $1 AND event_type = $3)`,
		tenantID.String(), commandID.String(), eventType).Scan(&sent); err != nil {
		return false, fmt.Errorf("held notice: look up: %w", err)
	}
	if sent {
		return false, nil
	}
	if err := send(tx); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("held notice: commit: %w", err)
	}
	return true, nil
}

// IsHeld reports whether the tenant's finding is held (false for a finding
// of another tenant or none).
func (r *FindingRepository) IsHeld(ctx context.Context, tenantID, findingID shared.ID) (bool, error) {
	var held bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM findings WHERE tenant_id = $1 AND id = $2 AND verification_state = 'held')`,
		tenantID.String(), findingID.String()).Scan(&held)
	if err != nil {
		return false, fmt.Errorf("finding held state: %w", err)
	}
	return held, nil
}
