package postgres

// CI gate baselines (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md, "Gate
// baseline"). Every statement is scoped to one tenant and one repository.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	ciBaselineUpsert = `INSERT INTO ci_gate_baselines (tenant_id, repository_asset_id, source, branch, findings_count,
		set_by, set_at) VALUES ($1, $2, $3, $4, 0, $5, $6)
		ON CONFLICT (tenant_id, repository_asset_id) DO UPDATE SET source = EXCLUDED.source, branch = EXCLUDED.branch,
			findings_count = 0, set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at, cleared_at = NULL`
	ciBaselineInsertOnce = `INSERT INTO ci_gate_baselines (tenant_id, repository_asset_id, source, branch, findings_count,
		set_by, set_at) VALUES ($1, $2, $3, $4, 0, $5, $6)
		ON CONFLICT (tenant_id, repository_asset_id) DO NOTHING`
)

// GateBaseline returns a repository's gate baseline, or nil when it has none.
func (r *CIRunRepository) GateBaseline(ctx context.Context, tenantID, assetID shared.ID) (*cirun.GateBaseline, error) {
	b := cirun.GateBaseline{TenantID: tenantID, RepositoryAssetID: assetID}
	var setBy sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT source, branch, findings_count, set_by, set_at FROM ci_gate_baselines
		WHERE tenant_id = $1 AND repository_asset_id = $2 AND cleared_at IS NULL`, tenantID.String(), assetID.String()).
		Scan(&b.Source, &b.Branch, &b.FindingsCount, &setBy, &b.SetAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no baseline is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("read gate baseline: %w", err)
	}
	b.SetBy = parseOptID(setBy)
	return &b, nil
}

// GateBaselineFingerprints returns those of fingerprints that are in the
// repository's gate baseline.
func (r *CIRunRepository) GateBaselineFingerprints(ctx context.Context, tenantID, assetID shared.ID, fingerprints []string) ([]string, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT fingerprint FROM ci_gate_baseline_findings
		WHERE tenant_id = $1 AND repository_asset_id = $2 AND fingerprint = ANY($3)`,
		tenantID.String(), assetID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("read gate baseline findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0, len(fingerprints))
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

// SetGateBaseline records the findings open now on the repository's default
// branch as its gate baseline, in one transaction, replacing any earlier one.
func (r *CIRunRepository) SetGateBaseline(ctx context.Context, b *cirun.GateBaseline) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var branch sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT name FROM repository_branches WHERE repository_id = $1 AND is_default
		ORDER BY updated_at DESC LIMIT 1`, b.RepositoryAssetID.String()).Scan(&branch); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read default branch: %w", err)
	}
	b.Branch = branch.String
	q := ciBaselineUpsert
	if b.Source == cirun.BaselineSourceFirstRun {
		// Once per repository: a baseline it has, or had and lost, wins.
		q = ciBaselineInsertOnce
	}
	res, err := tx.ExecContext(ctx, q, b.TenantID.String(), b.RepositoryAssetID.String(), b.Source, b.Branch,
		nullID(b.SetBy), b.SetAt)
	if err != nil {
		return fmt.Errorf("save gate baseline: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return cirun.ErrBaselineExists
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ci_gate_baseline_findings WHERE tenant_id = $1 AND repository_asset_id = $2`,
		b.TenantID.String(), b.RepositoryAssetID.String()); err != nil {
		return fmt.Errorf("clear gate baseline findings: %w", err)
	}
	res, err = tx.ExecContext(ctx, `INSERT INTO ci_gate_baseline_findings (tenant_id, repository_asset_id, fingerprint)
		SELECT DISTINCT $1::uuid, $2::uuid, f.fingerprint
		FROM finding_branch_occurrences o
		JOIN findings f ON f.id = o.finding_id AND f.tenant_id = o.tenant_id
		JOIN repository_branches rb ON rb.id = o.branch_id
		WHERE o.tenant_id = $1 AND f.asset_id = $2 AND rb.repository_id = $2 AND rb.is_default
		  AND o.status = 'open' AND f.fingerprint <> ''`,
		b.TenantID.String(), b.RepositoryAssetID.String())
	if err != nil {
		return fmt.Errorf("record gate baseline findings: %w", err)
	}
	n, _ := res.RowsAffected()
	b.FindingsCount = int(n)
	if _, err := tx.ExecContext(ctx, `UPDATE ci_gate_baselines SET findings_count = $3 WHERE tenant_id = $1 AND repository_asset_id = $2`,
		b.TenantID.String(), b.RepositoryAssetID.String(), b.FindingsCount); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteGateBaseline removes a repository's gate baseline and its findings,
// keeping the row (cleared_at) as the record that it had one.
func (r *CIRunRepository) DeleteGateBaseline(ctx context.Context, tenantID, assetID shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE ci_gate_baselines SET cleared_at = now(), findings_count = 0
		WHERE tenant_id = $1 AND repository_asset_id = $2 AND cleared_at IS NULL`, tenantID.String(), assetID.String())
	if err != nil {
		return err
	}
	if err := requireOneRow(res, cirun.ErrBaselineNotFound); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ci_gate_baseline_findings WHERE tenant_id = $1 AND repository_asset_id = $2`,
		tenantID.String(), assetID.String()); err != nil {
		return err
	}
	return tx.Commit()
}
