package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

var _ cirun.UnverifiedRefusalStore = (*CIRunRepository)(nil)

// RecordUnverifiedRefusal adds r.Count to the (tenant, issuer, reason)
// record. Nothing is written for a tenant without a CI trust configuration
// (a made-up or unrelated tenant id); the tenant keeps its
// cirun.MaxUnverifiedRefusals newest records.
func (r *CIRunRepository) RecordUnverifiedRefusal(ctx context.Context, u cirun.UnverifiedRefusal) error {
	if u.TenantID.IsZero() || u.Count <= 0 {
		return nil
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO ci_unverified_refusals (tenant_id, issuer, reason, cause, first_seen, last_seen, count)
		SELECT $1, $2, $3, $4, $5, $5, $6
		WHERE EXISTS (SELECT 1 FROM ci_trust_configs WHERE tenant_id = $1)
		ON CONFLICT (tenant_id, issuer, reason) DO UPDATE
		SET count = ci_unverified_refusals.count + EXCLUDED.count,
			last_seen = GREATEST(ci_unverified_refusals.last_seen, EXCLUDED.last_seen),
			cause = EXCLUDED.cause`,
		u.TenantID.String(), u.Issuer, u.Reason, u.Cause, u.LastSeen.UTC(), u.Count)
	if err != nil {
		return fmt.Errorf("record unverified ci refusal: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	if _, err := r.db.ExecContext(ctx, `
		DELETE FROM ci_unverified_refusals
		WHERE tenant_id = $1 AND (issuer, reason) IN (
			SELECT issuer, reason FROM ci_unverified_refusals
			WHERE tenant_id = $1 ORDER BY last_seen DESC, issuer, reason OFFSET $2)`,
		u.TenantID.String(), cirun.MaxUnverifiedRefusals); err != nil {
		return fmt.Errorf("trim unverified ci refusals: %w", err)
	}
	return nil
}

// ListUnverifiedRefusals lists the tenant's records, newest first.
func (r *CIRunRepository) ListUnverifiedRefusals(ctx context.Context, tenantID shared.ID) ([]cirun.UnverifiedRefusal, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT issuer, reason, cause, first_seen, last_seen, count
		FROM ci_unverified_refusals WHERE tenant_id = $1
		ORDER BY last_seen DESC, issuer, reason LIMIT $2`, tenantID.String(), cirun.MaxUnverifiedRefusals)
	if err != nil {
		return nil, fmt.Errorf("list unverified ci refusals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.UnverifiedRefusal{}
	for rows.Next() {
		u := cirun.UnverifiedRefusal{TenantID: tenantID}
		if err := rows.Scan(&u.Issuer, &u.Reason, &u.Cause, &u.FirstSeen, &u.LastSeen, &u.Count); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
