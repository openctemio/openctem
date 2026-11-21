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
// (a made-up or unrelated tenant id). A tenant keeps at most
// cirun.MaxUnverifiedRefusals no_configuration records (the others are bounded by its configurations): when full, a new record is written
// only in place of one not seen for cirun.UnverifiedRefusalRetention, so an
// anonymous caller cannot push a real record out (existing records keep
// counting).
func (r *CIRunRepository) RecordUnverifiedRefusal(ctx context.Context, u cirun.UnverifiedRefusal) error {
	if u.TenantID.IsZero() || u.Count <= 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	tid := u.TenantID.String()
	// One writer per tenant, so the bound holds under concurrent refusals.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('ci_unverified:' || $1))`, tid); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE ci_unverified_refusals SET count = count + $4, last_seen = GREATEST(last_seen, $5), cause = $6
		WHERE tenant_id = $1 AND issuer = $2 AND reason = $3`,
		tid, u.Issuer, u.Reason, u.Count, u.LastSeen.UTC(), u.Cause)
	if err != nil {
		return fmt.Errorf("record unverified ci refusal: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Only no_configuration records (a caller-chosen issuer) are bounded;
		// the others name a configured issuer and are never refused.
		var held int
		if u.Reason == cirun.UnverifiedReasonNoConfiguration {
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ci_unverified_refusals WHERE tenant_id = $1 AND reason = $2`,
				tid, cirun.UnverifiedReasonNoConfiguration).Scan(&held); err != nil {
				return err
			}
		}
		if held >= cirun.MaxUnverifiedRefusals {
			res, err := tx.ExecContext(ctx, `
				DELETE FROM ci_unverified_refusals
				WHERE tenant_id = $1 AND (issuer, reason) IN (
					SELECT issuer, reason FROM ci_unverified_refusals
					WHERE tenant_id = $1 AND reason = $3 AND last_seen < $2 ORDER BY last_seen LIMIT 1)`,
				tid, u.LastSeen.UTC().Add(-cirun.UnverifiedRefusalRetention), cirun.UnverifiedReasonNoConfiguration)
			if err != nil {
				return fmt.Errorf("trim unverified ci refusals: %w", err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return tx.Commit() // full of records seen recently: no new one
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ci_unverified_refusals (tenant_id, issuer, reason, cause, first_seen, last_seen, count)
			SELECT $1, $2, $3, $4, $5, $5, $6
			WHERE EXISTS (SELECT 1 FROM ci_trust_configs WHERE tenant_id = $1)
			ON CONFLICT (tenant_id, issuer, reason) DO NOTHING`,
			tid, u.Issuer, u.Reason, u.Cause, u.LastSeen.UTC(), u.Count); err != nil {
			return fmt.Errorf("record unverified ci refusal: %w", err)
		}
	}
	return tx.Commit()
}

// ListUnverifiedRefusals lists the tenant's records, newest first.
func (r *CIRunRepository) ListUnverifiedRefusals(ctx context.Context, tenantID shared.ID) ([]cirun.UnverifiedRefusal, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT issuer, reason, cause, first_seen, last_seen, count
		FROM ci_unverified_refusals WHERE tenant_id = $1
		ORDER BY last_seen DESC, issuer, reason LIMIT $2`, tenantID.String(), cirun.MaxUnverifiedListed)
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
