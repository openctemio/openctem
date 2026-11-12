package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/certmonitor"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Rejection tombstones (easm_tombstones, RFC-036 §6.4, O7). Every statement
// is tenant-scoped.

var _ certmonitor.TombstoneChecker = (*AttributionRepository)(nil)

type execQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// syncTombstones keeps the tombstones in step with a person's decision on
// the given assets: a rejection of a domain or subdomain asset writes (or
// refreshes) a tombstone with the rules that supported the name, any other
// decision removes it.
func syncTombstones(ctx context.Context, q execQuerier, tenantID shared.ID, assetIDs []string, state attribution.State, by any) error {
	if len(assetIDs) == 0 {
		return nil
	}
	if state == attribution.StateRejected {
		_, err := q.ExecContext(ctx, `
			INSERT INTO easm_tombstones (tenant_id, name, rules, rejected_by)
			SELECT a.tenant_id, lower(a.name),
			       COALESCE((SELECT array_agg(DISTINCT e.rule) FROM easm_evidence e
			                  WHERE e.asset_id = a.id AND e.tenant_id = a.tenant_id), '{}'),
			       (SELECT u.id FROM users u WHERE u.id = $3::uuid)
			FROM assets a
			WHERE a.id = ANY($1::uuid[]) AND a.tenant_id = $2 AND a.asset_type IN ('domain', 'subdomain')
			ON CONFLICT (tenant_id, name) DO UPDATE SET
				rules       = EXCLUDED.rules,
				rejected_by = EXCLUDED.rejected_by,
				created_at  = now(),
				expires_at  = now() + INTERVAL '12 months'`,
			pq.Array(assetIDs), tenantID.String(), by)
		if err != nil {
			return fmt.Errorf("write tombstones: %w", err)
		}
		return nil
	}
	_, err := q.ExecContext(ctx, `
		DELETE FROM easm_tombstones t USING assets a
		WHERE t.tenant_id = $2 AND a.tenant_id = $2 AND a.id = ANY($1::uuid[]) AND t.name = lower(a.name)`,
		pq.Array(assetIDs), tenantID.String())
	if err != nil {
		return fmt.Errorf("remove tombstones: %w", err)
	}
	return nil
}

// Tombstoned returns, for the given names that the tenant rejected and whose
// tombstone has not expired, the rules recorded at rejection.
func (r *AttributionRepository) Tombstoned(ctx context.Context, tenantID shared.ID, names []string) (map[string][]attribution.Rule, error) {
	out := map[string][]attribution.Rule{}
	if len(names) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT name, rules FROM easm_tombstones
		WHERE tenant_id = $1 AND name = ANY($2) AND expires_at > now()`,
		tenantID.String(), pq.Array(names))
	if err != nil {
		return nil, fmt.Errorf("list tombstones: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name  string
			rules []string
		)
		if err := rows.Scan(&name, pq.Array(&rules)); err != nil {
			return nil, err
		}
		rs := make([]attribution.Rule, 0, len(rules))
		for _, x := range rules {
			rs = append(rs, attribution.Rule(x))
		}
		out[name] = rs
	}
	return out, rows.Err()
}

// PurgeExpiredTombstones deletes the tenant's expired tombstones (O7: 12
// months) and returns how many.
func (r *AttributionRepository) PurgeExpiredTombstones(ctx context.Context, tenantID shared.ID) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM easm_tombstones WHERE tenant_id = $1 AND expires_at <= now()`, tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("purge tombstones: %w", err)
	}
	return res.RowsAffected()
}
