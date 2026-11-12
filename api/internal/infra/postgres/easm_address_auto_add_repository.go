package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMAddressAutoAddRepository remembers the patterns the address auto add
// wrote for a tenant (research/425), so a person's removal is never undone
// by the next run. Every query is pinned to the tenant.
type EASMAddressAutoAddRepository struct {
	db *DB
}

// NewEASMAddressAutoAddRepository creates it.
func NewEASMAddressAutoAddRepository(db *DB) *EASMAddressAutoAddRepository {
	return &EASMAddressAutoAddRepository{db: db}
}

// Seen returns the tenant's patterns among patterns the auto add wrote before.
func (r *EASMAddressAutoAddRepository) Seen(ctx context.Context, tenantID shared.ID, patterns []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(patterns) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT pattern FROM easm_address_auto_adds
		WHERE tenant_id = $1 AND pattern = ANY($2::text[])`, tenantID.String(), pq.Array(patterns))
	if err != nil {
		return nil, fmt.Errorf("address auto adds: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out[p] = true
	}
	return out, rows.Err()
}

// Record remembers patterns for the tenant (an existing one is kept).
func (r *EASMAddressAutoAddRepository) Record(ctx context.Context, tenantID shared.ID, patterns []string) error {
	if len(patterns) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO easm_address_auto_adds (tenant_id, pattern)
		SELECT $1, p FROM unnest($2::text[]) AS p ON CONFLICT DO NOTHING`, tenantID.String(), pq.Array(patterns))
	if err != nil {
		return fmt.Errorf("record address auto adds: %w", err)
	}
	return nil
}
