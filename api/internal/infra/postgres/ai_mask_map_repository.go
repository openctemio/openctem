package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aimaskmap"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AIMaskMapRepository stores encrypted AI run mask maps (ai_mask_maps).
// Every read and write is scoped by tenant_id; the columns hold ciphertext
// only (internal/app/aimaskmap encrypts).
type AIMaskMapRepository struct {
	db *DB
}

// NewAIMaskMapRepository creates the repository.
func NewAIMaskMapRepository(db *DB) *AIMaskMapRepository {
	return &AIMaskMapRepository{db: db}
}

var _ aimaskmap.Repository = (*AIMaskMapRepository)(nil)

// Put writes a run's map; one map per run (tenant, run).
func (r *AIMaskMapRepository) Put(ctx context.Context, row aimaskmap.Row) error {
	const q = `INSERT INTO ai_mask_maps (tenant_id, run_id, key_enc, map_enc, expires_at) VALUES ($1, $2, $3, $4, $5)`
	if _, err := r.db.ExecContext(ctx, q, row.TenantID.String(), row.RunID.String(), row.KeyEnc, row.MapEnc, row.ExpiresAt); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: the run already has a mask map", shared.ErrConflict)
		}
		return fmt.Errorf("save AI mask map: %w", err)
	}
	return nil
}

// Get reads a run's map of the tenant unless it has expired.
func (r *AIMaskMapRepository) Get(ctx context.Context, tenantID, runID shared.ID, now time.Time) (aimaskmap.Row, error) {
	const q = `SELECT key_enc, map_enc, expires_at FROM ai_mask_maps
		WHERE tenant_id = $1 AND run_id = $2 AND expires_at > $3`
	row := aimaskmap.Row{TenantID: tenantID, RunID: runID}
	err := r.db.QueryRowContext(ctx, q, tenantID.String(), runID.String(), now).Scan(&row.KeyEnc, &row.MapEnc, &row.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return aimaskmap.Row{}, aimaskmap.ErrNotFound
	}
	if err != nil {
		return aimaskmap.Row{}, fmt.Errorf("read AI mask map: %w", err)
	}
	return row, nil
}

// DeleteExpired removes up to limit maps that expired before now (all
// tenants: the retention job runs as the system).
func (r *AIMaskMapRepository) DeleteExpired(ctx context.Context, now time.Time, limit int) (int64, error) {
	const q = `DELETE FROM ai_mask_maps WHERE id IN (
		SELECT id FROM ai_mask_maps WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2)`
	res, err := r.db.ExecContext(ctx, q, now, limit)
	if err != nil {
		return 0, fmt.Errorf("purge AI mask maps: %w", err)
	}
	return res.RowsAffected()
}
