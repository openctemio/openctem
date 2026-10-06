package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Finding import records (migration 001133). Every statement is scoped by
// tenant_id.

// CreateFindingImport inserts the record of an import (its counts may be
// filled later by FinishFindingImport).
func (r *FindingRepository) CreateFindingImport(ctx context.Context, rec *vulnerability.FindingImport) error {
	var actor any
	if rec.ActorUserID != nil {
		actor = rec.ActorUserID.String()
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO finding_imports (id, tenant_id, actor_user_id, format, filename_sha256)
		VALUES ($1, $2, $3, $4, $5)`,
		rec.ID.String(), rec.TenantID.String(), actor, rec.Format, rec.FilenameSHA256)
	if err != nil {
		return fmt.Errorf("create finding import: %w", err)
	}
	return nil
}

// FinishFindingImport stores the counts of an import of the tenant.
func (r *FindingRepository) FinishFindingImport(ctx context.Context, rec *vulnerability.FindingImport) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE finding_imports SET
			assets_created = $3, assets_updated = $4, findings_created = $5, findings_updated = $6,
			components = $7, statements = $8, skipped = $9, vex_stored = $10, vex_closed = $11
		WHERE tenant_id = $1 AND id = $2`,
		rec.TenantID.String(), rec.ID.String(), rec.AssetsCreated, rec.AssetsUpdated, rec.FindingsCreated,
		rec.FindingsUpdated, rec.Components, rec.Statements, rec.Skipped, rec.VEXStored, rec.VEXClosed)
	if err != nil {
		return fmt.Errorf("finish finding import: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// GetFindingImport returns an import record of the tenant; another tenant's
// is ErrNotFound.
func (r *FindingRepository) GetFindingImport(ctx context.Context, tenantID, id shared.ID) (*vulnerability.FindingImport, error) {
	var rec vulnerability.FindingImport
	var tenant, rid string
	var actor sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT id::text, tenant_id::text, actor_user_id::text, format, filename_sha256,
			assets_created, assets_updated, findings_created, findings_updated,
			components, statements, skipped, vex_stored, vex_closed, created_at
		FROM finding_imports WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String()).Scan(&rid, &tenant, &actor, &rec.Format, &rec.FilenameSHA256,
		&rec.AssetsCreated, &rec.AssetsUpdated, &rec.FindingsCreated, &rec.FindingsUpdated,
		&rec.Components, &rec.Statements, &rec.Skipped, &rec.VEXStored, &rec.VEXClosed, &rec.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get finding import: %w", err)
	}
	rec.ID, _ = shared.IDFromString(rid)
	rec.TenantID, _ = shared.IDFromString(tenant)
	if actor.Valid {
		if a, err := shared.IDFromString(actor.String); err == nil {
			rec.ActorUserID = &a
		}
	}
	return &rec, nil
}

// StampAssetsImport records importID as the producer of the tenant's assets
// ids (the last import that created or updated them).
func (r *FindingRepository) StampAssetsImport(ctx context.Context, tenantID, importID shared.ID, ids []shared.ID) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	res, err := r.db.ExecContext(ctx, `UPDATE assets SET import_id = $2 WHERE tenant_id = $1 AND id = ANY($3::uuid[])`,
		tenantID.String(), importID.String(), pq.Array(strs))
	if err != nil {
		return 0, fmt.Errorf("stamp assets import: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
