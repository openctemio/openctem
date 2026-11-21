package postgres

// The version-less software link backfill's view of the database
// (docs/architecture/vulnerability-matching.md, "Version hidden").

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	assettechapp "github.com/openctemio/openctem/server/internal/app/assettech"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

var _ assettechapp.SoftwareLinkStore = (*AssetTechnologyBackfillRepository)(nil)

// PendingSoftwareLinkTenants (see assettechapp.SoftwareLinkStore).
func (r *AssetTechnologyBackfillRepository) PendingSoftwareLinkTenants(ctx context.Context, version int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		WHERE EXISTS (SELECT 1 FROM asset_technologies a WHERE a.tenant_id = t.id)
		  AND NOT EXISTS (SELECT 1 FROM asset_software_versionless_backfill b
		                  WHERE b.tenant_id = t.id AND b.version >= $1 AND b.completed_at IS NOT NULL)
		ORDER BY t.id`, version)
	if err != nil {
		return nil, fmt.Errorf("list tenants to link version-less software: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// SoftwareLinkProgress (see assettechapp.SoftwareLinkStore). A position
// saved by an older job version starts over.
func (r *AssetTechnologyBackfillRepository) SoftwareLinkProgress(ctx context.Context, tenantID shared.ID, version int) (assettechapp.SoftwareLinkProgress, error) {
	var p assettechapp.SoftwareLinkProgress
	var after sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT after_asset::text, after_key, linked FROM asset_software_versionless_backfill
		WHERE tenant_id = $1 AND version = $2 AND completed_at IS NULL`, tenantID.String(), version).
		Scan(&after, &p.AfterKey, &p.Linked)
	if errors.Is(err, sql.ErrNoRows) {
		return assettechapp.SoftwareLinkProgress{}, nil
	}
	if err != nil {
		return p, fmt.Errorf("version-less software link progress: %w", err)
	}
	p.AfterAsset = after.String
	return p, nil
}

// ScanVersionlessTechnologies (see assettechapp.SoftwareLinkStore). It walks
// the primary key (tenant_id, asset_id, name_key) from the saved position,
// so every batch reads forward from where the last one stopped.
func (r *AssetTechnologyBackfillRepository) ScanVersionlessTechnologies(ctx context.Context, tenantID shared.ID,
	afterAsset, afterKey string, keys []string, limit int,
) ([]assettechapp.VersionlessTechnology, error) {
	if afterAsset == "" {
		afterAsset = zeroUUID
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT asset_id, name_key, name, confidence, last_seen FROM asset_technologies
		 WHERE tenant_id = $1 AND (asset_id, name_key) > ($2::uuid, $3::text)
		   AND btrim(version) = '' AND cpe IS NULL AND name_key = ANY($4::text[])
		 ORDER BY asset_id, name_key
		 LIMIT $5`, tenantID.String(), afterAsset, afterKey, pq.Array(keys), limit)
	if err != nil {
		return nil, fmt.Errorf("scan version-less technologies: %w", err)
	}
	defer rows.Close()
	var out []assettechapp.VersionlessTechnology
	for rows.Next() {
		var id string
		var t assettechapp.VersionlessTechnology
		if err := rows.Scan(&id, &t.Key, &t.Name, &t.Confidence, &t.LastSeen); err != nil {
			return nil, fmt.Errorf("scan version-less technology: %w", err)
		}
		if t.AssetID, err = shared.IDFromString(id); err != nil {
			continue
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveSoftwareLinkProgress (see assettechapp.SoftwareLinkStore).
func (r *AssetTechnologyBackfillRepository) SaveSoftwareLinkProgress(ctx context.Context, tenantID shared.ID, version int,
	p assettechapp.SoftwareLinkProgress, done bool,
) error {
	var after any
	if p.AfterAsset != "" {
		after = p.AfterAsset
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_software_versionless_backfill (tenant_id, version, after_asset, after_key, linked, completed_at, updated_at)
		VALUES ($1, $2, $3::uuid, $4, $5, CASE WHEN $6::boolean THEN now() END, now())
		ON CONFLICT (tenant_id) DO UPDATE SET
		       version = EXCLUDED.version, after_asset = EXCLUDED.after_asset, after_key = EXCLUDED.after_key,
		       linked = EXCLUDED.linked, completed_at = EXCLUDED.completed_at, updated_at = now()`,
		tenantID.String(), version, after, p.AfterKey, p.Linked, done)
	if err != nil {
		if isForeignKeyViolation(err) {
			return nil // the tenant was deleted meanwhile
		}
		return fmt.Errorf("save version-less software link progress: %w", err)
	}
	return nil
}
