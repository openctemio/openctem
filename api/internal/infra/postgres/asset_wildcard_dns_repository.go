package postgres

// Wildcard-only name marks (asset_wildcard_dns; RFC-088 decision A4).

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetWildcardDNSRepository stores asset_wildcard_dns rows.
type AssetWildcardDNSRepository struct {
	db *DB
}

// NewAssetWildcardDNSRepository creates the repository.
func NewAssetWildcardDNSRepository(db *DB) *AssetWildcardDNSRepository {
	return &AssetWildcardDNSRepository{db: db}
}

var _ assetfreshness.WildcardDNSStore = (*AssetWildcardDNSRepository)(nil)

// maxWildcardIDs bounds one call (a resolution job holds far fewer names).
const maxWildcardIDs = 20000

func wildcardIDs(ids []shared.ID) ([]string, error) {
	if len(ids) > maxWildcardIDs {
		return nil, fmt.Errorf("wildcard-only marks: %d assets, at most %d", len(ids), maxWildcardIDs)
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out, nil
}

// MarkWildcardOnly marks the assets. The INSERT selects from the tenant's
// live assets, so an id of another tenant (or a deleted asset) writes
// nothing. A newer mark replaces an older one.
func (r *AssetWildcardDNSRepository) MarkWildcardOnly(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, commandID shared.ID, at time.Time) error {
	if len(assetIDs) == 0 {
		return nil
	}
	ids, err := wildcardIDs(assetIDs)
	if err != nil {
		return err
	}
	var cmd any
	if !commandID.IsZero() {
		cmd = commandID.String()
	}
	if at.IsZero() || at.After(time.Now()) {
		at = time.Now()
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO asset_wildcard_dns (tenant_id, asset_id, command_id, observed_at)
		SELECT a.tenant_id, a.id, $3::uuid, $4
		  FROM assets a
		 WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND a.deleted_at IS NULL
		ON CONFLICT (tenant_id, asset_id) DO UPDATE
		   SET command_id = EXCLUDED.command_id, observed_at = EXCLUDED.observed_at
		 WHERE asset_wildcard_dns.observed_at <= EXCLUDED.observed_at`,
		tenantID.String(), pq.Array(ids), cmd, at)
	if err != nil {
		return fmt.Errorf("mark wildcard-only names: %w", err)
	}
	return nil
}

// ClearWildcardOnly removes the tenant's marks of the assets.
func (r *AssetWildcardDNSRepository) ClearWildcardOnly(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}
	ids, err := wildcardIDs(assetIDs)
	if err != nil {
		return err
	}
	if _, err := r.db.ExecContext(ctx,
		`DELETE FROM asset_wildcard_dns WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(ids)); err != nil {
		return fmt.Errorf("clear wildcard-only names: %w", err)
	}
	return nil
}

// WildcardOnly reports which of the tenant's assets are marked.
func (r *AssetWildcardDNSRepository) WildcardOnly(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	ids, err := wildcardIDs(assetIDs)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT asset_id FROM asset_wildcard_dns WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read wildcard-only names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan wildcard-only names: %w", err)
		}
		id, err := shared.IDFromString(raw)
		if err != nil {
			return nil, fmt.Errorf("scan wildcard-only names: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}
