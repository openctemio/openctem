package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetIdentityBackfillRepository is the identifier backfill's view of the
// inventory (ingest.BackfillSource).
type AssetIdentityBackfillRepository struct {
	db *DB
}

// NewAssetIdentityBackfillRepository creates the repository.
func NewAssetIdentityBackfillRepository(db *DB) *AssetIdentityBackfillRepository {
	return &AssetIdentityBackfillRepository{db: db}
}

var _ ingest.BackfillSource = (*AssetIdentityBackfillRepository)(nil)

// PendingTenants returns tenants with assets that were not backfilled at
// version or later.
func (r *AssetIdentityBackfillRepository) PendingTenants(ctx context.Context, version int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		WHERE EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = t.id AND a.deleted_at IS NULL)
		  AND NOT EXISTS (SELECT 1 FROM asset_identity_backfill b WHERE b.tenant_id = t.id AND b.version >= $1)
		ORDER BY t.id`, version)
	if err != nil {
		return nil, fmt.Errorf("list tenants to backfill: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("parse tenant id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

const storedAssetSelect = `
	SELECT a.id, a.name, a.asset_type, COALESCE(a.properties, '{}'::jsonb),
	       COALESCE(r.repo_id, ''), a.last_seen, a.created_at, COALESCE(a.discovery_tool, ''),
	       (SELECT count(*) FROM findings f WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id)
	FROM assets a
	LEFT JOIN asset_repositories r ON r.asset_id = a.id`

// ScanAssets pages through a tenant's assets in id order.
func (r *AssetIdentityBackfillRepository) ScanAssets(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]ingest.StoredAsset, error) {
	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	rows, err := r.db.QueryContext(ctx, storedAssetSelect+`
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.id > $2::uuid
		ORDER BY a.id
		LIMIT $3`, tenantID.String(), afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("scan assets for backfill: %w", err)
	}
	return scanStoredAssets(rows)
}

// GetStoredAssets loads assets by id, keyed by id string.
func (r *AssetIdentityBackfillRepository) GetStoredAssets(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]ingest.StoredAsset, error) {
	out := map[string]ingest.StoredAsset{}
	if len(ids) == 0 {
		return out, nil
	}
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, storedAssetSelect+`
		WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])`, tenantID.String(), pq.Array(s))
	if err != nil {
		return nil, fmt.Errorf("load assets for backfill: %w", err)
	}
	list, err := scanStoredAssets(rows)
	if err != nil {
		return nil, err
	}
	for _, a := range list {
		out[a.ID.String()] = a
	}
	return out, nil
}

// RenamedHostCandidates returns host pairs that one Nessus, Tenable or Vuls
// scan source reported with the same IP address under different names.
// Pairs where both assets carry different values of a single-valued strong
// identifier are different machines and are left out.
func (r *AssetIdentityBackfillRepository) RenamedHostCandidates(ctx context.Context, tenantID shared.ID, limit int) ([]ingest.RenamedHostPair, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT ON (ia.asset_id, ib.asset_id) ia.asset_id, ib.asset_id, ia.value, a.discovery_tool
		FROM asset_identifiers ia
		JOIN asset_identifiers ib ON ib.tenant_id = ia.tenant_id AND ib.kind = 'ip'
		     AND ib.value = ia.value AND ib.asset_id > ia.asset_id
		JOIN assets a ON a.id = ia.asset_id AND a.tenant_id = ia.tenant_id AND a.deleted_at IS NULL
		JOIN assets b ON b.id = ib.asset_id AND b.tenant_id = ib.tenant_id AND b.deleted_at IS NULL
		WHERE ia.tenant_id = $1 AND ia.kind = 'ip'
		  AND a.asset_type IN ('host', 'ip_address') AND b.asset_type IN ('host', 'ip_address')
		  AND a.name <> b.name
		  AND lower(a.discovery_tool) = lower(b.discovery_tool)
		  AND lower(a.discovery_tool) ~ '(nessus|tenable|vuls)'
		  AND NOT EXISTS (
		      SELECT 1 FROM asset_identifiers xa
		      JOIN asset_identifiers xb ON xb.asset_id = b.id AND xb.kind = xa.kind AND xb.value <> xa.value
		      WHERE xa.asset_id = a.id AND xa.kind IN ('host_id', 'cloud_id', 'bios_uuid', 'serial_number')
		        AND NOT EXISTS (SELECT 1 FROM asset_identifiers xc
		                        WHERE xc.asset_id = b.id AND xc.kind = xa.kind AND xc.value = xa.value))
		ORDER BY ia.asset_id, ib.asset_id, ia.value
		LIMIT $2`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("find renamed host candidates: %w", err)
	}
	type raw struct{ a, b, ip, tool string }
	var found []raw
	func() {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var x raw
			if err = rows.Scan(&x.a, &x.b, &x.ip, &x.tool); err != nil {
				return
			}
			found = append(found, x)
		}
		err = rows.Err()
	}()
	if err != nil {
		return nil, fmt.Errorf("scan renamed host candidates: %w", err)
	}
	if len(found) == 0 {
		return nil, nil
	}
	ids := make([]shared.ID, 0, 2*len(found))
	for _, f := range found {
		for _, s := range []string{f.a, f.b} {
			if id, perr := shared.IDFromString(s); perr == nil {
				ids = append(ids, id)
			}
		}
	}
	loaded, err := r.GetStoredAssets(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	out := make([]ingest.RenamedHostPair, 0, len(found))
	for _, f := range found {
		a, oka := loaded[f.a]
		b, okb := loaded[f.b]
		if oka && okb {
			out = append(out, ingest.RenamedHostPair{A: a, B: b, IP: f.ip, Tool: f.tool})
		}
	}
	return out, nil
}

// MarkBackfilled records that a tenant was backfilled at version.
func (r *AssetIdentityBackfillRepository) MarkBackfilled(ctx context.Context, tenantID shared.ID, version int, stats ingest.BackfillStats) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_identity_backfill (tenant_id, version, assets_scanned, identifiers_added, reviews_enqueued, completed_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			version = EXCLUDED.version,
			assets_scanned = EXCLUDED.assets_scanned,
			identifiers_added = EXCLUDED.identifiers_added,
			reviews_enqueued = EXCLUDED.reviews_enqueued,
			completed_at = EXCLUDED.completed_at`,
		tenantID.String(), version, stats.AssetsScanned, stats.IdentifiersAdded, stats.ReviewsEnqueued)
	if err != nil {
		return fmt.Errorf("mark identifier backfill: %w", err)
	}
	return nil
}

func scanStoredAssets(rows *sql.Rows) ([]ingest.StoredAsset, error) {
	defer func() { _ = rows.Close() }()
	var out []ingest.StoredAsset
	for rows.Next() {
		var (
			id, name, typ, repoID, tool string
			props                       []byte
			lastSeen, createdAt         sql.NullTime
			findings                    int
		)
		if err := rows.Scan(&id, &name, &typ, &props, &repoID, &lastSeen, &createdAt, &tool, &findings); err != nil {
			return nil, fmt.Errorf("scan stored asset: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			return nil, fmt.Errorf("parse asset id: %w", err)
		}
		m := map[string]any{}
		if len(props) > 0 {
			if err := json.Unmarshal(props, &m); err != nil {
				m = map[string]any{}
			}
		}
		out = append(out, ingest.StoredAsset{
			ID: aid, Name: name, Type: asset.AssetType(typ), Properties: m, RepoID: repoID,
			LastSeen: backfillTime(lastSeen), CreatedAt: backfillTime(createdAt),
			FindingCount: findings, DiscoveryTool: tool,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stored assets: %w", err)
	}
	return out, nil
}

func backfillTime(t sql.NullTime) time.Time {
	if t.Valid {
		return t.Time
	}
	return time.Time{}
}
