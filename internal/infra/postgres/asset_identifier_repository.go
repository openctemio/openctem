package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetIdentifierRepository stores the identifiers assets were seen with
// (table asset_identifiers). Strong kinds are unique per tenant; the others
// are unique per asset.
type AssetIdentifierRepository struct {
	db     *DB
	assets *AssetRepository
}

// NewAssetIdentifierRepository creates the repository. assets loads the
// assets an identifier lookup points at.
func NewAssetIdentifierRepository(db *DB, assets *AssetRepository) *AssetIdentifierRepository {
	return &AssetIdentifierRepository{db: db, assets: assets}
}

const assetIdentifierColumns = `asset_id, kind, value, source, first_seen, last_seen`

// FindByValues returns every recorded identifier matching one of keys.
func (r *AssetIdentifierRepository) FindByValues(ctx context.Context, tenantID shared.ID, keys []asset.IdentifierKey) ([]asset.Identifier, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	kinds := make([]string, len(keys))
	values := make([]string, len(keys))
	for i, k := range keys {
		kinds[i] = string(k.Kind)
		values[i] = k.Value
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+assetIdentifierColumns+`
		FROM asset_identifiers
		WHERE tenant_id = $1
		  AND (kind, value) IN (SELECT k, v FROM unnest($2::text[], $3::text[]) AS t(k, v))`,
		tenantID.String(), pq.Array(kinds), pq.Array(values))
	if err != nil {
		return nil, fmt.Errorf("find asset identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out, err := scanIdentifiers(rows)
	if err != nil {
		return nil, err
	}
	return out, rows.Err()
}

// ListByAssets returns every identifier recorded for the assets.
func (r *AssetIdentifierRepository) ListByAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]asset.Identifier, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+assetIdentifierColumns+`
		FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])
		ORDER BY asset_id, kind, last_seen DESC`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("list asset identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out, err := scanIdentifiers(rows)
	if err != nil {
		return nil, err
	}
	return out, rows.Err()
}

// GetAssetsByIDs loads assets by id, keyed by id string.
func (r *AssetIdentifierRepository) GetAssetsByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]*asset.Asset, error) {
	return r.assets.GetByIDs(ctx, tenantID, ids)
}

// Upsert records identifiers and refreshes last_seen on ones already
// recorded. A strong identifier another asset already holds is not moved:
// it is returned in taken, with AssetID set to the asset that holds it, so
// the caller can raise a duplicate review instead of silently re-pointing it.
func (r *AssetIdentifierRepository) Upsert(ctx context.Context, tenantID shared.ID, ids []asset.Identifier) (taken []asset.Identifier, err error) {
	strong, weak, contested := splitIdentifiers(ids)

	if len(weak) > 0 {
		a, k, v, s, f, l := identifierArrays(weak)
		if _, err := r.db.ExecContext(ctx, `
			INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, strong, source, first_seen, last_seen)
			SELECT $1, t.a, t.k, t.v, FALSE, t.s, t.f, t.l
			FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::timestamptz[], $7::timestamptz[]) AS t(a, k, v, s, f, l)
			ON CONFLICT (asset_id, kind, value) DO UPDATE SET
				last_seen  = GREATEST(asset_identifiers.last_seen, EXCLUDED.last_seen),
				first_seen = LEAST(asset_identifiers.first_seen, EXCLUDED.first_seen),
				source     = CASE WHEN EXCLUDED.last_seen >= asset_identifiers.last_seen AND EXCLUDED.source <> ''
				                  THEN EXCLUDED.source ELSE asset_identifiers.source END`,
			tenantID.String(), a, k, v, s, f, l); err != nil {
			return nil, fmt.Errorf("upsert asset identifiers: %w", err)
		}
	}

	if len(strong) == 0 {
		return nil, nil
	}
	written, err := r.upsertStrong(ctx, tenantID, strong)
	if err != nil {
		return nil, err
	}

	var missing []asset.IdentifierKey
	for _, id := range strong {
		if !written[id.Key()] || contested[id.Key()] {
			missing = append(missing, id.Key())
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	return r.FindByValues(ctx, tenantID, missing)
}

// upsertStrong inserts strong identifiers and returns the keys it wrote. A
// key another asset holds is not written.
func (r *AssetIdentifierRepository) upsertStrong(ctx context.Context, tenantID shared.ID, strong []asset.Identifier) (map[asset.IdentifierKey]bool, error) {
	a, k, v, s, f, l := identifierArrays(strong)
	rows, err := r.db.QueryContext(ctx, `
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, strong, source, first_seen, last_seen)
		SELECT $1, t.a, t.k, t.v, TRUE, t.s, t.f, t.l
		FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::timestamptz[], $7::timestamptz[]) AS t(a, k, v, s, f, l)
		ON CONFLICT (tenant_id, kind, value) WHERE strong DO UPDATE SET
			last_seen  = GREATEST(asset_identifiers.last_seen, EXCLUDED.last_seen),
			first_seen = LEAST(asset_identifiers.first_seen, EXCLUDED.first_seen),
			source     = CASE WHEN EXCLUDED.last_seen >= asset_identifiers.last_seen AND EXCLUDED.source <> ''
			                  THEN EXCLUDED.source ELSE asset_identifiers.source END
		WHERE asset_identifiers.asset_id = EXCLUDED.asset_id
		RETURNING kind, value`,
		tenantID.String(), a, k, v, s, f, l)
	if err != nil {
		return nil, fmt.Errorf("upsert strong asset identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	written := make(map[asset.IdentifierKey]bool, len(strong))
	for rows.Next() {
		var kind, value string
		if err := rows.Scan(&kind, &value); err != nil {
			return nil, fmt.Errorf("scan upserted identifier: %w", err)
		}
		written[asset.IdentifierKey{Kind: asset.IdentifierKind(kind), Value: value}] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate upserted identifiers: %w", err)
	}
	return written, nil
}

// splitIdentifiers drops invalid entries and in-statement duplicates (one
// INSERT ... ON CONFLICT cannot touch a row twice) and splits by strength.
// A strong key claimed by two assets in one call keeps the first claim and is
// returned in contested, so Upsert reports it as taken to the caller.
func splitIdentifiers(ids []asset.Identifier) (strong, weak []asset.Identifier, contested map[asset.IdentifierKey]bool) {
	contested = map[asset.IdentifierKey]bool{}
	firstOwner := map[asset.IdentifierKey]string{}
	type akey struct {
		asset string
		key   asset.IdentifierKey
	}
	seenStrong := make(map[asset.IdentifierKey]bool)
	seenWeak := make(map[akey]bool)
	for _, id := range ids {
		if !id.Kind.IsValid() || id.Value == "" || id.AssetID.IsZero() {
			continue
		}
		if id.LastSeen.IsZero() {
			id.LastSeen = time.Now().UTC()
		}
		if id.FirstSeen.IsZero() || id.FirstSeen.After(id.LastSeen) {
			id.FirstSeen = id.LastSeen
		}
		if id.Kind.IsStrong() {
			if seenStrong[id.Key()] {
				if firstOwner[id.Key()] != id.AssetID.String() {
					contested[id.Key()] = true
				}
				continue
			}
			seenStrong[id.Key()] = true
			firstOwner[id.Key()] = id.AssetID.String()
			strong = append(strong, id)
			continue
		}
		k := akey{id.AssetID.String(), id.Key()}
		if seenWeak[k] {
			continue
		}
		seenWeak[k] = true
		weak = append(weak, id)
	}
	return strong, weak, contested
}

func identifierArrays(ids []asset.Identifier) (assetIDs, kinds, values, sources any, first, last any) {
	a := make([]string, len(ids))
	k := make([]string, len(ids))
	v := make([]string, len(ids))
	s := make([]string, len(ids))
	f := make([]string, len(ids))
	l := make([]string, len(ids))
	for i, id := range ids {
		a[i] = id.AssetID.String()
		k[i] = string(id.Kind)
		v[i] = id.Value
		s[i] = truncateIdentifierSource(id.Source)
		f[i] = id.FirstSeen.UTC().Format(time.RFC3339Nano)
		l[i] = id.LastSeen.UTC().Format(time.RFC3339Nano)
	}
	return pq.Array(a), pq.Array(k), pq.Array(v), pq.Array(s), pq.Array(f), pq.Array(l)
}

// truncateIdentifierSource fits a tool name into the 100-char source column.
func truncateIdentifierSource(s string) string {
	if len(s) <= 100 {
		return s
	}
	return s[:100]
}

type identifierRows interface {
	Next() bool
	Scan(dest ...any) error
}

// scanIdentifiers reads identifier rows; the caller closes rows and checks
// rows.Err.
func scanIdentifiers(rows identifierRows) ([]asset.Identifier, error) {
	var out []asset.Identifier
	for rows.Next() {
		var (
			assetID, kind, value, source string
			first, last                  time.Time
		)
		if err := rows.Scan(&assetID, &kind, &value, &source, &first, &last); err != nil {
			return nil, fmt.Errorf("scan asset identifier: %w", err)
		}
		id, err := shared.IDFromString(assetID)
		if err != nil {
			return nil, fmt.Errorf("parse asset id: %w", err)
		}
		out = append(out, asset.Identifier{
			AssetID: id, Kind: asset.IdentifierKind(kind), Value: value, Source: source,
			FirstSeen: first, LastSeen: last,
		})
	}
	return out, nil
}
