package postgres

// Inputs of path discovery's derived candidate list
// (docs/architecture/web-discovery.md). Every query carries the tenant: an
// origin, an endpoint or an API description of another organization is
// never read.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

// Bounds of the rows one derived list reads.
const (
	derivedOwnRows     = 5000
	derivedSiblingRows = 2000
	derivedSpecRows    = 1000
)

// WebDiscoveryRepository reads the derived list inputs.
type WebDiscoveryRepository struct{ db *DB }

// NewWebDiscoveryRepository returns the repository.
func NewWebDiscoveryRepository(db *DB) *WebDiscoveryRepository {
	return &WebDiscoveryRepository{db: db}
}

// DerivedInput reads one origin's inputs: its active in-scope GET endpoints,
// the paths at least two of the organization's other origins serve that
// this one does not, and the GET paths its API descriptions declare. An
// origin the organization does not have gives an empty input.
func (r *WebDiscoveryRepository) DerivedInput(ctx context.Context, tenantID shared.ID, origin string) (webendpoint.DerivedInput, error) {
	var in webendpoint.DerivedInput
	ids, err := r.originIDs(ctx, tenantID, origin)
	if err != nil || len(ids) == 0 {
		return in, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT e.path_template, e.catalog_key IS NOT NULL, e.last_seen_at
		FROM web_endpoints e
		WHERE e.tenant_id = $1 AND e.origin_asset_id = ANY($2::uuid[])
		  AND e.state = 'active' AND e.in_scope AND e.method IN ('GET', 'HEAD', 'ANY')
		ORDER BY e.last_seen_at DESC
		LIMIT $3`, tenantID.String(), pq.Array(ids), derivedOwnRows)
	if err != nil {
		return in, fmt.Errorf("derived: own endpoints: %w", err)
	}
	for rows.Next() {
		var row webendpoint.DerivedRow
		var seen time.Time
		if err := rows.Scan(&row.Template, &row.Catalog, &seen); err != nil {
			_ = rows.Close()
			return in, fmt.Errorf("derived: scan endpoint: %w", err)
		}
		row.LastSeen = seen
		in.Own = append(in.Own, row)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return in, err
	}

	rows, err = r.db.QueryContext(ctx, `
		SELECT e.path_template, count(DISTINCT e.origin_asset_id)
		FROM web_endpoints e
		JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.origin_asset_id AND a.deleted_at IS NULL
		WHERE e.tenant_id = $1 AND NOT (e.origin_asset_id = ANY($2::uuid[]))
		  AND e.state = 'active' AND e.in_scope AND e.method IN ('GET', 'HEAD', 'ANY')
		  AND NOT EXISTS (SELECT 1 FROM web_endpoints h
			WHERE h.tenant_id = e.tenant_id AND h.origin_asset_id = ANY($2::uuid[]) AND h.path_hash = e.path_hash)
		GROUP BY e.path_template
		HAVING count(DISTINCT e.origin_asset_id) >= 2
		ORDER BY count(DISTINCT e.origin_asset_id) DESC, e.path_template
		LIMIT $3`, tenantID.String(), pq.Array(ids), derivedSiblingRows)
	if err != nil {
		return in, fmt.Errorf("derived: sibling paths: %w", err)
	}
	for rows.Next() {
		var s webendpoint.SiblingPath
		if err := rows.Scan(&s.Template, &s.Origins); err != nil {
			_ = rows.Close()
			return in, fmt.Errorf("derived: scan sibling: %w", err)
		}
		in.Siblings = append(in.Siblings, s)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return in, err
	}

	rows, err = r.db.QueryContext(ctx, `
		SELECT DISTINCT o.path
		FROM api_spec_operations o
		JOIN api_specs s ON s.tenant_id = o.tenant_id AND s.id = o.spec_id
		WHERE o.tenant_id = $1 AND s.origin_asset_id = ANY($2::uuid[])
		  AND o.method IN ('GET', 'HEAD') AND strpos(o.path, '{') = 0
		ORDER BY o.path
		LIMIT $3`, tenantID.String(), pq.Array(ids), derivedSpecRows)
	if err != nil {
		return in, fmt.Errorf("derived: declared paths: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return in, fmt.Errorf("derived: scan declared path: %w", err)
		}
		in.SpecPaths = append(in.SpecPaths, p)
	}
	return in, rows.Err()
}

// originIDs are the tenant's live web service assets named origin.
func (r *WebDiscoveryRepository) originIDs(ctx context.Context, tenantID shared.ID, origin string) ([]string, error) {
	origin = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(origin), "/"))
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.asset_type = 'service' AND a.sub_type = 'http'
		  AND lower(rtrim(a.name, '/')) = $2
		LIMIT 8`, tenantID.String(), origin)
	if err != nil {
		return nil, fmt.Errorf("derived: origin: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
