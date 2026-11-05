package postgres

// Inputs of path discovery's derived candidate list
// (docs/architecture/web-discovery.md). Every query carries the tenant: an
// origin, an endpoint or an API description of another organization is
// never read.

import (
	"context"
	"fmt"
	"strings"
	"sync"
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
type WebDiscoveryRepository struct {
	db    *DB
	mu    sync.Mutex
	cache map[string]siblingCacheEntry
}

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
		  AND e.sources <> '{guess}'
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

	in.Siblings, err = r.siblingPaths(ctx, tenantID, ids)
	if err != nil {
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

// siblingCacheTTL is how long an organization's path counts are reused. A
// path discovery job reads them once per origin; an organization with many
// origins would otherwise aggregate its whole endpoint table once per claim.
const siblingCacheTTL = 10 * time.Minute

// siblingCacheMax bounds the organizations whose counts are held.
const siblingCacheMax = 256

// siblingCount is one path the organization's origins serve.
type siblingCount struct {
	template string
	hash     string
	origins  int
}

type siblingCacheEntry struct {
	at     time.Time
	counts []siblingCount
}

// siblingPaths are the paths at least two of the organization's other
// origins serve that origin (ids) does not, most shared first. Paths of
// path discovery's own guesses (sources exactly {guess}) are not counted:
// a guess confirmed on two origins would otherwise be offered to a third as
// if the organization served it. The counts are of the whole organization,
// computed once per siblingCacheTTL; the origin's own paths (any state) are
// subtracted per call.
func (r *WebDiscoveryRepository) siblingPaths(ctx context.Context, tenantID shared.ID, ids []string) ([]webendpoint.SiblingPath, error) {
	counts, err := r.siblingCounts(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT path_hash FROM web_endpoints
		WHERE tenant_id = $1 AND origin_asset_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("derived: own path hashes: %w", err)
	}
	own := map[string]bool{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("derived: scan own path hash: %w", err)
		}
		own[h] = true
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]webendpoint.SiblingPath, 0, min(len(counts), derivedSiblingRows))
	for _, c := range counts {
		if own[c.hash] {
			continue
		}
		out = append(out, webendpoint.SiblingPath{Template: c.template, Origins: c.origins})
		if len(out) >= derivedSiblingRows {
			break
		}
	}
	return out, nil
}

// siblingCounts reads (or reuses) the organization's path counts: the paths
// at least two origins serve, ordered most shared first. It keeps the rows
// an origin's own paths can take out of the top (derivedOwnRows of them) so
// the trimmed list still holds derivedSiblingRows after the subtraction.
func (r *WebDiscoveryRepository) siblingCounts(ctx context.Context, tenantID shared.ID) ([]siblingCount, error) {
	key := tenantID.String()
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && time.Since(e.at) < siblingCacheTTL {
		r.mu.Unlock()
		return e.counts, nil
	}
	r.mu.Unlock()
	rows, err := r.db.QueryContext(ctx, `
		SELECT e.path_template, min(e.path_hash), count(DISTINCT e.origin_asset_id)
		FROM web_endpoints e
		JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.origin_asset_id AND a.deleted_at IS NULL
		WHERE e.tenant_id = $1 AND e.state = 'active' AND e.in_scope AND e.method IN ('GET', 'HEAD', 'ANY')
		  AND e.sources <> '{guess}'
		GROUP BY e.path_template
		HAVING count(DISTINCT e.origin_asset_id) >= 2
		ORDER BY count(DISTINCT e.origin_asset_id) DESC, e.path_template
		LIMIT $2`, key, derivedSiblingRows+derivedOwnRows)
	if err != nil {
		return nil, fmt.Errorf("derived: sibling paths: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []siblingCount
	for rows.Next() {
		var c siblingCount
		if err := rows.Scan(&c.template, &c.hash, &c.origins); err != nil {
			return nil, fmt.Errorf("derived: scan sibling: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.cache == nil || len(r.cache) >= siblingCacheMax {
		r.cache = map[string]siblingCacheEntry{}
	}
	r.cache[key] = siblingCacheEntry{at: time.Now(), counts: out}
	r.mu.Unlock()
	return out, nil
}
