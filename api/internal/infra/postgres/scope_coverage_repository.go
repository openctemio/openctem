package postgres

// Scope coverage: how much of the tenant's internet-facing inventory its
// active scope targets cover (research/53 SC8, S-3). Computed in one SQL
// statement, never by paging every asset into memory, and only over the
// assets the caller may see (Layer 2 data scope), so the counts are not an
// oracle for the size of the inventory outside the caller's scope.
//
// The match mirrors pkg/domain/scope on the asset's host (the name, or the
// host of a URL or host:port), as the active-probe authority does:
//
//   - domain targets: "x" is exactly x; "*.x" / "**.x" is x and every name
//     below it (RFC-054 §4.1);
//   - ip_address targets: the address; cidr / ip_range targets: the address
//     is inside the network or the a-b range;
//   - every other target type: the scope wildcard on the asset name
//     (exact, "prefix/*", or one "*").
//
// An active, approved, unexpired exclusion of the same kinds wins (an IP
// exclusion wins on any overlap). Exclusions of finding_type, scanner and
// path do not describe assets and are not applied here.

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeCoverageRepository counts scope coverage of the inventory.
type ScopeCoverageRepository struct {
	db *DB
}

// NewScopeCoverageRepository creates the repository.
func NewScopeCoverageRepository(db *DB) *ScopeCoverageRepository {
	return &ScopeCoverageRepository{db: db}
}

// scopeCoverageAssetTypes are the stored internet-facing asset types (the EASM
// governed set without certificates, which are not probe targets).
var scopeCoverageAssetTypes = []string{"domain", "subdomain", "ip_address", "service", "application"}

// scopeCoverageInventoryStates are the attribution states inside the inventory
// (RFC-054 §4.4, §15: discovered included, so what no entry covers shows);
// an asset with no attribution record is in it too.
var scopeCoverageInventoryStates = []string{"confirmed", "discovered", "dependency", "monitor_only"}

const scopeCoverageQuery = `
WITH inv AS (
	SELECT a.id, lower(a.name) AS name,
		lower(rtrim(trim(both '[]' from CASE
			WHEN a.name ~ '://' THEN substring(a.name from '://(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)')
			WHEN a.name ~ '^\[[^\]]+\]' THEN substring(a.name from '^(\[[^\]]+\])')
			-- A service, stored as host:port:proto (also host:port/proto and the
			-- unbracketed IPv6 v6:port:proto): the host (asset.SplitServiceName).
			WHEN a.name ~ ':[0-9]{1,5}[:/](tcp|udp|sctp)$' THEN regexp_replace(a.name, ':[0-9]{1,5}[:/](tcp|udp|sctp)$', '')
			WHEN a.name ~ '^[^:/]+:[0-9]+$' THEN split_part(a.name, ':', 1)
			ELSE a.name END), '.')) AS host
	FROM assets a
	WHERE a.tenant_id = $1
	  AND a.status = 'active'
	  AND a.asset_type = ANY($2)
	  AND (NOT EXISTS (SELECT 1 FROM asset_attributions x WHERE x.asset_id = a.id AND x.tenant_id = a.tenant_id)
	       OR EXISTS (SELECT 1 FROM asset_attributions x
	                  WHERE x.asset_id = a.id AND x.tenant_id = a.tenant_id AND x.state = ANY($3)))
	  AND ($4::uuid IS NULL OR a.id IN (
	       SELECT u.asset_id FROM user_accessible_assets u WHERE u.user_id = $4::uuid AND u.tenant_id = $1))
), c AS (
	SELECT i.id, i.name, i.host,
		CASE WHEN pg_input_is_valid(i.host, 'inet') THEN i.host::inet END AS ip
	FROM inv i
), cls AS (
	SELECT c.*,
		(c.ip IS NOT NULL AND (
			c.ip <<= ANY (ARRAY['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16',
			                    '100.64.0.0/10','0.0.0.0/8','::1/128','fc00::/7','fe80::/10']::inet[])))
		OR c.host = 'localhost' OR c.host LIKE '%.localhost' OR c.host LIKE '%.local'
		OR c.host LIKE '%.internal' OR c.host LIKE '%.lan' AS internal
	FROM c
), rules AS (
	SELECT r.side, r.kind, r.p,
		(r.p LIKE '*.%' OR r.p LIKE '**.%') AS wild,
		regexp_replace(r.p, '^\*\*?\.', '') AS root,
		CASE WHEN r.kind IN ('ip_address', 'cidr', 'ip_range') AND pg_input_is_valid(r.p, 'inet') THEN r.p::inet END AS net,
		CASE WHEN r.p ~ '^[^-]+-[^-]+$' AND pg_input_is_valid(trim(split_part(r.p, '-', 1)), 'inet')
		          AND pg_input_is_valid(trim(split_part(r.p, '-', 2)), 'inet')
		     THEN trim(split_part(r.p, '-', 1))::inet END AS lo,
		CASE WHEN r.p ~ '^[^-]+-[^-]+$' AND pg_input_is_valid(trim(split_part(r.p, '-', 1)), 'inet')
		          AND pg_input_is_valid(trim(split_part(r.p, '-', 2)), 'inet')
		     THEN trim(split_part(r.p, '-', 2))::inet END AS hi
	FROM (
		SELECT 'in' AS side, t.target_type AS kind, lower(rtrim(trim(t.pattern), '.')) AS p
		FROM scope_targets t WHERE t.tenant_id = $1 AND t.status = 'active' AND t.ports = '' AND t.protocol = ''
		UNION ALL
		SELECT 'out', e.exclusion_type, lower(rtrim(trim(e.pattern), '.'))
		FROM scope_exclusions e
		WHERE e.tenant_id = $1 AND e.status = 'active' AND e.approved_at IS NOT NULL
		  AND (e.expires_at IS NULL OR e.expires_at > now())
		  AND e.exclusion_type NOT IN ('finding_type', 'scanner', 'path')
	) r
), matched AS (
	SELECT cls.id,
		bool_or(m.side = 'in') AS covered,
		bool_or(m.side = 'out') AS excluded
	FROM cls
	JOIN rules m ON (
		(m.kind IN ('domain', 'subdomain', 'email_domain')
			AND ((NOT m.wild AND cls.host = m.root)
			  OR (m.wild AND (cls.host = m.root OR right(cls.host, length(m.root) + 1) = '.' || m.root))))
		OR (m.kind IN ('ip_address', 'cidr', 'ip_range') AND cls.ip IS NOT NULL AND (
			(m.net IS NOT NULL AND (cls.ip <<= m.net OR (m.side = 'out' AND cls.ip && m.net)))
			OR (m.lo IS NOT NULL AND m.hi IS NOT NULL AND cls.ip >= m.lo AND cls.ip <= m.hi)))
		OR (m.kind NOT IN ('domain', 'subdomain', 'email_domain', 'ip_address', 'cidr', 'ip_range') AND (
			cls.name = m.p
			OR (m.p LIKE '%/*' AND (cls.name = left(m.p, -2) OR left(cls.name, length(m.p) - 1) = left(m.p, -1)))
			OR (m.p NOT LIKE '%/*' AND array_length(string_to_array(m.p, '*'), 1) = 2
			    AND left(cls.name, length(split_part(m.p, '*', 1))) = split_part(m.p, '*', 1)
			    AND right(cls.name, length(split_part(m.p, '*', 2))) = split_part(m.p, '*', 2))))
	)
	GROUP BY cls.id
)
SELECT
	count(*) FILTER (WHERE NOT cls.internal) AS internet_facing,
	count(*) FILTER (WHERE NOT cls.internal AND coalesce(m.covered, false) AND NOT coalesce(m.excluded, false)) AS in_scope,
	count(*) FILTER (WHERE cls.internal) AS internal
FROM cls LEFT JOIN matched m ON m.id = cls.id`

// CountCoverage counts the tenant's internet-facing inventory, the part of
// it the active scope targets cover (and no exclusion removes), and the
// internal names and addresses left out of both (zone-gated). A non-nil
// scope narrows every count to the assets that user may see.
func (r *ScopeCoverageRepository) CountCoverage(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (scopedom.InventoryCoverage, error) {
	var out scopedom.InventoryCoverage
	var user any
	if scope != nil {
		if !scope.TenantID.IsZero() && scope.TenantID != tenantID {
			// A scope for another tenant admits nothing (fail closed).
			return out, nil
		}
		if scope.Restricted() {
			// Program-only assets are not the organization's coverage; an
			// unrestricted scope counts like the whole organization.
			user = scope.UserID.String()
		}
	}
	err := r.db.QueryRowContext(ctx, scopeCoverageQuery, tenantID.String(),
		pq.Array(scopeCoverageAssetTypes), pq.Array(scopeCoverageInventoryStates), user).
		Scan(&out.InternetFacing, &out.InScope, &out.Internal)
	if err != nil {
		return out, fmt.Errorf("count scope coverage: %w", err)
	}
	return out, nil
}

// CountVisibleAssets counts the given assets of the tenant that the data
// scope lets the caller see (nil scope: every one); the scope join counts
// (scope.Service.JoinNow, PreviewJoin). Ids that are not the tenant's assets
// count for nothing.
func (r *ScopeCoverageRepository) CountVisibleAssets(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, assetIDs []string) (int, error) {
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		if _, err := shared.IDFromString(id); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var user any
	if scope != nil {
		if !scope.TenantID.IsZero() && scope.TenantID != tenantID {
			return 0, nil // a scope for another tenant admits nothing
		}
		if scope.Restricted() {
			user = scope.UserID.String()
		}
	}
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM assets a
		WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])
		  AND ($3::uuid IS NULL OR a.id IN (
		       SELECT u.asset_id FROM user_accessible_assets u WHERE u.user_id = $3::uuid AND u.tenant_id = $1))`,
		tenantID.String(), pq.Array(ids), user).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count visible assets: %w", err)
	}
	return n, nil
}

var _ scopeapp.ExclusionMatchCounter = (*ScopeCoverageRepository)(nil)

// maxExclusionSample is how many names a preview lists per pattern.
const maxExclusionSample = 10

// ExclusionMatches counts, for each candidate exclusion, the tenant's live
// inventory assets it would match (the same match as the scope status filter
// and the coverage count), narrowed to the data scope ds (nil: the whole
// tenant), with up to ten names. Results are in item order. One statement.
func (r *ScopeCoverageRepository) ExclusionMatches(ctx context.Context, tenantID shared.ID, ds *shared.DataScope, items []scopeapp.BulkExclusionItem) ([]scopeapp.ExclusionMatch, error) {
	out := make([]scopeapp.ExclusionMatch, len(items))
	if len(items) == 0 {
		return out, nil
	}
	if ds != nil && !ds.TenantID.IsZero() && ds.TenantID != tenantID {
		return out, nil // a scope for another tenant admits nothing (fail closed)
	}
	kinds := make([]string, len(items))
	patterns := make([]string, len(items))
	for i, it := range items {
		kinds[i], patterns[i] = it.ExclusionType, it.Pattern
	}
	args := []any{tenantID.String(), pq.Array(kinds), pq.Array(patterns)}
	sc, args := scopeClause("a.id", ds, args)
	//nolint:gosec // G202: the match and scope clauses are fixed SQL with numbered placeholders
	rows, err := r.db.QueryContext(ctx, `
		WITH items AS (
			SELECT i.kind, i.pattern, i.ord FROM unnest($2::text[], $3::text[]) WITH ORDINALITY AS i(kind, pattern, ord)
		), inv AS (
			SELECT a.id, a.name, lower(a.name) AS lname, hh.host,
				CASE WHEN pg_input_is_valid(hh.host, 'inet') THEN hh.host::inet END AS ip,
				(SELECT count(*) FROM findings f WHERE f.tenant_id = $1 AND f.asset_id = a.id
				   AND f.status IN `+scopeEffectsOpenStatuses+`) AS open_findings
			FROM assets a CROSS JOIN LATERAL (SELECT `+assetHostSQL("a")+` AS host) hh
			WHERE a.tenant_id = $1 AND a.deleted_at IS NULL`+sc+`
		)
		SELECT items.ord, count(inv.id), COALESCE(sum(inv.open_findings), 0), COALESCE((array_agg(inv.name ORDER BY inv.name) FILTER (WHERE inv.id IS NOT NULL))[1:`+fmt.Sprint(maxExclusionSample)+`], '{}')
		FROM items
		LEFT JOIN inv ON `+scopePatternMatchSQL("items.kind", "items.pattern", "inv.host", "inv.ip", "inv.lname")+`
		GROUP BY items.ord
		ORDER BY items.ord`, args...)
	if err != nil {
		return nil, fmt.Errorf("preview exclusion matches: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ord, n, open int
		var sample []string
		if err := rows.Scan(&ord, &n, &open, pq.Array(&sample)); err != nil {
			return nil, err
		}
		if ord >= 1 && ord <= len(out) {
			out[ord-1] = scopeapp.ExclusionMatch{Matched: n, OpenFindings: open, Sample: sample}
		}
	}
	return out, rows.Err()
}
