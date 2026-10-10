package postgres

// Software components inventory reads. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.
//
// Every query starts from the tenant's package links (asset_software rows
// with source 'package') of live assets and, when a data scope is given,
// only of assets in it; a package, version, path or graph node is visible
// only through such a link.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ComponentRepository reads the inventory and, through the embedded package
// writer, records package observations.
type ComponentRepository struct {
	db *DB
	*SoftwarePackageWriter
}

// NewComponentRepository creates a ComponentRepository.
func NewComponentRepository(db *DB) *ComponentRepository {
	return &ComponentRepository{db: db, SoftwarePackageWriter: NewSoftwarePackageWriter(db)}
}

var (
	_ component.Repository   = (*ComponentRepository)(nil)
	_ software.PackageWriter = (*ComponentRepository)(nil)
)

const (
	// closedStatusesSQL are the finding statuses that need no action.
	closedStatusesSQL = `('resolved', 'false_positive', 'accepted', 'duplicate')`

	// pkgKEVExpr: the finding's vulnerability is known exploited.
	pkgKEVExpr = `(COALESCE(f.is_in_kev, false) OR v.cisa_kev_date_added IS NOT NULL)`
	// pkgFixExpr: a fixed version or fix is known for the finding.
	pkgFixExpr = `(COALESCE(f.remedy_available, false) OR f.remediation->>'fix_available' = 'true'
		OR cardinality(COALESCE(v.fixed_versions, '{}'::text[])) > 0)`
	// pkgRiskExpr is the finding's contribution to package risk (0-100):
	// severity floor, +15 known exploited, +10 EPSS >= 0.1, times the asset
	// criticality factor.
	pkgRiskExpr = `LEAST(100, GREATEST(0, ROUND(
		((CASE f.severity WHEN 'critical' THEN 90 WHEN 'high' THEN 70 WHEN 'medium' THEN 40 WHEN 'low' THEN 10 ELSE 0 END)
		 + CASE WHEN ` + pkgKEVExpr + ` THEN 15 ELSE 0 END
		 + CASE WHEN COALESCE(f.epss_score, v.epss_score, 0) >= 0.1 THEN 10 ELSE 0 END)
		* (CASE a.criticality WHEN 'critical' THEN 1.0 WHEN 'high' THEN 0.9 WHEN 'medium' THEN 0.75 WHEN 'low' THEN 0.6 ELSE 0.75 END)
	)))::int`
)

// sqlArgs numbers placeholders as conditions are added.
type sqlArgs struct{ vals []any }

func (a *sqlArgs) add(v any) string {
	a.vals = append(a.vals, v)
	return fmt.Sprintf("$%d", len(a.vals))
}

func (a *sqlArgs) scope(assetExpr string, s *shared.DataScope) string {
	if s == nil {
		return ""
	}
	cond, vals := dataScopeCondAt(assetExpr, s, len(a.vals)+1)
	a.vals = append(a.vals, vals...)
	return " AND " + cond
}

// packagesCTE builds the CTEs every list, facet and summary query reads:
// links (filtered package links), vf (open findings on those links) and
// pkgs (one row per package with its aggregates and product filters).
func packagesCTE(f component.Filter, args *sqlArgs) string {
	tenant := args.add(f.TenantID.String())
	var link strings.Builder
	link.WriteString(args.scope("s.asset_id", f.Scope))
	if f.AssetID != nil {
		link.WriteString(" AND s.asset_id = " + args.add(f.AssetID.String()))
	}
	if len(f.Relationship) > 0 {
		link.WriteString(" AND s.relationship = ANY(" + args.add(pq.Array(f.Relationship)) + ")")
	}
	if len(f.Scopes) > 0 {
		link.WriteString(" AND COALESCE(s.dep_scope, 'runtime') = ANY(" + args.add(pq.Array(f.Scopes)) + ")")
	}
	if f.OwnerID != nil {
		owner := args.add(f.OwnerID.String())
		link.WriteString(` AND EXISTS (SELECT 1 FROM asset_owners o WHERE o.asset_id = s.asset_id AND (o.user_id = ` + owner +
			` OR o.group_id IN (SELECT gm.group_id FROM group_members gm WHERE gm.user_id = ` + owner + `)))`)
	}

	var prod strings.Builder
	if q := strings.TrimSpace(f.Query); q != "" {
		like := args.add("%" + escapeLikePattern(q) + "%")
		prod.WriteString(" AND (p.name ILIKE " + like + " OR p.purl_name ILIKE " + like + " OR p.purl_namespace ILIKE " + like + ")")
	}
	if len(f.PURLTypes) > 0 {
		prod.WriteString(" AND p.purl_type = ANY(" + args.add(pq.Array(f.PURLTypes)) + ")")
	}
	if len(f.Licenses) > 0 {
		prod.WriteString(" AND COALESCE(plic.licenses, '{}'::text[]) && " + args.add(pq.Array(f.Licenses)) + "::text[]")
	}
	if len(f.Severities) > 0 {
		conds := make([]string, 0, len(f.Severities))
		for _, s := range f.Severities {
			switch s {
			case "critical", "high", "medium", "low":
				conds = append(conds, "COALESCE(pf."+s+", 0) > 0")
			}
		}
		if len(conds) > 0 {
			prod.WriteString(" AND (" + strings.Join(conds, " OR ") + ")")
		}
	}
	boolCond := func(b *bool, expr string) {
		if b == nil {
			return
		}
		if *b {
			prod.WriteString(" AND " + expr)
		} else {
			prod.WriteString(" AND NOT " + expr)
		}
	}
	boolCond(f.KEV, "(COALESCE(pf.kev, 0) > 0)")
	boolCond(f.HasFix, "COALESCE(pf.fix, false)")
	boolCond(f.HasVulns, "(COALESCE(pf.critical + pf.high + pf.medium + pf.low, 0) > 0)")

	return `
		WITH links AS (
			SELECT s.id, s.asset_id, s.product_id, s.software_version_id AS version_id, s.relationship,
			       s.dep_scope, s.licenses, s.first_seen_at, s.last_seen_at
			FROM asset_software s
			JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id AND a.deleted_at IS NULL
			WHERE s.tenant_id = ` + tenant + ` AND s.source = 'package' AND s.superseded_at IS NULL` + link.String() + `
		), vf AS (
			SELECT sv.product_id, f.component_id AS version_id, f.asset_id, f.severity,
			       ` + pkgKEVExpr + ` AS kev, ` + pkgFixExpr + ` AS fix, ` + pkgRiskExpr + ` AS risk
			FROM findings f
			JOIN software_versions sv ON sv.id = f.component_id
			JOIN assets a ON a.id = f.asset_id
			LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
			WHERE f.tenant_id = ` + tenant + ` AND f.component_id IS NOT NULL AND f.status NOT IN ` + closedStatusesSQL + `
			  AND EXISTS (SELECT 1 FROM links l WHERE l.asset_id = f.asset_id AND l.version_id = f.component_id)
		), pl AS (
			SELECT product_id, count(DISTINCT version_id) AS versions, count(DISTINCT asset_id) AS assets,
			       count(*) FILTER (WHERE relationship = 'direct') AS direct_links,
			       count(*) FILTER (WHERE relationship = 'transitive') AS transitive_links,
			       min(first_seen_at) AS first_seen_at, max(last_seen_at) AS last_seen_at
			FROM links GROUP BY product_id
		), plic AS (
			SELECT product_id, array_agg(DISTINCT lic ORDER BY lic) AS licenses
			FROM links, unnest(licenses) AS lic GROUP BY product_id
		), pf AS (
			SELECT product_id,
			       count(*) FILTER (WHERE severity = 'critical') AS critical,
			       count(*) FILTER (WHERE severity = 'high') AS high,
			       count(*) FILTER (WHERE severity = 'medium') AS medium,
			       count(*) FILTER (WHERE severity = 'low') AS low,
			       count(*) FILTER (WHERE kev) AS kev, bool_or(fix) AS fix, max(risk) AS risk
			FROM vf GROUP BY product_id
		), pkgs AS (
			SELECT p.id, p.name, COALESCE(p.purl_namespace, '') AS namespace, p.purl_type, p.purl_name,
			       pl.versions, pl.assets, pl.direct_links, pl.transitive_links, pl.first_seen_at, pl.last_seen_at,
			       COALESCE(plic.licenses, '{}'::text[]) AS licenses,
			       COALESCE(pf.critical, 0) AS critical, COALESCE(pf.high, 0) AS high,
			       COALESCE(pf.medium, 0) AS medium, COALESCE(pf.low, 0) AS low,
			       COALESCE(pf.kev, 0) AS kev, COALESCE(pf.fix, false) AS fix, COALESCE(pf.risk, 0) AS risk
			FROM pl
			JOIN software_products p ON p.id = pl.product_id AND (p.tenant_id IS NULL OR p.tenant_id = ` + tenant + `)
			LEFT JOIN plic ON plic.product_id = pl.product_id
			LEFT JOIN pf ON pf.product_id = pl.product_id
			WHERE p.purl_type IS NOT NULL` + prod.String() + `
		)`
}

func packageOrder(sortKey string) string {
	desc := strings.HasPrefix(sortKey, "-")
	key := strings.TrimPrefix(sortKey, "-")
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	switch key {
	case "name":
		return "lower(name) " + dir + ", id"
	case "assets":
		return "assets " + dir + ", lower(name), id"
	case "versions":
		return "versions " + dir + ", lower(name), id"
	case "vulns":
		return "(critical * 1000000 + high * 10000 + medium * 100 + low) " + dir + ", lower(name), id"
	case "last_seen":
		return "last_seen_at " + dir + ", id"
	default: // risk, the default view: the most urgent first
		if key == "risk" && !desc {
			return "risk ASC, lower(name), id"
		}
		return "risk DESC, (critical * 1000000 + high * 10000 + medium * 100 + low) DESC, assets DESC, lower(name), id"
	}
}

// ListPackages returns one page of packages.
func (r *ComponentRepository) ListPackages(ctx context.Context, f component.Filter, page pagination.Pagination) (pagination.Result[component.Package], error) {
	empty := pagination.NewResult([]component.Package{}, 0, page)
	args := &sqlArgs{}
	cte := packagesCTE(f, args)
	var total int64
	if err := r.db.QueryRowContext(ctx, cte+` SELECT count(*) FROM pkgs`, args.vals...).Scan(&total); err != nil {
		return empty, fmt.Errorf("count packages: %w", err)
	}
	if total == 0 {
		return empty, nil
	}
	limit, offset := args.add(page.Limit()), args.add(page.Offset())
	rows, err := r.db.QueryContext(ctx, cte+`
		SELECT id, name, namespace, purl_type, purl_name, versions, assets, direct_links, transitive_links,
		       critical, high, medium, low, kev, fix, licenses, risk, first_seen_at, last_seen_at
		FROM pkgs ORDER BY `+packageOrder(f.Sort)+` LIMIT `+limit+` OFFSET `+offset, args.vals...)
	if err != nil {
		return empty, fmt.Errorf("list packages: %w", err)
	}
	defer rows.Close()
	out := make([]component.Package, 0, page.Limit())
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return empty, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list packages: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

func scanPackage(row rowScanner) (component.Package, error) {
	var p component.Package
	var purlName string
	var lic pq.StringArray
	if err := row.Scan(&p.ID, &p.Name, &p.Namespace, &p.PURLType, &purlName, &p.VersionsInUse, &p.Assets,
		&p.DirectLinks, &p.TransitiveLinks, &p.Vulnerabilities.Critical, &p.Vulnerabilities.High,
		&p.Vulnerabilities.Medium, &p.Vulnerabilities.Low, &p.KEV, &p.FixAvailable, &lic, &p.RiskScore,
		&p.FirstSeenAt, &p.LastSeenAt); err != nil {
		return p, fmt.Errorf("scan package: %w", err)
	}
	p.Licenses = []string(lic)
	if p.Licenses == nil {
		p.Licenses = []string{}
	}
	p.Ecosystem = software.EcosystemForType(p.PURLType)
	p.PURL = software.PURL{Type: p.PURLType, Namespace: p.Namespace, Name: purlName}.Base()
	return p, nil
}

// PackageFacets returns the facet values of the filtered package set.
func (r *ComponentRepository) PackageFacets(ctx context.Context, f component.Filter) (component.Facets, error) {
	out := component.Facets{}
	queries := map[string]string{
		"ecosystem": `SELECT purl_type, count(*) FROM pkgs GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 50`,
		"license":   `SELECT lic, count(*) FROM pkgs, unnest(licenses) AS lic GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 30`,
		"severity": `SELECT s, n FROM (SELECT 'critical' AS s, count(*) FILTER (WHERE critical > 0) AS n FROM pkgs
			UNION ALL SELECT 'high', count(*) FILTER (WHERE high > 0) FROM pkgs
			UNION ALL SELECT 'medium', count(*) FILTER (WHERE medium > 0) FROM pkgs
			UNION ALL SELECT 'low', count(*) FILTER (WHERE low > 0) FROM pkgs) x WHERE n > 0`,
		"kev":          `SELECT 'true', count(*) FROM pkgs WHERE kev > 0 HAVING count(*) > 0`,
		"has_fix":      `SELECT 'true', count(*) FROM pkgs WHERE fix HAVING count(*) > 0`,
		"relationship": `SELECT l.relationship, count(DISTINCT l.product_id) FROM links l JOIN pkgs ON pkgs.id = l.product_id GROUP BY 1 ORDER BY 2 DESC`,
		"scope":        `SELECT COALESCE(l.dep_scope, 'runtime'), count(DISTINCT l.product_id) FROM links l JOIN pkgs ON pkgs.id = l.product_id GROUP BY 1 ORDER BY 2 DESC`,
	}
	keys := make([]string, 0, len(queries))
	for k := range queries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals, err := r.facet(ctx, f, queries[k])
		if err != nil {
			return nil, fmt.Errorf("facet %s: %w", k, err)
		}
		if k == "ecosystem" {
			for i := range vals {
				vals[i].Value = software.EcosystemForType(vals[i].Value)
			}
		}
		out[k] = vals
	}
	return out, nil
}

func (r *ComponentRepository) facet(ctx context.Context, f component.Filter, query string) ([]component.FacetValue, error) {
	args := &sqlArgs{}
	cte := packagesCTE(f, args)
	rows, err := r.db.QueryContext(ctx, cte+" "+query, args.vals...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	vals := []component.FacetValue{}
	for rows.Next() {
		var v component.FacetValue
		if err := rows.Scan(&v.Value, &v.Count); err != nil {
			return nil, err
		}
		vals = append(vals, v)
	}
	return vals, rows.Err()
}

// queryIDs runs a query returning one text column.
func (r *ComponentRepository) queryIDs(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Summary returns the KPI strip for the filter.
func (r *ComponentRepository) Summary(ctx context.Context, f component.Filter) (component.Summary, error) {
	var s component.Summary
	args := &sqlArgs{}
	cte := packagesCTE(f, args)
	err := r.db.QueryRowContext(ctx, cte+`
		SELECT count(*),
		       (SELECT count(DISTINCT l.version_id) FROM links l JOIN pkgs ON pkgs.id = l.product_id),
		       (SELECT count(DISTINCT l.asset_id) FROM links l JOIN pkgs ON pkgs.id = l.product_id),
		       count(*) FILTER (WHERE critical + high + medium + low > 0),
		       count(*) FILTER (WHERE kev > 0),
		       count(*) FILTER (WHERE fix)
		FROM pkgs`, args.vals...).Scan(&s.Packages, &s.Versions, &s.Assets, &s.VulnerablePackages, &s.KEVPackages, &s.FixablePackages)
	if err != nil {
		return s, fmt.Errorf("component summary: %w", err)
	}
	return s, nil
}

// GetPackage returns a package visible through an in-scope link.
func (r *ComponentRepository) GetPackage(ctx context.Context, tenantID, productID shared.ID, scope *shared.DataScope) (*component.PackageDetail, error) {
	args := &sqlArgs{}
	cte := packagesCTE(component.Filter{TenantID: tenantID, Scope: scope}, args)
	id := args.add(productID.String())
	row := r.db.QueryRowContext(ctx, cte+`
		SELECT pkgs.id, pkgs.name, pkgs.namespace, pkgs.purl_type, pkgs.purl_name, versions, assets, direct_links,
		       transitive_links, critical, high, medium, low, kev, fix, licenses, risk, first_seen_at, last_seen_at,
		       p.tenant_id IS NULL, COALESCE(p.description, ''), COALESCE(p.homepage, '')
		FROM pkgs JOIN software_products p ON p.id = pkgs.id
		WHERE pkgs.id = `+id, args.vals...)
	var d component.PackageDetail
	var purlName string
	var lic pq.StringArray
	err := row.Scan(&d.ID, &d.Name, &d.Namespace, &d.PURLType, &purlName, &d.VersionsInUse, &d.Assets,
		&d.DirectLinks, &d.TransitiveLinks, &d.Vulnerabilities.Critical, &d.Vulnerabilities.High,
		&d.Vulnerabilities.Medium, &d.Vulnerabilities.Low, &d.KEV, &d.FixAvailable, &lic, &d.RiskScore,
		&d.FirstSeenAt, &d.LastSeenAt, &d.Global, &d.Description, &d.Homepage)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, component.ErrComponentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get package: %w", err)
	}
	d.Licenses = []string(lic)
	if d.Licenses == nil {
		d.Licenses = []string{}
	}
	d.Ecosystem = software.EcosystemForType(d.PURLType)
	d.PURL = software.PURL{Type: d.PURLType, Namespace: d.Namespace, Name: purlName}.Base()
	return &d, nil
}

// ListVersions lists the in-scope versions of a package, newest-seen first.
func (r *ComponentRepository) ListVersions(ctx context.Context, tenantID, productID shared.ID, scope *shared.DataScope) ([]component.Version, error) {
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	product := args.add(productID.String())
	scoped := args.scope("s.asset_id", scope)
	rows, err := r.db.QueryContext(ctx, `
		WITH links AS (
			SELECT s.asset_id, s.software_version_id AS version_id, s.licenses, s.first_seen_at, s.last_seen_at
			FROM asset_software s
			JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id AND a.deleted_at IS NULL
			WHERE s.tenant_id = `+tenant+` AND s.product_id = `+product+` AND s.source = 'package'
			  AND s.superseded_at IS NULL`+scoped+`
		), vf AS (
			SELECT f.component_id AS version_id, f.severity, `+pkgKEVExpr+` AS kev,
			       COALESCE(v.fixed_versions, '{}'::text[]) AS fixed
			FROM findings f
			LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
			WHERE f.tenant_id = `+tenant+` AND f.status NOT IN `+closedStatusesSQL+`
			  AND EXISTS (SELECT 1 FROM links l WHERE l.asset_id = f.asset_id AND l.version_id = f.component_id)
		)
		SELECT sv.id, sv.raw, COALESCE(sv.purl, ''), count(DISTINCT l.asset_id),
		       (SELECT count(*) FROM vf WHERE vf.version_id = sv.id AND severity = 'critical'),
		       (SELECT count(*) FROM vf WHERE vf.version_id = sv.id AND severity = 'high'),
		       (SELECT count(*) FROM vf WHERE vf.version_id = sv.id AND severity = 'medium'),
		       (SELECT count(*) FROM vf WHERE vf.version_id = sv.id AND severity = 'low'),
		       (SELECT count(*) FROM vf WHERE vf.version_id = sv.id AND kev),
		       COALESCE((SELECT array_agg(DISTINCT fv) FROM vf, unnest(vf.fixed) AS fv WHERE vf.version_id = sv.id), '{}'::text[]),
		       COALESCE((SELECT array_agg(DISTINCT lic ORDER BY lic) FROM links l2, unnest(l2.licenses) AS lic WHERE l2.version_id = sv.id), '{}'::text[]),
		       min(l.first_seen_at), max(l.last_seen_at)
		FROM links l
		JOIN software_versions sv ON sv.id = l.version_id
		GROUP BY sv.id, sv.raw, sv.purl
		ORDER BY max(l.last_seen_at) DESC, sv.raw DESC
		LIMIT 500`, args.vals...)
	if err != nil {
		return nil, fmt.Errorf("list package versions: %w", err)
	}
	defer rows.Close()
	out := []component.Version{}
	for rows.Next() {
		var v component.Version
		var fixed, lic pq.StringArray
		if err := rows.Scan(&v.ID, &v.Version, &v.PURL, &v.Assets, &v.Vulnerabilities.Critical,
			&v.Vulnerabilities.High, &v.Vulnerabilities.Medium, &v.Vulnerabilities.Low, &v.KEV, &fixed, &lic,
			&v.FirstSeenAt, &v.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan package version: %w", err)
		}
		v.FixedVersions = component.SortVersions([]string(fixed))
		v.Licenses = nonNilStrings([]string(lic))
		v.Upgrade = component.AdviseUpgrade(v.Version, v.FixedVersions, v.Vulnerabilities.Total() > 0)
		out = append(out, v)
	}
	return out, rows.Err()
}

const usageSelect = `
	SELECT s.id, a.id, a.name, a.asset_type, COALESCE(a.criticality, ''), p.id, p.name, p.purl_type,
	       sv.id, sv.raw, COALESCE(sv.purl, ''), COALESCE(s.relationship, 'unknown'), COALESCE(s.dep_scope, ''),
	       s.location, s.depth, COALESCE(s.channel, ''), s.licenses,
	       (SELECT count(*) FROM findings f WHERE f.tenant_id = s.tenant_id AND f.asset_id = s.asset_id
	          AND f.component_id = s.software_version_id AND f.status NOT IN ` + closedStatusesSQL + `),
	       s.first_seen_at, s.last_seen_at
	FROM asset_software s
	JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id AND a.deleted_at IS NULL
	JOIN software_products p ON p.id = s.product_id
	JOIN software_versions sv ON sv.id = s.software_version_id`

func scanUsage(row rowScanner) (component.Usage, error) {
	var u component.Usage
	var depth sql.NullInt64
	var lic pq.StringArray
	var ptype string
	if err := row.Scan(&u.LinkID, &u.AssetID, &u.AssetName, &u.AssetType, &u.Criticality, &u.ProductID, &u.Name,
		&ptype, &u.VersionID, &u.Version, &u.PURL, &u.Relationship, &u.Scope, &u.Location, &depth, &u.Channel,
		&lic, &u.OpenFindings, &u.FirstSeenAt, &u.LastSeenAt); err != nil {
		return u, fmt.Errorf("scan package usage: %w", err)
	}
	u.Ecosystem = software.EcosystemForType(ptype)
	if depth.Valid {
		d := int(depth.Int64)
		u.Depth = &d
	}
	u.Licenses = nonNilStrings([]string(lic))
	return u, nil
}

func (r *ComponentRepository) listUsages(ctx context.Context, where string, args *sqlArgs, page pagination.Pagination,
	order string) (pagination.Result[component.Usage], error) {
	empty := pagination.NewResult([]component.Usage{}, 0, page)
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_software s
		JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id AND a.deleted_at IS NULL
		JOIN software_versions sv ON sv.id = s.software_version_id `+where, args.vals...).Scan(&total); err != nil {
		return empty, fmt.Errorf("count package usages: %w", err)
	}
	if total == 0 {
		return empty, nil
	}
	limit, offset := args.add(page.Limit()), args.add(page.Offset())
	rows, err := r.db.QueryContext(ctx, usageSelect+" "+where+" ORDER BY "+order+" LIMIT "+limit+" OFFSET "+offset, args.vals...)
	if err != nil {
		return empty, fmt.Errorf("list package usages: %w", err)
	}
	defer rows.Close()
	out := make([]component.Usage, 0, page.Limit())
	for rows.Next() {
		u, err := scanUsage(rows)
		if err != nil {
			return empty, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list package usages: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// ListUsages lists where a package is used, in scope.
func (r *ComponentRepository) ListUsages(ctx context.Context, tenantID, productID shared.ID, f component.UsageFilter,
	scope *shared.DataScope, page pagination.Pagination) (pagination.Result[component.Usage], error) {
	args := &sqlArgs{}
	where := "WHERE s.tenant_id = " + args.add(tenantID.String()) + " AND s.product_id = " + args.add(productID.String()) +
		" AND s.source = 'package' AND s.superseded_at IS NULL" + args.scope("s.asset_id", scope)
	if f.VersionID != nil {
		where += " AND s.software_version_id = " + args.add(f.VersionID.String())
	}
	if len(f.Relationship) > 0 {
		where += " AND s.relationship = ANY(" + args.add(pq.Array(f.Relationship)) + ")"
	}
	if len(f.Scopes) > 0 {
		where += " AND COALESCE(s.dep_scope, 'runtime') = ANY(" + args.add(pq.Array(f.Scopes)) + ")"
	}
	order := `CASE a.criticality WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
		a.name, sv.raw, s.location`
	return r.listUsages(ctx, where, args, page, order)
}

// ListAssetPackages lists one asset's package links.
func (r *ComponentRepository) ListAssetPackages(ctx context.Context, tenantID, assetID shared.ID, page pagination.Pagination) (pagination.Result[component.Usage], error) {
	args := &sqlArgs{}
	where := "WHERE s.tenant_id = " + args.add(tenantID.String()) + " AND s.asset_id = " + args.add(assetID.String()) +
		" AND s.source = 'package' AND s.superseded_at IS NULL"
	return r.listUsages(ctx, where, args, page, "COALESCE(s.depth, 99), lower(sv.purl), s.location")
}

// ListVulnerabilities lists the vulnerabilities of a package's in-scope
// findings, grouped across versions.
func (r *ComponentRepository) ListVulnerabilities(ctx context.Context, tenantID, productID shared.ID, includeResolved bool,
	scope *shared.DataScope, page pagination.Pagination) (pagination.Result[component.Vulnerability], error) {
	empty := pagination.NewResult([]component.Vulnerability{}, 0, page)
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	product := args.add(productID.String())
	where := `WHERE f.tenant_id = ` + tenant + ` AND sv.product_id = ` + product + ` AND f.vulnerability_id IS NOT NULL` +
		args.scope("f.asset_id", scope)
	if !includeResolved {
		where += ` AND f.status NOT IN ` + closedStatusesSQL
	}
	from := ` FROM findings f JOIN software_versions sv ON sv.id = f.component_id
		JOIN assets a ON a.id = f.asset_id AND a.deleted_at IS NULL `
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(DISTINCT f.vulnerability_id)`+from+where, args.vals...).Scan(&total); err != nil {
		return empty, fmt.Errorf("count package vulnerabilities: %w", err)
	}
	if total == 0 {
		return empty, nil
	}
	limit, offset := args.add(page.Limit()), args.add(page.Offset())
	rows, err := r.db.QueryContext(ctx, `
		WITH agg AS (
			SELECT f.vulnerability_id,
			       count(DISTINCT f.asset_id) AS assets, count(*) AS total,
			       count(*) FILTER (WHERE f.status NOT IN `+closedStatusesSQL+`) AS open,
			       array_agg(DISTINCT sv.raw) AS versions,
			       min(f.first_detected_at) AS first_detected_at, max(f.last_seen_at) AS last_seen_at,
			       bool_or(COALESCE(f.is_in_kev, false)) AS kev, max(f.epss_score) AS epss, max(f.cvss_score) AS cvss,
			       min(CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END) AS sev_rank,
			       (array_agg(f.vex_status ORDER BY f.vex_at DESC NULLS LAST) FILTER (WHERE f.vex_status IS NOT NULL))[1] AS vex
			`+from+where+`
			GROUP BY f.vulnerability_id
		)
		SELECT v.id, COALESCE(v.cve_id, ''), COALESCE(v.title, ''),
		       (ARRAY['critical','high','medium','low','info']::text[])[agg.sev_rank],
		       COALESCE(agg.cvss, v.cvss_score), COALESCE(agg.epss, v.epss_score),
		       (agg.kev OR v.cisa_kev_date_added IS NOT NULL), COALESCE(v.fixed_versions, '{}'::text[]),
		       agg.versions, agg.assets, agg.open, agg.total, COALESCE(agg.vex, ''), agg.first_detected_at, agg.last_seen_at
		FROM agg JOIN vulnerabilities v ON v.id = agg.vulnerability_id
		ORDER BY agg.sev_rank, (agg.kev OR v.cisa_kev_date_added IS NOT NULL) DESC, COALESCE(agg.cvss, v.cvss_score, 0) DESC, agg.assets DESC
		LIMIT `+limit+` OFFSET `+offset, args.vals...)
	if err != nil {
		return empty, fmt.Errorf("list package vulnerabilities: %w", err)
	}
	defer rows.Close()
	out := make([]component.Vulnerability, 0, page.Limit())
	for rows.Next() {
		var v component.Vulnerability
		var cvss, epss sql.NullFloat64
		var fixed, affected pq.StringArray
		if err := rows.Scan(&v.VulnerabilityID, &v.CVEID, &v.Title, &v.Severity, &cvss, &epss, &v.InCISAKEV,
			&fixed, &affected, &v.AffectedAssetsCount, &v.OpenFindingCount, &v.TotalFindingCount, &v.VEXStatus,
			&v.FirstDetectedAt, &v.LastSeenAt); err != nil {
			return empty, fmt.Errorf("scan package vulnerability: %w", err)
		}
		if cvss.Valid {
			v.CVSSScore = &cvss.Float64
		}
		if epss.Valid {
			v.EPSSScore = &epss.Float64
		}
		v.FixedVersions = component.SortVersions([]string(fixed))
		v.AffectedVersions = component.SortVersions([]string(affected))
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list package vulnerabilities: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// graphNodeSelect reads graph nodes for a set of link ids ($3).
const graphNodeSelect = `
	SELECT s.id, p.id, sv.id, p.name, sv.raw, COALESCE(sv.purl, ''), p.purl_type, COALESCE(s.relationship, 'unknown'),
	       COALESCE(s.dep_scope, ''), s.location, s.depth,
	       count(f.id) FILTER (WHERE f.severity = 'critical'), count(f.id) FILTER (WHERE f.severity = 'high'),
	       count(f.id) FILTER (WHERE f.severity = 'medium'), count(f.id) FILTER (WHERE f.severity = 'low'),
	       COALESCE(bool_or(COALESCE(f.is_in_kev, false)), false)
	FROM asset_software s
	JOIN software_products p ON p.id = s.product_id
	JOIN software_versions sv ON sv.id = s.software_version_id
	LEFT JOIN findings f ON f.tenant_id = s.tenant_id AND f.asset_id = s.asset_id
	     AND f.component_id = s.software_version_id AND f.status NOT IN ` + closedStatusesSQL + `
	WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.id = ANY($3::uuid[])
	GROUP BY s.id, p.id, sv.id`

func (r *ComponentRepository) loadGraphNodes(ctx context.Context, tenantID, assetID shared.ID, ids []string) (map[string]component.GraphNode, error) {
	out := make(map[string]component.GraphNode, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, graphNodeSelect, tenantID.String(), assetID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("load graph nodes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var n component.GraphNode
		var depth sql.NullInt64
		var ptype string
		if err := rows.Scan(&n.ID, &n.ProductID, &n.VersionID, &n.Name, &n.Version, &n.PURL, &ptype, &n.Relationship,
			&n.Scope, &n.Location, &depth, &n.Vulnerabilities.Critical, &n.Vulnerabilities.High,
			&n.Vulnerabilities.Medium, &n.Vulnerabilities.Low, &n.KEV); err != nil {
			return nil, fmt.Errorf("scan graph node: %w", err)
		}
		n.Ecosystem = software.EcosystemForType(ptype)
		if depth.Valid {
			d := int(depth.Int64)
			n.Depth = &d
		}
		out[n.ID] = n
	}
	return out, rows.Err()
}

// assetEdges loads the asset's whole edge list (bounded by the snapshot
// limits) as parent -> children and child -> parents maps.
func (r *ComponentRepository) assetEdges(ctx context.Context, tenantID, assetID shared.ID) (map[string][]string, map[string][]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT parent_id, child_id FROM asset_software_edges
		WHERE tenant_id = $1 AND asset_id = $2 LIMIT $3`, tenantID.String(), assetID.String(), software.MaxSnapshotEdges)
	if err != nil {
		return nil, nil, fmt.Errorf("load dependency edges: %w", err)
	}
	defer rows.Close()
	down, up := map[string][]string{}, map[string][]string{}
	for rows.Next() {
		var p, c string
		if err := rows.Scan(&p, &c); err != nil {
			return nil, nil, fmt.Errorf("scan dependency edge: %w", err)
		}
		down[p] = append(down[p], c)
		up[c] = append(up[c], p)
	}
	return down, up, rows.Err()
}

// DependencyPaths returns up to limit shortest paths from a root link to a
// link of the version on the asset.
func (r *ComponentRepository) DependencyPaths(ctx context.Context, tenantID, assetID, versionID shared.ID, limit int) ([]component.Path, error) {
	if limit <= 0 || limit > component.MaxPaths {
		limit = component.MaxPaths
	}
	targets, err := r.queryIDs(ctx, `SELECT id FROM asset_software
		WHERE tenant_id = $1 AND asset_id = $2 AND software_version_id = $3 AND source = 'package'`,
		tenantID.String(), assetID.String(), versionID.String())
	if err != nil {
		return nil, fmt.Errorf("dependency targets: %w", err)
	}
	if len(targets) == 0 {
		return nil, component.ErrComponentNotFound
	}
	_, up, err := r.assetEdges(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	idPaths := component.ShortestPaths(targets, up, component.MaxGraphDepth, limit)
	need := map[string]bool{}
	for _, p := range idPaths {
		for _, id := range p {
			need[id] = true
		}
	}
	ids := make([]string, 0, len(need))
	for id := range need {
		ids = append(ids, id)
	}
	nodes, err := r.loadGraphNodes(ctx, tenantID, assetID, ids)
	if err != nil {
		return nil, err
	}
	out := make([]component.Path, 0, len(idPaths))
	for _, p := range idPaths {
		path := make(component.Path, 0, len(p))
		for _, id := range p {
			if n, ok := nodes[id]; ok {
				path = append(path, n)
			}
		}
		out = append(out, path)
	}
	return out, nil
}

// DependencyGraph returns a bounded part of the asset's graph: around the
// focus version's links when given, else from the roots.
func (r *ComponentRepository) DependencyGraph(ctx context.Context, tenantID, assetID shared.ID, focus *shared.ID, depth, limit int) (*component.Graph, error) {
	if depth <= 0 || depth > component.MaxGraphDepth {
		depth = component.MaxGraphDepth
	}
	if limit <= 0 || limit > component.MaxGraphNodes {
		limit = component.MaxGraphNodes
	}
	args := []any{tenantID.String(), assetID.String()}
	q := `SELECT id FROM asset_software
		WHERE tenant_id = $1 AND asset_id = $2 AND source = 'package' AND superseded_at IS NULL`
	if focus != nil {
		q += ` AND software_version_id = $3`
		args = append(args, focus.String())
	}
	all, err := r.queryIDs(ctx, q+` LIMIT 100000`, args...)
	if err != nil {
		return nil, fmt.Errorf("dependency graph: %w", err)
	}
	roots, err := r.queryIDs(ctx, `SELECT id FROM asset_software
		WHERE tenant_id = $1 AND asset_id = $2 AND source = 'package' AND superseded_at IS NULL
		  AND (relationship = 'direct' OR depth = 0) LIMIT 100000`, tenantID.String(), assetID.String())
	if err != nil {
		return nil, fmt.Errorf("dependency graph: %w", err)
	}
	down, up, err := r.assetEdges(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	var ids []string
	var edges []component.GraphEdge
	var truncated bool
	if focus != nil {
		if len(all) == 0 {
			return nil, component.ErrComponentNotFound
		}
		ids, edges, truncated = component.Neighborhood(all, down, up, depth, limit)
	} else {
		if len(roots) == 0 {
			for _, id := range all {
				if len(up[id]) == 0 {
					roots = append(roots, id)
				}
			}
		}
		ids, edges, truncated = component.Descend(roots, down, depth, limit)
	}
	nodes, err := r.loadGraphNodes(ctx, tenantID, assetID, ids)
	if err != nil {
		return nil, err
	}
	g := &component.Graph{Nodes: make([]component.GraphNode, 0, len(ids)), Edges: edges, Truncated: truncated}
	for _, id := range ids {
		if n, ok := nodes[id]; ok {
			g.Nodes = append(g.Nodes, n)
		}
	}
	if g.Edges == nil {
		g.Edges = []component.GraphEdge{}
	}
	return g, nil
}

// ListSBOMEntries returns the packages for an SBOM export: one asset's, or
// every in-scope asset's when assetID is nil; at most limit entries.
func (r *ComponentRepository) ListSBOMEntries(ctx context.Context, tenantID shared.ID, assetID *shared.ID,
	scope *shared.DataScope, limit int) ([]component.SBOMEntry, error) {
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	where := "WHERE s.tenant_id = " + tenant + " AND s.source = 'package' AND s.superseded_at IS NULL" + args.scope("s.asset_id", scope)
	if assetID != nil {
		where += " AND s.asset_id = " + args.add(assetID.String())
	}
	lim := args.add(limit)
	rows, err := r.db.QueryContext(ctx, `
		SELECT sv.id, p.name, sv.raw, p.purl_type, COALESCE(sv.purl, ''),
		       COALESCE(array_agg(DISTINCT lic) FILTER (WHERE lic IS NOT NULL), '{}'::text[]),
		       (SELECT count(DISTINCT f.vulnerability_id) FROM findings f
		         WHERE f.tenant_id = `+tenant+` AND f.component_id = sv.id AND f.status NOT IN `+closedStatusesSQL+`)
		FROM asset_software s
		JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id AND a.deleted_at IS NULL
		JOIN software_products p ON p.id = s.product_id
		JOIN software_versions sv ON sv.id = s.software_version_id
		LEFT JOIN LATERAL unnest(s.licenses) AS lic ON true
		`+where+`
		GROUP BY sv.id, p.name, sv.raw, p.purl_type, sv.purl
		ORDER BY lower(COALESCE(sv.purl, p.name)), sv.raw
		LIMIT `+lim, args.vals...)
	if err != nil {
		return nil, fmt.Errorf("list sbom entries: %w", err)
	}
	defer rows.Close()
	out := []component.SBOMEntry{}
	for rows.Next() {
		var e component.SBOMEntry
		var ptype string
		var lic pq.StringArray
		if err := rows.Scan(&e.ID, &e.Name, &e.Version, &ptype, &e.PURL, &lic, &e.VulnerabilityCount); err != nil {
			return nil, fmt.Errorf("scan sbom entry: %w", err)
		}
		e.Ecosystem = software.EcosystemForType(ptype)
		e.Licenses = nonNilStrings([]string(lic))
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetFindingComponent returns the version a finding names, when it is global
// or the tenant's own, and how assetID uses it.
func (r *ComponentRepository) GetFindingComponent(ctx context.Context, tenantID, versionID shared.ID, assetID *shared.ID) (*component.FindingComponent, error) {
	var c component.FindingComponent
	var ptype string
	err := r.db.QueryRowContext(ctx, `
		SELECT sv.id, p.id, p.name, sv.raw, p.purl_type, COALESCE(sv.purl, '')
		FROM software_versions sv
		JOIN software_products p ON p.id = sv.product_id
		WHERE sv.id = $1 AND (sv.tenant_id IS NULL OR sv.tenant_id = $2) AND p.purl_type IS NOT NULL`,
		versionID.String(), tenantID.String()).Scan(&c.VersionID, &c.ProductID, &c.Name, &c.Version, &ptype, &c.PURL)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, component.ErrComponentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("finding component: %w", err)
	}
	c.Ecosystem = software.EcosystemForType(ptype)
	c.Licenses = []string{}
	if assetID == nil {
		return &c, nil
	}
	var depth sql.NullInt64
	var lic pq.StringArray
	err = r.db.QueryRowContext(ctx, `
		SELECT COALESCE(relationship, 'unknown'), COALESCE(dep_scope, ''), location, depth, licenses
		FROM asset_software
		WHERE tenant_id = $1 AND asset_id = $2 AND software_version_id = $3 AND source = 'package'
		ORDER BY COALESCE(depth, 99), location LIMIT 1`,
		tenantID.String(), assetID.String(), versionID.String()).Scan(&c.Relationship, &c.Scope, &c.Location, &depth, &lic)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("finding component usage: %w", err)
	}
	if depth.Valid {
		d := int(depth.Int64)
		c.Depth = &d
	}
	c.Licenses = nonNilStrings([]string(lic))
	return &c, nil
}
