package postgres

// The vulnerabilities list (docs/architecture/vulnerability-page.md, "The
// list"): the findings of the list's own compiled WHERE, as the caller,
// grouped by CVE. Every count on a row is therefore the findings list
// filtered by that CVE and the same params. Reads of other tables carry the
// tenant (alerts, tasks, assets) and the caller's asset scope (an alert's
// assets), or are public reference data (catalog, KEV, aliases).

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// sortTerm is one ORDER BY expression of the list with its natural
// direction; a flipped sort inverts every term but the CVE tie-breaker.
type sortTerm struct {
	expr string
	desc bool
}

// cveListSortTerms maps a sort key to constant SQL over the rows CTE.
var cveListSortTerms = map[string][]sortTerm{
	vulnerability.CVEListSortRisk: {
		{"r.prio_rank", false}, {"r.kev", true}, {"(r.em_id IS NOT NULL)", true},
		{"r.epss", true}, {"r.cvss", true}, {"r.assets", true},
	},
	vulnerability.CVEListSortCVSS:      {{"r.cvss", true}},
	vulnerability.CVEListSortEPSS:      {{"r.epss", true}},
	vulnerability.CVEListSortAssets:    {{"r.assets", true}},
	vulnerability.CVEListSortFindings:  {{"r.total", true}},
	vulnerability.CVEListSortFirstSeen: {{"r.first_seen", true}},
	vulnerability.CVEListSortLastSeen:  {{"r.last_seen", true}},
	vulnerability.CVEListSortKEVDue:    {{"r.kev_due", false}},
	vulnerability.CVEListSortCVE:       {},
}

// cveListOrderBy builds the ORDER BY list of a sort. Empty values sort last
// in either direction, and the CVE id breaks ties so pages are stable.
func cveListOrderBy(s vulnerability.CVEListSort) (string, error) {
	terms, ok := cveListSortTerms[s.Key]
	if !ok {
		return "", fmt.Errorf("unknown cve list sort %q", s.Key)
	}
	parts := make([]string, 0, len(terms)+1)
	for _, t := range terms {
		desc := t.desc != s.Flipped
		dir := "ASC"
		if desc {
			dir = "DESC"
		}
		parts = append(parts, t.expr+" "+dir+" NULLS LAST")
	}
	cveDir := "ASC"
	if s.Key == vulnerability.CVEListSortCVE && s.Flipped {
		cveDir = "DESC"
	}
	return strings.Join(append(parts, "r.cve_id "+cveDir), ", "), nil
}

// cveListSettings are the transaction settings of the list read: it is one
// grouping statement under the heavy-read limiter, so JIT compilation (whose
// cost dwarfs a sub-second plan: seconds of CPU at 300k findings) is off,
// and work_mem holds the per-CVE and per-asset hash tables in memory.
const cveListSettings = "SET LOCAL jit = off; SET LOCAL work_mem = '64MB'"

// ListCVEExposures returns one page of the vulnerabilities list as the
// caller, with its total and the summary counts.
func (r *FindingRepository) ListCVEExposures(ctx context.Context, q vulnerability.CVEListQuery) (*vulnerability.CVEList, error) {
	query, args, page, err := cveListStatement(q)
	if err != nil {
		return nil, err
	}
	tx, err := r.beginFindingRead(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, cveListSettings); err != nil {
		return nil, fmt.Errorf("cve list settings: %w", err)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, findingTimeout(fmt.Errorf("list cve exposures: %w", err))
	}
	defer rows.Close()
	return r.scanCVEList(ctx, tx, q.Where, rows, page)
}

// cveListStatement builds the list statement: page rows, total and summary
// in one read over the caller's compiled WHERE.
func cveListStatement(q vulnerability.CVEListQuery) (string, []any, pagination.Pagination, error) {
	if err := checkFindingWhere(q.Where); err != nil {
		return "", nil, pagination.Pagination{}, err
	}
	if q.AssetScope == nil {
		return "", nil, pagination.Pagination{}, fmt.Errorf("cve list: no asset scope")
	}
	o := q.Options
	orderBy, err := cveListOrderBy(o.Sort)
	if err != nil {
		return "", nil, pagination.Pagination{}, err
	}
	page := pagination.New(o.Page, o.PerPage)
	w := q.Where

	args := append([]any{}, w.Args...)
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	tenantArg := arg(q.TenantID.String())
	scopeCond, scopeArgs := q.AssetScope("taa.asset_id", len(args)+1)
	args = append(args, scopeArgs...)

	var filters []string
	boolFilter := func(expr string, v *bool) {
		if v == nil {
			return
		}
		if *v {
			filters = append(filters, expr)
		} else {
			filters = append(filters, "NOT "+expr)
		}
	}
	boolFilter("r.kev", o.KEV)
	boolFilter("r.exploit", o.Exploit)
	boolFilter("r.has_fix", o.HasFix)
	boolFilter("(r.em_id IS NOT NULL)", o.Emerging)
	if o.PastSLA {
		filters = append(filters, "r.past_sla > 0")
	}
	if o.EPSSGte != nil {
		filters = append(filters, "COALESCE(r.epss, 0) >= "+arg(*o.EPSSGte))
	}
	if s := strings.TrimSpace(o.Search); s != "" {
		p := arg("%" + filterspec.EscapeLike(s) + "%")
		filters = append(filters, `(r.cve_id ILIKE `+p+` ESCAPE '\' OR r.title ILIKE `+p+` ESCAPE '\'
			OR EXISTS (SELECT 1 FROM vuln_id_aliases al WHERE al.cve_id = r.cve_id AND al.alias_id ILIKE `+p+` ESCAPE '\'))`)
	}
	where := ""
	if len(filters) > 0 {
		where = " WHERE " + strings.Join(filters, " AND ")
	}
	lo := arg(page.Offset())
	hi := arg(page.Offset() + page.Limit())

	open := vulnerability.OpenStatusSQL("s.status")
	pastSLA := "s.sla_status IN ('overdue', 'exceeded')"
	//nolint:gosec // G202: the compiled filter, constants and placeholders only, no request text
	query := cveListScopedCTE(w) + `,
	-- Per CVE: hash aggregation over 20k-scale groups, no distinct counts
	-- (those force a sort of every scoped finding).
	agg0 AS (
		SELECT s.cve_id,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE ` + open + `) AS open_count,
			MIN(CASE s.priority_class WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 END) AS prio_rank,
			MIN(CASE s.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END) AS sev_rank,
			MAX(s.cvss_score) AS f_cvss,
			MAX(s.epss_score) AS f_epss,
			BOOL_OR(` + vulnerability.KEVFindingSQL("s.is_in_kev") + `) AS f_kev,
			-- The open known exploited findings of the CVE: the same
			-- predicate as the findings stats' kev_open (one KEV definition).
			COUNT(*) FILTER (WHERE ` + vulnerability.OpenKEVFindingSQL("s") + `) AS kev_open,
			BOOL_OR(COALESCE(s.exploit_available, FALSE)) AS f_exploit,
			BOOL_OR(s.f_fix) AS f_fix,
			COUNT(*) FILTER (WHERE ` + open + ` AND ` + pastSLA + `) AS past_sla,
			MIN(s.sla_deadline) FILTER (WHERE ` + open + ` AND NOT (` + pastSLA + `)) AS next_due,
			COUNT(*) FILTER (WHERE ` + open + ` AND EXISTS (
				SELECT 1 FROM remediation_task_members m
				WHERE m.tenant_id = s.tenant_id AND m.finding_id = s.id AND m.left_at IS NULL AND m.role = 'primary')) AS in_task,
			MIN(s.first_detected_at) AS first_seen,
			MAX(s.last_seen_at) AS last_seen
		FROM scoped s
		GROUP BY s.cve_id
	),
	-- Per CVE: the distinct assets, from the narrow (CVE, asset) pairs.
	reach AS (
		SELECT p.cve_id,
			COUNT(*) AS assets,
			COUNT(*) FILTER (WHERE ` + asset.InternetFacingSQL("a") + `) AS internet,
			COUNT(*) FILTER (WHERE COALESCE(a.is_crown_jewel, FALSE)) AS crown
		FROM (SELECT DISTINCT s.cve_id, s.asset_id FROM scoped s) p
		LEFT JOIN assets a ON a.tenant_id = ` + tenantArg + ` AND a.id = p.asset_id
		GROUP BY p.cve_id
	),
	agg AS (
		SELECT agg0.*, COALESCE(reach.assets, 0) AS assets, COALESCE(reach.internet, 0) AS internet,
			COALESCE(reach.crown, 0) AS crown
		FROM agg0 LEFT JOIN reach ON reach.cve_id = agg0.cve_id
	),
	vrows AS MATERIALIZED (
		SELECT agg.*,
			(v.id IS NOT NULL) AS in_catalog,
			COALESCE(v.title, '') AS title,
			CASE WHEN v.severity IN ('critical', 'high', 'medium', 'low', 'info') THEN v.severity
				ELSE (ARRAY['critical','high','medium','low','info','unknown']::text[])[agg.sev_rank] END AS severity,
			COALESCE(v.cvss_score, agg.f_cvss) AS cvss,
			COALESCE(v.cvss_version, '') AS cvss_version,
			COALESCE(v.epss_score, agg.f_epss) AS epss,
			v.epss_percentile AS epss_pct,
			-- Known exploited: in the CISA KEV catalog, or a finding of the
			-- CVE carries the flag the catalog keeps (KEVFindingSQL). The
			-- vulnerability catalog's own KEV date is not a third source.
			(k.cve_id IS NOT NULL OR agg.f_kev) AS kev,
			COALESCE(k.due_date::timestamptz, v.cisa_kev_due_date) AS kev_due,
			(LOWER(COALESCE(k.known_ransomware_campaign_use, v.cisa_kev_ransomware_use, '')) = 'known') AS ransomware,
			(COALESCE(v.exploit_available, FALSE) OR agg.f_exploit
				OR COALESCE(v.exploit_maturity, 'none') IN ('poc', 'functional', 'weaponized')) AS exploit,
			COALESCE(v.exploit_maturity, 'none') AS maturity,
			(COALESCE(cardinality(v.fixed_versions), 0) > 0 OR agg.f_fix) AS has_fix,
			COALESCE(v.fixed_versions, '{}'::text[]) AS catalog_fixed,
			al.id AS em_id, al.level AS em_level, al.state AS em_state
		FROM agg
		LEFT JOIN vulnerabilities v ON v.cve_id = agg.cve_id
		LEFT JOIN kev_catalog k ON k.cve_id = agg.cve_id
		LEFT JOIN LATERAL (
			SELECT ta.id::text AS id, ta.level, ta.state FROM threat_alerts ta
			WHERE ta.tenant_id = ` + tenantArg + ` AND ta.vuln_id = agg.cve_id
			  AND ta.state IN ('new', 'acknowledged', 'remediating')
			  AND EXISTS (SELECT 1 FROM threat_alert_assets taa
				WHERE taa.tenant_id = ta.tenant_id AND taa.alert_id = ta.id AND ` + scopeCond + `)
			LIMIT 1
		) al ON TRUE
	),
	ranked AS (
		SELECT r.*, ROW_NUMBER() OVER (ORDER BY ` + orderBy + `) AS rn FROM vrows r` + where + `
	),
	sm AS (
		SELECT COUNT(*) AS total,
			COUNT(*) FILTER (WHERE kev) AS kev,
			COUNT(*) FILTER (WHERE exploit) AS exploit,
			COUNT(*) FILTER (WHERE em_id IS NOT NULL) AS emerging,
			COUNT(*) FILTER (WHERE past_sla > 0) AS past_sla,
			COALESCE(SUM(kev_open), 0) AS kev_open,
			(SELECT COUNT(*) FROM ranked) AS matched
		FROM vrows
	)
	SELECT sm.total, sm.kev, sm.exploit, sm.emerging, sm.past_sla, sm.kev_open, sm.matched,
		p.cve_id, p.in_catalog, p.title, p.severity, p.cvss, p.cvss_version, p.epss, p.epss_pct,
		p.kev, p.kev_due, p.ransomware, p.exploit, p.maturity, p.has_fix, p.catalog_fixed,
		p.em_id, p.em_level, p.em_state,
		COALESCE((ARRAY['P0','P1','P2','P3']::text[])[p.prio_rank + 1], ''),
		p.total, p.open_count, p.kev_open, p.assets, p.internet, p.crown, p.past_sla, p.next_due, p.in_task,
		p.first_seen, p.last_seen
	FROM sm
	LEFT JOIN LATERAL (SELECT * FROM ranked WHERE rn > ` + lo + ` AND rn <= ` + hi + `) p ON TRUE
	ORDER BY p.rn`
	return query, args, page, nil
}

// scanCVEList reads the list statement's rows and fills each row's details.
func (r *FindingRepository) scanCVEList(ctx context.Context, tx *sql.Tx, w *filterspec.Where, rows *sql.Rows, page pagination.Pagination) (*vulnerability.CVEList, error) {
	out := &vulnerability.CVEList{Data: make([]vulnerability.CVEListItem, 0, capHint(page.Limit()))}
	for rows.Next() {
		var (
			cve, title, severity, cvssVersion, maturity, prio  sql.NullString
			emID, emLevel, emState                             sql.NullString
			inCatalog, kev, ransomware, exploit, hasFix        sql.NullBool
			cvss, epss, epssPct                                sql.NullFloat64
			kevDue, nextDue, firstSeen, lastSeen               sql.NullTime
			total, open, assets, internet, crown, past, inTask sql.NullInt64
			kevOpen                                            sql.NullInt64
			catalogFixed                                       pq.StringArray
		)
		if err := rows.Scan(&out.Summary.Total, &out.Summary.KEV, &out.Summary.Exploit, &out.Summary.Emerging,
			&out.Summary.PastSLA, &out.Summary.OpenKEVFindings, &out.Total,
			&cve, &inCatalog, &title, &severity, &cvss, &cvssVersion, &epss, &epssPct,
			&kev, &kevDue, &ransomware, &exploit, &maturity, &hasFix, &catalogFixed,
			&emID, &emLevel, &emState, &prio,
			&total, &open, &kevOpen, &assets, &internet, &crown, &past, &nextDue, &inTask,
			&firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan cve exposure row: %w", err)
		}
		if !cve.Valid {
			// The summary row of a page past the end: no list row rides on it.
			continue
		}
		it := vulnerability.CVEListItem{
			CVEID: cve.String, InCatalog: inCatalog.Bool, Title: title.String, Aliases: []string{}, EPSSTrend: []vulnerability.EPSSPoint{},
			Severity: severity.String, CVSSVersion: cvssVersion.String,
			KEV: kev.Bool, KEVDueDate: coverageTime(kevDue), KEVRansomware: ransomware.Bool,
			Exploit: exploit.Bool, ExploitMaturity: maturity.String,
			WorstPriority: prio.String,
			Findings:      total.Int64, OpenFindings: open.Int64, OpenKEVFindings: kevOpen.Int64,
			Assets: assets.Int64, InternetFacing: internet.Int64, CrownJewels: crown.Int64,
			Products: []vulnerability.CVEListProduct{}, FixedVersions: []string(catalogFixed),
			HasFix: hasFix.Bool, PastSLA: past.Int64, NextSLADue: coverageTime(nextDue), InTask: inTask.Int64,
			FirstSeenAt: coverageTime(firstSeen), LastSeenAt: coverageTime(lastSeen),
		}
		it.CVSSScore = cveListFloat(cvss)
		it.EPSSScore = cveListFloat(epss)
		it.EPSSPercentile = cveListFloat(epssPct)
		if emID.Valid {
			it.Emerging = &vulnerability.CVEListEmerging{ID: emID.String, Level: emLevel.String, State: emState.String}
		}
		out.Data = append(out.Data, it)
	}
	if err := rows.Err(); err != nil {
		return nil, findingTimeout(err)
	}
	rows.Close()

	if err := r.cveListDetails(ctx, tx, w, out.Data); err != nil {
		return nil, findingTimeout(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit cve exposure list: %w", err)
	}
	return out, nil
}

// cveListScopedCTE is the list's scoped findings (the compiled WHERE, as
// the caller), materialized once with only the columns the grouping reads:
// the fix flag is computed here so the wide metadata column is never
// carried through the aggregation.
func cveListScopedCTE(w *filterspec.Where) string {
	return `WITH scoped AS MATERIALIZED (
		SELECT findings.id, findings.tenant_id, findings.asset_id, findings.cve_id, findings.status,
			findings.priority_class, findings.severity, findings.cvss_score, findings.epss_score,
			findings.is_in_kev, findings.exploit_available, findings.sla_status, findings.sla_deadline,
			findings.first_detected_at, findings.last_seen_at,
			(CASE WHEN jsonb_typeof(findings.metadata->'fixed_versions') = 'array'
				THEN jsonb_array_length(findings.metadata->'fixed_versions') > 0 ELSE FALSE END) AS f_fix
		FROM findings WHERE (` + w.SQL + `) AND findings.cve_id IS NOT NULL
	)`
}

func cveListFloat(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

// cveListDetails fills the aliases, EPSS trend, affected products and fixed
// versions of a page's rows: four statements whatever the page size. Products and
// fixes come from the same scoped findings as the counts.
func (r *FindingRepository) cveListDetails(ctx context.Context, tx *sql.Tx, w *filterspec.Where, items []vulnerability.CVEListItem) error {
	if len(items) == 0 {
		return nil
	}
	idx := make(map[string]int, len(items))
	cves := make([]string, 0, len(items))
	for i := range items {
		idx[items[i].CVEID] = i
		cves = append(cves, items[i].CVEID)
	}

	arows, err := tx.QueryContext(ctx, `
		SELECT cve_id, alias_id FROM vuln_id_aliases
		WHERE cve_id = ANY($1::text[]) ORDER BY cve_id, source, alias_id`, pq.Array(cves))
	if err != nil {
		return fmt.Errorf("cve list aliases: %w", err)
	}
	defer arows.Close()
	for arows.Next() {
		var cve, alias string
		if err := arows.Scan(&cve, &alias); err != nil {
			return fmt.Errorf("scan cve list alias: %w", err)
		}
		if it := &items[idx[cve]]; len(it.Aliases) < vulnerability.MaxCVEListAliases {
			it.Aliases = append(it.Aliases, alias)
		}
	}
	if err := arows.Err(); err != nil {
		return err
	}
	arows.Close()

	// The page's rows are CVEs the caller has a finding of in scope, so
	// their EPSS history may be shown.
	trends, err := epssTrends(ctx, tx, cves)
	if err != nil {
		return err
	}
	for cve, pts := range trends {
		items[idx[cve]].EPSSTrend = pts
	}

	cveArg := "$" + strconv.Itoa(w.NextArg)
	args := append(append([]any{}, w.Args...), pq.Array(cves))

	//nolint:gosec // G202: the compiled filter, constants and placeholders only, no request text
	prows, err := tx.QueryContext(ctx, scopedFindingsCTE(w, "findings.cve_id = ANY("+cveArg+"::text[]) AND findings.component_id IS NOT NULL")+`
	SELECT s.cve_id, p.name, sv.raw, COUNT(*)
	FROM scoped s
	JOIN software_versions sv ON sv.id = s.component_id AND (sv.tenant_id IS NULL OR sv.tenant_id = s.tenant_id)
	JOIN software_products p ON p.id = sv.product_id AND (p.tenant_id IS NULL OR p.tenant_id = s.tenant_id)
	GROUP BY s.cve_id, p.name, sv.raw
	ORDER BY s.cve_id, COUNT(*) DESC, p.name, sv.raw`, args...)
	if err != nil {
		return fmt.Errorf("cve list products: %w", err)
	}
	defer prows.Close()
	for prows.Next() {
		var cve, name, version string
		var n int64
		if err := prows.Scan(&cve, &name, &version, &n); err != nil {
			return fmt.Errorf("scan cve list product: %w", err)
		}
		addCVEListProduct(&items[idx[cve]], name, version, n)
	}
	if err := prows.Err(); err != nil {
		return err
	}
	prows.Close()

	//nolint:gosec // G202: the compiled filter, constants and placeholders only, no request text
	frows, err := tx.QueryContext(ctx, scopedFindingsCTE(w, "findings.cve_id = ANY("+cveArg+"::text[])")+`
	SELECT DISTINCT s.cve_id, fv
	FROM scoped s, jsonb_array_elements_text(CASE WHEN jsonb_typeof(s.metadata->'fixed_versions') = 'array'
		THEN s.metadata->'fixed_versions' ELSE '[]'::jsonb END) fv
	WHERE length(fv) BETWEEN 1 AND 64
	ORDER BY 1, 2`, args...)
	if err != nil {
		return fmt.Errorf("cve list fixed versions: %w", err)
	}
	defer frows.Close()
	scanner := map[string][]string{}
	for frows.Next() {
		var cve, fv string
		if err := frows.Scan(&cve, &fv); err != nil {
			return fmt.Errorf("scan cve list fixed version: %w", err)
		}
		scanner[cve] = append(scanner[cve], fv)
	}
	if err := frows.Err(); err != nil {
		return err
	}
	for i := range items {
		it := &items[i]
		fixed := mergeVersions(scanner[it.CVEID], it.FixedVersions)
		if len(fixed) > vulnerability.MaxCVEListFixes {
			fixed = fixed[:vulnerability.MaxCVEListFixes]
		}
		it.FixedVersions = fixed
	}
	return nil
}

// addCVEListProduct adds one installed version of a product to a row, in
// the order the rows arrive (most findings first), within the bounds.
func addCVEListProduct(it *vulnerability.CVEListItem, name, version string, findings int64) {
	for i := range it.Products {
		p := &it.Products[i]
		if p.Name != name {
			continue
		}
		p.Findings += findings
		if version != "" && len(p.Versions) < vulnerability.MaxCVEListFixes {
			p.Versions = append(p.Versions, version)
		}
		return
	}
	if len(it.Products) >= vulnerability.MaxCVEListProducts {
		return
	}
	versions := []string{}
	if version != "" {
		versions = append(versions, version)
	}
	it.Products = append(it.Products, vulnerability.CVEListProduct{Name: name, Versions: versions, Findings: findings})
}
