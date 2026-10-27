package postgres

// The vulnerability page's reads for one CVE (docs/architecture/vulnerability-page.md).
// Every finding count runs over the findings list's own compiled WHERE for
// "cve_id in [CVE]" as the caller (tenant, data scope, member visibility,
// branch default), so the page and the filtered findings list count the same
// rows. Reads of other tables (the software assets run, an alert's assets)
// carry the tenant and the caller's asset scope predicate.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// cweIDPattern keeps feed weakness ids to the "CWE-<n>" shape (the feeds
// also carry "NVD-CWE-Other" and "NVD-CWE-noinfo").
var cweIDPattern = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)

// scopedFindingsCTE is the findings of the compiled filter with the columns
// the exposure reads use. extra is ANDed to the filter.
func scopedFindingsCTE(w *filterspec.Where, extra string) string {
	cond := w.SQL
	if extra != "" {
		cond = "(" + cond + ") AND " + extra
	}
	return `WITH scoped AS (
		SELECT findings.id, findings.tenant_id, findings.asset_id, findings.status, findings.priority_class,
			findings.severity, findings.source, findings.tool_name, findings.component_id, findings.metadata,
			findings.first_detected_at, findings.last_seen_at, findings.resolved_at,
			COALESCE(findings.reopen_count, 0) AS reopen_count, findings.last_reopened_at,
			findings.cve_id, findings.cvss_score, findings.epss_score, findings.is_in_kev, findings.exploit_available,
			findings.sla_status, findings.sla_deadline, findings.network_port, findings.network_transport, findings.file_path
		FROM findings WHERE ` + cond + `
	)`
}

// GetCVEExposure answers the vulnerability page for one CVE as the caller.
// The catalog part (title, scores, KEV) is read by the service; this fills
// the counts, software buckets, components, sources, timeline and the
// public intel beside the catalog.
func (r *FindingRepository) GetCVEExposure(ctx context.Context, q vulnerability.CVEExposureQuery) (*vulnerability.CVEExposure, error) {
	if err := checkFindingWhere(q.Where); err != nil {
		return nil, err
	}
	tx, err := r.beginFindingRead(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	out := &vulnerability.CVEExposure{
		CVEID:      q.CVEID,
		Components: []vulnerability.CVEExposureComponent{},
		Upgrades:   []vulnerability.CVEExposureUpgrade{},
		Sources:    []vulnerability.CVEExposureSource{},
		Possible:   vulnerability.CVEExposureSoftware{Products: []string{}},
		NotAffected: vulnerability.CVEExposureSoftware{
			Products: []string{},
		},
		Intel: vulnerability.CVEExposureIntel{
			Aliases: []vulnerability.CVEAlias{}, CWEs: []string{}, Feeds: []vulnerability.FeedFreshness{},
		},
	}
	if err := r.cveExposureCounts(ctx, tx, q.Where, out); err != nil {
		return nil, findingTimeout(err)
	}
	if err := r.cveExposureStatuses(ctx, tx, q.Where, out); err != nil {
		return nil, findingTimeout(err)
	}
	productAssets, err := r.cveExposureComponents(ctx, tx, q.Where, out)
	if err != nil {
		return nil, findingTimeout(err)
	}
	if err := r.cveExposureSources(ctx, tx, q.Where, out); err != nil {
		return nil, findingTimeout(err)
	}
	matched, err := r.cveExposureSoftware(ctx, tx, q, out)
	if err != nil {
		return nil, findingTimeout(err)
	}
	if err := r.cveExposureIntel(ctx, tx, q, out); err != nil {
		return nil, findingTimeout(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit cve exposure read: %w", err)
	}

	// The fix each installed version needs: the finding's own fixed
	// versions (the scanner's, for this package) and the catalog's.
	for i := range out.Components {
		c := &out.Components[i]
		c.FixedVersions = mergeVersions(c.FixedVersions, q.CatalogFixed)
		c.RecommendedFix = vulnerability.RecommendedFixVersion(c.Version, c.FixedVersions)
	}
	out.Upgrades = vulnerability.UpgradePlan(out.Components, productAssets)
	out.Findings.WorstPriority = vulnerability.WorstPriorityClass(out.Findings.ByPriority)
	out.Findings.NotInTask = out.Findings.Active - out.Findings.InTask
	closed := out.Findings.Total - out.Findings.Active
	out.Verdict = vulnerability.ExposureVerdict(out.Findings.Active, matched,
		out.Possible.Assets, out.NotAffected.Assets, closed)
	return out, nil
}

func (r *FindingRepository) cveExposureCounts(ctx context.Context, tx *sql.Tx, w *filterspec.Where, out *vulnerability.CVEExposure) error {
	open := vulnerability.OpenStatusSQL("s.status")
	fixed := vulnerability.FixedStatusSQL("s.status")
	q := scopedFindingsCTE(w, "") + `
	SELECT
		COUNT(*),
		COUNT(*) FILTER (WHERE ` + open + `),
		COUNT(*) FILTER (WHERE ` + open + ` AND s.priority_class = 'P0'),
		COUNT(*) FILTER (WHERE ` + open + ` AND s.priority_class = 'P1'),
		COUNT(*) FILTER (WHERE ` + open + ` AND s.priority_class = 'P2'),
		COUNT(*) FILTER (WHERE ` + open + ` AND s.priority_class = 'P3'),
		COUNT(*) FILTER (WHERE ` + open + ` AND s.priority_class IS NULL),
		COUNT(*) FILTER (WHERE ` + open + ` AND EXISTS (
			SELECT 1 FROM remediation_task_members m
			WHERE m.tenant_id = s.tenant_id AND m.finding_id = s.id AND m.left_at IS NULL AND m.role = 'primary')),
		COUNT(DISTINCT s.asset_id) FILTER (WHERE ` + open + `),
		COUNT(DISTINCT s.asset_id) FILTER (WHERE ` + open + ` AND COALESCE(a.is_crown_jewel, FALSE)),
		COUNT(DISTINCT s.asset_id) FILTER (WHERE ` + open + ` AND ` + asset.InternetFacingSQL("a") + `),
		COUNT(DISTINCT s.asset_id),
		MIN(s.first_detected_at),
		MAX(s.last_seen_at),
		MAX(s.resolved_at) FILTER (WHERE ` + fixed + `),
		COUNT(*) FILTER (WHERE ` + fixed + `),
		COUNT(*) FILTER (WHERE s.reopen_count > 0),
		MAX(s.last_reopened_at)
	FROM scoped s
	LEFT JOIN assets a ON a.tenant_id = s.tenant_id AND a.id = s.asset_id`
	var p0, p1, p2, p3, none int64
	var first, last, lastFixed, lastReopened sql.NullTime
	f, as, tl := &out.Findings, &out.Assets, &out.Timeline
	if err := tx.QueryRowContext(ctx, q, w.Args...).Scan(
		&f.Total, &f.Active, &p0, &p1, &p2, &p3, &none, &f.InTask,
		&as.Impacted, &as.CrownJewels, &as.InternetFacing, &as.WithFindings,
		&first, &last, &lastFixed, &tl.Fixed, &tl.Reopened, &lastReopened,
	); err != nil {
		return fmt.Errorf("cve exposure counts: %w", err)
	}
	f.ByPriority = map[string]int64{"P0": p0, "P1": p1, "P2": p2, "P3": p3, "none": none}
	tl.FirstSeenAt, tl.LastSeenAt = coverageTime(first), coverageTime(last)
	tl.LastFixedAt, tl.LastReopenedAt = coverageTime(lastFixed), coverageTime(lastReopened)
	return nil
}

func (r *FindingRepository) cveExposureStatuses(ctx context.Context, tx *sql.Tx, w *filterspec.Where, out *vulnerability.CVEExposure) error {
	rows, err := tx.QueryContext(ctx, scopedFindingsCTE(w, "")+` SELECT s.status, COUNT(*) FROM scoped s GROUP BY s.status`, w.Args...)
	if err != nil {
		return fmt.Errorf("cve exposure statuses: %w", err)
	}
	defer rows.Close()
	out.Findings.ByStatus = map[string]int64{}
	for rows.Next() {
		var st string
		var n int64
		if err := rows.Scan(&st, &n); err != nil {
			return fmt.Errorf("scan cve exposure status: %w", err)
		}
		out.Findings.ByStatus[st] = n
	}
	return rows.Err()
}

// cveExposureComponents lists the installed package versions the active
// findings name, and per product the assets with an active finding.
func (r *FindingRepository) cveExposureComponents(ctx context.Context, tx *sql.Tx, w *filterspec.Where, out *vulnerability.CVEExposure) (map[string]int64, error) {
	open := vulnerability.OpenStatusSQL("s.status")
	//nolint:gosec // G202: the compiled filter, constants and placeholders only, no request text
	q := scopedFindingsCTE(w, "findings.component_id IS NOT NULL") + `
	SELECT sv.product_id, p.name, COALESCE(sv.purl, ''), sv.raw,
		COUNT(DISTINCT s.asset_id) FILTER (WHERE ` + open + `),
		COUNT(*) FILTER (WHERE ` + open + `),
		COALESCE(ARRAY(
			SELECT DISTINCT fv FROM scoped s2,
				jsonb_array_elements_text(CASE WHEN jsonb_typeof(s2.metadata->'fixed_versions') = 'array'
					THEN s2.metadata->'fixed_versions' ELSE '[]'::jsonb END) fv
			WHERE s2.component_id = sv.id AND length(fv) <= 64
			ORDER BY fv LIMIT 20), '{}')
	FROM scoped s
	JOIN software_versions sv ON sv.id = s.component_id
	JOIN software_products p ON p.id = sv.product_id
	GROUP BY sv.id, sv.product_id, p.name, sv.purl, sv.raw
	HAVING COUNT(*) FILTER (WHERE ` + open + `) > 0
	ORDER BY 6 DESC, p.name, sv.raw
	LIMIT ` + strconv.Itoa(vulnerability.MaxExposureComponents)
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return nil, fmt.Errorf("cve exposure components: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c vulnerability.CVEExposureComponent
		var fixed pq.StringArray
		if err := rows.Scan(&c.ProductID, &c.Name, &c.Purl, &c.Version, &c.Assets, &c.ActiveFindings, &fixed); err != nil {
			return nil, fmt.Errorf("scan cve exposure component: %w", err)
		}
		c.FixedVersions = []string(fixed)
		out.Components = append(out.Components, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	//nolint:gosec // G202: the compiled filter, constants and placeholders only, no request text
	pq2 := scopedFindingsCTE(w, "findings.component_id IS NOT NULL AND "+vulnerability.OpenStatusSQL("findings.status")) + `
	SELECT sv.product_id, COUNT(DISTINCT s.asset_id)
	FROM scoped s JOIN software_versions sv ON sv.id = s.component_id
	GROUP BY sv.product_id`
	prow, err := tx.QueryContext(ctx, pq2, w.Args...)
	if err != nil {
		return nil, fmt.Errorf("cve exposure product assets: %w", err)
	}
	defer prow.Close()
	productAssets := map[string]int64{}
	for prow.Next() {
		var id string
		var n int64
		if err := prow.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("scan cve exposure product assets: %w", err)
		}
		productAssets[id] = n
	}
	return productAssets, prow.Err()
}

// cveExposureSources counts, per tool, the assets with an active finding it
// reported, and the assets only one tool reported.
func (r *FindingRepository) cveExposureSources(ctx context.Context, tx *sql.Tx, w *filterspec.Where, out *vulnerability.CVEExposure) error {
	cte := scopedFindingsCTE(w, vulnerability.OpenStatusSQL("findings.status")+" AND findings.asset_id IS NOT NULL")
	//nolint:gosec // G202: the compiled filter, constants and placeholders only, no request text
	q := cte + `
	SELECT COALESCE(NULLIF(s.tool_name, ''), s.source), s.source, COUNT(DISTINCT s.asset_id)
	FROM scoped s
	GROUP BY 1, 2
	ORDER BY 3 DESC, 1
	LIMIT ` + strconv.Itoa(vulnerability.MaxExposureSources)
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return fmt.Errorf("cve exposure sources: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s vulnerability.CVEExposureSource
		if err := rows.Scan(&s.Name, &s.Source, &s.Assets); err != nil {
			return fmt.Errorf("scan cve exposure source: %w", err)
		}
		out.Sources = append(out.Sources, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	single := cte + `
	SELECT COUNT(*) FROM (
		SELECT s.asset_id FROM scoped s GROUP BY s.asset_id
		HAVING COUNT(DISTINCT COALESCE(NULLIF(s.tool_name, ''), s.source)) = 1) one`
	if err := tx.QueryRowContext(ctx, single, w.Args...).Scan(&out.SingleSourceAssets); err != nil {
		return fmt.Errorf("cve exposure single-source assets: %w", err)
	}
	return nil
}

// cveExposureSoftware fills the possible and not-affected buckets from the
// software inventory: assets in scope running a product the CVE's ranges
// name, with no active finding of the CVE. A version the matcher matched
// counts as confirmed (returned); an unknown or unparseable version as
// possible; any other version as not affected. One asset lands in one
// bucket, the strongest.
func (r *FindingRepository) cveExposureSoftware(ctx context.Context, tx *sql.Tx, q vulnerability.CVEExposureQuery, out *vulnerability.CVEExposure) (int64, error) {
	w := q.Where
	cveArg, tenantArg := w.NextArg, w.NextArg+1
	scopeCond, scopeArgs := q.AssetScope("asw.asset_id", w.NextArg+2)
	args := append(append(append([]any{}, w.Args...), q.CVEID, q.TenantID.String()), scopeArgs...)
	cte := scopedFindingsCTE(w, vulnerability.OpenStatusSQL("findings.status")+" AND findings.asset_id IS NOT NULL") + `,
	links AS (
		SELECT asw.asset_id, p.name,
			(sv.raw = '' OR sv.normalized IS NULL) AS unknown_version,
			EXISTS (SELECT 1 FROM software_version_vulns m
				WHERE m.software_version_id = asw.software_version_id AND m.cve_id = $` + strconv.Itoa(cveArg) + `) AS matched
		FROM asset_software asw
		JOIN software_versions sv ON sv.id = asw.software_version_id
		JOIN software_products p ON p.id = asw.product_id
		JOIN assets a ON a.tenant_id = asw.tenant_id AND a.id = asw.asset_id AND a.deleted_at IS NULL
		WHERE asw.tenant_id = $` + strconv.Itoa(tenantArg) + ` AND asw.superseded_at IS NULL
		  AND asw.product_id IN (SELECT va.product_id FROM vulnerability_affected va WHERE va.cve_id = $` + strconv.Itoa(cveArg) + `)
		  AND asw.asset_id NOT IN (SELECT s.asset_id FROM scoped s)
		  AND ` + scopeCond + `
	),
	per_asset AS (
		SELECT asset_id, bool_or(matched) AS m, bool_or(NOT matched AND unknown_version) AS pos
		FROM links GROUP BY asset_id
	)`
	var matched int64
	if err := tx.QueryRowContext(ctx, cte+`
	SELECT COUNT(*) FILTER (WHERE m), COUNT(*) FILTER (WHERE NOT m AND pos), COUNT(*) FILTER (WHERE NOT m AND NOT pos)
	FROM per_asset`, args...).Scan(&matched, &out.Possible.Assets, &out.NotAffected.Assets); err != nil {
		return 0, fmt.Errorf("cve exposure software buckets: %w", err)
	}
	var possible, notAffected pq.StringArray
	if err := tx.QueryRowContext(ctx, cte+`
	SELECT
		COALESCE(ARRAY(SELECT DISTINCT l.name FROM links l JOIN per_asset pa ON pa.asset_id = l.asset_id
			WHERE NOT pa.m AND pa.pos AND l.unknown_version ORDER BY l.name LIMIT 10), '{}'),
		COALESCE(ARRAY(SELECT DISTINCT l.name FROM links l JOIN per_asset pa ON pa.asset_id = l.asset_id
			WHERE NOT pa.m AND NOT pa.pos ORDER BY l.name LIMIT 10), '{}')`, args...).Scan(&possible, &notAffected); err != nil {
		return 0, fmt.Errorf("cve exposure software products: %w", err)
	}
	out.Possible.Products, out.NotAffected.Products = []string(possible), []string(notAffected)
	return matched, nil
}

// cveExposureIntel reads the public intel beside the catalog record (aliases
// with provenance, weaknesses, feed freshness) and the organization's
// emerging-threat alert when it has an asset in the caller's scope.
func (r *FindingRepository) cveExposureIntel(ctx context.Context, tx *sql.Tx, q vulnerability.CVEExposureQuery, out *vulnerability.CVEExposure) error {
	//nolint:gosec // G202: the compiled filter, constants and placeholders only, no request text
	rows, err := tx.QueryContext(ctx, `
		SELECT alias_id, source, synced_at FROM vuln_id_aliases
		WHERE cve_id = $1 ORDER BY source, alias_id LIMIT `+strconv.Itoa(vulnerability.MaxExposureAliases), q.CVEID)
	if err != nil {
		return fmt.Errorf("cve aliases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a vulnerability.CVEAlias
		if err := rows.Scan(&a.ID, &a.Source, &a.SyncedAt); err != nil {
			return fmt.Errorf("scan cve alias: %w", err)
		}
		out.Intel.Aliases = append(out.Intel.Aliases, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	var cwes pq.StringArray
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE((SELECT cwes FROM cve_records WHERE cve_id = $1), '{}')
			|| COALESCE((SELECT cwes FROM kev_catalog WHERE cve_id = $1), '{}')`, q.CVEID).Scan(&cwes); err != nil {
		return fmt.Errorf("cve weaknesses: %w", err)
	}
	out.Intel.CWEs = cleanCWEs(cwes)

	frows, err := tx.QueryContext(ctx, `
		SELECT source_name, last_sync_at, last_sync_status FROM threat_intel_sync_status
		WHERE source_name IN ('kev', 'epss', 'vulnfeed') AND is_enabled
		ORDER BY source_name`)
	if err != nil {
		return fmt.Errorf("feed freshness: %w", err)
	}
	defer frows.Close()
	for frows.Next() {
		var f vulnerability.FeedFreshness
		var at sql.NullTime
		if err := frows.Scan(&f.Source, &at, &f.Status); err != nil {
			return fmt.Errorf("scan feed freshness: %w", err)
		}
		f.LastSyncAt = coverageTime(at)
		out.Intel.Feeds = append(out.Intel.Feeds, f)
	}
	if err := frows.Err(); err != nil {
		return err
	}
	frows.Close()

	scopeCond, scopeArgs := q.AssetScope("taa.asset_id", 3)
	var alert vulnerability.CVEEmergingAlert
	err = tx.QueryRowContext(ctx, `
		SELECT ta.id, ta.state, ta.level, ta.tier FROM threat_alerts ta
		WHERE ta.tenant_id = $1 AND ta.vuln_id = $2
		  AND EXISTS (SELECT 1 FROM threat_alert_assets taa
			WHERE taa.tenant_id = ta.tenant_id AND taa.alert_id = ta.id AND `+scopeCond+`)`,
		append([]any{q.TenantID.String(), q.CVEID}, scopeArgs...)...).Scan(&alert.ID, &alert.State, &alert.Level, &alert.Tier)
	switch {
	case err == nil:
		out.Intel.Emerging = &alert
	case !isNoRows(err):
		return fmt.Errorf("cve emerging alert: %w", err)
	}
	return nil
}

// ListCVEExposureAssets lists the assets with a finding of the CVE as the
// caller (the same compiled WHERE as the counts), one page, with the
// exposure context the page shows: crown jewel, internet-facing, the
// primary owner, open findings and the worst open priority.
func (r *FindingRepository) ListCVEExposureAssets(ctx context.Context, q vulnerability.CVEExposureQuery, search string, page pagination.Pagination) (pagination.Result[vulnerability.CVEExposureAsset], error) {
	empty := pagination.NewResult([]vulnerability.CVEExposureAsset{}, 0, page)
	if err := checkFindingWhere(q.Where); err != nil {
		return empty, err
	}
	w := q.Where
	open := vulnerability.OpenStatusSQL("s.status")
	args := append(append([]any{}, w.Args...), q.TenantID.String())
	tenantArg := len(args)
	searchCond := ""
	if s := strings.TrimSpace(search); s != "" {
		args = append(args, "%"+filterspec.EscapeLike(s)+"%")
		searchCond = " AND a.name ILIKE $" + strconv.Itoa(len(args)) + ` ESCAPE '\'`
	}
	args = append(args, page.Limit(), page.Offset())
	limitArg, offsetArg := len(args)-1, len(args)
	//nolint:gosec // G202: the compiled filter, constants and placeholders only, no request text
	query := scopedFindingsCTE(w, "findings.asset_id IS NOT NULL") + `,
	agg AS (
		SELECT s.asset_id,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE ` + open + `) AS open_count,
			MIN(CASE s.priority_class WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 END)
				FILTER (WHERE ` + open + `) AS prio_rank,
			MIN(CASE s.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END)
				FILTER (WHERE ` + open + `) AS sev_rank,
			MAX(s.last_seen_at) AS last_seen_at
		FROM scoped s GROUP BY s.asset_id
	)
	SELECT a.id, a.name, a.asset_type, COALESCE(a.criticality, ''), COALESCE(a.is_crown_jewel, FALSE),
		` + asset.InternetFacingSQL("a") + `,
		COALESCE((SELECT COALESCE(u.name, g.name, '') FROM asset_owners o
			LEFT JOIN users u ON u.id = o.user_id
			LEFT JOIN groups g ON g.id = o.group_id AND g.tenant_id = a.tenant_id
			WHERE o.asset_id = a.id AND o.ownership_type = 'primary'
			ORDER BY o.assigned_at, o.id LIMIT 1), ''),
		agg.open_count, agg.total,
		COALESCE((ARRAY['P0','P1','P2','P3']::text[])[agg.prio_rank + 1], ''),
		COALESCE((ARRAY['critical','high','medium','low','info','none']::text[])[agg.sev_rank], ''),
		agg.last_seen_at,
		COALESCE(ARRAY(
			SELECT t FROM (
				SELECT DISTINCT CASE WHEN s2.network_port IS NOT NULL
					THEN s2.network_port::text || '/' || COALESCE(s2.network_transport, 'tcp')
					ELSE NULLIF(LEFT(BTRIM(COALESCE(s2.file_path, '')), 200), '') END AS t
				FROM scoped s2 WHERE s2.asset_id = agg.asset_id
			) tt WHERE t IS NOT NULL ORDER BY t LIMIT ` + strconv.Itoa(vulnerability.MaxExposureTargets+1) + `), '{}'),
		COUNT(*) OVER ()
	FROM agg
	JOIN assets a ON a.tenant_id = $` + strconv.Itoa(tenantArg) + ` AND a.id = agg.asset_id
	WHERE TRUE` + searchCond + `
	ORDER BY (agg.open_count > 0) DESC, agg.prio_rank ASC NULLS LAST, agg.sev_rank ASC NULLS LAST,
		agg.open_count DESC, a.name, a.id
	LIMIT $` + strconv.Itoa(limitArg) + ` OFFSET $` + strconv.Itoa(offsetArg)

	tx, err := r.beginFindingRead(ctx)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return empty, findingTimeout(fmt.Errorf("list cve exposure assets: %w", err))
	}
	defer rows.Close()
	var total int64
	list := make([]vulnerability.CVEExposureAsset, 0, capHint(page.Limit()))
	for rows.Next() {
		var a vulnerability.CVEExposureAsset
		var last sql.NullTime
		var targets pq.StringArray
		if err := rows.Scan(&a.AssetID, &a.Name, &a.AssetType, &a.Criticality, &a.CrownJewel, &a.InternetFacing,
			&a.Owner, &a.OpenFindings, &a.TotalFindings, &a.WorstPriority, &a.WorstSeverity, &last, &targets, &total); err != nil {
			return empty, fmt.Errorf("scan cve exposure asset: %w", err)
		}
		a.LastSeenAt = coverageTime(last)
		a.Targets, a.TargetsMore = []string(targets), false
		if len(a.Targets) > vulnerability.MaxExposureTargets {
			a.Targets, a.TargetsMore = a.Targets[:vulnerability.MaxExposureTargets], true
		}
		list = append(list, a)
	}
	if err := rows.Err(); err != nil {
		return empty, findingTimeout(err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit cve exposure assets: %w", err)
	}
	if len(list) == 0 && page.Offset() > 0 {
		// Past the last page the window count has no row to ride on.
		countQ := scopedFindingsCTE(w, "findings.asset_id IS NOT NULL") + `
		SELECT COUNT(DISTINCT s.asset_id) FROM scoped s
		JOIN assets a ON a.tenant_id = $` + strconv.Itoa(tenantArg) + ` AND a.id = s.asset_id
		WHERE TRUE` + searchCond
		if err := r.db.QueryRowContext(ctx, countQ, args[:len(args)-2]...).Scan(&total); err != nil {
			return empty, findingTimeout(fmt.Errorf("count cve exposure assets: %w", err))
		}
	}
	return pagination.NewResult(list, total, page), nil
}

// ResolveVulnAlias returns the CVE the signed feed ties an advisory id to,
// or "" when it ties none.
func (r *FindingRepository) ResolveVulnAlias(ctx context.Context, aliasID string) (string, error) {
	var cve string
	err := r.db.QueryRowContext(ctx, `SELECT cve_id FROM vuln_id_aliases WHERE alias_id = $1`, aliasID).Scan(&cve)
	if isNoRows(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve vulnerability alias: %w", err)
	}
	return cve, nil
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// cleanCWEs de-duplicates and sorts weakness ids, keeping the CWE-<n> shape.
func cleanCWEs(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if !cweIDPattern.MatchString(c) || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(out[i], "CWE-"))
		b, _ := strconv.Atoi(strings.TrimPrefix(out[j], "CWE-"))
		return a < b
	})
	return out
}

// mergeVersions is a, then the versions of b not in a.
func mergeVersions(a, b []string) []string {
	out := append([]string{}, a...)
	seen := make(map[string]bool, len(a))
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
