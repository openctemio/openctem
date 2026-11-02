package technology

import (
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// The view is one query in two stages. The row stage reads asset_technologies
// (alias t) of live assets (a), each joined to the software version it was
// matched to (sw, at most one: see RowsFromSQL). The filter, the tenant and
// the data scope apply there, per asset, so a version only counts the assets
// the caller may see. The group stage (g) folds the rows into one row per
// name and version, and adds the CVE figures of the matched versions (c) and
// the open alerts about them (al). Filter fields therefore use row-stage
// columns; sort keys use group-stage columns.

// VendorSQL and CPESQL prefer what the tool reported over the matched
// product's.
const (
	VendorSQL = "COALESCE(t.vendor, sw.vendor)"
	CPESQL    = "COALESCE(t.cpe, sw.cpe)"
)

// RowsFromSQL is the FROM of the row stage. The software link is the
// technology's own detection (source technology, current link) on the same
// asset of the same tenant whose product carries the technology's name, as
// its name or as a name alias global or private to the tenant. A product of
// another tenant can never match: links and aliases are tenant-checked.
const RowsFromSQL = ` FROM asset_technologies t
	JOIN assets a ON a.tenant_id = t.tenant_id AND a.id = t.asset_id AND a.deleted_at IS NULL
	LEFT JOIN LATERAL (
		SELECT s.software_version_id, NULLIF(p.vendor, '') AS vendor,
		       CASE WHEN p.cpe_vendor IS NOT NULL AND p.cpe_product IS NOT NULL
		            THEN 'cpe:2.3:' || p.part || ':' || p.cpe_vendor || ':' || p.cpe_product || ':*:*:*:*:*:*:*:*' END AS cpe
		  FROM asset_software s
		  JOIN software_products p ON p.id = s.product_id
		 WHERE s.tenant_id = t.tenant_id AND s.asset_id = t.asset_id
		   AND s.source = 'technology' AND s.superseded_at IS NULL
		   AND (lower(p.name) = t.name_key OR EXISTS (
		        SELECT 1 FROM software_product_aliases pa
		         WHERE pa.product_id = p.id AND pa.kind = 'name' AND pa.value = t.name_key
		           AND (pa.tenant_id IS NULL OR pa.tenant_id = t.tenant_id)))
		 ORDER BY s.confidence DESC, s.last_seen_at DESC
		 LIMIT 1) sw ON true`

// GroupSelectSQL folds the row stage into one row per name and version. It
// is followed by RowsFromSQL, " WHERE " and the compiled filter, and
// GroupBySQL.
const GroupSelectSQL = `SELECT t.tenant_id, t.name_key, t.version,
		mode() WITHIN GROUP (ORDER BY t.name) AS name,
		mode() WITHIN GROUP (ORDER BY t.category) AS category,
		max(` + VendorSQL + `) AS vendor, max(` + CPESQL + `) AS cpe,
		COALESCE(array_agg(DISTINCT t.source) FILTER (WHERE t.source <> ''), '{}') AS sources,
		count(DISTINCT t.asset_id) AS asset_count,
		array_agg(DISTINCT sw.software_version_id) FILTER (WHERE sw.software_version_id IS NOT NULL) AS svids,
		array_agg(DISTINCT t.asset_id) AS asset_ids,
		min(t.first_seen) AS first_seen, max(t.last_seen) AS last_seen`

// GroupBySQL ends the group stage.
const GroupBySQL = ` GROUP BY t.tenant_id, t.name_key, t.version`

// FiguresSQL adds, to a group stage aliased g, the CVE figures of its matched
// software versions (c: rejected CVEs never count) and the open
// emerging-threat alerts about those CVEs on its assets (al: the tenant's
// own alerts, on assets the caller may see, since g only holds those).
const FiguresSQL = `
	LEFT JOIN LATERAL (
		SELECT count(*) AS cve_count, max(v.cvss) AS top_cvss,
		       (array_agg(v.cve_id ORDER BY v.cvss DESC NULLS LAST, v.cve_id))[1] AS top_cve,
		       COALESCE(bool_or(v.kev), false) AS kev, COALESCE(bool_or(v.kev OR v.exploit), false) AS exploit
		  FROM (SELECT m.cve_id, max(r.cvss_score) AS cvss, bool_or(k.cve_id IS NOT NULL) AS kev,
		               bool_or(EXISTS (SELECT 1 FROM vulnerabilities x
		                                WHERE x.cve_id = m.cve_id AND x.tenant_id IS NULL AND x.exploit_available)) AS exploit
		          FROM software_version_vulns m
		          JOIN cve_records r ON r.cve_id = m.cve_id AND r.status <> 'Rejected'
		          LEFT JOIN kev_catalog k ON k.cve_id = m.cve_id
		         WHERE m.software_version_id = ANY(g.svids)
		         GROUP BY m.cve_id) v) c ON true
	LEFT JOIN LATERAL (
		SELECT count(DISTINCT ta.id) AS active_alerts
		  FROM threat_alerts ta
		  JOIN threat_alert_assets taa ON taa.tenant_id = ta.tenant_id AND taa.alert_id = ta.id
		 WHERE ta.tenant_id = g.tenant_id AND ta.state IN ('new', 'acknowledged', 'remediating')
		   AND taa.asset_id = ANY(g.asset_ids)
		   AND ta.vuln_id IN (SELECT m.cve_id FROM software_version_vulns m WHERE m.software_version_id = ANY(g.svids))) al ON true`

var (

	// hasCVEsSQL: the matched software version has a CVE that is not
	// rejected.
	hasCVEsSQL = `(sw.software_version_id IS NOT NULL AND EXISTS (SELECT 1 FROM software_version_vulns m
		JOIN cve_records r ON r.cve_id = m.cve_id AND r.status <> 'Rejected' WHERE m.software_version_id = sw.software_version_id))`
	// kevSQL: one of those CVEs is in the known-exploited catalog.
	kevSQL = `(sw.software_version_id IS NOT NULL AND EXISTS (SELECT 1 FROM software_version_vulns m
		JOIN cve_records r ON r.cve_id = m.cve_id AND r.status <> 'Rejected'
		JOIN kev_catalog k ON k.cve_id = m.cve_id WHERE m.software_version_id = sw.software_version_id))`

	inNotIn  = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}
	textOps  = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn, filterspec.OpContains}
	timeOps  = []filterspec.Op{filterspec.OpGte, filterspec.OpLte, filterspec.OpGt, filterspec.OpLt}
	boolOnly = []filterspec.Op{filterspec.OpEq}
)

// Categories are the values of the category field.
func Categories() []string {
	all := assettech.AllCategories()
	out := make([]string, len(all))
	for i, c := range all {
		out[i] = string(c)
	}
	return out
}

// Fields is the list query contract registry of GET
// /attack-surface/technologies. The data scope applies to each asset that
// runs a technology: a version is listed when at least one visible asset
// runs it, and its counts include visible assets only.
var Fields = filterspec.MustRegistry(filterspec.Registry{
	Name:          "technologies",
	TenantSQL:     "t.tenant_id",
	ScopeAssetSQL: "t.asset_id",
	IDSQL:         "g.name_key, g.version",
	DefaultSort:   []filterspec.SortKey{{Field: "asset_count", Desc: true}, {Field: "name"}},
	Search: &filterspec.Search{
		Template: `t.name ILIKE {arg} ESCAPE '\' OR t.version ILIKE {arg} ESCAPE '\' OR ` + VendorSQL + ` ILIKE {arg} ESCAPE '\'`,
		Pattern:  true,
	},
},
	filterspec.Field{Name: "name", Type: filterspec.TypeString, Ops: textOps, SQL: "t.name_key", SortSQL: "g.name_key",
		Sortable: true, FreeText: true},
	filterspec.Field{Name: "version", Type: filterspec.TypeString, Ops: textOps, SQL: "t.version", SortSQL: "g.version",
		Sortable: true, FreeText: true},
	filterspec.Field{Name: "version_known", Type: filterspec.TypeBool, Ops: boolOnly, SQL: "t.version",
		BoolTemplate: "t.version <> ''"},
	filterspec.Field{Name: "category", Type: filterspec.TypeEnum, Enum: Categories(), Ops: inNotIn, SQL: "t.category",
		SortSQL: "g.category", Sortable: true},
	filterspec.Field{Name: "source", Type: filterspec.TypeString, Ops: textOps, SQL: "t.source", FreeText: true},
	filterspec.Field{Name: "vendor", Type: filterspec.TypeString, Ops: textOps, SQL: VendorSQL, Nullable: true,
		SortSQL: "g.vendor", Sortable: true, FreeText: true},
	filterspec.Field{Name: "asset_id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "t.asset_id"},
	filterspec.Field{Name: "has_cves", Type: filterspec.TypeBool, Ops: boolOnly, SQL: "sw.software_version_id",
		BoolTemplate: hasCVEsSQL},
	filterspec.Field{Name: "kev", Type: filterspec.TypeBool, Ops: boolOnly, SQL: "sw.software_version_id",
		BoolTemplate: kevSQL},
	filterspec.Field{Name: "last_seen", Type: filterspec.TypeTime, Ops: timeOps, SQL: "t.last_seen", SortSQL: "g.last_seen",
		Sortable: true},
	filterspec.Field{Name: "first_seen", Type: filterspec.TypeTime, Ops: timeOps, SQL: "t.first_seen", SortSQL: "g.first_seen",
		Sortable: true},
	// Sort-only keys over the group stage.
	filterspec.Field{Name: "asset_count", Type: filterspec.TypeInt, SQL: "g.asset_count", Sortable: true},
	filterspec.Field{Name: "cve_count", Type: filterspec.TypeInt, SQL: "c.cve_count", Sortable: true},
	filterspec.Field{Name: "top_cvss", Type: filterspec.TypeNumber, SQL: "c.top_cvss", Nullable: true, Sortable: true},
	filterspec.Field{Name: "active_alerts", Type: filterspec.TypeInt, SQL: "al.active_alerts", Sortable: true},
)
