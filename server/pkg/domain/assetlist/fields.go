package assetlist

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/pkg/domain/assetfreshness"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/assetdomain"
	"github.com/openctemio/openctem/server/pkg/domain/assettech"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/dashboard"
	"github.com/openctemio/openctem/server/pkg/domain/liveness"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// The asset inventory's field registry: every filter of GET /assets, its
// document endpoint, saved views of the assets page and the search box
// (entity assets). Columns are qualified with the alias "a" (the list reads
// FROM assets a); the query language rebases them onto the table name.
//
// Every template that reads another table pins it to the caller's tenant
// ({tenant}) or to the asset's own row, and binds values only through
// {arg}. Left out on purpose: free-form properties, descriptions, owner
// contact data, sync errors, integration references and soft deletion.

// Values of the list's derived-state fields.
const (
	CoverageCovered        = "covered"
	CoverageUncovered      = "uncovered"
	ResolutionResolving    = "resolving"
	ResolutionNotResolving = "not_resolving"
	ProgramAssetsOnly      = "only"
	ProgramAssetsExclude   = "exclude"
)

// Field names and columns used more than once.
const (
	fieldTag      = "tag"
	fieldProvider = "provider"
	colID         = "a.id"
	colName       = "a.name"
)

// Limits of the list's own fields.
const (
	maxDomainValues    = 20
	maxUnderValues     = 10
	maxTechniqueValues = 10
	maxIPValues        = 20
)

var (
	inNotIn  = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}
	onlyIn   = []filterspec.Op{filterspec.OpIn}
	onlyEq   = []filterspec.Op{filterspec.OpEq}
	ranges   = []filterspec.Op{filterspec.OpGte, filterspec.OpGt, filterspec.OpLte, filterspec.OpLt}
	rangesEq = []filterspec.Op{filterspec.OpEq, filterspec.OpGte, filterspec.OpGt, filterspec.OpLte, filterspec.OpLt}
)

// ownerSQL is "the acting user owns the tenant": owners see the system tags
// of every bug-bounty program; anyone else (a user-less key included) only
// those of programs not hidden from them (RFC-065 §15.3).
const ownerSQL = `EXISTS (SELECT 1 FROM tenant_members otm WHERE otm.tenant_id = {tenant} AND otm.user_id = {user}
	AND otm.role = 'owner' AND otm.status = 'active')`

// tagSQL is "the asset carries a tag of the bound array": its own tags, or a
// system tag of a program the caller may see.
var tagSQL = `(a.tags && {arg} OR (a.system_tags && {arg} AND (` + ownerSQL + ` OR ` +
	VisibleProgramLinkSQL("a.id", "a.tenant_id", "{user}", "AND t = ANY({arg})") + `)))`

// A tag filter takes at most maxTagValues tags of at most maxTagLen
// characters (an asset tag is at most maxTagLen long, so a longer value can
// never match).
const (
	maxTagValues = 20
	maxTagLen    = 50
)

var errTagTooLong = errors.New("a tag is at most 50 characters")

// checkTagValue refuses a tag longer than any stored tag.
func checkTagValue(v string) (string, error) {
	if utf8.RuneCountInString(v) > maxTagLen {
		return "", errTagTooLong
	}
	return v, nil
}

// tagAllSQL is "the asset carries every tag of the bound array".
var tagAllSQL = `(` + tagSQL + ` AND NOT EXISTS (SELECT 1 FROM unnest({arg}) AS want(tag) WHERE NOT (want.tag = ANY(a.tags)
	OR (want.tag = ANY(a.system_tags) AND (` + ownerSQL + ` OR ` +
	VisibleProgramLinkSQL("a.id", "a.tenant_id", "{user}", "AND t = want.tag") + `)))))`

// openFindingsSQL is "the asset has an open finding that counts" (the
// asset's tenant pinned on the finding as well).
var openFindingsSQL = "EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id AND f.tenant_id = a.tenant_id AND " +
	vulnerability.OpenStatusSQL("f.status") + " AND NOT f.branch_only)"

// openFindingCountSQL counts the same findings.
var openFindingCountSQL = "(SELECT count(*) FROM findings f WHERE f.asset_id = a.id AND f.tenant_id = a.tenant_id AND " +
	vulnerability.OpenStatusSQL("f.status") + " AND NOT f.branch_only)"

// coverageSince is the start of the coverage window, as SQL.
var coverageSince = fmt.Sprintf("(now() - interval '%d seconds')", int64(asset.CoverageWindow.Seconds()))

// confidenceSQL is the asset's attribution confidence; no record counts as
// 100, as the attribution API reports it.
const confidenceSQL = "COALESCE((SELECT acf.confidence FROM asset_attributions acf WHERE acf.asset_id = a.id AND acf.tenant_id = a.tenant_id), 100)"

// attributionStateSQL is the asset's attribution state; an asset with no
// record reads as "unknown".
const attributionStateSQL = "COALESCE((SELECT aat.state FROM asset_attributions aat WHERE aat.asset_id = a.id AND aat.tenant_id = a.tenant_id), '" +
	attribution.FilterUnrecorded + "')"

// ipRangeSQL is an asset with its name or a recorded address inside the
// bound range (asset.AssetIDsInRangesSQL, shared with the findings filter
// and smart group rules): one btree range scan, pinned to the tenant.
var ipRangeSQL = asset.AssetInRangesSQL("a.id", "{tenant}", "{arg}")

// underSQL is "the name is one of the bound DNS names or below one on a
// label boundary"; LIKE metacharacters of the name are escaped.
const underSQL = `EXISTS (SELECT 1 FROM unnest({arg}) AS u(d) WHERE a.name = u.d
	OR a.name ILIKE '%.' || replace(replace(replace(u.d, '\', '\\'), '%', '\%'), '_', '\_') ESCAPE '\')`

// technologySQL matches a technology by name, or by name@version (the
// version after the first "@"; "name@" is a version the tools could not
// tell).
const technologySQL = `EXISTS (SELECT 1 FROM asset_technologies t WHERE t.tenant_id = {tenant} AND t.asset_id = a.id
	AND (t.name_key = ANY({arg}) OR t.name_key || '@' || t.version = ANY({arg})))`

// normalizeTechnology is a technology filter value: the name key, with an
// optional "@version" kept as written.
func normalizeTechnology(v string) (string, error) {
	name, version, hasVersion := strings.Cut(v, "@")
	k := assettech.Key(name)
	if k == "" {
		return "", fmt.Errorf("not a technology name")
	}
	if !hasVersion {
		return k, nil
	}
	if len(version) > 64 {
		return "", fmt.Errorf("a technology version is at most 64 characters")
	}
	return k + "@" + strings.TrimSpace(version), nil
}

// portOps are the operators of the port field (a list, or a range with
// port>=8000 port<=8999).
var portOps = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn, filterspec.OpGte, filterspec.OpGt, filterspec.OpLte, filterspec.OpLt}

// portSQL is "the asset answers on an open port matching cond" (cond over
// asset_ports ap), pinned to the caller's tenant.
func portSQL(cond string) string {
	return "EXISTS (SELECT 1 FROM asset_ports ap WHERE ap.tenant_id = {tenant} AND ap.asset_id = a.id AND " + cond + ")"
}

// normalizeService is a service name as asset_ports stores it.
func normalizeService(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || len(v) > 64 {
		return "", fmt.Errorf("a service name is 1 to 64 characters")
	}
	return v, nil
}

// normalizeUnder is an under value: a DNS name, lower case.
func normalizeUnder(v string) (string, error) {
	name, ok := assetdomain.NormalizeDNSName(v)
	if !ok {
		return "", fmt.Errorf("not a DNS name")
	}
	return name, nil
}

// MonitoringScanned selects the registry variant for the tenant's
// unclassified-scans mode, the one input of the monitoring state that is
// not in the database (it depends on the platform's placement policy).
type MonitoringScanned bool

var (
	fieldsScanned   = build(true)
	fieldsUnscanned = build(false)
)

// Fields is the registry for parsing and validating an assets filter
// (params, documents, saved views, the search box). Compile a request with
// FieldsFor, which also fixes the monitoring state input.
var Fields = fieldsUnscanned

// FieldsFor is the registry to compile a request with: identical fields,
// with the tenant's unclassified-scans mode in the monitoring state.
func FieldsFor(scanned MonitoringScanned) *filterspec.Registry {
	if scanned {
		return fieldsScanned
	}
	return fieldsUnscanned
}

// Aliases are the params GET /assets took before the list query contract;
// they keep working, with Deprecation and Sunset, for two releases.
func Aliases() map[string]filterspec.Alias {
	return map[string]filterspec.Alias{
		"types":                {To: "type"},
		"lenses":               {To: "lens"},
		"criticalities":        {To: "criticality"},
		"statuses":             {To: "status"},
		"scopes":               {To: "scope"},
		"exposures":            {To: "exposure"},
		"tags":                 {To: "tag"},
		"exclude_tags":         {To: "tag_not"},
		"search":               {To: "q"},
		"min_risk_score":       {To: "risk_score_gte"},
		"max_risk_score":       {To: "risk_score_lte"},
		"is_crown_jewel":       {To: "crown_jewel"},
		"business_unit_ids":    {To: "business_unit"},
		"asset_group_ids":      {To: "asset_group"},
		"owner_ids":            {To: "owner"},
		"ids":                  {To: "id"},
		"in_cidr":              {To: "ip"},
		"data_classifications": {To: "data_classification"},
		"is_control_plane":     {To: "control_plane"},
		"environments":         {To: "environment"},
		"providers":            {To: "provider"},
		"last_seen_after":      {To: "last_seen_gte"},
		"last_seen_before":     {To: "last_seen_lte"},
		"expires_after":        {To: "expires_gt"},
		"expires_before":       {To: "expires_lt"},
		"min_confidence":       {To: "confidence_gte"},
		"max_confidence":       {To: "confidence_lte"},
		"first_seen_after":     {To: "created_at_gte"},
		"first_seen_before":    {To: "created_at_lte"},
	}
}

func build(scanned bool) *filterspec.Registry {
	base := asset.AssetFields.Rebase("assets", "a")
	fields := make([]filterspec.Field, 0, 64)
	for _, f := range base.Fields() {
		switch f.Name {
		case "deleted", "program_only", fieldTag, fieldProvider:
			continue // server-side only, or replaced below
		}
		nf := *f
		switch nf.Name {
		case "name":
			nf.Ops = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn, filterspec.OpContains}
			nf.Normalize = filterspec.NormalizeGlob
			nf.Expand = func(v string) []string { return []string{filterspec.GlobToLike(v)} }
			nf.Glob = true
			nf.Doc = "name or name pattern (* any characters, ? one)"
			nf.Templates = map[filterspec.Op]string{
				filterspec.OpIn:    "a.name ILIKE ANY({arg})",
				filterspec.OpNotIn: "NOT (a.name ILIKE ANY({arg}))",
			}
			nf.Sortable = true
		case "type":
			nf.Sortable = true
			nf.SortSQL = "a.asset_type"
		case "status", "scope", "first_seen", "last_seen", "created_at", "risk_score":
			nf.Sortable = true
		case "criticality":
			nf.Ordered = true
			nf.Sortable = true
			nf.SortSQL = "CASE a.criticality" + strings.TrimPrefix(asset.CriticalityRankSQL, "CASE criticality")
		case "exposure":
			nf.Sortable = true
			nf.SortSQL = "CASE a.exposure" + strings.TrimPrefix(asset.ExposureRankSQL, "CASE exposure")
		}
		fields = append(fields, nf)
	}
	fields = append(fields,
		filterspec.Field{Name: "lens", Type: filterspec.TypeEnum, Enum: lensNames(), Ops: inNotIn, SQL: "a.asset_lens"},
		filterspec.Field{Name: fieldTag, Type: filterspec.TypeString, Ops: inNotIn, SQL: "a.tags", UserOptional: true,
			MaxValues: maxTagValues, Normalize: checkTagValue,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    tagSQL,
				filterspec.OpNotIn: "NOT COALESCE(" + tagSQL + ", FALSE)",
			}},
		filterspec.Field{Name: "tag_all", Type: filterspec.TypeString, Ops: onlyIn, SQL: "a.tags", UserOptional: true, Doc: "carries every one of these tags",
			MaxValues: maxTagValues, Normalize: checkTagValue,
			Templates: map[filterspec.Op]string{filterspec.OpIn: tagAllSQL}},
		filterspec.Field{Name: fieldProvider, Type: filterspec.TypeString, Ops: inNotIn, SQL: "a.provider", Sortable: true,
			Doc: "provider (unset: none recorded)",
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    "COALESCE(a.provider, 'unset') = ANY({arg})",
				filterspec.OpNotIn: "NOT (COALESCE(a.provider, 'unset') = ANY({arg}))",
			}},
		filterspec.Field{Name: "updated_at", Type: filterspec.TypeTime, Ops: ranges, SQL: "a.updated_at", Sortable: true},
		filterspec.Field{Name: "last_synced", Type: filterspec.TypeTime, Ops: ranges, SQL: "a.last_synced_at", Nullable: true, Sortable: true},
		filterspec.Field{Name: "sync_status", Type: filterspec.TypeString, Ops: inNotIn, SQL: "a.sync_status", Sortable: true},
		filterspec.Field{Name: "has_findings", Type: filterspec.TypeBool, Ops: onlyEq, SQL: colID, BoolTemplate: openFindingsSQL},
		filterspec.Field{Name: "finding_count", Type: filterspec.TypeInt, Ops: rangesEq, SQL: openFindingCountSQL, Expensive: true,
			Doc: "open findings", Sortable: true, SortSQL: "COALESCE(fc.finding_count, 0)"},
		filterspec.Field{Name: "coverage", Type: filterspec.TypeEnum, Enum: []string{CoverageCovered, CoverageUncovered}, Ops: onlyEq, SQL: colID,
			EnumTemplates: map[string]string{
				CoverageCovered:   CoverageCondition(CoverageCovered, coverageSince),
				CoverageUncovered: CoverageCondition(CoverageUncovered, coverageSince),
			}},
		filterspec.Field{Name: "coverage_cause", Type: filterspec.TypeEnum, Enum: dashboard.CoverageCauses(), Ops: onlyIn, SQL: colID,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: CoverageCondition(CoverageUncovered, coverageSince) + " AND " + CoverageCauseExpr(coverageSince) + " = ANY({arg})",
			}},
		filterspec.Field{Name: "freshness", Type: filterspec.TypeEnum, Enum: []string{assetfreshness.FilterStale, assetfreshness.FilterNever}, Ops: onlyEq, SQL: colID,
			EnumTemplates: map[string]string{
				assetfreshness.FilterStale: FreshnessSQL(assetfreshness.FilterStale),
				assetfreshness.FilterNever: FreshnessSQL(assetfreshness.FilterNever),
			}},
		filterspec.Field{Name: "resolution", Type: filterspec.TypeEnum, Enum: []string{ResolutionResolving, ResolutionNotResolving}, Ops: onlyEq, SQL: colID,
			EnumTemplates: map[string]string{
				ResolutionResolving:    ResolutionSQL(ResolutionResolving),
				ResolutionNotResolving: ResolutionSQL(ResolutionNotResolving),
			}},
		filterspec.Field{Name: "technology", Type: filterspec.TypeString, Ops: inNotIn, SQL: colID, MaxValues: assettech.MaxFilterValues,
			Normalize: normalizeTechnology, Doc: "technology name, or name@version",
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    technologySQL,
				filterspec.OpNotIn: "NOT " + technologySQL,
			}},
		filterspec.Field{Name: "technology_version", Type: filterspec.TypeString, Ops: onlyIn, SQL: colID, MaxValues: assettech.MaxFilterValues,
			Doc: "a technology of this exact version",
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: "EXISTS (SELECT 1 FROM asset_technologies t WHERE t.tenant_id = {tenant} AND t.asset_id = a.id AND t.version = ANY({arg}))",
			}},
		filterspec.Field{Name: "technology_category", Type: filterspec.TypeEnum, Enum: technologyCategoryNames(), Ops: onlyIn, SQL: colID,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: "EXISTS (SELECT 1 FROM asset_technologies t WHERE t.tenant_id = {tenant} AND t.asset_id = a.id AND t.category = ANY({arg}))",
			}},
		filterspec.Field{Name: "business_unit", Type: filterspec.TypeID, Ops: onlyIn, SQL: colID,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: `EXISTS (SELECT 1 FROM business_unit_assets ba JOIN business_units bu ON bu.id = ba.business_unit_id AND bu.tenant_id = {tenant}
					WHERE ba.asset_id = a.id AND ba.business_unit_id = ANY({arg}))`,
			}},
		filterspec.Field{Name: "asset_group", Type: filterspec.TypeID, Ops: onlyIn, SQL: colID, MaxValues: 20,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: `EXISTS (SELECT 1 FROM asset_group_members agm JOIN asset_groups fg ON fg.id = agm.asset_group_id AND fg.tenant_id = {tenant}
					WHERE agm.asset_id = a.id AND agm.asset_group_id = ANY({arg}))`,
			}},
		// asset_owners has no tenant column: the owner is pinned to the
		// tenant's members and groups.
		filterspec.Field{Name: "owner", Type: filterspec.TypeID, Ops: onlyIn, SQL: colID, MaxValues: 20,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: `EXISTS (SELECT 1 FROM asset_owners ao WHERE ao.asset_id = a.id AND (
					(ao.user_id = ANY({arg}) AND ao.user_id IN (SELECT user_id FROM tenant_members WHERE tenant_id = {tenant}))
					OR (ao.group_id = ANY({arg}) AND ao.group_id IN (SELECT id FROM groups WHERE tenant_id = {tenant}))))`,
			}},
		filterspec.Field{Name: "has_owner", Type: filterspec.TypeBool, Ops: onlyEq, SQL: colID,
			BoolTemplate: `EXISTS (SELECT 1 FROM asset_owners ao WHERE ao.asset_id = a.id
				AND (ao.group_id IS NULL OR ao.group_id IN (SELECT id FROM groups WHERE tenant_id = {tenant}))
				AND (ao.user_id IS NULL OR ao.user_id IN (SELECT user_id FROM tenant_members WHERE tenant_id = {tenant})))`},
		filterspec.Field{Name: "under", Type: filterspec.TypeString, Ops: onlyIn, SQL: colName, MaxValues: maxUnderValues,
			Normalize: normalizeUnder, Doc: "names equal to or below these DNS names",
			Templates: map[filterspec.Op]string{filterspec.OpIn: underSQL}},
		// Domain membership (docs/architecture/asset-domain-membership.md):
		// names, the addresses they resolve to, services on them and
		// certificates naming the domain; one index lookup.
		filterspec.Field{Name: "domain", Type: filterspec.TypeString, Ops: inNotIn, SQL: colID, MaxValues: maxDomainValues,
			Doc: "domain (x: x and everything that belongs to it; *.x: only below x)", Glob: true,
			Normalize: assetdomain.NormalizeDomainFilter, Expand: assetdomain.DomainFilterKeys,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    "a.id IN (SELECT m.asset_id FROM asset_domain_memberships m WHERE m.tenant_id = {tenant} AND m.key = ANY({arg}))",
				filterspec.OpNotIn: "a.id NOT IN (SELECT m.asset_id FROM asset_domain_memberships m WHERE m.tenant_id = {tenant} AND m.key = ANY({arg}))",
			}},
		filterspec.Field{Name: "ip", Type: filterspec.TypeInet, Ops: onlyIn, SQL: colName, MaxValues: maxIPValues,
			Doc:       "IP address or CIDR range (10.0.0.0/8)",
			Templates: map[filterspec.Op]string{filterspec.OpIn: ipRangeSQL}},
		// Network of an address (the /24 of IPv4, the /64 of IPv6):
		// network=10.1.2.0/24, or an address for "the same network as".
		filterspec.Field{Name: "network", Type: filterspec.TypeInet, Ops: onlyIn, SQL: colName, MaxValues: maxIPValues,
			Doc: "network (/24 of an IPv4 address, /64 of IPv6) of address assets",
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: "a.tenant_id = {tenant} AND a.asset_type = 'ip_address' AND asset_ip_network(a.name) = asset_ip_network(host({arg}))",
			}},
		// Open ports (asset_ports, docs/architecture/asset-ports.md): the
		// port asset, its address and the names resolving to it.
		filterspec.Field{Name: "port", Type: filterspec.TypeInt, Ops: portOps, SQL: colID, Doc: "open port (0-65535)",
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    portSQL("ap.port = ANY({arg})"),
				filterspec.OpNotIn: "NOT " + portSQL("ap.port = ANY({arg})"),
				filterspec.OpGte:   portSQL("ap.port >= {arg}"),
				filterspec.OpGt:    portSQL("ap.port > {arg}"),
				filterspec.OpLte:   portSQL("ap.port <= {arg}"),
				filterspec.OpLt:    portSQL("ap.port < {arg}"),
			}},
		filterspec.Field{Name: "service", Type: filterspec.TypeString, Ops: inNotIn, SQL: colID, MaxValues: 20,
			Doc: "service on an open port (https, ssh...)", Normalize: normalizeService,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    portSQL("ap.service = ANY({arg})"),
				filterspec.OpNotIn: "NOT " + portSQL("ap.service = ANY({arg})"),
			}},
		filterspec.Field{Name: "control_plane", Type: filterspec.TypeBool, Ops: onlyEq, SQL: colID,
			BoolTemplate: "EXISTS (SELECT 1 FROM asset_relationships ar WHERE ar.target_asset_id = a.id AND ar.is_control_plane = true AND ar.tenant_id = a.tenant_id)"},
		filterspec.Field{Name: "expires", Type: filterspec.TypeTime, Ops: ranges, SQL: ExpirySQL, Nullable: true,
			Doc: "expiry (a certificate's not after, a domain's expiry)"},
		filterspec.Field{Name: "attribution", Type: filterspec.TypeEnum, Enum: attributionFilterNames(), EnumExpand: attributionExpand(),
			Ops: inNotIn, SQL: attributionStateSQL},
		filterspec.Field{Name: "covered_by", Type: filterspec.TypeID, Ops: onlyIn, SQL: colID, MaxValues: 20, Doc: "scope entry that confirmed the asset",
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: `EXISTS (SELECT 1 FROM easm_evidence sje WHERE sje.asset_id = a.id AND sje.tenant_id = {tenant}
					AND sje.rule = 'matches_scope_target' AND sje.source = ANY (ARRAY(SELECT 'scope_target:' || x FROM unnest({arg}) AS x)))`,
			}},
		filterspec.Field{Name: "scope_status", Type: filterspec.TypeEnum, Enum: []string{ScopeStatusInScope, ScopeStatusNotCovered, ScopeStatusExcluded, ScopeStatusInternal},
			Ops: onlyIn, SQL: ScopeStatusSQL("a"), Expensive: true},
		filterspec.Field{Name: "monitoring_state", Type: filterspec.TypeEnum, Enum: monitoringStateNames(), Ops: onlyIn,
			SQL: MonitoringStateSQL("a", fmt.Sprint(scanned)), Expensive: true},
		filterspec.Field{Name: "liveness", Type: filterspec.TypeEnum, Enum: livenessNames(), Ops: onlyIn,
			SQL: "COALESCE((SELECT lv.state FROM asset_liveness lv WHERE lv.tenant_id = a.tenant_id AND lv.asset_id = a.id), 'unknown')"},
		filterspec.Field{Name: "primary", Type: filterspec.TypeBool, Ops: onlyEq, SQL: colID, BoolTemplate: asset.PrimarySQL("a"),
			Doc: "the organization's root domains"},
		filterspec.Field{Name: "discovered_by", Type: filterspec.TypeEnum, Enum: discoveryRuleNames(), Ops: onlyIn, SQL: colID,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: "EXISTS (SELECT 1 FROM easm_evidence dbe WHERE dbe.asset_id = a.id AND dbe.tenant_id = a.tenant_id AND dbe.rule = ANY({arg}))",
			}},
		filterspec.Field{Name: "discovery_technique", Type: filterspec.TypeString, Ops: onlyIn, SQL: colID, MaxValues: maxTechniqueValues,
			Templates: map[filterspec.Op]string{
				filterspec.OpIn: "EXISTS (SELECT 1 FROM easm_evidence dte WHERE dte.asset_id = a.id AND dte.tenant_id = a.tenant_id AND dte.technique = ANY({arg}))",
			}},
		filterspec.Field{Name: "confidence", Type: filterspec.TypeInt, Ops: ranges, SQL: confidenceSQL, Doc: "attribution confidence (0-100)"},
		filterspec.Field{Name: "program_assets", Type: filterspec.TypeEnum, Enum: []string{ProgramAssetsOnly, ProgramAssetsExclude}, Ops: onlyEq, SQL: colID, UserOptional: true,
			Doc: "bug-bounty program assets",
			EnumTemplates: map[string]string{
				ProgramAssetsOnly: `('bug-bounty' = ANY(a.system_tags) AND (` + ownerSQL + ` OR ` +
					VisibleProgramLinkSQL("a.id", "a.tenant_id", "{user}", "") + `))`,
				ProgramAssetsExclude: "NOT a.program_only",
			}},
	)
	return filterspec.MustRegistry(filterspec.Registry{
		Name:          "assets",
		TenantSQL:     "a.tenant_id",
		ScopeAssetSQL: colID,
		IDSQL:         "a.id",
		DefaultSort:   []filterspec.SortKey{{Field: "created_at", Desc: true}},
		Search: &filterspec.Search{
			Template: `(a.name ILIKE {arg} OR a.description ILIKE {arg} OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(
				CASE WHEN jsonb_typeof(a.properties -> 'aliases') = 'array' THEN a.properties -> 'aliases' ELSE '[]'::jsonb END) AS al(v)
				WHERE al.v ILIKE {arg}))`,
			Pattern: true,
			Fields:  []string{"name", "description", "aliases"},
		},
		Aliases: Aliases(),
	}, fields...)
}

func lensNames() []string {
	ls := asset.AllLenses()
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = string(l)
	}
	return out
}

func technologyCategoryNames() []string {
	cs := assettech.AllCategories()
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = string(c)
	}
	return out
}

func livenessNames() []string {
	ss := liveness.AllStates()
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

func monitoringStateNames() []string {
	ss := asset.MonitoringStates()
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

func discoveryRuleNames() []string {
	return []string{
		string(attribution.RuleVerifiedRoot), string(attribution.RuleAssertedRoot), string(attribution.RuleTenantScanned),
		string(attribution.RuleScanDiscovered), string(attribution.RuleMatchesScopeTarget), string(attribution.RuleCertificateSAN),
	}
}

// attributionFilterNames are the stored states plus the filter words of
// attribution.ParseFilter.
func attributionFilterNames() []string {
	stored := storedAttributionStates()
	out := make([]string, 0, 5+len(stored))
	out = append(out, attribution.FilterAll, attribution.FilterUnrecorded, attribution.FilterUnconfirmed,
		attribution.FilterApproved, attribution.FilterAttributed)
	for _, s := range stored {
		out = append(out, string(s))
	}
	return out
}

// attributionExpand maps each filter word to the stored states it means
// (attribution.ParseFilter); "unknown" is an asset with no record.
func attributionExpand() map[string][]string {
	unknown := attribution.FilterUnrecorded
	states := func(ss ...attribution.State) []string {
		out := make([]string, 0, len(ss)+1)
		for _, s := range ss {
			out = append(out, string(s))
		}
		return out
	}
	all := states(storedAttributionStates()...)
	return map[string][]string{
		attribution.FilterAll:         append(all, unknown),
		attribution.FilterUnconfirmed: states(attribution.StateNeedsReview, attribution.StateCandidate),
		attribution.FilterApproved: append(states(attribution.StateConfirmed, attribution.StateDiscovered,
			attribution.StateDependency, attribution.StateMonitorOnly), unknown),
		attribution.FilterAttributed: append(states(attribution.StateConfirmed, attribution.StateDependency,
			attribution.StateMonitorOnly), unknown),
		string(attribution.StateConfirmed): {unknown},
	}
}

// storedAttributionStates are the states attribution.State.Valid accepts.
func storedAttributionStates() []attribution.State {
	return []attribution.State{attribution.StateConfirmed, attribution.StateDiscovered, attribution.StateNeedsReview,
		attribution.StateCandidate, attribution.StateDependency, attribution.StateMonitorOnly, attribution.StateRejected}
}
