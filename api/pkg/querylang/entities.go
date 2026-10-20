package querylang

import (
	"sort"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// The entities of this version: findings and assets. Every field comes
// from the entity's filterspec registry; nothing here builds SQL from
// input.

// findingAssetSubquery is "the finding's asset, in the caller's tenant,
// matches cond" for a relation field. {tenant} pins the asset to the
// tenant even though findings.asset_id already belongs to it.
func findingAssetSubquery(cond string) string {
	return "findings.asset_id IN (SELECT a.id FROM assets a WHERE a.tenant_id = {tenant} AND " + cond + ")"
}

func findingAssetNotIn(cond string) string {
	return "findings.asset_id IS NULL OR findings.asset_id NOT IN (SELECT a.id FROM assets a WHERE a.tenant_id = {tenant} AND " + cond + ")"
}

func assetEnumRelation(name, column string, enum []string) filterspec.Field {
	return filterspec.Field{Name: name, Type: filterspec.TypeEnum, Enum: enum, SQL: "findings.asset_id",
		Ops: []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}, Permission: permission.AssetsRead.String(),
		Templates: map[filterspec.Op]string{
			filterspec.OpIn:    findingAssetSubquery("a." + column + " = ANY({arg})"),
			filterspec.OpNotIn: findingAssetNotIn("a." + column + " = ANY({arg})"),
		}}
}

func assetBoolRelation(name, column string) filterspec.Field {
	return filterspec.Field{Name: name, Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "findings.asset_id",
		Permission: permission.AssetsRead.String(), BoolTemplate: findingAssetSubquery("a." + column)}
}

func enumOf(reg *filterspec.Registry, name string) []string {
	f, _ := reg.Field(name)
	return append([]string(nil), f.Enum...)
}

// withPermission is a copy of a list registry field that needs perm in
// queries.
func withPermission(reg *filterspec.Registry, name, perm string) filterspec.Field {
	f, _ := reg.Field(name)
	c := *f
	c.Permission = perm
	return c
}

// textSearchField is the internal field behind `text ~ "..."`: the
// registry's search template as a contains operator (the value is bound as
// an escaped ILIKE pattern), so a text search is a condition like any
// other and may sit anywhere in the filter.
func textSearchField(reg *filterspec.Registry) filterspec.Field {
	return filterspec.Field{Name: "text_search", Type: filterspec.TypeString, Ops: []filterspec.Op{filterspec.OpContains},
		SQL: reg.IDSQL, Templates: map[filterspec.Op]string{filterspec.OpContains: reg.Search.Template}}
}

// findingQueryFields extends the findings list registry with the curated
// finding -> asset relation (asset attributes need assets:read) and the
// server-side program exclusion.
var findingQueryFields = func() *filterspec.Registry {
	reg, err := vulnerability.FindingFields.Extend(
		assetEnumRelation("asset_type", "asset_type", enumOf(asset.AssetFields, "type")),
		assetEnumRelation("asset_environment", "environment", asset.AssetEnvironments()),
		assetEnumRelation("asset_exposure", "exposure", enumOf(asset.AssetFields, "exposure")),
		filterspec.Field{Name: "asset_internet_facing", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "findings.asset_id",
			Permission: permission.AssetsRead.String(), BoolTemplate: findingAssetSubquery(asset.InternetFacingSQL("a"))},
		assetBoolRelation("asset_crown_jewel", "is_crown_jewel"),
		withPermission(vulnerability.FindingFields, "asset_criticality", permission.AssetsRead.String()),
		withPermission(vulnerability.FindingFields, "asset_tag", permission.AssetsRead.String()),
		withPermission(vulnerability.FindingFields, "asset_owner_id", permission.AssetsRead.String()),
		textSearchField(vulnerability.FindingFields),
		filterspec.Field{Name: "program_asset", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "findings.asset_id",
			BoolTemplate: findingAssetSubquery("a.program_only")},
	)
	if err != nil {
		panic(err)
	}
	return reg
}()

// Findings is the findings entity.
var Findings = MustEntity(EntityDef{
	Name: "findings", Noun: "findings", Permission: permission.FindingsRead.String(),
	Registry: findingQueryFields,
	Paths: map[string]string{
		"asset.type": "asset_type", "asset.environment": "asset_environment", "asset.exposure": "asset_exposure",
		"asset.internet_facing": "asset_internet_facing", "asset.crown_jewel": "asset_crown_jewel",
		"asset.criticality": "asset_criticality", "asset.tag": "asset_tag", "asset.owner_id": "asset_owner_id",
	},
	Internal:  []string{"program_asset", "text_search"},
	TextField: "text_search",
	Dimensions: []string{
		"severity", "status", "source", "sla_status", "priority_class", "finding_type", "observation", "validation",
		"tool_name", "family", "cve_id", "rule_id", "is_in_kev", "is_reachable", "network_transport", "network_service",
		"asset.type", "asset.criticality", "asset.environment", "asset.exposure", "asset.internet_facing", "asset.crown_jewel",
	},
	Measures: []string{"cvss_score", "epss_score"},
	Times:    []string{"first_detected_at", "last_seen_at", "resolved_at", "created_at"},
	Mandatory: []Mandatory{
		{Leaf: &filterspec.Leaf{Field: "status", Op: filterspec.OpNotIn, Values: []any{"draft", "in_review"}},
			Why: "pentest findings still in draft or in review are left out"},
		{Leaf: &filterspec.Leaf{Field: "branch_only", Op: filterspec.OpEq, Values: []any{false}},
			Why: "findings seen only on branches that do not count as exposure are left out"},
		{Leaf: &filterspec.Leaf{Field: "program_asset", Op: filterspec.OpEq, Values: []any{false}},
			Why: "findings on bug-bounty program assets are left out"},
	},
})

// assetQueryFields is the assets registry plus the text search field.
var assetQueryFields = func() *filterspec.Registry {
	reg, err := asset.AssetFields.Extend(textSearchField(asset.AssetFields))
	if err != nil {
		panic(err)
	}
	return reg
}()

// Assets is the assets entity.
var Assets = MustEntity(EntityDef{
	Name: "assets", Noun: "assets", Permission: permission.AssetsRead.String(),
	Registry:  assetQueryFields,
	Internal:  []string{"deleted", "program_only", "text_search"},
	TextField: "text_search",
	Dimensions: []string{
		"type", "sub_type", "criticality", "status", "scope", "exposure", "environment", "data_classification",
		"internet_facing", "crown_jewel", "discovery_source", "provider",
	},
	Measures: []string{"risk_score"},
	Times:    []string{"first_seen", "last_seen", "discovered_at", "created_at"},
	Mandatory: []Mandatory{
		{Leaf: &filterspec.Leaf{Field: "deleted", Op: filterspec.OpEq, Values: []any{false}},
			Why: "deleted assets are left out"},
		{Leaf: &filterspec.Leaf{Field: "program_only", Op: filterspec.OpEq, Values: []any{false}},
			Why: "bug-bounty program assets are left out"},
	},
})

var entities = map[string]*Entity{Findings.Name: Findings, Assets.Name: Assets}

// Lookup returns an entity by name.
func Lookup(name string) (*Entity, bool) {
	e, ok := entities[name]
	return e, ok
}

// EntityNames lists the entities, sorted.
func EntityNames() []string {
	out := make([]string, 0, len(entities))
	for n := range entities {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
