package asset

// The assets field registry: the allowlist the custom query language
// (pkg/querylang, docs/architecture/query-language.md) parses and compiles
// asset queries against. Columns are qualified with the bare table name
// ("assets."), because queries read FROM assets without an alias.
//
// Left out on purpose: free-form properties, descriptions, owner contact
// data, sync errors and integration references. They are not dimensions
// anyone groups by, and some carry personal or secret data.

import (
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

var (
	assetInNotIn = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}
	assetRanges  = []filterspec.Op{filterspec.OpGte, filterspec.OpGt, filterspec.OpLte, filterspec.OpLt}
)

// AssetEnvironments are the values of assets.environment (its check
// constraint).
func AssetEnvironments() []string {
	return []string{"production", "staging", "development", "testing", "dr"}
}

// AssetFields is the assets registry.
var AssetFields = filterspec.MustRegistry(filterspec.Registry{
	Name:          "assets",
	TenantSQL:     "assets.tenant_id",
	ScopeAssetSQL: "assets.id",
	IDSQL:         "assets.id",
	Search:        &filterspec.Search{Template: `assets.name ILIKE {arg}`, Pattern: true},
},
	filterspec.Field{Name: "id", Type: filterspec.TypeID, Ops: assetInNotIn, SQL: "assets.id"},
	filterspec.Field{Name: "name", Type: filterspec.TypeString, Ops: []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn, filterspec.OpContains}, SQL: "assets.name"},
	filterspec.Field{Name: "type", Type: filterspec.TypeEnum, Enum: assetTypeNames(), Ops: assetInNotIn, SQL: "assets.asset_type"},
	filterspec.Field{Name: "sub_type", Type: filterspec.TypeString, Ops: assetInNotIn, SQL: "assets.sub_type", Nullable: true},
	filterspec.Field{Name: "criticality", Type: filterspec.TypeEnum, Enum: assetCriticalityNames(), Ops: assetInNotIn, SQL: "assets.criticality"},
	filterspec.Field{Name: "status", Type: filterspec.TypeEnum, Enum: assetStatusNames(), Ops: assetInNotIn, SQL: "assets.status"},
	filterspec.Field{Name: "scope", Type: filterspec.TypeEnum, Enum: assetScopeNames(), Ops: assetInNotIn, SQL: "assets.scope"},
	filterspec.Field{Name: "exposure", Type: filterspec.TypeEnum, Enum: assetExposureNames(), Ops: assetInNotIn, SQL: "assets.exposure"},
	filterspec.Field{Name: "environment", Type: filterspec.TypeEnum, Enum: AssetEnvironments(), Ops: append(append([]filterspec.Op{}, assetInNotIn...), filterspec.OpIsNull),
		SQL: "assets.environment", Nullable: true},
	filterspec.Field{Name: "data_classification", Type: filterspec.TypeEnum, Enum: assetDataClassificationNames(), Ops: assetInNotIn,
		SQL: "assets.data_classification", Nullable: true},
	// A NULL flag counts as false.
	filterspec.Field{Name: "internet_facing", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "assets.is_internet_accessible",
		BoolTemplate: InternetFacingSQL("assets")},
	filterspec.Field{Name: "crown_jewel", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "assets.is_crown_jewel",
		BoolTemplate: "assets.is_crown_jewel"},
	filterspec.Field{Name: "tag", Type: filterspec.TypeString, Ops: assetInNotIn, SQL: "assets.tags",
		Templates: map[filterspec.Op]string{
			filterspec.OpIn:    "assets.tags && {arg}",
			filterspec.OpNotIn: "NOT COALESCE(assets.tags && {arg}, FALSE)",
		}},
	filterspec.Field{Name: "risk_score", Type: filterspec.TypeInt, Ops: assetRanges, SQL: "assets.risk_score", Sortable: true},
	filterspec.Field{Name: "discovery_source", Type: filterspec.TypeString, Ops: assetInNotIn, SQL: "assets.discovery_source", Nullable: true},
	filterspec.Field{Name: "provider", Type: filterspec.TypeString, Ops: assetInNotIn, SQL: "assets.provider", Nullable: true},
	filterspec.Field{Name: "first_seen", Type: filterspec.TypeTime, Ops: assetRanges, SQL: "assets.first_seen", Sortable: true},
	filterspec.Field{Name: "last_seen", Type: filterspec.TypeTime, Ops: assetRanges, SQL: "assets.last_seen", Sortable: true},
	filterspec.Field{Name: "discovered_at", Type: filterspec.TypeTime, Ops: assetRanges, SQL: "assets.discovered_at", Nullable: true},
	filterspec.Field{Name: "created_at", Type: filterspec.TypeTime, Ops: assetRanges, SQL: "assets.created_at", Sortable: true},
	// Server-side only (the query language never accepts them): soft
	// deletion and bug-bounty program assets.
	filterspec.Field{Name: "deleted", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "assets.deleted_at",
		BoolTemplate: "assets.deleted_at IS NOT NULL"},
	filterspec.Field{Name: "program_only", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "assets.program_only",
		BoolTemplate: "assets.program_only"},
)

func assetTypeNames() []string {
	ts := StoredAssetTypes()
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.String())
	}
	return out
}

func assetCriticalityNames() []string {
	cs := AllCriticalities()
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.String())
	}
	return out
}

func assetStatusNames() []string {
	ss := AllStatuses()
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.String())
	}
	return out
}

func assetScopeNames() []string {
	ss := AllScopes()
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.String())
	}
	return out
}

func assetExposureNames() []string {
	es := AllExposures()
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.String())
	}
	return out
}

func assetDataClassificationNames() []string {
	ds := AllDataClassifications()
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.String())
	}
	return out
}
