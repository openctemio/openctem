package posture

import "github.com/openctemio/openctem/api/pkg/filterspec"

// LiveSQL keeps facts whose asset still exists (not deleted, not
// program-only) and the row of issues without an asset. Facts are rebuilt on
// a schedule, so an asset deleted since then stops counting at once.
const LiveSQL = `(p.asset_id = '00000000-0000-0000-0000-000000000000'::uuid OR EXISTS (SELECT 1 FROM assets pa
	WHERE pa.tenant_id = p.tenant_id AND pa.id = p.asset_id AND pa.deleted_at IS NULL AND NOT pa.program_only))`

// Fields is the list query contract registry of GET
// /attack-surface/posture over easm_posture_assets (alias p). The data scope
// applies to each asset: a scoped reader's score sums only the assets they
// may see, and never the row of issues without an asset.
var Fields = filterspec.MustRegistry(filterspec.Registry{
	Name:          "attack_surface_posture",
	TenantSQL:     "p.tenant_id",
	ScopeAssetSQL: "p.asset_id",
	IDSQL:         "p.asset_id",
	DefaultSort:   []filterspec.SortKey{{Field: "root_domain"}},
},
	filterspec.Field{Name: "root_domain", Type: filterspec.TypeString,
		Ops: []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn, filterspec.OpContains}, SQL: "p.root_domain",
		Sortable: true, FreeText: true},
	filterspec.Field{Name: "criticality", Type: filterspec.TypeEnum, Enum: Criticalities(),
		Ops: []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}, SQL: "p.criticality"},
	filterspec.Field{Name: "asset_id", Type: filterspec.TypeID,
		Ops: []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}, SQL: "p.asset_id"},
)
