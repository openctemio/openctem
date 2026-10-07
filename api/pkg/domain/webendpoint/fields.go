package webendpoint

import (
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// Fields is the list query contract registry of GET /web-endpoints
// (docs/rfcs/RFC-048-list-query-contract.md). The data scope applies to the
// origin asset: an endpoint is listed exactly when its origin is visible.
var Fields = filterspec.MustRegistry(filterspec.Registry{
	Name:          "web_endpoints",
	TenantSQL:     "e.tenant_id",
	ScopeAssetSQL: "e.origin_asset_id",
	IDSQL:         "e.id",
	DefaultSort:   []filterspec.SortKey{{Field: "last_seen_at", Desc: true}},
	Search: &filterspec.Search{
		Template: `e.path_template ILIKE {arg} ESCAPE '\' OR e.example_path ILIKE {arg} ESCAPE '\'`,
		Pattern:  true,
	},
},
	filterspec.Field{Name: "id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "e.id", MaxValuesDocument: filterspec.MaxValuesDocument},
	filterspec.Field{Name: "origin_asset_id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "e.origin_asset_id", Indexed: true},
	filterspec.Field{Name: "method", Type: filterspec.TypeEnum, Enum: Methods(), Ops: inNotIn, SQL: "e.method", Sortable: true},
	filterspec.Field{Name: "kind", Type: filterspec.TypeEnum, Enum: Kinds(), Ops: inNotIn, SQL: "e.kind", Sortable: true},
	filterspec.Field{Name: "auth_state", Type: filterspec.TypeEnum, Enum: AuthStates(), Ops: inNotIn, SQL: "e.auth_state", Sortable: true},
	filterspec.Field{Name: "state", Type: filterspec.TypeEnum, Enum: []string{string(StateActive), string(StateGone), string(StateIgnored)},
		Ops: inNotIn, SQL: "e.state", Sortable: true},
	filterspec.Field{Name: "in_scope", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "e.in_scope"},
	filterspec.Field{Name: "source", Type: filterspec.TypeEnum, Enum: Sources(), Ops: []filterspec.Op{filterspec.OpIn},
		SQL: "e.sources", Templates: map[filterspec.Op]string{filterspec.OpIn: "e.sources && {arg}"}},
	filterspec.Field{Name: "label", Type: filterspec.TypeString, Ops: []filterspec.Op{filterspec.OpIn},
		SQL: "e.labels", Templates: map[filterspec.Op]string{filterspec.OpIn: "e.labels && {arg}"}},
	filterspec.Field{Name: "catalog_key", Type: filterspec.TypeString, Ops: inNotIn, SQL: "e.catalog_key", Nullable: true},
	filterspec.Field{Name: "path_hash", Type: filterspec.TypeString, Ops: []filterspec.Op{filterspec.OpIn}, SQL: "e.path_hash", Indexed: true},
	filterspec.Field{Name: "path_template", Type: filterspec.TypeString, Ops: []filterspec.Op{filterspec.OpContains},
		SQL: "e.path_template", Sortable: true, FreeText: true},
	filterspec.Field{Name: "last_status", Type: filterspec.TypeInt, Ops: []filterspec.Op{filterspec.OpIn, filterspec.OpGte, filterspec.OpLte},
		SQL: "e.last_status", Nullable: true, Sortable: true},
	filterspec.Field{Name: "param_count", Type: filterspec.TypeInt, Ops: []filterspec.Op{filterspec.OpGte, filterspec.OpLte},
		SQL: "e.param_count", Sortable: true},
	filterspec.Field{Name: "first_seen_at", Type: filterspec.TypeTime, Ops: timeOps, SQL: "e.first_seen_at", Sortable: true, Indexed: true},
	filterspec.Field{Name: "last_seen_at", Type: filterspec.TypeTime, Ops: timeOps, SQL: "e.last_seen_at", Sortable: true},
	filterspec.Field{Name: "last_changed_at", Type: filterspec.TypeTime, Ops: timeOps, SQL: "e.last_changed_at", Nullable: true, Sortable: true},
)

var (
	inNotIn = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}
	timeOps = []filterspec.Op{filterspec.OpGte, filterspec.OpLte, filterspec.OpGt, filterspec.OpLt}
)

// Methods are the stored methods.
func Methods() []string {
	return []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "ANY"}
}

// Kinds are the stored kinds (static files are never stored).
func Kinds() []string {
	out := []string{}
	for _, k := range ctis.AllEndpointKinds() {
		if k != ctis.EndpointKindStatic {
			out = append(out, string(k))
		}
	}
	return out
}

// AuthStates are the stored auth states.
func AuthStates() []string {
	out := []string{}
	for _, a := range ctis.AllEndpointAuths() {
		out = append(out, string(a))
	}
	return out
}

// Sources are the endpoint sources.
func Sources() []string {
	out := []string{}
	for _, s := range ctis.AllEndpointSources() {
		out = append(out, string(s))
	}
	return out
}
