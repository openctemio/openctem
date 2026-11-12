package exposure

// The Exposure Items view of the external attack surface
// (docs/architecture/exposure-taxonomy.md, "Exposure Items view"): every
// exposure of the tenant with the asset it is on, read through the list
// query contract (docs/rfcs/RFC-048-list-query-contract.md), so the tenant
// and the caller's data scope are always in the WHERE.
//
// The query reads exposure_events (alias e) joined to its live asset (a, an
// exposure without an asset has none). The asset's monitoring state is the
// lateral ms (ms.state, NULL without an asset); the repository adds that join
// only when a filter or sort reads it. A restricted caller sees only the
// exposures of assets in their scope: an exposure without an asset is not in
// anyone's scope and only unrestricted callers see it.

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Item is one exposure with the asset it is on. AssetName, AssetType and
// MonitoringState are empty for an exposure without a (live) asset.
type Item struct {
	Event           *ExposureEvent
	AssetName       string
	AssetType       string
	MonitoringState string
	// Primary: the asset is one of the organization's root domains
	// (asset.PrimarySQL).
	Primary bool
}

// ItemStats are the counts of one filtered set, for the summary strip.
type ItemStats struct {
	Total      int64
	BySeverity map[string]int64
	ByCategory map[string]int64
	ByState    map[string]int64
}

// AssetGroup is one asset of a filtered set with the counts of its
// exposures: the group-by-asset form of the list.
type AssetGroup struct {
	AssetID         string
	AssetName       string
	AssetType       string
	MonitoringState string
	Primary         bool
	Total           int64
	BySeverity      map[string]int64
	// TopSeverity is the highest effective severity among its exposures.
	TopSeverity string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// ItemReader reads the view. Every method takes a filter compiled for
// ItemFields from placeholder $2: $1 is the tenant's unclassified-scans mode
// (true when assets no scope entry covers are scanned), an input of the
// monitoring state.
type ItemReader interface {
	ListItems(ctx context.Context, w *filterspec.Where, scanned bool, page pagination.Pagination) (pagination.Result[*Item], error)
	ItemStats(ctx context.Context, w *filterspec.Where, scanned bool) (*ItemStats, error)
	ItemsByAsset(ctx context.Context, w *filterspec.Where, scanned bool, page pagination.Pagination) (pagination.Result[*AssetGroup], error)
}

// ItemFilterFirstArg is the first placeholder of an ItemFields filter.
const ItemFilterFirstArg = 2

// SeverityRankSQL orders the effective severity (info 1 .. critical 5).
const SeverityRankSQL = "array_position(ARRAY['info','low','medium','high','critical']::text[], e.severity::text)"

// MonitoringStateSQL is the column the monitoring state is read from.
const MonitoringStateSQL = "ms.state"

// CategorySQL is the display category of e.event_type, from the same map as
// EventType.Category, so a filter and the row label never disagree.
var CategorySQL = categorySQL()

func categorySQL() string {
	types := AllEventTypes()
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	var b strings.Builder
	b.WriteString("(CASE e.event_type")
	for _, t := range types {
		b.WriteString(" WHEN '" + string(t) + "' THEN '" + string(t.Category()) + "'")
	}
	b.WriteString(" ELSE '" + string(CategoryOther) + "' END)")
	return b.String()
}

// categoryKeys are the values of the category field.
func categoryKeys() []string {
	all := Categories()
	out := make([]string, len(all))
	for i, c := range all {
		out[i] = string(c.Key)
	}
	return out
}

func toStrings[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

func monitoringStates() []string { return toStrings(asset.MonitoringStates()) }

var (
	itemInNotIn = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}
	itemTextOps = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn, filterspec.OpContains}
	itemTimeOps = []filterspec.Op{filterspec.OpGte, filterspec.OpLte, filterspec.OpGt, filterspec.OpLt}
	itemBoolEq  = []filterspec.Op{filterspec.OpEq}
)

// ItemFields is the list query contract registry of GET
// /attack-surface/exposures (and its /stats and /assets forms).
var ItemFields = filterspec.MustRegistry(filterspec.Registry{
	Name:          "exposure_items",
	TenantSQL:     "e.tenant_id",
	ScopeAssetSQL: "e.asset_id",
	IDSQL:         "e.id",
	DefaultSort:   []filterspec.SortKey{{Field: "severity", Desc: true}, {Field: "last_seen", Desc: true}},
	Search: &filterspec.Search{
		Template: `e.title ILIKE {arg} ESCAPE '\' OR a.name ILIKE {arg} ESCAPE '\'`,
		Pattern:  true,
	},
},
	filterspec.Field{Name: "id", Type: filterspec.TypeID, Ops: itemInNotIn, SQL: "e.id", MaxValuesDocument: filterspec.MaxValuesDocument},
	filterspec.Field{Name: "severity", Type: filterspec.TypeEnum, Enum: toStrings(AllSeverities()), Ops: itemInNotIn,
		SQL: "e.severity", SortSQL: SeverityRankSQL, Sortable: true},
	filterspec.Field{Name: "state", Type: filterspec.TypeEnum, Enum: toStrings(AllStates()), Ops: itemInNotIn,
		SQL: "e.state", Sortable: true},
	filterspec.Field{Name: "event_type", Type: filterspec.TypeEnum, Enum: toStrings(AllEventTypes()), Ops: itemInNotIn,
		SQL: "e.event_type", Sortable: true},
	filterspec.Field{Name: "category", Type: filterspec.TypeEnum, Enum: categoryKeys(), Ops: itemInNotIn, SQL: CategorySQL},
	filterspec.Field{Name: "source", Type: filterspec.TypeString, Ops: itemTextOps, SQL: "e.source", FreeText: true},
	filterspec.Field{Name: "asset_id", Type: filterspec.TypeID, Ops: itemInNotIn, SQL: "e.asset_id", Nullable: true},
	filterspec.Field{Name: "asset_name", Type: filterspec.TypeString, Ops: itemTextOps, SQL: "a.name", Nullable: true,
		Sortable: true, FreeText: true},
	filterspec.Field{Name: "asset_type", Type: filterspec.TypeString, Ops: itemInNotIn, SQL: "a.asset_type", Nullable: true},
	filterspec.Field{Name: "asset_monitoring_state", Type: filterspec.TypeEnum, Enum: monitoringStates(), Ops: itemInNotIn,
		SQL: MonitoringStateSQL, Nullable: true},
	filterspec.Field{Name: "primary", Type: filterspec.TypeBool, Ops: itemBoolEq, SQL: "a.id",
		BoolTemplate: "(a.id IS NOT NULL AND " + asset.PrimarySQL("a") + ")"},
	filterspec.Field{Name: "severity_overridden", Type: filterspec.TypeBool, Ops: itemBoolEq, SQL: "e.severity_overridden_at",
		BoolTemplate: "e.severity_overridden_at IS NOT NULL"},
	filterspec.Field{Name: "first_seen", Type: filterspec.TypeTime, Ops: itemTimeOps, SQL: "e.first_seen_at", Sortable: true},
	filterspec.Field{Name: "last_seen", Type: filterspec.TypeTime, Ops: itemTimeOps, SQL: "e.last_seen_at", Sortable: true},
)
