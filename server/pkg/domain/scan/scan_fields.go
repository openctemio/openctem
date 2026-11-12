package scan

// The scans list on the list query contract: the registry of GET /scans and
// POST /scans/search. Design: docs/rfcs/RFC-048-list-query-contract.md; how
// to add a field: docs/architecture/list-query-contract.md.

import (
	"context"

	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

var (
	inNotIn = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}
	rangeOp = []filterspec.Op{filterspec.OpIn, filterspec.OpGte, filterspec.OpLte, filterspec.OpGt, filterspec.OpLt}
	timeOps = []filterspec.Op{filterspec.OpGte, filterspec.OpLte, filterspec.OpGt, filterspec.OpLt}
	textOps = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn, filterspec.OpContains}
)

// Names of the fields the list rules refer to.
const (
	fieldOrigin    = "origin"
	fieldArchive   = "archived"
	fieldAdHoc     = "ad_hoc"
	fieldName      = "name"
	fieldCreatedAt = "created_at"
	fieldLastRunAt = "last_run_at"
	fieldNextRunAt = "next_run_at"
	fieldTotalRuns = "total_runs"
)

// ScanTypes are the values of the scan_type field.
func ScanTypes() []string { return []string{string(ScanTypeWorkflow), string(ScanTypeSingle)} }

// ScheduleTypes are the values of the schedule_type field.
func ScheduleTypes() []string {
	return []string{
		string(ScheduleManual), string(ScheduleDaily), string(ScheduleWeekly), string(ScheduleMonthly),
		string(ScheduleCrontab), string(ScheduleRRule), string(ScheduleOnce),
	}
}

// Statuses are the values of the status field.
func Statuses() []string {
	return []string{string(StatusActive), string(StatusPaused), string(StatusDisabled)}
}

// SensorPreferences are the values of the sensor_preference field.
func SensorPreferences() []string {
	return []string{string(SensorPreferenceAuto), string(SensorPreferenceTenant), string(SensorPreferencePlatform)}
}

// Origins are the values of the origin field.
func Origins() []string { return []string{string(OriginUser), string(OriginSystem)} }

// scanRegistry is the registry config shared by Fields and ListFields. A
// scan is tenant configuration, not an asset row: the list applies no data
// scope today and keeps it that way (every member with scans:read sees the
// tenant's saved scans), so the registry is Unscoped. The tenant predicate
// is first in every compiled filter regardless.
var scanRegistry = filterspec.Registry{
	Name:        "scans",
	TenantSQL:   "scans.tenant_id",
	IDSQL:       "scans.id",
	Unscoped:    "scans are tenant configuration (schedules, targets, tools), not asset rows; the list is tenant-wide for every caller with scans:read",
	DefaultSort: []filterspec.SortKey{{Field: fieldName}},
	Search: &filterspec.Search{
		Template: `scans.name ILIKE {arg} ESCAPE '\' OR scans.description ILIKE {arg} ESCAPE '\'`,
		Pattern:  true,
		Fields:   []string{fieldName, "description"},
	},
	Aliases: map[string]filterspec.Alias{
		"search": {To: "q"},
		"tags":   {To: "tag"},
	},
}

// publicFields are the filterable fields of the scans list.
func publicFields() []filterspec.Field {
	return []filterspec.Field{
		{Name: "id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "scans.id", MaxValuesDocument: filterspec.MaxValuesDocument},
		{Name: fieldName, Type: filterspec.TypeString, Ops: textOps, SQL: "scans.name", Sortable: true, FreeText: true,
			Doc: "scan name pattern (* any characters, ? one)", Glob: true,
			Normalize: filterspec.NormalizeGlob, Expand: func(v string) []string { return []string{filterspec.GlobToLike(v)} },
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    `scans.name ILIKE ANY({arg})`,
				filterspec.OpNotIn: `NOT (scans.name ILIKE ANY({arg}))`,
			}},
		{Name: "status", Type: filterspec.TypeEnum, Enum: Statuses(), Ops: inNotIn, SQL: "scans.status", Indexed: true},
		{Name: "scan_type", Type: filterspec.TypeEnum, Enum: ScanTypes(), Ops: inNotIn, SQL: "scans.scan_type", Indexed: true},
		{Name: "schedule_type", Type: filterspec.TypeEnum, Enum: ScheduleTypes(), Ops: inNotIn, SQL: "scans.schedule_type", Indexed: true},
		{Name: "sensor_preference", Type: filterspec.TypeEnum, Enum: SensorPreferences(), Ops: inNotIn, SQL: "scans.sensor_preference", Nullable: true},
		// Who owns the scan: a person (user) or a platform policy (system).
		// One value, compiled to a constant predicate on managed_by.
		{Name: fieldOrigin, Type: filterspec.TypeEnum, Enum: Origins(), Ops: []filterspec.Op{filterspec.OpEq}, SQL: "scans.managed_by",
			EnumTemplates: map[string]string{
				string(OriginUser):   "scans.managed_by IS NULL",
				string(OriginSystem): "scans.managed_by IS NOT NULL",
			}},
		{Name: "tag", Type: filterspec.TypeString, Ops: inNotIn, SQL: "scans.tags", MaxValues: 20,
			Doc: "scan tag",
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    `COALESCE(scans.tags && {arg}, false)`,
				filterspec.OpNotIn: `NOT COALESCE(scans.tags && {arg}, false)`,
			}},
		// The scan's asset groups: the legacy single group and the list.
		{Name: "asset_group_id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "scans.asset_group_id", Nullable: true, MaxValues: 20,
			Doc: "asset group the scan covers",
			Templates: map[filterspec.Op]string{
				filterspec.OpIn:    `(scans.asset_group_id = ANY({arg}) OR COALESCE(scans.asset_group_ids && {arg}, false))`,
				filterspec.OpNotIn: `NOT (scans.asset_group_id = ANY({arg}) OR COALESCE(scans.asset_group_ids && {arg}, false))`,
			}},
		{Name: "scan_workflow_id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "scans.scan_workflow_id", Nullable: true},
		{Name: "profile_id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "scans.profile_id", Nullable: true},
		{Name: "scan_zone_id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "scans.scan_zone_id", Nullable: true, Indexed: true},
		{Name: "scanner_name", Type: filterspec.TypeString, Ops: textOps, SQL: "scans.scanner_name", Nullable: true, FreeText: true},
		{Name: "last_run_status", Type: filterspec.TypeString, Ops: inNotIn, SQL: "scans.last_run_status", Nullable: true},
		{Name: "created_by", Type: filterspec.TypeID, Ops: inNotIn, SQL: "scans.created_by", Nullable: true},
		{Name: fieldCreatedAt, Type: filterspec.TypeTime, Ops: timeOps, SQL: "scans.created_at", Sortable: true, Indexed: true},
		{Name: fieldLastRunAt, Type: filterspec.TypeTime, Ops: timeOps, SQL: "scans.last_run_at", Nullable: true, Sortable: true},
		{Name: fieldNextRunAt, Type: filterspec.TypeTime, Ops: timeOps, SQL: "scans.next_run_at", Nullable: true, Sortable: true},
		{Name: fieldTotalRuns, Type: filterspec.TypeInt, Ops: rangeOp, SQL: "scans.total_runs", Sortable: true},
		{Name: "failed_runs", Type: filterspec.TypeInt, Ops: rangeOp, SQL: "scans.failed_runs"},
	}
}

// Fields is the list query contract registry of GET /scans and POST
// /scans/search: the fields a request may filter and sort by.
var Fields = filterspec.MustRegistry(scanRegistry, publicFields()...)

// ListFields is Fields plus the two server-side visibility fields the list
// adds itself (WithListVisibility); a request can not name them. Lists are
// compiled with it.
var ListFields = func() *filterspec.Registry {
	reg, err := Fields.Extend(
		filterspec.Field{Name: fieldArchive, Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "scans.archived_at",
			BoolTemplate: "scans.archived_at IS NOT NULL"},
		filterspec.Field{Name: fieldAdHoc, Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "scans.ad_hoc",
			BoolTemplate: "scans.ad_hoc"},
	)
	if err != nil {
		panic(err)
	}
	return reg
}()

// WithListVisibility returns spec with the rules every scans list applies,
// whatever the request names:
//
//   - archived scans (never-run one-off scans the archive job retired) are
//     never listed;
//   - quick scans that were never saved (ad_hoc) are listed only when
//     includeAdHoc is set, or when the request asks for the scans the
//     platform manages (origin=system): those are ad hoc by nature.
//
// spec is not modified.
func WithListVisibility(spec *filterspec.Spec, includeAdHoc bool) *filterspec.Spec {
	rules := []*filterspec.Node{{Leaf: &filterspec.Leaf{Field: fieldArchive, Op: filterspec.OpEq, Values: []any{false}}}}
	if !includeAdHoc && !asksForSystemScans(spec) {
		rules = append(rules, &filterspec.Node{Leaf: &filterspec.Leaf{Field: fieldAdHoc, Op: filterspec.OpEq, Values: []any{false}}})
	}
	cp := *spec
	if spec.Root != nil {
		rules = append([]*filterspec.Node{spec.Root}, rules...)
	}
	cp.Root = &filterspec.Node{All: rules}
	return &cp
}

// asksForSystemScans reports whether the top-level AND of spec holds
// origin=system.
func asksForSystemScans(spec *filterspec.Spec) bool {
	if spec.Root == nil {
		return false
	}
	nodes := spec.Root.All
	if spec.Root.Leaf != nil {
		nodes = []*filterspec.Node{spec.Root}
	}
	for _, n := range nodes {
		if l := n.Leaf; l != nil && l.Field == fieldOrigin && l.Op == filterspec.OpEq && len(l.Values) == 1 && l.Values[0] == string(OriginSystem) {
			return true
		}
	}
	return false
}

// WhereReader reads one page of scans matching a filter compiled from
// ListFields (filterspec.Compile): its WHERE starts with the tenant
// predicate and carries WithListVisibility's rules.
type WhereReader interface {
	ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*Scan], error)
}
