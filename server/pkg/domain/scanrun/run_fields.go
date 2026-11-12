package scanrun

// The tenant-wide runs list on the list query contract: the registry of GET
// /scan-runs. Design: docs/rfcs/RFC-048-list-query-contract.md; how to add a
// field: docs/architecture/list-query-contract.md.

import (
	"context"

	"github.com/openctemio/openctem/server/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

var (
	runInNotIn = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}
	runRangeOp = []filterspec.Op{filterspec.OpIn, filterspec.OpGte, filterspec.OpLte, filterspec.OpGt, filterspec.OpLt}
	runTimeOps = []filterspec.Op{filterspec.OpGte, filterspec.OpLte, filterspec.OpGt, filterspec.OpLt}
)

// Names of the fields the list rules refer to.
const (
	runFieldKind        = "kind"
	runFieldCreatedAt   = "created_at"
	runFieldStartedAt   = "started_at"
	runFieldCompletedAt = "completed_at"
	runFieldFindings    = "total_findings"
)

// RunStatuses are the values of the status field.
func RunStatuses() []string {
	return []string{
		string(RunStatusPending), string(RunStatusRunning), string(RunStatusCompleted), string(RunStatusPartial),
		string(RunStatusFailed), string(RunStatusCanceled), string(RunStatusTimeout), string(RunStatusBlocked),
	}
}

// RunKinds are the values of the kind field.
func RunKinds() []string {
	return []string{
		string(RunKindScan), string(RunKindQuick), string(RunKindRetest), string(RunKindValidation),
		string(RunKindTest), string(RunKindConnector), string(RunKindSystem),
	}
}

// RunTriggers are the values of the trigger_type field.
func RunTriggers() []string {
	return []string{
		string(scanworkflow.TriggerTypeManual), string(scanworkflow.TriggerTypeSchedule), string(scanworkflow.TriggerTypeWebhook),
		string(scanworkflow.TriggerTypeAPI), string(scanworkflow.TriggerTypeOnAssetDiscovery),
		string(scanworkflow.TriggerTypeSystem), string(scanworkflow.TriggerTypeAutomation),
	}
}

// managedScanSQL is "the run belongs to a scan a platform policy manages",
// pinned to the run's tenant on both sides.
const managedScanSQL = `EXISTS (SELECT 1 FROM scans ms WHERE ms.id = scan_runs.scan_id AND ms.tenant_id = scan_runs.tenant_id AND ms.managed_by IS NOT NULL)`

// RunFields is the list query contract registry of GET /scan-runs: the
// fields a request may filter and sort by. A run is tenant configuration
// history (what the platform did for the organization), not an asset row:
// the list applies no data scope today and keeps it that way, so the
// registry is Unscoped; the tenant predicate is first in every filter.
var RunFields = filterspec.MustRegistry(filterspec.Registry{
	Name:        "scan_runs",
	TenantSQL:   "scan_runs.tenant_id",
	IDSQL:       "scan_runs.id",
	Unscoped:    "scan runs are the history of tenant scans (schedules, workflows), not asset rows; the list is tenant-wide for every caller with scans:read",
	DefaultSort: []filterspec.SortKey{{Field: runFieldCreatedAt, Desc: true}},
},
	filterspec.Field{Name: "id", Type: filterspec.TypeID, Ops: runInNotIn, SQL: "scan_runs.id", MaxValuesDocument: filterspec.MaxValuesDocument},
	filterspec.Field{Name: "status", Type: filterspec.TypeEnum, Enum: RunStatuses(), Ops: runInNotIn, SQL: "scan_runs.status", Nullable: true, Indexed: true},
	filterspec.Field{Name: runFieldKind, Type: filterspec.TypeEnum, Enum: RunKinds(), Ops: runInNotIn, SQL: "scan_runs.kind", Indexed: true},
	filterspec.Field{Name: "trigger_type", Type: filterspec.TypeEnum, Enum: RunTriggers(), Ops: runInNotIn, SQL: "scan_runs.trigger_type"},
	filterspec.Field{Name: "scan_id", Type: filterspec.TypeID, Ops: runInNotIn, SQL: "scan_runs.scan_id", Nullable: true, Indexed: true},
	filterspec.Field{Name: "scan_workflow_id", Type: filterspec.TypeID, Ops: runInNotIn, SQL: "scan_runs.scan_workflow_id", Nullable: true, Indexed: true},
	filterspec.Field{Name: "asset_id", Type: filterspec.TypeID, Ops: runInNotIn, SQL: "scan_runs.asset_id", Nullable: true, Indexed: true},
	// Who owns the scan of the run: a person (user) or a platform policy
	// (system). One value, compiled to a constant predicate.
	filterspec.Field{Name: "origin", Type: filterspec.TypeEnum, Enum: []string{string(RunOriginUser), string(RunOriginSystem)},
		Ops: []filterspec.Op{filterspec.OpEq}, SQL: "scan_runs.scan_id",
		EnumTemplates: map[string]string{
			string(RunOriginUser):   "NOT " + managedScanSQL,
			string(RunOriginSystem): managedScanSQL,
		}},
	filterspec.Field{Name: runFieldCreatedAt, Type: filterspec.TypeTime, Ops: runTimeOps, SQL: "scan_runs.created_at", Sortable: true, Indexed: true},
	filterspec.Field{Name: runFieldStartedAt, Type: filterspec.TypeTime, Ops: runTimeOps, SQL: "scan_runs.started_at", Nullable: true, Sortable: true},
	filterspec.Field{Name: runFieldCompletedAt, Type: filterspec.TypeTime, Ops: runTimeOps, SQL: "scan_runs.completed_at", Nullable: true, Sortable: true},
	// Seconds from start to completion; unset while the run is open.
	filterspec.Field{Name: "duration", Type: filterspec.TypeInt, Ops: runRangeOp, Nullable: true, Sortable: true,
		SQL: "(EXTRACT(EPOCH FROM (scan_runs.completed_at - scan_runs.started_at)))::bigint", Doc: "run duration in seconds"},
	filterspec.Field{Name: runFieldFindings, Type: filterspec.TypeInt, Ops: runRangeOp, SQL: "scan_runs.total_findings", Nullable: true, Sortable: true},
)

// RunListRules returns spec with the rules the runs list adds whatever the
// request names. spec is not modified.
//
//   - System runs (housekeeping) are left out unless includeSystem is set or
//     the request names a kind.
//   - hideFindingRuns leaves out the runs about one finding (retests and
//     validations) for a caller who may not see findings.
func RunListRules(spec *filterspec.Spec, includeSystem, hideFindingRuns bool) *filterspec.Spec {
	var hide []any
	if !includeSystem && !namesKind(spec) {
		hide = append(hide, string(RunKindSystem))
	}
	if hideFindingRuns {
		hide = append(hide, string(RunKindRetest), string(RunKindValidation))
	}
	if len(hide) == 0 {
		return spec
	}
	rule := &filterspec.Node{Leaf: &filterspec.Leaf{Field: runFieldKind, Op: filterspec.OpNotIn, Values: hide}}
	cp := *spec
	if spec.Root == nil {
		cp.Root = rule
	} else {
		cp.Root = &filterspec.Node{All: []*filterspec.Node{spec.Root, rule}}
	}
	return &cp
}

// namesKind reports whether the top-level AND of spec asks for kinds (kind=
// or kind in), not merely leaves some out.
func namesKind(spec *filterspec.Spec) bool {
	if spec.Root == nil {
		return false
	}
	nodes := spec.Root.All
	if spec.Root.Leaf != nil {
		nodes = []*filterspec.Node{spec.Root}
	}
	for _, n := range nodes {
		if l := n.Leaf; l != nil && l.Field == runFieldKind && (l.Op == filterspec.OpIn || l.Op == filterspec.OpEq) {
			return true
		}
	}
	return false
}

// RunWhereReader reads one page of runs matching a filter compiled from
// RunFields (filterspec.Compile): its WHERE starts with the tenant
// predicate and carries RunListRules.
type RunWhereReader interface {
	ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*Run], error)
}
