package filterspec

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TaskOwnerFindingSQL is the condition "the finding findingExpr is an active
// primary member of a live remediation task the user owns": the task is
// assigned to the user, or to a team in which the user is an active member
// whose membership has not expired. Placeholders $userArg (user) and
// $tenantArg (tenant). It is the ownership relation of the task owner's
// access to the findings they are asked to fix (RFC-117 task owner access):
// computed on every read, nothing is stored, so it ends by itself when the
// owner changes, the finding leaves the task, the task closes, or the
// membership ends, expires or is suspended.
//
// It grants nothing by itself: callers combine it with the asset not being
// hidden from the user (NotHiddenSQL) and use it only for viewing the task's
// findings and for the fix workflow.
func TaskOwnerFindingSQL(findingExpr string, userArg, tenantArg int) string {
	return fmt.Sprintf(`EXISTS (
		SELECT 1 FROM remediation_task_members rtm
		JOIN remediation_tasks rt ON rt.tenant_id = rtm.tenant_id AND rt.id = rtm.task_id
		WHERE rtm.tenant_id = $%[3]d AND rtm.finding_id = %[1]s
		  AND rtm.left_at IS NULL AND rtm.role = 'primary'
		  AND rt.state IN ('open', 'in_progress', 'verifying', 'on_hold')
		  AND principal_is_active($%[3]d, $%[2]d)
		  AND (rt.assignee_user_id = $%[2]d
		       OR rt.assignee_group_id IN (
		           SELECT gm.group_id FROM group_members gm
		           JOIN groups g ON g.id = gm.group_id AND g.tenant_id = $%[3]d AND g.is_active
		           WHERE gm.user_id = $%[2]d AND (gm.expires_at IS NULL OR gm.expires_at > now()))))`,
		findingExpr, userArg, tenantArg)
}

// TaskViewScopeSQL is ScopeSQL for a finding seen through a task: a
// restricted caller also sees the findings of the tasks they own
// (TaskOwnerFindingSQL), still never on an asset hidden from them. Used by
// the task reads (members, counters, filters). An unrestricted scope is
// ScopeSQL.
func TaskViewScopeSQL(assetExpr, findingExpr string, scope *shared.DataScope, first int) (string, []any) {
	cond, args := ScopeSQL(assetExpr, scope, first)
	if scope.Unrestricted || findingExpr == "" {
		return cond, args
	}
	return fmt.Sprintf(
		"((%s IN (SELECT uaa.asset_id FROM user_accessible_assets uaa WHERE uaa.user_id = $%d AND uaa.tenant_id = $%d) OR %s) AND %s)",
		assetExpr, first, first+1, TaskOwnerFindingSQL(findingExpr, first, first+1), NotHiddenSQL(assetExpr, first, first+1)), args
}
