package handler

import (
	"context"
	"net/http"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/workflow"
)

// actionNodePermission returns the platform permission a user must hold to use
// a given workflow action type, mirroring the authZ of the equivalent direct
// API route (e.g. update_status ⇄ PATCH /findings/{id}/status requires
// FindingsWrite; trigger_scan ⇄ ScansWrite; trigger_pipeline ⇄ PipelinesWrite).
//
// Without this gate a user granted only WorkflowsWrite
// ("findings:workflows:write") could build a workflow whose action nodes
// execute finding mutations, scans and pipeline runs they were never granted —
// an intra-tenant privilege escalation, since permission matching is exact (no
// wildcard implies WorkflowsWrite ⊃ FindingsWrite). The bool is false when the
// action needs nothing beyond WorkflowsWrite: disabled run_script, and outbound
// http_request which mutates no platform resource.
func actionNodePermission(actionType string) (permission.Permission, bool) {
	switch workflow.ActionType(actionType) {
	case workflow.ActionTypeAssignUser, workflow.ActionTypeAssignTeam,
		workflow.ActionTypeUpdatePriority, workflow.ActionTypeUpdateStatus,
		workflow.ActionTypeAddTags, workflow.ActionTypeRemoveTags,
		workflow.ActionTypeCreateTicket, workflow.ActionTypeUpdateTicket,
		workflow.ActionTypeTriggerAITriage:
		return permission.FindingsWrite, true
	case workflow.ActionTypeTriggerScan:
		return permission.ScansWrite, true
	case workflow.ActionTypeTriggerPipeline:
		return permission.PipelinesWrite, true
	}
	return "", false
}

// authorizeActionConfigs checks the caller holds the per-resource permission
// for every action node in the supplied node configs. It returns the first
// permission the caller lacks and false when unauthorized; ("", true) means the
// caller may create/update these nodes. Owners/admins bypass via
// middleware.HasPermission. nil configs and non-action nodes (empty ActionType)
// are ignored.
//
// Enforced at workflow create/graph-update/add-node/update-node so that the
// authority needed to *build* a privileged action is checked once by an
// authenticated user — covering both manual (POST /runs) and event-dispatched
// executions, which run with no actor context.
func authorizeActionConfigs(ctx context.Context, configs ...*NodeConfigRequest) (permission.Permission, bool) {
	for _, c := range configs {
		if c == nil || c.ActionType == "" {
			continue
		}
		if perm, required := actionNodePermission(c.ActionType); required && !middleware.HasPermission(ctx, string(perm)) {
			return perm, false
		}
	}
	return "", true
}

// requireActionPermissions runs authorizeActionConfigs and, when the caller is
// not authorized, writes a 403 (logging the denied permission) and returns
// false. Handlers should return immediately when it returns false.
func (h *WorkflowHandler) requireActionPermissions(w http.ResponseWriter, r *http.Request, configs ...*NodeConfigRequest) bool {
	if perm, ok := authorizeActionConfigs(r.Context(), configs...); !ok {
		h.logger.Warn("workflow action node permission denied",
			"user_id", middleware.GetUserID(r.Context()),
			"required_permission", string(perm))
		apierror.Forbidden("insufficient permission for a workflow action node; '" + string(perm) + "' is required").WriteJSON(w)
		return false
	}
	return true
}
