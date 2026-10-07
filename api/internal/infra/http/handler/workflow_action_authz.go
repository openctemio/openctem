package handler

import (
	"context"
	"net/http"

	workflowsvc "github.com/openctemio/openctem/api/internal/app/workflow"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// authorizeActionConfigs checks the caller holds the permission of every
// action and notification node in the supplied configs (see
// workflowsvc.NodePermission: the permission of the equivalent direct API
// route). It returns the first permission the caller lacks and false when
// unauthorized; ("", true) means the caller may build these nodes.
// Owners/admins bypass via middleware.HasPermission. nil configs and trigger
// or condition nodes are ignored.
//
// Without this gate a user granted only WorkflowsWrite
// ("findings:workflows:write") could build a workflow whose nodes change
// findings, start scans or send data out, which they were never granted (an
// intra-tenant privilege escalation: permission matching is exact). The same
// permissions are checked again, on the person a run acts as, before every
// step runs (workflowsvc.StepAuthorizer).
func authorizeActionConfigs(ctx context.Context, configs ...*NodeConfigRequest) (permission.Permission, bool) {
	for _, c := range configs {
		if c == nil {
			continue
		}
		if perm, required := workflowsvc.NodePermission(toNodeConfig(c)); required && !middleware.HasPermission(ctx, string(perm)) {
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

// requireWorkflowPermissions is requireActionPermissions over every node the
// stored workflow has, plus extra (the configs the request adds). Any change
// to what a workflow does (an edge, a deleted node, a trigger filter, switching
// it on) needs the permissions of all its steps: removing a condition in front
// of an action, or widening its trigger, changes what that action runs on as
// much as adding the action does. It writes the error and returns false when
// the caller may not.
func (h *WorkflowHandler) requireWorkflowPermissions(w http.ResponseWriter, r *http.Request, tenantID, workflowID shared.ID, extra ...*NodeConfigRequest) bool {
	wf, err := h.service.GetWorkflow(r.Context(), tenantID, workflowID)
	if err != nil {
		h.handleServiceError(w, err)
		return false
	}
	configs := make([]*NodeConfigRequest, 0, len(wf.Nodes)+len(extra))
	for _, n := range wf.Nodes {
		if n == nil {
			continue
		}
		c := n.Config
		configs = append(configs, &NodeConfigRequest{
			ActionType:       string(c.ActionType),
			NotificationType: string(c.NotificationType),
		})
	}
	configs = append(configs, extra...)
	return h.requireActionPermissions(w, r, configs...)
}
