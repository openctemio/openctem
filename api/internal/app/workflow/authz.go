package workflow

// Who an automation run acts as, and what it may touch.
//
// Every run acts as one person, the principal:
//
//   - a manual run acts as the member who started it (run.TriggeredBy);
//   - an event run acts as the automation's owner (workflows.created_by: the
//     member lifecycle already pauses and reassigns automations by this
//     column, and saving or switching on an automation makes the editor its
//     owner).
//
// Before each action or notification step the principal is checked again,
// live: an active member of the tenant, holding the step's permission (the
// one the equivalent direct API route needs), with the run's subject (the
// finding or asset the step reads or changes) inside their data scope. A
// failed check fails the step; nothing is done with more access than the
// principal has now. The step then runs with the principal in its context,
// so the services it calls apply the same data scope.

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
)

// ErrCodeRunNotAuthorized is the step error code when the run's principal
// may not run the step (gone, lost the permission, subject out of scope).
const ErrCodeRunNotAuthorized = "AUTOMATION_RUN_NOT_AUTHORIZED"

// NodePermission returns the permission a member needs to build a node with
// this config, and that the run's principal needs when the node runs. It
// mirrors the direct API route for the same change: update_status needs
// FindingsWrite like PATCH /findings/{id}/status, trigger_scan needs
// ScansWrite, and so on. Outbound HTTP needs IntegrationsManage (it sends
// data to an address of the editor's choosing, like configuring an
// integration does); a notification needs IntegrationsRead. The bool is false
// for trigger and condition nodes, which need nothing beyond the workflow
// permission.
func NodePermission(c workflowdom.NodeConfig) (permission.Permission, bool) {
	switch c.ActionType {
	case "":
	case workflowdom.ActionTypeAssignUser, workflowdom.ActionTypeAssignTeam,
		workflowdom.ActionTypeUpdatePriority, workflowdom.ActionTypeUpdateStatus,
		workflowdom.ActionTypeAddTags, workflowdom.ActionTypeRemoveTags,
		workflowdom.ActionTypeCreateTicket, workflowdom.ActionTypeUpdateTicket,
		workflowdom.ActionTypeTriggerAITriage:
		return permission.FindingsWrite, true
	case workflowdom.ActionTypeTriggerScan:
		return permission.ScansWrite, true
	case workflowdom.ActionTypeTriggerPipeline:
		return permission.ScanWorkflowsWrite, true
	case workflowdom.ActionTypeHTTPRequest:
		return permission.IntegrationsManage, true
	default:
		// An action type with no mapping (run_script, which never runs) is
		// refused for everyone but administrators rather than allowed.
		return permission.IntegrationsManage, true
	}
	if c.NotificationType != "" {
		return permission.IntegrationsRead, true
	}
	return "", false
}

// StepAuthorization is one check before a step runs.
type StepAuthorization struct {
	TenantID shared.ID
	// PrincipalID is the person the run acts as; zero when there is none
	// (an automation with no owner), which is refused.
	PrincipalID shared.ID
	// Permission the principal must hold; "" for none.
	Permission permission.Permission
	// FindingIDs and AssetIDs are the subjects the step reads or changes.
	// Each must be inside the principal's data scope.
	FindingIDs []shared.ID
	AssetIDs   []shared.ID
}

// StepAuthorizer decides whether the run's principal may run a step. On
// success it returns the context the step runs with (carrying the principal,
// so the services the step calls apply the principal's data scope).
type StepAuthorizer interface {
	AuthorizeStep(ctx context.Context, req StepAuthorization) (context.Context, error)
}

// Principal is the identity a step runs as.
type Principal struct {
	TenantID    shared.ID
	UserID      shared.ID
	IsAdmin     bool
	Permissions []string
}

// PrincipalContextFunc returns ctx carrying p as the acting user (wired at the
// composition root to the request auth keys, so data-scope checks inside the
// services see the principal instead of an unrestricted internal call).
type PrincipalContextFunc func(ctx context.Context, p Principal) context.Context

// MemberReader reads a membership and whether the member and their account
// are both active.
type MemberReader interface {
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
	IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}

// PermissionReader returns a user's permissions in a tenant (the union of
// their roles).
type PermissionReader interface {
	GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error)
}

// ScopeChecker answers data-scope questions for a user outside a request.
type ScopeChecker interface {
	AssertFindingForUser(ctx context.Context, tenantID, userID, findingID shared.ID) error
	ForUser(ctx context.Context, tenantID, userID shared.ID) (*shared.DataScope, error)
	Filter(ctx context.Context, scope *shared.DataScope, assetIDs []shared.ID) (func(shared.ID) bool, error)
}

// PrincipalAuthorizer is the production StepAuthorizer.
type PrincipalAuthorizer struct {
	members       MemberReader
	permissions   PermissionReader
	scope         ScopeChecker
	withPrincipal PrincipalContextFunc
}

// NewPrincipalAuthorizer creates a PrincipalAuthorizer. withPrincipal may be
// nil (the step then runs with ctx unchanged).
func NewPrincipalAuthorizer(members MemberReader, perms PermissionReader, scope ScopeChecker, withPrincipal PrincipalContextFunc) *PrincipalAuthorizer {
	return &PrincipalAuthorizer{members: members, permissions: perms, scope: scope, withPrincipal: withPrincipal}
}

// errNotAuthorized builds the refusal for a step. kind is ErrForbidden for
// a missing principal or permission and ErrNotFound for a subject outside the
// principal's scope (the answer does not confirm the subject exists).
func errNotAuthorized(kind error, msg string) error {
	return shared.NewDomainError(ErrCodeRunNotAuthorized, msg, kind)
}

// AuthorizeStep implements StepAuthorizer. Any lookup error refuses.
func (a *PrincipalAuthorizer) AuthorizeStep(ctx context.Context, req StepAuthorization) (context.Context, error) {
	if a == nil || a.members == nil || a.permissions == nil || a.scope == nil {
		return ctx, errNotAuthorized(shared.ErrForbidden, "automation run authorization is not configured")
	}
	if req.PrincipalID.IsZero() {
		return ctx, errNotAuthorized(shared.ErrForbidden, "the automation has no owner to act as; save it again to become its owner")
	}
	active, err := a.members.IsActiveTenantMember(ctx, req.TenantID, req.PrincipalID)
	if err != nil {
		return ctx, fmt.Errorf("check the run's principal: %w", err)
	}
	if !active {
		return ctx, errNotAuthorized(shared.ErrForbidden, "the person this run acts as is no longer an active member")
	}
	m, err := a.members.GetMembership(ctx, req.PrincipalID, req.TenantID)
	if err != nil {
		return ctx, fmt.Errorf("read the run's principal: %w", err)
	}
	p := Principal{TenantID: req.TenantID, UserID: req.PrincipalID, IsAdmin: m.IsOwner() || m.IsAdmin()}
	if !p.IsAdmin {
		perms, err := a.permissions.GetUserPermissions(ctx, req.TenantID.String(), req.PrincipalID.String())
		if err != nil {
			return ctx, fmt.Errorf("read the run's principal permissions: %w", err)
		}
		p.Permissions = perms
		if req.Permission != "" && !slices.Contains(perms, string(req.Permission)) {
			return ctx, errNotAuthorized(shared.ErrForbidden,
				fmt.Sprintf("the person this run acts as does not hold '%s'", req.Permission))
		}
	}
	for _, fid := range req.FindingIDs {
		if err := a.scope.AssertFindingForUser(ctx, req.TenantID, req.PrincipalID, fid); err != nil {
			return ctx, errSubjectNotFound
		}
	}
	if len(req.AssetIDs) > 0 {
		sc, err := a.scope.ForUser(ctx, req.TenantID, req.PrincipalID)
		if err != nil {
			return ctx, errSubjectNotFound
		}
		if sc != nil {
			in, err := a.scope.Filter(ctx, sc, req.AssetIDs)
			if err != nil {
				return ctx, fmt.Errorf("check asset scope: %w", err)
			}
			for _, id := range req.AssetIDs {
				if !in(id) {
					return ctx, errSubjectNotFound
				}
			}
		}
	}
	if a.withPrincipal != nil {
		ctx = a.withPrincipal(ctx, p)
	}
	return ctx, nil
}

// IsRunNotAuthorized reports whether err is a step refusal.
func IsRunNotAuthorized(err error) bool {
	var de *shared.DomainError
	return errors.As(err, &de) && de.Code == ErrCodeRunNotAuthorized
}

// runPrincipal is the person a run acts as: the member who started a manual
// run, otherwise the automation's owner.
func runPrincipal(run *workflowdom.Run, wf *workflowdom.Workflow) shared.ID {
	if run.TriggerType == workflowdom.TriggerTypeManual && run.TriggeredBy != nil {
		return *run.TriggeredBy
	}
	if wf.CreatedBy != nil {
		return *wf.CreatedBy
	}
	return shared.ID{}
}

// stepSubjects returns the findings and assets a step reads or changes: the
// finding an action names in its config, and the run's subject (the
// trigger's finding, asset and discovered assets).
func stepSubjects(actionConfig, trigger map[string]any) (findings, assets []shared.ID) {
	addFinding := func(v any) {
		if s, ok := v.(string); ok && s != "" {
			if id, err := shared.IDFromString(s); err == nil && !slices.Contains(findings, id) {
				findings = append(findings, id)
			}
		}
	}
	addAsset := func(v any) {
		if s, ok := v.(string); ok && s != "" {
			if id, err := shared.IDFromString(s); err == nil && !slices.Contains(assets, id) {
				assets = append(assets, id)
			}
		}
	}
	if actionConfig != nil {
		addFinding(actionConfig["finding_id"])
		addAsset(actionConfig["asset_id"])
	}
	if f, ok := trigger["finding"].(map[string]any); ok {
		addFinding(f["id"])
	}
	addFinding(trigger["finding_id"])
	if a, ok := trigger["asset"].(map[string]any); ok {
		addAsset(a["id"])
	}
	if list, ok := trigger["assets"].([]map[string]any); ok {
		for _, a := range list {
			addAsset(a["id"])
		}
	}
	if list, ok := trigger["assets"].([]any); ok {
		for _, v := range list {
			if a, ok := v.(map[string]any); ok {
				addAsset(a["id"])
			}
		}
	}
	return findings, assets
}
