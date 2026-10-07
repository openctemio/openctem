package workflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
)

// FindingReader reads one finding of a tenant.
type FindingReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
}

// AssetReader reads one asset of a tenant.
type AssetReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.Asset, error)
}

// WithWorkflowStepAuthorizer sets the principal check a manual run passes
// before it is created (the same check the executor repeats per step).
func WithWorkflowStepAuthorizer(a StepAuthorizer) WorkflowServiceOption {
	return func(s *WorkflowService) {
		s.authorizer = a
	}
}

// WithWorkflowSubjectReaders sets the readers a manual run loads its subject
// with.
func WithWorkflowSubjectReaders(findings FindingReader, assets AssetReader) WorkflowServiceOption {
	return func(s *WorkflowService) {
		s.findings = findings
		s.assets = assets
	}
}

// errSubjectNotFound answers a subject that does not exist exactly like one
// outside the data scope of the person the run acts as.
var errSubjectNotFound = errNotAuthorized(shared.ErrNotFound, "subject not found in the data scope of the person this run acts as")

// ManualRunInput starts an automation by hand on at most one subject.
//
// The caller names the subject by id only. The run's data is built here from
// the stored finding or asset, never taken from the request, so a caller
// cannot point an automation at an entity by forging its trigger data.
type ManualRunInput struct {
	TenantID   shared.ID
	UserID     shared.ID
	WorkflowID shared.ID
	FindingID  *shared.ID
	AssetID    *shared.ID
}

// TriggerManualRun starts a manual run. It acts as the caller: the caller
// must hold the permission of every action and notification step and have
// the subject in their data scope, checked here (so the refusal reaches the
// caller) and again before each step runs.
func (s *WorkflowService) TriggerManualRun(ctx context.Context, input ManualRunInput) (*workflowdom.Run, error) {
	if input.UserID.IsZero() {
		return nil, shared.NewDomainError(ErrCodeRunNotAuthorized, "a manual run acts as the person who starts it; no user in the request", shared.ErrForbidden)
	}
	if input.FindingID != nil && input.AssetID != nil {
		return nil, shared.NewDomainError("VALIDATION", "pass finding_id or asset_id, not both", shared.ErrValidation)
	}
	w, err := s.workflowRepo.GetWithGraph(ctx, input.WorkflowID)
	if err != nil {
		return nil, err
	}
	if w.TenantID != input.TenantID {
		return nil, shared.ErrNotFound
	}

	data := map[string]any{"event_type": string(workflowdom.TriggerTypeManual)}
	var findingIDs, assetIDs []shared.ID
	switch {
	case input.FindingID != nil:
		if s.findings == nil {
			return nil, fmt.Errorf("manual run on a finding: finding reader not configured")
		}
		f, err := s.findings.GetByID(ctx, input.TenantID, *input.FindingID)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return nil, errSubjectNotFound
			}
			return nil, fmt.Errorf("load the run's finding: %w", err)
		}
		data["finding"] = findingTriggerSummary(f)
		findingIDs = []shared.ID{f.ID()}
	case input.AssetID != nil:
		if s.assets == nil {
			return nil, fmt.Errorf("manual run on an asset: asset reader not configured")
		}
		a, err := s.assets.GetByID(ctx, input.TenantID, *input.AssetID)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return nil, errSubjectNotFound
			}
			return nil, fmt.Errorf("load the run's asset: %w", err)
		}
		data["asset"] = assetTriggerSummary(a)
		assetIDs = []shared.ID{a.ID()}
	}

	if err := s.authorizeManualRun(ctx, w, input.UserID, findingIDs, assetIDs); err != nil {
		return nil, err
	}

	return s.TriggerWorkflow(ctx, TriggerWorkflowInput{
		TenantID:    input.TenantID,
		UserID:      input.UserID,
		WorkflowID:  input.WorkflowID,
		TriggerType: workflowdom.TriggerTypeManual,
		TriggerData: data,
	})
}

// authorizeManualRun checks the caller against every step of the workflow:
// each step's permission, and the subject plus any finding a step names in
// its config inside the caller's data scope.
func (s *WorkflowService) authorizeManualRun(ctx context.Context, w *workflowdom.Workflow, userID shared.ID, findingIDs, assetIDs []shared.ID) error {
	if s.authorizer == nil {
		return shared.NewDomainError(ErrCodeRunNotAuthorized, "automation run authorization is not configured", shared.ErrForbidden)
	}
	checked := false
	for _, n := range w.Nodes {
		perm, required := NodePermission(n.Config)
		if !required {
			continue
		}
		f, a := stepSubjects(n.Config.ActionConfig, nil)
		if _, err := s.authorizer.AuthorizeStep(ctx, StepAuthorization{
			TenantID:    w.TenantID,
			PrincipalID: userID,
			Permission:  perm,
			FindingIDs:  append(f, findingIDs...),
			AssetIDs:    append(a, assetIDs...),
		}); err != nil {
			return err
		}
		checked = true
	}
	if !checked {
		// No action step: still the caller must be an active member with
		// the subject in scope.
		if _, err := s.authorizer.AuthorizeStep(ctx, StepAuthorization{
			TenantID:    w.TenantID,
			PrincipalID: userID,
			FindingIDs:  findingIDs,
			AssetIDs:    assetIDs,
		}); err != nil {
			return err
		}
	}
	return nil
}

// findingTriggerSummary is the finding a run sees in its trigger data.
func findingTriggerSummary(f *vulnerability.Finding) map[string]any {
	return map[string]any{
		"id":        f.ID().String(),
		"title":     f.Title(),
		"severity":  string(f.Severity()),
		"status":    string(f.Status()),
		"source":    string(f.Source()),
		"tool_name": f.ToolName(),
		"asset_id":  f.AssetID().String(),
	}
}
