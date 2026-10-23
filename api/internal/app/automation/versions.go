package automation

// Versions and modes (RFC-125 §5). Publishing stores the draft graph as an
// immutable version and makes it the one live runs execute. A run of a live
// automation pins the published version; a run of a simulate automation
// executes the draft and records what it would do.

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WithWorkflowVersions sets the version store (required for publishing and
// for runs of live automations).
func WithWorkflowVersions(r automationdom.VersionRepository) WorkflowServiceOption {
	return func(s *WorkflowService) { s.versions = r }
}

// WithExecutorVersions sets the version store the executor loads a live
// run's definition from.
func WithExecutorVersions(r automationdom.VersionRepository) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) { e.versions = r }
}

// WorkflowDetail is an automation with its draft graph and the versions
// that matter to the editor.
type WorkflowDetail struct {
	Workflow *automationdom.Workflow
	// Published is the version live runs execute (nil before the first publish).
	Published *automationdom.Version
	// Pending is the newest version waiting for a second person (nil when none).
	Pending *automationdom.Version
	// DraftChanged: the draft differs from the published version.
	DraftChanged bool
	// RiskClass is the class of the draft.
	RiskClass automationdom.RiskClass
}

// GetWorkflowDetail returns the automation, its draft graph, its published and
// pending versions, whether the draft changed since the publish, and the
// draft's risk class.
func (s *WorkflowService) GetWorkflowDetail(ctx context.Context, tenantID, workflowID shared.ID) (*WorkflowDetail, error) {
	w, err := s.GetWorkflow(ctx, tenantID, workflowID)
	if err != nil {
		return nil, err
	}
	def := automationdom.DefinitionOf(w)
	d := &WorkflowDetail{Workflow: w, RiskClass: def.Risk()}
	if s.versions == nil {
		return d, nil
	}
	versions, err := s.versions.ListByAutomation(ctx, tenantID, workflowID, 20)
	if err != nil {
		return nil, fmt.Errorf("list automation versions: %w", err)
	}
	for _, v := range versions {
		switch {
		case v.Status == automationdom.VersionPublished && d.Published == nil:
			d.Published = v
		case v.Status == automationdom.VersionPendingApproval && d.Pending == nil:
			d.Pending = v
		}
	}
	d.DraftChanged = d.Published == nil || d.Published.Definition.Digest() != def.Digest()
	return d, nil
}

// PublishedDefinition returns the definition of the automation's published
// version (empty when it has none).
func (s *WorkflowService) PublishedDefinition(ctx context.Context, tenantID, workflowID shared.ID) (automationdom.Definition, error) {
	w, err := s.workflowRepo.GetByTenantAndID(ctx, tenantID, workflowID)
	if err != nil {
		return automationdom.Definition{}, err
	}
	if w.PublishedVersionID == nil || s.versions == nil {
		return automationdom.Definition{}, nil
	}
	v, err := s.versions.GetByTenantAndID(ctx, tenantID, *w.PublishedVersionID)
	if err != nil {
		return automationdom.Definition{}, fmt.Errorf("load the published version: %w", err)
	}
	return v.Definition, nil
}

// ListVersions lists an automation's versions, newest first.
func (s *WorkflowService) ListVersions(ctx context.Context, tenantID, workflowID shared.ID) ([]*automationdom.Version, error) {
	if _, err := s.workflowRepo.GetByTenantAndID(ctx, tenantID, workflowID); err != nil {
		return nil, err
	}
	if s.versions == nil {
		return nil, nil
	}
	return s.versions.ListByAutomation(ctx, tenantID, workflowID, 100)
}

// GetVersion returns one version of the automation (404 for a version of
// another automation or tenant).
func (s *WorkflowService) GetVersion(ctx context.Context, tenantID, workflowID, versionID shared.ID) (*automationdom.Version, error) {
	if s.versions == nil {
		return nil, shared.ErrNotFound
	}
	v, err := s.versions.GetByTenantAndID(ctx, tenantID, versionID)
	if err != nil {
		return nil, err
	}
	if v.AutomationID != workflowID {
		return nil, shared.ErrNotFound
	}
	return v, nil
}

// PublishInput asks to make the automation's draft live.
type PublishInput struct {
	TenantID   shared.ID
	UserID     shared.ID
	WorkflowID shared.ID
	// Authorize checks the caller may publish exactly this definition (the
	// permission of every step). The service calls it on the definition it
	// is about to store, not on a copy read earlier, so an edit between the
	// check and the store cannot slip an unchecked step in. Required: a nil
	// Authorize refuses the publish.
	Authorize func(automationdom.Definition) error
}

// PublishResult is the outcome of a publish.
type PublishResult struct {
	Version *automationdom.Version
	// Live: the version is now the one live runs execute.
	Live bool
}

// Publish stores the draft as a new version and makes it live. The draft
// must hold only known types and a valid graph. The publisher becomes the
// automation's owner: live runs act as the person who published them.
func (s *WorkflowService) Publish(ctx context.Context, in PublishInput) (*PublishResult, error) {
	if s.versions == nil {
		return nil, fmt.Errorf("%w: automation versions are not configured", shared.ErrNotImplemented)
	}
	w, err := s.GetWorkflow(ctx, in.TenantID, in.WorkflowID)
	if err != nil {
		return nil, err
	}
	if err := w.ValidateSupported(); err != nil {
		return nil, err
	}
	if err := w.ValidateGraph(); err != nil {
		return nil, err
	}
	return s.publishDefinition(ctx, in, w, audit.ActionWorkflowPublished, "published")
}

// Rollback publishes an older version's definition again, as a new version
// (the history keeps every version).
func (s *WorkflowService) Rollback(ctx context.Context, in PublishInput, versionID shared.ID) (*PublishResult, error) {
	old, err := s.GetVersion(ctx, in.TenantID, in.WorkflowID, versionID)
	if err != nil {
		return nil, err
	}
	w, err := s.workflowRepo.GetByTenantAndID(ctx, in.TenantID, in.WorkflowID)
	if err != nil {
		return nil, err
	}
	target := old.Definition.Materialize(w)
	if err := target.ValidateSupported(); err != nil {
		return nil, err
	}
	if err := target.ValidateGraph(); err != nil {
		return nil, err
	}
	return s.publishDefinition(ctx, in, target, audit.ActionWorkflowRolledBack,
		fmt.Sprintf("rolled back to version %d", old.Version))
}

func (s *WorkflowService) publishDefinition(ctx context.Context, in PublishInput, w *automationdom.Workflow, action audit.Action, verb string) (*PublishResult, error) {
	tenantID, userID := in.TenantID, in.UserID
	v, err := automationdom.NewVersion(w, userID, automationdom.VersionPendingApproval)
	if err != nil {
		return nil, err
	}
	// The permission check runs on the definition that is stored below.
	if in.Authorize == nil {
		return nil, shared.NewDomainError("FORBIDDEN", "publishing needs a permission check", shared.ErrForbidden)
	}
	if err := in.Authorize(v.Definition); err != nil {
		return nil, err
	}
	now := time.Now()
	// One transaction: a failure leaves no pending row behind.
	if err := s.versions.CreateAndPublish(ctx, v, nil, now); err != nil {
		return nil, err
	}
	v.Status = automationdom.VersionPublished
	v.PublishedAt = &now
	if err := s.takeOwnership(ctx, w, userID); err != nil {
		return nil, err
	}
	s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: userID.String()},
		auditapp.NewSuccessEvent(action, audit.ResourceTypeWorkflow, w.ID.String()).
			WithResourceName(w.Name).
			WithMessage(fmt.Sprintf("Automation '%s' %s as version %d (%s risk)", w.Name, verb, v.Version, v.RiskClass)).
			WithMetadata("version", v.Version).
			WithMetadata("version_id", v.ID.String()).
			WithMetadata("digest", v.Digest).
			WithMetadata("risk_class", string(v.RiskClass)))
	return &PublishResult{Version: v, Live: true}, nil
}

// ChangeMode switches an automation to simulate. Live is reached only by
// publishing (Publish), so the go-live gate cannot be skipped.
func (s *WorkflowService) ChangeMode(ctx context.Context, tenantID, userID, workflowID shared.ID, mode automationdom.Mode) (*automationdom.Workflow, error) {
	if mode != automationdom.ModeSimulate {
		return nil, shared.NewDomainError("MODE_LIVE_NEEDS_PUBLISH", "an automation goes live by publishing it", shared.ErrValidation)
	}
	w, err := s.workflowRepo.GetByTenantAndID(ctx, tenantID, workflowID)
	if err != nil {
		return nil, err
	}
	if w.Mode == mode {
		return w, nil
	}
	setter, ok := s.workflowRepo.(automationdom.ModeSetter)
	if !ok {
		return nil, fmt.Errorf("%w: the repository cannot set the mode", shared.ErrNotImplemented)
	}
	if err := setter.SetMode(ctx, tenantID, workflowID, mode); err != nil {
		return nil, err
	}
	w.Mode = mode
	s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: userID.String()},
		auditapp.NewSuccessEvent(audit.ActionWorkflowModeChanged, audit.ResourceTypeWorkflow, w.ID.String()).
			WithResourceName(w.Name).
			WithMessage(fmt.Sprintf("Automation '%s' switched to %s", w.Name, mode)).
			WithMetadata("mode", string(mode)))
	return w, nil
}

// runGraph returns the graph a new run of w executes and the run's mode and
// version: the published version for a live automation, the draft for a
// simulate one. w must have its draft graph loaded.
func (s *WorkflowService) runGraph(ctx context.Context, w *automationdom.Workflow) (*automationdom.Workflow, automationdom.Mode, *automationdom.Version, error) {
	if w.Mode != automationdom.ModeLive {
		return w, automationdom.ModeSimulate, nil, nil
	}
	if w.PublishedVersionID == nil || s.versions == nil {
		return nil, "", nil, shared.NewDomainError(automationdom.ErrCodeNotPublished, "the automation is live but has no published version", shared.ErrValidation)
	}
	v, err := s.versions.GetByTenantAndID(ctx, w.TenantID, *w.PublishedVersionID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("load the published version: %w", err)
	}
	return v.Definition.Materialize(w), automationdom.ModeLive, v, nil
}
