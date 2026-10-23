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
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
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

// UserDirectory reads accounts by id (the names shown next to a version).
type UserDirectory interface {
	GetByIDs(ctx context.Context, ids []shared.ID) ([]*userdom.User, error)
}

// WithWorkflowUserDirectory sets where version publisher and approver names
// are read from.
func WithWorkflowUserDirectory(d UserDirectory) WorkflowServiceOption {
	return func(s *WorkflowService) { s.users = d }
}

// VersionNames returns the display names of the people who published or
// approved the versions (best effort: an unknown id has no name).
func (s *WorkflowService) VersionNames(ctx context.Context, versions ...*automationdom.Version) map[shared.ID]string {
	names := map[shared.ID]string{}
	if s.users == nil {
		return names
	}
	var ids []shared.ID
	for _, v := range versions {
		if v == nil {
			continue
		}
		for _, id := range []*shared.ID{v.PublishedBy, v.ApprovedBy} {
			if id != nil {
				ids = append(ids, *id)
			}
		}
	}
	if len(ids) == 0 {
		return names
	}
	users, err := s.users.GetByIDs(ctx, ids)
	if err != nil {
		s.logger.Warn("failed to read version publisher names", "error", err)
		return names
	}
	for _, u := range users {
		names[u.ID()] = u.Name()
	}
	return names
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
	// Names of the people who published or approved Published and Pending.
	Names map[shared.ID]string
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
	d.Names = s.VersionNames(ctx, d.Published, d.Pending)
	return d, nil
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
}

// PublishResult is the outcome of a publish.
type PublishResult struct {
	Version *automationdom.Version
	// Live: the version is now the one live runs execute. False when a
	// high-risk version waits for a second person's approval.
	Live bool
}

// ErrCodeWorkflowInvalid is the error code of a publish refused because the
// draft has blocking validate problems (WorkflowInvalidError).
const ErrCodeWorkflowInvalid = "WORKFLOW_INVALID"

// WorkflowInvalidError refuses a publish whose draft has blocking problems.
type WorkflowInvalidError struct {
	Problems []Problem
}

func (e *WorkflowInvalidError) Error() string {
	return fmt.Sprintf("the automation has %d problem(s) to fix before it can go live", len(e.Problems))
}

// Unwrap makes it a validation error (400).
func (e *WorkflowInvalidError) Unwrap() error { return shared.ErrValidation }

// SetStepUpGate sets the recent re-authentication check publishing elevated
// and high-risk automations needs. Without one such publishes are refused
// (fail closed).
func (s *WorkflowService) SetStepUpGate(g shared.RecentAuthGate) { s.stepUp = g }

// Publish makes the draft live through the go-live gate (RFC-125 D6):
//   - the draft must hold only known types, a valid graph and no blocking
//     validate problem;
//   - low risk: published at once;
//   - elevated: the caller must have re-authenticated recently;
//   - high: re-authentication, and the version waits until a second person
//     with the publish permission approves its digest (ApproveVersion).
//
// The publisher becomes the owner live runs act as.
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
	res, err := s.Validate(ctx, DraftInput{TenantID: in.TenantID, UserID: in.UserID, WorkflowID: in.WorkflowID})
	if err != nil {
		return nil, err
	}
	if len(res.Problems) > 0 {
		return nil, &WorkflowInvalidError{Problems: res.Problems}
	}
	return s.publishDefinition(ctx, in.TenantID, in.UserID, w, audit.ActionWorkflowPublished, "published")
}

// Rollback publishes an older version's definition again, as a new version
// (the history keeps every version), through the same gate as its risk.
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
	// An older version may predate a guardrail (an update_status target a
	// person decides, a request without its reason): it is not published
	// again as it was.
	if err := validateNodeConfigs(old.Definition.Configs()...); err != nil {
		return nil, err
	}
	return s.publishDefinition(ctx, in.TenantID, in.UserID, target, audit.ActionWorkflowRolledBack,
		fmt.Sprintf("rolled back to version %d", old.Version))
}

// requireStepUp checks the caller re-authenticated recently (fail closed
// without a gate).
func (s *WorkflowService) requireStepUp(ctx context.Context, userID shared.ID) error {
	if s.stepUp == nil {
		return fmt.Errorf("%w: step-up re-authentication is not configured", shared.ErrForbidden)
	}
	return s.stepUp.RequireRecentAuth(ctx, userID.String())
}

func (s *WorkflowService) publishDefinition(ctx context.Context, tenantID, userID shared.ID, w *automationdom.Workflow, action audit.Action, verb string) (*PublishResult, error) {
	if userID.IsZero() {
		// The publisher is the person live runs act as.
		return nil, fmt.Errorf("%w: an automation is published by a person", shared.ErrForbidden)
	}
	v, err := automationdom.NewVersion(w, userID, automationdom.VersionPendingApproval)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if v.RiskClass.NeedsStepUp() {
		if err := s.requireStepUp(ctx, userID); err != nil {
			return nil, err
		}
		v.StepUpAt = &now
	}
	// A new request replaces any version still waiting for approval.
	if err := s.versions.RetirePending(ctx, tenantID, w.ID); err != nil {
		return nil, err
	}
	if err := s.versions.Create(ctx, v); err != nil {
		return nil, err
	}
	actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorID: userID.String()}
	event := func(a audit.Action, msg string) auditapp.AuditEvent {
		return auditapp.NewSuccessEvent(a, audit.ResourceTypeWorkflow, w.ID.String()).
			WithResourceName(w.Name).WithMessage(msg).
			WithMetadata("version", v.Version).WithMetadata("version_id", v.ID.String()).
			WithMetadata("digest", v.Digest).WithMetadata("risk_class", string(v.RiskClass)).
			WithSeverity(audit.SeverityMedium)
	}
	if v.RiskClass.NeedsSecondApprover() {
		s.logAudit(ctx, actx, event(audit.ActionWorkflowPublishRequested,
			fmt.Sprintf("Automation '%s' version %d (%s risk) waits for a second person to approve it", w.Name, v.Version, v.RiskClass)))
		return &PublishResult{Version: v, Live: false}, nil
	}
	if err := s.versions.Publish(ctx, tenantID, w.ID, v.ID, nil, now); err != nil {
		return nil, err
	}
	v.Status, v.PublishedAt = automationdom.VersionPublished, &now
	if err := s.takeOwnership(ctx, w, userID); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, event(action, fmt.Sprintf("Automation '%s' %s as version %d (%s risk)", w.Name, verb, v.Version, v.RiskClass)))
	return &PublishResult{Version: v, Live: true}, nil
}

// draftDigest is the digest of the automation's draft ("" when versions are
// not configured or the draft cannot be read).
func (s *WorkflowService) draftDigest(ctx context.Context, tenantID, workflowID shared.ID) string {
	if s.versions == nil {
		return ""
	}
	w, err := s.GetWorkflow(ctx, tenantID, workflowID)
	if err != nil {
		return ""
	}
	return automationdom.DefinitionOf(w).Digest()
}

// withdrawRequestIfChanged retires the version waiting for approval when an
// edit changed what the draft does (its digest differs from before). The
// second person reviews the automation as the editor shows it, so a request
// cannot stay approvable after the draft moved away from it (the publisher
// asks again). An unknown before-digest withdraws (fail safe).
func (s *WorkflowService) withdrawRequestIfChanged(ctx context.Context, tenantID, workflowID shared.ID, before string) error {
	if s.versions == nil {
		return nil
	}
	if before != "" && s.draftDigest(ctx, tenantID, workflowID) == before {
		return nil
	}
	return s.versions.RetirePending(ctx, tenantID, workflowID)
}

// ApproveVersion is the second person's approval of a high-risk version: the
// approver holds the publish permission (route), re-authenticated recently,
// is not the publisher, and names the digest they reviewed. The version goes
// live and its publisher becomes the owner live runs act as.
func (s *WorkflowService) ApproveVersion(ctx context.Context, tenantID, userID, workflowID, versionID shared.ID, digest string) (*automationdom.Version, error) {
	v, err := s.GetVersion(ctx, tenantID, workflowID, versionID)
	if err != nil {
		return nil, err
	}
	if v.Status != automationdom.VersionPendingApproval {
		return nil, automationdom.ErrVersionNotPending
	}
	if userID.IsZero() || v.PublishedBy == nil || *v.PublishedBy == userID {
		return nil, automationdom.ErrSelfApproval
	}
	if digest != v.Digest {
		return nil, automationdom.ErrVersionDigestChanged
	}
	if err := s.requireStepUp(ctx, userID); err != nil {
		return nil, err
	}
	now := time.Now()
	if err := s.versions.Publish(ctx, tenantID, workflowID, v.ID, &userID, now); err != nil {
		return nil, err
	}
	w, err := s.workflowRepo.GetByTenantAndID(ctx, tenantID, workflowID)
	if err != nil {
		return nil, err
	}
	if err := s.takeOwnership(ctx, w, *v.PublishedBy); err != nil {
		return nil, err
	}
	v.Status, v.ApprovedBy, v.ApprovedAt = automationdom.VersionPublished, &userID, &now
	s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: userID.String()},
		auditapp.NewSuccessEvent(audit.ActionWorkflowVersionApproved, audit.ResourceTypeWorkflow, workflowID.String()).
			WithResourceName(w.Name).
			WithMessage(fmt.Sprintf("Automation '%s' version %d approved and live", w.Name, v.Version)).
			WithMetadata("version", v.Version).WithMetadata("version_id", v.ID.String()).
			WithMetadata("digest", v.Digest).WithMetadata("published_by", v.PublishedBy.String()).
			WithSeverity(audit.SeverityMedium))
	return v, nil
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
