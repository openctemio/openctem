package automation

// Reading runs follows the caller's data scope (RFC-125 D8): a run about a
// finding or asset outside the caller's scope is not listed and answers 404,
// and trace counts include only runs whose subject the caller may see. Runs
// without a subject (a scan finished) are visible to every reader.

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// WithWorkflowRunReaders sets the scope checker run reads use and where
// deliveries are read from.
func WithWorkflowRunReaders(scope ScopeChecker, deliveries automationdom.DeliveryRepository) WorkflowServiceOption {
	return func(s *WorkflowService) {
		s.scope = scope
		s.deliveries = deliveries
	}
}

// callerScope is the data scope of userID in tenantID. A zero user (an
// internal call) is not narrowed. Without a scope checker every read is
// refused rather than widened.
func (s *WorkflowService) callerScope(ctx context.Context, tenantID, userID shared.ID) (*shared.DataScope, error) {
	if userID.IsZero() {
		return nil, nil
	}
	if s.scope == nil {
		return nil, fmt.Errorf("%w: run reads need the data scope", shared.ErrForbidden)
	}
	return s.scope.ForUser(ctx, tenantID, userID)
}

// findingViewerRecorder records on ctx who reads finding rows, so storage
// applies the pentest member-visibility rule (datascope.Enforcer).
type findingViewerRecorder interface {
	WithFindingViewer(ctx context.Context) context.Context
}

// withFindingViewer is ctx with the reader recorded when the scope checker
// can do so. Without it storage applies the rule to everyone (fail closed).
func (s *WorkflowService) withFindingViewer(ctx context.Context) context.Context {
	if r, ok := s.scope.(findingViewerRecorder); ok {
		return r.WithFindingViewer(ctx)
	}
	return ctx
}

// RunDetail is one run with its steps, deliveries and retention.
type RunDetail struct {
	Run           *automationdom.Run
	Deliveries    []*automationdom.Delivery
	RetainedUntil time.Time
}

// GetRunForCaller returns a run of the tenant with its steps and deliveries,
// when its subject is in the caller's scope (404 otherwise, like a run that
// does not exist). A delivery about another finding the caller may not read
// (a step that names a fixed finding) keeps its channel and status, not its
// payload.
func (s *WorkflowService) GetRunForCaller(ctx context.Context, tenantID, userID, runID shared.ID) (*RunDetail, error) {
	ctx = s.withFindingViewer(ctx)
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	scope, err := s.callerScope(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	reader, _ := s.runRepo.(automationdom.RunScopeReader)
	visible := func(id shared.ID) (bool, error) {
		if scope == nil {
			return true, nil
		}
		if reader == nil {
			return false, nil
		}
		return reader.SubjectVisible(ctx, tenantID, id, scope)
	}
	if run.SubjectID != nil {
		ok, err := visible(*run.SubjectID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, shared.ErrNotFound
		}
	}
	d := &RunDetail{Run: run, RetainedUntil: automationdom.RetainedUntil(run.Mode, run.CreatedAt)}
	if s.deliveries != nil {
		if d.Deliveries, err = s.deliveries.ListByRun(ctx, tenantID, runID); err != nil {
			return nil, fmt.Errorf("list run deliveries: %w", err)
		}
	}
	for _, dl := range d.Deliveries {
		raw, _ := dl.Payload["finding_id"].(string)
		fid, err := shared.IDFromString(raw)
		if err != nil || (run.SubjectID != nil && fid == *run.SubjectID) {
			continue
		}
		ok, err := visible(fid)
		if err != nil {
			return nil, err
		}
		if !ok {
			dl.Payload = map[string]any{"redacted": "not_in_scope"}
		}
	}
	return d, nil
}

// ListRunsForCaller is ListRuns limited to runs whose subject is in the
// caller's scope.
func (s *WorkflowService) ListRunsForCaller(ctx context.Context, userID shared.ID, input ListWorkflowRunsInput) (pagination.Result[*automationdom.Run], error) {
	ctx = s.withFindingViewer(ctx)
	scope, err := s.callerScope(ctx, input.TenantID, userID)
	if err != nil {
		return pagination.Result[*automationdom.Run]{}, err
	}
	input.scope = scope
	return s.ListRuns(ctx, input)
}

// TraceInput asks for an automation's trace.
type TraceInput struct {
	TenantID   shared.ID
	UserID     shared.ID
	WorkflowID shared.ID
	Mode       automationdom.Mode
	// Days back (1..180, default 30).
	Days int
}

// Trace sums the steps of the automation's runs of a mode over the last days,
// counting only runs whose subject the caller may see.
func (s *WorkflowService) Trace(ctx context.Context, in TraceInput) (*automationdom.TraceAggregate, error) {
	ctx = s.withFindingViewer(ctx)
	if _, err := s.workflowRepo.GetByTenantAndID(ctx, in.TenantID, in.WorkflowID); err != nil {
		return nil, err
	}
	if !in.Mode.IsValid() {
		in.Mode = automationdom.ModeSimulate
	}
	if in.Days <= 0 {
		in.Days = 30
	}
	if in.Days > 180 {
		in.Days = 180
	}
	reader, ok := s.runRepo.(automationdom.RunScopeReader)
	if !ok {
		return &automationdom.TraceAggregate{DeliveriesByChannel: map[string]int{}}, nil
	}
	scope, err := s.callerScope(ctx, in.TenantID, in.UserID)
	if err != nil {
		return nil, err
	}
	return reader.AggregateTrace(ctx, in.TenantID, in.WorkflowID, in.Mode, time.Now().AddDate(0, 0, -in.Days), scope)
}

// ResumeRun lets a run paused at its change cap continue past the cap. Only
// a still-paused run of the tenant resumes; its finished steps are kept.
func (s *WorkflowService) ResumeRun(ctx context.Context, tenantID, userID, runID shared.ID) error {
	run, err := s.runRepo.GetByTenantAndID(ctx, tenantID, runID)
	if err != nil {
		return err
	}
	if run.Status != automationdom.RunStatusPaused {
		return shared.NewDomainError("INVALID_STATUS", "only a paused run can continue", shared.ErrValidation)
	}
	resumer, ok := s.runRepo.(automationdom.PausedRunResumer)
	if !ok {
		return fmt.Errorf("%w: runs cannot be resumed", shared.ErrNotImplemented)
	}
	resumed, err := resumer.ResumePaused(ctx, tenantID, runID)
	if err != nil {
		return err
	}
	if !resumed {
		return shared.NewDomainError("INVALID_STATUS", "only a paused run can continue", shared.ErrValidation)
	}
	s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: userID.String()},
		auditapp.NewSuccessEvent(audit.ActionWorkflowRunResumed, audit.ResourceTypeWorkflowRun, runID.String()).
			WithMessage("Automation run allowed past its change cap").
			WithMetadata("workflow_id", run.WorkflowID.String()))
	if s.executor != nil {
		s.executor.ExecuteAsyncWithTenant(runID, tenantID)
	}
	return nil
}
