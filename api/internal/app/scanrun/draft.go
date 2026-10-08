package scanrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Drafts: the builder saves a scan workflow's draft (steps, node positions)
// whatever its state, so the layout and the edits are never lost to a
// problem the user fixes later; the check's issues are stored with it.
// Publishing makes the draft the steps runs use and needs no blocking
// issue. Runs only ever read the published steps.

// WithDraftStore enables drafts.
func WithDraftStore(d scanworkflow.DraftRepository) Option {
	return func(s *Service) { s.draftRepo = d }
}

// DraftSpec is what a draft holds.
type DraftSpec struct {
	Steps           []AddStepInput           `json:"steps"`
	UIStartPosition *scanworkflow.UIPosition `json:"ui_start_position,omitempty"`
	UIEndPosition   *scanworkflow.UIPosition `json:"ui_end_position,omitempty"`
}

// DraftInput saves a draft.
type DraftInput struct {
	TenantID   string
	TemplateID string
	Spec       DraftSpec
}

// DraftView is a stored draft and what its last check found.
type DraftView struct {
	Spec      DraftSpec
	Issues    stage.GraphReport
	UpdatedAt time.Time
}

var errDraftsDisabled = errors.New("scan workflow drafts are not configured")

// ownWorkflow is the tenant's own, writable workflow.
func (s *Service) ownWorkflow(ctx context.Context, tenantID, templateID string) (*scanworkflow.Workflow, shared.ID, error) {
	if s.draftRepo == nil {
		return nil, shared.ID{}, errDraftsDisabled
	}
	t, err := s.getWritableTemplate(ctx, tenantID, templateID)
	if err != nil {
		return nil, shared.ID{}, err
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil || t.TenantID != tid {
		return nil, shared.ID{}, shared.ErrNotFound
	}
	return t, tid, nil
}

// SaveDraft stores the draft and the issues its check finds. A draft with
// problems is saved all the same: only a request that cannot be stored is
// refused.
func (s *Service) SaveDraft(ctx context.Context, in DraftInput) (*DraftView, error) {
	t, tid, err := s.ownWorkflow(ctx, in.TenantID, in.TemplateID)
	if err != nil {
		return nil, err
	}
	for i := range in.Spec.Steps {
		in.Spec.Steps[i].TenantID, in.Spec.Steps[i].TemplateID = in.TenantID, ""
	}
	rep, err := s.CheckSteps(ctx, ValidateGraphInput{TenantID: in.TenantID, Steps: in.Spec.Steps})
	if err != nil {
		return nil, err
	}
	for i := range in.Spec.Steps {
		in.Spec.Steps[i].TenantID = ""
	}
	spec, err := json.Marshal(in.Spec)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the draft: %w", err)
	}
	issues, err := json.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the draft issues: %w", err)
	}
	now := time.Now().UTC()
	if err := s.draftRepo.SaveDraft(ctx, tid, t.ID, &scanworkflow.Draft{Spec: spec, Issues: issues, UpdatedAt: now}); err != nil {
		return nil, err
	}
	return &DraftView{Spec: in.Spec, Issues: rep, UpdatedAt: now}, nil
}

// GetDraft returns the tenant's draft of the workflow, ErrNotFound when
// there is none.
func (s *Service) GetDraft(ctx context.Context, tenantID, templateID string) (*DraftView, error) {
	if s.draftRepo == nil {
		return nil, errDraftsDisabled
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	wid, err := shared.IDFromString(templateID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scan workflow id", shared.ErrValidation)
	}
	d, err := s.draftRepo.GetDraft(ctx, tid, wid)
	if err != nil {
		return nil, err
	}
	return decodeDraft(d)
}

func decodeDraft(d *scanworkflow.Draft) (*DraftView, error) {
	v := &DraftView{UpdatedAt: d.UpdatedAt}
	if err := json.Unmarshal(d.Spec, &v.Spec); err != nil {
		return nil, fmt.Errorf("failed to decode the draft: %w", err)
	}
	if len(d.Issues) > 0 {
		if err := json.Unmarshal(d.Issues, &v.Issues); err != nil {
			return nil, fmt.Errorf("failed to decode the draft issues: %w", err)
		}
	}
	return v, nil
}

// DiscardDraft removes the draft; the published steps stay.
func (s *Service) DiscardDraft(ctx context.Context, tenantID, templateID string) error {
	t, tid, err := s.ownWorkflow(ctx, tenantID, templateID)
	if err != nil {
		return err
	}
	return s.draftRepo.ClearDraft(ctx, tid, t.ID)
}

// PublishDraft makes the draft the steps runs use. It is checked again, now;
// a blocking issue refuses it (a GraphInvalidError with every issue) and
// leaves the draft as it is. On success the steps are replaced in place
// (each step keeps its id and run history), the node positions saved, the
// version moved on and the draft removed.
func (s *Service) PublishDraft(ctx context.Context, tenantID, templateID string) (*scanworkflow.Workflow, error) {
	t, tid, err := s.ownWorkflow(ctx, tenantID, templateID)
	if err != nil {
		return nil, err
	}
	d, err := s.draftRepo.GetDraft(ctx, tid, t.ID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, scanworkflow.ErrNoDraft
	}
	if err != nil {
		return nil, err
	}
	view, err := decodeDraft(d)
	if err != nil {
		return nil, err
	}
	steps := view.Spec.Steps
	for i := range steps {
		steps[i].TenantID, steps[i].TemplateID = tenantID, templateID
	}
	rep, err := s.CheckSteps(ctx, ValidateGraphInput{TenantID: tenantID, Steps: steps})
	if err != nil {
		return nil, err
	}
	if !rep.Valid() {
		return nil, &GraphInvalidError{Report: rep}
	}
	if _, err := s.ReplaceSteps(ctx, ReplaceStepsInput{TenantID: tenantID, TemplateID: templateID, Steps: steps}); err != nil {
		return nil, err
	}

	t, err = s.templateRepo.GetByTenantAndID(ctx, tid, t.ID)
	if err != nil {
		return nil, err
	}
	if view.Spec.UIStartPosition != nil {
		t.UIStartPosition = view.Spec.UIStartPosition
	}
	if view.Spec.UIEndPosition != nil {
		t.UIEndPosition = view.Spec.UIEndPosition
	}
	t.IncrementVersion()
	if err := s.templateRepo.Update(ctx, t); err != nil {
		return nil, err
	}
	// The published steps become an immutable version now: the version
	// store is what runs read, so a failure here fails the publish (the
	// draft is kept). The next run reuses it, as its digest matches.
	if s.versions != nil {
		// Ownership was checked above (ownWorkflow).
		published, err := s.templateRepo.GetWithSteps(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.versions.PinVersion(ctx, tid, t.ID, scanworkflow.SpecOf(published)); err != nil {
			return nil, fmt.Errorf("pin the published scan workflow version: %w", err)
		}
	}
	if err := s.draftRepo.ClearDraft(ctx, tid, t.ID); err != nil {
		return nil, err
	}
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionScanWorkflowUpdated, audit.ResourceTypeScanWorkflow, t.ID.String()).
			WithResourceName(t.Name).
			WithMessage(fmt.Sprintf("Scan workflow '%s' published as version %d", t.Name, t.Version)).
			WithMetadata("version", t.Version))
	return t, nil
}
