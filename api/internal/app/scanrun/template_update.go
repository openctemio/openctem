package scanrun

// Template updates for tenant copies of system scan workflows
// (docs/architecture/scan-stages.md#template-updates). The comparison and
// the changes live in pkg/domain/scanworkflow (TemplateChanges); this side
// loads the copy and its source, applies the changes through the same check
// and replace as a published draft, and audits it. A copy is only ever
// changed by a person applying an update.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetTemplateLineage wires the lineage of tenant copies. Nil: no copy is
// offered updates and copies keep no lineage.
func (s *Service) SetTemplateLineage(l scanworkflow.LineageStore) { s.lineage = l }

// TemplateUpdateView is what a copy is offered.
type TemplateUpdateView struct {
	SourceTemplateID   string
	SourceTemplateName string
	Changes            []scanworkflow.TemplateChange
	// TemplateDigest identifies the template's spec the changes come from;
	// apply and dismiss must name it (a template that changed since the
	// preview refuses them).
	TemplateDigest string
}

// ErrTemplateUpdateStale: the template changed since the update was shown.
var ErrTemplateUpdateStale = fmt.Errorf("%w: the template changed since this update was shown; review it again", shared.ErrConflict)

// errNoTemplateUpdate: nothing to apply.
var errNoTemplateUpdate = fmt.Errorf("%w: this scan workflow has no template update", shared.ErrValidation)

// templateUpdate computes the update of the tenant's copy (nil when it has
// no lineage), with the copy and the template it compares.
func (s *Service) templateUpdate(ctx context.Context, tenantID shared.ID, copyWF *scanworkflow.Workflow) (*TemplateUpdateView, *scanworkflow.Workflow, error) {
	if s.lineage == nil || copyWF.IsSystemTemplate || copyWF.TenantID != tenantID {
		return nil, nil, nil
	}
	l, err := s.lineage.GetLineage(ctx, tenantID, copyWF.ID)
	if err != nil || l == nil {
		return nil, nil, err
	}
	tpl, err := s.templateRepo.GetWithSteps(ctx, l.SourceTemplateID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if !tpl.IsSystemTemplate {
		return nil, nil, nil
	}
	copySpec := scanworkflow.SpecOf(copyWF)
	base := copySpec
	if l.Base != nil {
		base = *l.Base
	}
	tplSpec := scanworkflow.SpecOf(tpl)
	digest, err := tplSpec.Digest()
	if err != nil {
		return nil, nil, err
	}
	return &TemplateUpdateView{
		SourceTemplateID:   tpl.ID.String(),
		SourceTemplateName: tpl.Name,
		Changes:            scanworkflow.TemplateChanges(base, tplSpec, copySpec),
		TemplateDigest:     digest,
	}, tpl, nil
}

// RetiredSource returns the retired system workflow the tenant's copy was made
// from, nil when the copy has no lineage or its source is still in use.
func (s *Service) RetiredSource(ctx context.Context, tenantID string, copyWF *scanworkflow.Workflow) (*scanworkflow.Workflow, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if s.lineage == nil || copyWF.IsSystemTemplate || copyWF.TenantID != tid {
		return nil, nil
	}
	l, err := s.lineage.GetLineage(ctx, tid, copyWF.ID)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, nil
	}
	src, err := s.templateRepo.GetSystemTemplateByID(ctx, l.SourceTemplateID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !src.IsRetiredSystem() {
		return nil, nil
	}
	return src, nil
}

// ownCopy loads the tenant's own workflow with its steps; another tenant's
// workflow is not found.
func (s *Service) ownCopy(ctx context.Context, tenantID, workflowID string) (*scanworkflow.Workflow, shared.ID, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	wid, err := shared.IDFromString(workflowID)
	if err != nil {
		return nil, shared.ID{}, fmt.Errorf("%w: invalid scan workflow id", shared.ErrValidation)
	}
	if _, err := s.templateRepo.GetByTenantAndID(ctx, tid, wid); err != nil {
		return nil, shared.ID{}, err
	}
	w, err := s.templateRepo.GetWithSteps(ctx, wid)
	if err != nil {
		return nil, shared.ID{}, err
	}
	if w.TenantID != tid {
		return nil, shared.ID{}, shared.ErrNotFound
	}
	return w, tid, nil
}

// GetTemplateUpdate returns the update the tenant's copy is offered; nil
// when it has none (no lineage, or nothing it can take).
func (s *Service) GetTemplateUpdate(ctx context.Context, tenantID, workflowID string) (*TemplateUpdateView, error) {
	w, tid, err := s.ownCopy(ctx, tenantID, workflowID)
	if err != nil {
		return nil, err
	}
	if w.IsSystemTemplate || w.RetiredAt != nil {
		return nil, nil
	}
	v, _, err := s.templateUpdate(ctx, tid, w)
	if err != nil || v == nil || len(v.Changes) == 0 {
		return nil, err
	}
	return v, nil
}

// ApplyTemplateUpdate applies the offered changes to the tenant's copy:
// checked like a published draft, the steps replaced in place, the version
// moved on and pinned, the lineage's base moved to the template, and the
// change audited. It is refused while the copy has an unpublished draft (it
// would be overwritten by publishing it) and when the template changed since
// templateDigest was shown.
func (s *Service) ApplyTemplateUpdate(ctx context.Context, tenantID, workflowID, templateDigest string) (*scanworkflow.Workflow, error) {
	w, tid, err := s.ownCopy(ctx, tenantID, workflowID)
	if err != nil {
		return nil, err
	}
	if _, err := s.getWritableTemplate(ctx, tenantID, workflowID); err != nil {
		return nil, err
	}
	v, tpl, err := s.templateUpdate(ctx, tid, w)
	if err != nil {
		return nil, err
	}
	if v == nil || len(v.Changes) == 0 {
		return nil, errNoTemplateUpdate
	}
	if v.TemplateDigest != templateDigest {
		return nil, ErrTemplateUpdateStale
	}
	if s.draftRepo != nil {
		if _, err := s.draftRepo.GetDraft(ctx, tid, w.ID); err == nil {
			return nil, fmt.Errorf("%w: this scan workflow has an unpublished draft; publish or discard it first", shared.ErrConflict)
		} else if !errors.Is(err, shared.ErrNotFound) {
			return nil, err
		}
	}

	tplSpec := scanworkflow.SpecOf(tpl)
	steps := scanworkflow.ApplyTemplateChanges(scanworkflow.SpecOf(w), tplSpec, v.Changes)
	inputs := make([]AddStepInput, 0, len(steps))
	for _, st := range steps {
		inputs = append(inputs, stepInputOf(tenantID, workflowID, st))
	}
	rep, err := s.CheckSteps(ctx, ValidateGraphInput{TenantID: tenantID, Steps: inputs})
	if err != nil {
		return nil, err
	}
	if !rep.Valid() {
		return nil, &GraphInvalidError{Report: rep}
	}
	if _, err := s.ReplaceSteps(ctx, ReplaceStepsInput{TenantID: tenantID, TemplateID: workflowID, Steps: inputs}); err != nil {
		return nil, err
	}
	t, err := s.templateRepo.GetByTenantAndID(ctx, tid, w.ID)
	if err != nil {
		return nil, err
	}
	t.IncrementVersion()
	if err := s.templateRepo.Update(ctx, t); err != nil {
		return nil, err
	}
	if s.versions != nil {
		published, err := s.templateRepo.GetWithSteps(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.versions.PinVersion(ctx, tid, t.ID, scanworkflow.SpecOf(published)); err != nil {
			return nil, fmt.Errorf("pin the updated scan workflow version: %w", err)
		}
	}
	if err := s.lineage.SetLineage(ctx, tid, t.ID, tpl.ID, tplSpec); err != nil {
		return nil, err
	}
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionScanWorkflowUpdated, audit.ResourceTypeScanWorkflow, t.ID.String()).
			WithResourceName(t.Name).
			WithMessage(fmt.Sprintf("Scan workflow '%s' took the update of template '%s' (version %d)", t.Name, tpl.Name, t.Version)).
			WithMetadata("template_update", "applied").
			WithMetadata("source_template_id", tpl.ID.String()).
			WithMetadata("template_digest", v.TemplateDigest).
			WithMetadata("changes", changeSummary(v.Changes)).
			WithMetadata("version", t.Version))
	return t, nil
}

// DismissTemplateUpdate keeps the copy as it is and stops offering the
// changes shown (the lineage's base moves to the template); audited.
func (s *Service) DismissTemplateUpdate(ctx context.Context, tenantID, workflowID, templateDigest string) error {
	w, tid, err := s.ownCopy(ctx, tenantID, workflowID)
	if err != nil {
		return err
	}
	if _, err := s.getWritableTemplate(ctx, tenantID, workflowID); err != nil {
		return err
	}
	v, tpl, err := s.templateUpdate(ctx, tid, w)
	if err != nil {
		return err
	}
	if v == nil || len(v.Changes) == 0 {
		return errNoTemplateUpdate
	}
	if v.TemplateDigest != templateDigest {
		return ErrTemplateUpdateStale
	}
	if err := s.lineage.SetLineage(ctx, tid, w.ID, tpl.ID, scanworkflow.SpecOf(tpl)); err != nil {
		return err
	}
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionScanWorkflowUpdated, audit.ResourceTypeScanWorkflow, w.ID.String()).
			WithResourceName(w.Name).
			WithMessage(fmt.Sprintf("Scan workflow '%s' kept as it is; the update of template '%s' was dismissed", w.Name, tpl.Name)).
			WithMetadata("template_update", "dismissed").
			WithMetadata("source_template_id", tpl.ID.String()).
			WithMetadata("template_digest", v.TemplateDigest).
			WithMetadata("changes", changeSummary(v.Changes)))
	return nil
}

// changeSummary lists the changes as "add_step:hosts", "depends_on:ports".
func changeSummary(changes []scanworkflow.TemplateChange) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Kind+":"+c.StepKey)
	}
	return out
}

// stepInputOf is a spec step as a ReplaceSteps entry (its id keeps an
// existing step; an empty id adds one).
func stepInputOf(tenantID, workflowID string, st scanworkflow.SpecStep) AddStepInput {
	in := AddStepInput{
		TenantID: tenantID, TemplateID: workflowID, ID: st.ID,
		StepKey: st.StepKey, Name: st.Name, Description: st.Description, Order: st.StepOrder,
		Tool: st.Tool, Capabilities: st.Capabilities, PreferTools: st.PreferTools, Config: st.Config,
		TimeoutSeconds: st.TimeoutSeconds, DependsOn: st.DependsOn, MaxRetries: st.MaxRetries,
		RetryDelaySeconds: st.RetryDelaySeconds,
		RunPolicy:         st.RunPolicy,
	}
	cond := st.Condition
	in.Condition = &cond
	if st.UIPosition != nil {
		x, y := st.UIPosition.X, st.UIPosition.Y
		in.UIPositionX, in.UIPositionY = &x, &y
	}
	return in
}
