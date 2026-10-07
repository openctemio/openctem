package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Editing a pipeline's steps.
//
// Every change goes through StepRepository.MutateSteps: one transaction that
// locks the pipeline, refuses while a run of it is active, and updates steps
// in place. A step keeps its id across saves, so its step runs (and their
// chaining inputs in scan_step_outputs) stay attached to it; a removed step's
// step runs keep their history with step_id NULL. Saving used to delete and
// re-create every step, which cascaded away the step history of every past
// and running run of the pipeline.

// AddStepInput represents the input for adding a step.
// Capabilities are optional - if not provided and tool is specified, they will be derived from the tool.
type AddStepInput struct {
	TenantID   string `json:"tenant_id" validate:"required,uuid"`
	TemplateID string `json:"template_id" validate:"required,uuid"`
	// ID names the existing step this entry is, in ReplaceSteps. Only an id
	// of one of the pipeline's own steps is honored; anything else (a
	// client-side temporary id, another pipeline's step) makes the entry a
	// new step with a server-generated id.
	ID                string              `json:"id"`
	StepKey           string              `json:"step_key" validate:"required,min=1,max=100"`
	Name              string              `json:"name" validate:"required,min=1,max=255"`
	Description       string              `json:"description" validate:"max=1000"`
	Order             int                 `json:"order"`
	UIPositionX       *float64            `json:"ui_position_x"`
	UIPositionY       *float64            `json:"ui_position_y"`
	Tool              string              `json:"tool" validate:"max=100"`
	Capabilities      []string            `json:"capabilities" validate:"omitempty,max=10"`
	Config            map[string]any      `json:"config"`
	TimeoutSeconds    int                 `json:"timeout_seconds"`
	DependsOn         []string            `json:"depends_on"`
	Condition         *pipeline.Condition `json:"condition"`
	MaxRetries        int                 `json:"max_retries"`
	RetryDelaySeconds int                 `json:"retry_delay_seconds"`
}

// buildStep validates one step input (key format, tool and config) and
// builds the step it describes, with a fresh id.
func (s *Service) buildStep(ctx context.Context, tenantID, templateID shared.ID, input AddStepInput) (*pipeline.Step, error) {
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateIdentifier(input.StepKey, 100, "step_key")
		if !result.Valid {
			s.logger.Warn("step_key validation failed",
				"template_id", templateID.String(),
				"step_key", sanitizeLogValue(input.StepKey),
				"errors", len(result.Errors))
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	// Derive capabilities from the tool when none are given.
	capabilities := input.Capabilities
	if len(capabilities) == 0 && input.Tool != "" && s.toolRepo != nil {
		t, err := s.toolRepo.GetByName(ctx, tenantID, input.Tool)
		if err != nil {
			t, err = s.toolRepo.GetByTenantAndName(ctx, tenantID, input.Tool)
		}
		if err == nil && t != nil && len(t.Capabilities) > 0 {
			capabilities = t.Capabilities
		}
	}
	// A tool with no capabilities of its own gets the generic one; a step
	// with no tool keeps none (and NewStep refuses it).
	if len(capabilities) == 0 && input.Tool != "" {
		capabilities = []string{"scan"}
	}

	if s.securityValidator != nil {
		result := s.securityValidator.ValidateStepConfig(ctx, tenantID, input.Tool, capabilities, input.Config)
		if !result.Valid {
			s.logger.Warn("step config validation failed",
				"template_id", templateID.String(),
				"step_key", sanitizeLogValue(input.StepKey),
				"errors", len(result.Errors))
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	step, err := pipeline.NewStep(templateID, input.StepKey, input.Name, input.Order, capabilities)
	if err != nil {
		return nil, err
	}
	if input.Description != "" {
		step.Description = input.Description
	}
	if input.UIPositionX != nil && input.UIPositionY != nil {
		step.SetUIPosition(*input.UIPositionX, *input.UIPositionY)
	}
	if input.Tool != "" {
		step.SetTool(input.Tool)
	}
	if input.Config != nil {
		step.SetConfig(input.Config)
	}
	if input.TimeoutSeconds > 0 {
		if err := step.SetTimeout(input.TimeoutSeconds); err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
	}
	if len(input.DependsOn) > 0 {
		step.SetDependencies(input.DependsOn)
	}
	if input.Condition != nil {
		if err := step.SetCondition(*input.Condition); err != nil {
			return nil, fmt.Errorf("invalid condition: %w", err)
		}
	}
	if input.MaxRetries > 0 {
		step.SetRetry(input.MaxRetries, input.RetryDelaySeconds)
	}
	return step, nil
}

// ValidateSteps validates step inputs without storing anything: each step
// as buildStep checks it, and that no two share a key.
func (s *Service) ValidateSteps(ctx context.Context, inputs []AddStepInput) error {
	if len(inputs) == 0 {
		return nil
	}
	tenantID, err := shared.IDFromString(inputs[0].TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	keys := make(map[string]bool, len(inputs))
	for _, in := range inputs {
		step, err := s.buildStep(ctx, tenantID, shared.ID{}, in)
		if err != nil {
			return err
		}
		if keys[step.StepKey] {
			return fmt.Errorf("%w: step key '%s' is used by more than one step", shared.ErrValidation, step.StepKey)
		}
		keys[step.StepKey] = true
	}
	return nil
}

// errStepKeyTaken refuses a second step with the same key in one pipeline.
func errStepKeyTaken(key string) error {
	return shared.NewDomainError("ALREADY_EXISTS",
		fmt.Sprintf("a step with key '%s' already exists in this pipeline", key), shared.ErrAlreadyExists)
}

// AddStep adds a step to a template.
func (s *Service) AddStep(ctx context.Context, input AddStepInput) (*pipeline.Step, error) {
	t, err := s.getWritableTemplate(ctx, input.TenantID, input.TemplateID)
	if err != nil {
		return nil, err
	}
	tenantID, _ := shared.IDFromString(input.TenantID)

	step, err := s.buildStep(ctx, tenantID, t.ID, input)
	if err != nil {
		return nil, err
	}

	_, err = s.stepRepo.MutateSteps(ctx, tenantID, t.ID, func(current []*pipeline.Step) ([]*pipeline.Step, error) {
		for _, c := range current {
			if c.StepKey == step.StepKey {
				return nil, errStepKeyTaken(step.StepKey)
			}
		}
		return append(current, step), nil
	})
	if err != nil {
		if errors.Is(err, shared.ErrAlreadyExists) {
			s.logger.Warn("step_key collision detected",
				"tenant_id", sanitizeLogValue(input.TenantID),
				"template_id", sanitizeLogValue(input.TemplateID),
				"step_key", sanitizeLogValue(input.StepKey),
			)
			s.logAudit(ctx, AuditContext{TenantID: input.TenantID},
				NewFailureEvent(audit.ActionPipelineStepCreated, audit.ResourceTypePipelineStep, "", err).
					WithMessage(fmt.Sprintf("Step key collision: '%s' already exists in pipeline", input.StepKey)).
					WithMetadata("template_id", input.TemplateID).
					WithMetadata("step_key", input.StepKey).
					WithMetadata("reason", "step_key_collision"))
		}
		return nil, err
	}

	s.auditStep(ctx, input.TenantID, audit.ActionPipelineStepCreated, step, "added to template")
	return step, nil
}

// ReplaceStepsInput is a full save of a pipeline's steps (the builder's Save).
type ReplaceStepsInput struct {
	TenantID   string
	TemplateID string
	Steps      []AddStepInput
}

// ReplaceSteps makes the pipeline's steps exactly input.Steps.
//
// Each entry is matched to an existing step, first by its ID, then by its
// step key; a matched step is updated in place and keeps its id, so its run
// history stays attached. Unmatched entries are added, unmatched existing
// steps are removed (their step runs are kept). Every entry is validated
// before anything changes, and the change is one transaction that is
// refused while a run of the pipeline is active.
func (s *Service) ReplaceSteps(ctx context.Context, input ReplaceStepsInput) ([]*pipeline.Step, error) {
	t, err := s.getWritableTemplate(ctx, input.TenantID, input.TemplateID)
	if err != nil {
		return nil, err
	}
	tenantID, _ := shared.IDFromString(input.TenantID)

	built := make([]*pipeline.Step, 0, len(input.Steps))
	keys := make(map[string]bool, len(input.Steps))
	for i, in := range input.Steps {
		if in.Order == 0 {
			in.Order = i + 1
		}
		step, err := s.buildStep(ctx, tenantID, t.ID, in)
		if err != nil {
			return nil, err
		}
		if keys[step.StepKey] {
			return nil, fmt.Errorf("%w: step key '%s' is used by more than one step", shared.ErrValidation, step.StepKey)
		}
		keys[step.StepKey] = true
		built = append(built, step)
	}

	var added, updated, removed []*pipeline.Step
	steps, err := s.stepRepo.MutateSteps(ctx, tenantID, t.ID, func(current []*pipeline.Step) ([]*pipeline.Step, error) {
		added, updated, removed = matchSteps(current, input.Steps, built)
		return built, nil
	})
	if err != nil {
		return nil, err
	}

	for _, st := range added {
		s.auditStep(ctx, input.TenantID, audit.ActionPipelineStepCreated, st, "added to template")
	}
	for _, st := range updated {
		s.auditStep(ctx, input.TenantID, audit.ActionPipelineStepUpdated, st, "updated")
	}
	for _, st := range removed {
		s.auditStep(ctx, input.TenantID, audit.ActionPipelineStepDeleted, st, "removed (its run history is kept)")
	}
	return steps, nil
}

// matchSteps gives each built step the id of the existing step it replaces
// and reports which steps are added, updated and removed.
//
// An entry's ID is honored only when it is one of current's ids, so a
// client can never point an entry at another pipeline's step: such an id is
// ignored and the entry falls back to matching by key. IDs are claimed before
// keys, so a key match cannot take a step that a later entry names by id.
func matchSteps(current []*pipeline.Step, inputs []AddStepInput, built []*pipeline.Step) (added, updated, removed []*pipeline.Step) {
	byID := make(map[shared.ID]*pipeline.Step, len(current))
	byKey := make(map[string]*pipeline.Step, len(current))
	for _, c := range current {
		byID[c.ID] = c
		byKey[c.StepKey] = c
	}
	claimed := make(map[shared.ID]bool, len(current))
	match := make([]*pipeline.Step, len(built))

	for i, in := range inputs {
		id, err := shared.IDFromString(in.ID)
		if err != nil {
			continue
		}
		if c, ok := byID[id]; ok && !claimed[id] {
			match[i], claimed[id] = c, true
		}
	}
	for i, b := range built {
		if match[i] != nil {
			continue
		}
		if c, ok := byKey[b.StepKey]; ok && !claimed[c.ID] {
			match[i], claimed[c.ID] = c, true
		}
	}

	for i, b := range built {
		c := match[i]
		if c == nil {
			added = append(added, b)
			continue
		}
		b.ID = c.ID
		b.CreatedAt = c.CreatedAt
		if b.Tool == c.Tool {
			b.ToolID = c.ToolID
		}
		updated = append(updated, b)
	}
	for _, c := range current {
		if !claimed[c.ID] {
			removed = append(removed, c)
		}
	}
	return added, updated, removed
}

// UpdateStep updates a step.
func (s *Service) UpdateStep(ctx context.Context, stepID string, input AddStepInput) (*pipeline.Step, error) {
	sid, err := shared.IDFromString(stepID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid step id", shared.ErrValidation)
	}

	step, err := s.stepRepo.GetByID(ctx, sid)
	if err != nil {
		return nil, err
	}

	// Security: bind the step to the template named in the request. The step
	// is loaded by raw ID, so without this check a caller could pass a
	// template they own in the path but a step ID belonging to another
	// tenant's template, mutating it (IDOR). The handler separately verifies
	// the named template belongs to the caller's tenant.
	if input.TemplateID != "" {
		tid, err := shared.IDFromString(input.TemplateID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid template id", shared.ErrValidation)
		}
		if step.PipelineID != tid {
			return nil, shared.ErrNotFound
		}
	}
	if _, err := s.getWritableTemplate(ctx, input.TenantID, step.PipelineID.String()); err != nil {
		return nil, err
	}

	tenantID, _ := shared.IDFromString(input.TenantID)
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateStepConfig(ctx, tenantID, input.Tool, input.Capabilities, input.Config)
		if !result.Valid {
			s.logger.Warn("step config validation failed",
				"step_id", sid.String(),
				"errors", len(result.Errors))
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	var updated *pipeline.Step
	_, err = s.stepRepo.MutateSteps(ctx, tenantID, step.PipelineID, func(current []*pipeline.Step) ([]*pipeline.Step, error) {
		for _, c := range current {
			if c.ID == sid {
				if err := applyStepUpdate(c, input); err != nil {
					return nil, err
				}
				updated = c
				return current, nil
			}
		}
		return nil, shared.ErrNotFound
	})
	if err != nil {
		return nil, err
	}

	s.auditStep(ctx, input.TenantID, audit.ActionPipelineStepUpdated, updated, "updated")
	return updated, nil
}

// applyStepUpdate applies the fields an UpdateStep request sets.
func applyStepUpdate(step *pipeline.Step, input AddStepInput) error {
	if input.Name != "" {
		step.Name = input.Name
	}
	if input.Description != "" {
		step.Description = input.Description
	}
	if input.Order > 0 {
		step.StepOrder = input.Order
	}
	if input.UIPositionX != nil && input.UIPositionY != nil {
		step.SetUIPosition(*input.UIPositionX, *input.UIPositionY)
	}
	if input.Tool != "" {
		step.SetTool(input.Tool)
	}
	if len(input.Capabilities) > 0 {
		step.Capabilities = input.Capabilities
	}
	if input.Config != nil {
		step.SetConfig(input.Config)
	}
	if input.TimeoutSeconds > 0 {
		if err := step.SetTimeout(input.TimeoutSeconds); err != nil {
			return fmt.Errorf("invalid timeout: %w", err)
		}
	}
	if len(input.DependsOn) > 0 {
		step.SetDependencies(input.DependsOn)
	}
	if input.Condition != nil {
		if err := step.SetCondition(*input.Condition); err != nil {
			return fmt.Errorf("invalid condition: %w", err)
		}
	}
	if input.MaxRetries >= 0 {
		step.SetRetry(input.MaxRetries, input.RetryDelaySeconds)
	}
	return nil
}

// DeleteStep removes a step. Its step runs are kept (step_id becomes NULL).
func (s *Service) DeleteStep(ctx context.Context, tenantID, stepID string) error {
	sid, err := shared.IDFromString(stepID)
	if err != nil {
		return fmt.Errorf("%w: invalid step id", shared.ErrValidation)
	}

	step, err := s.stepRepo.GetByID(ctx, sid)
	if err != nil {
		return err
	}

	// Security: the step is loaded by raw ID. The handler only checks that the
	// template named in the PATH belongs to the tenant — not that this step
	// actually lives under it. Without binding the step to a template the
	// caller's tenant owns, a caller could pass an owned template plus a step ID
	// from another tenant's template and delete it (cross-tenant IDOR). Mirrors
	// the guard in UpdateStep.
	if _, err := s.getWritableTemplate(ctx, tenantID, step.PipelineID.String()); err != nil {
		return err
	}

	tid, _ := shared.IDFromString(tenantID)
	_, err = s.stepRepo.MutateSteps(ctx, tid, step.PipelineID, func(current []*pipeline.Step) ([]*pipeline.Step, error) {
		kept := make([]*pipeline.Step, 0, len(current))
		for _, c := range current {
			if c.ID != sid {
				kept = append(kept, c)
			}
		}
		if len(kept) == len(current) {
			return nil, shared.ErrNotFound
		}
		return kept, nil
	})
	if err != nil {
		return err
	}

	s.auditStep(ctx, tenantID, audit.ActionPipelineStepDeleted, step, "removed (its run history is kept)")
	return nil
}

// auditStep records one step change.
func (s *Service) auditStep(ctx context.Context, tenantID string, action audit.Action, step *pipeline.Step, what string) {
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(action, audit.ResourceTypePipelineStep, step.ID.String()).
			WithResourceName(step.Name).
			WithMessage(fmt.Sprintf("Pipeline step '%s' %s", step.Name, what)).
			WithMetadata("template_id", step.PipelineID.String()).
			WithMetadata("step_key", step.StepKey))
}

// sanitizeLogValue strips CR/LF and other control characters from a
// request-supplied value before it is logged (log forging in text mode),
// and caps its length.
func sanitizeLogValue(v string) string {
	const maxLen = 128
	if len(v) > maxLen {
		v = v[:maxLen]
	}
	// The explicit ReplaceAll pair is the form CodeQL go/log-injection
	// accepts as a barrier; strings.Map then drops other control characters.
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}
