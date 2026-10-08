package scanrun

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Editing a scan workflow's steps.
//
// Every change goes through StepRepository.MutateSteps: one transaction that
// locks the scan workflow, refuses while a run of it is active, and updates steps
// in place. A step keeps its id across saves, so its step runs (and their
// chaining inputs in scan_step_outputs) stay attached to it; a removed step's
// step runs keep their history with step_id NULL. Saving used to delete and
// re-create every step, which cascaded away the step history of every past
// and running run of the scan workflow.

// AddStepInput represents the input for adding a step.
// Capabilities are optional - if not provided and tool is specified, they will be derived from the tool.
type AddStepInput struct {
	TenantID   string `json:"tenant_id" validate:"required,uuid"`
	TemplateID string `json:"template_id" validate:"required,uuid"`
	// ID names the existing step this entry is, in ReplaceSteps. Only an id
	// of one of the scan workflow's own steps is honored; anything else (a
	// client-side temporary id, another scan workflow's step) makes the entry a
	// new step with a server-generated id.
	ID                string                  `json:"id"`
	StepKey           string                  `json:"step_key" validate:"required,min=1,max=100"`
	Name              string                  `json:"name" validate:"required,min=1,max=255"`
	Description       string                  `json:"description" validate:"max=1000"`
	Order             int                     `json:"order"`
	UIPositionX       *float64                `json:"ui_position_x"`
	UIPositionY       *float64                `json:"ui_position_y"`
	Tool              string                  `json:"tool" validate:"max=100"`
	Capabilities      []string                `json:"capabilities" validate:"omitempty,max=10"`
	PreferTools       []string                `json:"prefer_tools" validate:"omitempty,max=5"`
	Config            map[string]any          `json:"config"`
	TimeoutSeconds    int                     `json:"timeout_seconds"`
	DependsOn         []string                `json:"depends_on"`
	Condition         *scanworkflow.Condition `json:"condition"`
	MaxRetries        int                     `json:"max_retries"`
	RetryDelaySeconds int                     `json:"retry_delay_seconds"`
}

// buildStep validates one step input (key format, tool and config) and
// builds the step it describes, with a fresh id.
func (s *Service) buildStep(ctx context.Context, tenantID, templateID shared.ID, input AddStepInput) (*scanworkflow.Step, error) {
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
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, stepMessage(input, result.Errors[0].Message))
		}
	}

	step, err := scanworkflow.NewStep(templateID, input.StepKey, input.Name, input.Order, capabilities)
	if err != nil {
		return nil, err
	}
	if input.Description != "" {
		step.Description = input.Description
	}
	if input.UIPositionX != nil && input.UIPositionY != nil {
		if err := step.SetUIPosition(*input.UIPositionX, *input.UIPositionY); err != nil {
			return nil, err
		}
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
	step.PreferTools = normalizeToolList(input.PreferTools)
	if err := checkStepSelection(step); err != nil {
		return nil, err
	}
	return step, nil
}

// stepMessage names the step a validation message is about, so a save of a
// whole workflow says which step to fix.
func stepMessage(input AddStepInput, msg string) string {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = input.StepKey
	}
	if name == "" {
		return msg
	}
	return fmt.Sprintf("step %q: %s", name, msg)
}

// normalizeToolList lowercases and de-duplicates tool names, in order.
func normalizeToolList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// checkStepSelection checks how a step picks its tool and its settings
// against its capability contract: a pinned tool or a prefer list, not both;
// every preferred tool implements the capability; the standard params have
// the contract's types and bounds; tool settings need a pinned tool. A step
// the catalog cannot place (a tenant tool) keeps its settings as they are.
func checkStepSelection(step *scanworkflow.Step) error {
	if step.Tool != "" && len(step.PreferTools) > 0 {
		return fmt.Errorf("%w: a step pins a tool or lists tools to prefer, not both", shared.ErrValidation)
	}
	st, ok := stage.ForStep(step.Tool, step.Capabilities)
	if !ok {
		if len(step.PreferTools) > 0 {
			return fmt.Errorf("%w: step '%s': tools to prefer need a catalog capability", shared.ErrValidation, step.StepKey)
		}
		return nil
	}
	for _, t := range step.PreferTools {
		if !st.Implements(t) {
			return fmt.Errorf("%w: step '%s': %s does not implement %s (it can run on %s)",
				shared.ErrValidation, step.StepKey, t, st.Key, strings.Join(st.Tools(), ", "))
		}
	}
	if err := stage.ValidateParams(st, step.Config, step.Tool); err != nil {
		return fmt.Errorf("%w: step '%s': %w", shared.ErrValidation, step.StepKey, err)
	}
	return nil
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

// errStepKeyTaken refuses a second step with the same key in one scan workflow.
func errStepKeyTaken(key string) error {
	return shared.NewDomainError("ALREADY_EXISTS",
		fmt.Sprintf("a step with key '%s' already exists in this pipeline", key), shared.ErrAlreadyExists)
}

// AddStep adds a step to a template.
func (s *Service) AddStep(ctx context.Context, input AddStepInput) (*scanworkflow.Step, error) {
	t, err := s.getWritableTemplate(ctx, input.TenantID, input.TemplateID)
	if err != nil {
		return nil, err
	}
	tenantID, _ := shared.IDFromString(input.TenantID)

	step, err := s.buildStep(ctx, tenantID, t.ID, input)
	if err != nil {
		return nil, err
	}

	_, err = s.stepRepo.MutateSteps(ctx, tenantID, t.ID, func(current []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		for _, c := range current {
			if c.StepKey == step.StepKey {
				return nil, errStepKeyTaken(step.StepKey)
			}
		}
		next := append(slices.Clone(current), step)
		if err := validateStepsGraph(next); err != nil {
			return nil, err
		}
		return next, nil
	})
	if err != nil {
		if errors.Is(err, shared.ErrAlreadyExists) {
			s.logger.Warn("step_key collision detected",
				"tenant_id", sanitizeLogValue(input.TenantID),
				"template_id", sanitizeLogValue(input.TemplateID),
				"step_key", sanitizeLogValue(input.StepKey),
			)
			s.logAudit(ctx, AuditContext{TenantID: input.TenantID},
				NewFailureEvent(audit.ActionScanWorkflowStepCreated, audit.ResourceTypeScanWorkflowStep, "", err).
					WithMessage(fmt.Sprintf("Step key collision: '%s' already exists in pipeline", input.StepKey)).
					WithMetadata("template_id", input.TemplateID).
					WithMetadata("step_key", input.StepKey).
					WithMetadata("reason", "step_key_collision"))
		}
		return nil, err
	}

	s.auditStep(ctx, input.TenantID, audit.ActionScanWorkflowStepCreated, step, "added to template")
	return step, nil
}

// ReplaceStepsInput is a full save of a scan workflow's steps (the builder's Save).
type ReplaceStepsInput struct {
	TenantID   string
	TemplateID string
	Steps      []AddStepInput
}

// ReplaceSteps makes the scan workflow's steps exactly input.Steps.
//
// Each entry is matched to an existing step, first by its ID, then by its
// step key; a matched step is updated in place and keeps its id, so its run
// history stays attached. Unmatched entries are added, unmatched existing
// steps are removed (their step runs are kept). Every entry is validated
// before anything changes, and the change is one transaction that is
// refused while a run of the scan workflow is active.
func (s *Service) ReplaceSteps(ctx context.Context, input ReplaceStepsInput) ([]*scanworkflow.Step, error) {
	t, err := s.getWritableTemplate(ctx, input.TenantID, input.TemplateID)
	if err != nil {
		return nil, err
	}
	tenantID, _ := shared.IDFromString(input.TenantID)

	built := make([]*scanworkflow.Step, 0, len(input.Steps))
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

	var added, updated, removed []*scanworkflow.Step
	steps, err := s.stepRepo.MutateSteps(ctx, tenantID, t.ID, func(current []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		added, updated, removed = matchSteps(current, input.Steps, built)
		if err := validateStepsGraph(built); err != nil {
			return nil, err
		}
		return built, nil
	})
	if err != nil {
		return nil, err
	}

	for _, st := range added {
		s.auditStep(ctx, input.TenantID, audit.ActionScanWorkflowStepCreated, st, "added to template")
	}
	for _, st := range updated {
		s.auditStep(ctx, input.TenantID, audit.ActionScanWorkflowStepUpdated, st, "updated")
	}
	for _, st := range removed {
		s.auditStep(ctx, input.TenantID, audit.ActionScanWorkflowStepDeleted, st, "removed (its run history is kept)")
	}
	return steps, nil
}

// matchSteps gives each built step the id of the existing step it replaces
// and reports which steps are added, updated and removed.
//
// An entry's ID is honored only when it is one of current's ids, so a
// client can never point an entry at another scan workflow's step: such an id is
// ignored and the entry falls back to matching by key. IDs are claimed before
// keys, so a key match cannot take a step that a later entry names by id.
func matchSteps(current []*scanworkflow.Step, inputs []AddStepInput, built []*scanworkflow.Step) (added, updated, removed []*scanworkflow.Step) {
	byID := make(map[shared.ID]*scanworkflow.Step, len(current))
	byKey := make(map[string]*scanworkflow.Step, len(current))
	for _, c := range current {
		byID[c.ID] = c
		byKey[c.StepKey] = c
	}
	claimed := make(map[shared.ID]bool, len(current))
	match := make([]*scanworkflow.Step, len(built))

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
func (s *Service) UpdateStep(ctx context.Context, stepID string, input AddStepInput) (*scanworkflow.Step, error) {
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
		if step.ScanWorkflowID != tid {
			return nil, shared.ErrNotFound
		}
	}
	if _, err := s.getWritableTemplate(ctx, input.TenantID, step.ScanWorkflowID.String()); err != nil {
		return nil, err
	}

	tenantID, _ := shared.IDFromString(input.TenantID)
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateStepConfig(ctx, tenantID, input.Tool, input.Capabilities, input.Config)
		if !result.Valid {
			s.logger.Warn("step config validation failed",
				"step_id", sid.String(),
				"errors", len(result.Errors))
			name := input
			if name.Name == "" {
				name.Name, name.StepKey = step.Name, step.StepKey
			}
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, stepMessage(name, result.Errors[0].Message))
		}
	}

	var updated *scanworkflow.Step
	_, err = s.stepRepo.MutateSteps(ctx, tenantID, step.ScanWorkflowID, func(current []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		for _, c := range current {
			if c.ID == sid {
				if err := applyStepUpdate(c, input); err != nil {
					return nil, err
				}
				if err := checkStepSelection(c); err != nil {
					return nil, err
				}
				updated = c
				if err := validateStepsGraph(current); err != nil {
					return nil, err
				}
				return current, nil
			}
		}
		return nil, shared.ErrNotFound
	})
	if err != nil {
		return nil, err
	}

	s.auditStep(ctx, input.TenantID, audit.ActionScanWorkflowStepUpdated, updated, "updated")
	return updated, nil
}

// applyStepUpdate applies the fields an UpdateStep request sets.
func applyStepUpdate(step *scanworkflow.Step, input AddStepInput) error {
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
		if err := step.SetUIPosition(*input.UIPositionX, *input.UIPositionY); err != nil {
			return err
		}
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
	if input.PreferTools != nil {
		step.PreferTools = normalizeToolList(input.PreferTools)
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
	if _, err := s.getWritableTemplate(ctx, tenantID, step.ScanWorkflowID.String()); err != nil {
		return err
	}

	tid, _ := shared.IDFromString(tenantID)
	_, err = s.stepRepo.MutateSteps(ctx, tid, step.ScanWorkflowID, func(current []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		kept := make([]*scanworkflow.Step, 0, len(current))
		for _, c := range current {
			if c.ID != sid {
				kept = append(kept, c)
			}
		}
		if len(kept) == len(current) {
			return nil, shared.ErrNotFound
		}
		// Steps that depended on the removed one no longer do.
		for _, c := range kept {
			c.DependsOn = slices.DeleteFunc(c.DependsOn, func(d string) bool { return d == step.StepKey })
		}
		if err := validateStepsGraph(kept); err != nil {
			return nil, err
		}
		return kept, nil
	})
	if err != nil {
		return err
	}

	s.auditStep(ctx, tenantID, audit.ActionScanWorkflowStepDeleted, step, "removed (its run history is kept)")
	return nil
}

// auditStep records one step change.
func (s *Service) auditStep(ctx context.Context, tenantID string, action audit.Action, step *scanworkflow.Step, what string) {
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(action, audit.ResourceTypeScanWorkflowStep, step.ID.String()).
			WithResourceName(step.Name).
			WithMessage(fmt.Sprintf("Pipeline step '%s' %s", step.Name, what)).
			WithMetadata("template_id", step.ScanWorkflowID.String()).
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
