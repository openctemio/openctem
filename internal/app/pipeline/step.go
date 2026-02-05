package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ========== Step Operations ==========

// AddStepInput represents the input for adding a step.
// Capabilities are optional - if not provided and tool is specified, they will be derived from the tool.
type AddStepInput struct {
	TenantID          string              `json:"tenant_id" validate:"required,uuid"`
	TemplateID        string              `json:"template_id" validate:"required,uuid"`
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

// AddStep adds a step to a template.
func (s *Service) AddStep(ctx context.Context, input AddStepInput) (*pipeline.Step, error) {
	// Verify template exists and belongs to tenant
	t, err := s.GetTemplate(ctx, input.TenantID, input.TemplateID)
	if err != nil {
		return nil, err
	}

	// Validate step_key format (only alphanumeric, dash, underscore allowed)
	tenantID, _ := shared.IDFromString(input.TenantID)
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateIdentifier(input.StepKey, 100, "step_key")
		if !result.Valid {
			s.logger.Warn("step_key validation failed",
				"template_id", input.TemplateID,
				"step_key", input.StepKey,
				"errors", result.Errors)
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	// Derive capabilities from tool if not provided
	capabilities := input.Capabilities
	if len(capabilities) == 0 && input.Tool != "" && s.toolRepo != nil {
		// Try to get capabilities from tool
		tool, err := s.toolRepo.GetByName(ctx, input.Tool)
		if err != nil {
			// Try tenant-specific tool
			tool, err = s.toolRepo.GetByTenantAndName(ctx, tenantID, input.Tool)
		}
		if err == nil && tool != nil && len(tool.Capabilities) > 0 {
			capabilities = tool.Capabilities
		}
	}

	// Only set default capability if tool is specified but has no capabilities
	// If no tool is selected, capabilities should be empty
	if len(capabilities) == 0 && input.Tool != "" {
		capabilities = []string{"scan"}
	}

	// Security validation: validate tool and config (skip capability-tool matching since we derive from tool)
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateStepConfig(ctx, tenantID, input.Tool, capabilities, input.Config)
		if !result.Valid {
			s.logger.Warn("step config validation failed",
				"template_id", input.TemplateID,
				"step_key", input.StepKey,
				"errors", result.Errors)
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	step, err := pipeline.NewStep(t.ID, input.StepKey, input.Name, input.Order, capabilities)
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

	if err := s.stepRepo.Create(ctx, step); err != nil {
		// Security audit: log step_key collision (potential attack or bug)
		if errors.Is(err, shared.ErrAlreadyExists) {
			s.logger.Warn("step_key collision detected",
				"tenant_id", input.TenantID,
				"template_id", input.TemplateID,
				"step_key", input.StepKey,
				"step_name", input.Name,
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

	// Audit log: step created
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID},
		NewSuccessEvent(audit.ActionPipelineStepCreated, audit.ResourceTypePipelineStep, step.ID.String()).
			WithResourceName(step.Name).
			WithMessage(fmt.Sprintf("Pipeline step '%s' added to template", step.Name)).
			WithMetadata("template_id", input.TemplateID).
			WithMetadata("step_key", step.StepKey))

	return step, nil
}

// ValidateSteps validates a list of step inputs without creating them.
// This is used to pre-validate steps before deleting existing ones during update.
func (s *Service) ValidateSteps(ctx context.Context, inputs []AddStepInput) error {
	if len(inputs) == 0 {
		return nil
	}

	// Get tenant ID from first input
	tenantID, err := shared.IDFromString(inputs[0].TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	for _, input := range inputs {
		// Validate step_key format
		if s.securityValidator != nil {
			result := s.securityValidator.ValidateIdentifier(input.StepKey, 100, "step_key")
			if !result.Valid {
				s.logger.Warn("step_key validation failed",
					"template_id", input.TemplateID,
					"step_key", input.StepKey,
					"errors", result.Errors)
				return fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
			}
		}

		// Derive capabilities from tool if not provided
		capabilities := input.Capabilities
		if len(capabilities) == 0 && input.Tool != "" && s.toolRepo != nil {
			// Try to get capabilities from tool
			t, err := s.toolRepo.GetByName(ctx, input.Tool)
			if err != nil {
				// Try tenant-specific tool
				t, err = s.toolRepo.GetByTenantAndName(ctx, tenantID, input.Tool)
			}
			if err == nil && t != nil && len(t.Capabilities) > 0 {
				capabilities = t.Capabilities
			}
		}

		// Only set default capability if tool is specified but has no capabilities
		// If no tool is selected, capabilities should be empty
		if len(capabilities) == 0 && input.Tool != "" {
			capabilities = []string{"scan"}
		}

		// Security validation: validate tool and config
		if s.securityValidator != nil {
			result := s.securityValidator.ValidateStepConfig(ctx, tenantID, input.Tool, capabilities, input.Config)
			if !result.Valid {
				s.logger.Warn("step config validation failed during pre-validation",
					"template_id", input.TemplateID,
					"step_key", input.StepKey,
					"errors", result.Errors)
				return fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
			}
		}
	}

	return nil
}

// ValidateToolReferences validates that all tools referenced by pipeline steps are available and active.
// This should be called before triggering a pipeline or activating it to ensure all required tools are present.
// Returns an error with details if any tool is missing or inactive.
//
// Validation rules:
// 1. If step has Tool specified → Tool must exist and be active
// 2. If step has no Tool but has Capabilities → At least one active tool must match those capabilities
// 3. If step has no Tool AND no Capabilities → Step is invalid (cannot execute)
func (s *Service) ValidateToolReferences(ctx context.Context, template *pipeline.Template, tenantID shared.ID) error {
	if template == nil || len(template.Steps) == 0 {
		return nil
	}

	if s.toolRepo == nil {
		s.logger.Warn("tool repository not available, skipping tool validation")
		return nil
	}

	var missingTools []string
	var inactiveTools []string
	var stepsWithoutExecutor []string
	var stepsWithNoMatchingCapabilities []string

	for _, step := range template.Steps {
		// Case 1: Step has explicit tool specified
		if step.Tool != "" {
			// Try to find the tool (platform first, then tenant-specific)
			t, err := s.toolRepo.GetByName(ctx, step.Tool)
			if err != nil {
				// Try tenant-specific tool
				t, err = s.toolRepo.GetByTenantAndName(ctx, tenantID, step.Tool)
			}

			if err != nil {
				missingTools = append(missingTools, fmt.Sprintf("%s (step: %s)", step.Tool, step.StepKey))
				continue
			}

			if !t.IsActive {
				inactiveTools = append(inactiveTools, fmt.Sprintf("%s (step: %s)", step.Tool, step.StepKey))
			}
			continue
		}

		// Case 2: Step has no tool but has capabilities - find matching tool
		if len(step.Capabilities) > 0 {
			// Try to find an active tool that matches the capabilities
			matchingTool, err := s.toolRepo.FindByCapabilities(ctx, tenantID, step.Capabilities)
			if err != nil || matchingTool == nil {
				stepsWithNoMatchingCapabilities = append(stepsWithNoMatchingCapabilities,
					fmt.Sprintf("step '%s' with capabilities %v", step.StepKey, step.Capabilities))
			} else if !matchingTool.IsActive {
				inactiveTools = append(inactiveTools,
					fmt.Sprintf("%s (step: %s, matched by capabilities)", matchingTool.Name, step.StepKey))
			}
			continue
		}

		// Case 3: Step has neither tool nor capabilities - invalid step
		stepsWithoutExecutor = append(stepsWithoutExecutor, step.StepKey)
	}

	// Build error message if there are issues
	var errParts []string

	if len(stepsWithoutExecutor) > 0 {
		errParts = append(errParts,
			fmt.Sprintf("steps without tool or capabilities: %v", stepsWithoutExecutor))
	}
	if len(missingTools) > 0 {
		errParts = append(errParts, fmt.Sprintf("tools not found: %v", missingTools))
	}
	if len(inactiveTools) > 0 {
		errParts = append(errParts, fmt.Sprintf("tools not active: %v", inactiveTools))
	}
	if len(stepsWithNoMatchingCapabilities) > 0 {
		errParts = append(errParts,
			fmt.Sprintf("no active tools match capabilities: %v", stepsWithNoMatchingCapabilities))
	}

	if len(errParts) > 0 {
		return shared.NewDomainError("TOOL_UNAVAILABLE", strings.Join(errParts, "; "), shared.ErrValidation)
	}

	return nil
}

// DeactivatePipelinesByTool deactivates all active pipelines that use a specific tool.
// This is called when a tool is deactivated or deleted to ensure data consistency.
// Returns the count of deactivated pipelines and list of affected pipeline IDs.
func (s *Service) DeactivatePipelinesByTool(ctx context.Context, toolName string) (int, []shared.ID, error) {
	if toolName == "" {
		return 0, nil, nil
	}

	// Find all active pipelines using this tool
	pipelineIDs, err := s.stepRepo.FindPipelineIDsByToolName(ctx, toolName)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to find pipelines by tool: %w", err)
	}

	if len(pipelineIDs) == 0 {
		return 0, nil, nil
	}

	// Deactivate each pipeline
	deactivatedCount := 0
	for _, id := range pipelineIDs {
		template, err := s.templateRepo.GetByID(ctx, id)
		if err != nil {
			s.logger.Warn("failed to get pipeline for deactivation",
				"pipeline_id", id.String(),
				"tool_name", toolName,
				"error", err)
			continue
		}

		// Skip if already inactive
		if !template.IsActive {
			continue
		}

		// Deactivate
		template.Deactivate()
		if err := s.templateRepo.Update(ctx, template); err != nil {
			s.logger.Warn("failed to deactivate pipeline",
				"pipeline_id", id.String(),
				"tool_name", toolName,
				"error", err)
			continue
		}

		// Cascade deactivate scans using this pipeline
		if s.scanDeactivator != nil {
			scanCount, err := s.scanDeactivator.DeactivateScansByPipeline(ctx, id)
			if err != nil {
				s.logger.Warn("failed to deactivate scans for pipeline",
					"pipeline_id", id.String(),
					"error", err)
			} else if scanCount > 0 {
				s.logger.Info("cascade deactivated scans for pipeline",
					"pipeline_id", id.String(),
					"deactivated_scans", scanCount)
			}
		}

		s.logger.Info("pipeline deactivated due to tool change",
			"pipeline_id", id.String(),
			"pipeline_name", template.Name,
			"tool_name", toolName)
		deactivatedCount++
	}

	return deactivatedCount, pipelineIDs, nil
}

// GetPipelinesUsingTool returns all active pipeline IDs that use a specific tool.
// This can be used to check if a tool can be safely deleted.
func (s *Service) GetPipelinesUsingTool(ctx context.Context, toolName string) ([]shared.ID, error) {
	if toolName == "" {
		return nil, nil
	}
	return s.stepRepo.FindPipelineIDsByToolName(ctx, toolName)
}

// GetSteps retrieves all steps for a template.
func (s *Service) GetSteps(ctx context.Context, templateID string) ([]*pipeline.Step, error) {
	pid, err := shared.IDFromString(templateID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid template id", shared.ErrValidation)
	}

	return s.stepRepo.GetByPipelineID(ctx, pid)
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

	// Security validation: validate tool, capabilities, and config
	tenantID, _ := shared.IDFromString(input.TenantID)
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateStepConfig(ctx, tenantID, input.Tool, input.Capabilities, input.Config)
		if !result.Valid {
			s.logger.Warn("step config validation failed",
				"step_id", stepID,
				"errors", result.Errors)
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

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

	if input.MaxRetries >= 0 {
		step.SetRetry(input.MaxRetries, input.RetryDelaySeconds)
	}

	if err := s.stepRepo.Update(ctx, step); err != nil {
		return nil, err
	}

	// Audit log: step updated
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID},
		NewSuccessEvent(audit.ActionPipelineStepUpdated, audit.ResourceTypePipelineStep, step.ID.String()).
			WithResourceName(step.Name).
			WithMessage(fmt.Sprintf("Pipeline step '%s' updated", step.Name)).
			WithMetadata("step_key", step.StepKey))

	return step, nil
}

// DeleteStep deletes a step.
func (s *Service) DeleteStep(ctx context.Context, tenantID, stepID string) error {
	sid, err := shared.IDFromString(stepID)
	if err != nil {
		return fmt.Errorf("%w: invalid step id", shared.ErrValidation)
	}

	// Get step for audit logging
	step, err := s.stepRepo.GetByID(ctx, sid)
	if err != nil {
		return err
	}

	stepName := step.Name
	stepKey := step.StepKey

	if err := s.stepRepo.Delete(ctx, sid); err != nil {
		return err
	}

	// Audit log: step deleted
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionPipelineStepDeleted, audit.ResourceTypePipelineStep, stepID).
			WithResourceName(stepName).
			WithMessage(fmt.Sprintf("Pipeline step '%s' deleted", stepName)).
			WithMetadata("step_key", stepKey))

	return nil
}

// DeleteStepsByPipelineID deletes all steps for a pipeline.
func (s *Service) DeleteStepsByPipelineID(ctx context.Context, tenantID, pipelineID string) error {
	pid, err := shared.IDFromString(pipelineID)
	if err != nil {
		return fmt.Errorf("%w: invalid pipeline id", shared.ErrValidation)
	}

	// Verify pipeline belongs to tenant
	_, err = s.GetTemplate(ctx, tenantID, pipelineID)
	if err != nil {
		return err
	}

	return s.stepRepo.DeleteByPipelineID(ctx, pid)
}
