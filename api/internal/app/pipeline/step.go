package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

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
	stepsWithoutExecutor := make([]string, 0, len(template.Steps))
	var stepsWithNoMatchingCapabilities []string

	for _, step := range template.Steps {
		// Case 1: Step has explicit tool specified
		if step.Tool != "" {
			// Try to find the tool (platform first, then tenant-specific)
			t, err := s.toolRepo.GetByName(ctx, tenantID, step.Tool)
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

		// Case 2: Step has no tool but has capabilities: the planner's own
		// rule (scan.ResolveStepTool), so a step that validates is a step
		// the dispatcher names a scanner for (research/27 F1).
		if len(step.Capabilities) > 0 {
			if _, err := scanapp.ResolveStepTool(ctx, s.toolRepo, tenantID, step); err != nil {
				stepsWithNoMatchingCapabilities = append(stepsWithNoMatchingCapabilities,
					fmt.Sprintf("step '%s' with capabilities %v (%s)", step.StepKey, step.Capabilities, resolveReason(err)))
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
func (s *Service) DeactivatePipelinesByTool(ctx context.Context, tenantID shared.ID, toolName string) (int, []shared.ID, error) {
	if toolName == "" {
		return 0, nil, nil
	}

	// Find the tenant's active pipelines using this tool
	pipelineIDs, err := s.stepRepo.FindPipelineIDsByToolName(ctx, tenantID, toolName)
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
func (s *Service) GetPipelinesUsingTool(ctx context.Context, tenantID shared.ID, toolName string) ([]shared.ID, error) {
	if toolName == "" {
		return nil, nil
	}
	return s.stepRepo.FindPipelineIDsByToolName(ctx, tenantID, toolName)
}

// GetSteps retrieves all steps for a template.
func (s *Service) GetSteps(ctx context.Context, templateID string) ([]*pipeline.Step, error) {
	pid, err := shared.IDFromString(templateID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid template id", shared.ErrValidation)
	}

	return s.stepRepo.GetByPipelineID(ctx, pid)
}

// resolveReason is the caller-facing reason a step's capabilities resolved
// to no tool.
func resolveReason(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) && de.Message != "" {
		return de.Message
	}
	return "no active tool"
}
