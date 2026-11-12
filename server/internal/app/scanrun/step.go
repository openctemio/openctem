package scanrun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ValidateToolReferences refuses a workflow whose steps cannot be planned at
// all: a step with neither a tool nor capabilities, or with capabilities
// that name more than one kind of scan. A tool that is missing, turned off
// or that no tool implements never refuses the workflow (activating it, or
// running it): the run skips that step with the reason (StepToolSkips) and
// goes on with the others.
func (s *Service) ValidateToolReferences(ctx context.Context, template *scanworkflow.Workflow, tenantID shared.ID) error {
	_, err := s.StepToolSkips(ctx, template, tenantID)
	return err
}

// StepToolSkips is the steps of a workflow that no tool of the organization
// runs, with the reason each is skipped: a pinned tool that is not
// installed (TOOL_NOT_INSTALLED) or turned off (TOOL_DISABLED), or a
// capability no active tool implements (NO_MATCHING_TOOL). The tool lookups
// are scoped to the tenant (its own tools and platform tools), so another
// organization's tool never counts. A step that cannot be planned at all is
// the error (see ValidateToolReferences).
func (s *Service) StepToolSkips(ctx context.Context, template *scanworkflow.Workflow, tenantID shared.ID) (map[string]scanapp.StepSkip, error) {
	skips := map[string]scanapp.StepSkip{}
	if template == nil || len(template.Steps) == 0 {
		return skips, nil
	}
	if s.toolRepo == nil {
		s.logger.Warn("tool repository not available, skipping tool validation")
		return skips, nil
	}

	var invalid []string
	for _, step := range template.Steps {
		switch {
		case step.Tool != "":
			// The tool: platform first, then the organization's own.
			t, err := s.toolRepo.GetByName(ctx, tenantID, step.Tool)
			if err != nil {
				t, err = s.toolRepo.GetByTenantAndName(ctx, tenantID, step.Tool)
			}
			switch {
			case err != nil || t == nil:
				skips[step.StepKey] = scanapp.StepSkip{Code: scanrun.FailureToolNotInstalled,
					Reason: fmt.Sprintf("skipped: tool %s is not installed in this organization", step.Tool)}
			case !t.IsActive:
				skips[step.StepKey] = scanapp.StepSkip{Code: scanrun.FailureToolDisabled,
					Reason: fmt.Sprintf("skipped: tool %s is turned off", step.Tool)}
			}
		case len(step.Capabilities) > 0:
			// The planner's own rule (scan.ResolveStepTool), so a step that
			// passes is a step the dispatcher names a scanner for.
			if _, err := scanapp.ResolveStepTool(ctx, s.toolRepo, tenantID, step); err != nil {
				if skip, ok := scanapp.UnsupportedStepSkip(step, err); ok {
					skips[step.StepKey] = skip
					continue
				}
				invalid = append(invalid, fmt.Sprintf("step '%s' (%s)", step.StepKey, resolveReason(err)))
			}
		default:
			invalid = append(invalid, fmt.Sprintf("step '%s' has no tool or capabilities", step.StepKey))
		}
	}
	if len(invalid) > 0 {
		return nil, shared.NewDomainError("TOOL_UNAVAILABLE", "steps that cannot run: "+strings.Join(invalid, "; "), shared.ErrValidation)
	}
	return skips, nil
}

// DeactivateScanWorkflowsByTool deactivates all active scan workflows that use a specific tool.
// This is called when a tool is deactivated or deleted to ensure data consistency.
// Returns the count of deactivated scan workflows and list of affected scan workflow IDs.
func (s *Service) DeactivateScanWorkflowsByTool(ctx context.Context, tenantID shared.ID, toolName string) (int, []shared.ID, error) {
	if toolName == "" {
		return 0, nil, nil
	}

	// Find the tenant's active scan workflows using this tool
	scanWorkflowIDs, err := s.stepRepo.FindScanWorkflowIDsByToolName(ctx, tenantID, toolName)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to find scan workflows by tool: %w", err)
	}

	if len(scanWorkflowIDs) == 0 {
		return 0, nil, nil
	}

	// Deactivate each scan workflow
	deactivatedCount := 0
	for _, id := range scanWorkflowIDs {
		template, err := s.templateRepo.GetByID(ctx, id)
		if err != nil {
			s.logger.Warn("failed to get scan workflow for deactivation",
				"scan_workflow_id", id.String(),
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
			s.logger.Warn("failed to deactivate scan workflow",
				"scan_workflow_id", id.String(),
				"tool_name", toolName,
				"error", err)
			continue
		}

		// Cascade deactivate scans using this scan workflow
		if s.scanDeactivator != nil {
			scanCount, err := s.scanDeactivator.DeactivateScansByScanWorkflow(ctx, id)
			if err != nil {
				s.logger.Warn("failed to deactivate scans for scan workflow",
					"scan_workflow_id", id.String(),
					"error", err)
			} else if scanCount > 0 {
				s.logger.Info("cascade deactivated scans for scan workflow",
					"scan_workflow_id", id.String(),
					"deactivated_scans", scanCount)
			}
		}

		s.logger.Info("scan workflow deactivated due to tool change",
			"scan_workflow_id", id.String(),
			"scan_workflow_name", template.Name,
			"tool_name", toolName)
		deactivatedCount++
	}

	return deactivatedCount, scanWorkflowIDs, nil
}

// GetScanWorkflowsUsingTool returns all active scan workflow IDs that use a specific tool.
// This can be used to check if a tool can be safely deleted.
func (s *Service) GetScanWorkflowsUsingTool(ctx context.Context, tenantID shared.ID, toolName string) ([]shared.ID, error) {
	if toolName == "" {
		return nil, nil
	}
	return s.stepRepo.FindScanWorkflowIDsByToolName(ctx, tenantID, toolName)
}

// GetSteps retrieves all steps for a template.
func (s *Service) GetSteps(ctx context.Context, templateID string) ([]*scanworkflow.Step, error) {
	pid, err := shared.IDFromString(templateID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid template id", shared.ErrValidation)
	}

	return s.stepRepo.GetByScanWorkflowID(ctx, pid)
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
