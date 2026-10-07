package scanrun

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ========== Template Operations ==========

// CreateTemplateInput represents the input for creating a template.
type CreateTemplateInput struct {
	TenantID    string                 `json:"tenant_id" validate:"required,uuid"`
	Name        string                 `json:"name" validate:"required,min=1,max=255"`
	Description string                 `json:"description" validate:"max=1000"`
	Triggers    []scanworkflow.Trigger `json:"triggers"`
	Settings    *scanworkflow.Settings `json:"settings"`
	Tags        []string               `json:"tags" validate:"max=10,dive,max=50"`
	CreatedBy   string                 `json:"created_by" validate:"omitempty,uuid"`
}

// CreateTemplate creates a new scan workflow.
func (s *Service) CreateTemplate(ctx context.Context, input CreateTemplateInput) (*scanworkflow.Workflow, error) {
	s.logger.Info("creating pipeline template", "name", input.Name)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Validate tags format (only alphanumeric, dash, underscore allowed)
	if s.securityValidator != nil && len(input.Tags) > 0 {
		result := s.securityValidator.ValidateIdentifiers(input.Tags, 50, "tags")
		if !result.Valid {
			s.logger.Warn("tags validation failed", "errors", result.Errors)
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	t, err := scanworkflow.NewWorkflow(tenantID, input.Name, input.Description)
	if err != nil {
		return nil, err
	}

	if len(input.Triggers) > 0 {
		t.Triggers = input.Triggers
	}

	if input.Settings != nil {
		t.Settings = *input.Settings
	}

	if len(input.Tags) > 0 {
		t.Tags = input.Tags
	}

	if input.CreatedBy != "" {
		createdByID, err := shared.IDFromString(input.CreatedBy)
		if err == nil {
			t.SetCreatedBy(createdByID)
		}
	}

	if err := s.templateRepo.Create(ctx, t); err != nil {
		return nil, err
	}

	// Audit log: template created
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID, ActorID: input.CreatedBy},
		NewSuccessEvent(audit.ActionScanWorkflowCreated, audit.ResourceTypeScanWorkflow, t.ID.String()).
			WithResourceName(t.Name).
			WithMessage(fmt.Sprintf("Pipeline template '%s' created", t.Name)))

	return t, nil
}

// CloneSystemTemplateInput represents the input for cloning a system template.
type CloneSystemTemplateInput struct {
	TenantID         string `json:"tenant_id" validate:"required,uuid"`
	SystemTemplateID string `json:"system_template_id" validate:"required,uuid"`
	NewName          string `json:"new_name" validate:"omitempty,min=1,max=255"`
	CreatedBy        string `json:"created_by" validate:"omitempty,uuid"`
}

// CloneSystemTemplate clones a system template for a tenant.
// This is the "copy-on-use" mechanism for system templates.
func (s *Service) CloneSystemTemplate(ctx context.Context, input CloneSystemTemplateInput) (*scanworkflow.Workflow, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	templateID, err := shared.IDFromString(input.SystemTemplateID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid template id", shared.ErrValidation)
	}

	// Get system template with steps
	systemTemplate, err := s.templateRepo.GetWithSteps(ctx, templateID)
	if err != nil {
		return nil, err
	}

	// Verify it's a system template
	if !systemTemplate.IsSystemTemplate {
		return nil, fmt.Errorf("%w: template is not a system template", shared.ErrValidation)
	}

	// Determine new name
	newName := input.NewName
	if newName == "" {
		newName = systemTemplate.Name + " (Copy)"
	}

	// Clone the template for tenant
	clone := systemTemplate.Clone(newName)
	clone.TenantID = tenantID

	// Set created by
	if input.CreatedBy != "" {
		createdByID, err := shared.IDFromString(input.CreatedBy)
		if err == nil {
			clone.SetCreatedBy(createdByID)
		}
	}

	// Create the cloned template
	if err := s.templateRepo.Create(ctx, clone); err != nil {
		return nil, err
	}

	// Create cloned steps
	if len(clone.Steps) > 0 {
		if err := s.stepRepo.CreateBatch(ctx, clone.Steps); err != nil {
			// Cleanup on failure
			_ = s.templateRepo.Delete(ctx, clone.ID)
			return nil, fmt.Errorf("failed to create cloned steps: %w", err)
		}
	}

	// Audit log: template cloned
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID, ActorID: input.CreatedBy},
		NewSuccessEvent(audit.ActionScanWorkflowCreated, audit.ResourceTypeScanWorkflow, clone.ID.String()).
			WithResourceName(clone.Name).
			WithMessage(fmt.Sprintf("Pipeline template '%s' cloned from system template '%s'", clone.Name, systemTemplate.Name)).
			WithMetadata("source_template_id", systemTemplate.ID.String()).
			WithMetadata("source_template_name", systemTemplate.Name))

	return clone, nil
}

// GetTemplate retrieves a template by ID.
// For system templates, this returns the template as read-only (for viewing).
// Use CloneSystemTemplate to create an editable copy for a tenant.
func (s *Service) GetTemplate(ctx context.Context, tenantID, templateID string) (*scanworkflow.Workflow, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	pid, err := shared.IDFromString(templateID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid template id", shared.ErrValidation)
	}

	// First try to get tenant's own template
	t, err := s.templateRepo.GetByTenantAndID(ctx, tid, pid)
	if err == nil {
		return t, nil
	}

	// If not found, check if it's a system template (visible to all tenants)
	if errors.Is(err, shared.ErrNotFound) {
		systemTemplate, sysErr := s.templateRepo.GetSystemTemplateByID(ctx, pid)
		if sysErr == nil {
			// Return system template (read-only)
			return systemTemplate, nil
		}
	}

	return nil, err
}

// GetTemplateWithSteps retrieves a template with its steps.
func (s *Service) GetTemplateWithSteps(ctx context.Context, templateID string) (*scanworkflow.Workflow, error) {
	pid, err := shared.IDFromString(templateID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid template id", shared.ErrValidation)
	}

	return s.templateRepo.GetWithSteps(ctx, pid)
}

// ListTemplatesInput represents the input for listing templates.
type ListTemplatesInput struct {
	TenantID string   `json:"tenant_id" validate:"required,uuid"`
	IsActive *bool    `json:"is_active"`
	Tags     []string `json:"tags"`
	Search   string   `json:"search" validate:"max=255"`
	Page     int      `json:"page"`
	PerPage  int      `json:"per_page"`
}

// ListTemplates lists templates with filters.
// Returns both tenant-specific templates AND system templates (available to all tenants).
func (s *Service) ListTemplates(ctx context.Context, input ListTemplatesInput) (pagination.Result[*scanworkflow.Workflow], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*scanworkflow.Workflow]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := scanworkflow.Filter{
		IsActive: input.IsActive,
		Tags:     input.Tags,
		Search:   input.Search,
	}

	page := pagination.New(input.Page, input.PerPage)

	// Use ListWithSystemTemplates to include system templates
	return s.templateRepo.ListWithSystemTemplates(ctx, tenantID, filter, page)
}

// UpdateTemplateInput represents the input for updating a template.
type UpdateTemplateInput struct {
	TenantID        string                   `json:"tenant_id" validate:"required,uuid"`
	TemplateID      string                   `json:"template_id" validate:"required,uuid"`
	Name            string                   `json:"name" validate:"omitempty,min=1,max=255"`
	Description     string                   `json:"description" validate:"max=1000"`
	Triggers        []scanworkflow.Trigger   `json:"triggers"`
	Settings        *scanworkflow.Settings   `json:"settings"`
	Tags            []string                 `json:"tags" validate:"max=10,dive,max=50"`
	IsActive        *bool                    `json:"is_active"`
	UIStartPosition *scanworkflow.UIPosition `json:"ui_start_position"`
	UIEndPosition   *scanworkflow.UIPosition `json:"ui_end_position"`
}

// UpdateTemplate updates a template.
// Note: System templates cannot be updated directly. They must be cloned first.
func (s *Service) UpdateTemplate(ctx context.Context, input UpdateTemplateInput) (*scanworkflow.Workflow, error) {
	t, err := s.GetTemplate(ctx, input.TenantID, input.TemplateID)
	if err != nil {
		return nil, err
	}

	// Protect system templates from direct modification
	if t.IsSystemTemplate {
		return nil, shared.NewDomainError("FORBIDDEN",
			"System templates cannot be modified directly. Please clone it first using 'Use Template' button.",
			shared.ErrForbidden)
	}

	// Verify tenant ownership
	tenantID, _ := shared.IDFromString(input.TenantID)
	if t.TenantID != tenantID {
		return nil, shared.NewDomainError("FORBIDDEN",
			"You can only modify templates owned by your organization",
			shared.ErrForbidden)
	}

	if input.Name != "" {
		t.Name = input.Name
	}

	if input.Description != "" {
		t.Description = input.Description
	}

	if len(input.Triggers) > 0 {
		t.Triggers = input.Triggers
	}

	if input.Settings != nil {
		t.Settings = *input.Settings
	}

	if len(input.Tags) > 0 {
		t.Tags = input.Tags
	}

	// Update UI positions for visual builder
	if input.UIStartPosition != nil {
		t.UIStartPosition = input.UIStartPosition
	}
	if input.UIEndPosition != nil {
		t.UIEndPosition = input.UIEndPosition
	}

	// Track activation/deactivation for audit
	var activationChange string
	if input.IsActive != nil {
		switch {
		case *input.IsActive && !t.IsActive:
			// Activating the template - validate tool references first
			// Get template with steps for validation
			templateWithSteps, err := s.templateRepo.GetWithSteps(ctx, t.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to get template steps for validation: %w", err)
			}
			if err := s.ValidateToolReferences(ctx, templateWithSteps, tenantID); err != nil {
				return nil, fmt.Errorf("cannot activate pipeline: %w", err)
			}
			t.Activate()
			activationChange = activationChangeActivated
		case *input.IsActive:
			// Already active, just confirm
			t.Activate()
		default:
			t.Deactivate()
			activationChange = activationChangeDeactivated
		}
	}

	if err := s.templateRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	// Audit log: template updated
	if activationChange != "" {
		action := audit.ActionScanWorkflowUpdated
		if activationChange == activationChangeActivated {
			action = audit.ActionScanWorkflowActivated
		} else {
			action = audit.ActionScanWorkflowDeactivated
		}
		s.logAudit(ctx, AuditContext{TenantID: input.TenantID},
			NewSuccessEvent(action, audit.ResourceTypeScanWorkflow, t.ID.String()).
				WithResourceName(t.Name).
				WithMessage(fmt.Sprintf("Pipeline template '%s' %s", t.Name, activationChange)))
	} else {
		s.logAudit(ctx, AuditContext{TenantID: input.TenantID},
			NewSuccessEvent(audit.ActionScanWorkflowUpdated, audit.ResourceTypeScanWorkflow, t.ID.String()).
				WithResourceName(t.Name).
				WithMessage(fmt.Sprintf("Pipeline template '%s' updated", t.Name)))
	}

	return t, nil
}

// errSystemTemplateReadOnly refuses a tenant change to a system template.
func errSystemTemplateReadOnly() error {
	return shared.NewDomainError("FORBIDDEN",
		"System templates cannot be modified directly. Please clone it first using 'Use Template' button.",
		shared.ErrForbidden)
}

// getWritableTemplate returns a template the tenant may change: its own.
// GetTemplate also resolves the shared system templates (so every tenant can
// read and clone them); those are refused here. Deleting the Quick Scan
// template or editing its steps used to change it for every tenant, and a
// delete cascaded to every tenant's runs of it.
func (s *Service) getWritableTemplate(ctx context.Context, tenantID, templateID string) (*scanworkflow.Workflow, error) {
	t, err := s.GetTemplate(ctx, tenantID, templateID)
	if err != nil {
		return nil, err
	}
	if t.IsSystemTemplate {
		return nil, errSystemTemplateReadOnly()
	}
	return t, nil
}

// DeleteTemplate deletes a template.
func (s *Service) DeleteTemplate(ctx context.Context, tenantID, templateID string) error {
	t, err := s.getWritableTemplate(ctx, tenantID, templateID)
	if err != nil {
		return err
	}

	templateName := t.Name

	// Use transaction if DB is available for atomic delete
	if s.db != nil {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		// Delete steps first (within transaction)
		if err := s.stepRepo.DeleteByScanWorkflowIDInTx(ctx, tx, t.ID); err != nil {
			return err
		}

		// Delete template (within transaction)
		if err := s.templateRepo.DeleteInTx(ctx, tx, t.ID); err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit transaction: %w", err)
		}
	} else {
		// Fallback to non-transactional (backward compatibility)
		if err := s.stepRepo.DeleteByScanWorkflowID(ctx, t.ID); err != nil {
			return err
		}

		if err := s.templateRepo.Delete(ctx, t.ID); err != nil {
			return err
		}
	}

	// Audit log: template deleted (AFTER commit)
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionScanWorkflowDeleted, audit.ResourceTypeScanWorkflow, templateID).
			WithResourceName(templateName).
			WithMessage(fmt.Sprintf("Pipeline template '%s' deleted", templateName)))

	return nil
}

// CloneTemplateInput represents the input for cloning a template.
type CloneTemplateInput struct {
	TenantID   string `json:"tenant_id" validate:"required,uuid"`
	TemplateID string `json:"template_id" validate:"required,uuid"`
	NewName    string `json:"new_name" validate:"required,min=1,max=255"`
	ClonedBy   string `json:"cloned_by" validate:"omitempty,uuid"`
}

// CloneTemplate creates a copy of an existing template with all its steps.
// This supports cloning both tenant templates AND system templates.
func (s *Service) CloneTemplate(ctx context.Context, input CloneTemplateInput) (*scanworkflow.Workflow, error) {
	s.logger.Info("cloning pipeline template", "template_id", input.TemplateID, "new_name", input.NewName)

	// Get the original template with steps
	original, err := s.GetTemplateWithSteps(ctx, input.TemplateID)
	if err != nil {
		return nil, err
	}

	// Verify tenant access:
	// - System templates can be cloned by any tenant
	// - Non-system templates can only be cloned by the owning tenant
	if !original.IsSystemTemplate && original.TenantID.String() != input.TenantID {
		return nil, shared.ErrNotFound
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Create new template with same settings
	newTemplate, err := scanworkflow.NewWorkflow(tenantID, input.NewName, original.Description)
	if err != nil {
		return nil, err
	}

	// Copy triggers and settings
	newTemplate.Triggers = original.Triggers
	newTemplate.Settings = original.Settings
	newTemplate.Tags = original.Tags
	newTemplate.Deactivate() // Start deactivated

	if input.ClonedBy != "" {
		clonedByID, err := shared.IDFromString(input.ClonedBy)
		if err == nil {
			newTemplate.SetCreatedBy(clonedByID)
		}
	}

	// Create the new template
	if err := s.templateRepo.Create(ctx, newTemplate); err != nil {
		return nil, err
	}

	// Clone all steps
	for _, originalStep := range original.Steps {
		step, err := scanworkflow.NewStep(newTemplate.ID, originalStep.StepKey, originalStep.Name, originalStep.StepOrder, originalStep.Capabilities)
		if err != nil {
			return nil, err
		}

		step.Description = originalStep.Description
		step.SetUIPosition(originalStep.UIPosition.X, originalStep.UIPosition.Y)
		step.SetTool(originalStep.Tool)
		step.SetConfig(originalStep.Config)
		if err := step.SetTimeout(originalStep.TimeoutSeconds); err != nil {
			// Use default timeout if original is invalid (shouldn't happen for existing data)
			_ = step.SetTimeout(scanworkflow.DefaultTimeoutSeconds)
		}
		step.SetDependencies(originalStep.DependsOn)
		if err := step.SetCondition(originalStep.Condition); err != nil {
			// Use default condition if original is invalid (e.g., expression type)
			_ = step.SetCondition(scanworkflow.AlwaysCondition())
		}
		step.SetRetry(originalStep.MaxRetries, originalStep.RetryDelaySeconds)

		if err := s.stepRepo.Create(ctx, step); err != nil {
			return nil, err
		}
		newTemplate.Steps = append(newTemplate.Steps, step)
	}

	// Audit log: template cloned
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID, ActorID: input.ClonedBy},
		NewSuccessEvent(audit.ActionScanWorkflowCreated, audit.ResourceTypeScanWorkflow, newTemplate.ID.String()).
			WithResourceName(newTemplate.Name).
			WithMessage(fmt.Sprintf("Pipeline template '%s' cloned from '%s'", newTemplate.Name, original.Name)).
			WithMetadata("source_template_id", input.TemplateID))

	return newTemplate, nil
}
