// Package app provides adapters for connecting services to sub-packages.
// These adapters implement the interfaces expected by the scan and pipeline
// sub-packages while delegating to the concrete app-level services.
package app

import (
	"context"

	"github.com/openctemio/api/internal/app/pipeline"
	"github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/templatesource"
)

// =============================================================================
// Audit Service Adapters
// =============================================================================

// scanAuditServiceAdapter adapts AuditService to scan.AuditService interface.
type scanAuditServiceAdapter struct {
	svc *AuditService
}

// NewScanAuditServiceAdapter creates an adapter for the scan package's AuditService interface.
func NewScanAuditServiceAdapter(svc *AuditService) scan.AuditService {
	return &scanAuditServiceAdapter{svc: svc}
}

// LogEvent implements scan.AuditService.
func (a *scanAuditServiceAdapter) LogEvent(ctx context.Context, actx scan.AuditContext, event scan.AuditEvent) error {
	// Convert scan.AuditEvent to app.AuditEvent
	appEvent := AuditEvent{
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		ResourceName: event.ResourceName,
		Message:      event.Message,
		Metadata:     event.Metadata,
	}

	// Convert success/error to Result
	if event.Success {
		appEvent.Result = audit.ResultSuccess
	} else {
		appEvent.Result = audit.ResultFailure
		if event.Error != nil {
			appEvent.Message = event.Error.Error()
		}
	}

	// Convert scan.AuditContext to app.AuditContext
	appCtx := AuditContext{
		TenantID: actx.TenantID,
		ActorID:  actx.ActorID,
	}

	return a.svc.LogEvent(ctx, appCtx, appEvent)
}

// pipelineAuditServiceAdapter adapts AuditService to pipeline.AuditService interface.
type pipelineAuditServiceAdapter struct {
	svc *AuditService
}

// NewPipelineAuditServiceAdapter creates an adapter for the pipeline package's AuditService interface.
func NewPipelineAuditServiceAdapter(svc *AuditService) pipeline.AuditService {
	return &pipelineAuditServiceAdapter{svc: svc}
}

// LogEvent implements pipeline.AuditService.
func (a *pipelineAuditServiceAdapter) LogEvent(ctx context.Context, actx pipeline.AuditContext, event pipeline.AuditEvent) error {
	// Convert pipeline.AuditEvent to app.AuditEvent
	appEvent := AuditEvent{
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		ResourceName: event.ResourceName,
		Message:      event.Message,
		Metadata:     event.Metadata,
	}

	// Convert success/error to Result
	if event.Success {
		appEvent.Result = audit.ResultSuccess
	} else {
		appEvent.Result = audit.ResultFailure
		if event.Error != nil {
			appEvent.Message = event.Error.Error()
		}
	}

	// Convert pipeline.AuditContext to app.AuditContext
	appCtx := AuditContext{
		TenantID: actx.TenantID,
		ActorID:  actx.ActorID,
	}

	return a.svc.LogEvent(ctx, appCtx, appEvent)
}

// =============================================================================
// Agent Selector Adapter
// =============================================================================

// scanAgentSelectorAdapter adapts AgentSelector to scan.AgentSelector interface.
type scanAgentSelectorAdapter struct {
	selector *AgentSelector
}

// NewScanAgentSelectorAdapter creates an adapter for the scan package's AgentSelector interface.
func NewScanAgentSelectorAdapter(selector *AgentSelector) scan.AgentSelector {
	return &scanAgentSelectorAdapter{selector: selector}
}

// CheckAgentAvailability implements scan.AgentSelector.
func (a *scanAgentSelectorAdapter) CheckAgentAvailability(ctx context.Context, tenantID shared.ID, tool string, tenantOnly bool) *scan.AgentAvailability {
	result := a.selector.CheckAgentAvailability(ctx, tenantID, tool, tenantOnly)
	return &scan.AgentAvailability{
		HasTenantAgent: result.HasTenantAgent,
		Available:      result.Available,
		Message:        result.Message,
	}
}

// CanUsePlatformAgents implements scan.AgentSelector.
// In OSS edition, platform agents are not available.
func (a *scanAgentSelectorAdapter) CanUsePlatformAgents(ctx context.Context, tenantID shared.ID) (bool, string) {
	return false, "Platform agents not available in OSS edition"
}

// SelectAgent implements scan.AgentSelector.
func (a *scanAgentSelectorAdapter) SelectAgent(ctx context.Context, req scan.SelectAgentRequest) (*scan.SelectAgentResult, error) {
	// Make the call with app types
	appReq := SelectAgentRequest{
		TenantID:     req.TenantID,
		Capabilities: req.Capabilities,
		Tool:         req.Tool,
		Mode:         SelectTenantOnly,
		AllowQueue:   req.AllowQueue,
	}

	result, err := a.selector.SelectAgent(ctx, appReq)
	if err != nil {
		return nil, err
	}

	return &scan.SelectAgentResult{
		Agent: result.Agent,
	}, nil
}

// pipelineAgentSelectorAdapter adapts AgentSelector to pipeline.AgentSelector interface.
type pipelineAgentSelectorAdapter struct {
	selector *AgentSelector
}

// NewPipelineAgentSelectorAdapter creates an adapter for the pipeline package's AgentSelector interface.
func NewPipelineAgentSelectorAdapter(selector *AgentSelector) pipeline.AgentSelector {
	return &pipelineAgentSelectorAdapter{selector: selector}
}

// SelectAgent implements pipeline.AgentSelector.
func (a *pipelineAgentSelectorAdapter) SelectAgent(ctx context.Context, req pipeline.SelectAgentRequest) (*pipeline.SelectAgentResult, error) {
	// Make the call with app types
	appReq := SelectAgentRequest{
		TenantID:     req.TenantID,
		Capabilities: req.Capabilities,
		Tool:         req.Tool,
		Mode:         SelectTenantOnly,
		AllowQueue:   req.AllowQueue,
	}

	result, err := a.selector.SelectAgent(ctx, appReq)
	if err != nil {
		return nil, err
	}

	return &pipeline.SelectAgentResult{
		Agent: result.Agent,
	}, nil
}

// CanUsePlatformAgents implements pipeline.AgentSelector.
// In OSS edition, platform agents are not available.
func (a *pipelineAgentSelectorAdapter) CanUsePlatformAgents(ctx context.Context, tenantID shared.ID) (bool, string) {
	return false, "Platform agents not available in OSS edition"
}

// =============================================================================
// Template Syncer Adapter
// =============================================================================

// scanTemplateSyncerAdapter adapts TemplateSyncer to scan.TemplateSyncer interface.
type scanTemplateSyncerAdapter struct {
	syncer *TemplateSyncer
}

// NewScanTemplateSyncerAdapter creates an adapter for the scan package's TemplateSyncer interface.
func NewScanTemplateSyncerAdapter(syncer *TemplateSyncer) scan.TemplateSyncer {
	return &scanTemplateSyncerAdapter{syncer: syncer}
}

// SyncSource implements scan.TemplateSyncer.
func (a *scanTemplateSyncerAdapter) SyncSource(ctx context.Context, source *templatesource.TemplateSource) (*scan.TemplateSyncResult, error) {
	result, err := a.syncer.SyncSource(ctx, source)
	if err != nil {
		return nil, err
	}
	return &scan.TemplateSyncResult{
		Success:        result.Success,
		TemplatesFound: result.TemplatesFound,
		TemplatesAdded: result.TemplatesAdded,
	}, nil
}

// =============================================================================
// Security Validator Adapters
// =============================================================================

// scanSecurityValidatorAdapter adapts SecurityValidator to scan.SecurityValidator interface.
type scanSecurityValidatorAdapter struct {
	validator *SecurityValidator
}

// NewScanSecurityValidatorAdapter creates an adapter for the scan package's SecurityValidator interface.
func NewScanSecurityValidatorAdapter(validator *SecurityValidator) scan.SecurityValidator {
	return &scanSecurityValidatorAdapter{validator: validator}
}

// ValidateIdentifier implements scan.SecurityValidator.
func (a *scanSecurityValidatorAdapter) ValidateIdentifier(value string, maxLen int, fieldName string) *scan.ValidationResult {
	result := a.validator.ValidateIdentifier(value, maxLen, fieldName)
	return convertValidationResult(result)
}

// ValidateIdentifiers implements scan.SecurityValidator.
func (a *scanSecurityValidatorAdapter) ValidateIdentifiers(values []string, maxLen int, fieldName string) *scan.ValidationResult {
	result := a.validator.ValidateIdentifiers(values, maxLen, fieldName)
	return convertValidationResult(result)
}

// ValidateScannerConfig implements scan.SecurityValidator.
func (a *scanSecurityValidatorAdapter) ValidateScannerConfig(ctx context.Context, tenantID shared.ID, config map[string]any) *scan.ValidationResult {
	result := a.validator.ValidateScannerConfig(ctx, tenantID, config)
	return convertValidationResult(result)
}

// ValidateCronExpression implements scan.SecurityValidator.
func (a *scanSecurityValidatorAdapter) ValidateCronExpression(cronExpr string) error {
	return a.validator.ValidateCronExpression(cronExpr)
}

// pipelineSecurityValidatorAdapter adapts SecurityValidator to pipeline.SecurityValidator interface.
type pipelineSecurityValidatorAdapter struct {
	validator *SecurityValidator
}

// NewPipelineSecurityValidatorAdapter creates an adapter for the pipeline package's SecurityValidator interface.
func NewPipelineSecurityValidatorAdapter(validator *SecurityValidator) pipeline.SecurityValidator {
	return &pipelineSecurityValidatorAdapter{validator: validator}
}

// ValidateIdentifier implements pipeline.SecurityValidator.
func (a *pipelineSecurityValidatorAdapter) ValidateIdentifier(value string, maxLen int, fieldName string) *pipeline.ValidationResult {
	result := a.validator.ValidateIdentifier(value, maxLen, fieldName)
	return convertToPipelineValidationResult(result)
}

// ValidateIdentifiers implements pipeline.SecurityValidator.
func (a *pipelineSecurityValidatorAdapter) ValidateIdentifiers(values []string, maxLen int, fieldName string) *pipeline.ValidationResult {
	result := a.validator.ValidateIdentifiers(values, maxLen, fieldName)
	return convertToPipelineValidationResult(result)
}

// ValidateStepConfig implements pipeline.SecurityValidator.
func (a *pipelineSecurityValidatorAdapter) ValidateStepConfig(ctx context.Context, tenantID shared.ID, tool string, capabilities []string, config map[string]any) *pipeline.ValidationResult {
	result := a.validator.ValidateStepConfig(ctx, tenantID, tool, capabilities, config)
	return convertToPipelineValidationResult(result)
}

// ValidateCommandPayload implements pipeline.SecurityValidator.
func (a *pipelineSecurityValidatorAdapter) ValidateCommandPayload(ctx context.Context, tenantID shared.ID, payload map[string]any) *pipeline.ValidationResult {
	result := a.validator.ValidateCommandPayload(ctx, tenantID, payload)
	return convertToPipelineValidationResult(result)
}

// =============================================================================
// Helper Functions
// =============================================================================

// convertValidationResult converts app.ValidationResult to scan.ValidationResult.
func convertValidationResult(r *ValidationResult) *scan.ValidationResult {
	errors := make([]scan.ValidationError, len(r.Errors))
	for i, e := range r.Errors {
		errors[i] = scan.ValidationError{
			Field:   e.Field,
			Message: e.Message,
			Code:    e.Code,
		}
	}
	return &scan.ValidationResult{
		Valid:  r.Valid,
		Errors: errors,
	}
}

// convertToPipelineValidationResult converts app.ValidationResult to pipeline.ValidationResult.
func convertToPipelineValidationResult(r *ValidationResult) *pipeline.ValidationResult {
	errors := make([]pipeline.ValidationError, len(r.Errors))
	for i, e := range r.Errors {
		errors[i] = pipeline.ValidationError{
			Field:   e.Field,
			Message: e.Message,
			Code:    e.Code,
		}
	}
	return &pipeline.ValidationResult{
		Valid:  r.Valid,
		Errors: errors,
	}
}
