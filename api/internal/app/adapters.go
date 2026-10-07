// Package app provides adapters for connecting services to sub-packages.
// These adapters implement the interfaces expected by the scan and scan workflow
// sub-packages while delegating to the concrete app-level services.
package app

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// =============================================================================
// Audit Service Adapters
// =============================================================================

// scanAuditServiceAdapter adapts AuditService to scan.AuditService interface.
type scanAuditServiceAdapter struct {
	svc *auditsvc.AuditService
}

// NewScanAuditServiceAdapter creates an adapter for the scan package's AuditService interface.
func NewScanAuditServiceAdapter(svc *auditsvc.AuditService) scan.AuditService {
	return &scanAuditServiceAdapter{svc: svc}
}

// LogEvent implements scan.AuditService.
func (a *scanAuditServiceAdapter) LogEvent(ctx context.Context, actx scan.AuditContext, event scan.AuditEvent) error {
	// Convert scan.AuditEvent to app.AuditEvent
	appEvent := auditsvc.AuditEvent{
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
	appCtx := auditsvc.AuditContext{
		TenantID: actx.TenantID,
		ActorID:  actx.ActorID,
	}

	return a.svc.LogEvent(ctx, appCtx, appEvent)
}

// scanWorkflowAuditServiceAdapter adapts AuditService to scanrun.AuditService interface.
type scanWorkflowAuditServiceAdapter struct {
	svc *auditsvc.AuditService
}

// NewScanWorkflowAuditServiceAdapter creates an adapter for the scanrun package's AuditService interface.
func NewScanWorkflowAuditServiceAdapter(svc *auditsvc.AuditService) scanrun.AuditService {
	return &scanWorkflowAuditServiceAdapter{svc: svc}
}

// LogEvent implements scanrun.AuditService.
func (a *scanWorkflowAuditServiceAdapter) LogEvent(ctx context.Context, actx scanrun.AuditContext, event scanrun.AuditEvent) error {
	// Convert scanrun.AuditEvent to app.AuditEvent
	appEvent := auditsvc.AuditEvent{
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

	// Convert scanrun.AuditContext to app.AuditContext
	appCtx := auditsvc.AuditContext{
		TenantID: actx.TenantID,
		ActorID:  actx.ActorID,
	}

	return a.svc.LogEvent(ctx, appCtx, appEvent)
}

// =============================================================================
// Sensor Selector Adapter
// =============================================================================

// scanSensorSelectorAdapter adapts SensorSelector to scan.SensorSelector interface.
type scanSensorSelectorAdapter struct {
	selector *sensor.SensorSelector
}

// NewScanSensorSelectorAdapter creates an adapter for the scan package's SensorSelector interface.
func NewScanSensorSelectorAdapter(selector *sensor.SensorSelector) scan.SensorSelector {
	return &scanSensorSelectorAdapter{selector: selector}
}

// CheckSensorAvailability implements scan.SensorSelector.
func (a *scanSensorSelectorAdapter) CheckSensorAvailability(ctx context.Context, tenantID shared.ID, tool string, tenantOnly bool) *scan.SensorAvailability {
	result := a.selector.CheckSensorAvailability(ctx, tenantID, tool, tenantOnly)
	return &scan.SensorAvailability{
		HasTenantSensor: result.HasTenantSensor,
		Available:       result.Available,
		Message:         result.Message,
	}
}

// CanUsePlatformSensors implements scan.SensorSelector.
// In OSS edition, platform sensors are not available.
func (a *scanSensorSelectorAdapter) CanUsePlatformSensors(ctx context.Context, tenantID shared.ID) (bool, string) {
	return false, "Platform sensors not available in OSS edition"
}

// SelectSensor implements scan.SensorSelector.
func (a *scanSensorSelectorAdapter) SelectSensor(ctx context.Context, req scan.SelectSensorRequest) (*scan.SelectSensorResult, error) {
	// Make the call with app types
	appReq := sensor.SelectSensorRequest{
		TenantID:     req.TenantID,
		Capabilities: req.Capabilities,
		Tool:         req.Tool,
		Mode:         sensor.SelectTenantOnly,
		AllowQueue:   req.AllowQueue,
	}

	result, err := a.selector.SelectSensor(ctx, appReq)
	if err != nil {
		return nil, err
	}

	return &scan.SelectSensorResult{
		Sensor:     result.Sensor,
		TenantBusy: result.TenantBusy,
	}, nil
}

// scanRunSensorSelectorAdapter adapts SensorSelector to scanrun.SensorSelector interface.
type scanRunSensorSelectorAdapter struct {
	selector *sensor.SensorSelector
}

// NewScanRunSensorSelectorAdapter creates an adapter for the scanrun package's SensorSelector interface.
func NewScanRunSensorSelectorAdapter(selector *sensor.SensorSelector) scanrun.SensorSelector {
	return &scanRunSensorSelectorAdapter{selector: selector}
}

// SelectSensor implements scanrun.SensorSelector.
func (a *scanRunSensorSelectorAdapter) SelectSensor(ctx context.Context, req scanrun.SelectSensorRequest) (*scanrun.SelectSensorResult, error) {
	// Make the call with app types
	appReq := sensor.SelectSensorRequest{
		TenantID:     req.TenantID,
		Capabilities: req.Capabilities,
		Tool:         req.Tool,
		Mode:         sensor.SelectTenantOnly,
		AllowQueue:   req.AllowQueue,
	}

	result, err := a.selector.SelectSensor(ctx, appReq)
	if err != nil {
		return nil, err
	}

	return &scanrun.SelectSensorResult{
		Sensor: result.Sensor,
	}, nil
}

// CanUsePlatformSensors implements scanrun.SensorSelector.
// In OSS edition, platform sensors are not available.
func (a *scanRunSensorSelectorAdapter) CanUsePlatformSensors(ctx context.Context, tenantID shared.ID) (bool, string) {
	return false, "Platform sensors not available in OSS edition"
}

// Template Syncer adapter lives in internal/app/template/scan_adapter.go
// (moved there because `template` imports `app` for SecretStoreService
// and metrics — keeping the adapter here would introduce a cycle).

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

// scanWorkflowSecurityValidatorAdapter adapts SecurityValidator to scanrun.SecurityValidator interface.
type scanWorkflowSecurityValidatorAdapter struct {
	validator *SecurityValidator
}

// NewScanWorkflowSecurityValidatorAdapter creates an adapter for the scanrun package's SecurityValidator interface.
func NewScanWorkflowSecurityValidatorAdapter(validator *SecurityValidator) scanrun.SecurityValidator {
	return &scanWorkflowSecurityValidatorAdapter{validator: validator}
}

// ValidateIdentifier implements scanrun.SecurityValidator.
func (a *scanWorkflowSecurityValidatorAdapter) ValidateIdentifier(value string, maxLen int, fieldName string) *scanrun.ValidationResult {
	result := a.validator.ValidateIdentifier(value, maxLen, fieldName)
	return convertToScanWorkflowValidationResult(result)
}

// ValidateIdentifiers implements scanrun.SecurityValidator.
func (a *scanWorkflowSecurityValidatorAdapter) ValidateIdentifiers(values []string, maxLen int, fieldName string) *scanrun.ValidationResult {
	result := a.validator.ValidateIdentifiers(values, maxLen, fieldName)
	return convertToScanWorkflowValidationResult(result)
}

// ValidateStepConfig implements scanrun.SecurityValidator.
func (a *scanWorkflowSecurityValidatorAdapter) ValidateStepConfig(ctx context.Context, tenantID shared.ID, tool string, capabilities []string, config map[string]any) *scanrun.ValidationResult {
	result := a.validator.ValidateStepConfig(ctx, tenantID, tool, capabilities, config)
	return convertToScanWorkflowValidationResult(result)
}

// ValidateCommandPayload implements scanrun.SecurityValidator.
func (a *scanWorkflowSecurityValidatorAdapter) ValidateCommandPayload(ctx context.Context, tenantID shared.ID, payload map[string]any) *scanrun.ValidationResult {
	result := a.validator.ValidateCommandPayload(ctx, tenantID, payload)
	return convertToScanWorkflowValidationResult(result)
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

// convertToScanWorkflowValidationResult converts app.ValidationResult to scanrun.ValidationResult.
func convertToScanWorkflowValidationResult(r *ValidationResult) *scanrun.ValidationResult {
	errors := make([]scanrun.ValidationError, len(r.Errors))
	for i, e := range r.Errors {
		errors[i] = scanrun.ValidationError{
			Field:   e.Field,
			Message: e.Message,
			Code:    e.Code,
		}
	}
	return &scanrun.ValidationResult{
		Valid:  r.Valid,
		Errors: errors,
	}
}
