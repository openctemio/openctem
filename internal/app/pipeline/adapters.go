// Package pipeline provides adapters to bridge app types with pipeline interfaces.
package pipeline

import (
	"context"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ========== Security Validator Adapter ==========

// SecurityValidatorFunc is a function that implements SecurityValidator.
type SecurityValidatorFunc struct {
	ValidateIdentifierFunc     func(value string, maxLen int, fieldName string) *ValidationResult
	ValidateIdentifiersFunc    func(values []string, maxLen int, fieldName string) *ValidationResult
	ValidateStepConfigFunc     func(ctx context.Context, tenantID shared.ID, tool string, capabilities []string, config map[string]any) *ValidationResult
	ValidateCommandPayloadFunc func(ctx context.Context, tenantID shared.ID, payload map[string]any) *ValidationResult
}

func (f *SecurityValidatorFunc) ValidateIdentifier(value string, maxLen int, fieldName string) *ValidationResult {
	return f.ValidateIdentifierFunc(value, maxLen, fieldName)
}

func (f *SecurityValidatorFunc) ValidateIdentifiers(values []string, maxLen int, fieldName string) *ValidationResult {
	return f.ValidateIdentifiersFunc(values, maxLen, fieldName)
}

func (f *SecurityValidatorFunc) ValidateStepConfig(ctx context.Context, tenantID shared.ID, tool string, capabilities []string, config map[string]any) *ValidationResult {
	return f.ValidateStepConfigFunc(ctx, tenantID, tool, capabilities, config)
}

func (f *SecurityValidatorFunc) ValidateCommandPayload(ctx context.Context, tenantID shared.ID, payload map[string]any) *ValidationResult {
	return f.ValidateCommandPayloadFunc(ctx, tenantID, payload)
}

// ========== Audit Service Adapter ==========

// AuditServiceFunc wraps a function to implement AuditService.
type AuditServiceFunc func(ctx context.Context, actx AuditContext, event AuditEvent) error

func (f AuditServiceFunc) LogEvent(ctx context.Context, actx AuditContext, event AuditEvent) error {
	return f(ctx, actx, event)
}

// AuditServiceAdapter adapts app.AuditService to pipeline.AuditService.
type AuditServiceAdapter struct {
	LogEventFunc func(ctx context.Context, tenantID, actorID string, action audit.Action, resourceType audit.ResourceType, resourceID, resourceName, message string, success bool, err error, metadata map[string]any) error
}

func (a *AuditServiceAdapter) LogEvent(ctx context.Context, actx AuditContext, event AuditEvent) error {
	return a.LogEventFunc(ctx, actx.TenantID, actx.ActorID, event.Action, event.ResourceType, event.ResourceID, event.ResourceName, event.Message, event.Success, event.Error, event.Metadata)
}

// ========== Agent Selector Adapter ==========

// AgentSelectorAdapter adapts app.AgentSelector to pipeline.AgentSelector.
type AgentSelectorAdapter struct {
	SelectAgentFunc          func(ctx context.Context, req SelectAgentRequest) (*SelectAgentResult, error)
	CanUsePlatformAgentsFunc func(ctx context.Context, tenantID shared.ID) (bool, string)
}

func (a *AgentSelectorAdapter) SelectAgent(ctx context.Context, req SelectAgentRequest) (*SelectAgentResult, error) {
	return a.SelectAgentFunc(ctx, req)
}

func (a *AgentSelectorAdapter) CanUsePlatformAgents(ctx context.Context, tenantID shared.ID) (bool, string) {
	return a.CanUsePlatformAgentsFunc(ctx, tenantID)
}
