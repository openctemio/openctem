package scan

import (
	"context"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/templatesource"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/logger"
)

// Concurrent run limits for scans.
const (
	// MaxConcurrentRunsPerScan is the maximum concurrent runs per scan config.
	MaxConcurrentRunsPerScan = 3

	// MaxConcurrentRunsPerTenant is the maximum concurrent runs per tenant.
	MaxConcurrentRunsPerTenant = 50
)

// ========== Interfaces ==========

// SecurityValidator interface for security validation.
type SecurityValidator interface {
	ValidateIdentifier(value string, maxLen int, fieldName string) *ValidationResult
	ValidateIdentifiers(values []string, maxLen int, fieldName string) *ValidationResult
	ValidateScannerConfig(ctx context.Context, tenantID shared.ID, config map[string]any) *ValidationResult
	ValidateCronExpression(cronExpr string) error
}

// ValidationResult represents the result of a validation.
type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// ValidationError represents a validation error.
type ValidationError struct {
	Field   string
	Message string
	Code    string
}

// AuditService interface for audit logging.
type AuditService interface {
	LogEvent(ctx context.Context, actx AuditContext, event AuditEvent) error
}

// AuditContext contains context for audit logging.
type AuditContext struct {
	TenantID string
	ActorID  string
}

// AuditEvent represents an audit event.
type AuditEvent struct {
	Action       audit.Action
	ResourceType audit.ResourceType
	ResourceID   string
	ResourceName string
	Message      string
	Success      bool
	Error        error
	Metadata     map[string]any
}

// NewSuccessEvent creates a success audit event.
func NewSuccessEvent(action audit.Action, resourceType audit.ResourceType, resourceID string) AuditEvent {
	return AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Success:      true,
		Metadata:     make(map[string]any),
	}
}

// NewFailureEvent creates a failure audit event.
func NewFailureEvent(action audit.Action, resourceType audit.ResourceType, resourceID string, err error) AuditEvent {
	return AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Success:      false,
		Error:        err,
		Metadata:     make(map[string]any),
	}
}

// WithResourceName sets the resource name.
func (e AuditEvent) WithResourceName(name string) AuditEvent {
	e.ResourceName = name
	return e
}

// WithMessage sets the message.
func (e AuditEvent) WithMessage(msg string) AuditEvent {
	e.Message = msg
	return e
}

// WithMetadata adds metadata.
func (e AuditEvent) WithMetadata(key string, value any) AuditEvent {
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	e.Metadata[key] = value
	return e
}

// AgentSelector interface for agent selection.
type AgentSelector interface {
	CheckAgentAvailability(ctx context.Context, tenantID shared.ID, tool string, tenantOnly bool) *AgentAvailability
	CanUsePlatformAgents(ctx context.Context, tenantID shared.ID) (bool, string)
	SelectAgent(ctx context.Context, req SelectAgentRequest) (*SelectAgentResult, error)
}

// AgentAvailability represents agent availability status.
type AgentAvailability struct {
	HasTenantAgent   bool
	HasPlatformAgent bool
	Available        bool
	Message          string
}

// SelectAgentRequest represents a request to select an agent.
type SelectAgentRequest struct {
	TenantID     shared.ID
	Capabilities []string
	Tool         string
	Mode         SelectMode
	AllowQueue   bool
}

// SelectMode represents the agent selection mode.
type SelectMode int

const (
	// SelectTenantFirst tries tenant agents first, then platform.
	SelectTenantFirst SelectMode = iota
)

// SelectAgentResult represents the result of agent selection.
type SelectAgentResult struct {
	Agent      *agent.Agent
	IsPlatform bool
}

// TemplateSyncer interface for template sync operations.
type TemplateSyncer interface {
	SyncSource(ctx context.Context, source *templatesource.TemplateSource) (*TemplateSyncResult, error)
}

// TemplateSyncResult represents the result of syncing a template source.
type TemplateSyncResult struct {
	Success        bool
	TemplatesFound int
	TemplatesAdded int
}

// ========== Service ==========

// Service handles scan business operations.
type Service struct {
	scanRepo            scan.Repository
	templateRepo        pipeline.TemplateRepository
	assetGroupRepo      assetgroup.Repository
	runRepo             pipeline.RunRepository
	stepRepo            pipeline.StepRepository
	stepRunRepo         pipeline.StepRunRepository
	commandRepo         command.Repository
	scannerTemplateRepo scannertemplate.Repository
	templateSourceRepo  templatesource.Repository
	toolRepo            tool.Repository
	targetMappingRepo   tool.TargetMappingRepository // For asset-scanner compatibility
	templateSyncer      TemplateSyncer
	agentSelector       AgentSelector
	securityValidator   SecurityValidator
	auditService        AuditService
	logger              *logger.Logger
}

// ServiceOption is a functional option for Service.
type ServiceOption func(*Service)

// WithAuditService sets the audit service for Service.
func WithAuditService(auditService AuditService) ServiceOption {
	return func(s *Service) {
		s.auditService = auditService
	}
}

// WithTargetMappingRepo sets the target mapping repository for asset-scanner compatibility.
func WithTargetMappingRepo(repo tool.TargetMappingRepository) ServiceOption {
	return func(s *Service) {
		s.targetMappingRepo = repo
	}
}

// NewService creates a new Service.
func NewService(
	scanRepo scan.Repository,
	templateRepo pipeline.TemplateRepository,
	assetGroupRepo assetgroup.Repository,
	runRepo pipeline.RunRepository,
	stepRepo pipeline.StepRepository,
	stepRunRepo pipeline.StepRunRepository,
	commandRepo command.Repository,
	scannerTemplateRepo scannertemplate.Repository,
	templateSourceRepo templatesource.Repository,
	toolRepo tool.Repository,
	templateSyncer TemplateSyncer,
	agentSelector AgentSelector,
	securityValidator SecurityValidator,
	log *logger.Logger,
	opts ...ServiceOption,
) *Service {
	svc := &Service{
		scanRepo:            scanRepo,
		templateRepo:        templateRepo,
		assetGroupRepo:      assetGroupRepo,
		runRepo:             runRepo,
		stepRepo:            stepRepo,
		stepRunRepo:         stepRunRepo,
		commandRepo:         commandRepo,
		scannerTemplateRepo: scannerTemplateRepo,
		templateSourceRepo:  templateSourceRepo,
		toolRepo:            toolRepo,
		templateSyncer:      templateSyncer,
		agentSelector:       agentSelector,
		securityValidator:   securityValidator,
		logger:              log.With("service", "scan"),
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// logAudit logs an audit event if audit service is configured.
func (s *Service) logAudit(ctx context.Context, actx AuditContext, event AuditEvent) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}

// =============================================================================
// Validation Helpers
// =============================================================================

// validateTimezone validates that a timezone string is a valid IANA timezone.
// Returns error if the timezone cannot be loaded.
func validateTimezone(tz string) error {
	if tz == "" || tz == "UTC" || tz == "Local" {
		return nil // Common valid timezones
	}
	_, err := time.LoadLocation(tz)
	if err != nil {
		return shared.NewDomainError("VALIDATION", "invalid timezone '"+tz+"': must be a valid IANA timezone (e.g., 'America/New_York', 'Europe/London')", shared.ErrValidation)
	}
	return nil
}

// validateCronParseable validates that a cron expression can be parsed and used by the scheduler.
// This is a stricter validation than SecurityValidator.ValidateCronExpression which only checks format.
func validateCronParseable(cronExpr string) error {
	if cronExpr == "" {
		return nil
	}

	// Use the same parser as the scheduler (robfig/cron)
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	_, err := parser.Parse(cronExpr)
	if err != nil {
		return shared.NewDomainError("VALIDATION", "cannot parse cron expression: "+err.Error(), shared.ErrValidation)
	}
	return nil
}
