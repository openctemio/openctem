// Package pipeline provides pipeline management services.
package pipeline

import (
	"context"
	"database/sql"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// Concurrent run limits to prevent resource exhaustion.
const (
	// MaxConcurrentRunsPerPipeline is the maximum concurrent runs per pipeline template.
	MaxConcurrentRunsPerPipeline = 5

	// MaxConcurrentRunsPerTenant is the maximum concurrent runs per tenant.
	MaxConcurrentRunsPerTenant = 50

	// Activation change constants for audit logging.
	activationChangeActivated   = "activated"
	activationChangeDeactivated = "deactivated"
)

// ========== Interfaces ==========

// TransactionDB defines the interface for database transaction support.
type TransactionDB interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// ScanDeactivator interface for cascade deactivation when pipelines are disabled.
type ScanDeactivator interface {
	DeactivateScansByPipeline(ctx context.Context, pipelineID shared.ID) (int, error)
}

// SecurityValidator interface for security validation.
type SecurityValidator interface {
	ValidateIdentifier(value string, maxLen int, fieldName string) *ValidationResult
	ValidateIdentifiers(values []string, maxLen int, fieldName string) *ValidationResult
	ValidateStepConfig(ctx context.Context, tenantID shared.ID, tool string, capabilities []string, config map[string]any) *ValidationResult
	ValidateCommandPayload(ctx context.Context, tenantID shared.ID, payload map[string]any) *ValidationResult
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
	SelectAgent(ctx context.Context, req SelectAgentRequest) (*SelectAgentResult, error)
	CanUsePlatformAgents(ctx context.Context, tenantID shared.ID) (bool, string)
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

// Service handles pipeline-related business operations.
type Service struct {
	templateRepo      pipeline.TemplateRepository
	stepRepo          pipeline.StepRepository
	runRepo           pipeline.RunRepository
	stepRunRepo       pipeline.StepRunRepository
	agentRepo         agent.Repository
	commandRepo       command.Repository
	toolRepo          tool.Repository // For deriving capabilities from tools
	securityValidator SecurityValidator
	agentSelector     AgentSelector // Optional: for platform agent support
	auditService      AuditService
	scanDeactivator   ScanDeactivator // Optional: for cascade scan deactivation
	db                TransactionDB   // Optional: for transaction support
	logger            *logger.Logger

	// Quality Gate dependencies (optional)
	scanProfileRepo scanprofile.Repository
	findingRepo     vulnerability.FindingRepository
}

// Option is a functional option for Service.
type Option func(*Service)

// WithAuditService sets the audit service for Service.
func WithAuditService(auditService AuditService) Option {
	return func(s *Service) {
		s.auditService = auditService
	}
}

// WithDB sets the database for transaction support.
func WithDB(db TransactionDB) Option {
	return func(s *Service) {
		s.db = db
	}
}

// WithAgentSelector sets the agent selector for platform agent support.
func WithAgentSelector(selector AgentSelector) Option {
	return func(s *Service) {
		s.agentSelector = selector
	}
}

// WithToolRepo sets the tool repository for deriving capabilities from tools.
func WithToolRepo(toolRepo tool.Repository) Option {
	return func(s *Service) {
		s.toolRepo = toolRepo
	}
}

// WithQualityGate sets the dependencies for quality gate evaluation.
func WithQualityGate(profileRepo scanprofile.Repository, findingRepo vulnerability.FindingRepository) Option {
	return func(s *Service) {
		s.scanProfileRepo = profileRepo
		s.findingRepo = findingRepo
	}
}

// WithScanDeactivator sets the scan deactivator for cascade deactivation.
func WithScanDeactivator(deactivator ScanDeactivator) Option {
	return func(s *Service) {
		s.scanDeactivator = deactivator
	}
}

// NewService creates a new Service.
func NewService(
	templateRepo pipeline.TemplateRepository,
	stepRepo pipeline.StepRepository,
	runRepo pipeline.RunRepository,
	stepRunRepo pipeline.StepRunRepository,
	agentRepo agent.Repository,
	commandRepo command.Repository,
	securityValidator SecurityValidator,
	log *logger.Logger,
	opts ...Option,
) *Service {
	s := &Service{
		templateRepo:      templateRepo,
		stepRepo:          stepRepo,
		runRepo:           runRepo,
		stepRunRepo:       stepRunRepo,
		agentRepo:         agentRepo,
		commandRepo:       commandRepo,
		securityValidator: securityValidator,
		logger:            log.With("service", "pipeline"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
