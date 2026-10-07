// Package pipeline provides pipeline management services.
package pipeline

import (
	"context"
	"database/sql"
	"fmt"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
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

// ScanRunRecorder refreshes the run summary of the scan that spawned a run
// (last run, counters) from its runs once the run has finished, so the scan
// never reads "never run" after a run that just completed. Optional: a
// workflow run with no ScanID (or no recorder wired) skips it. Satisfied by
// *postgres.ScanRepository.RefreshRunSummary.
type ScanRunRecorder interface {
	RefreshRunSummary(ctx context.Context, tenantID, scanID shared.ID) error
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

// SensorSelector interface for sensor selection.
type SensorSelector interface {
	SelectSensor(ctx context.Context, req SelectSensorRequest) (*SelectSensorResult, error)
	CanUsePlatformSensors(ctx context.Context, tenantID shared.ID) (bool, string)
}

// SelectSensorRequest represents a request to select a sensor.
type SelectSensorRequest struct {
	TenantID     shared.ID
	Capabilities []string
	Tool         string
	Mode         SelectMode
	AllowQueue   bool
}

// SelectMode represents the sensor selection mode.
type SelectMode int

const (
	// SelectTenantFirst tries tenant sensors first, then platform.
	SelectTenantFirst SelectMode = iota
)

// SelectSensorResult represents the result of sensor selection.
type SelectSensorResult struct {
	Sensor     *sensor.Sensor
	IsPlatform bool
}

// Service handles pipeline-related business operations.
type Service struct {
	templateRepo      pipeline.TemplateRepository
	stepRepo          pipeline.StepRepository
	runRepo           pipeline.RunRepository
	stepRunRepo       pipeline.StepRunRepository
	sensorRepo        sensor.Repository
	commandRepo       command.Repository
	toolRepo          tool.Repository // For deriving capabilities from tools
	securityValidator SecurityValidator
	sensorSelector    SensorSelector // Optional: for platform sensor support
	auditService      AuditService
	scanDeactivator   ScanDeactivator        // Optional: for cascade scan deactivation
	scanRunRecorder   ScanRunRecorder        // Optional: records run outcome back onto the scan
	runCompleted      RunCompletedCallback   // Optional: fires scan_completed automation
	db                TransactionDB          // Optional: for transaction support
	targetGate        TargetGate             // checks run-context targets; nil refuses runs that carry targets
	assetRefChecker   AssetRefChecker        // tenant + scope check of a run's asset_id; nil refuses runs that carry one
	hops              pipeline.HopRepository // stage chaining (hop_router.go); nil keeps every step on the run's seeds
	webScope          WebScopeBuilder        // web_scope of web steps (web_scope.go); nil refuses web steps
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

// WithSensorSelector sets the sensor selector for platform sensor support.
func WithSensorSelector(selector SensorSelector) Option {
	return func(s *Service) {
		s.sensorSelector = selector
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

// TargetGate applies a scan trigger's target checks (private-range policy,
// scope exclusions, scan zones) to the targets a pipeline run is started
// with. Implemented by *scan.Service.
type TargetGate interface {
	ResolveDispatchTargets(ctx context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error)
}

// StepTargetFilter gates a run's typed targets for one step's tool
// (RFC-042 §6.3.8 O6): a step is handed only the targets its tool can scan.
// A target gate that implements it (*scan.Service does) is used at every
// step dispatch.
type StepTargetFilter interface {
	FilterStepTargets(ctx context.Context, tenantID shared.ID, toolName string, runContext map[string]any) (*scanapp.StepTargets, error)
}

// WithTargetGate wires the target gate. Without it a run started with
// targets is refused (fail closed).
func WithTargetGate(g TargetGate) Option {
	return func(s *Service) {
		s.targetGate = g
	}
}

// ErrRunAssetNotFound is the one answer for a run asset_id that is unknown,
// soft-deleted, of another tenant, or outside the caller's data scope.
var ErrRunAssetNotFound = fmt.Errorf("%w: asset not found", shared.ErrNotFound)

// AssetRefChecker decides whether a caller may start a run on an asset:
// shared.ErrNotFound unless the asset is a live asset of the tenant and in
// the caller's data scope. datascope.Enforcer.AssertAssetRef implements it.
type AssetRefChecker interface {
	AssertAssetRef(ctx context.Context, tenantID, assetID shared.ID) error
}

// WithAssetRefChecker wires the check a run's asset_id goes through. Without
// it a run started with an asset_id is refused (fail closed).
func WithAssetRefChecker(c AssetRefChecker) Option {
	return func(s *Service) {
		s.assetRefChecker = c
	}
}

// WithScanRunRecorder sets the recorder that writes a pipeline run's terminal
// outcome back onto its scan.
func WithScanRunRecorder(recorder ScanRunRecorder) Option {
	return func(s *Service) {
		s.scanRunRecorder = recorder
	}
}

// RunCompletedCallback is notified when a pipeline run completes successfully.
// Implementations must not block (the workflow dispatcher runs async).
type RunCompletedCallback func(ctx context.Context, run *pipeline.Run)

// SetRunCompletedCallback wires the consumer of successful run completions
// (the `scan_completed` workflow trigger). A setter rather than an Option
// because the workflow dispatcher is built after the pipeline service.
func (s *Service) SetRunCompletedCallback(cb RunCompletedCallback) {
	s.runCompleted = cb
}

// NewService creates a new Service.
func NewService(
	templateRepo pipeline.TemplateRepository,
	stepRepo pipeline.StepRepository,
	runRepo pipeline.RunRepository,
	stepRunRepo pipeline.StepRunRepository,
	sensorRepo sensor.Repository,
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
		sensorRepo:        sensorRepo,
		commandRepo:       commandRepo,
		securityValidator: securityValidator,
		logger:            log.With("service", "pipeline"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type auditActorKey struct{}

// WithAuditActor returns ctx carrying the id of the user making the request.
// The service's audit entries name that user when the call itself passes no
// actor: template update and delete, step add, update and delete, and run
// cancel take none, so their entries had an empty actor.
func WithAuditActor(ctx context.Context, actorID string) context.Context {
	if actorID == "" {
		return ctx
	}
	return context.WithValue(ctx, auditActorKey{}, actorID)
}

func auditActorFromContext(ctx context.Context) string {
	v, _ := ctx.Value(auditActorKey{}).(string)
	return v
}

// logAudit logs an audit event if audit service is configured. An explicit
// actor in actx wins; otherwise the request's actor from ctx is used.
func (s *Service) logAudit(ctx context.Context, actx AuditContext, event AuditEvent) {
	if s.auditService == nil {
		return
	}
	if actx.ActorID == "" {
		actx.ActorID = auditActorFromContext(ctx)
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}
