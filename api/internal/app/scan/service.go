// Package scan implements the application service for the scan bounded context — orchestrates pkg/domain/scan entities and cross-cutting concerns (audit, notifications, RBAC).
package scan

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/robfig/cron/v3"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/templatesource"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
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

// SensorSelector interface for sensor selection.
type SensorSelector interface {
	CheckSensorAvailability(ctx context.Context, tenantID shared.ID, tool string, tenantOnly bool) *SensorAvailability
	CanUsePlatformSensors(ctx context.Context, tenantID shared.ID) (bool, string)
	SelectSensor(ctx context.Context, req SelectSensorRequest) (*SelectSensorResult, error)
}

// SensorAvailability represents sensor availability status.
type SensorAvailability struct {
	HasTenantSensor   bool
	HasPlatformSensor bool
	Available         bool
	Message           string
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
	// TenantBusy: the tenant has capable sensors, all busy; the job waits
	// for them (RFC-023 D14), it is not moved to shared sensors.
	TenantBusy bool
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
	ownerActivity       OwnerActivity
	templateRepo        scanworkflow.Repository
	assetGroupRepo      assetgroup.Repository
	runRepo             scanrun.RunRepository
	stepRepo            scanworkflow.StepRepository
	stepRunRepo         scanrun.StepRunRepository
	commandRepo         command.Repository
	scannerTemplateRepo scannertemplate.Repository
	templateSourceRepo  templatesource.Repository
	toolRepo            tool.Repository
	targetMappingRepo   tool.TargetMappingRepository // For asset-scanner compatibility
	profileRepo         scanprofile.Repository       // For ScanProfile linking and quality gates
	templateSyncer      TemplateSyncer
	sensorSelector      SensorSelector
	securityValidator   SecurityValidator
	auditService        AuditService
	scopeExclusions     ScopeExclusionFilter // optional; nil = no exclusions configured
	attributionGate     AttributionGate      // optional in tests; production always wires it (nil = not checked on a run, refused by the dispatch gate)
	zones               ZoneDirectory        // optional; nil = zone routing off (RFC-023)
	zoneResolver        scanzone.Resolver    // resolves hostname targets for zone routing
	freezeWindows       FreezeWindows        // optional; nil = no trigger-time freeze check (freeze.go)
	actScope            ActScopeChecker      // optional; nil = act scope not enforced (research/15 L-06)
	// activeProof is the operator's SCOPE_ACTIVE_PROOF (active_proof.go).
	activeProof      string
	connectorScans   ConnectorScans            // optional; nil = a connector cannot be a scanner (RFC-047)
	policySensors    AvailableSensorLister     // optional; nil = no policy preflight outside zones (policy_preflight.go)
	privatePolicy    PrivateTargetPolicy       // optional; nil = the private-target switch is not read at trigger
	readiness        *readinessSources         // optional; nil = no workflow readiness (readiness.go)
	toolAvailability ToolAvailability          // optional; nil = no tool availability check at trigger (tool_availability_gate.go)
	tenantTools      TenantToolConfigs         // optional; nil = per-organization tool switch not enforced
	optIns           OptInPolicy               // optional; nil = every sensor opt-in counts as enabled (opt_ins.go)
	stepQueuer       StepQueuer                // the scan run service's step dispatcher; nil refuses workflow scans
	workflowVersions scanworkflow.VersionStore // pins workflow runs to the version they start with; nil leaves them on the live workflow
	logger           *logger.Logger
}

// ScopeExclusionFilter reports which of the given candidate targets match an
// active scope EXCLUSION for the tenant and must therefore be skipped by a scan.
// Implemented by *scope.Service. A lookup error is returned, and the scan is
// not dispatched: scanning something the tenant excluded is worse than a
// delayed scan (fail closed).
type ScopeExclusionFilter interface {
	ExcludedTargets(ctx context.Context, tenantID string, candidates []scope.ExclusionCandidate) (map[shared.ID]bool, error)
}

// AttributionGate decides which assets and typed targets may not be checked
// actively (RFC-036 §6.3 active_allowed, O4): an asset whose attribution is
// not confirmed, a name under one the tenant rejected, and an
// internet-facing asset with no record outside every scope target and seed.
// Implemented by *easm.ActiveGate. A lookup error stops the dispatch.
type AttributionGate interface {
	// ActiveCheckBlocked returns the given assets that may not be probed,
	// with the reason.
	ActiveCheckBlocked(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.State, error)
	// BlockedTargets returns the typed targets that may not be probed: a
	// target naming an inventory asset is decided as that asset; free text
	// only when it is (or sits under) a name the tenant rejected.
	BlockedTargets(ctx context.Context, tenantID shared.ID, targets []string) (map[string]attribution.State, error)
	// TierExceeded returns the targets the tenant's scope authority covers,
	// but only below tier (RFC-054 §4.2 step 6), with the covering entry of
	// the highest ceiling.
	TierExceeded(ctx context.Context, tenantID shared.ID, targets []string, tier scopedom.Tier) (map[string]*scopedom.RuleRef, error)
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

// WithProfileRepo sets the scan profile repository for ScanProfile linking and quality gates.
func WithProfileRepo(repo scanprofile.Repository) ServiceOption {
	return func(s *Service) {
		s.profileRepo = repo
	}
}

// WithScopeExclusionFilter wires scope-exclusion enforcement into scan target
// selection: excluded targets are removed server-side before dispatch, and a
// failed lookup stops the dispatch.
func WithScopeExclusionFilter(f ScopeExclusionFilter) ServiceOption {
	return func(s *Service) {
		s.scopeExclusions = f
	}
}

// WithAttributionGate makes every active-scan path refuse what the tenant
// has not authorized: asset-group members and typed targets that name an
// asset whose ownership is not confirmed, names under a rejected name, and
// unattributed internet-facing assets (see AttributionGate).
func WithAttributionGate(g AttributionGate) ServiceOption {
	return func(s *Service) {
		s.attributionGate = g
	}
}

// NewService creates a new Service.
func NewService(
	scanRepo scan.Repository,
	templateRepo scanworkflow.Repository,
	assetGroupRepo assetgroup.Repository,
	runRepo scanrun.RunRepository,
	stepRepo scanworkflow.StepRepository,
	stepRunRepo scanrun.StepRunRepository,
	commandRepo command.Repository,
	scannerTemplateRepo scannertemplate.Repository,
	templateSourceRepo templatesource.Repository,
	toolRepo tool.Repository,
	templateSyncer TemplateSyncer,
	sensorSelector SensorSelector,
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
		sensorSelector:      sensorSelector,
		securityValidator:   securityValidator,
		logger:              log.With("service", "scan"),
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

type auditActorKey struct{}

// WithAuditActor returns ctx carrying the id of the user making the request.
// Most scan mutations (update, delete, activate, pause, disable, import,
// export) take no actor argument; the HTTP handler attaches the caller here
// so their audit entries say who made the change instead of leaving the actor
// empty. An explicit AuditContext.ActorID still wins.
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

// logAudit logs an audit event if audit service is configured.
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

// recordScheduledOutcome writes a scheduled occurrence that did not produce a
// run (skipped by the overlap policy, or the trigger failed) to the scan's
// audit trail, with the reason.
func (s *Service) recordScheduledOutcome(ctx context.Context, sc *scan.Scan, message string, cause error) {
	s.logAudit(ctx, AuditContext{TenantID: sc.TenantID.String()},
		NewFailureEvent(audit.ActionScanConfigTriggered, audit.ResourceTypeScanConfig, sc.ID.String(), cause).
			WithResourceName(sc.Name).
			WithMessage(message).
			WithMetadata("trigger_type", "schedule"))
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
