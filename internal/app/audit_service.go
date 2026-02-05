package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AuditService handles audit logging operations.
type AuditService struct {
	auditRepo audit.Repository
	logger    *logger.Logger
	// Buffer for batch operations (optional async processing)
	asyncEnabled bool
}

// NewAuditService creates a new AuditService.
func NewAuditService(repo audit.Repository, log *logger.Logger) *AuditService {
	return &AuditService{
		auditRepo:    repo,
		logger:       log.With("service", "audit"),
		asyncEnabled: false,
	}
}

// AuditContext holds contextual information for audit logging.
type AuditContext struct {
	TenantID   string
	ActorID    string
	ActorEmail string
	ActorIP    string
	UserAgent  string
	RequestID  string
	SessionID  string
}

// LogEvent creates and persists an audit log entry.
func (s *AuditService) LogEvent(ctx context.Context, actx AuditContext, event AuditEvent) error {
	log, err := audit.NewAuditLog(
		event.Action,
		event.ResourceType,
		event.ResourceID,
		event.Result,
	)
	if err != nil {
		s.logger.Error("failed to create audit log", "error", err)
		return err
	}

	// Set tenant context
	if actx.TenantID != "" {
		tenantID, err := shared.IDFromString(actx.TenantID)
		if err == nil {
			log.WithTenantID(tenantID)
		}
	}

	// Set actor information
	if actx.ActorID != "" {
		actorID, err := shared.IDFromString(actx.ActorID)
		if err == nil {
			log.WithActor(actorID, actx.ActorEmail)
		}
	} else if actx.ActorEmail != "" {
		// System action with email only
		log.WithActor(shared.ID{}, actx.ActorEmail)
	}

	// Set request context
	if actx.ActorIP != "" {
		log.WithActorIP(actx.ActorIP)
	}
	if actx.UserAgent != "" {
		log.WithActorAgent(actx.UserAgent)
	}
	if actx.RequestID != "" {
		log.WithRequestID(actx.RequestID)
	}
	if actx.SessionID != "" {
		log.WithSessionID(actx.SessionID)
	}

	// Set event details
	if event.ResourceName != "" {
		log.WithResourceName(event.ResourceName)
	}
	if event.Changes != nil {
		log.WithChanges(event.Changes)
	}
	if event.Message != "" {
		log.WithMessage(event.Message)
	}
	if event.Severity != "" {
		log.WithSeverity(event.Severity)
	}
	for k, v := range event.Metadata {
		log.WithMetadata(k, v)
	}

	// Persist
	if err := s.auditRepo.Create(ctx, log); err != nil {
		s.logger.Error("failed to persist audit log",
			"error", err,
			"action", event.Action,
			"resource_type", event.ResourceType,
			"resource_id", event.ResourceID,
		)
		return err
	}

	// Log to structured logger as well for immediate visibility
	s.logger.Info("audit event",
		"action", event.Action.String(),
		"resource_type", event.ResourceType.String(),
		"resource_id", event.ResourceID,
		"result", event.Result.String(),
		"actor_email", actx.ActorEmail,
		"tenant_id", actx.TenantID,
	)

	return nil
}

// AuditEvent represents an audit event to log.
type AuditEvent struct {
	Action       audit.Action
	ResourceType audit.ResourceType
	ResourceID   string
	ResourceName string
	Result       audit.Result
	Severity     audit.Severity
	Changes      *audit.Changes
	Message      string
	Metadata     map[string]any
}

// NewSuccessEvent creates a success audit event.
func NewSuccessEvent(action audit.Action, resourceType audit.ResourceType, resourceID string) AuditEvent {
	return AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       audit.ResultSuccess,
		Metadata:     make(map[string]any),
	}
}

// NewFailureEvent creates a failure audit event.
func NewFailureEvent(action audit.Action, resourceType audit.ResourceType, resourceID string, err error) AuditEvent {
	event := AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       audit.ResultFailure,
		Metadata:     make(map[string]any),
	}
	if err != nil {
		event.Metadata["error"] = err.Error()
	}
	return event
}

// NewDeniedEvent creates a denied audit event.
func NewDeniedEvent(action audit.Action, resourceType audit.ResourceType, resourceID string, reason string) AuditEvent {
	event := AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       audit.ResultDenied,
		Severity:     audit.SeverityHigh,
		Metadata:     make(map[string]any),
	}
	if reason != "" {
		event.Metadata["reason"] = reason
	}
	return event
}

// WithResourceName sets the resource name.
func (e AuditEvent) WithResourceName(name string) AuditEvent {
	e.ResourceName = name
	return e
}

// WithChanges sets the changes.
func (e AuditEvent) WithChanges(changes *audit.Changes) AuditEvent {
	e.Changes = changes
	return e
}

// WithMessage sets the message.
func (e AuditEvent) WithMessage(message string) AuditEvent {
	e.Message = message
	return e
}

// WithSeverity sets the severity.
func (e AuditEvent) WithSeverity(severity audit.Severity) AuditEvent {
	e.Severity = severity
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

// ============================================
// QUERY OPERATIONS
// ============================================

// ListAuditLogsInput represents the input for listing audit logs.
type ListAuditLogsInput struct {
	TenantID      string   `validate:"omitempty,uuid"`
	ActorID       string   `validate:"omitempty,uuid"`
	Actions       []string `validate:"max=20"`
	ResourceTypes []string `validate:"max=10"`
	ResourceID    string   `validate:"max=255"`
	Results       []string `validate:"max=3"`
	Severities    []string `validate:"max=4"`
	RequestID     string   `validate:"max=100"`
	Since         *time.Time
	Until         *time.Time
	SearchTerm    string `validate:"max=255"`
	Page          int    `validate:"min=0"`
	PerPage       int    `validate:"min=0,max=100"`
	SortBy        string `validate:"omitempty,oneof=logged_at action resource_type result severity"`
	SortOrder     string `validate:"omitempty,oneof=asc desc"`
	ExcludeSystem bool
}

// ListAuditLogs retrieves audit logs with filtering and pagination.
func (s *AuditService) ListAuditLogs(ctx context.Context, input ListAuditLogsInput) (pagination.Result[*audit.AuditLog], error) {
	filter := audit.NewFilter()

	if input.TenantID != "" {
		tenantID, err := shared.IDFromString(input.TenantID)
		if err != nil {
			return pagination.Result[*audit.AuditLog]{}, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
		}
		filter = filter.WithTenantID(tenantID)
	}

	if input.ActorID != "" {
		actorID, err := shared.IDFromString(input.ActorID)
		if err != nil {
			return pagination.Result[*audit.AuditLog]{}, fmt.Errorf("%w: invalid actor id format", shared.ErrValidation)
		}
		filter = filter.WithActorID(actorID)
	}

	if len(input.Actions) > 0 {
		actions := make([]audit.Action, 0, len(input.Actions))
		for _, a := range input.Actions {
			actions = append(actions, audit.Action(a))
		}
		filter = filter.WithActions(actions...)
	}

	if len(input.ResourceTypes) > 0 {
		types := make([]audit.ResourceType, 0, len(input.ResourceTypes))
		for _, rt := range input.ResourceTypes {
			types = append(types, audit.ResourceType(rt))
		}
		filter = filter.WithResourceTypes(types...)
	}

	if input.ResourceID != "" {
		filter = filter.WithResourceID(input.ResourceID)
	}

	if len(input.Results) > 0 {
		results := make([]audit.Result, 0, len(input.Results))
		for _, r := range input.Results {
			results = append(results, audit.Result(r))
		}
		filter = filter.WithResults(results...)
	}

	if len(input.Severities) > 0 {
		severities := make([]audit.Severity, 0, len(input.Severities))
		for _, sev := range input.Severities {
			severities = append(severities, audit.Severity(sev))
		}
		filter = filter.WithSeverities(severities...)
	}

	if input.RequestID != "" {
		filter = filter.WithRequestID(input.RequestID)
	}

	if input.Since != nil {
		filter = filter.WithSince(*input.Since)
	}

	if input.Until != nil {
		filter = filter.WithUntil(*input.Until)
	}

	if input.SearchTerm != "" {
		filter = filter.WithSearchTerm(input.SearchTerm)
	}

	if input.SortBy != "" {
		filter = filter.WithSort(input.SortBy, input.SortOrder)
	}

	if input.ExcludeSystem {
		filter = filter.WithExcludeSystem(true)
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.auditRepo.List(ctx, filter, page)
}

// GetAuditLog retrieves an audit log by ID.
func (s *AuditService) GetAuditLog(ctx context.Context, auditLogID string) (*audit.AuditLog, error) {
	parsedID, err := shared.IDFromString(auditLogID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.auditRepo.GetByID(ctx, parsedID)
}

// GetResourceHistory retrieves audit history for a specific resource.
func (s *AuditService) GetResourceHistory(ctx context.Context, resourceType, resourceID string, page, perPage int) (pagination.Result[*audit.AuditLog], error) {
	p := pagination.New(page, perPage)
	return s.auditRepo.ListByResource(ctx, audit.ResourceType(resourceType), resourceID, p)
}

// GetUserActivity retrieves audit logs for a specific user.
func (s *AuditService) GetUserActivity(ctx context.Context, userID string, page, perPage int) (pagination.Result[*audit.AuditLog], error) {
	actorID, err := shared.IDFromString(userID)
	if err != nil {
		return pagination.Result[*audit.AuditLog]{}, fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}

	p := pagination.New(page, perPage)
	return s.auditRepo.ListByActor(ctx, actorID, p)
}

// ============================================
// RETENTION OPERATIONS
// ============================================

// CleanupOldLogs removes audit logs older than the retention period.
// Preserves high and critical severity logs.
func (s *AuditService) CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays < 30 {
		return 0, fmt.Errorf("%w: retention period must be at least 30 days", shared.ErrValidation)
	}

	before := time.Now().AddDate(0, 0, -retentionDays)
	count, err := s.auditRepo.DeleteOlderThan(ctx, before)
	if err != nil {
		return 0, err
	}

	s.logger.Info("audit log cleanup completed",
		"deleted_count", count,
		"retention_days", retentionDays,
		"before", before,
	)

	return count, nil
}

// ============================================
// STATISTICS
// ============================================

// GetActionCount returns the count of a specific action within a time range.
func (s *AuditService) GetActionCount(ctx context.Context, tenantID string, action audit.Action, since time.Time) (int64, error) {
	var tid *shared.ID
	if tenantID != "" {
		parsedID, err := shared.IDFromString(tenantID)
		if err != nil {
			return 0, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
		}
		tid = &parsedID
	}

	return s.auditRepo.CountByAction(ctx, tid, action, since)
}

// ============================================
// CONVENIENCE METHODS FOR COMMON EVENTS
// ============================================

// LogUserCreated logs a user creation event.
func (s *AuditService) LogUserCreated(ctx context.Context, actx AuditContext, userID, email string) error {
	event := NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, userID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("User %s created", email))
	return s.LogEvent(ctx, actx, event)
}

// LogUserUpdated logs a user update event.
func (s *AuditService) LogUserUpdated(ctx context.Context, actx AuditContext, userID, email string, changes *audit.Changes) error {
	event := NewSuccessEvent(audit.ActionUserUpdated, audit.ResourceTypeUser, userID).
		WithResourceName(email).
		WithChanges(changes).
		WithMessage(fmt.Sprintf("User %s updated", email))
	return s.LogEvent(ctx, actx, event)
}

// LogUserSuspended logs a user suspension event.
func (s *AuditService) LogUserSuspended(ctx context.Context, actx AuditContext, userID, email, reason string) error {
	event := NewSuccessEvent(audit.ActionUserSuspended, audit.ResourceTypeUser, userID).
		WithResourceName(email).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("User %s suspended: %s", email, reason)).
		WithMetadata("reason", reason)
	return s.LogEvent(ctx, actx, event)
}

// LogMemberAdded logs a member addition event.
func (s *AuditService) LogMemberAdded(ctx context.Context, actx AuditContext, membershipID, email, role string) error {
	event := NewSuccessEvent(audit.ActionMemberAdded, audit.ResourceTypeMembership, membershipID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("Member %s added with role %s", email, role)).
		WithMetadata("role", role)
	return s.LogEvent(ctx, actx, event)
}

// LogMemberRemoved logs a member removal event.
func (s *AuditService) LogMemberRemoved(ctx context.Context, actx AuditContext, membershipID, email string) error {
	event := NewSuccessEvent(audit.ActionMemberRemoved, audit.ResourceTypeMembership, membershipID).
		WithResourceName(email).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Member %s removed", email))
	return s.LogEvent(ctx, actx, event)
}

// LogMemberRoleChanged logs a member role change event.
func (s *AuditService) LogMemberRoleChanged(ctx context.Context, actx AuditContext, membershipID, email, oldRole, newRole string) error {
	changes := audit.NewChanges().Set("role", oldRole, newRole)
	event := NewSuccessEvent(audit.ActionMemberRoleChanged, audit.ResourceTypeMembership, membershipID).
		WithResourceName(email).
		WithChanges(changes).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Member %s role changed from %s to %s", email, oldRole, newRole))
	return s.LogEvent(ctx, actx, event)
}

// LogInvitationCreated logs an invitation creation event.
func (s *AuditService) LogInvitationCreated(ctx context.Context, actx AuditContext, invitationID, email, role string) error {
	event := NewSuccessEvent(audit.ActionInvitationCreated, audit.ResourceTypeInvitation, invitationID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("Invitation sent to %s with role %s", email, role)).
		WithMetadata("role", role)
	return s.LogEvent(ctx, actx, event)
}

// LogInvitationAccepted logs an invitation acceptance event.
func (s *AuditService) LogInvitationAccepted(ctx context.Context, actx AuditContext, invitationID, email string) error {
	event := NewSuccessEvent(audit.ActionInvitationAccepted, audit.ResourceTypeInvitation, invitationID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("Invitation accepted by %s", email))
	return s.LogEvent(ctx, actx, event)
}

// LogPermissionDenied logs a permission denied event.
func (s *AuditService) LogPermissionDenied(ctx context.Context, actx AuditContext, resourceType audit.ResourceType, resourceID, action, reason string) error {
	event := NewDeniedEvent(audit.ActionPermissionDenied, resourceType, resourceID, reason).
		WithMessage(fmt.Sprintf("Permission denied for %s on %s %s: %s", action, resourceType, resourceID, reason))
	return s.LogEvent(ctx, actx, event)
}

// LogAuthFailed logs an authentication failure event.
func (s *AuditService) LogAuthFailed(ctx context.Context, actx AuditContext, reason string) error {
	event := NewFailureEvent(audit.ActionAuthFailed, audit.ResourceTypeToken, "", nil).
		WithSeverity(audit.SeverityCritical).
		WithMessage(fmt.Sprintf("Authentication failed: %s", reason)).
		WithMetadata("reason", reason)
	return s.LogEvent(ctx, actx, event)
}

// LogUserLogin logs a user login event.
func (s *AuditService) LogUserLogin(ctx context.Context, actx AuditContext, userID, email string) error {
	event := NewSuccessEvent(audit.ActionAuthLogin, audit.ResourceTypeUser, userID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("User %s logged in", email))
	return s.LogEvent(ctx, actx, event)
}

// LogUserLogout logs a user logout event.
func (s *AuditService) LogUserLogout(ctx context.Context, actx AuditContext, userID, email string) error {
	event := NewSuccessEvent(audit.ActionAuthLogout, audit.ResourceTypeUser, userID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("User %s logged out", email))
	return s.LogEvent(ctx, actx, event)
}

// LogUserRegistered logs a user registration event.
func (s *AuditService) LogUserRegistered(ctx context.Context, actx AuditContext, userID, email string) error {
	event := NewSuccessEvent(audit.ActionAuthRegister, audit.ResourceTypeUser, userID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("User %s registered", email))
	return s.LogEvent(ctx, actx, event)
}

// ============================================
// AGENT AUDIT EVENTS
// ============================================

// LogAgentCreated logs an agent creation event.
func (s *AuditService) LogAgentCreated(ctx context.Context, actx AuditContext, agentID, agentName, agentType string) error {
	event := NewSuccessEvent(audit.ActionAgentCreated, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithMessage(fmt.Sprintf("Agent '%s' created (type: %s)", agentName, agentType)).
		WithMetadata("agent_type", agentType)
	return s.LogEvent(ctx, actx, event)
}

// LogAgentUpdated logs an agent update event.
func (s *AuditService) LogAgentUpdated(ctx context.Context, actx AuditContext, agentID, agentName string, changes *audit.Changes) error {
	event := NewSuccessEvent(audit.ActionAgentUpdated, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithChanges(changes).
		WithMessage(fmt.Sprintf("Agent '%s' updated", agentName))
	return s.LogEvent(ctx, actx, event)
}

// LogAgentDeleted logs an agent deletion event.
func (s *AuditService) LogAgentDeleted(ctx context.Context, actx AuditContext, agentID, agentName string) error {
	event := NewSuccessEvent(audit.ActionAgentDeleted, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithSeverity(audit.SeverityCritical).
		WithMessage(fmt.Sprintf("Agent '%s' deleted", agentName))
	return s.LogEvent(ctx, actx, event)
}

// LogAgentActivated logs an agent activation event.
func (s *AuditService) LogAgentActivated(ctx context.Context, actx AuditContext, agentID, agentName string) error {
	event := NewSuccessEvent(audit.ActionAgentActivated, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithMessage(fmt.Sprintf("Agent '%s' activated", agentName))
	return s.LogEvent(ctx, actx, event)
}

// LogCredentialCreated logs a credential creation event.
func (s *AuditService) LogCredentialCreated(ctx context.Context, actx AuditContext, credID, name, credType string) error {
	event := NewSuccessEvent(audit.ActionCredentialCreated, audit.ResourceTypeToken, credID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Credential '%s' (%s) created", name, credType)).
		WithMetadata("type", credType)
	return s.LogEvent(ctx, actx, event)
}

// LogCredentialUpdated logs a credential update event.
func (s *AuditService) LogCredentialUpdated(ctx context.Context, actx AuditContext, credID, name string) error {
	event := NewSuccessEvent(audit.ActionCredentialUpdated, audit.ResourceTypeToken, credID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Credential '%s' updated", name))
	return s.LogEvent(ctx, actx, event)
}

// LogCredentialDeleted logs a credential deletion event.
func (s *AuditService) LogCredentialDeleted(ctx context.Context, actx AuditContext, credID string) error {
	event := NewSuccessEvent(audit.ActionCredentialDeleted, audit.ResourceTypeToken, credID).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Credential %s deleted", credID))
	return s.LogEvent(ctx, actx, event)
}

// LogCredentialAccessed logs a credential access (decrypt) event.
func (s *AuditService) LogCredentialAccessed(ctx context.Context, actx AuditContext, credID, name string) error {
	event := NewSuccessEvent(audit.ActionCredentialAccessed, audit.ResourceTypeToken, credID).
		WithResourceName(name).
		WithSeverity(audit.SeverityHigh). // Accessing secrets is high sensitivity
		WithMessage(fmt.Sprintf("Credential '%s' decrypted/accessed", name))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleSourceCreated logs a rule source creation event.
func (s *AuditService) LogRuleSourceCreated(ctx context.Context, actx AuditContext, sourceID, name, sourceType string) error {
	event := NewSuccessEvent(audit.ActionRuleSourceCreated, audit.ResourceTypeRuleSource, sourceID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Rule Source '%s' (%s) created", name, sourceType)).
		WithMetadata("type", sourceType)
	return s.LogEvent(ctx, actx, event)
}

// LogRuleSourceUpdated logs a rule source update event.
func (s *AuditService) LogRuleSourceUpdated(ctx context.Context, actx AuditContext, sourceID, name string) error {
	event := NewSuccessEvent(audit.ActionRuleSourceUpdated, audit.ResourceTypeRuleSource, sourceID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Rule Source '%s' updated", name))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleSourceDeleted logs a rule source deletion event.
func (s *AuditService) LogRuleSourceDeleted(ctx context.Context, actx AuditContext, sourceID, name string) error {
	event := NewSuccessEvent(audit.ActionRuleSourceDeleted, audit.ResourceTypeRuleSource, sourceID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Rule Source '%s' deleted", name))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleOverrideCreated logs a rule override creation event.
func (s *AuditService) LogRuleOverrideCreated(ctx context.Context, actx AuditContext, overrideID, pattern string) error {
	event := NewSuccessEvent(audit.ActionRuleOverrideCreated, audit.ResourceTypeRuleOverride, overrideID).
		WithResourceName(pattern).
		WithMessage(fmt.Sprintf("Rule Override for '%s' created", pattern))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleOverrideUpdated logs a rule override update event.
func (s *AuditService) LogRuleOverrideUpdated(ctx context.Context, actx AuditContext, overrideID, pattern string) error {
	event := NewSuccessEvent(audit.ActionRuleOverrideUpdated, audit.ResourceTypeRuleOverride, overrideID).
		WithResourceName(pattern).
		WithMessage(fmt.Sprintf("Rule Override for '%s' updated", pattern))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleOverrideDeleted logs a rule override deletion event.
func (s *AuditService) LogRuleOverrideDeleted(ctx context.Context, actx AuditContext, overrideID, pattern string) error {
	event := NewSuccessEvent(audit.ActionRuleOverrideDeleted, audit.ResourceTypeRuleOverride, overrideID).
		WithResourceName(pattern).
		WithMessage(fmt.Sprintf("Rule Override for '%s' deleted", pattern))
	return s.LogEvent(ctx, actx, event)
}

// LogAgentDeactivated logs an agent deactivation event.
func (s *AuditService) LogAgentDeactivated(ctx context.Context, actx AuditContext, agentID, agentName, reason string) error {
	event := NewSuccessEvent(audit.ActionAgentDeactivated, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Agent '%s' deactivated: %s", agentName, reason)).
		WithMetadata("reason", reason)
	return s.LogEvent(ctx, actx, event)
}

// LogAgentRevoked logs an agent revocation event.
func (s *AuditService) LogAgentRevoked(ctx context.Context, actx AuditContext, agentID, agentName, reason string) error {
	event := NewSuccessEvent(audit.ActionAgentRevoked, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithSeverity(audit.SeverityCritical).
		WithMessage(fmt.Sprintf("Agent '%s' access revoked: %s", agentName, reason)).
		WithMetadata("reason", reason)
	return s.LogEvent(ctx, actx, event)
}

// LogAgentKeyRegenerated logs an agent API key regeneration event.
func (s *AuditService) LogAgentKeyRegenerated(ctx context.Context, actx AuditContext, agentID, agentName string) error {
	event := NewSuccessEvent(audit.ActionAgentKeyRegenerated, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Agent '%s' API key regenerated", agentName))
	return s.LogEvent(ctx, actx, event)
}

// LogAgentConnected logs when an agent first connects (comes online).
func (s *AuditService) LogAgentConnected(ctx context.Context, actx AuditContext, agentID, agentName, ipAddress string) error {
	event := NewSuccessEvent(audit.ActionAgentConnected, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithMessage(fmt.Sprintf("Agent '%s' connected from %s", agentName, ipAddress)).
		WithMetadata("ip_address", ipAddress)
	return s.LogEvent(ctx, actx, event)
}

// LogAgentDisconnected logs when an agent goes offline (timeout).
func (s *AuditService) LogAgentDisconnected(ctx context.Context, actx AuditContext, agentID, agentName string) error {
	event := NewSuccessEvent(audit.ActionAgentDisconnected, audit.ResourceTypeAgent, agentID).
		WithResourceName(agentName).
		WithMessage(fmt.Sprintf("Agent '%s' disconnected (heartbeat timeout)", agentName))
	return s.LogEvent(ctx, actx, event)
}
