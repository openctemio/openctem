// Package audit provides public types and helpers reusable across the codebase.
package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// AuditLog represents an audit log entry.
type AuditLog struct {
	id           shared.ID
	tenantID     *shared.ID // nil for global/system events
	actorID      *shared.ID // User who performed the action (nil for system)
	actorEmail   string     // Email of actor (for display when user deleted)
	actorIP      string     // IP address of actor
	actorAgent   string     // User agent string
	action       Action
	resourceType ResourceType
	resourceID   string // ID of the affected resource
	resourceName string // Name/title for display (e.g., repository name)
	changes      *Changes
	result       Result
	severity     Severity
	message      string         // Human-readable description
	metadata     map[string]any // Additional context
	requestID    string         // Request tracing ID
	sessionID    string         // Session ID if applicable
	timestamp    time.Time
}

// NewAuditLog creates a new audit log entry.
func NewAuditLog(
	action Action,
	resourceType ResourceType,
	resourceID string,
	result Result,
) (*AuditLog, error) {
	if !action.IsValid() {
		return nil, fmt.Errorf("%w: invalid action", shared.ErrValidation)
	}
	if !resourceType.IsValid() {
		return nil, fmt.Errorf("%w: invalid resource type", shared.ErrValidation)
	}
	if !result.IsValid() {
		return nil, fmt.Errorf("%w: invalid result", shared.ErrValidation)
	}

	return &AuditLog{
		id:           shared.NewID(),
		action:       action,
		resourceType: resourceType,
		resourceID:   resourceID,
		result:       result,
		severity:     SeverityForAction(action),
		metadata:     make(map[string]any),
		// Rounded to microseconds because that is the resolution PostgreSQL
		// stores (and it rounds, not truncates). Keeping the in-memory value
		// equal to the stored value is what makes the hash chain verifiable.
		timestamp: time.Now().UTC().Round(time.Microsecond),
	}, nil
}

// Reconstitute recreates an AuditLog from persistence.
func Reconstitute(
	id shared.ID,
	tenantID *shared.ID,
	actorID *shared.ID,
	actorEmail string,
	actorIP string,
	actorAgent string,
	action Action,
	resourceType ResourceType,
	resourceID string,
	resourceName string,
	changes *Changes,
	result Result,
	severity Severity,
	message string,
	metadata map[string]any,
	requestID string,
	sessionID string,
	timestamp time.Time,
) *AuditLog {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &AuditLog{
		id:           id,
		tenantID:     tenantID,
		actorID:      actorID,
		actorEmail:   actorEmail,
		actorIP:      actorIP,
		actorAgent:   actorAgent,
		action:       action,
		resourceType: resourceType,
		resourceID:   resourceID,
		resourceName: resourceName,
		changes:      changes,
		result:       result,
		severity:     severity,
		message:      message,
		metadata:     metadata,
		requestID:    requestID,
		sessionID:    sessionID,
		timestamp:    timestamp,
	}
}

// Getters

// ID returns the audit log ID.
func (a *AuditLog) ID() shared.ID {
	return a.id
}

// TenantID returns the tenant ID.
func (a *AuditLog) TenantID() *shared.ID {
	return a.tenantID
}

// ActorID returns the actor ID.
func (a *AuditLog) ActorID() *shared.ID {
	return a.actorID
}

// ActorEmail returns the actor email.
func (a *AuditLog) ActorEmail() string {
	return a.actorEmail
}

// ActorIP returns the actor IP address.
func (a *AuditLog) ActorIP() string {
	return a.actorIP
}

// ActorAgent returns the actor user agent.
func (a *AuditLog) ActorAgent() string {
	return a.actorAgent
}

// Action returns the action.
func (a *AuditLog) Action() Action {
	return a.action
}

// ResourceType returns the resource type.
func (a *AuditLog) ResourceType() ResourceType {
	return a.resourceType
}

// ResourceID returns the resource ID.
func (a *AuditLog) ResourceID() string {
	return a.resourceID
}

// ResourceName returns the resource name.
func (a *AuditLog) ResourceName() string {
	return a.resourceName
}

// Changes returns the changes.
func (a *AuditLog) Changes() *Changes {
	return a.changes
}

// Result returns the result.
func (a *AuditLog) Result() Result {
	return a.result
}

// Severity returns the severity.
func (a *AuditLog) Severity() Severity {
	return a.severity
}

// Message returns the message.
func (a *AuditLog) Message() string {
	return a.message
}

// Metadata returns a copy of the metadata.
func (a *AuditLog) Metadata() map[string]any {
	metadata := make(map[string]any, len(a.metadata))
	for k, v := range a.metadata {
		metadata[k] = v
	}
	return metadata
}

// RequestID returns the request ID.
func (a *AuditLog) RequestID() string {
	return a.requestID
}

// SessionID returns the session ID.
func (a *AuditLog) SessionID() string {
	return a.sessionID
}

// Timestamp returns the timestamp.
func (a *AuditLog) Timestamp() time.Time {
	return a.timestamp
}

// Setters (builder pattern)

// WithTenantID sets the tenant ID.
func (a *AuditLog) WithTenantID(tenantID shared.ID) *AuditLog {
	a.tenantID = &tenantID
	return a
}

// WithActor sets the actor information.
func (a *AuditLog) WithActor(actorID shared.ID, email string) *AuditLog {
	a.actorID = &actorID
	a.actorEmail = email
	return a
}

// maxActorIPLen matches the audit_logs.actor_ip column (varchar(45)). A value
// longer than this does not truncate — the INSERT fails outright, which drops the
// audit row AND its hash-chain entry with no error surfaced to the caller. That
// makes the audit trail suppressible: several handlers assign the raw
// X-Forwarded-For header, so a long (or multi-hop) header silently erases the
// record of the request that carried it. A plain IPv6 RemoteAddr like
// "[2001:db8:85a3::8a2e:370:7334]:54321" is already 47 characters and hits this.
const maxActorIPLen = 45

// WithActorIP sets the actor IP address. The value is reduced to a single,
// storable address: callers routinely pass a whole X-Forwarded-For chain, of
// which only the leftmost entry is the client.
func (a *AuditLog) WithActorIP(ip string) *AuditLog {
	a.actorIP = normalizeActorIP(ip)
	return a
}

// WithActorAgent sets the actor user agent.
func (a *AuditLog) WithActorAgent(agent string) *AuditLog {
	a.actorAgent = agent
	return a
}

// WithResourceName sets the resource name.
func (a *AuditLog) WithResourceName(name string) *AuditLog {
	a.resourceName = name
	return a
}

// WithChanges sets the changes.
func (a *AuditLog) WithChanges(changes *Changes) *AuditLog {
	a.changes = changes
	return a
}

// WithSeverity sets the severity (overrides default).
func (a *AuditLog) WithSeverity(severity Severity) *AuditLog {
	a.severity = severity
	return a
}

// WithMessage sets the message.
func (a *AuditLog) WithMessage(message string) *AuditLog {
	a.message = message
	return a
}

// WithMetadata sets a metadata key-value pair.
func (a *AuditLog) WithMetadata(key string, value any) *AuditLog {
	a.metadata[key] = value
	return a
}

// WithRequestID sets the request ID.
func (a *AuditLog) WithRequestID(requestID string) *AuditLog {
	a.requestID = requestID
	return a
}

// WithSessionID sets the session ID.
func (a *AuditLog) WithSessionID(sessionID string) *AuditLog {
	a.sessionID = sessionID
	return a
}

// Helper methods

// IsSuccess checks if the action was successful.
func (a *AuditLog) IsSuccess() bool {
	return a.result == ResultSuccess
}

// IsFailure checks if the action failed.
func (a *AuditLog) IsFailure() bool {
	return a.result == ResultFailure
}

// IsDenied checks if the action was denied.
func (a *AuditLog) IsDenied() bool {
	return a.result == ResultDenied
}

// IsCritical checks if the severity is critical.
func (a *AuditLog) IsCritical() bool {
	return a.severity == SeverityCritical
}

// IsHighOrCritical checks if the severity is high or critical.
func (a *AuditLog) IsHighOrCritical() bool {
	return a.severity == SeverityHigh || a.severity == SeverityCritical
}

// Category returns the action category.
func (a *AuditLog) Category() string {
	return a.action.Category()
}

// HasChanges checks if there are recorded changes.
func (a *AuditLog) HasChanges() bool {
	return a.changes != nil && !a.changes.IsEmpty()
}

// GenerateMessage generates a default message if none is set.
func (a *AuditLog) GenerateMessage() string {
	if a.message != "" {
		return a.message
	}

	actor := "System"
	if a.actorEmail != "" {
		actor = a.actorEmail
	}

	resource := string(a.resourceType)
	if a.resourceName != "" {
		resource = fmt.Sprintf("%s '%s'", a.resourceType, a.resourceName)
	} else if a.resourceID != "" {
		resource = fmt.Sprintf("%s %s", a.resourceType, a.resourceID)
	}

	return fmt.Sprintf("%s performed %s on %s (%s)", actor, a.action, resource, a.result)
}

// normalizeActorIP keeps the leftmost X-Forwarded-For entry and bounds the result
// to what the column can store, so an over-long or multi-hop value can never
// suppress the audit row.
func normalizeActorIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if idx := strings.Index(ip, ","); idx != -1 {
		ip = strings.TrimSpace(ip[:idx])
	}
	if len(ip) > maxActorIPLen {
		ip = ip[:maxActorIPLen]
	}
	return ip
}
