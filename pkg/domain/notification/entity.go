package notification

import (
	"slices"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ID is the unique identifier for a notification.
type ID = shared.ID

// ParseID parses a string into a notification ID.
func ParseID(s string) (ID, error) {
	return shared.IDFromString(s)
}

// Audience constants
const (
	AudienceAll   = "all"
	AudienceGroup = "group"
	AudienceUser  = "user"
)

// Severity constants
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Notification types
const (
	TypeFindingNew          = "finding_new"
	TypeFindingAssigned     = "finding_assigned"
	TypeFindingStatusChange = "finding_status_change"
	TypeFindingComment      = "finding_comment"
	TypeFindingMention      = "finding_mention"
	TypeScanStarted         = "scan_started"
	TypeScanCompleted       = "scan_completed"
	TypeScanFailed          = "scan_failed"
	TypeAssetDiscovered     = "asset_discovered"
	TypeMemberInvited       = "member_invited"
	TypeMemberJoined        = "member_joined"
	TypeRoleChanged         = "role_changed"
	TypeSLABreach           = "sla_breach"
	TypeSystemAlert         = "system_alert"
)

// Notification represents an in-app notification.
type Notification struct {
	id               ID
	tenantID         shared.ID
	audience         string
	audienceID       *shared.ID
	notificationType string
	title            string
	body             string
	severity         string
	resourceType     string
	resourceID       *shared.ID
	url              string
	actorID          *shared.ID
	createdAt        time.Time
	isRead           bool // computed field, not stored directly
}

// NotificationParams contains parameters for creating a new notification.
type NotificationParams struct {
	TenantID         shared.ID
	Audience         string
	AudienceID       *shared.ID
	NotificationType string
	Title            string
	Body             string
	Severity         string
	ResourceType     string
	ResourceID       *shared.ID
	URL              string
	ActorID          *shared.ID
}

// NewNotification creates a new notification.
func NewNotification(params NotificationParams) *Notification {
	return &Notification{
		id:               shared.NewID(),
		tenantID:         params.TenantID,
		audience:         params.Audience,
		audienceID:       params.AudienceID,
		notificationType: params.NotificationType,
		title:            params.Title,
		body:             params.Body,
		severity:         params.Severity,
		resourceType:     params.ResourceType,
		resourceID:       params.ResourceID,
		url:              params.URL,
		actorID:          params.ActorID,
		createdAt:        time.Now(),
	}
}

// Reconstitute recreates a notification from persistence.
func Reconstitute(
	id ID,
	tenantID shared.ID,
	audience string,
	audienceID *shared.ID,
	notificationType string,
	title string,
	body string,
	severity string,
	resourceType string,
	resourceID *shared.ID,
	url string,
	actorID *shared.ID,
	createdAt time.Time,
	isRead bool,
) *Notification {
	return &Notification{
		id:               id,
		tenantID:         tenantID,
		audience:         audience,
		audienceID:       audienceID,
		notificationType: notificationType,
		title:            title,
		body:             body,
		severity:         severity,
		resourceType:     resourceType,
		resourceID:       resourceID,
		url:              url,
		actorID:          actorID,
		createdAt:        createdAt,
		isRead:           isRead,
	}
}

// Getters
func (n *Notification) ID() ID                   { return n.id }
func (n *Notification) TenantID() shared.ID      { return n.tenantID }
func (n *Notification) Audience() string          { return n.audience }
func (n *Notification) AudienceID() *shared.ID    { return n.audienceID }
func (n *Notification) NotificationType() string  { return n.notificationType }
func (n *Notification) Title() string             { return n.title }
func (n *Notification) Body() string              { return n.body }
func (n *Notification) Severity() string          { return n.severity }
func (n *Notification) ResourceType() string      { return n.resourceType }
func (n *Notification) ResourceID() *shared.ID    { return n.resourceID }
func (n *Notification) URL() string               { return n.url }
func (n *Notification) ActorID() *shared.ID       { return n.actorID }
func (n *Notification) CreatedAt() time.Time      { return n.createdAt }
func (n *Notification) IsRead() bool              { return n.isRead }

// Preferences represents user notification preferences.
type Preferences struct {
	tenantID     shared.ID
	userID       shared.ID
	inAppEnabled bool
	emailDigest  string
	mutedTypes   []string
	minSeverity  string
	updatedAt    time.Time
}

// PreferencesParams contains parameters for creating/updating preferences.
type PreferencesParams struct {
	InAppEnabled bool
	EmailDigest  string
	MutedTypes   []string
	MinSeverity  string
}

// DefaultPreferences returns default preferences.
func DefaultPreferences(tenantID, userID shared.ID) *Preferences {
	return &Preferences{
		tenantID:     tenantID,
		userID:       userID,
		inAppEnabled: true,
		emailDigest:  "none",
		updatedAt:    time.Now(),
	}
}

// ReconstitutePref recreates preferences from persistence.
func ReconstitutePref(
	tenantID shared.ID,
	userID shared.ID,
	inAppEnabled bool,
	emailDigest string,
	mutedTypes []string,
	minSeverity string,
	updatedAt time.Time,
) *Preferences {
	return &Preferences{
		tenantID:     tenantID,
		userID:       userID,
		inAppEnabled: inAppEnabled,
		emailDigest:  emailDigest,
		mutedTypes:   mutedTypes,
		minSeverity:  minSeverity,
		updatedAt:    updatedAt,
	}
}

// Getters
func (p *Preferences) TenantID() shared.ID  { return p.tenantID }
func (p *Preferences) UserID() shared.ID    { return p.userID }
func (p *Preferences) InAppEnabled() bool   { return p.inAppEnabled }
func (p *Preferences) EmailDigest() string  { return p.emailDigest }
func (p *Preferences) MutedTypes() []string { return p.mutedTypes }
func (p *Preferences) MinSeverity() string  { return p.minSeverity }
func (p *Preferences) UpdatedAt() time.Time { return p.updatedAt }

// IsTypeMuted checks if a notification type is muted.
func (p *Preferences) IsTypeMuted(notifType string) bool {
	return slices.Contains(p.mutedTypes, notifType)
}

// IsSeverityAllowed checks if a severity meets the minimum threshold.
func (p *Preferences) IsSeverityAllowed(severity string) bool {
	if p.minSeverity == "" {
		return true
	}
	return severityRank(severity) >= severityRank(p.minSeverity)
}

// IsValidSeverity checks if a string is a valid severity value.
func IsValidSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// IsValidType checks if a string is a valid notification type.
func IsValidType(t string) bool {
	switch t {
	case TypeFindingNew, TypeFindingAssigned, TypeFindingStatusChange,
		TypeFindingComment, TypeFindingMention,
		TypeScanStarted, TypeScanCompleted, TypeScanFailed,
		TypeAssetDiscovered,
		TypeMemberInvited, TypeMemberJoined, TypeRoleChanged,
		TypeSLABreach, TypeSystemAlert:
		return true
	}
	return false
}

func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
