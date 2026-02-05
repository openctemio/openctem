package group

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Group represents a user group for access control.
type Group struct {
	id                 shared.ID
	tenantID           shared.ID
	name               string
	slug               string
	description        string
	groupType          GroupType
	externalID         *string
	externalSource     *ExternalSource
	settings           GroupSettings
	notificationConfig NotificationConfig
	metadata           map[string]any
	isActive           bool
	createdAt          time.Time
	updatedAt          time.Time
}

// NewGroup creates a new Group entity.
func NewGroup(tenantID shared.ID, name, slug string, groupType GroupType) (*Group, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenantID is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if slug == "" {
		return nil, fmt.Errorf("%w: slug is required", shared.ErrValidation)
	}
	if !IsValidSlug(slug) {
		return nil, fmt.Errorf("%w: invalid slug format (use lowercase letters, numbers, and hyphens)", shared.ErrValidation)
	}
	if !groupType.IsValid() {
		return nil, fmt.Errorf("%w: invalid group type", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &Group{
		id:                 shared.NewID(),
		tenantID:           tenantID,
		name:               name,
		slug:               strings.ToLower(slug),
		groupType:          groupType,
		settings:           DefaultGroupSettings(),
		notificationConfig: DefaultNotificationConfig(),
		metadata:           make(map[string]any),
		isActive:           true,
		createdAt:          now,
		updatedAt:          now,
	}, nil
}

// Reconstitute recreates a Group from persistence.
func Reconstitute(
	id shared.ID,
	tenantID shared.ID,
	name, slug, description string,
	groupType GroupType,
	externalID *string,
	externalSource *ExternalSource,
	settings GroupSettings,
	notificationConfig NotificationConfig,
	metadata map[string]any,
	isActive bool,
	createdAt, updatedAt time.Time,
) *Group {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &Group{
		id:                 id,
		tenantID:           tenantID,
		name:               name,
		slug:               slug,
		description:        description,
		groupType:          groupType,
		externalID:         externalID,
		externalSource:     externalSource,
		settings:           settings,
		notificationConfig: notificationConfig,
		metadata:           metadata,
		isActive:           isActive,
		createdAt:          createdAt,
		updatedAt:          updatedAt,
	}
}

// ID returns the group ID.
func (g *Group) ID() shared.ID {
	return g.id
}

// TenantID returns the tenant ID.
func (g *Group) TenantID() shared.ID {
	return g.tenantID
}

// Name returns the group name.
func (g *Group) Name() string {
	return g.name
}

// Slug returns the group slug.
func (g *Group) Slug() string {
	return g.slug
}

// Description returns the group description.
func (g *Group) Description() string {
	return g.description
}

// GroupType returns the group type.
func (g *Group) GroupType() GroupType {
	return g.groupType
}

// ExternalID returns the external system ID (if synced).
func (g *Group) ExternalID() *string {
	return g.externalID
}

// ExternalSource returns the external sync source.
func (g *Group) ExternalSource() *ExternalSource {
	return g.externalSource
}

// Settings returns the group settings.
func (g *Group) Settings() GroupSettings {
	return g.settings
}

// NotificationConfig returns the notification configuration.
func (g *Group) NotificationConfig() NotificationConfig {
	return g.notificationConfig
}

// Metadata returns a copy of the metadata.
func (g *Group) Metadata() map[string]any {
	result := make(map[string]any, len(g.metadata))
	for k, v := range g.metadata {
		result[k] = v
	}
	return result
}

// IsActive returns whether the group is active.
func (g *Group) IsActive() bool {
	return g.isActive
}

// CreatedAt returns the creation timestamp.
func (g *Group) CreatedAt() time.Time {
	return g.createdAt
}

// UpdatedAt returns the last update timestamp.
func (g *Group) UpdatedAt() time.Time {
	return g.updatedAt
}

// IsSecurityTeam checks if this is a security team.
func (g *Group) IsSecurityTeam() bool {
	return g.groupType == GroupTypeSecurityTeam
}

// IsAssetOwnerTeam checks if this is an asset owner team.
func (g *Group) IsAssetOwnerTeam() bool {
	return g.groupType == GroupTypeTeam
}

// IsExternalGroup checks if this group is synced from external source.
func (g *Group) IsExternalGroup() bool {
	return g.externalID != nil && g.externalSource != nil
}

// UpdateName updates the group name.
func (g *Group) UpdateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	g.name = name
	g.updatedAt = time.Now().UTC()
	return nil
}

// UpdateDescription updates the group description.
func (g *Group) UpdateDescription(description string) {
	g.description = description
	g.updatedAt = time.Now().UTC()
}

// UpdateSlug updates the group slug.
func (g *Group) UpdateSlug(slug string) error {
	if !IsValidSlug(slug) {
		return fmt.Errorf("%w: invalid slug format", shared.ErrValidation)
	}
	g.slug = strings.ToLower(slug)
	g.updatedAt = time.Now().UTC()
	return nil
}

// UpdateSettings updates the group settings.
func (g *Group) UpdateSettings(settings GroupSettings) {
	g.settings = settings
	g.updatedAt = time.Now().UTC()
}

// UpdateNotificationConfig updates the notification configuration.
func (g *Group) UpdateNotificationConfig(config NotificationConfig) {
	g.notificationConfig = config
	g.updatedAt = time.Now().UTC()
}

// SetMetadata sets a metadata value.
func (g *Group) SetMetadata(key string, value any) {
	if key == "" {
		return
	}
	g.metadata[key] = value
	g.updatedAt = time.Now().UTC()
}

// GetMetadata gets a metadata value.
func (g *Group) GetMetadata(key string) (any, bool) {
	v, ok := g.metadata[key]
	return v, ok
}

// SetExternalSync sets the external sync information.
func (g *Group) SetExternalSync(externalID string, source ExternalSource) error {
	if externalID == "" {
		return fmt.Errorf("%w: externalID is required", shared.ErrValidation)
	}
	if !source.IsValid() {
		return fmt.Errorf("%w: invalid external source", shared.ErrValidation)
	}
	g.externalID = &externalID
	g.externalSource = &source
	g.updatedAt = time.Now().UTC()
	return nil
}

// ClearExternalSync clears the external sync information.
func (g *Group) ClearExternalSync() {
	g.externalID = nil
	g.externalSource = nil
	g.updatedAt = time.Now().UTC()
}

// Activate activates the group.
func (g *Group) Activate() {
	g.isActive = true
	g.updatedAt = time.Now().UTC()
}

// Deactivate deactivates the group.
func (g *Group) Deactivate() {
	g.isActive = false
	g.updatedAt = time.Now().UTC()
}

// IsValidSlug checks if a slug is valid.
func IsValidSlug(slug string) bool {
	if len(slug) < 2 || len(slug) > 100 {
		return false
	}
	return slugRegex.MatchString(slug)
}

// GenerateSlug generates a slug from a name.
func GenerateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 100 {
		slug = slug[:100]
	}
	return slug
}
