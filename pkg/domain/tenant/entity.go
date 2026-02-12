package tenant

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Tenant represents a tenant (displayed as "Team" in UI) entity.
type Tenant struct {
	id          shared.ID
	name        string
	slug        string
	description string
	logoURL     string
	settings    map[string]any
	createdBy   string // Keycloak user ID
	createdAt   time.Time
	updatedAt   time.Time
}

// NewTenant creates a new Tenant entity.
func NewTenant(name, slug, createdBy string) (*Tenant, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if slug == "" {
		return nil, fmt.Errorf("%w: slug is required", shared.ErrValidation)
	}
	if !IsValidSlug(slug) {
		return nil, fmt.Errorf("%w: invalid slug format (use lowercase letters, numbers, and hyphens)", shared.ErrValidation)
	}
	if createdBy == "" {
		return nil, fmt.Errorf("%w: createdBy is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &Tenant{
		id:        shared.NewID(),
		name:      name,
		slug:      strings.ToLower(slug),
		settings:  make(map[string]any),
		createdBy: createdBy,
		createdAt: now,
		updatedAt: now,
	}, nil
}

// Reconstitute recreates a Tenant from persistence.
func Reconstitute(
	id shared.ID,
	name, slug, description, logoURL string,
	settings map[string]any,
	createdBy string,
	createdAt, updatedAt time.Time,
) *Tenant {
	if settings == nil {
		settings = make(map[string]any)
	}
	return &Tenant{
		id:          id,
		name:        name,
		slug:        slug,
		description: description,
		logoURL:     logoURL,
		settings:    settings,
		createdBy:   createdBy,
		createdAt:   createdAt,
		updatedAt:   updatedAt,
	}
}

// ID returns the tenant ID.
func (t *Tenant) ID() shared.ID {
	return t.id
}

// Name returns the tenant name.
func (t *Tenant) Name() string {
	return t.name
}

// Slug returns the tenant slug (URL-friendly identifier).
func (t *Tenant) Slug() string {
	return t.slug
}

// Description returns the tenant description.
func (t *Tenant) Description() string {
	return t.description
}

// LogoURL returns the tenant logo URL.
func (t *Tenant) LogoURL() string {
	return t.logoURL
}

// Plan returns the tenant's module configuration.
// In OSS edition, all tenants have the free plan with unlimited access.
func (t *Tenant) Plan() Plan {
	return PlanFree
}

// Settings returns the tenant settings.
func (t *Tenant) Settings() map[string]any {
	result := make(map[string]any, len(t.settings))
	for k, v := range t.settings {
		result[k] = v
	}
	return result
}

// CreatedBy returns the user ID who created this tenant.
func (t *Tenant) CreatedBy() string {
	return t.createdBy
}

// CreatedAt returns the creation timestamp.
func (t *Tenant) CreatedAt() time.Time {
	return t.createdAt
}

// UpdatedAt returns the last update timestamp.
func (t *Tenant) UpdatedAt() time.Time {
	return t.updatedAt
}

// UpdateName updates the tenant name.
func (t *Tenant) UpdateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	t.name = name
	t.updatedAt = time.Now().UTC()
	return nil
}

// UpdateDescription updates the tenant description.
func (t *Tenant) UpdateDescription(description string) {
	t.description = description
	t.updatedAt = time.Now().UTC()
}

// UpdateLogoURL updates the tenant logo URL.
func (t *Tenant) UpdateLogoURL(logoURL string) {
	t.logoURL = logoURL
	t.updatedAt = time.Now().UTC()
}

// UpdateSlug updates the tenant slug.
// Note: Caller must verify uniqueness before calling this method.
func (t *Tenant) UpdateSlug(slug string) error {
	if !IsValidSlug(slug) {
		return fmt.Errorf("%w: slug must be 3-100 characters and contain only lowercase letters, numbers, and hyphens", shared.ErrValidation)
	}
	t.slug = slug
	t.updatedAt = time.Now().UTC()
	return nil
}

// UpdatePlan updates the tenant's module configuration.
// In OSS edition, this is a no-op as all tenants have unlimited access.
func (t *Tenant) UpdatePlan(_ Plan) error {
	return nil
}

// SetSetting sets a setting value.
func (t *Tenant) SetSetting(key string, value any) {
	if key == "" {
		return
	}
	t.settings[key] = value
	t.updatedAt = time.Now().UTC()
}

// GetSetting gets a setting value.
func (t *Tenant) GetSetting(key string) (any, bool) {
	v, ok := t.settings[key]
	return v, ok
}

// IsValidSlug checks if a slug is valid.
func IsValidSlug(slug string) bool {
	if len(slug) < 3 || len(slug) > 100 {
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
