package tenant

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
	// plan is the stored plan (tenant_plans); empty when none is stored.
	plan      plan.Plan
	createdAt time.Time
	updatedAt time.Time
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
	// A new organization asks personal accounts for a second factor
	// (RFC-058) and its owners and admins for one too; organizations created
	// before keep their settings.
	initial := DefaultSettings()
	initial.Security.PersonalAccounts = PersonalAccountsAllowedWithMFA
	// Owners and admins of a new organization use a second factor.
	initial.Security.MFARequiredForAdmins = true
	return &Tenant{
		id:        shared.NewID(),
		name:      name,
		slug:      strings.ToLower(slug),
		settings:  initial.ToMap(),
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

// Plan returns the organization's plan: the stored one, or plan.Unassigned
// when none is stored. The repository loads it from tenant_plans, the one
// source of the plan that limits, the console and Settings > Plan & usage read.
func (t *Tenant) Plan() plan.Plan {
	if t.plan == "" {
		return plan.Unassigned
	}
	return t.plan
}

// StoredPlan returns the plan stored for the organization; ok=false when none
// is stored (the organization resolves to plan.Unassigned).
func (t *Tenant) StoredPlan() (plan.Plan, bool) {
	return t.plan, t.plan != ""
}

// SetPlan records the organization's plan: the repository sets the stored
// plan when it loads the organization, and a self-service creation sets Free
// before the organization is written, so the plan is stored in the same
// transaction (never an organization without its Free plan).
func (t *Tenant) SetPlan(p plan.Plan) error {
	if !p.IsValid() {
		return plan.ErrInvalid
	}
	t.plan = p
	return nil
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
