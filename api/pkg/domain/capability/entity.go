// Package capability defines the Capability domain entity.
// Capabilities describe what a tool can do (e.g., sast, sca, xss, portscan).
// They can be platform-wide (builtin) or tenant-specific (custom).
package capability

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Security: Strict name validation - only ASCII lowercase alphanumeric with hyphens
// Prevents Unicode homograph attacks (e.g., "sast" vs Cyrillic "ѕаѕт")
var nameRegex = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]+$`)

// Security: Reserved capability names that cannot be used by tenants
var reservedNames = map[string]bool{
	"admin": true, "system": true, "platform": true, "root": true,
	"all": true, "any": true, "none": true, "null": true,
}

// MaxCustomCapabilitiesPerTenant is the limit for custom capabilities per tenant
// to prevent DoS through capability enumeration/creation
const MaxCustomCapabilitiesPerTenant = 50

// Capability represents a tool capability.
// Platform capabilities (TenantID = nil, IsBuiltin = true) are available to all tenants.
// Tenant custom capabilities (TenantID = UUID, IsBuiltin = false) are private to that tenant.
type Capability struct {
	ID          shared.ID
	TenantID    *shared.ID // nil = platform capability, UUID = tenant custom capability
	Name        string     // Unique slug: 'sast', 'xss', 'portscan'
	DisplayName string     // Display: 'SAST', 'XSS Detection', 'Port Scanning'
	Description string

	// UI customization
	Icon  string // Lucide icon name
	Color string // Badge color

	// Classification
	Category string // Group: 'security', 'recon', 'analysis'

	// Status
	IsBuiltin bool
	SortOrder int

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewPlatformCapability creates a new platform (builtin) capability.
func NewPlatformCapability(
	name string,
	displayName string,
	description string,
	icon string,
	color string,
	category string,
	sortOrder int,
) (*Capability, error) {
	c := &Capability{
		ID:          shared.NewID(),
		TenantID:    nil,
		Name:        strings.ToLower(strings.TrimSpace(name)),
		DisplayName: strings.TrimSpace(displayName),
		Description: strings.TrimSpace(description),
		Icon:        icon,
		Color:       color,
		Category:    category,
		IsBuiltin:   true,
		SortOrder:   sortOrder,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c, nil
}

// NewTenantCapability creates a new tenant-specific (custom) capability.
func NewTenantCapability(
	tenantID shared.ID,
	createdBy shared.ID,
	name string,
	displayName string,
	description string,
	icon string,
	color string,
	category string,
) (*Capability, error) {
	c := &Capability{
		ID:          shared.NewID(),
		TenantID:    &tenantID,
		Name:        strings.ToLower(strings.TrimSpace(name)),
		DisplayName: strings.TrimSpace(displayName),
		Description: strings.TrimSpace(description),
		Icon:        icon,
		Color:       color,
		Category:    category,
		IsBuiltin:   false,
		SortOrder:   100, // Custom capabilities come after builtin
		CreatedBy:   &createdBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c, nil
}

// Update updates the capability fields.
func (c *Capability) Update(
	displayName string,
	description string,
	icon string,
	color string,
	category string,
) error {
	c.DisplayName = strings.TrimSpace(displayName)
	c.Description = strings.TrimSpace(description)
	c.Icon = icon
	c.Color = color
	c.Category = category
	c.UpdatedAt = time.Now()

	return c.Validate()
}

// Validate validates the capability data.
func (c *Capability) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	if len(c.Name) < 2 || len(c.Name) > 50 {
		return fmt.Errorf("%w: name must be 2-50 characters", shared.ErrValidation)
	}

	// Security: Check for non-ASCII characters (Unicode homograph attack prevention)
	if !isASCIIOnly(c.Name) {
		return fmt.Errorf("%w: name must contain only ASCII characters", shared.ErrValidation)
	}

	if !nameRegex.MatchString(c.Name) {
		return fmt.Errorf("%w: name must be lowercase alphanumeric with hyphens (e.g., 'port-scan')", shared.ErrValidation)
	}

	// Security: Check for reserved names (only for non-builtin capabilities)
	if !c.IsBuiltin && reservedNames[c.Name] {
		return fmt.Errorf("%w: name is reserved and cannot be used", shared.ErrValidation)
	}

	if c.DisplayName == "" {
		return fmt.Errorf("%w: display name is required", shared.ErrValidation)
	}

	if len(c.DisplayName) > 100 {
		return fmt.Errorf("%w: display name must be at most 100 characters", shared.ErrValidation)
	}

	// Security: Sanitize display name to prevent XSS
	c.DisplayName = sanitizeDisplayText(c.DisplayName)
	c.Description = sanitizeDisplayText(c.Description)

	if c.Icon == "" {
		c.Icon = "zap" // Default icon
	}

	// Security: Validate icon name (only alphanumeric with hyphens)
	if !isValidIconName(c.Icon) {
		return fmt.Errorf("%w: icon must be alphanumeric with hyphens only", shared.ErrValidation)
	}

	if c.Color == "" {
		c.Color = "gray" // Default color
	}

	// Security: Validate color name (only alphanumeric)
	if !isValidColorName(c.Color) {
		return fmt.Errorf("%w: color must be alphanumeric only", shared.ErrValidation)
	}

	return nil
}

// isASCIIOnly checks if a string contains only ASCII characters.
// Prevents Unicode homograph attacks.
func isASCIIOnly(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// sanitizeDisplayText removes HTML tags and escapes special characters.
// Prevents XSS attacks when display name/description is rendered in UI.
func sanitizeDisplayText(s string) string {
	// Escape HTML entities
	s = html.EscapeString(s)
	// Remove any remaining angle brackets (shouldn't exist after escape, but be safe)
	s = strings.ReplaceAll(s, "<", "")
	s = strings.ReplaceAll(s, ">", "")
	return s
}

// isValidIconName validates that icon name is safe.
var iconNameRegex = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func isValidIconName(s string) bool {
	return len(s) <= 50 && iconNameRegex.MatchString(s)
}

// isValidColorName validates that color name is safe.
var colorNameRegex = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

func isValidColorName(s string) bool {
	return len(s) <= 20 && colorNameRegex.MatchString(s)
}

// IsPlatformCapability returns true if this is a platform (builtin) capability.
func (c *Capability) IsPlatformCapability() bool {
	return c.TenantID == nil && c.IsBuiltin
}

// IsTenantCapability returns true if this is a tenant custom capability.
func (c *Capability) IsTenantCapability() bool {
	return c.TenantID != nil && !c.IsBuiltin
}

// CanBeModifiedByTenant checks if a tenant can modify this capability.
// Only tenant's own custom capabilities can be modified.
func (c *Capability) CanBeModifiedByTenant(tenantID shared.ID) bool {
	return c.TenantID != nil && *c.TenantID == tenantID
}

// EmbeddedCapability contains minimal capability info for embedding in responses.
type EmbeddedCapability struct {
	ID          shared.ID `json:"id"`
	Name        string    `json:"name"`         // slug: 'sast', 'xss'
	DisplayName string    `json:"display_name"` // 'SAST', 'XSS Detection'
	Icon        string    `json:"icon"`
	Color       string    `json:"color"`
	Category    string    `json:"category"`
}

// ToEmbedded converts a Capability to EmbeddedCapability.
func (c *Capability) ToEmbedded() EmbeddedCapability {
	return EmbeddedCapability{
		ID:          c.ID,
		Name:        c.Name,
		DisplayName: c.DisplayName,
		Icon:        c.Icon,
		Color:       c.Color,
		Category:    c.Category,
	}
}
