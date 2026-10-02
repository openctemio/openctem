// Package toolcategory defines the ToolCategory domain entity.
// Tool categories can be platform-wide (builtin) or tenant-specific (custom).
package toolcategory

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

var nameRegex = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)

// ToolCategory represents a tool category.
// Platform categories (TenantID = nil, IsBuiltin = true) are available to all tenants.
// Tenant custom categories (TenantID = UUID, IsBuiltin = false) are private to that tenant.
type ToolCategory struct {
	ID          shared.ID
	TenantID    *shared.ID // nil = platform category, UUID = tenant custom category
	Name        string     // Unique slug: 'sast', 'my-custom-cat'
	DisplayName string     // Display: 'SAST', 'My Custom Category'
	Description string

	// UI customization
	Icon  string // Lucide icon name
	Color string // Badge color

	// Status
	IsBuiltin bool
	SortOrder int

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewPlatformCategory creates a new platform (builtin) category.
func NewPlatformCategory(
	name string,
	displayName string,
	description string,
	icon string,
	color string,
	sortOrder int,
) (*ToolCategory, error) {
	tc := &ToolCategory{
		ID:          shared.NewID(),
		TenantID:    nil,
		Name:        strings.ToLower(strings.TrimSpace(name)),
		DisplayName: strings.TrimSpace(displayName),
		Description: strings.TrimSpace(description),
		Icon:        icon,
		Color:       color,
		IsBuiltin:   true,
		SortOrder:   sortOrder,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := tc.Validate(); err != nil {
		return nil, err
	}

	return tc, nil
}

// NewTenantCategory creates a new tenant-specific (custom) category.
func NewTenantCategory(
	tenantID shared.ID,
	createdBy shared.ID,
	name string,
	displayName string,
	description string,
	icon string,
	color string,
) (*ToolCategory, error) {
	tc := &ToolCategory{
		ID:          shared.NewID(),
		TenantID:    &tenantID,
		Name:        strings.ToLower(strings.TrimSpace(name)),
		DisplayName: strings.TrimSpace(displayName),
		Description: strings.TrimSpace(description),
		Icon:        icon,
		Color:       color,
		IsBuiltin:   false,
		SortOrder:   100, // Custom categories come after builtin
		CreatedBy:   &createdBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := tc.Validate(); err != nil {
		return nil, err
	}

	return tc, nil
}

// Update updates the category fields.
func (tc *ToolCategory) Update(
	displayName string,
	description string,
	icon string,
	color string,
) error {
	tc.DisplayName = strings.TrimSpace(displayName)
	tc.Description = strings.TrimSpace(description)
	tc.Icon = icon
	tc.Color = color
	tc.UpdatedAt = time.Now()

	return tc.Validate()
}

// Validate validates the category data.
func (tc *ToolCategory) Validate() error {
	if tc.Name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	if len(tc.Name) < 2 || len(tc.Name) > 50 {
		return fmt.Errorf("%w: name must be 2-50 characters", shared.ErrValidation)
	}

	if !nameRegex.MatchString(tc.Name) {
		return fmt.Errorf("%w: name must be lowercase alphanumeric with hyphens (e.g., 'my-category')", shared.ErrValidation)
	}

	if tc.DisplayName == "" {
		return fmt.Errorf("%w: display name is required", shared.ErrValidation)
	}

	if len(tc.DisplayName) > 100 {
		return fmt.Errorf("%w: display name must be at most 100 characters", shared.ErrValidation)
	}

	if tc.Icon == "" {
		tc.Icon = "folder" // Default icon
	}

	if tc.Color == "" {
		tc.Color = "gray" // Default color
	}

	return nil
}

// IsPlatformCategory returns true if this is a platform (builtin) category.
func (tc *ToolCategory) IsPlatformCategory() bool {
	return tc.TenantID == nil && tc.IsBuiltin
}

// IsTenantCategory returns true if this is a tenant custom category.
func (tc *ToolCategory) IsTenantCategory() bool {
	return tc.TenantID != nil && !tc.IsBuiltin
}

// CanBeModifiedByTenant checks if a tenant can modify this category.
// Only tenant's own custom categories can be modified.
func (tc *ToolCategory) CanBeModifiedByTenant(tenantID shared.ID) bool {
	return tc.TenantID != nil && *tc.TenantID == tenantID
}
