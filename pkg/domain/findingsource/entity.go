package findingsource

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Category represents a finding source category.
type Category struct {
	id           shared.ID
	code         string
	name         string
	description  string
	icon         string
	displayOrder int
	isActive     bool
	createdAt    time.Time
	updatedAt    time.Time
}

// NewCategory creates a new Category entity.
func NewCategory(code, name string) (*Category, error) {
	if code == "" {
		return nil, fmt.Errorf("%w: code is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &Category{
		id:           shared.NewID(),
		code:         code,
		name:         name,
		isActive:     true,
		displayOrder: 0,
		createdAt:    now,
		updatedAt:    now,
	}, nil
}

// ReconstituteCategory recreates a Category from persistence.
func ReconstituteCategory(
	id shared.ID,
	code, name, description, icon string,
	displayOrder int,
	isActive bool,
	createdAt, updatedAt time.Time,
) *Category {
	return &Category{
		id:           id,
		code:         code,
		name:         name,
		description:  description,
		icon:         icon,
		displayOrder: displayOrder,
		isActive:     isActive,
		createdAt:    createdAt,
		updatedAt:    updatedAt,
	}
}

// Getters
func (c *Category) ID() shared.ID        { return c.id }
func (c *Category) Code() string         { return c.code }
func (c *Category) Name() string         { return c.name }
func (c *Category) Description() string  { return c.description }
func (c *Category) Icon() string         { return c.icon }
func (c *Category) DisplayOrder() int    { return c.displayOrder }
func (c *Category) IsActive() bool       { return c.isActive }
func (c *Category) CreatedAt() time.Time { return c.createdAt }
func (c *Category) UpdatedAt() time.Time { return c.updatedAt }

// Setters
func (c *Category) SetDescription(description string) {
	c.description = description
	c.updatedAt = time.Now().UTC()
}

func (c *Category) SetIcon(icon string) {
	c.icon = icon
	c.updatedAt = time.Now().UTC()
}

func (c *Category) SetDisplayOrder(order int) {
	c.displayOrder = order
	c.updatedAt = time.Now().UTC()
}

func (c *Category) Activate() {
	c.isActive = true
	c.updatedAt = time.Now().UTC()
}

func (c *Category) Deactivate() {
	c.isActive = false
	c.updatedAt = time.Now().UTC()
}

// FindingSource represents a master finding source.
// Finding sources are system-level configuration, not per-tenant.
// Created only via DB seed or by system admin.
type FindingSource struct {
	id          shared.ID
	categoryID  *shared.ID
	code        string
	name        string
	description string

	// Display
	icon         string
	color        string
	displayOrder int

	// Status
	isSystem bool
	isActive bool

	createdAt time.Time
	updatedAt time.Time
}

// NewFindingSource creates a new FindingSource entity.
func NewFindingSource(code, name string) (*FindingSource, error) {
	if code == "" {
		return nil, fmt.Errorf("%w: code is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &FindingSource{
		id:           shared.NewID(),
		code:         code,
		name:         name,
		isActive:     true,
		isSystem:     false,
		displayOrder: 0,
		createdAt:    now,
		updatedAt:    now,
	}, nil
}

// ReconstituteFindingSource recreates a FindingSource from persistence.
func ReconstituteFindingSource(
	id shared.ID,
	categoryID *shared.ID,
	code, name, description string,
	icon, color string,
	displayOrder int,
	isSystem, isActive bool,
	createdAt, updatedAt time.Time,
) *FindingSource {
	return &FindingSource{
		id:           id,
		categoryID:   categoryID,
		code:         code,
		name:         name,
		description:  description,
		icon:         icon,
		color:        color,
		displayOrder: displayOrder,
		isSystem:     isSystem,
		isActive:     isActive,
		createdAt:    createdAt,
		updatedAt:    updatedAt,
	}
}

// Getters
func (f *FindingSource) ID() shared.ID          { return f.id }
func (f *FindingSource) CategoryID() *shared.ID { return f.categoryID }
func (f *FindingSource) Code() string           { return f.code }
func (f *FindingSource) Name() string           { return f.name }
func (f *FindingSource) Description() string    { return f.description }
func (f *FindingSource) Icon() string           { return f.icon }
func (f *FindingSource) Color() string          { return f.color }
func (f *FindingSource) DisplayOrder() int      { return f.displayOrder }
func (f *FindingSource) IsSystem() bool         { return f.isSystem }
func (f *FindingSource) IsActive() bool         { return f.isActive }
func (f *FindingSource) CreatedAt() time.Time   { return f.createdAt }
func (f *FindingSource) UpdatedAt() time.Time   { return f.updatedAt }

// Setters
func (f *FindingSource) SetCategoryID(categoryID *shared.ID) {
	f.categoryID = categoryID
	f.updatedAt = time.Now().UTC()
}

func (f *FindingSource) SetDescription(description string) {
	f.description = description
	f.updatedAt = time.Now().UTC()
}

func (f *FindingSource) SetIcon(icon string) {
	f.icon = icon
	f.updatedAt = time.Now().UTC()
}

func (f *FindingSource) SetColor(color string) {
	f.color = color
	f.updatedAt = time.Now().UTC()
}

func (f *FindingSource) SetDisplayOrder(order int) {
	f.displayOrder = order
	f.updatedAt = time.Now().UTC()
}

func (f *FindingSource) Activate() {
	f.isActive = true
	f.updatedAt = time.Now().UTC()
}

func (f *FindingSource) Deactivate() {
	f.isActive = false
	f.updatedAt = time.Now().UTC()
}

// FindingSourceWithCategory represents a finding source with its category loaded.
type FindingSourceWithCategory struct {
	FindingSource *FindingSource
	Category      *Category
}
