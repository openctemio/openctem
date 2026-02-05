package assettype

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Category represents an asset type category.
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

// AssetType represents a master asset type.
// Asset types are system-level configuration, not per-tenant.
// Created only via DB seed or by system admin.
type AssetType struct {
	id          shared.ID
	categoryID  *shared.ID
	code        string
	name        string
	description string

	// Display
	icon         string
	color        string
	displayOrder int

	// Validation patterns
	patternRegex       string
	patternPlaceholder string
	patternExample     string

	// Capabilities
	supportsWildcard bool
	supportsCIDR     bool
	isDiscoverable   bool
	isScannable      bool

	// Status
	isSystem bool
	isActive bool

	createdAt time.Time
	updatedAt time.Time
}

// NewAssetType creates a new AssetType entity.
func NewAssetType(code, name string) (*AssetType, error) {
	if code == "" {
		return nil, fmt.Errorf("%w: code is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &AssetType{
		id:               shared.NewID(),
		code:             code,
		name:             name,
		isActive:         true,
		isSystem:         false,
		isDiscoverable:   true,
		isScannable:      true,
		supportsWildcard: false,
		supportsCIDR:     false,
		displayOrder:     0,
		createdAt:        now,
		updatedAt:        now,
	}, nil
}

// ReconstituteAssetType recreates an AssetType from persistence.
func ReconstituteAssetType(
	id shared.ID,
	categoryID *shared.ID,
	code, name, description string,
	icon, color string,
	displayOrder int,
	patternRegex, patternPlaceholder, patternExample string,
	supportsWildcard, supportsCIDR bool,
	isDiscoverable, isScannable bool,
	isSystem, isActive bool,
	createdAt, updatedAt time.Time,
) *AssetType {
	return &AssetType{
		id:                 id,
		categoryID:         categoryID,
		code:               code,
		name:               name,
		description:        description,
		icon:               icon,
		color:              color,
		displayOrder:       displayOrder,
		patternRegex:       patternRegex,
		patternPlaceholder: patternPlaceholder,
		patternExample:     patternExample,
		supportsWildcard:   supportsWildcard,
		supportsCIDR:       supportsCIDR,
		isDiscoverable:     isDiscoverable,
		isScannable:        isScannable,
		isSystem:           isSystem,
		isActive:           isActive,
		createdAt:          createdAt,
		updatedAt:          updatedAt,
	}
}

// Getters
func (a *AssetType) ID() shared.ID              { return a.id }
func (a *AssetType) CategoryID() *shared.ID     { return a.categoryID }
func (a *AssetType) Code() string               { return a.code }
func (a *AssetType) Name() string               { return a.name }
func (a *AssetType) Description() string        { return a.description }
func (a *AssetType) Icon() string               { return a.icon }
func (a *AssetType) Color() string              { return a.color }
func (a *AssetType) DisplayOrder() int          { return a.displayOrder }
func (a *AssetType) PatternRegex() string       { return a.patternRegex }
func (a *AssetType) PatternPlaceholder() string { return a.patternPlaceholder }
func (a *AssetType) PatternExample() string     { return a.patternExample }
func (a *AssetType) SupportsWildcard() bool     { return a.supportsWildcard }
func (a *AssetType) SupportsCIDR() bool         { return a.supportsCIDR }
func (a *AssetType) IsDiscoverable() bool       { return a.isDiscoverable }
func (a *AssetType) IsScannable() bool          { return a.isScannable }
func (a *AssetType) IsSystem() bool             { return a.isSystem }
func (a *AssetType) IsActive() bool             { return a.isActive }
func (a *AssetType) CreatedAt() time.Time       { return a.createdAt }
func (a *AssetType) UpdatedAt() time.Time       { return a.updatedAt }

// Setters
func (a *AssetType) SetCategoryID(categoryID *shared.ID) {
	a.categoryID = categoryID
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetDescription(description string) {
	a.description = description
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetIcon(icon string) {
	a.icon = icon
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetColor(color string) {
	a.color = color
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetDisplayOrder(order int) {
	a.displayOrder = order
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetPatternRegex(regex string) {
	a.patternRegex = regex
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetPatternPlaceholder(placeholder string) {
	a.patternPlaceholder = placeholder
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetPatternExample(example string) {
	a.patternExample = example
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetSupportsWildcard(supports bool) {
	a.supportsWildcard = supports
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetSupportsCIDR(supports bool) {
	a.supportsCIDR = supports
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetIsDiscoverable(discoverable bool) {
	a.isDiscoverable = discoverable
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) SetIsScannable(scannable bool) {
	a.isScannable = scannable
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) Activate() {
	a.isActive = true
	a.updatedAt = time.Now().UTC()
}

func (a *AssetType) Deactivate() {
	a.isActive = false
	a.updatedAt = time.Now().UTC()
}

// AssetTypeWithCategory represents an asset type with its category loaded.
type AssetTypeWithCategory struct {
	AssetType *AssetType
	Category  *Category
}
