package compliance

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Framework represents a compliance framework (e.g., SOC2, ISO27001).
type Framework struct {
	id            shared.ID
	tenantID      *shared.ID // nil = system framework
	name          string
	slug          string
	version       string
	description   string
	category      FrameworkCategory
	totalControls int
	isSystem      bool
	isActive      bool
	metadata      map[string]any
	createdAt     time.Time
	updatedAt     time.Time
}

// NewFramework creates a new custom framework.
func NewFramework(tenantID shared.ID, name, slug, version, description string, category FrameworkCategory) (*Framework, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if slug == "" {
		return nil, fmt.Errorf("%w: slug is required", shared.ErrValidation)
	}

	now := time.Now()
	return &Framework{
		id:        shared.NewID(),
		tenantID:  &tenantID,
		name:      name,
		slug:      slug,
		version:   version,
		description: description,
		category:  category,
		isSystem:  false,
		isActive:  true,
		metadata:  map[string]any{},
		createdAt: now,
		updatedAt: now,
	}, nil
}

// ReconstituteFramework creates a Framework from persisted data.
func ReconstituteFramework(
	id shared.ID, tenantID *shared.ID,
	name, slug, version, description string, category FrameworkCategory,
	totalControls int, isSystem, isActive bool, metadata map[string]any,
	createdAt, updatedAt time.Time,
) *Framework {
	return &Framework{
		id: id, tenantID: tenantID, name: name, slug: slug,
		version: version, description: description, category: category,
		totalControls: totalControls, isSystem: isSystem, isActive: isActive,
		metadata: metadata, createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Getters
func (f *Framework) ID() shared.ID             { return f.id }
func (f *Framework) TenantID() *shared.ID      { return f.tenantID }
func (f *Framework) Name() string              { return f.name }
func (f *Framework) Slug() string              { return f.slug }
func (f *Framework) Version() string           { return f.version }
func (f *Framework) Description() string       { return f.description }
func (f *Framework) Category() FrameworkCategory { return f.category }
func (f *Framework) TotalControls() int        { return f.totalControls }
func (f *Framework) IsSystem() bool            { return f.isSystem }
func (f *Framework) IsActive() bool            { return f.isActive }
func (f *Framework) Metadata() map[string]any  { return f.metadata }
func (f *Framework) CreatedAt() time.Time      { return f.createdAt }
func (f *Framework) UpdatedAt() time.Time      { return f.updatedAt }
