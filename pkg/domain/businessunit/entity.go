// Package businessunit provides domain models for business unit management.
package businessunit

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// BusinessUnit represents an organizational unit for risk aggregation.
type BusinessUnit struct {
	id                   shared.ID
	tenantID             shared.ID
	name                 string
	description          string
	ownerName            string
	ownerEmail           string
	assetCount           int
	findingCount         int
	avgRiskScore         float64
	criticalFindingCount int
	tags                 []string
	createdAt            time.Time
	updatedAt            time.Time
}

// NewBusinessUnit creates a new business unit.
func NewBusinessUnit(tenantID shared.ID, name string) (*BusinessUnit, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	now := time.Now()
	return &BusinessUnit{
		id: shared.NewID(), tenantID: tenantID, name: name,
		tags: []string{}, createdAt: now, updatedAt: now,
	}, nil
}

// ReconstituteBusinessUnit creates from persisted data.
func ReconstituteBusinessUnit(
	id, tenantID shared.ID, name, description, ownerName, ownerEmail string,
	assetCount, findingCount int, avgRiskScore float64, criticalFindingCount int,
	tags []string, createdAt, updatedAt time.Time,
) *BusinessUnit {
	return &BusinessUnit{
		id: id, tenantID: tenantID, name: name, description: description,
		ownerName: ownerName, ownerEmail: ownerEmail,
		assetCount: assetCount, findingCount: findingCount,
		avgRiskScore: avgRiskScore, criticalFindingCount: criticalFindingCount,
		tags: tags, createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Getters
func (b *BusinessUnit) ID() shared.ID               { return b.id }
func (b *BusinessUnit) TenantID() shared.ID          { return b.tenantID }
func (b *BusinessUnit) Name() string                 { return b.name }
func (b *BusinessUnit) Description() string           { return b.description }
func (b *BusinessUnit) OwnerName() string             { return b.ownerName }
func (b *BusinessUnit) OwnerEmail() string            { return b.ownerEmail }
func (b *BusinessUnit) AssetCount() int               { return b.assetCount }
func (b *BusinessUnit) FindingCount() int             { return b.findingCount }
func (b *BusinessUnit) AvgRiskScore() float64         { return b.avgRiskScore }
func (b *BusinessUnit) CriticalFindingCount() int     { return b.criticalFindingCount }
func (b *BusinessUnit) Tags() []string                { return b.tags }
func (b *BusinessUnit) CreatedAt() time.Time          { return b.createdAt }
func (b *BusinessUnit) UpdatedAt() time.Time          { return b.updatedAt }

// Update sets mutable fields.
func (b *BusinessUnit) Update(name, description, ownerName, ownerEmail string) {
	if name != "" {
		b.name = name
	}
	b.description = description
	b.ownerName = ownerName
	b.ownerEmail = ownerEmail
	b.updatedAt = time.Now()
}

// SetTags sets tags.
func (b *BusinessUnit) SetTags(tags []string) {
	b.tags = tags
	b.updatedAt = time.Now()
}

// UpdateStats updates cached statistics.
func (b *BusinessUnit) UpdateStats(assetCount, findingCount, criticalCount int, avgRisk float64) {
	b.assetCount = assetCount
	b.findingCount = findingCount
	b.criticalFindingCount = criticalCount
	b.avgRiskScore = avgRisk
	b.updatedAt = time.Now()
}

// Errors
var ErrNotFound = fmt.Errorf("%w: business unit not found", shared.ErrNotFound)

// Filter defines listing criteria.
type Filter struct {
	TenantID *shared.ID
	Search   *string
}

// Repository defines persistence.
type Repository interface {
	Create(ctx context.Context, bu *BusinessUnit) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*BusinessUnit, error)
	Update(ctx context.Context, bu *BusinessUnit) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*BusinessUnit], error)
	// Asset linking
	AddAsset(ctx context.Context, tenantID, buID, assetID shared.ID) error
	RemoveAsset(ctx context.Context, tenantID, buID, assetID shared.ID) error
	ListAssetIDs(ctx context.Context, tenantID, buID shared.ID) ([]shared.ID, error)
}
