package asset

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Value Objects: RelationshipType
// =============================================================================

// RelationshipType represents the type of relationship between assets.
type RelationshipType string

const (
	// Attack Surface Mapping
	RelTypeRunsOn      RelationshipType = "runs_on"
	RelTypeDeployedTo  RelationshipType = "deployed_to"
	RelTypeContains    RelationshipType = "contains"
	RelTypeExposes     RelationshipType = "exposes"
	RelTypeMemberOf    RelationshipType = "member_of"
	RelTypeResolvesTo  RelationshipType = "resolves_to"

	// Attack Path Analysis
	RelTypeDependsOn       RelationshipType = "depends_on"
	RelTypeSendsDataTo     RelationshipType = "sends_data_to"
	RelTypeStoresDataIn    RelationshipType = "stores_data_in"
	RelTypeAuthenticatesTo RelationshipType = "authenticates_to"
	RelTypeGrantedTo       RelationshipType = "granted_to"
	RelTypeLoadBalances    RelationshipType = "load_balances"

	// Control & Ownership
	RelTypeProtectedBy RelationshipType = "protected_by"
	RelTypeMonitors    RelationshipType = "monitors"
	RelTypeManages     RelationshipType = "manages"
	RelTypeOwnedBy     RelationshipType = "owned_by"
)

// AllRelationshipTypes returns all valid relationship types.
func AllRelationshipTypes() []RelationshipType {
	return []RelationshipType{
		// Attack Surface Mapping
		RelTypeRunsOn, RelTypeDeployedTo, RelTypeContains,
		RelTypeExposes, RelTypeMemberOf, RelTypeResolvesTo,
		// Attack Path Analysis
		RelTypeDependsOn, RelTypeSendsDataTo, RelTypeStoresDataIn,
		RelTypeAuthenticatesTo, RelTypeGrantedTo, RelTypeLoadBalances,
		// Control & Ownership
		RelTypeProtectedBy, RelTypeMonitors, RelTypeManages, RelTypeOwnedBy,
	}
}

// IsValid checks if the relationship type is valid.
func (t RelationshipType) IsValid() bool {
	return slices.Contains(AllRelationshipTypes(), t)
}

// String returns the string representation.
func (t RelationshipType) String() string {
	return string(t)
}

// ParseRelationshipType parses a string into a RelationshipType.
func ParseRelationshipType(s string) (RelationshipType, error) {
	t := RelationshipType(strings.ToLower(strings.TrimSpace(s)))
	if !t.IsValid() {
		return "", fmt.Errorf("%w: invalid relationship type: %s", shared.ErrValidation, s)
	}
	return t, nil
}

// =============================================================================
// Value Objects: RelationshipConfidence
// =============================================================================

// RelationshipConfidence represents the confidence level of a relationship.
type RelationshipConfidence string

const (
	ConfidenceHigh   RelationshipConfidence = "high"
	ConfidenceMedium RelationshipConfidence = "medium"
	ConfidenceLow    RelationshipConfidence = "low"
)

// IsValid checks if the confidence level is valid.
func (c RelationshipConfidence) IsValid() bool {
	return c == ConfidenceHigh || c == ConfidenceMedium || c == ConfidenceLow
}

// String returns the string representation.
func (c RelationshipConfidence) String() string {
	return string(c)
}

// ParseRelationshipConfidence parses a string into a RelationshipConfidence.
func ParseRelationshipConfidence(s string) (RelationshipConfidence, error) {
	c := RelationshipConfidence(strings.ToLower(strings.TrimSpace(s)))
	if !c.IsValid() {
		return "", fmt.Errorf("%w: invalid confidence: %s", shared.ErrValidation, s)
	}
	return c, nil
}

// =============================================================================
// Value Objects: DiscoveryMethod
// =============================================================================

// RelationshipDiscoveryMethod represents how a relationship was discovered.
type RelationshipDiscoveryMethod string

const (
	DiscoveryAutomatic RelationshipDiscoveryMethod = "automatic"
	DiscoveryManual    RelationshipDiscoveryMethod = "manual"
	DiscoveryImported  RelationshipDiscoveryMethod = "imported"
	DiscoveryInferred  RelationshipDiscoveryMethod = "inferred"
)

// IsValid checks if the discovery method is valid.
func (d RelationshipDiscoveryMethod) IsValid() bool {
	return d == DiscoveryAutomatic || d == DiscoveryManual || d == DiscoveryImported || d == DiscoveryInferred
}

// String returns the string representation.
func (d RelationshipDiscoveryMethod) String() string {
	return string(d)
}

// ParseRelationshipDiscoveryMethod parses a string into a RelationshipDiscoveryMethod.
func ParseRelationshipDiscoveryMethod(s string) (RelationshipDiscoveryMethod, error) {
	d := RelationshipDiscoveryMethod(strings.ToLower(strings.TrimSpace(s)))
	if !d.IsValid() {
		return "", fmt.Errorf("%w: invalid discovery method: %s", shared.ErrValidation, s)
	}
	return d, nil
}

// =============================================================================
// Entity: Relationship
// =============================================================================

// Relationship represents a directed relationship between two assets.
type Relationship struct {
	id               shared.ID
	tenantID         shared.ID
	sourceAssetID    shared.ID
	targetAssetID    shared.ID
	relationshipType RelationshipType
	description      string
	confidence       RelationshipConfidence
	discoveryMethod  RelationshipDiscoveryMethod
	impactWeight     int
	tags             []string
	lastVerified     *time.Time
	createdAt        time.Time
	updatedAt        time.Time
}

// NewRelationship creates a new Relationship entity with validation.
func NewRelationship(
	tenantID, sourceAssetID, targetAssetID shared.ID,
	relType RelationshipType,
) (*Relationship, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}
	if sourceAssetID.IsZero() {
		return nil, fmt.Errorf("%w: source asset ID is required", shared.ErrValidation)
	}
	if targetAssetID.IsZero() {
		return nil, fmt.Errorf("%w: target asset ID is required", shared.ErrValidation)
	}
	if sourceAssetID == targetAssetID {
		return nil, fmt.Errorf("%w: cannot create self-referential relationship", shared.ErrValidation)
	}
	if !relType.IsValid() {
		return nil, fmt.Errorf("%w: invalid relationship type", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &Relationship{
		id:               shared.NewID(),
		tenantID:         tenantID,
		sourceAssetID:    sourceAssetID,
		targetAssetID:    targetAssetID,
		relationshipType: relType,
		confidence:       ConfidenceMedium,
		discoveryMethod:  DiscoveryManual,
		impactWeight:     5,
		tags:             make([]string, 0),
		createdAt:        now,
		updatedAt:        now,
	}, nil
}

// ReconstituteRelationship recreates a Relationship from persistence (used by repository).
func ReconstituteRelationship(
	id, tenantID, sourceAssetID, targetAssetID shared.ID,
	relType RelationshipType,
	description string,
	confidence RelationshipConfidence,
	discoveryMethod RelationshipDiscoveryMethod,
	impactWeight int,
	tags []string,
	lastVerified *time.Time,
	createdAt, updatedAt time.Time,
) *Relationship {
	if tags == nil {
		tags = make([]string, 0)
	}
	return &Relationship{
		id:               id,
		tenantID:         tenantID,
		sourceAssetID:    sourceAssetID,
		targetAssetID:    targetAssetID,
		relationshipType: relType,
		description:      description,
		confidence:       confidence,
		discoveryMethod:  discoveryMethod,
		impactWeight:     impactWeight,
		tags:             tags,
		lastVerified:     lastVerified,
		createdAt:        createdAt,
		updatedAt:        updatedAt,
	}
}

// =============================================================================
// Getters
// =============================================================================

// ID returns the relationship ID.
func (r *Relationship) ID() shared.ID { return r.id }

// TenantID returns the tenant ID.
func (r *Relationship) TenantID() shared.ID { return r.tenantID }

// SourceAssetID returns the source asset ID.
func (r *Relationship) SourceAssetID() shared.ID { return r.sourceAssetID }

// TargetAssetID returns the target asset ID.
func (r *Relationship) TargetAssetID() shared.ID { return r.targetAssetID }

// Type returns the relationship type.
func (r *Relationship) Type() RelationshipType { return r.relationshipType }

// Description returns the description.
func (r *Relationship) Description() string { return r.description }

// Confidence returns the confidence level.
func (r *Relationship) Confidence() RelationshipConfidence { return r.confidence }

// DiscoveryMethod returns the discovery method.
func (r *Relationship) DiscoveryMethod() RelationshipDiscoveryMethod { return r.discoveryMethod }

// ImpactWeight returns the impact weight.
func (r *Relationship) ImpactWeight() int { return r.impactWeight }

// Tags returns a copy of the tags.
func (r *Relationship) Tags() []string {
	result := make([]string, len(r.tags))
	copy(result, r.tags)
	return result
}

// LastVerified returns when the relationship was last verified.
func (r *Relationship) LastVerified() *time.Time { return r.lastVerified }

// CreatedAt returns the creation timestamp.
func (r *Relationship) CreatedAt() time.Time { return r.createdAt }

// UpdatedAt returns the last update timestamp.
func (r *Relationship) UpdatedAt() time.Time { return r.updatedAt }

// =============================================================================
// Setters (mutators)
// =============================================================================

// SetDescription updates the description.
func (r *Relationship) SetDescription(description string) {
	r.description = description
	r.updatedAt = time.Now().UTC()
}

// SetConfidence updates the confidence level.
func (r *Relationship) SetConfidence(confidence RelationshipConfidence) error {
	if !confidence.IsValid() {
		return fmt.Errorf("%w: invalid confidence", shared.ErrValidation)
	}
	r.confidence = confidence
	r.updatedAt = time.Now().UTC()
	return nil
}

// SetDiscoveryMethod updates the discovery method.
func (r *Relationship) SetDiscoveryMethod(method RelationshipDiscoveryMethod) error {
	if !method.IsValid() {
		return fmt.Errorf("%w: invalid discovery method", shared.ErrValidation)
	}
	r.discoveryMethod = method
	r.updatedAt = time.Now().UTC()
	return nil
}

// SetImpactWeight updates the impact weight.
func (r *Relationship) SetImpactWeight(weight int) error {
	if weight < 1 || weight > 10 {
		return fmt.Errorf("%w: impact weight must be between 1 and 10", shared.ErrValidation)
	}
	r.impactWeight = weight
	r.updatedAt = time.Now().UTC()
	return nil
}

// SetTags replaces all tags.
func (r *Relationship) SetTags(tags []string) {
	if tags == nil {
		tags = make([]string, 0)
	}
	r.tags = tags
	r.updatedAt = time.Now().UTC()
}

// Verify marks the relationship as verified now.
func (r *Relationship) Verify() {
	now := time.Now().UTC()
	r.lastVerified = &now
	r.updatedAt = now
}

// =============================================================================
// Errors
// =============================================================================

// Domain-specific errors for relationship.
var (
	ErrRelationshipNotFound      = fmt.Errorf("relationship %w", shared.ErrNotFound)
	ErrRelationshipAlreadyExists = fmt.Errorf("relationship %w", shared.ErrAlreadyExists)
)

// RelationshipNotFoundError creates a relationship not found error.
func RelationshipNotFoundError(id shared.ID) error {
	return fmt.Errorf("%w: id=%s", ErrRelationshipNotFound, id.String())
}

// RelationshipAlreadyExistsError creates a relationship already exists error.
func RelationshipAlreadyExistsError() error {
	return fmt.Errorf("%w: same source, target, and type", ErrRelationshipAlreadyExists)
}

// =============================================================================
// RelationshipWithAssets (for API responses - avoids N+1)
// =============================================================================

// RelationshipWithAssets includes joined asset data for API responses.
type RelationshipWithAssets struct {
	*Relationship
	SourceAssetName string
	SourceAssetType AssetType
	TargetAssetName string
	TargetAssetType AssetType
}
