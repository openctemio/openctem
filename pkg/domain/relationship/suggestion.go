// Package relationship provides domain entities for relationship suggestions.
package relationship

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Suggestion status constants.
const (
	SuggestionPending   = "pending"
	SuggestionApproved  = "approved"
	SuggestionDismissed = "dismissed"
)

// Suggestion represents a suggested relationship between two assets.
type Suggestion struct {
	id               shared.ID
	tenantID         shared.ID
	sourceAssetID    shared.ID
	targetAssetID    shared.ID
	relationshipType string
	reason           string
	confidence       float64
	status           string
	reviewedBy       *shared.ID
	reviewedAt       *time.Time
	createdAt        time.Time
	// Enrichment fields (populated by JOINs, not stored)
	sourceAssetName string
	sourceAssetType string
	targetAssetName string
	targetAssetType string
}

// NewSuggestion creates a new Suggestion with validation.
func NewSuggestion(
	tenantID, sourceAssetID, targetAssetID shared.ID,
	relType, reason string,
	confidence float64,
) (*Suggestion, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}
	if sourceAssetID.IsZero() {
		return nil, fmt.Errorf("%w: source asset ID is required", shared.ErrValidation)
	}
	if targetAssetID.IsZero() {
		return nil, fmt.Errorf("%w: target asset ID is required", shared.ErrValidation)
	}
	if relType == "" {
		return nil, fmt.Errorf("%w: relationship type is required", shared.ErrValidation)
	}
	if reason == "" {
		return nil, fmt.Errorf("%w: reason is required", shared.ErrValidation)
	}
	if confidence < 0 || confidence > 1 {
		return nil, fmt.Errorf("%w: confidence must be between 0 and 1", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &Suggestion{
		id:               shared.NewID(),
		tenantID:         tenantID,
		sourceAssetID:    sourceAssetID,
		targetAssetID:    targetAssetID,
		relationshipType: relType,
		reason:           reason,
		confidence:       confidence,
		status:           SuggestionPending,
		createdAt:        now,
	}, nil
}

// ReconstituteSuggestion rebuilds a Suggestion from persistence.
func ReconstituteSuggestion(
	id, tenantID, sourceAssetID, targetAssetID shared.ID,
	relType, reason string,
	confidence float64,
	status string,
	reviewedBy *shared.ID,
	reviewedAt *time.Time,
	createdAt time.Time,
) *Suggestion {
	return &Suggestion{
		id:               id,
		tenantID:         tenantID,
		sourceAssetID:    sourceAssetID,
		targetAssetID:    targetAssetID,
		relationshipType: relType,
		reason:           reason,
		confidence:       confidence,
		status:           status,
		reviewedBy:       reviewedBy,
		reviewedAt:       reviewedAt,
		createdAt:        createdAt,
	}
}

// Approve marks the suggestion as approved.
func (s *Suggestion) Approve(reviewerID shared.ID) {
	s.status = SuggestionApproved
	s.reviewedBy = &reviewerID
	now := time.Now().UTC()
	s.reviewedAt = &now
}

// Dismiss marks the suggestion as dismissed.
func (s *Suggestion) Dismiss(reviewerID shared.ID) {
	s.status = SuggestionDismissed
	s.reviewedBy = &reviewerID
	now := time.Now().UTC()
	s.reviewedAt = &now
}

// Accessors.

func (s *Suggestion) ID() shared.ID            { return s.id }
func (s *Suggestion) TenantID() shared.ID      { return s.tenantID }
func (s *Suggestion) SourceAssetID() shared.ID { return s.sourceAssetID }
func (s *Suggestion) TargetAssetID() shared.ID { return s.targetAssetID }
func (s *Suggestion) RelationshipType() string { return s.relationshipType }
func (s *Suggestion) Reason() string           { return s.reason }
func (s *Suggestion) Confidence() float64      { return s.confidence }
func (s *Suggestion) Status() string           { return s.status }
func (s *Suggestion) ReviewedBy() *shared.ID   { return s.reviewedBy }
func (s *Suggestion) ReviewedAt() *time.Time   { return s.reviewedAt }
func (s *Suggestion) CreatedAt() time.Time     { return s.createdAt }
func (s *Suggestion) SourceAssetName() string  { return s.sourceAssetName }
func (s *Suggestion) SourceAssetType() string  { return s.sourceAssetType }
func (s *Suggestion) TargetAssetName() string  { return s.targetAssetName }
func (s *Suggestion) TargetAssetType() string  { return s.targetAssetType }

// SetAssetInfo sets enrichment fields (called by repository after JOIN).
func (s *Suggestion) SetAssetInfo(srcName, srcType, tgtName, tgtType string) {
	s.sourceAssetName = srcName
	s.sourceAssetType = srcType
	s.targetAssetName = tgtName
	s.targetAssetType = tgtType
}

// SuggestionRepository defines the persistence interface for suggestions.
type SuggestionRepository interface {
	Create(ctx context.Context, s *Suggestion) error
	CreateBatch(ctx context.Context, suggestions []*Suggestion) (int, error)
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Suggestion, error)
	ListPending(ctx context.Context, tenantID shared.ID, search string, page pagination.Pagination) (pagination.Result[*Suggestion], error)
	UpdateStatus(ctx context.Context, s *Suggestion) error
	CountPending(ctx context.Context, tenantID shared.ID) (int64, error)
	DeleteByAssetID(ctx context.Context, tenantID, assetID shared.ID) error
	DeletePending(ctx context.Context, tenantID shared.ID) error
	ApproveAll(ctx context.Context, tenantID, reviewerID shared.ID) ([]*Suggestion, error)
}

// Errors.
var (
	ErrSuggestionNotFound = fmt.Errorf("%w: suggestion not found", shared.ErrNotFound)
)
