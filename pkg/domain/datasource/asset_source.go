package datasource

import (
	"maps"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetSource represents the relationship between an asset and a data source.
// It tracks when and how a source discovered/reported an asset, and what data
// the source contributed.
type AssetSource struct {
	// Identity
	id      shared.ID
	assetID shared.ID

	// Source reference
	sourceType SourceType
	sourceID   *shared.ID // nil for manual sources

	// Timing
	firstSeenAt time.Time
	lastSeenAt  time.Time

	// Source-specific data
	sourceRef       string         // External reference (scan ID, job ID)
	contributedData map[string]any // Data this source contributed

	// Quality indicators
	confidence int  // 0-100
	isPrimary  bool // Is this the authoritative source?
	seenCount  int  // How many times this source reported this asset

	// Timestamps
	createdAt time.Time
	updatedAt time.Time
}

// NewAssetSource creates a new asset source record.
func NewAssetSource(
	assetID shared.ID,
	sourceType SourceType,
	sourceID *shared.ID,
) (*AssetSource, error) {
	if assetID.IsZero() {
		return nil, ValidationError("asset ID is required")
	}
	if !sourceType.IsValid() {
		return nil, ErrInvalidSourceType
	}

	now := time.Now()
	return &AssetSource{
		id:              shared.NewID(),
		assetID:         assetID,
		sourceType:      sourceType,
		sourceID:        sourceID,
		firstSeenAt:     now,
		lastSeenAt:      now,
		contributedData: make(map[string]any),
		confidence:      100, // Default confidence
		isPrimary:       false,
		seenCount:       1,
		createdAt:       now,
		updatedAt:       now,
	}, nil
}

// ReconstructAssetSource creates an AssetSource from stored data (used by repository).
func ReconstructAssetSource(
	id shared.ID,
	assetID shared.ID,
	sourceType SourceType,
	sourceID *shared.ID,
	firstSeenAt time.Time,
	lastSeenAt time.Time,
	sourceRef string,
	contributedData map[string]any,
	confidence int,
	isPrimary bool,
	seenCount int,
	createdAt time.Time,
	updatedAt time.Time,
) *AssetSource {
	if contributedData == nil {
		contributedData = make(map[string]any)
	}

	return &AssetSource{
		id:              id,
		assetID:         assetID,
		sourceType:      sourceType,
		sourceID:        sourceID,
		firstSeenAt:     firstSeenAt,
		lastSeenAt:      lastSeenAt,
		sourceRef:       sourceRef,
		contributedData: contributedData,
		confidence:      confidence,
		isPrimary:       isPrimary,
		seenCount:       seenCount,
		createdAt:       createdAt,
		updatedAt:       updatedAt,
	}
}

// =============================================================================
// Getters
// =============================================================================

func (as *AssetSource) ID() shared.ID                   { return as.id }
func (as *AssetSource) AssetID() shared.ID              { return as.assetID }
func (as *AssetSource) SourceType() SourceType          { return as.sourceType }
func (as *AssetSource) SourceID() *shared.ID            { return as.sourceID }
func (as *AssetSource) FirstSeenAt() time.Time          { return as.firstSeenAt }
func (as *AssetSource) LastSeenAt() time.Time           { return as.lastSeenAt }
func (as *AssetSource) SourceRef() string               { return as.sourceRef }
func (as *AssetSource) ContributedData() map[string]any { return as.contributedData }
func (as *AssetSource) Confidence() int                 { return as.confidence }
func (as *AssetSource) IsPrimary() bool                 { return as.isPrimary }
func (as *AssetSource) SeenCount() int                  { return as.seenCount }
func (as *AssetSource) CreatedAt() time.Time            { return as.createdAt }
func (as *AssetSource) UpdatedAt() time.Time            { return as.updatedAt }

// =============================================================================
// Setters / Mutations
// =============================================================================

// SetSourceRef sets the source reference.
func (as *AssetSource) SetSourceRef(ref string) {
	as.sourceRef = ref
	as.updatedAt = time.Now()
}

// SetContributedData sets the contributed data.
func (as *AssetSource) SetContributedData(data map[string]any) {
	if data == nil {
		data = make(map[string]any)
	}
	as.contributedData = data
	as.updatedAt = time.Now()
}

// MergeContributedData merges new data into the existing contributed data.
func (as *AssetSource) MergeContributedData(data map[string]any) {
	if data == nil {
		return
	}
	maps.Copy(as.contributedData, data)
	as.updatedAt = time.Now()
}

// SetConfidence sets the confidence score.
func (as *AssetSource) SetConfidence(confidence int) {
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	as.confidence = confidence
	as.updatedAt = time.Now()
}

// SetPrimary sets whether this is the primary source.
func (as *AssetSource) SetPrimary(primary bool) {
	as.isPrimary = primary
	as.updatedAt = time.Now()
}

// =============================================================================
// Business Logic
// =============================================================================

// RecordSighting records that this source has seen the asset again.
// Updates last_seen_at and increments seen_count.
func (as *AssetSource) RecordSighting() {
	as.lastSeenAt = time.Now()
	as.seenCount++
	as.updatedAt = as.lastSeenAt
}

// RecordSightingWithData records a sighting with new contributed data.
func (as *AssetSource) RecordSightingWithData(data map[string]any, sourceRef string) {
	as.lastSeenAt = time.Now()
	as.seenCount++
	if sourceRef != "" {
		as.sourceRef = sourceRef
	}
	as.MergeContributedData(data)
	as.updatedAt = as.lastSeenAt
}

// DaysSinceLastSeen returns the number of days since this source last saw the asset.
func (as *AssetSource) DaysSinceLastSeen() int {
	return int(time.Since(as.lastSeenAt).Hours() / 24)
}

// IsStale returns true if the source hasn't seen the asset recently.
func (as *AssetSource) IsStale(threshold time.Duration) bool {
	return time.Since(as.lastSeenAt) > threshold
}

// =============================================================================
// Summary Types
// =============================================================================

// AssetSourceSummary is a lightweight summary of an asset source for API responses.
type AssetSourceSummary struct {
	SourceType      SourceType     `json:"source_type"`
	SourceID        *string        `json:"source_id,omitempty"`
	SourceName      string         `json:"source_name,omitempty"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	SourceRef       string         `json:"source_ref,omitempty"`
	ContributedData map[string]any `json:"contributed_data,omitempty"`
	Confidence      int            `json:"confidence"`
	IsPrimary       bool           `json:"is_primary"`
	SeenCount       int            `json:"seen_count"`
}

// ToSummary converts an AssetSource to a summary (source name must be provided externally).
func (as *AssetSource) ToSummary(sourceName string) AssetSourceSummary {
	var sourceIDStr *string
	if as.sourceID != nil {
		s := as.sourceID.String()
		sourceIDStr = &s
	}

	return AssetSourceSummary{
		SourceType:      as.sourceType,
		SourceID:        sourceIDStr,
		SourceName:      sourceName,
		FirstSeenAt:     as.firstSeenAt,
		LastSeenAt:      as.lastSeenAt,
		SourceRef:       as.sourceRef,
		ContributedData: as.contributedData,
		Confidence:      as.confidence,
		IsPrimary:       as.isPrimary,
		SeenCount:       as.seenCount,
	}
}
