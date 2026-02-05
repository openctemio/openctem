package datasource

import (
	"maps"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// FindingDataSource represents the relationship between a finding and a data source.
// It tracks when and how a source discovered/reported a finding, and what data
// the source contributed. This is separate from vulnerability.FindingSource which
// is an enum representing the scan type (sast, dast, etc.).
type FindingDataSource struct {
	// Identity
	id        shared.ID
	findingID shared.ID

	// Source reference
	sourceType SourceType
	sourceID   *shared.ID // nil for manual sources

	// Timing
	firstSeenAt time.Time
	lastSeenAt  time.Time

	// Source-specific data
	sourceRef       string         // External reference (scan ID, job ID)
	scanID          string         // Scan identifier from the source
	contributedData map[string]any // Data this source contributed

	// Quality indicators
	confidence int  // 0-100
	isPrimary  bool // Is this the authoritative source?
	seenCount  int  // How many times this source reported this finding

	// Timestamps
	createdAt time.Time
	updatedAt time.Time
}

// NewFindingDataSource creates a new finding data source record.
func NewFindingDataSource(
	findingID shared.ID,
	sourceType SourceType,
	sourceID *shared.ID,
) (*FindingDataSource, error) {
	if findingID.IsZero() {
		return nil, ValidationError("finding ID is required")
	}
	if !sourceType.IsValid() {
		return nil, ErrInvalidSourceType
	}

	now := time.Now()
	return &FindingDataSource{
		id:              shared.NewID(),
		findingID:       findingID,
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

// ReconstructFindingDataSource creates a FindingDataSource from stored data (used by repository).
func ReconstructFindingDataSource(
	id shared.ID,
	findingID shared.ID,
	sourceType SourceType,
	sourceID *shared.ID,
	firstSeenAt time.Time,
	lastSeenAt time.Time,
	sourceRef string,
	scanID string,
	contributedData map[string]any,
	confidence int,
	isPrimary bool,
	seenCount int,
	createdAt time.Time,
	updatedAt time.Time,
) *FindingDataSource {
	if contributedData == nil {
		contributedData = make(map[string]any)
	}

	return &FindingDataSource{
		id:              id,
		findingID:       findingID,
		sourceType:      sourceType,
		sourceID:        sourceID,
		firstSeenAt:     firstSeenAt,
		lastSeenAt:      lastSeenAt,
		sourceRef:       sourceRef,
		scanID:          scanID,
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

func (fs *FindingDataSource) ID() shared.ID                   { return fs.id }
func (fs *FindingDataSource) FindingID() shared.ID            { return fs.findingID }
func (fs *FindingDataSource) SourceType() SourceType          { return fs.sourceType }
func (fs *FindingDataSource) SourceID() *shared.ID            { return fs.sourceID }
func (fs *FindingDataSource) FirstSeenAt() time.Time          { return fs.firstSeenAt }
func (fs *FindingDataSource) LastSeenAt() time.Time           { return fs.lastSeenAt }
func (fs *FindingDataSource) SourceRef() string               { return fs.sourceRef }
func (fs *FindingDataSource) ScanID() string                  { return fs.scanID }
func (fs *FindingDataSource) ContributedData() map[string]any { return fs.contributedData }
func (fs *FindingDataSource) Confidence() int                 { return fs.confidence }
func (fs *FindingDataSource) IsPrimary() bool                 { return fs.isPrimary }
func (fs *FindingDataSource) SeenCount() int                  { return fs.seenCount }
func (fs *FindingDataSource) CreatedAt() time.Time            { return fs.createdAt }
func (fs *FindingDataSource) UpdatedAt() time.Time            { return fs.updatedAt }

// =============================================================================
// Setters / Mutations
// =============================================================================

// SetSourceRef sets the source reference.
func (fs *FindingDataSource) SetSourceRef(ref string) {
	fs.sourceRef = ref
	fs.updatedAt = time.Now()
}

// SetScanID sets the scan ID.
func (fs *FindingDataSource) SetScanID(scanID string) {
	fs.scanID = scanID
	fs.updatedAt = time.Now()
}

// SetContributedData sets the contributed data.
func (fs *FindingDataSource) SetContributedData(data map[string]any) {
	if data == nil {
		data = make(map[string]any)
	}
	fs.contributedData = data
	fs.updatedAt = time.Now()
}

// MergeContributedData merges new data into the existing contributed data.
func (fs *FindingDataSource) MergeContributedData(data map[string]any) {
	if data == nil {
		return
	}
	maps.Copy(fs.contributedData, data)
	fs.updatedAt = time.Now()
}

// SetConfidence sets the confidence score.
func (fs *FindingDataSource) SetConfidence(confidence int) {
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	fs.confidence = confidence
	fs.updatedAt = time.Now()
}

// SetPrimary sets whether this is the primary source.
func (fs *FindingDataSource) SetPrimary(primary bool) {
	fs.isPrimary = primary
	fs.updatedAt = time.Now()
}

// =============================================================================
// Business Logic
// =============================================================================

// RecordSighting records that this source has seen the finding again.
// Updates last_seen_at and increments seen_count.
func (fs *FindingDataSource) RecordSighting() {
	fs.lastSeenAt = time.Now()
	fs.seenCount++
	fs.updatedAt = fs.lastSeenAt
}

// RecordSightingWithData records a sighting with new contributed data.
func (fs *FindingDataSource) RecordSightingWithData(data map[string]any, sourceRef, scanID string) {
	fs.lastSeenAt = time.Now()
	fs.seenCount++
	if sourceRef != "" {
		fs.sourceRef = sourceRef
	}
	if scanID != "" {
		fs.scanID = scanID
	}
	fs.MergeContributedData(data)
	fs.updatedAt = fs.lastSeenAt
}

// DaysSinceLastSeen returns the number of days since this source last saw the finding.
func (fs *FindingDataSource) DaysSinceLastSeen() int {
	return int(time.Since(fs.lastSeenAt).Hours() / 24)
}

// IsStale returns true if the source hasn't seen the finding recently.
func (fs *FindingDataSource) IsStale(threshold time.Duration) bool {
	return time.Since(fs.lastSeenAt) > threshold
}

// =============================================================================
// Summary Types
// =============================================================================

// FindingDataSourceSummary is a lightweight summary for API responses.
type FindingDataSourceSummary struct {
	SourceType      SourceType     `json:"source_type"`
	SourceID        *string        `json:"source_id,omitempty"`
	SourceName      string         `json:"source_name,omitempty"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	SourceRef       string         `json:"source_ref,omitempty"`
	ScanID          string         `json:"scan_id,omitempty"`
	ContributedData map[string]any `json:"contributed_data,omitempty"`
	Confidence      int            `json:"confidence"`
	IsPrimary       bool           `json:"is_primary"`
	SeenCount       int            `json:"seen_count"`
}

// ToSummary converts a FindingDataSource to a summary (source name must be provided externally).
func (fs *FindingDataSource) ToSummary(sourceName string) FindingDataSourceSummary {
	var sourceIDStr *string
	if fs.sourceID != nil {
		s := fs.sourceID.String()
		sourceIDStr = &s
	}

	return FindingDataSourceSummary{
		SourceType:      fs.sourceType,
		SourceID:        sourceIDStr,
		SourceName:      sourceName,
		FirstSeenAt:     fs.firstSeenAt,
		LastSeenAt:      fs.lastSeenAt,
		SourceRef:       fs.sourceRef,
		ScanID:          fs.scanID,
		ContributedData: fs.contributedData,
		Confidence:      fs.confidence,
		IsPrimary:       fs.isPrimary,
		SeenCount:       fs.seenCount,
	}
}
