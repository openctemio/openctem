package asset

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Asset State History Entity
// =============================================================================

// AssetStateChange represents a tracked change in asset state.
// Used for audit logging, compliance tracking, and shadow IT detection.
// Records are stored in the `asset_state_history` table (append-only).
type AssetStateChange struct {
	id       shared.ID
	tenantID shared.ID
	assetID  shared.ID

	// What changed
	changeType StateChangeType
	field      string // Which field changed (optional, for field-level changes)
	oldValue   string
	newValue   string

	// Context
	reason   string       // Why the change occurred
	source   ChangeSource // What triggered: scan, manual, integration, system
	metadata string       // Optional JSON metadata for additional context

	// Audit
	changedBy *shared.ID // User ID if manual change
	changedAt time.Time
	createdAt time.Time // When record was created (immutable)
}

// =============================================================================
// Constructors
// =============================================================================

// NewAssetStateChange creates a new state change record.
func NewAssetStateChange(
	tenantID, assetID shared.ID,
	changeType StateChangeType,
	source ChangeSource,
) (*AssetStateChange, error) {
	if !changeType.IsValid() {
		return nil, fmt.Errorf("%w: invalid change type", shared.ErrValidation)
	}
	if source != "" && !source.IsValid() {
		return nil, fmt.Errorf("%w: invalid source", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &AssetStateChange{
		id:         shared.NewID(),
		tenantID:   tenantID,
		assetID:    assetID,
		changeType: changeType,
		source:     source,
		changedAt:  now,
		createdAt:  now,
	}, nil
}

// RecordAssetAppeared creates a state change for a newly discovered asset.
func RecordAssetAppeared(tenantID, assetID shared.ID, source ChangeSource, reason string) *AssetStateChange {
	now := time.Now().UTC()
	return &AssetStateChange{
		id:         shared.NewID(),
		tenantID:   tenantID,
		assetID:    assetID,
		changeType: StateChangeAppeared,
		source:     source,
		reason:     reason,
		changedAt:  now,
		createdAt:  now,
	}
}

// RecordAssetDisappeared creates a state change for an asset that's no longer seen.
func RecordAssetDisappeared(tenantID, assetID shared.ID, source ChangeSource, reason string) *AssetStateChange {
	now := time.Now().UTC()
	return &AssetStateChange{
		id:         shared.NewID(),
		tenantID:   tenantID,
		assetID:    assetID,
		changeType: StateChangeDisappeared,
		source:     source,
		reason:     reason,
		changedAt:  now,
		createdAt:  now,
	}
}

// RecordAssetRecovered creates a state change for an asset that reappeared.
func RecordAssetRecovered(tenantID, assetID shared.ID, source ChangeSource, reason string) *AssetStateChange {
	now := time.Now().UTC()
	return &AssetStateChange{
		id:         shared.NewID(),
		tenantID:   tenantID,
		assetID:    assetID,
		changeType: StateChangeRecovered,
		source:     source,
		reason:     reason,
		changedAt:  now,
		createdAt:  now,
	}
}

// RecordFieldChange creates a state change for a specific field change.
func RecordFieldChange(
	tenantID, assetID shared.ID,
	changeType StateChangeType,
	field, oldValue, newValue string,
	source ChangeSource,
	changedBy *shared.ID,
) *AssetStateChange {
	now := time.Now().UTC()
	return &AssetStateChange{
		id:         shared.NewID(),
		tenantID:   tenantID,
		assetID:    assetID,
		changeType: changeType,
		field:      field,
		oldValue:   oldValue,
		newValue:   newValue,
		source:     source,
		changedBy:  changedBy,
		changedAt:  now,
		createdAt:  now,
	}
}

// ReconstituteStateChange recreates a state change from persistence.
func ReconstituteStateChange(
	id, tenantID, assetID shared.ID,
	changeType StateChangeType,
	field, oldValue, newValue, reason, metadata string,
	source ChangeSource,
	changedBy *shared.ID,
	changedAt, createdAt time.Time,
) *AssetStateChange {
	return &AssetStateChange{
		id:         id,
		tenantID:   tenantID,
		assetID:    assetID,
		changeType: changeType,
		field:      field,
		oldValue:   oldValue,
		newValue:   newValue,
		reason:     reason,
		metadata:   metadata,
		source:     source,
		changedBy:  changedBy,
		changedAt:  changedAt,
		createdAt:  createdAt,
	}
}

// =============================================================================
// Getters
// =============================================================================

func (s *AssetStateChange) ID() shared.ID               { return s.id }
func (s *AssetStateChange) TenantID() shared.ID         { return s.tenantID }
func (s *AssetStateChange) AssetID() shared.ID          { return s.assetID }
func (s *AssetStateChange) ChangeType() StateChangeType { return s.changeType }
func (s *AssetStateChange) Field() string               { return s.field }
func (s *AssetStateChange) OldValue() string            { return s.oldValue }
func (s *AssetStateChange) NewValue() string            { return s.newValue }
func (s *AssetStateChange) Reason() string              { return s.reason }
func (s *AssetStateChange) Metadata() string            { return s.metadata }
func (s *AssetStateChange) Source() ChangeSource        { return s.source }
func (s *AssetStateChange) ChangedBy() *shared.ID       { return s.changedBy }
func (s *AssetStateChange) ChangedAt() time.Time        { return s.changedAt }
func (s *AssetStateChange) CreatedAt() time.Time        { return s.createdAt }

// =============================================================================
// Setters (limited - state history is mostly append-only)
// =============================================================================

// SetReason sets the reason for the change.
func (s *AssetStateChange) SetReason(reason string) {
	s.reason = reason
}

// SetChangedBy sets the user who made the change.
func (s *AssetStateChange) SetChangedBy(userID *shared.ID) {
	s.changedBy = userID
}

// SetFieldChange sets the field-level change details.
func (s *AssetStateChange) SetFieldChange(field, oldValue, newValue string) {
	s.field = field
	s.oldValue = oldValue
	s.newValue = newValue
}

// SetMetadata sets optional JSON metadata.
func (s *AssetStateChange) SetMetadata(metadata string) {
	s.metadata = metadata
}

// =============================================================================
// Business Logic
// =============================================================================

// IsLifecycleChange returns true if this is an asset lifecycle event.
func (s *AssetStateChange) IsLifecycleChange() bool {
	return s.changeType == StateChangeAppeared ||
		s.changeType == StateChangeDisappeared ||
		s.changeType == StateChangeRecovered
}

// IsExposureChange returns true if this is an exposure-related change.
func (s *AssetStateChange) IsExposureChange() bool {
	return s.changeType == StateChangeExposureChanged ||
		s.changeType == StateChangeInternetExposureChanged
}

// IsComplianceChange returns true if this is a compliance-related change.
func (s *AssetStateChange) IsComplianceChange() bool {
	return s.changeType == StateChangeComplianceChanged ||
		s.changeType == StateChangeClassificationChanged ||
		s.changeType == StateChangeOwnerChanged
}

// IsManualChange returns true if this change was made by a user.
func (s *AssetStateChange) IsManualChange() bool {
	return s.source == ChangeSourceManual && s.changedBy != nil
}

// IsAutomatedChange returns true if this change was automated.
func (s *AssetStateChange) IsAutomatedChange() bool {
	return s.source == ChangeSourceScan ||
		s.source == ChangeSourceIntegration ||
		s.source == ChangeSourceSystem ||
		s.source == ChangeSourceAgent
}

// =============================================================================
// Value Objects
// =============================================================================

// StateChangeType represents the type of state change.
type StateChangeType string

const (
	// Lifecycle changes
	StateChangeAppeared    StateChangeType = "appeared"    // New asset discovered
	StateChangeDisappeared StateChangeType = "disappeared" // Asset no longer seen
	StateChangeRecovered   StateChangeType = "recovered"   // Asset seen again after disappearing

	// Property changes
	StateChangeExposureChanged         StateChangeType = "exposure_changed"          // Exposure level changed
	StateChangeInternetExposureChanged StateChangeType = "internet_exposure_changed" // Internet accessibility changed
	StateChangeStatusChanged           StateChangeType = "status_changed"            // Status changed (active/inactive/archived)
	StateChangeCriticalityChanged      StateChangeType = "criticality_changed"       // Criticality level changed
	StateChangeOwnerChanged            StateChangeType = "owner_changed"             // Owner changed
	StateChangeComplianceChanged       StateChangeType = "compliance_changed"        // Compliance scope changed
	StateChangeClassificationChanged   StateChangeType = "classification_changed"    // Data classification changed
)

// AllStateChangeTypes returns all valid state change types.
func AllStateChangeTypes() []StateChangeType {
	return []StateChangeType{
		StateChangeAppeared,
		StateChangeDisappeared,
		StateChangeRecovered,
		StateChangeExposureChanged,
		StateChangeInternetExposureChanged,
		StateChangeStatusChanged,
		StateChangeCriticalityChanged,
		StateChangeOwnerChanged,
		StateChangeComplianceChanged,
		StateChangeClassificationChanged,
	}
}

func (t StateChangeType) IsValid() bool {
	for _, valid := range AllStateChangeTypes() {
		if t == valid {
			return true
		}
	}
	return false
}

func (t StateChangeType) String() string {
	return string(t)
}

// Description returns a human-readable description of the change type.
func (t StateChangeType) Description() string {
	descriptions := map[StateChangeType]string{
		StateChangeAppeared:                "Asset discovered",
		StateChangeDisappeared:             "Asset no longer detected",
		StateChangeRecovered:               "Asset reappeared",
		StateChangeExposureChanged:         "Exposure level changed",
		StateChangeInternetExposureChanged: "Internet accessibility changed",
		StateChangeStatusChanged:           "Status changed",
		StateChangeCriticalityChanged:      "Criticality level changed",
		StateChangeOwnerChanged:            "Owner changed",
		StateChangeComplianceChanged:       "Compliance scope changed",
		StateChangeClassificationChanged:   "Data classification changed",
	}
	if desc, ok := descriptions[t]; ok {
		return desc
	}
	return string(t)
}

// ChangeSource represents the source of the change.
type ChangeSource string

const (
	ChangeSourceScan        ChangeSource = "scan"        // From vulnerability/port scan
	ChangeSourceManual      ChangeSource = "manual"      // Manual user action
	ChangeSourceIntegration ChangeSource = "integration" // From external integration (GitHub, AWS, etc.)
	ChangeSourceSystem      ChangeSource = "system"      // System-generated (e.g., auto-archive)
	ChangeSourceAgent       ChangeSource = "agent"       // From platform agent
	ChangeSourceAPI         ChangeSource = "api"         // From API call
)

// AllChangeSources returns all valid change sources.
func AllChangeSources() []ChangeSource {
	return []ChangeSource{
		ChangeSourceScan,
		ChangeSourceManual,
		ChangeSourceIntegration,
		ChangeSourceSystem,
		ChangeSourceAgent,
		ChangeSourceAPI,
	}
}

func (s ChangeSource) IsValid() bool {
	for _, valid := range AllChangeSources() {
		if s == valid {
			return true
		}
	}
	return false
}

func (s ChangeSource) String() string {
	return string(s)
}

// =============================================================================
// List Options
// =============================================================================

// ListStateHistoryOptions contains options for listing state history.
type ListStateHistoryOptions struct {
	AssetID     *shared.ID
	ChangeType  *StateChangeType  // Single filter for simpler API
	ChangeTypes []StateChangeType // Multiple filters
	Source      *ChangeSource     // Single filter for simpler API
	Sources     []ChangeSource    // Multiple filters
	ChangedBy   *shared.ID
	From        *time.Time
	To          *time.Time

	// Pagination
	Limit  int
	Offset int

	// Sorting (default: changed_at DESC)
	SortOrder string // asc, desc
}

// DefaultListStateHistoryOptions returns default options.
func DefaultListStateHistoryOptions() ListStateHistoryOptions {
	return ListStateHistoryOptions{
		Limit:     50,
		Offset:    0,
		SortOrder: "desc",
	}
}

// WithAssetID filters by asset ID.
func (o ListStateHistoryOptions) WithAssetID(assetID shared.ID) ListStateHistoryOptions {
	o.AssetID = &assetID
	return o
}

// WithChangeTypes filters by change types.
func (o ListStateHistoryOptions) WithChangeTypes(types ...StateChangeType) ListStateHistoryOptions {
	o.ChangeTypes = types
	return o
}

// WithSources filters by change sources.
func (o ListStateHistoryOptions) WithSources(sources ...ChangeSource) ListStateHistoryOptions {
	o.Sources = sources
	return o
}

// WithTimeRange filters by time range.
func (o ListStateHistoryOptions) WithTimeRange(from, to *time.Time) ListStateHistoryOptions {
	o.From = from
	o.To = to
	return o
}

// LifecycleChanges returns options for lifecycle changes only.
func LifecycleChangesOptions() ListStateHistoryOptions {
	return ListStateHistoryOptions{
		ChangeTypes: []StateChangeType{
			StateChangeAppeared,
			StateChangeDisappeared,
			StateChangeRecovered,
		},
		Limit:     50,
		SortOrder: "desc",
	}
}

// ExposureChangesOptions returns options for exposure changes only.
func ExposureChangesOptions() ListStateHistoryOptions {
	return ListStateHistoryOptions{
		ChangeTypes: []StateChangeType{
			StateChangeExposureChanged,
			StateChangeInternetExposureChanged,
		},
		Limit:     50,
		SortOrder: "desc",
	}
}

// ComplianceChangesOptions returns options for compliance changes only.
func ComplianceChangesOptions() ListStateHistoryOptions {
	return ListStateHistoryOptions{
		ChangeTypes: []StateChangeType{
			StateChangeComplianceChanged,
			StateChangeClassificationChanged,
			StateChangeOwnerChanged,
		},
		Limit:     50,
		SortOrder: "desc",
	}
}
