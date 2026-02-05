package exposure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ExposureEvent represents an attack surface change that is NOT a vulnerability.
// Examples: open ports, public buckets, exposed APIs, certificate expiry, etc.
type ExposureEvent struct {
	id       shared.ID
	tenantID shared.ID

	assetID         *shared.ID
	eventType       EventType
	severity        Severity
	state           State
	title           string
	description     string
	details         map[string]any
	fingerprint     string
	source          string
	firstSeenAt     time.Time
	lastSeenAt      time.Time
	resolvedAt      *time.Time
	resolvedBy      *shared.ID
	resolutionNotes string
	createdAt       time.Time
	updatedAt       time.Time
}

// NewExposureEvent creates a new ExposureEvent.
func NewExposureEvent(
	tenantID shared.ID,
	eventType EventType,
	severity Severity,
	title string,
	source string,
	details map[string]any,
) (*ExposureEvent, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}
	if !eventType.IsValid() {
		return nil, fmt.Errorf("%w: invalid event type", shared.ErrValidation)
	}
	if !severity.IsValid() {
		return nil, fmt.Errorf("%w: invalid severity", shared.ErrValidation)
	}
	if title == "" {
		return nil, fmt.Errorf("%w: title is required", shared.ErrValidation)
	}
	if source == "" {
		return nil, fmt.Errorf("%w: source is required", shared.ErrValidation)
	}

	if details == nil {
		details = make(map[string]any)
	}

	now := time.Now().UTC()
	event := &ExposureEvent{
		id:          shared.NewID(),
		tenantID:    tenantID,
		eventType:   eventType,
		severity:    severity,
		state:       StateActive,
		title:       title,
		details:     details,
		source:      source,
		firstSeenAt: now,
		lastSeenAt:  now,
		createdAt:   now,
		updatedAt:   now,
	}

	// Generate fingerprint
	event.fingerprint = event.generateFingerprint()

	return event, nil
}

// Reconstitute recreates an ExposureEvent from persistence.
func Reconstitute(
	id shared.ID,
	tenantID shared.ID,

	assetID *shared.ID,
	eventType EventType,
	severity Severity,
	state State,
	title string,
	description string,
	details map[string]any,
	fingerprint string,
	source string,
	firstSeenAt, lastSeenAt time.Time,
	resolvedAt *time.Time,
	resolvedBy *shared.ID,
	resolutionNotes string,
	createdAt, updatedAt time.Time,
) *ExposureEvent {
	if details == nil {
		details = make(map[string]any)
	}
	return &ExposureEvent{
		id:       id,
		tenantID: tenantID,

		assetID:         assetID,
		eventType:       eventType,
		severity:        severity,
		state:           state,
		title:           title,
		description:     description,
		details:         details,
		fingerprint:     fingerprint,
		source:          source,
		firstSeenAt:     firstSeenAt,
		lastSeenAt:      lastSeenAt,
		resolvedAt:      resolvedAt,
		resolvedBy:      resolvedBy,
		resolutionNotes: resolutionNotes,
		createdAt:       createdAt,
		updatedAt:       updatedAt,
	}
}

// generateFingerprint creates a stable fingerprint for deduplication.
func (e *ExposureEvent) generateFingerprint() string {
	// Include key fields that define uniqueness
	data := map[string]any{
		"tenant_id":  e.tenantID.String(),
		"event_type": e.eventType.String(),
		"title":      e.title,
		"source":     e.source,
	}

	// Include canonical asset if set

	// Include native asset if set
	if e.assetID != nil {
		data["asset_id"] = e.assetID.String()
	}

	// Include key details that affect uniqueness
	if e.details != nil {
		// Include specific fields that define uniqueness
		for _, key := range []string{"port", "protocol", "service", "path", "url", "bucket", "domain"} {
			if v, ok := e.details[key]; ok {
				data[key] = v
			}
		}
	}

	jsonData, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:])
}

// ID returns the exposure event ID.
func (e *ExposureEvent) ID() shared.ID {
	return e.id
}

// TenantID returns the tenant ID.
func (e *ExposureEvent) TenantID() shared.ID {
	return e.tenantID
}

// AssetID returns the asset ID.
func (e *ExposureEvent) AssetID() *shared.ID {
	return e.assetID
}

// EventType returns the event type.
func (e *ExposureEvent) EventType() EventType {
	return e.eventType
}

// Severity returns the severity level.
func (e *ExposureEvent) Severity() Severity {
	return e.severity
}

// State returns the current state.
func (e *ExposureEvent) State() State {
	return e.state
}

// Title returns the title.
func (e *ExposureEvent) Title() string {
	return e.title
}

// Description returns the description.
func (e *ExposureEvent) Description() string {
	return e.description
}

// Details returns a copy of the details.
func (e *ExposureEvent) Details() map[string]any {
	result := make(map[string]any, len(e.details))
	for k, v := range e.details {
		result[k] = v
	}
	return result
}

// Fingerprint returns the deduplication fingerprint.
func (e *ExposureEvent) Fingerprint() string {
	return e.fingerprint
}

// Source returns the source of the exposure event.
func (e *ExposureEvent) Source() string {
	return e.source
}

// FirstSeenAt returns when the exposure was first seen.
func (e *ExposureEvent) FirstSeenAt() time.Time {
	return e.firstSeenAt
}

// LastSeenAt returns when the exposure was last seen.
func (e *ExposureEvent) LastSeenAt() time.Time {
	return e.lastSeenAt
}

// ResolvedAt returns when the exposure was resolved.
func (e *ExposureEvent) ResolvedAt() *time.Time {
	return e.resolvedAt
}

// ResolvedBy returns who resolved the exposure.
func (e *ExposureEvent) ResolvedBy() *shared.ID {
	return e.resolvedBy
}

// ResolutionNotes returns the resolution notes.
func (e *ExposureEvent) ResolutionNotes() string {
	return e.resolutionNotes
}

// CreatedAt returns the creation timestamp.
func (e *ExposureEvent) CreatedAt() time.Time {
	return e.createdAt
}

// UpdatedAt returns the last update timestamp.
func (e *ExposureEvent) UpdatedAt() time.Time {
	return e.updatedAt
}

// SetAssetID sets the asset ID.
func (e *ExposureEvent) SetAssetID(id *shared.ID) {
	e.assetID = id
	e.fingerprint = e.generateFingerprint()
	e.updatedAt = time.Now().UTC()
}

// UpdateSeverity updates the severity level.
func (e *ExposureEvent) UpdateSeverity(severity Severity) error {
	if !severity.IsValid() {
		return fmt.Errorf("%w: invalid severity", shared.ErrValidation)
	}
	e.severity = severity
	e.updatedAt = time.Now().UTC()
	return nil
}

// UpdateDescription updates the description.
func (e *ExposureEvent) UpdateDescription(description string) {
	e.description = description
	e.updatedAt = time.Now().UTC()
}

// MarkSeen updates the last seen timestamp.
func (e *ExposureEvent) MarkSeen() {
	e.lastSeenAt = time.Now().UTC()
	e.updatedAt = e.lastSeenAt
}

// Resolve marks the exposure as resolved.
func (e *ExposureEvent) Resolve(resolvedBy shared.ID, notes string) error {
	if !e.state.CanTransitionTo(StateResolved) {
		return fmt.Errorf("%w: cannot transition from %s to resolved", shared.ErrValidation, e.state)
	}
	now := time.Now().UTC()
	e.state = StateResolved
	e.resolvedAt = &now
	e.resolvedBy = &resolvedBy
	e.resolutionNotes = notes
	e.updatedAt = now
	return nil
}

// Accept marks the exposure as accepted risk.
func (e *ExposureEvent) Accept(acceptedBy shared.ID, notes string) error {
	if !e.state.CanTransitionTo(StateAccepted) {
		return fmt.Errorf("%w: cannot transition from %s to accepted", shared.ErrValidation, e.state)
	}
	now := time.Now().UTC()
	e.state = StateAccepted
	e.resolvedAt = &now
	e.resolvedBy = &acceptedBy
	e.resolutionNotes = notes
	e.updatedAt = now
	return nil
}

// MarkFalsePositive marks the exposure as a false positive.
func (e *ExposureEvent) MarkFalsePositive(markedBy shared.ID, notes string) error {
	if !e.state.CanTransitionTo(StateFalsePositive) {
		return fmt.Errorf("%w: cannot transition from %s to false_positive", shared.ErrValidation, e.state)
	}
	now := time.Now().UTC()
	e.state = StateFalsePositive
	e.resolvedAt = &now
	e.resolvedBy = &markedBy
	e.resolutionNotes = notes
	e.updatedAt = now
	return nil
}

// Reactivate marks the exposure as active again.
func (e *ExposureEvent) Reactivate() error {
	if !e.state.CanTransitionTo(StateActive) {
		return fmt.Errorf("%w: cannot transition from %s to active", shared.ErrValidation, e.state)
	}
	e.state = StateActive
	e.resolvedAt = nil
	e.resolvedBy = nil
	e.resolutionNotes = ""
	e.updatedAt = time.Now().UTC()
	return nil
}

// IsActive returns true if the exposure is active.
func (e *ExposureEvent) IsActive() bool {
	return e.state == StateActive
}

// IsCritical returns true if the exposure is critical severity.
func (e *ExposureEvent) IsCritical() bool {
	return e.severity == SeverityCritical
}

// IsHighOrCritical returns true if the exposure is high or critical severity.
func (e *ExposureEvent) IsHighOrCritical() bool {
	return e.severity == SeverityCritical || e.severity == SeverityHigh
}

// SetDetail sets a detail key-value pair.
func (e *ExposureEvent) SetDetail(key string, value any) {
	if key == "" {
		return
	}
	e.details[key] = value
	e.fingerprint = e.generateFingerprint()
	e.updatedAt = time.Now().UTC()
}

// GetDetail gets a detail value by key.
func (e *ExposureEvent) GetDetail(key string) (any, bool) {
	v, ok := e.details[key]
	return v, ok
}
