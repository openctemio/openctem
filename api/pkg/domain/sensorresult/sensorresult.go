// Package sensorresult is the domain of sensor results that no command
// stands behind (RFC-040 §5.3, owner decision Q6 (a),
// docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md): the tenant's policy
// for them and the quarantine where they wait for a person to accept or
// discard them.
//
// A sensor report is "bound" when it names a command assigned to the
// submitting sensor and still open; it then behaves as before. A report
// without one is "unsolicited". Collector and CI runner sensors exist to push
// unsolicited results, so theirs are applied with limits (existing assets and
// human-resolved findings are left alone). Any other sensor's unsolicited
// report is quarantined when the tenant's mode is "quarantine", and applied
// with the same limits, plus an audit entry and a metric, when it is "warn".
package sensorresult

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Mode is what happens to an unsolicited report from a sensor whose role may
// not push results on its own (everything but collector and runner).
type Mode string

const (
	// ModeWarn applies the report with the unsolicited limits and records an
	// audit entry and a metric. The mode of every tenant that existed before
	// migration 000317.
	ModeWarn Mode = "warn"
	// ModeQuarantine stores the report for review and applies nothing. The
	// mode of a tenant without a stored policy, i.e. every new tenant.
	ModeQuarantine Mode = "quarantine"
)

// DefaultMode is the mode of a tenant with no stored policy.
const DefaultMode = ModeQuarantine

// ParseMode validates a mode.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeWarn, ModeQuarantine:
		return Mode(s), nil
	}
	return "", fmt.Errorf("%w: mode must be %q or %q", shared.ErrValidation, ModeWarn, ModeQuarantine)
}

// Policy is a tenant's policy for unsolicited sensor results.
type Policy struct {
	TenantID shared.ID
	Mode     Mode
	// AllowAdvisoryEvidence lets a sensor post validation evidence without
	// the validate command assigned to it; the evidence is then recorded as
	// advisory and never changes the finding. Off unless an administrator
	// turns it on.
	AllowAdvisoryEvidence bool
	UpdatedBy             *shared.ID
	UpdatedAt             time.Time
	// Stored is false when the tenant has no policy row: the defaults apply.
	Stored bool
}

// DefaultPolicy is the policy of a tenant with no stored row.
func DefaultPolicy(tenantID shared.ID) Policy {
	return Policy{TenantID: tenantID, Mode: DefaultMode}
}

// Status is a quarantined report's review state.
type Status string

const (
	StatusPending   Status = "pending"
	StatusAccepted  Status = "accepted"
	StatusDiscarded Status = "discarded"
)

// ParseStatus validates a status filter value.
func ParseStatus(s string) (Status, error) {
	switch Status(s) {
	case StatusPending, StatusAccepted, StatusDiscarded:
		return Status(s), nil
	}
	return "", fmt.Errorf("%w: status must be pending, accepted or discarded", shared.ErrValidation)
}

// Reason says why a report was quarantined.
type Reason string

const (
	// ReasonNoCommand: the report named no command, and the sensor's role may
	// not push results on its own.
	ReasonNoCommand Reason = "no_command"
	// ReasonOutOfContract: a report bound to a command carried asset types
	// its tool does not produce (research/27 G12, output-type binding).
	ReasonOutOfContract Reason = "out_of_contract"
)

// Protocol is the results protocol the report arrived on; it decides how an
// accepted report is applied.
type Protocol string

const (
	ProtocolV1 Protocol = "v1"
	ProtocolV2 Protocol = "v2"
)

// Item is one quarantined report (a v1 request, or one v2 segment).
type Item struct {
	ID         shared.ID
	TenantID   shared.ID
	SensorID   shared.ID
	SensorName string // read side only
	SensorType string
	Protocol   Protocol
	// Route is the ingest route (ctis, sarif, recon, scan, chunk, v2).
	Route string
	// ReportID is the report's own id (v1 metadata.id, v2 report id).
	ReportID string
	// Segment is the v2 segment number; nil for v1.
	Segment       *int
	ToolName      string
	Reason        Reason
	AssetsCount   int
	FindingsCount int
	// Payload is the CTIS report as JSON. Never returned by List.
	Payload     []byte
	PayloadSize int
	Status      Status
	CreatedAt   time.Time
	ReviewedBy  *shared.ID
	ReviewedAt  *time.Time
	// Result is what applying an accepted report did (counts), as JSON.
	Result []byte
}

// Limits bound what one tenant and one sensor may park in the quarantine, so
// a stolen key cannot fill the database through it.
type Limits struct {
	MaxPendingPerTenant int
	MaxPendingPerSensor int
	// MaxPendingBytesPerTenant caps the payload bytes a tenant's pending
	// items hold together: pending items are kept until someone reviews
	// them, so the item count alone (MaxPendingPerTenant x MaxPayloadBytes)
	// would let one tenant hold gigabytes.
	MaxPendingBytesPerTenant int64
	// MaxPayloadBytes is the largest report kept; a larger one is refused.
	MaxPayloadBytes int
}

// DefaultLimits are the quarantine bounds.
func DefaultLimits() Limits {
	return Limits{MaxPendingPerTenant: 1000, MaxPendingPerSensor: 200, MaxPayloadBytes: 16 << 20,
		MaxPendingBytesPerTenant: 512 << 20}
}

// ListFilter selects quarantined items.
type ListFilter struct {
	Status   Status // "" = every status
	SensorID *shared.ID
	Page     int
	PerPage  int
}

// Errors.
var (
	ErrNotFound = shared.NewDomainError("NOT_FOUND", "quarantined result not found", shared.ErrNotFound)
	// ErrAlreadyReviewed: the item was accepted or discarded already.
	ErrAlreadyReviewed = shared.NewDomainError("CONFLICT", "quarantined result was already reviewed", shared.ErrConflict)
	// ErrFull: the tenant's or the sensor's quarantine is at its limit, or
	// the report is larger than the quarantine keeps.
	ErrFull = shared.NewDomainError("RESULTS_QUARANTINE_FULL", "the results quarantine is full; the report was refused", shared.ErrValidation)
)

// Repository stores the policy and the quarantine.
type Repository interface {
	// GetPolicy returns the tenant's stored policy, or DefaultPolicy with
	// Stored false when there is none.
	GetPolicy(ctx context.Context, tenantID shared.ID) (Policy, error)
	// SavePolicy upserts the tenant's policy.
	SavePolicy(ctx context.Context, p *Policy) error

	// Create stores an item unless the limits are reached (ErrFull).
	Create(ctx context.Context, item *Item, limits Limits) error
	// List returns a page of items without their payloads, newest first.
	List(ctx context.Context, tenantID shared.ID, f ListFilter) ([]Item, int, error)
	// Get returns one item with its payload.
	Get(ctx context.Context, tenantID, id shared.ID) (*Item, error)
	// Review moves a pending item to accepted or discarded. ErrAlreadyReviewed
	// when it is not pending any more. Discarding drops the payload.
	Review(ctx context.Context, tenantID, id shared.ID, to Status, by shared.ID) error
	// SetResult stores what applying an accepted item did.
	SetResult(ctx context.Context, tenantID, id shared.ID, result []byte) error
	// PurgeReviewed deletes reviewed items older than the cutoff.
	PurgeReviewed(ctx context.Context, before time.Time) (int, error)
}
