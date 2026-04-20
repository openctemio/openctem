// Package ioc — Indicators of Compromise.
//
// An IOC is a tenant-scoped artefact (IP, domain, hash, URL, process
// name, user-agent) that has been observed in connection with a
// vulnerability/finding. At runtime, agents emit telemetry events;
// the correlator matches those events against the IOC catalogue and
// auto-reopens the originating finding when a hit occurs — the loop
// closure named "invariant B6" in the CTEM model.
//
// The domain package defines the entity + the persistence contract
// only. Correlation logic and the runtime wire live in
// internal/app/ioc.
package ioc

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Type enumerates the kinds of indicator currently supported.
type Type string

const (
	TypeIP          Type = "ip"
	TypeDomain      Type = "domain"
	TypeURL         Type = "url"
	TypeFileHash    Type = "file_hash"
	TypeProcessName Type = "process_name"
	TypeUserAgent   Type = "user_agent"
)

// AllTypes is the canonical list — used for validation and iteration.
var AllTypes = []Type{TypeIP, TypeDomain, TypeURL, TypeFileHash, TypeProcessName, TypeUserAgent}

// IsValid reports whether the type is one of the supported values.
func (t Type) IsValid() bool {
	for _, v := range AllTypes {
		if v == t {
			return true
		}
	}
	return false
}

// Source describes where an indicator originated.
type Source string

const (
	SourceScanFinding Source = "scan_finding"
	SourceThreatFeed  Source = "threat_feed"
	SourceManual      Source = "manual"
)

// ErrInvalidType is returned by NewIndicator when the type isn't
// one of the supported Type constants.
var ErrInvalidType = errors.New("ioc: invalid type")

// ErrEmptyValue is returned by NewIndicator when value is empty
// after normalization.
var ErrEmptyValue = errors.New("ioc: value required")

// Indicator is one IOC row. The correlator looks it up by
// (TenantID, Type, Normalized) — never by raw Value.
type Indicator struct {
	ID              shared.ID
	TenantID        shared.ID
	Type            Type
	Value           string  // display value
	Normalized      string  // matching value (lowercase, stripped)
	SourceFindingID *shared.ID
	Source          Source
	Active          bool
	Confidence      int // 0-100, default 75
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// NewIndicator validates + builds a new Indicator. Normalisation is
// done here so the repo never has to care about input hygiene.
func NewIndicator(tenantID shared.ID, t Type, value string, src Source) (*Indicator, error) {
	if !t.IsValid() {
		return nil, ErrInvalidType
	}
	norm := Normalise(t, value)
	if norm == "" {
		return nil, ErrEmptyValue
	}
	now := time.Now().UTC()
	return &Indicator{
		ID:          shared.NewID(),
		TenantID:    tenantID,
		Type:        t,
		Value:       strings.TrimSpace(value),
		Normalized:  norm,
		Source:      src,
		Active:      true,
		Confidence:  75,
		FirstSeenAt: now,
		LastSeenAt:  now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// Normalise returns the match form for a given type. Kept exported
// so callers doing lookups (correlator) produce the same key the
// entity stores.
//
//   - IP, domain, URL, user-agent → lower + trim.
//   - file hash                   → lower + trim (hex case doesn't
//     matter, but leave raw hex bytes alone).
//   - process name                → trim only (Windows process names
//     are case-insensitive on disk, but keep the display form).
func Normalise(t Type, value string) string {
	v := strings.TrimSpace(value)
	switch t {
	case TypeProcessName:
		return v
	default:
		return strings.ToLower(v)
	}
}

// Match is the return shape of the correlator — one per IOC hit.
type Match struct {
	ID                shared.ID
	TenantID          shared.ID
	IOCID             shared.ID
	TelemetryEventID  *shared.ID
	FindingID         *shared.ID
	Reopened          bool
	MatchedAt         time.Time
}

// Repository is the persistence contract.
type Repository interface {
	// Create inserts a new indicator. Duplicate key on
	// (tenant_id, type, normalized) should update last_seen_at only.
	Create(ctx context.Context, ind *Indicator) error
	// GetByID loads one. Tenant-scoped.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Indicator, error)
	// FindActiveByValues bulk-matches a set of (type, normalized)
	// candidates — this is the correlator's hot path.
	FindActiveByValues(ctx context.Context, tenantID shared.ID, candidates []Candidate) ([]*Indicator, error)
	// RecordMatch appends an ioc_matches row.
	RecordMatch(ctx context.Context, m Match) error
	// ListByTenant paginates IOC rows for the UI.
	ListByTenant(ctx context.Context, tenantID shared.ID, limit, offset int) ([]*Indicator, error)
	// Deactivate flips active=false on an IOC (soft delete).
	Deactivate(ctx context.Context, tenantID, id shared.ID) error
}

// Candidate is a (type, normalized_value) pair the correlator
// extracts from a telemetry event and hands to the repo.
type Candidate struct {
	Type       Type
	Normalized string
}
