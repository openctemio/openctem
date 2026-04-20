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
	"net"
	"net/url"
	"regexp"
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

// ErrInvalidValueFormat is returned by NewIndicator when the value
// doesn't match the format implied by the type (e.g. "not-an-ip"
// submitted with type=ip). Without this check the catalogue would
// accept garbage that the correlator can never match, and attackers
// could pollute a tenant's catalogue with unbounded junk values.
var ErrInvalidValueFormat = errors.New("ioc: value format doesn't match type")

// maxValueBytes caps the byte length of a single IOC value. A URL or
// user-agent can legitimately be long; process names and hashes are
// short. 2 KB is generous across all types and stops an attacker from
// stuffing pagefuls of garbage into one row.
const maxValueBytes = 2048

// fileHashRegex matches hex strings of the lengths produced by the
// hash algorithms the correlator sees in agent telemetry:
//   - MD5    : 32 hex chars
//   - SHA-1  : 40 hex chars
//   - SHA-256: 64 hex chars
//   - SHA-512: 128 hex chars
// Case is not enforced here because Normalize lowercases.
var fileHashRegex = regexp.MustCompile(`^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{128}$`)

// domainRegex matches RFC 1035 labels joined by dots. Stricter than
// "anything lower-cased" — rejects whitespace, slashes, NUL bytes,
// and hostnames longer than 253 chars.
var domainRegex = regexp.MustCompile(`^(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?))+$`)

// validateValue applies per-type format rules. Called from
// NewIndicator before the struct is constructed so a garbage row
// never lands in the DB. Exported for reuse by bulk-import callers
// that want to prevalidate before batching.
func validateValue(t Type, normalized string) error {
	if len(normalized) == 0 {
		return ErrEmptyValue
	}
	if len(normalized) > maxValueBytes {
		return ErrInvalidValueFormat
	}
	switch t {
	case TypeIP:
		if net.ParseIP(normalized) == nil {
			return ErrInvalidValueFormat
		}
	case TypeDomain:
		if len(normalized) > 253 || !domainRegex.MatchString(normalized) {
			return ErrInvalidValueFormat
		}
	case TypeURL:
		u, err := url.Parse(normalized)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return ErrInvalidValueFormat
		}
	case TypeFileHash:
		if !fileHashRegex.MatchString(normalized) {
			return ErrInvalidValueFormat
		}
	case TypeProcessName:
		// Process names can contain spaces, backslashes (Windows), and
		// slashes (Linux). Only reject control characters.
		for _, r := range normalized {
			if r < 0x20 || r == 0x7f {
				return ErrInvalidValueFormat
			}
		}
	case TypeUserAgent:
		// UA strings are free-form by spec; only length-limit them.
	}
	return nil
}

// Indicator is one IOC row. The correlator looks it up by
// (TenantID, Type, Normalized) — never by raw Value.
type Indicator struct {
	ID              shared.ID
	TenantID        shared.ID
	Type            Type
	Value           string // display value
	Normalized      string // matching value (lowercase, stripped)
	SourceFindingID *shared.ID
	Source          Source
	Active          bool
	Confidence      int // 0-100, default 75
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// NewIndicator validates + builds a new Indicator. Normalization is
// done here so the repo never has to care about input hygiene.
func NewIndicator(tenantID shared.ID, t Type, value string, src Source) (*Indicator, error) {
	if !t.IsValid() {
		return nil, ErrInvalidType
	}
	norm := Normalize(t, value)
	if norm == "" {
		return nil, ErrEmptyValue
	}
	if err := validateValue(t, norm); err != nil {
		return nil, err
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

// Normalize returns the match form for a given type. Kept exported
// so callers doing lookups (correlator) produce the same key the
// entity stores.
//
//   - IP, domain, URL, user-agent → lower + trim.
//   - file hash                   → lower + trim (hex case doesn't
//     matter, but leave raw hex bytes alone).
//   - process name                → trim only (Windows process names
//     are case-insensitive on disk, but keep the display form).
func Normalize(t Type, value string) string {
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
	ID               shared.ID
	TenantID         shared.ID
	IOCID            shared.ID
	TelemetryEventID *shared.ID
	FindingID        *shared.ID
	Reopened         bool
	MatchedAt        time.Time
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
