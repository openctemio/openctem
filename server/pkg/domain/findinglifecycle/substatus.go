package findinglifecycle

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ObjectKind is what a sub-status or a scheme applies to.
type ObjectKind string

// ObjectKindFinding: findings (remediation tasks follow once their model is
// complete).
const ObjectKindFinding ObjectKind = "finding"

// Colors is the fixed palette a sub-status picks from: a token the web
// console maps to its theme, never free CSS.
var Colors = []string{ //nolint:gochecknoglobals // static palette
	"gray", "red", "orange", "amber", "yellow", "lime", "green", "emerald",
	"teal", "cyan", "sky", "blue", "indigo", "violet", "purple", "pink",
}

// Errors of the catalog.
var (
	ErrSubStatusNotFound   = fmt.Errorf("%w: sub-status not found", shared.ErrNotFound)
	ErrSubStatusKeyTaken   = fmt.Errorf("%w: a sub-status with this key already exists", shared.ErrConflict)
	ErrSubStatusInUse      = fmt.Errorf("%w: the sub-status is in use", shared.ErrConflict)
	ErrSubStatusArchived   = fmt.Errorf("%w: the sub-status is archived", shared.ErrValidation)
	ErrSubStatusLimit      = fmt.Errorf("%w: the organization has reached its sub-status limit", shared.ErrValidation)
	ErrCategoryImmutable   = fmt.Errorf("%w: the canonical status and closure reason of a sub-status cannot change", shared.ErrValidation)
	errInvalidCanonical    = fmt.Errorf("%w: canonical_status must be one of new, confirmed, in_progress, fix_applied, resolved, false_positive, accepted, duplicate", shared.ErrValidation)
	errClosureReasonNeeded = fmt.Errorf("%w: a sub-status of a closed status names its closure reason", shared.ErrValidation)
	errClosureReasonOpen   = fmt.Errorf("%w: a sub-status of an open status has no closure reason", shared.ErrValidation)
)

// SubStatus is an organization's label for findings in one canonical status.
type SubStatus struct {
	id              shared.ID
	tenantID        shared.ID
	kind            ObjectKind
	canonicalStatus vulnerability.FindingStatus
	closureReason   vulnerability.ClosureReason
	key             string
	name            string
	labels          map[string]string
	description     string
	color           string
	sortOrder       int
	archivedAt      *time.Time
	createdAt       time.Time
	createdBy       *shared.ID
	updatedAt       time.Time
	updatedBy       *shared.ID
}

// SubStatusInput is what a person sets on a new sub-status.
type SubStatusInput struct {
	Key             string
	Name            string
	Labels          map[string]string
	Description     string
	Color           string
	SortOrder       int
	CanonicalStatus string
	ClosureReason   string
}

// NewSubStatus validates in and returns a new sub-status of tenantID.
func NewSubStatus(tenantID shared.ID, in SubStatusInput, actor *shared.ID, now time.Time) (*SubStatus, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	key := strings.TrimSpace(in.Key)
	if !keyPattern.MatchString(key) {
		return nil, fmt.Errorf("%w: key must be 2-40 lowercase letters, digits or underscores, starting with a letter", shared.ErrValidation)
	}
	status := vulnerability.FindingStatus(strings.TrimSpace(in.CanonicalStatus))
	if !IsCanonical(status) {
		return nil, errInvalidCanonical
	}
	reason, err := boundReason(status, in.ClosureReason)
	if err != nil {
		return nil, err
	}
	s := &SubStatus{
		id: shared.NewID(), tenantID: tenantID, kind: ObjectKindFinding,
		canonicalStatus: status, closureReason: reason, key: key,
		createdAt: now, createdBy: actor, updatedAt: now, updatedBy: actor,
	}
	if err := s.setPresentation(in.Name, in.Labels, in.Description, in.Color, in.SortOrder); err != nil {
		return nil, err
	}
	return s, nil
}

// boundReason validates the closure reason a sub-status of status binds: one
// of the status's own reasons (never "unknown") under a closed status, none
// under an open one.
func boundReason(status vulnerability.FindingStatus, raw string) (vulnerability.ClosureReason, error) {
	r := vulnerability.ClosureReason(strings.ToLower(strings.TrimSpace(raw)))
	if !status.IsClosed() {
		if r != "" {
			return "", errClosureReasonOpen
		}
		return "", nil
	}
	if r == "" {
		return "", errClosureReasonNeeded
	}
	if !slices.Contains(vulnerability.ClosureReasonsFor(status), r) {
		return "", fmt.Errorf("%w: closure_reason %q is not a reason of %s", shared.ErrValidation, r, status)
	}
	return r, nil
}

// SubStatusUpdate is what a person may change on a sub-status: its
// presentation, never its category or key.
type SubStatusUpdate struct {
	Name        *string
	Labels      map[string]string // nil keeps the labels; an empty map clears them
	Description *string
	Color       *string
	SortOrder   *int
}

// Update applies u.
func (s *SubStatus) Update(u SubStatusUpdate, actor *shared.ID, now time.Time) error {
	name, labels, description, color, order := s.name, s.labels, s.description, s.color, s.sortOrder
	if u.Name != nil {
		name = *u.Name
	}
	if u.Labels != nil {
		labels = u.Labels
	}
	if u.Description != nil {
		description = *u.Description
	}
	if u.Color != nil {
		color = *u.Color
	}
	if u.SortOrder != nil {
		order = *u.SortOrder
	}
	if err := s.setPresentation(name, labels, description, color, order); err != nil {
		return err
	}
	s.updatedAt, s.updatedBy = now, actor
	return nil
}

func (s *SubStatus) setPresentation(name string, labels map[string]string, description, color string, order int) error {
	name, err := plainText("name", name, MaxNameLen, true)
	if err != nil {
		return err
	}
	description, err = plainText("description", description, MaxDescriptionLen, false)
	if err != nil {
		return err
	}
	if len(labels) > MaxLabels {
		return fmt.Errorf("%w: at most %d labels", shared.ErrValidation, MaxLabels)
	}
	clean := make(map[string]string, len(labels))
	for lang, label := range labels {
		if !languagePattern.MatchString(lang) {
			return fmt.Errorf("%w: label language %q must be a language code such as vi", shared.ErrValidation, lang)
		}
		v, err := plainText("label", label, MaxNameLen, true)
		if err != nil {
			return err
		}
		clean[lang] = v
	}
	color = strings.TrimSpace(color)
	if !slices.Contains(Colors, color) {
		return fmt.Errorf("%w: color must be one of %s", shared.ErrValidation, strings.Join(Colors, ", "))
	}
	if order < 0 || order > 10000 {
		return fmt.Errorf("%w: sort_order must be between 0 and 10000", shared.ErrValidation)
	}
	s.name, s.labels, s.description, s.color, s.sortOrder = name, clean, description, color, order
	return nil
}

// Archive retires the sub-status: it is no longer offered, existing findings
// keep it until they move. The caller checks that no published scheme uses it.
func (s *SubStatus) Archive(actor *shared.ID, now time.Time) {
	if s.archivedAt == nil {
		s.archivedAt = &now
	}
	s.updatedAt, s.updatedBy = now, actor
}

// Restore brings an archived sub-status back.
func (s *SubStatus) Restore(actor *shared.ID, now time.Time) {
	s.archivedAt = nil
	s.updatedAt, s.updatedBy = now, actor
}

// SubStatusData reconstitutes a stored sub-status.
type SubStatusData struct {
	ID              shared.ID
	TenantID        shared.ID
	Kind            ObjectKind
	CanonicalStatus vulnerability.FindingStatus
	ClosureReason   vulnerability.ClosureReason
	Key             string
	Name            string
	Labels          map[string]string
	Description     string
	Color           string
	SortOrder       int
	ArchivedAt      *time.Time
	CreatedAt       time.Time
	CreatedBy       *shared.ID
	UpdatedAt       time.Time
	UpdatedBy       *shared.ID
}

// ReconstituteSubStatus rebuilds a sub-status from storage.
func ReconstituteSubStatus(d SubStatusData) *SubStatus {
	labels := d.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return &SubStatus{
		id: d.ID, tenantID: d.TenantID, kind: d.Kind, canonicalStatus: d.CanonicalStatus,
		closureReason: d.ClosureReason, key: d.Key, name: d.Name, labels: labels,
		description: d.Description, color: d.Color, sortOrder: d.SortOrder, archivedAt: d.ArchivedAt,
		createdAt: d.CreatedAt, createdBy: d.CreatedBy, updatedAt: d.UpdatedAt, updatedBy: d.UpdatedBy,
	}
}

// Accessors.
func (s *SubStatus) ID() shared.ID                                { return s.id }
func (s *SubStatus) TenantID() shared.ID                          { return s.tenantID }
func (s *SubStatus) Kind() ObjectKind                             { return s.kind }
func (s *SubStatus) CanonicalStatus() vulnerability.FindingStatus { return s.canonicalStatus }
func (s *SubStatus) ClosureReason() vulnerability.ClosureReason   { return s.closureReason }
func (s *SubStatus) Key() string                                  { return s.key }
func (s *SubStatus) Name() string                                 { return s.name }
func (s *SubStatus) Labels() map[string]string                    { return maps.Clone(s.labels) }
func (s *SubStatus) Description() string                          { return s.description }
func (s *SubStatus) Color() string                                { return s.color }
func (s *SubStatus) SortOrder() int                               { return s.sortOrder }
func (s *SubStatus) ArchivedAt() *time.Time                       { return s.archivedAt }
func (s *SubStatus) IsArchived() bool                             { return s.archivedAt != nil }
func (s *SubStatus) CreatedAt() time.Time                         { return s.createdAt }
func (s *SubStatus) CreatedBy() *shared.ID                        { return s.createdBy }
func (s *SubStatus) UpdatedAt() time.Time                         { return s.updatedAt }
func (s *SubStatus) UpdatedBy() *shared.ID                        { return s.updatedBy }

// SubStatusFilter narrows a catalog listing.
type SubStatusFilter struct {
	Kind            ObjectKind
	IncludeArchived bool
}

// SubStatusRepository stores the catalog. Every method is tenant-scoped.
type SubStatusRepository interface {
	Create(ctx context.Context, s *SubStatus) error
	Update(ctx context.Context, s *SubStatus) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*SubStatus, error)
	List(ctx context.Context, tenantID shared.ID, f SubStatusFilter) ([]*SubStatus, error)
	// CountActive counts the tenant's sub-statuses of kind that are not archived.
	CountActive(ctx context.Context, tenantID shared.ID, kind ObjectKind) (int, error)
	// CountFindings counts the tenant's findings that carry the sub-status.
	CountFindings(ctx context.Context, tenantID, id shared.ID) (int64, error)
}
