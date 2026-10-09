// Package scope provides public types and helpers reusable across the codebase.
package scope

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// =============================================================================
// Scope Target Entity
// =============================================================================

// Target represents an in-scope target for security scanning.
type Target struct {
	id          shared.ID
	tenantID    shared.ID
	targetType  TargetType
	pattern     string
	description string
	priority    int
	status      Status
	tags        []string
	createdBy   string
	createdAt   time.Time
	updatedAt   time.Time

	// Entry fields (entry.go, RFC-054 §5).
	reason            string
	expiresAt         *time.Time
	maxTier           Tier
	approvalsRequired int
	approvals         []Approval
	approvedAt        *time.Time
	rejectedBy        string
	rejectedAt        *time.Time
	// remindedAt: when the approvers were last reminded (approvers.go).
	remindedAt *time.Time

	origin Origin
	// discoveryOff: discovery switched off (discovery.go); the zero value
	// is on.
	discoveryOff bool

	// Authorization source (authorization.go, RFC-065).
	authSource AuthorizationSource
	programID  *shared.ID
	letterID   *shared.ID
}

// NewTarget creates a new scope target: active, permanent, t1.
func NewTarget(
	tenantID shared.ID,
	targetType TargetType,
	pattern string,
	description string,
	createdBy string,
) (*Target, error) {
	if tenantID.IsZero() {
		return nil, ErrInvalidTenantID
	}

	if !targetType.IsValid() {
		return nil, ErrInvalidTargetType
	}

	if err := ValidatePattern(targetType, pattern); err != nil {
		return nil, err
	}

	now := time.Now()
	return &Target{
		id:          shared.NewID(),
		tenantID:    tenantID,
		targetType:  targetType,
		pattern:     pattern,
		description: description,
		priority:    0,
		status:      StatusActive,
		tags:        []string{},
		createdBy:   createdBy,
		createdAt:   now,
		updatedAt:   now,
		maxTier:     TierActive,
		approvedAt:  &now,
	}, nil
}

// ReconstituteTarget creates a Target from persistence data.
func ReconstituteTarget(
	id shared.ID,
	tenantID shared.ID,
	targetType TargetType,
	pattern string,
	description string,
	priority int,
	status Status,
	tags []string,
	createdBy string,
	createdAt time.Time,
	updatedAt time.Time,
) *Target {
	return &Target{
		id:          id,
		tenantID:    tenantID,
		targetType:  targetType,
		pattern:     pattern,
		description: description,
		priority:    priority,
		status:      status,
		tags:        tags,
		createdBy:   createdBy,
		createdAt:   createdAt,
		updatedAt:   updatedAt,
		maxTier:     TierActive,
	}
}

// Getters
func (t *Target) ID() shared.ID          { return t.id }
func (t *Target) TenantID() shared.ID    { return t.tenantID }
func (t *Target) TargetType() TargetType { return t.targetType }
func (t *Target) Pattern() string        { return t.pattern }
func (t *Target) Description() string    { return t.description }
func (t *Target) Priority() int          { return t.priority }
func (t *Target) Status() Status         { return t.status }
func (t *Target) Tags() []string         { return t.tags }
func (t *Target) CreatedBy() string      { return t.createdBy }
func (t *Target) CreatedAt() time.Time   { return t.createdAt }
func (t *Target) UpdatedAt() time.Time   { return t.updatedAt }

// IsActive reports whether the target is in effect now: active and not past
// its expiry (InEffect). A pending, inactive, rejected or expired target
// authorizes nothing.
func (t *Target) IsActive() bool {
	return t.InEffect(time.Now())
}

// Matches checks if a value matches this target's pattern.
func (t *Target) Matches(value string) bool {
	return MatchesPattern(t.targetType, t.pattern, value)
}

// Update methods
func (t *Target) UpdateDescription(description string) {
	t.description = description
	t.updatedAt = time.Now()
}

func (t *Target) UpdatePriority(priority int) error {
	if priority < 1 || priority > 10 {
		return fmt.Errorf("%w: priority must be between 1 and 10", shared.ErrValidation)
	}
	t.priority = priority
	t.updatedAt = time.Now()
	return nil
}

func (t *Target) UpdateTags(tags []string) {
	t.tags = tags
	t.updatedAt = time.Now()
}

func (t *Target) Activate() {
	t.status = StatusActive
	t.updatedAt = time.Now()
}

func (t *Target) Deactivate() {
	t.status = StatusInactive
	t.updatedAt = time.Now()
}

// =============================================================================
// Scope Exclusion Entity
// =============================================================================

// Exclusion represents an exclusion from scope for security scanning.
//
// Lifecycle (an exclusion suppresses scanning, so it is a two-person control):
//
//	pending --Approve--> active <--Activate/Deactivate--> inactive
//	   |                   |
//	   +--Reject--> rejected    +--(expires_at passes)--> expired
//
// NewExclusion creates a PENDING exclusion. It is not applied anywhere (scan
// target filtering, scope matching, coverage) until a user other than the
// requester, holding attack_surface:scope:exclusions:approve, approves it.
// Only an approved, active, unexpired exclusion is in effect (IsActive).
type Exclusion struct {
	id            shared.ID
	tenantID      shared.ID
	exclusionType ExclusionType
	pattern       string
	reason        string
	status        Status
	expiresAt     *time.Time
	approvedBy    string
	approvedAt    *time.Time
	rejectedBy    string
	rejectedAt    *time.Time
	createdBy     string
	createdAt     time.Time
	updatedAt     time.Time
	// web is the path rule of a `path` exclusion (web_rule.go).
	web    *WebRule
	origin Origin
}

// NewExclusion creates a new scope exclusion awaiting approval.
func NewExclusion(
	tenantID shared.ID,
	exclusionType ExclusionType,
	pattern string,
	reason string,
	expiresAt *time.Time,
	createdBy string,
) (*Exclusion, error) {
	if tenantID.IsZero() {
		return nil, ErrInvalidTenantID
	}

	if !exclusionType.IsValid() {
		return nil, ErrInvalidExclusionType
	}

	if reason == "" {
		return nil, ErrReasonRequired
	}

	now := time.Now()
	return &Exclusion{
		id:            shared.NewID(),
		tenantID:      tenantID,
		exclusionType: exclusionType,
		pattern:       pattern,
		reason:        reason,
		status:        StatusPending,
		expiresAt:     expiresAt,
		createdBy:     createdBy,
		createdAt:     now,
		updatedAt:     now,
	}, nil
}

// ReconstituteExclusion creates an Exclusion from persistence data.
func ReconstituteExclusion(
	id shared.ID,
	tenantID shared.ID,
	exclusionType ExclusionType,
	pattern string,
	reason string,
	status Status,
	expiresAt *time.Time,
	approvedBy string,
	approvedAt *time.Time,
	createdBy string,
	createdAt time.Time,
	updatedAt time.Time,
) *Exclusion {
	return &Exclusion{
		id:            id,
		tenantID:      tenantID,
		exclusionType: exclusionType,
		pattern:       pattern,
		reason:        reason,
		status:        status,
		expiresAt:     expiresAt,
		approvedBy:    approvedBy,
		approvedAt:    approvedAt,
		createdBy:     createdBy,
		createdAt:     createdAt,
		updatedAt:     updatedAt,
	}
}

// SetRejection restores the reviewer and time of a rejection from persistence.
func (e *Exclusion) SetRejection(rejectedBy string, rejectedAt *time.Time) {
	e.rejectedBy = rejectedBy
	e.rejectedAt = rejectedAt
}

// Getters
func (e *Exclusion) ID() shared.ID                { return e.id }
func (e *Exclusion) TenantID() shared.ID          { return e.tenantID }
func (e *Exclusion) ExclusionType() ExclusionType { return e.exclusionType }
func (e *Exclusion) Pattern() string              { return e.pattern }
func (e *Exclusion) Reason() string               { return e.reason }
func (e *Exclusion) Status() Status               { return e.status }
func (e *Exclusion) ExpiresAt() *time.Time        { return e.expiresAt }
func (e *Exclusion) ApprovedBy() string           { return e.approvedBy }
func (e *Exclusion) ApprovedAt() *time.Time       { return e.approvedAt }
func (e *Exclusion) RejectedBy() string           { return e.rejectedBy }
func (e *Exclusion) RejectedAt() *time.Time       { return e.rejectedAt }
func (e *Exclusion) CreatedBy() string            { return e.createdBy }
func (e *Exclusion) CreatedAt() time.Time         { return e.createdAt }
func (e *Exclusion) UpdatedAt() time.Time         { return e.updatedAt }

// IsActive returns true if the exclusion is in effect: approved, active and
// not expired. A pending or rejected exclusion is never in effect.
func (e *Exclusion) IsActive() bool {
	if e.status != StatusActive || !e.IsApproved() {
		return false
	}
	if e.expiresAt != nil && time.Now().After(*e.expiresAt) {
		return false
	}
	return true
}

// IsApproved returns true if the exclusion has been approved.
func (e *Exclusion) IsApproved() bool {
	return e.approvedBy != "" && e.approvedAt != nil
}

// IsPending returns true if the exclusion is waiting for review.
func (e *Exclusion) IsPending() bool {
	return e.status == StatusPending
}

// Matches checks if a value matches this exclusion's pattern.
func (e *Exclusion) Matches(value string) bool {
	if e.exclusionType == ExclusionTypePath {
		return e.matchesWebURL(value)
	}
	return MatchesExclusionPattern(e.exclusionType, e.pattern, value)
}

// Update methods
func (e *Exclusion) UpdateReason(reason string) {
	e.reason = reason
	e.updatedAt = time.Now()
}

// UpdateExpiresAt changes the exclusion window. An approval covers the window
// that was approved: extending it (a later date, or removing the expiry) on
// an approved exclusion sends it back to pending for a fresh review, so
// scope:write cannot turn a short approved exclusion into a permanent one.
// Shortening the window keeps the approval.
func (e *Exclusion) UpdateExpiresAt(expiresAt *time.Time) {
	if e.IsApproved() && extendsWindow(e.expiresAt, expiresAt) {
		e.approvedBy = ""
		e.approvedAt = nil
		e.status = StatusPending
	}
	e.expiresAt = expiresAt
	e.updatedAt = time.Now()
}

// Reviewer is the person changing an exclusion and whether they hold the
// exclusion approval permission (attack_surface:scope:exclusions:approve).
type Reviewer struct {
	UserID     string
	CanApprove bool
}

// InEffect reports whether the exclusion currently stops scans: approved and
// active (an expired one is marked expired by the sweeper).
func (e *Exclusion) InEffect() bool {
	return e.status == StatusActive && e.IsApproved()
}

// AuthorizeReduction decides whether r may take this exclusion out of effect
// (deactivate, delete) or shorten its window. An approved exclusion was put
// into effect by two people, so taking that protection away needs the same:
// the approval permission, and someone other than the requester. Without it
// scope:write (a member default) could switch off the exclusion protecting a
// production system and scan it. An exclusion not in effect protects nothing
// now, so any change to it is allowed.
func (e *Exclusion) AuthorizeReduction(r Reviewer) error {
	if !e.InEffect() {
		return nil
	}
	if !r.CanApprove {
		return ErrExclusionReduceNeedsApprover
	}
	if r.UserID == "" {
		return fmt.Errorf("%w: reviewer is required", shared.ErrValidation)
	}
	if e.createdBy != "" && r.UserID == e.createdBy {
		return ErrExclusionSelfReduce
	}
	return nil
}

// ShortensWindow reports whether setting expiresAt would end the exclusion
// earlier than now configured (a date in the past included).
func (e *Exclusion) ShortensWindow(expiresAt *time.Time) bool {
	return extendsWindow(expiresAt, e.expiresAt)
}

// extendsWindow reports whether next ends later than prev (nil = never).
func extendsWindow(prev, next *time.Time) bool {
	switch {
	case prev == nil:
		return false // already unbounded; nothing to extend
	case next == nil:
		return true
	default:
		return next.After(*prev)
	}
}

// Approve records that approvedBy reviewed and authorized the exclusion and
// puts it into effect. The user who requested the exclusion cannot approve it
// (separation of duties, as for finding status approvals). Only an exclusion
// that is not yet approved and not rejected can be approved.
func (e *Exclusion) Approve(approvedBy string) error {
	if approvedBy == "" {
		return fmt.Errorf("%w: approver is required", shared.ErrValidation)
	}
	if e.status == StatusRejected {
		return ErrExclusionRejected
	}
	if e.IsApproved() {
		return ErrExclusionNotPending
	}
	if e.createdBy != "" && approvedBy == e.createdBy {
		return ErrExclusionSelfApproval
	}
	now := time.Now()
	e.approvedBy = approvedBy
	e.approvedAt = &now
	e.status = StatusActive
	e.updatedAt = now
	return nil
}

// Reject records that rejectedBy declined the exclusion. A rejected exclusion
// never takes effect; only a pending one can be rejected.
func (e *Exclusion) Reject(rejectedBy string) error {
	if rejectedBy == "" {
		return fmt.Errorf("%w: reviewer is required", shared.ErrValidation)
	}
	if e.status != StatusPending {
		return ErrExclusionNotPending
	}
	now := time.Now()
	e.rejectedBy = rejectedBy
	e.rejectedAt = &now
	e.status = StatusRejected
	e.updatedAt = now
	return nil
}

// Activate puts an approved exclusion back into effect. An exclusion nobody
// approved (pending) or a rejected one cannot be activated.
func (e *Exclusion) Activate() error {
	if e.status == StatusRejected {
		return ErrExclusionRejected
	}
	if !e.IsApproved() {
		return ErrExclusionNotApproved
	}
	e.status = StatusActive
	e.updatedAt = time.Now()
	return nil
}

// Deactivate takes an approved exclusion out of effect. Pending and rejected
// exclusions are not in effect; they are reviewed or deleted instead.
func (e *Exclusion) Deactivate() error {
	if e.status == StatusRejected {
		return ErrExclusionRejected
	}
	if e.status == StatusPending {
		return ErrExclusionNotApproved
	}
	e.status = StatusInactive
	e.updatedAt = time.Now()
	return nil
}

func (e *Exclusion) MarkExpired() {
	e.status = StatusExpired
	e.updatedAt = time.Now()
}
