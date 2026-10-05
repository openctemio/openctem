package tenant

// Member lifecycle: disable, offboard, erase personal data.
// Design: docs/rfcs/RFC-050-asset-access-model.md.
//
// A person is never hard-deleted. Disabling cuts access and freezes what the
// member holds; offboarding strips it, reassigns owned work and keeps the
// membership as a tombstone; erasing anonymises the account after
// offboarding. None of the three deletes a row another table points at.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrAlreadyMember is returned when a membership is created for a person who
// already has an active or suspended membership in the tenant.
var ErrAlreadyMember = fmt.Errorf("%w: user is already a member of this organization", shared.ErrConflict)

// ErrReassignmentRequired is returned by an offboarding that leaves owned
// work (schedules, assigned findings, owned assets) without a new owner.
var ErrReassignmentRequired = fmt.Errorf("%w: reassign the member's schedules, findings and assets first", shared.ErrConflict)

// ErrInvalidReassignTarget is returned when a reassignment target is not an
// active member of the organization (or is the member being offboarded).
var ErrInvalidReassignTarget = fmt.Errorf("%w: the new owner must be another active member of the organization", shared.ErrValidation)

// ErrEraseNotAllowed is returned when personal data cannot be erased: the
// member is not offboarded here, or still belongs to another organization.
var ErrEraseNotAllowed = fmt.Errorf("%w: personal data can be erased only after offboarding, and only when the person belongs to no other organization", shared.ErrConflict)

// LifecycleRef names one thing a member holds or owns.
type LifecycleRef struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status,omitempty"`
	// Detail is a short type-specific note: a key prefix, a campaign role, a
	// schedule type.
	Detail string `json:"detail,omitempty"`
}

// AccessReport lists everything a member holds (access) or owns (work) in one
// organization. It drives the offboarding wizard and is the record exported
// with an offboarding.
type AccessReport struct {
	MembershipID string       `json:"membership_id"`
	UserID       string       `json:"user_id"`
	Status       MemberStatus `json:"status"`

	// Access sources.
	Roles     []LifecycleRef `json:"roles"`
	Groups    []LifecycleRef `json:"groups"`
	APIKeys   []LifecycleRef `json:"api_keys"`
	Campaigns []LifecycleRef `json:"campaigns"`
	// DirectGrants is the number of per-user asset grants.
	DirectGrants int `json:"direct_grants"`
	// VisibleAssets is the number of materialized scope rows (0 while the
	// member is disabled: the rows return when re-enabled).
	VisibleAssets int `json:"visible_assets"`

	// Owned work that an offboarding must hand to someone else.
	OwnedScans           []LifecycleRef `json:"owned_scans"`
	OwnedReportSchedules []LifecycleRef `json:"owned_report_schedules"`
	OwnedWorkflows       []LifecycleRef `json:"owned_workflows"`
	// AssignedFindings counts the member's open (not closed) findings.
	AssignedFindings int `json:"assigned_findings"`
	// OwnedAssets counts the assets the member is a named (user) owner of.
	OwnedAssets int `json:"owned_assets"`
}

// OwnsSchedules reports whether the member owns any scan, report schedule or
// workflow.
func (r *AccessReport) OwnsSchedules() bool {
	return len(r.OwnedScans)+len(r.OwnedReportSchedules)+len(r.OwnedWorkflows) > 0
}

// OffboardPlan says who takes over the member's work. Every category the
// member owns something in must be covered; nothing is ever left to run as
// the system or as a person who left.
type OffboardPlan struct {
	// SchedulesTo becomes the owner (created_by) of the member's scans,
	// report schedules and workflows.
	SchedulesTo *shared.ID
	// FindingsTo becomes the assignee of the member's open findings. When
	// nil, UnassignFindings must be set to put them back in the queue.
	FindingsTo       *shared.ID
	UnassignFindings bool
	// AssetsTo becomes the owner of the assets the member owns.
	AssetsTo *shared.ID
}

// Missing returns the categories the plan leaves without a new owner, for
// the given report. Empty means the plan is complete.
func (p OffboardPlan) Missing(r *AccessReport) []string {
	var out []string
	if r.OwnsSchedules() && p.SchedulesTo == nil {
		out = append(out, "schedules")
	}
	if r.AssignedFindings > 0 && p.FindingsTo == nil && !p.UnassignFindings {
		out = append(out, "findings")
	}
	if r.OwnedAssets > 0 && p.AssetsTo == nil {
		out = append(out, "assets")
	}
	return out
}

// Targets returns the distinct reassignment targets of the plan.
func (p OffboardPlan) Targets() []shared.ID {
	seen := map[shared.ID]bool{}
	var out []shared.ID
	for _, t := range []*shared.ID{p.SchedulesTo, p.FindingsTo, p.AssetsTo} {
		if t != nil && !t.IsZero() && !seen[*t] {
			seen[*t] = true
			out = append(out, *t)
		}
	}
	return out
}

// DisableResult reports what a disable paused, so administrators can be told.
type DisableResult struct {
	SuspendedKeys  int            `json:"suspended_keys"`
	PausedScans    []LifecycleRef `json:"paused_scans"`
	PausedReports  []LifecycleRef `json:"paused_report_schedules"`
	PausedWorkflow []LifecycleRef `json:"paused_workflows"`
}

// Paused reports whether anything was paused.
func (r *DisableResult) Paused() int {
	if r == nil {
		return 0
	}
	return len(r.PausedScans) + len(r.PausedReports) + len(r.PausedWorkflow)
}

// OffboardResult reports what an offboarding changed.
type OffboardResult struct {
	Report              *AccessReport `json:"report"`
	RevokedKeys         int           `json:"revoked_keys"`
	RemovedGroups       int           `json:"removed_groups"`
	RemovedGrants       int           `json:"removed_grants"`
	RemovedCampaigns    int           `json:"removed_campaigns"`
	ReassignedSchedules int           `json:"reassigned_schedules"`
	ReassignedFindings  int           `json:"reassigned_findings"`
	ReassignedAssets    int           `json:"reassigned_assets"`
	OffboardedAt        time.Time     `json:"offboarded_at"`
}

// ReassignmentError carries the categories an offboarding plan left uncovered.
type ReassignmentError struct {
	Missing []string
}

func (e *ReassignmentError) Error() string {
	return fmt.Sprintf("%s (missing: %v)", ErrReassignmentRequired.Error(), e.Missing)
}

// Unwrap lets errors.Is match ErrReassignmentRequired.
func (e *ReassignmentError) Unwrap() error { return ErrReassignmentRequired }

// AsReassignmentError extracts a *ReassignmentError.
func AsReassignmentError(err error) (*ReassignmentError, bool) {
	var re *ReassignmentError
	ok := errors.As(err, &re)
	return re, ok
}

// LifecycleRepository applies the member lifecycle. Every method runs in one
// transaction and is tenant-scoped: the tenant comes from the membership row,
// which the caller loaded with the caller's own tenant.
type LifecycleRepository interface {
	// AccessReport lists what the member holds and owns in the tenant.
	AccessReport(ctx context.Context, m *Membership) (*AccessReport, error)
	// Disable suspends the membership, suspends the member's API keys,
	// pauses the schedules they own and drops their materialized scope.
	// Groups, grants and ownership stay as they are.
	Disable(ctx context.Context, m *Membership) (*DisableResult, error)
	// Reenable reactivates the membership, re-activates the keys a disable
	// suspended and recomputes the materialized scope. Paused schedules stay
	// paused for an administrator to resume.
	Reenable(ctx context.Context, m *Membership) error
	// Offboard checks the plan against the member's current holdings,
	// reassigns owned work, strips every access source and turns the
	// membership into a tombstone.
	Offboard(ctx context.Context, m *Membership, actor *shared.ID, plan OffboardPlan) (*OffboardResult, error)
	// Rejoin re-activates an offboarded tombstone with a new role (from zero).
	Rejoin(ctx context.Context, m *Membership) error
	// ErasePersonalData anonymises the user's name and email and clears
	// their credentials. Allowed only when the membership in tenantID is
	// offboarded and the user has no other non-offboarded membership.
	ErasePersonalData(ctx context.Context, tenantID, userID shared.ID, label string) error
	// ActiveAdminIDs returns the active owners and administrators of the tenant.
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}
