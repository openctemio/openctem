package scangov

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Status of an approval request.
type Status string

// Statuses.
const (
	StatusPending    Status = "pending"
	StatusApproved   Status = "approved"
	StatusRejected   Status = "rejected"
	StatusExpired    Status = "expired"
	StatusSuperseded Status = "superseded"
	StatusCanceled   Status = "canceled"
)

// Limits.
const (
	MaxJustificationLen = 2000
	MaxTicketLen        = 100
	// ReminderInterval: approvers are reminded at most this often.
	ReminderInterval = time.Hour
	// MaxEmergencyHours bounds an emergency run's window.
	MaxEmergencyHours = 24
	// DefaultEmergencyHours is an emergency window when none is given.
	DefaultEmergencyHours = 4
)

// Error codes (the handler answers them).
var (
	ErrNotPending        = shared.NewDomainError("SCAN_APPROVAL_NOT_PENDING", "this approval request is no longer pending", shared.ErrConflict)
	ErrOwnRequest        = shared.NewDomainError("SCAN_APPROVAL_OWN_REQUEST", "you requested this scan; another approver must approve it", shared.ErrForbidden)
	ErrAlreadyApproved   = shared.NewDomainError("SCAN_APPROVAL_ALREADY_APPROVED", "you already approved this request", shared.ErrConflict)
	ErrNotEligible       = shared.NewDomainError("SCAN_APPROVAL_NOT_ELIGIBLE", "the approval rule does not name you as an approver for this scan", shared.ErrForbidden)
	ErrSelfNotAllowed    = shared.NewDomainError("SELF_APPROVAL_NOT_ALLOWED", "you may approve your own scan only as its organization's owner, when no other approver can", shared.ErrForbidden)
	ErrReminderTooSoon   = shared.NewDomainError("REMINDER_TOO_SOON", "the approvers were reminded less than an hour ago", shared.ErrConflict)
	ErrApprovalRequired  = shared.NewDomainError("SCAN_APPROVAL_REQUIRED", "this scan needs an approval before it runs; submit it for approval", shared.ErrForbidden)
	ErrApprovalPending   = shared.NewDomainError("SCAN_APPROVAL_PENDING", "this scan is waiting for approval; it runs once approved", shared.ErrForbidden)
	ErrNotRequired       = shared.NewDomainError("SCAN_APPROVAL_NOT_REQUIRED", "this scan needs no approval under the organization's rules", shared.ErrValidation)
	ErrEvidenceMissing   = shared.NewDomainError("SCAN_APPROVAL_EVIDENCE", "the approval request is missing required evidence", shared.ErrValidation)
	ErrEmergencyNotAdmin = shared.NewDomainError("EMERGENCY_RUN_NOT_ALLOWED", "only an owner or administrator may start an emergency run", shared.ErrForbidden)
	ErrGovernanceOff     = shared.NewDomainError("SCAN_APPROVAL_OFF", "scan approval is off for this organization", shared.ErrValidation)
)

// Approval is one person's approval of a request.
type Approval struct {
	UserID     string    `json:"user_id"`
	ApprovedAt time.Time `json:"approved_at"`
	Note       string    `json:"note,omitempty"`
	// Self: the requester's own approval as the organization's sole
	// available approver, proven with a fresh authenticator code.
	Self bool `json:"self,omitempty"`
	// Emergency: an owner's or administrator's emergency run.
	Emergency bool `json:"emergency,omitempty"`
}

// Request is an approval request for one scan definition.
type Request struct {
	ID       shared.ID
	TenantID shared.ID
	ScanID   shared.ID
	// ScanName is the scan's name when read (not stored on the request).
	ScanName   string
	Status     Status
	Digest     string
	Definition Definition
	// Changes from the last approved definition of the scan (re-approval).
	Changes    []Change
	Evaluation Evaluation
	// Evidence.
	Justification string
	Ticket        string
	// RunOnApproval: start a run as the requester once approved.
	RunOnApproval bool
	RequestedBy   string
	RequestedAt   time.Time
	ExpiresAt     time.Time
	Approvals     []Approval
	// ValidUntil: an approved request stops authorizing runs then (nil:
	// until the definition changes).
	ValidUntil *time.Time
	// ConsumedAt: a run-only approval was used by this run.
	ConsumedAt   *time.Time
	DecidedAt    *time.Time
	DecidedBy    string
	DecisionNote string
	RemindedAt   *time.Time
	Emergency    bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NewRequest opens a pending request for definition d under evaluation ev.
func NewRequest(tenantID, scanID shared.ID, d Definition, ev Evaluation, requester, justification, ticket string,
	runOnApproval bool, pendingDays int, now time.Time,
) *Request {
	if pendingDays < 1 || pendingDays > MaxPendingDays {
		pendingDays = DefaultPendingDays
	}
	now = now.UTC()
	return &Request{
		ID: shared.NewID(), TenantID: tenantID, ScanID: scanID, Status: StatusPending,
		Definition: d.Canonical(), Digest: d.Digest(), Evaluation: ev,
		Justification: strings.TrimSpace(justification), Ticket: strings.TrimSpace(ticket),
		RunOnApproval: runOnApproval, RequestedBy: requester, RequestedAt: now,
		ExpiresAt: now.Add(time.Duration(pendingDays) * 24 * time.Hour), Approvals: []Approval{},
		CreatedAt: now, UpdatedAt: now,
	}
}

// IsPending reports whether r still waits for approvers at now.
func (r *Request) IsPending(now time.Time) bool {
	return r.Status == StatusPending && now.Before(r.ExpiresAt)
}

// Remaining is how many approvals r still needs.
func (r *Request) Remaining() int {
	return max(0, r.Evaluation.Approvals-len(r.Approvals))
}

// HasApproved reports whether userID approved r.
func (r *Request) HasApproved(userID string) bool {
	return slices.ContainsFunc(r.Approvals, func(a Approval) bool { return a.UserID == userID })
}

// Approve records userID's approval. The caller checked that userID is an
// approver the rule allows (EligibleFor). The request is approved once it
// has enough.
func (r *Request) Approve(userID, note string, now time.Time) error {
	switch {
	case !r.IsPending(now):
		return ErrNotPending
	case userID == "" || userID == r.RequestedBy:
		return ErrOwnRequest
	case r.HasApproved(userID):
		return ErrAlreadyApproved
	}
	r.Approvals = append(r.Approvals, Approval{UserID: userID, ApprovedAt: now.UTC(), Note: strings.TrimSpace(note)})
	r.settle(now)
	return nil
}

// SelfApprove records the requester's own approval (counts once). The
// caller checked the owner role, the fresh authenticator code and that the
// other approvers cannot give the remaining approvals.
func (r *Request) SelfApprove(userID, reason string, now time.Time) error {
	switch {
	case !r.IsPending(now):
		return ErrNotPending
	case userID == "" || userID != r.RequestedBy || r.HasApproved(userID):
		return ErrSelfNotAllowed
	}
	r.Approvals = append(r.Approvals, Approval{UserID: userID, ApprovedAt: now.UTC(), Note: strings.TrimSpace(reason), Self: true})
	r.settle(now)
	return nil
}

func (r *Request) settle(now time.Time) {
	r.UpdatedAt = now.UTC()
	if r.Remaining() > 0 {
		return
	}
	r.Status = StatusApproved
	at := now.UTC()
	r.DecidedAt = &at
	if r.Evaluation.Validity == ValidityDays && r.Evaluation.ValidityDays > 0 {
		until := at.Add(time.Duration(r.Evaluation.ValidityDays) * 24 * time.Hour)
		r.ValidUntil = &until
	}
}

// Reject closes r. The requester cancels instead (Cancel).
func (r *Request) Reject(userID, note string, now time.Time) error {
	switch {
	case !r.IsPending(now):
		return ErrNotPending
	case userID == "" || userID == r.RequestedBy:
		return ErrOwnRequest
	}
	at := now.UTC()
	r.Status, r.DecidedAt, r.DecidedBy, r.DecisionNote, r.UpdatedAt = StatusRejected, &at, userID, strings.TrimSpace(note), at
	return nil
}

// Cancel withdraws the requester's own pending request.
func (r *Request) Cancel(userID string, now time.Time) error {
	if !r.IsPending(now) {
		return ErrNotPending
	}
	if userID != r.RequestedBy {
		return ErrNotEligible
	}
	at := now.UTC()
	r.Status, r.DecidedAt, r.DecidedBy, r.UpdatedAt = StatusCanceled, &at, userID, at
	return nil
}

// NewEmergency is an owner's or administrator's emergency approval of
// definition d for hours (1–24): approved at once, valid for the window,
// recorded with the reason.
func NewEmergency(tenantID, scanID shared.ID, d Definition, ev Evaluation, actor, reason string, hours int, now time.Time) *Request {
	if hours < 1 || hours > MaxEmergencyHours {
		hours = DefaultEmergencyHours
	}
	r := NewRequest(tenantID, scanID, d, ev, actor, reason, "", false, 1, now)
	at := now.UTC()
	until := at.Add(time.Duration(hours) * time.Hour)
	r.Status, r.Emergency, r.DecidedAt, r.DecidedBy, r.ValidUntil = StatusApproved, true, &at, actor, &until
	r.ExpiresAt = until
	r.Approvals = []Approval{{UserID: actor, ApprovedAt: at, Note: strings.TrimSpace(reason), Emergency: true}}
	r.Evaluation.Validity, r.Evaluation.ValidityDays = ValidityDays, 0
	return r
}

// Authorizes reports whether an approved r lets a run of the definition
// with digest start at now.
func (r *Request) Authorizes(digest string, now time.Time) bool {
	if r == nil || r.Status != StatusApproved || r.Digest != digest {
		return false
	}
	if r.ValidUntil != nil && !now.Before(*r.ValidUntil) {
		return false
	}
	return !(r.Evaluation.Validity == ValidityRun && r.ConsumedAt != nil)
}

// Approver is a member who may approve scans (owner, admin, or a role
// holding scans:approve).
type Approver struct {
	UserID string
	Name   string
	Email  string
	Role   string
}

// EligibleFor reports whether a may approve r under the decisive rule's
// approver limits: never the requester; when the rule names roles or
// people, a's role or id must be among them.
func (r *Request) EligibleFor(a Approver) bool {
	if a.UserID == "" || a.UserID == r.RequestedBy {
		return false
	}
	roles, users := r.Evaluation.ApproverRoles, r.Evaluation.ApproverUserIDs
	if len(roles) == 0 && len(users) == 0 {
		return true
	}
	return slices.Contains(roles, a.Role) || slices.Contains(users, a.UserID)
}

// Eligible are the approvers of all who may still approve r.
func (r *Request) Eligible(all []Approver) []Approver {
	out := make([]Approver, 0, len(all))
	for _, a := range all {
		if r.EligibleFor(a) && !r.HasApproved(a.UserID) {
			out = append(out, a)
		}
	}
	return out
}

// SelfApprovalAllowed reports whether viewer may approve their own request:
// they requested it, are an owner, and the other eligible approvers cannot
// give the remaining approvals.
func (r *Request) SelfApprovalAllowed(viewer string, all []Approver, now time.Time) bool {
	if !r.IsPending(now) || viewer == "" || viewer != r.RequestedBy || r.HasApproved(viewer) {
		return false
	}
	owner := slices.ContainsFunc(all, func(a Approver) bool { return a.UserID == viewer && a.Role == RoleOwner })
	return owner && len(r.Eligible(all)) < r.Remaining()
}

// Repository persists approval requests. Every method is tenant-scoped.
type Repository interface {
	Create(ctx context.Context, r *Request) error
	// Update saves r when its stored status is still pending (or, for a
	// consumed run-only approval, approved); false when it changed.
	Update(ctx context.Context, r *Request, expect Status) (bool, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*Request, error)
	// Pending returns the scan's pending request, nil when none.
	Pending(ctx context.Context, tenantID, scanID shared.ID) (*Request, error)
	// ApprovedFor returns the scan's newest approved request for digest,
	// nil when none.
	ApprovedFor(ctx context.Context, tenantID, scanID shared.ID, digest string) (*Request, error)
	// LastApproved returns the scan's newest approved request, nil when none.
	LastApproved(ctx context.Context, tenantID, scanID shared.ID) (*Request, error)
	// SupersedePending closes the scan's pending requests whose digest is
	// not keep ("" closes all).
	SupersedePending(ctx context.Context, tenantID, scanID shared.ID, keep string, now time.Time) error
	// Consume marks a run-only approval used; false when already used.
	Consume(ctx context.Context, tenantID, id shared.ID, now time.Time) (bool, error)
	// MarkReminded records a reminder when the last was at least interval
	// ago; false otherwise.
	MarkReminded(ctx context.Context, tenantID, id shared.ID, now time.Time, interval time.Duration) (bool, error)
	// ExpireOverdue marks the tenant's overdue pending requests expired.
	ExpireOverdue(ctx context.Context, tenantID shared.ID, now time.Time) (int, error)
	List(ctx context.Context, f ListFilter) ([]*Request, int, error)
	// LatestByScans returns the newest request of each scan, keyed by
	// scan id.
	LatestByScans(ctx context.Context, tenantID shared.ID, scanIDs []shared.ID) (map[shared.ID]*Request, error)
}

// ListFilter selects a tenant's requests.
type ListFilter struct {
	TenantID shared.ID
	Statuses []Status
	ScanID   *shared.ID
	Limit    int
	Offset   int
}
