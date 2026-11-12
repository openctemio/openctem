package scope

// Who approves a pending scope entry (RFC-054 §7, amendment 2026-10-09).
//
// An entry waiting for approval names the people who can approve it, and its
// requester or any scope writer may remind them, at most once per
// ReminderInterval. When nobody other than the requester can give the
// approvals still needed (an organization with a single owner), the owner may
// approve their own entry: with a fresh authenticator code and a reason,
// audited at high severity and announced to every administrator. Nothing is
// ever approved automatically.

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ReminderInterval is the shortest time between two reminders of one entry.
const ReminderInterval = time.Hour

// Approver errors.
var (
	ErrSelfApprovalNotAllowed = shared.NewDomainError("SELF_APPROVAL_NOT_ALLOWED",
		"you can approve your own scope entry only as an owner and only when no other approver exists; ask one of the approvers listed on the entry", shared.ErrForbidden)
	ErrSelfApprovalNeedsReason = shared.NewDomainError("SELF_APPROVAL_REASON_REQUIRED",
		"approving your own scope entry needs a reason", shared.ErrValidation)
	ErrSelfApprovalNeedsTOTP = shared.NewDomainError("SELF_APPROVAL_NEEDS_TOTP",
		"approving your own scope entry needs a code from your authenticator app; turn on two-factor authentication first", shared.ErrForbidden)
	ErrSelfApprovalBadCode = shared.NewDomainError("SELF_APPROVAL_INVALID_CODE",
		"the authenticator code is wrong or was already used; wait for a new one", shared.ErrForbidden)
	ErrReminderTooSoon = shared.NewDomainError("REMINDER_TOO_SOON",
		"the approvers of this entry were reminded less than an hour ago", shared.ErrConflict)
)

// RemindedAt is when the approvers were last reminded (nil: never).
func (t *Target) RemindedAt() *time.Time { return t.remindedAt }

// RestoreRemindedAt sets the reminder time read from persistence.
func (t *Target) RestoreRemindedAt(at *time.Time) { t.remindedAt = at }

// RemainingApprovals is how many more distinct approvals a pending entry
// needs (0 for an entry that is not pending).
func (t *Target) RemainingApprovals() int {
	if t.status != StatusPending {
		return 0
	}
	return max(0, max(1, t.approvalsRequired)-len(t.approvals))
}

// HasApproved reports whether userID already approved the entry.
func (t *Target) HasApproved(userID string) bool {
	for _, a := range t.approvals {
		if a.UserID == userID {
			return true
		}
	}
	return false
}

// SelfApprove puts a pending entry into effect on its requester's own
// approval. The caller has established that no other approver can give the
// remaining approvals, that userID is an owner, and that a fresh second
// factor was presented; this method checks what the entry decides: pending,
// unexpired, requested by userID, a reason given.
func (t *Target) SelfApprove(userID, reason string, now time.Time) error {
	reason = strings.TrimSpace(reason)
	switch {
	case userID == "":
		return fmt.Errorf("%w: approver is required", shared.ErrValidation)
	case t.status == StatusRejected:
		return ErrEntryRejected
	case t.status != StatusPending:
		return ErrEntryNotPending
	case t.ExpiredAt(now):
		return ErrEntryExpired
	case t.createdBy != userID:
		return ErrSelfApprovalNotAllowed
	case reason == "":
		return ErrSelfApprovalNeedsReason
	case len(reason) > MaxReasonLength:
		return fmt.Errorf("%w: reason must be at most %d characters", shared.ErrValidation, MaxReasonLength)
	}
	t.approvals = append(t.approvals, Approval{UserID: userID, ApprovedAt: now, Self: true, Reason: reason})
	t.status = StatusActive
	t.approvedAt = &now
	t.updatedAt = now
	return nil
}

// Approver is a member who may approve scope entries: an active member of
// the organization, signed up, whose role is owner or administrator or who
// holds attack_surface:scope:approve. Email is used to send the request and
// is never returned by the API.
type Approver struct {
	UserID string
	Name   string
	Email  string
	Owner  bool
}

// EligibleApprovers are the approvers who can still approve t: everyone in
// all except its requester and those who already approved.
func EligibleApprovers(t *Target, all []Approver) []Approver {
	out := make([]Approver, 0, len(all))
	for _, a := range all {
		if a.UserID == "" || a.UserID == t.createdBy || t.HasApproved(a.UserID) {
			continue
		}
		out = append(out, a)
	}
	return out
}
