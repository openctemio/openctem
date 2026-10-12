// Package accessrequest holds requests for an organization made by people who
// cannot sign up (the sign-up policy is admin_only and allows requests). A
// platform administrator approves one (the organization is created with the
// requester as its owner) or rejects it. Platform data: requests belong to no
// organization (docs/architecture/user-onboarding.md, "Request access").
package accessrequest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Status of a request.
type Status string

const (
	// StatusUnconfirmed: submitted; the requester has not opened the emailed
	// confirmation link yet. Purged after UnconfirmedTTL.
	StatusUnconfirmed Status = "unconfirmed"
	// StatusPending: confirmed (or no email could be sent); waits for an administrator.
	StatusPending Status = "pending"
	// StatusApproved: the organization was created.
	StatusApproved Status = "approved"
	// StatusRejected: an administrator declined it.
	StatusRejected Status = "rejected"
)

// IsValid reports whether s is a known status.
func (s Status) IsValid() bool {
	switch s {
	case StatusUnconfirmed, StatusPending, StatusApproved, StatusRejected:
		return true
	}
	return false
}

// Retention and limits.
const (
	// UnconfirmedTTL: an unconfirmed request is deleted after this.
	UnconfirmedTTL = 24 * time.Hour
	// DecidedRetention: an approved or rejected request is deleted after this.
	DecidedRetention = 90 * 24 * time.Hour
	// MaxPerIPPerHour and MaxPerDomainPerDay bound submissions; requests over
	// a limit are dropped silently (the requester sees the same answer).
	MaxPerIPPerHour    = 3
	MaxPerDomainPerDay = 5
	// Field bounds.
	MaxCompanyLen = 200
	MaxNoteLen    = 1000
)

// Errors.
var (
	ErrNotFound      = fmt.Errorf("%w: access request not found", shared.ErrNotFound)
	ErrInvalid       = fmt.Errorf("%w: invalid access request", shared.ErrValidation)
	ErrNotDecidable  = fmt.Errorf("%w: the access request is not pending", shared.ErrConflict)
	ErrInvalidToken  = fmt.Errorf("%w: invalid or expired confirmation link", shared.ErrValidation)
	ErrAlreadyExists = fmt.Errorf("%w: access request already exists", shared.ErrConflict)
)

// Request is one access request.
type Request struct {
	ID          shared.ID
	Company     string
	Email       string
	Domain      string
	Note        string
	Status      Status
	IPHash      string
	ConfirmHash string // hash of the emailed confirmation token; empty once used
	ConfirmedAt *time.Time
	CreatedAt   time.Time
	DecidedAt   *time.Time
	DecidedBy   *shared.ID // administrator id
	TenantID    *shared.ID // the organization created on approval
}

// EmailDomain returns the lower-cased domain of an email, or "".
func EmailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}

// Filter lists requests.
type Filter struct {
	Status Status // empty: pending and unconfirmed
	Limit  int
	Offset int
}

// Repository persists requests. Not tenant-scoped: only the platform console
// and the public submission endpoint use it.
type Repository interface {
	Create(ctx context.Context, r *Request) error
	GetByID(ctx context.Context, id shared.ID) (*Request, error)
	GetByConfirmHash(ctx context.Context, hash string) (*Request, error)
	// Update writes the mutable fields (status, confirmation, decision) when
	// the stored status is still expected; ErrNotDecidable otherwise (two
	// administrators deciding at once, a link used twice).
	Update(ctx context.Context, r *Request, expected Status) error
	List(ctx context.Context, f Filter) ([]*Request, int, error)
	// CountSince counts requests from an IP hash or for a domain since t
	// (either key may be empty to skip it).
	CountByIPSince(ctx context.Context, ipHash string, since time.Time) (int, error)
	CountByDomainSince(ctx context.Context, domain string, since time.Time) (int, error)
	// Purge deletes unconfirmed requests created before unconfirmedBefore and
	// decided requests decided before decidedBefore.
	Purge(ctx context.Context, unconfirmedBefore, decidedBefore time.Time) (int64, error)
}
