// Package accountdeletion lets a person delete their own account
// (docs/rfcs/RFC-104). The request ends every session at once; signing in
// again within the grace period cancels it; afterwards the account leaves
// every organization it belongs to (through the member offboarding) and its
// personal data is erased. The users row and every foreign key to it stay,
// so history shows "Deleted user #<hash>" instead of the person.
//
// A person who is the only owner of an organization cannot delete their
// account: they transfer ownership or delete the organization first.
package accountdeletion

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Grace is how long a deletion waits before the account is erased.
const Grace = 14 * 24 * time.Hour

var (
	// ErrPlatformAdmin: a platform administrator account is removed in the
	// admin console, not here.
	ErrPlatformAdmin = fmt.Errorf("%w: a platform administrator account cannot be deleted here", shared.ErrForbidden)
	// ErrNotScheduled: no deletion is pending.
	ErrNotScheduled = fmt.Errorf("%w: no account deletion is pending", shared.ErrNotFound)
)

// SoleOwnerError lists the organizations the person is the only owner of.
// It is shown to that person only.
type SoleOwnerError struct{ Organizations []string }

func (e *SoleOwnerError) Error() string {
	return "you are the only owner of: " + strings.Join(e.Organizations, ", ") +
		"; transfer ownership or delete the organization first"
}

// Is makes errors.Is(err, shared.ErrConflict) hold.
func (e *SoleOwnerError) Is(target error) bool { return target == shared.ErrConflict }

// Membership is one organization the account belongs to.
type Membership struct {
	TenantID     shared.ID
	MembershipID string
}

// Repository persists deletion requests and erases accounts.
type Repository interface {
	// Schedule stores (or replaces) the request.
	Schedule(ctx context.Context, userID shared.ID, requestedAt, eraseAfter time.Time) error
	// Get returns when the account will be erased, or ErrNotScheduled.
	Get(ctx context.Context, userID shared.ID) (time.Time, error)
	// Cancel removes the request; false when none was pending.
	Cancel(ctx context.Context, userID shared.ID) (bool, error)
	// Due lists accounts whose grace period ended before t.
	Due(ctx context.Context, t time.Time, limit int) ([]shared.ID, error)
	// SoleOwnerOrganizations names the organizations the account is the only
	// active owner of.
	SoleOwnerOrganizations(ctx context.Context, userID shared.ID) ([]string, error)
	// IsPlatformAdmin reports whether the account is a platform administrator.
	IsPlatformAdmin(ctx context.Context, userID shared.ID) (bool, error)
	// ActiveMemberships lists the account's memberships that are not
	// offboarded.
	ActiveMemberships(ctx context.Context, userID shared.ID) ([]Membership, error)
	// RevokeAPIKeys revokes the account's API keys in every organization.
	RevokeAPIKeys(ctx context.Context, userID shared.ID) (int64, error)
	// EraseAccount anonymises the account (every membership, any status),
	// removes its second factor, federated identities, sessions and refresh
	// tokens, and deletes the request, in one transaction.
	EraseAccount(ctx context.Context, userID shared.ID, label string) error
}

// Offboarder removes the account from an organization (member offboarding;
// when the person still owns work the membership is disabled and the
// organization's administrators are asked to reassign it).
type Offboarder interface {
	DeprovisionMember(ctx context.Context, membershipID string, actx auditapp.AuditContext) error
}

// Sessions ends every session of the account.
type Sessions interface {
	RevokeAllSessions(ctx context.Context, userID, exceptSessionID string) error
}

// Service schedules, cancels and carries out account deletions.
type Service struct {
	repo     Repository
	offboard Offboarder
	sessions Sessions
	audit    *auditapp.AuditService
	label    func(shared.ID) string
	log      *logger.Logger
	now      func() time.Time
}

// NewService creates the service. label names an erased account.
func NewService(repo Repository, offboard Offboarder, sessions Sessions, audit *auditapp.AuditService, label func(shared.ID) string, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, offboard: offboard, sessions: sessions, audit: audit, label: label,
		log: log.With("service", "account-deletion"), now: time.Now}
}

// Request schedules the deletion of the account and ends all its sessions.
// It returns when the account will be erased.
func (s *Service) Request(ctx context.Context, userID shared.ID, actx auditapp.AuditContext) (time.Time, error) {
	if admin, err := s.repo.IsPlatformAdmin(ctx, userID); err != nil {
		return time.Time{}, err
	} else if admin {
		return time.Time{}, ErrPlatformAdmin
	}
	orgs, err := s.repo.SoleOwnerOrganizations(ctx, userID)
	if err != nil {
		return time.Time{}, err
	}
	if len(orgs) > 0 {
		return time.Time{}, &SoleOwnerError{Organizations: orgs}
	}
	now := s.now().UTC()
	eraseAfter := now.Add(Grace)
	if err := s.repo.Schedule(ctx, userID, now, eraseAfter); err != nil {
		return time.Time{}, err
	}
	if s.sessions != nil {
		if err := s.sessions.RevokeAllSessions(ctx, userID.String(), ""); err != nil {
			s.log.Warn("end sessions after an account deletion request", "error", err)
		}
	}
	// Keys do not come back on cancel: the person creates new ones.
	if _, err := s.repo.RevokeAPIKeys(ctx, userID); err != nil {
		return time.Time{}, err
	}
	s.record(ctx, actx, audit.ActionAccountDeletionRequested, userID, "Account deletion requested",
		map[string]any{"erase_after": eraseAfter.Format(time.RFC3339)})
	return eraseAfter, nil
}

// Status returns when the account will be erased, or ErrNotScheduled.
func (s *Service) Status(ctx context.Context, userID shared.ID) (time.Time, error) {
	return s.repo.Get(ctx, userID)
}

// CancelOnSignIn cancels a pending deletion when the person signs in again.
// It never fails the sign-in.
func (s *Service) CancelOnSignIn(ctx context.Context, userID shared.ID) {
	canceled, err := s.repo.Cancel(ctx, userID)
	if err != nil {
		s.log.Warn("cancel account deletion on sign-in", "error", err)
		return
	}
	if canceled {
		s.record(ctx, auditapp.AuditContext{ActorID: userID.String()}, audit.ActionAccountDeletionCanceled, userID,
			"Account deletion canceled by signing in", nil)
	}
}

// EraseDue erases the accounts whose grace period ended. For each, every
// membership goes through the member offboarding first, then the personal
// data is erased. It returns how many accounts were erased.
func (s *Service) EraseDue(ctx context.Context) (int64, error) {
	ids, err := s.repo.Due(ctx, s.now().UTC(), 100)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, id := range ids {
		if err := s.erase(ctx, id); err != nil {
			s.log.Error("erase account", "user_id", id.String(), "error", err)
			continue
		}
		n++
	}
	return n, nil
}

func (s *Service) erase(ctx context.Context, userID shared.ID) error {
	// Someone who became the only owner during the grace period is not
	// erased: the organization would be left without an owner.
	orgs, err := s.repo.SoleOwnerOrganizations(ctx, userID)
	if err != nil {
		return err
	}
	if len(orgs) > 0 {
		return &SoleOwnerError{Organizations: orgs}
	}
	members, err := s.repo.ActiveMemberships(ctx, userID)
	if err != nil {
		return err
	}
	for _, m := range members {
		actx := auditapp.AuditContext{TenantID: m.TenantID.String(), ActorEmail: "account-deletion"}
		// Best effort: an owner (one of several) is not offboarded and a
		// failure is logged; the erasure below still ends every way in
		// (inactive account, sessions, refresh tokens and API keys revoked).
		if err := s.offboard.DeprovisionMember(ctx, m.MembershipID, actx); err != nil && !errors.Is(err, shared.ErrNotFound) {
			s.log.Warn("offboard an account being erased", "tenant_id", m.TenantID.String(), "error", err)
		}
	}
	if err := s.repo.EraseAccount(ctx, userID, s.label(userID)); err != nil {
		return err
	}
	s.record(ctx, auditapp.AuditContext{ActorEmail: "account-deletion"}, audit.ActionAccountErased, userID,
		"Account personal data erased after the deletion grace period", nil)
	return nil
}

func (s *Service) record(ctx context.Context, actx auditapp.AuditContext, action audit.Action, userID shared.ID, msg string, meta map[string]any) {
	if s.audit == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeUser, userID.String()).WithMessage(msg).WithSeverity(audit.SeverityHigh)
	for k, v := range meta {
		ev = ev.WithMetadata(k, v)
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.log.Error("audit account deletion", "action", string(action), "error", err)
	}
}
