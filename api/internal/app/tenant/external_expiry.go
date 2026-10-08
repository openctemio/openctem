package tenant

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ExpiredMembershipLister lists active memberships whose access expired
// (TenantRepository.ListExpiredMemberships), across tenants.
type ExpiredMembershipLister interface {
	ListExpiredMemberships(ctx context.Context, now time.Time, limit int) ([]*tenantdom.Membership, error)
}

// ExpireMemberships suspends the memberships whose access expired, each in its
// own tenant: tokens refused per request, caches dropped, sockets closed, the
// tenant's sessions ended, administrators told. Returns how many were
// suspended. One membership failing does not stop the others.
func (s *TenantService) ExpireMemberships(ctx context.Context, now time.Time, batch int) (int, error) {
	lister, ok := s.repo.(ExpiredMembershipLister)
	if !ok {
		return 0, nil
	}
	expired, err := lister.ListExpiredMemberships(ctx, now, batch)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, m := range expired {
		if err := s.expireMembership(ctx, m, now); err != nil {
			s.logger.Warn("failed to suspend an expired membership",
				"tenant_id", m.TenantID().String(), "membership_id", m.ID().String(), "error", err)
			continue
		}
		done++
	}
	return done, nil
}

func (s *TenantService) expireMembership(ctx context.Context, m *tenantdom.Membership, now time.Time) error {
	if err := m.SuspendExpired(now); err != nil {
		return err
	}
	var err error
	if s.lifecycle != nil {
		_, err = s.lifecycle.Disable(ctx, m)
	} else {
		err = s.repo.UpdateMembershipStatus(ctx, m)
	}
	if err != nil {
		return err
	}
	s.cutAccess(ctx, m.TenantID().String(), m.UserID().String())

	actx := auditapp.AuditContext{TenantID: m.TenantID().String(), ActorEmail: "system:access-expiry"}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionMemberSuspended, audit.ResourceTypeMembership, m.ID().String()).
		WithSeverity(audit.SeverityMedium).
		WithMessage("Member access expired").
		WithMetadata("user_id", m.UserID().String()).
		WithMetadata("reason", tenantdom.SuspendedReasonExpired).
		WithMetadata("member_kind", string(m.Kind())))
	s.notifyAdmins(ctx, m.TenantID(), "A member's access expired",
		"The access of a member from outside your organization reached its end date and was suspended. Open Members to extend it or remove them.",
		notificationdom.SeverityMedium)
	return nil
}

// ExtendMemberAccessInput sets a new end of access for an external member.
type ExtendMemberAccessInput struct {
	ExpiresAt *time.Time
	Reason    string
}

// ErrAccessNotExternal refuses an access change on an internal member.
var ErrAccessNotExternal = fmt.Errorf("%w: only members from outside the organization have an access end date", shared.ErrValidation)

// ExtendMemberAccess changes when an external member's access ends (at most
// MaxExternalAccessDays from now; mandatory when no organization manages the
// address). A membership suspended because its access expired is re-enabled.
// Owner or administrator, through the members route.
func (s *TenantService) ExtendMemberAccess(ctx context.Context, membershipID string, in ExtendMemberAccessInput, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	m, err := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if err != nil {
		return nil, err
	}
	if !m.IsExternal() {
		return nil, ErrAccessNotExternal
	}
	if err := s.authorizeMemberChange(ctx, m, actx); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	class := tenantdom.Classification{Kind: tenantdom.MemberKindExternal, HomeTenantID: m.HomeTenantID(), Domain: m.HomeDomain()}
	access := tenantdom.ExternalAccess{ExpiresAt: in.ExpiresAt, Reason: in.Reason}
	if err := m.Classify(class, access, now); err != nil {
		return nil, err
	}
	wasExpired := m.IsSuspended() && m.SuspendedReason() == tenantdom.SuspendedReasonExpired
	switch {
	case wasExpired:
		if err := m.Reactivate(); err != nil {
			return nil, err
		}
		if s.lifecycle != nil {
			err = s.lifecycle.Reenable(ctx, m)
		} else {
			err = s.repo.UpdateMembershipStatus(ctx, m)
		}
	default:
		err = s.repo.UpdateMembershipStatus(ctx, m)
	}
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}
	s.invalidateUserPermissions(ctx, m.TenantID().String(), m.UserID().String())
	s.invalidateMembershipCache(ctx, m.TenantID().String(), m.UserID().String())

	event := auditapp.NewSuccessEvent(audit.ActionMemberAccessChanged, audit.ResourceTypeMembership, m.ID().String()).
		WithSeverity(audit.SeverityMedium).
		WithMessage("Member access end date changed").
		WithMetadata("user_id", m.UserID().String()).
		WithMetadata("reenabled", wasExpired)
	if m.ExpiresAt() != nil {
		event = event.WithMetadata("access_expires_at", m.ExpiresAt().Format(time.RFC3339))
	}
	s.logAudit(ctx, actx, event)
	return m, nil
}
