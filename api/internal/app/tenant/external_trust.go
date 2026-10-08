package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ExternalFromHomeLister lists a host's active external members homed in one
// organization (TenantRepository.ListActiveExternalFromHome).
type ExternalFromHomeLister interface {
	ListActiveExternalFromHome(ctx context.Context, host, home shared.ID) ([]*tenantdom.Membership, error)
}

// SuspendExternalMembersFromHome suspends, in host only, every active external
// member homed in home (the trust between them ended). Each suspension cuts
// that member's access to host, ends the sessions host's IdP signed in, and
// is audited; administrators of host are told once. Returns how many were
// suspended.
func (s *TenantService) SuspendExternalMembersFromHome(ctx context.Context, host, home shared.ID, reason string) (int, error) {
	lister, ok := s.repo.(ExternalFromHomeLister)
	if !ok {
		return 0, nil
	}
	members, err := lister.ListActiveExternalFromHome(ctx, host, home)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, m := range members {
		if err := s.suspendExternalMember(ctx, m, reason); err != nil {
			s.logger.Warn("failed to suspend an external member",
				"tenant_id", host.String(), "membership_id", m.ID().String(), "error", err)
			continue
		}
		done++
	}
	if done > 0 {
		s.notifyAdmins(ctx, host, "External members suspended",
			fmt.Sprintf("%d member(s) from an organization you no longer trust were suspended. Open Members to review them.", done),
			notificationdom.SeverityMedium)
	}
	return done, nil
}

func (s *TenantService) suspendExternalMember(ctx context.Context, m *tenantdom.Membership, reason string) error {
	if err := m.SuspendExternal(reason); err != nil {
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
	s.logAudit(ctx, auditapp.AuditContext{TenantID: m.TenantID().String(), ActorEmail: "system:" + reason},
		auditapp.NewSuccessEvent(audit.ActionMemberSuspended, audit.ResourceTypeMembership, m.ID().String()).
			WithSeverity(audit.SeverityMedium).
			WithMessage("External member suspended").
			WithMetadata("user_id", m.UserID().String()).
			WithMetadata("reason", reason))
	return nil
}

// NotifyAdmins tells every active owner and administrator of tenantID,
// in-app (best effort).
func (s *TenantService) NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body, severity string) {
	s.notifyAdmins(ctx, tenantID, title, body, severity)
}

// TenantName returns an organization's display name (empty when unknown).
func (s *TenantService) TenantName(ctx context.Context, tenantID shared.ID) string {
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil || t == nil {
		return ""
	}
	return t.Name()
}
