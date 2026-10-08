package tenant

// Home cascade (RFC-058): the home organization controls the person. When it
// disables or removes them, or stops holding their email domain, every
// external membership homed there is suspended in its host at once; when the
// cause is reversed (the home re-enables them, re-verifies the domain), those
// memberships come back unless the host changed them meanwhile.
//
// Isolation: each suspension happens in its host only and is audited there;
// the home's own log records how many external memberships were affected,
// never anything about the hosts' data.

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// HomedLister lists external memberships by home organization
// (TenantRepository.ListExternalHomed).
type HomedLister interface {
	ListExternalHomed(ctx context.Context, f tenantdom.HomedFilter) ([]*tenantdom.Membership, error)
}

// homeAccessEnded runs after the home organization disabled or removed a
// person: their external memberships elsewhere are suspended, and, because
// the organization that owns their identity let them go, every session ends.
func (s *TenantService) homeAccessEnded(ctx context.Context, home shared.ID, user shared.ID) {
	uid := user
	n := s.suspendHomed(ctx, tenantdom.HomedFilter{Home: home, User: &uid}, tenantdom.SuspendedReasonHomeAccessEnded,
		"A member's own organization removed them",
		"A member from another organization was disabled or removed by that organization; their access here is suspended.")
	if n > 0 {
		s.logAudit(ctx, auditapp.AuditContext{TenantID: home.String(), ActorEmail: "system:home-cascade"},
			auditapp.NewSuccessEvent(audit.ActionMemberSuspended, audit.ResourceTypeMembership, user.String()).
				WithSeverity(audit.SeverityHigh).
				WithMessage(fmt.Sprintf("Access to %d other organization(s) suspended because this organization disabled the person", n)).
				WithMetadata("user_id", user.String()).
				WithMetadata("external_memberships_suspended", n))
	}
	if s.homeOf(ctx, user) == home && s.sessionService != nil {
		if err := s.sessionService.RevokeAllSessions(ctx, user.String(), ""); err != nil {
			s.logger.Warn("failed to revoke sessions after the home organization cut a person", "error", err)
		}
	}
}

// homeAccessRestored runs after the home organization re-enabled a person:
// the memberships the cascade suspended come back.
func (s *TenantService) homeAccessRestored(ctx context.Context, home shared.ID, user shared.ID) {
	uid := user
	s.restoreHomed(ctx, tenantdom.HomedFilter{Home: home, User: &uid, SuspendedReason: tenantdom.SuspendedReasonHomeAccessEnded})
}

// HomeDomainLost is called when an organization stops holding an SSO domain
// (its DNS proof lapsed, or it removed the domain): members homed there by
// that domain are suspended in their hosts (fail closed: nobody manages them
// any more).
func (s *TenantService) HomeDomainLost(ctx context.Context, home shared.ID, domain string) {
	s.suspendHomed(ctx, tenantdom.HomedFilter{Home: home, Domain: strings.ToLower(domain)}, tenantdom.SuspendedReasonHomeDomainLapsed,
		"External members suspended",
		"The organization that manages some of your external members no longer holds their email domain; their access is suspended until it does.")
}

// HomeDomainRestored is called when an organization proves an SSO domain
// again: the members the lapse suspended come back.
func (s *TenantService) HomeDomainRestored(ctx context.Context, home shared.ID, domain string) {
	s.restoreHomed(ctx, tenantdom.HomedFilter{Home: home, Domain: strings.ToLower(domain), SuspendedReason: tenantdom.SuspendedReasonHomeDomainLapsed})
}

func (s *TenantService) suspendHomed(ctx context.Context, f tenantdom.HomedFilter, reason, title, body string) int {
	lister, ok := s.repo.(HomedLister)
	if !ok {
		return 0
	}
	members, err := lister.ListExternalHomed(ctx, f)
	if err != nil {
		s.logger.Error("home cascade: list external members", "home_tenant_id", f.Home.String(), "error", err)
		return 0
	}
	hosts := map[shared.ID]bool{}
	n := 0
	for _, m := range members {
		if err := s.suspendExternalMember(ctx, m, reason); err != nil {
			s.logger.Warn("home cascade: suspend", "tenant_id", m.TenantID().String(), "error", err)
			continue
		}
		hosts[m.TenantID()] = true
		n++
	}
	for host := range hosts {
		s.notifyAdmins(ctx, host, title, body, notificationdom.SeverityHigh)
	}
	return n
}

func (s *TenantService) restoreHomed(ctx context.Context, f tenantdom.HomedFilter) {
	lister, ok := s.repo.(HomedLister)
	if !ok {
		return
	}
	members, err := lister.ListExternalHomed(ctx, f)
	if err != nil {
		s.logger.Error("home cascade: list suspended external members", "home_tenant_id", f.Home.String(), "error", err)
		return
	}
	for _, m := range members {
		if m.IsExpired(time.Now().UTC()) {
			continue // its own end of access passed meanwhile: the host decides
		}
		if err := m.Reactivate(); err != nil {
			continue
		}
		if s.lifecycle != nil {
			err = s.lifecycle.Reenable(ctx, m)
		} else {
			err = s.repo.UpdateMembershipStatus(ctx, m)
		}
		if err != nil {
			s.logger.Warn("home cascade: restore", "tenant_id", m.TenantID().String(), "error", err)
			continue
		}
		s.invalidateUserPermissions(ctx, m.TenantID().String(), m.UserID().String())
		s.invalidateMembershipCache(ctx, m.TenantID().String(), m.UserID().String())
		s.logAudit(ctx, auditapp.AuditContext{TenantID: m.TenantID().String(), ActorEmail: "system:home-cascade"},
			auditapp.NewSuccessEvent(audit.ActionMemberReactivated, audit.ResourceTypeMembership, m.ID().String()).
				WithSeverity(audit.SeverityMedium).
				WithMessage("External member re-enabled: their own organization restored them").
				WithMetadata("user_id", m.UserID().String()))
	}
}

// homeOf returns the organization that holds the person's email domain, or
// the zero ID.
func (s *TenantService) homeOf(ctx context.Context, user shared.ID) shared.ID {
	if s.classifier == nil || s.classifier.owners == nil || s.userService == nil {
		return shared.ID{}
	}
	users, err := s.userService.GetUsersByIDs(ctx, []string{user.String()})
	if err != nil || len(users) == 0 {
		return shared.ID{}
	}
	email := users[0].Email()
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return shared.ID{}
	}
	owner, ok, err := s.classifier.owners.OwnerOfDomain(ctx, email[at+1:])
	if err != nil || !ok {
		return shared.ID{}
	}
	return owner
}
