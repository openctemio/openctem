// Package orgtrust manages trusts between organizations (RFC-058): a host
// organization trusts a home organization, the home organization accepts,
// and external members from that home may then satisfy the host's SSO and 2FA
// policy with a session from their home identity provider.
//
// Threat model. A trust lets another organization's identity provider vouch
// for people inside the host, so:
//
//   - it is two-sided: only the host's owner may ask, only the home's owner
//     may accept (both with step-up at the route), and either side may end it;
//   - the home is named by a domain it holds verified for SSO, so a host can
//     never trust an organization that does not own the addresses it signs in;
//   - a trust grants nothing until accepted, and grants no access by itself:
//     the person still needs an invitation to the host;
//   - ending a trust suspends, in the host only, every external member homed
//     in that organization;
//   - every change is audited, at critical severity, in both organizations,
//     and both sides' administrators are told. Neither side learns anything
//     about the other beyond its name.
package orgtrust

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MaxTrustsPerOrganization caps the trusts one organization holds (as host
// or home).
const MaxTrustsPerOrganization = 200

// ErrHomeNotFound: no organization holds that domain verified for SSO.
var ErrHomeNotFound = fmt.Errorf("%w: no organization has verified this domain for single sign-on", shared.ErrNotFound)

// ErrNotYourSide refuses an action the caller's organization may not take on
// this trust (the host updates; the home accepts).
var ErrNotYourSide = fmt.Errorf("%w: your organization cannot do this on this trust", shared.ErrForbidden)

// ErrTooManyTrusts refuses a trust over MaxTrustsPerOrganization.
var ErrTooManyTrusts = fmt.Errorf("%w: too many trusted organizations", shared.ErrValidation)

// DomainOwnerLookup answers which organization holds an email domain verified
// for SSO.
type DomainOwnerLookup interface {
	OwnerOfDomain(ctx context.Context, domain string) (shared.ID, bool, error)
}

// Members is what the trust service needs from the member side.
type Members interface {
	SuspendExternalMembersFromHome(ctx context.Context, host, home shared.ID, reason string) (int, error)
	NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body, severity string)
	TenantName(ctx context.Context, tenantID shared.ID) string
}

// SSOEntitlement reports whether an organization's plan includes single
// sign-on features (trusts need it on the host). nil: every plan does.
type SSOEntitlement interface {
	HasSSO(ctx context.Context, tenantID shared.ID) (bool, error)
}

// ErrPlanLacksSSO refuses a trust on a plan without single sign-on.
var ErrPlanLacksSSO = fmt.Errorf("%w: trusted organizations need a plan with single sign-on", shared.ErrForbidden)

// Service manages trusts.
type Service struct {
	repo        orgtrust.Repository
	owners      DomainOwnerLookup
	members     Members
	audit       *auditapp.AuditService
	entitlement SSOEntitlement
	logger      *logger.Logger
}

// NewService builds the trust service.
func NewService(repo orgtrust.Repository, owners DomainOwnerLookup, members Members, auditSvc *auditapp.AuditService, log *logger.Logger) *Service {
	return &Service{repo: repo, owners: owners, members: members, audit: auditSvc, logger: log.With("service", "org_trust")}
}

// SetSSOEntitlement wires the plan check.
func (s *Service) SetSSOEntitlement(e SSOEntitlement) { s.entitlement = e }

// View is a trust seen from one of its organizations.
type View struct {
	Trust *orgtrust.Trust
	// Direction: "outgoing" (this organization is the host) or "incoming"
	// (this organization is the home).
	Direction string
	// OtherName is the other organization's name.
	OtherName string
}

// List returns the trusts tenantID is host or home of.
func (s *Service) List(ctx context.Context, tenantID shared.ID) ([]View, error) {
	trusts, err := s.repo.ListForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(trusts))
	for _, t := range trusts {
		v := View{Trust: t, Direction: "outgoing", OtherName: s.members.TenantName(ctx, t.HomeTenantID)}
		if t.HomeTenantID == tenantID {
			v.Direction = "incoming"
			v.OtherName = s.members.TenantName(ctx, t.HostTenantID)
		}
		out = append(out, v)
	}
	return out, nil
}

// Request asks to trust the organization that holds homeDomain. The caller
// is an owner of host (route) who re-authenticated (route).
func (s *Service) Request(ctx context.Context, host shared.ID, actor shared.ID, homeDomain string, settings orgtrust.Settings, actx auditapp.AuditContext) (*View, error) {
	if err := s.requireSSO(ctx, host); err != nil {
		return nil, err
	}
	home, ok, err := s.owners.OwnerOfDomain(ctx, homeDomain)
	if err != nil {
		return nil, fmt.Errorf("look up the domain holder: %w", err)
	}
	if !ok {
		return nil, ErrHomeNotFound
	}
	existing, err := s.repo.ListForTenant(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(existing) >= MaxTrustsPerOrganization {
		return nil, ErrTooManyTrusts
	}
	t, err := orgtrust.New(host, home, settings, actor)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, t); err != nil {
		return nil, err
	}
	hostName, homeName := s.members.TenantName(ctx, host), s.members.TenantName(ctx, home)
	s.record(ctx, actx, t, audit.ActionSSOTrustRequested, fmt.Sprintf("Trust requested: %s asks to trust %s", hostName, homeName))
	s.members.NotifyAdmins(ctx, home, "An organization asks to trust yours",
		fmt.Sprintf("%s asks to let your people sign in to it with your single sign-on. An owner can accept or decline it in Settings > Security > Trusted organizations.", hostName),
		notificationdom.SeverityMedium)
	return &View{Trust: t, Direction: "outgoing", OtherName: homeName}, nil
}

// Accept accepts a trust the caller's organization (home) was asked for.
// attestsMFA is the home owner's statement that its identity provider
// enforces MFA for everyone.
func (s *Service) Accept(ctx context.Context, home, id, actor shared.ID, attestsMFA bool, actx auditapp.AuditContext) (*View, error) {
	t, err := s.repo.GetForTenant(ctx, home, id)
	if err != nil {
		return nil, err
	}
	if t.HomeTenantID != home {
		return nil, ErrNotYourSide
	}
	if err := t.Accept(actor, attestsMFA, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, t); err != nil {
		return nil, err
	}
	hostName, homeName := s.members.TenantName(ctx, t.HostTenantID), s.members.TenantName(ctx, home)
	s.record(ctx, actx, t, audit.ActionSSOTrustAccepted, fmt.Sprintf("Trust accepted: %s trusts %s", hostName, homeName))
	s.members.NotifyAdmins(ctx, t.HostTenantID, "A trusted organization accepted",
		fmt.Sprintf("%s accepted your trust: its people can now sign in to your organization with their own single sign-on.", homeName),
		notificationdom.SeverityMedium)
	return &View{Trust: t, Direction: "incoming", OtherName: hostName}, nil
}

// Update changes the host's settings of a trust.
func (s *Service) Update(ctx context.Context, host, id shared.ID, settings orgtrust.Settings, actx auditapp.AuditContext) (*View, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	t, err := s.repo.GetForTenant(ctx, host, id)
	if err != nil {
		return nil, err
	}
	if t.HostTenantID != host {
		return nil, ErrNotYourSide
	}
	t.Settings = settings
	t.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, t); err != nil {
		return nil, err
	}
	s.record(ctx, actx, t, audit.ActionSSOTrustUpdated, "Trust settings changed")
	return &View{Trust: t, Direction: "outgoing", OtherName: s.members.TenantName(ctx, t.HomeTenantID)}, nil
}

// Revoke ends a trust from either side (a host withdrawing, a home declining
// or withdrawing). Every external member of the host homed in the home is
// suspended in the host.
func (s *Service) Revoke(ctx context.Context, tenantID, id shared.ID, actx auditapp.AuditContext) error {
	t, err := s.repo.GetForTenant(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	suspended := 0
	if t.IsActive() {
		n, serr := s.members.SuspendExternalMembersFromHome(ctx, t.HostTenantID, t.HomeTenantID, tenantdom.SuspendedReasonTrustRevoked)
		if serr != nil {
			s.logger.Error("suspend external members after a trust ended", "host_tenant_id", t.HostTenantID.String(), "error", serr)
		}
		suspended = n
	}
	by := "the host"
	other := t.HomeTenantID
	if tenantID == t.HomeTenantID {
		by, other = "the home organization", t.HostTenantID
	}
	s.record(ctx, actx, t, audit.ActionSSOTrustRevoked, fmt.Sprintf("Trust ended by %s; %d external member(s) suspended", by, suspended))
	s.members.NotifyAdmins(ctx, other, "A trust between organizations ended",
		fmt.Sprintf("%s ended the trust with your organization.", s.members.TenantName(ctx, tenantID)),
		notificationdom.SeverityMedium)
	return nil
}

func (s *Service) requireSSO(ctx context.Context, host shared.ID) error {
	if s.entitlement == nil {
		return nil
	}
	ok, err := s.entitlement.HasSSO(ctx, host)
	if err != nil {
		return fmt.Errorf("check the plan: %w", err)
	}
	if !ok {
		return ErrPlanLacksSSO
	}
	return nil
}

// record writes the audit row in both organizations' logs.
func (s *Service) record(ctx context.Context, actx auditapp.AuditContext, t *orgtrust.Trust, action audit.Action, message string) {
	if s.audit == nil {
		return
	}
	for _, tid := range []shared.ID{t.HostTenantID, t.HomeTenantID} {
		a := actx
		a.TenantID = tid.String()
		ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeOrgTrust, t.ID.String()).
			WithSeverity(audit.SeverityCritical).
			WithMessage(message).
			WithMetadata("host_tenant_id", t.HostTenantID.String()).
			WithMetadata("home_tenant_id", t.HomeTenantID.String()).
			WithMetadata("max_role", string(t.Settings.MaxRole)).
			WithMetadata("require_mfa_evidence", t.Settings.RequireMFAEvidence).
			WithMetadata("home_attests_mfa", t.HomeAttestsMFA)
		if err := s.audit.LogEvent(ctx, a, ev); err != nil {
			s.logger.Error("audit trust change", "error", err)
		}
	}
}

// IsNotFound reports whether err means the trust or the home is unknown.
func IsNotFound(err error) bool {
	return errors.Is(err, orgtrust.ErrNotFound) || errors.Is(err, ErrHomeNotFound)
}
