package auth

// The personal organization at sign-up (docs/architecture/user-onboarding.md,
// "Personal organization at sign-up"): with the sign-up policy switch on, a
// person who signed up by self-service and has no other way in gets their own
// organization at their first sign-in after their address is verified.

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/server/pkg/domain/signup"
	"github.com/openctemio/openctem/server/pkg/domain/signupevent"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
	"github.com/openctemio/openctem/server/pkg/emaildomain"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Rate bounds of automatic creation. Above them nothing is made and the
// person keeps the normal "create your organization" step (which has its own
// limits), so a bound never locks anyone out.
const (
	personalOrgPerPrefixPerHour = 5
	personalOrgPerDomainPerHour = 50
	personalOrgSlugAttempts     = 3
)

// PersonalOrganizations marks self-service sign-ups and makes their
// organization. A nil *PersonalOrganizations does nothing.
type PersonalOrganizations struct {
	repo        tenantdom.PersonalOrgRepository
	policy      signupdom.PolicySource
	domains     signupdom.DomainPolicySource
	invitations InvitationLookup
	limits      SelfServiceLimits
	signups     signupevent.Recorder
	audit       *auditapp.AuditService
	log         *logger.Logger
	rates       tenantdom.PersonalOrgRates
	now         func() time.Time
}

// NewPersonalOrganizations creates the service.
func NewPersonalOrganizations(repo tenantdom.PersonalOrgRepository, policy signupdom.PolicySource, log *logger.Logger) *PersonalOrganizations {
	if log == nil {
		log = logger.NewNop()
	}
	return &PersonalOrganizations{repo: repo, policy: policy, log: log.With("service", "personal_organization"),
		rates: tenantdom.PersonalOrgRates{PerPrefix: personalOrgPerPrefixPerHour, PerDomain: personalOrgPerDomainPerHour, Window: time.Hour},
		now:   time.Now}
}

// SetDomainPolicy wires the per-domain sign-up policy of claimed domains.
func (p *PersonalOrganizations) SetDomainPolicy(src signupdom.DomainPolicySource) { p.domains = src }

// SetInvitationLookup wires the pending-invitation check.
func (p *PersonalOrganizations) SetInvitationLookup(l InvitationLookup) { p.invitations = l }

// SetLimits wires the self-service limits (per-person cap, starting limits).
func (p *PersonalOrganizations) SetLimits(l SelfServiceLimits) { p.limits = l }

// SetSignupRecorder wires the console sign-ups feed.
func (p *PersonalOrganizations) SetSignupRecorder(r signupevent.Recorder) { p.signups = r }

// SetAuditService wires the tenant.created audit event.
func (p *PersonalOrganizations) SetAuditService(a *auditapp.AuditService) { p.audit = a }

// SetRates replaces the rate bounds (tests).
func (p *PersonalOrganizations) SetRates(r tenantdom.PersonalOrgRates) { p.rates = r }

func (p *PersonalOrganizations) enabled(ctx context.Context) bool {
	return p != nil && p.repo != nil && p.policy != nil && p.policy.Current(ctx).CreatesPersonalOrganization()
}

// Reserve marks an account just created by self-service sign-up (outcome
// self_service, no invitation). It does nothing while the switch is off. A
// failure is logged: the account keeps the normal step.
func (p *PersonalOrganizations) Reserve(ctx context.Context, userID shared.ID, outcome signupdom.Outcome) {
	if outcome != signupdom.OutcomeSelfService || !p.enabled(ctx) {
		return
	}
	if err := p.repo.ReservePersonalOrganization(ctx, userID, p.now().UTC()); err != nil {
		p.log.Warn("mark account for a personal organization", "user_id", userID.String(), "error", err)
	}
}

// Ensure makes the account's personal organization when it is due: the
// switch is on, the account is marked pending, its address is verified and
// it has no other way in. It never fails the sign-in that calls it: any
// refusal or error leaves the account as it was (it still has the normal
// "create your organization" step). It returns the organization made, or
// nil.
func (p *PersonalOrganizations) Ensure(ctx context.Context, u *userdom.User, ip, userAgent string) *tenantdom.Tenant {
	if u == nil || !p.enabled(ctx) || !u.EmailVerified() {
		return nil
	}
	pending, err := p.repo.PersonalOrganizationPending(ctx, u.ID(), p.now().UTC())
	if err != nil {
		p.log.Warn("read personal organization mark", "error", err)
		return nil
	}
	if !pending {
		return nil
	}
	t, err := p.create(ctx, u, ip)
	switch {
	case err == nil:
	case errors.Is(err, tenantdom.ErrPersonalOrgNotPending), errors.Is(err, tenantdom.ErrPersonalOrgHasMembership):
		return nil
	case errors.Is(err, errPersonalOrgNotAdmitted), errors.Is(err, tenantdom.ErrPersonalOrgInvited),
		errors.Is(err, tenantdom.ErrPersonalOrgDomainClaimed):
		p.log.Info("personal organization not made: the account has another way in", "user_id", u.ID().String())
		return nil
	case errors.Is(err, tenantdom.ErrPersonalOrgRateLimited):
		p.log.Warn("personal organization not made: rate bound reached", "user_id", u.ID().String(),
			"email_domain", signupevent.EmailDomain(u.Email()))
		return nil
	default:
		p.log.Warn("personal organization not made", "user_id", u.ID().String(), "error", err)
		return nil
	}

	recordSignup(ctx, p.signups, signupevent.Event{Kind: signupevent.KindOrganizationCreated,
		Source: signupevent.SourcePersonalOrganization, Email: u.Email(), TenantID: t.ID(), UserID: u.ID()})
	p.log.Info("personal organization made", "user_id", u.ID().String(), "tenant_id", t.ID().String())
	if p.audit != nil {
		actx := auditapp.AuditContext{TenantID: t.ID().String(), ActorID: u.ID().String(), ActorEmail: u.Email(),
			ActorIP: ip, UserAgent: userAgent}
		ev := auditapp.NewSuccessEvent(auditdom.ActionTenantCreated, auditdom.ResourceTypeTenant, t.ID().String()).
			WithResourceName(t.Name()).
			WithMessage("Personal organization created at sign-up").
			WithMetadata("via", "personal_organization")
		if aerr := p.audit.LogEvent(ctx, actx, ev); aerr != nil {
			p.log.Error("write audit for personal organization", "error", aerr)
		}
	}
	return t
}

var errPersonalOrgNotAdmitted = errors.New("personal organization: not admitted")

func (p *PersonalOrganizations) create(ctx context.Context, u *userdom.User, ip string) (*tenantdom.Tenant, error) {
	facts, err := signupdom.FactsForEmail(ctx, p.domains, u.Email())
	if err != nil {
		return nil, fmt.Errorf("domain sign-up policy: %w", err)
	}
	invited := false
	if p.invitations != nil {
		if invited, err = p.invitations.HasPendingInvitationForEmail(ctx, u.Email()); err != nil {
			return nil, fmt.Errorf("pending invitation: %w", err)
		}
	}
	id := facts.Apply(signupdom.Identity{
		Intent:          signupdom.IntentPersonalOrganization,
		EmailVerified:   u.EmailVerified(),
		InvitedPending:  invited,
		DisposableEmail: disposableEmail(u.Email()),
	})
	if signupdom.Admit(p.policy.Current(ctx), id) != signupdom.OutcomePersonalOrganization {
		return nil, errPersonalOrgNotAdmitted
	}

	var start limits.Limits
	if p.limits != nil {
		if err := p.limits.CheckOrgsPerUser(ctx, u.ID()); err != nil {
			return nil, err
		}
		if start, _, err = p.limits.SelfServiceDefaults(ctx); err != nil {
			return nil, fmt.Errorf("read self-service default limits: %w", err)
		}
	}

	domain := signupevent.EmailDomain(u.Email())
	name := tenantdom.PersonalOrgName(u.Name(), u.Email(), u.Preferences().Language)
	for attempt := 0; ; attempt++ {
		slug, err := tenantdom.PersonalOrgSlug(u.Name(), u.Email())
		if err != nil {
			return nil, err
		}
		t, err := tenantdom.NewTenant(name, slug, u.ID().String())
		if err != nil {
			return nil, err
		}
		if p.limits != nil {
			t.SetInitialLimits(limits.SelfServiceRows(t.ID(), start, t.CreatedAt()))
		}
		m, err := tenantdom.NewOwnerMembership(u.ID(), t.ID())
		if err != nil {
			return nil, err
		}
		err = p.repo.CreatePersonalOrganization(ctx, tenantdom.PersonalOrgCreation{
			UserID: u.ID(), Email: u.Email(), Tenant: t, Membership: m,
			EmailDomain: domain, IPPrefix: signupevent.IPPrefix(ip),
			Rates: p.ratesFor(domain), At: p.now().UTC(),
		})
		if errors.Is(err, tenantdom.ErrPersonalOrgSlugTaken) && attempt+1 < personalOrgSlugAttempts {
			continue
		}
		if err != nil {
			return nil, err
		}
		return t, nil
	}
}

// ratesFor gives the rate bounds for an address domain: the per-domain bound
// does not apply to a consumer mailbox provider (see PersonalOrgRates); the
// list is pkg/emaildomain's, the one used by every sign-up rule.
func (p *PersonalOrganizations) ratesFor(domain string) tenantdom.PersonalOrgRates {
	r := p.rates
	if emaildomain.IsConsumer(domain) {
		r.PerDomain = 0
	}
	return r
}
