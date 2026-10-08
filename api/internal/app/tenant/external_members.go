package tenant

// External members: people who belong to an organization that does not own
// their email domain. Design: docs/rfcs/RFC-058-external-members.md.
//
// Threat model. Users are global, so one person can be a member of several
// organizations. An organization that admits someone it does not manage must
// bound what that person can do and for how long, because nobody tells it when
// the person leaves their own company:
//
//   - every external member joins as a viewer, with no data scope until a
//     host administrator adds them to a team (a member with no scope row sees
//     nothing), and can never hold the owner role (database trigger) or the
//     admin role or a full-data-access role (role grant guard);
//   - an external member no organization manages (a personal address, or a
//     work domain nobody has verified) must have an expiry, 90 days by
//     default and 365 at most; an expired membership is suspended within a
//     minute (ExpireMemberships);
//   - an external person joins only by accepting an invitation addressed to
//     them (their consent); administrators cannot add or create them directly.
//
// Classification reads the platform-wide verified SSO domains (one holder per
// domain): the holder of the address's domain is the person's home
// organization. The host learns only the home organization's name.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/emaildomain"
)

// DomainOwnerLookup answers which organization holds an email domain verified
// for SSO (domainverify.Service.OwnerOfDomain).
type DomainOwnerLookup interface {
	OwnerOfDomain(ctx context.Context, domain string) (shared.ID, bool, error)
}

// ErrExternalNeedsInvitation refuses adding or creating someone outside the
// organization directly: they join by accepting an invitation.
var ErrExternalNeedsInvitation = fmt.Errorf("%w: people outside your organization join by accepting an invitation; invite them instead", shared.ErrValidation)

// ErrExternalViewerOnly refuses an invitation that gives an external invitee
// more than the viewer role.
var ErrExternalViewerOnly = fmt.Errorf("%w: people outside your organization join as viewers; change their role after they join", shared.ErrValidation)

// AddressClassifier classifies an email address for one organization.
type AddressClassifier struct {
	owners DomainOwnerLookup
	// verifiedDomains reports whether the organization holds any verified SSO
	// domain at all.
	ownsAny func(ctx context.Context, tenantID shared.ID) (bool, error)
}

// NewAddressClassifier builds a classifier. ownsAny reports whether an
// organization has verified any SSO domain.
func NewAddressClassifier(owners DomainOwnerLookup, ownsAny func(ctx context.Context, tenantID shared.ID) (bool, error)) *AddressClassifier {
	return &AddressClassifier{owners: owners, ownsAny: ownsAny}
}

// Classify decides how email relates to organization tenantID:
//
//   - its domain is held by tenantID: internal;
//   - held by another organization: external, homed there;
//   - a consumer mail domain (gmail.com, ...): external and personal;
//   - an unclaimed work domain: external, unless tenantID has not verified any
//     domain yet (it has not said which addresses are its own, so its
//     colleagues on its unverified domain stay internal).
//
// Fail closed: a lookup error is returned, never a guess.
func (c *AddressClassifier) Classify(ctx context.Context, tenantID shared.ID, email string) (tenantdom.Classification, error) {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return tenantdom.Classification{}, fmt.Errorf("%w: invalid email address", shared.ErrValidation)
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	out := tenantdom.Classification{Kind: tenantdom.MemberKindExternal, Domain: domain}
	if emaildomain.IsConsumer(domain) {
		out.Personal = true
		return out, nil
	}
	if c == nil || c.owners == nil {
		return tenantdom.Classification{}, errors.New("address classifier not configured")
	}
	owner, ok, err := c.owners.OwnerOfDomain(ctx, domain)
	if err != nil {
		return tenantdom.Classification{}, fmt.Errorf("look up the domain holder: %w", err)
	}
	if ok {
		if owner == tenantID {
			out.Kind = tenantdom.MemberKindInternal
			return out, nil
		}
		home := owner
		out.HomeTenantID = &home
		return out, nil
	}
	ownsAny, err := c.ownsAny(ctx, tenantID)
	if err != nil {
		return tenantdom.Classification{}, fmt.Errorf("look up the organization's domains: %w", err)
	}
	if !ownsAny {
		out.Kind = tenantdom.MemberKindInternal
	}
	return out, nil
}

// SetAddressClassifier wires external-member classification. Without it every
// invitation is refused for a non-consumer address that cannot be classified
// (fail closed), except in tests that never set it.
func (s *TenantService) SetAddressClassifier(c *AddressClassifier) { s.classifier = c }

// classifyInvitee classifies an invitee and settles their access: the expiry
// defaults to DefaultExternalAccessDays when one is required and none was set.
func (s *TenantService) classifyInvitee(ctx context.Context, tenantID shared.ID, email string,
	access tenantdom.ExternalAccess, now time.Time) (tenantdom.Classification, tenantdom.ExternalAccess, error) {
	if s.classifier == nil {
		return tenantdom.Classification{Kind: tenantdom.MemberKindInternal}, tenantdom.ExternalAccess{}, nil
	}
	c, err := s.classifier.Classify(ctx, tenantID, email)
	if err != nil {
		return c, access, err
	}
	// A trusted home organization may propose an end of access.
	if c.Managed() && access.ExpiresAt == nil && s.trustPolicy != nil {
		at, terr := s.trustPolicy.DefaultExpiryFor(ctx, tenantID, *c.HomeTenantID, now)
		if terr != nil {
			return c, access, terr
		}
		access.ExpiresAt = at
	}
	return c, SettleExternalAccess(c, access, now), nil
}

// TrustPolicy reads the trusts with members' home organizations
// (orgtrust.Policy).
type TrustPolicy interface {
	MaxRoleFor(ctx context.Context, host, home shared.ID) (orgtrust.MaxRole, error)
	DefaultExpiryFor(ctx context.Context, host, home shared.ID, now time.Time) (*time.Time, error)
}

// SetTrustPolicy wires the trusts (RFC-058).
func (s *TenantService) SetTrustPolicy(p TrustPolicy) { s.trustPolicy = p }

// SettleExternalAccess returns the access an invitee gets: none for an
// internal member; for an external one the given access, with the default
// expiry filled in when an expiry is required and none was set.
func SettleExternalAccess(c tenantdom.Classification, access tenantdom.ExternalAccess, now time.Time) tenantdom.ExternalAccess {
	if c.Kind != tenantdom.MemberKindExternal {
		return tenantdom.ExternalAccess{}
	}
	if access.ExpiresAt == nil && c.ExpiryRequired() {
		at := now.Add(tenantdom.DefaultExternalAccessDays * 24 * time.Hour).UTC()
		access.ExpiresAt = &at
	}
	return access
}

// requireViewerOnly refuses an external invitation that grants more than the
// viewer role.
func requireViewerOnly(roleIDs []string) error {
	if len(roleIDs) != 1 || !strings.EqualFold(roleIDs[0], roledom.ViewerRoleID.String()) {
		return ErrExternalViewerOnly
	}
	return nil
}

// ExternalInviteeRoleIDs is the role set an external invitee receives on
// acceptance: viewer, whatever the invitation said (the address may have
// become external after the invitation was sent).
func ExternalInviteeRoleIDs() []string { return []string{roledom.ViewerRoleID.String()} }

// ClassifyAcceptedInvitation classifies the invitee again at acceptance (the
// domain may have been claimed or released since the invitation was sent)
// and applies the outcome to the new membership: an external invitee joins
// as a viewer, with the invitation's access (or the default expiry when one
// is required). Fail closed: a classification error refuses the acceptance.
func (s *TenantService) ClassifyAcceptedInvitation(ctx context.Context, inv *tenantdom.Invitation, m *tenantdom.Membership, now time.Time) error {
	class, access, err := s.classifyInvitee(ctx, inv.TenantID(), inv.Email(), inv.Access(), now)
	if err != nil {
		return err
	}
	return ApplyInviteeClassification(inv, m, class, access, now)
}

// ApplyInviteeClassification applies a classification to an invitation being
// accepted and its new membership.
func ApplyInviteeClassification(inv *tenantdom.Invitation, m *tenantdom.Membership,
	class tenantdom.Classification, access tenantdom.ExternalAccess, now time.Time) error {
	if class.Kind == tenantdom.MemberKindExternal {
		inv.LimitRoles(ExternalInviteeRoleIDs(), tenantdom.RoleViewer)
		if err := m.UpdateRole(tenantdom.RoleViewer); err != nil {
			return err
		}
	}
	if err := m.Classify(class, access, now); err != nil {
		return fmt.Errorf("%w (ask the organization for a new invitation)", err)
	}
	return nil
}
