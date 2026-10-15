package tenant

// External members: people who belong to an organization that does not own
// their email domain. Design: docs/rfcs/RFC-058-external-members.md.
//
// Threat model. Users are global, so one person can be a member of several
// organizations. An organization that admits someone it does not manage must
// see that they are from outside and bound the risk of an account whose
// mailbox it does not control (RFC-058, amended by RFC-095 §4):
//
//   - anyone may be invited, to any role but owner, unless the organization
//     restricts who may be invited (Security.invitees);
//   - an outside member is marked as such everywhere, can never hold the
//     owner role (database CHECK and triggers), and is capped by a trust's
//     max_role when the host trusts their home organization;
//   - inviting an outside address with a privileged role set needs the
//     inviter's step-up, and an outside member holding a privileged role must
//     prove a second factor at every token mint (auth.enforceOutsidePrivilege);
//   - an end of access is optional, unless Security.external_access_end_required
//     makes it mandatory (90 days by default, 365 at most) for outside people
//     no organization manages; an expired membership is suspended within a
//     minute (ExpireMemberships);
//   - an outside person joins only by accepting an invitation addressed to
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

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
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

// ErrDirectAddNeedsVerifiedDomain refuses adding an existing account, or
// creating one, directly when the address is not on an email domain the
// organization has verified: without a verified domain the organization has
// not shown that the address is one of its own people, so it invites them
// and they consent by accepting.
var ErrDirectAddNeedsVerifiedDomain = fmt.Errorf("%w: people are added or created directly only on an email domain your organization has verified; invite them instead", shared.ErrValidation)

// ErrInviteeNotOnVerifiedDomain refuses an invitation to an address outside
// the organization's verified domains when Security.invitees is
// verified_domains.
var ErrInviteeNotOnVerifiedDomain = fmt.Errorf("%w: only addresses on your organization's verified domains can be invited", shared.ErrForbidden)

// ErrInvitationNoLongerValid refuses an acceptance whose inviter can no
// longer grant what the invitation offers (they left, were suspended or
// demoted), or that a trust's role ceiling now exceeds.
var ErrInvitationNoLongerValid = fmt.Errorf("%w: this invitation is no longer valid; ask the organization for a new one", shared.ErrForbidden)

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

// HeldBy reports whether email is on a domain organization tenantID has
// verified. A consumer mail domain never is. Fail closed: a lookup error is
// returned, never a guess.
func (c *AddressClassifier) HeldBy(ctx context.Context, tenantID shared.ID, email string) (bool, error) {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false, fmt.Errorf("%w: invalid email address", shared.ErrValidation)
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	if emaildomain.IsConsumer(domain) {
		return false, nil
	}
	if c == nil || c.owners == nil {
		return false, errors.New("address classifier not configured")
	}
	owner, ok, err := c.owners.OwnerOfDomain(ctx, domain)
	if err != nil {
		return false, fmt.Errorf("look up the domain holder: %w", err)
	}
	return ok && owner == tenantID, nil
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
	required, err := s.externalAccessEndRequired(ctx, tenantID)
	if err != nil {
		return c, access, err
	}
	c.EndOptional = !required
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

// ClassifyAcceptedInvitation classifies the invitee again at acceptance (the
// domain may have been claimed or released since the invitation was sent)
// and applies the outcome to the new membership: an outside invitee joins
// with the invited roles and the invitation's access (or the default expiry
// when one is required). A trust that now caps the invitee below the invited
// roles refuses the acceptance. Fail closed: a classification error refuses
// the acceptance.
func (s *TenantService) ClassifyAcceptedInvitation(ctx context.Context, inv *tenantdom.Invitation, m *tenantdom.Membership, now time.Time) error {
	class, access, err := s.classifyInvitee(ctx, inv.TenantID(), inv.Email(), inv.Access(), now)
	if err != nil {
		return err
	}
	if err := s.requirePersonalAllowed(ctx, inv.TenantID(), class); err != nil {
		return err
	}
	if err := s.requireWithinTrustCeiling(ctx, inv.TenantID(), class, inv.RoleIDs()); err != nil {
		if errors.Is(err, accesscontrol.ErrGrantForbidden) {
			return ErrInvitationNoLongerValid
		}
		return err
	}
	return ApplyInviteeClassification(inv, m, class, access, now)
}

// ApplyInviteeClassification applies a classification to the new membership
// of an invitation being accepted. The invited roles are kept: who may be
// invited, and to what, was decided when the invitation was created and is
// re-checked at acceptance (the inviter's authority, the trust ceiling).
func ApplyInviteeClassification(_ *tenantdom.Invitation, m *tenantdom.Membership,
	class tenantdom.Classification, access tenantdom.ExternalAccess, now time.Time) error {
	if err := m.Classify(class, access, now); err != nil {
		return fmt.Errorf("%w (ask the organization for a new invitation)", err)
	}
	return nil
}

// ErrPersonalAccountsBlocked refuses a personal address in an organization
// that blocks personal accounts.
var ErrPersonalAccountsBlocked = fmt.Errorf("%w: this organization does not accept personal email accounts", shared.ErrForbidden)

// requirePersonalAllowed refuses a personal invitee when the organization
// blocks personal accounts.
func (s *TenantService) requirePersonalAllowed(ctx context.Context, tenantID shared.ID, class tenantdom.Classification) error {
	if !class.Personal {
		return nil
	}
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		return fmt.Errorf("read the personal account policy: %w", err)
	}
	if sec.PersonalAccounts.Effective() == tenantdom.PersonalAccountsBlocked {
		return ErrPersonalAccountsBlocked
	}
	return nil
}

// validateSSOExceptions checks each exception and that it names a member of
// the organization.
func (s *TenantService) validateSSOExceptions(ctx context.Context, tenantID shared.ID, exceptions []tenantdom.SSOException) error {
	now := time.Now().UTC()
	seen := map[string]bool{}
	for _, e := range exceptions {
		if err := e.Validate(now); err != nil {
			return err
		}
		if seen[e.UserID] {
			return fmt.Errorf("%w: one sso exception per member", shared.ErrValidation)
		}
		seen[e.UserID] = true
		uid, _ := shared.IDFromString(e.UserID)
		m, err := s.repo.GetMembership(ctx, uid, tenantID)
		if err != nil || m == nil || m.IsOffboarded() {
			return fmt.Errorf("%w: an sso exception must name a member of this organization", shared.ErrValidation)
		}
	}
	return nil
}

// Lookalikes returns the members whose address looks like email once
// personal-mail variants are ignored (dots and +tags in Gmail, +tags
// elsewhere). It only warns: identity always stays the exact address.
func (s *TenantService) Lookalikes(ctx context.Context, tenantID shared.ID, email string) []string {
	want := canonicalMailbox(email)
	if want == "" {
		return nil
	}
	members, err := s.repo.ListMembersWithUserInfo(ctx, tenantID)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range members {
		if !strings.EqualFold(m.Email, email) && canonicalMailbox(m.Email) == want {
			out = append(out, m.Email)
		}
	}
	return out
}

// canonicalMailbox folds the variants a mail provider delivers to the same
// mailbox: lower case, +tag removed, and for Gmail dots removed and
// googlemail.com mapped to gmail.com.
func canonicalMailbox(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return ""
	}
	local, domain := email[:at], email[at+1:]
	if i := strings.IndexByte(local, '+'); i >= 0 {
		local = local[:i]
	}
	if domain == "googlemail.com" {
		domain = "gmail.com"
	}
	if domain == "gmail.com" {
		local = strings.ReplaceAll(local, ".", "")
	}
	return local + "@" + domain
}

// externalAccessEndRequired reads Security.external_access_end_required.
// Fail closed: an unreadable policy requires the end of access.
func (s *TenantService) externalAccessEndRequired(ctx context.Context, tenantID shared.ID) (bool, error) {
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return true, err
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		return true, fmt.Errorf("read the end of access policy: %w", err)
	}
	return sec.ExternalAccessEndRequired, nil
}

// requireInvitable applies Security.invitees to an address about to be
// invited, or whose invitation is being accepted. Fail closed: a domain
// lookup error refuses.
func (s *TenantService) requireInvitable(ctx context.Context, tenantID shared.ID, email string) error {
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		return fmt.Errorf("read the invitation policy: %w", err)
	}
	policy := sec.EffectiveInvitees()
	if policy == tenantdom.InviteesAny {
		return nil
	}
	held := false
	if s.classifier != nil {
		if held, err = s.classifier.HeldBy(ctx, tenantID, email); err != nil {
			return err
		}
	}
	if held {
		return nil
	}
	if policy == tenantdom.InviteesAllowList {
		if len(sec.AllowedDomains) > 0 && sec.EmailDomainAllowed(email) {
			return nil
		}
		return ErrEmailDomainNotAllowed
	}
	return ErrInviteeNotOnVerifiedDomain
}

// requireWithinTrustCeiling refuses roles above the ceiling of an active
// trust with the invitee's home organization: the trust's max_role (viewer
// or member) is what the two organizations agreed. Without a trust there is
// no ceiling but owner, which invitations never carry.
func (s *TenantService) requireWithinTrustCeiling(ctx context.Context, tenantID shared.ID, class tenantdom.Classification, roleIDs []string) error {
	if class.Kind != tenantdom.MemberKindExternal || !class.Managed() || s.trustPolicy == nil {
		return nil
	}
	ceiling, err := s.trustPolicy.MaxRoleFor(ctx, tenantID, *class.HomeTenantID)
	if err != nil {
		return fmt.Errorf("load the trust ceiling: %w", err)
	}
	if ceiling == "" {
		return nil
	}
	privileged, err := s.privilegedRoleSet(ctx, tenantID, roleIDs)
	if err != nil {
		return err
	}
	if privileged || accesscontrol.MembershipRoleForRoleIDs(roleIDs) == tenantdom.RoleAdmin {
		return accesscontrol.ErrExternalRoleCeiling
	}
	if ceiling == orgtrust.MaxRoleViewer && !(len(roleIDs) == 1 && strings.EqualFold(roleIDs[0], roledom.ViewerRoleID.String())) {
		return accesscontrol.ErrExternalViewerCeiling
	}
	return nil
}

// privilegedRoleSet reports whether the roles make their holder privileged:
// the admin role, full data access, or a privileged permission (members,
// teams, roles, API keys, secret store, settings).
func (s *TenantService) privilegedRoleSet(ctx context.Context, tenantID shared.ID, roleIDs []string) (bool, error) {
	for _, raw := range roleIDs {
		if strings.EqualFold(raw, roledom.AdminRoleID.String()) || strings.EqualFold(raw, roledom.OwnerRoleID.String()) {
			return true, nil
		}
	}
	if s.roleService == nil {
		return false, nil
	}
	for _, raw := range roleIDs {
		r, err := s.roleService.GetRole(ctx, tenantID.String(), raw)
		if err != nil {
			return false, err
		}
		if permission.IsAboveMember(r.Permissions(), r.HasFullDataAccess()) {
			return true, nil
		}
	}
	return false, nil
}
