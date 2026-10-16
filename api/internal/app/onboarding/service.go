// Package onboarding serves the fork a signed-in account without an
// organization sees (docs/rfcs/RFC-104): its pending invitations, the
// organizations its verified email domain may join, and whether it may
// create one. It also runs join requests: the requester asks, the
// organization's administrators decide.
//
// Offers carry opaque, per-account, short-lived references, never an
// organization id or slug, so a request cannot be aimed at an organization
// the account was not offered.
package onboarding

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/joinrequest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// refTTL bounds how long an offer reference is valid.
const refTTL = 30 * time.Minute

// Offer kinds carried in a reference.
const (
	kindInvitation = "inv"
	kindDomain     = "dom"
)

var (
	// ErrInvalidRef: the reference is malformed, expired, for another
	// account, or the offer no longer stands. One answer for all.
	ErrInvalidRef = fmt.Errorf("%w: this offer is no longer available", shared.ErrValidation)
	// ErrEmailNotVerified: offers by domain need a verified address.
	ErrEmailNotVerified = fmt.Errorf("%w: verify your email address first", shared.ErrValidation)
)

// Invitations lists and accepts pending invitations for an address.
type Invitations interface {
	ListInvitationOffersForEmail(ctx context.Context, email string) ([]tenantdom.InvitationOffer, error)
}

// Members reads and creates memberships and names organizations.
type Members interface {
	GetMembership(ctx context.Context, userID shared.ID, tenantID shared.ID) (*tenantdom.Membership, error)
	GetByID(ctx context.Context, id shared.ID) (*tenantdom.Tenant, error)
}

// Tenants accepts invitations, adds members and notifies administrators
// (tenant.TenantService).
type Tenants interface {
	AcceptInvitationByID(ctx context.Context, tenantID, invitationID, userID shared.ID, userEmail string, emailVerified bool, actx auditapp.AuditContext) (*tenantdom.Membership, error)
	AddMember(ctx context.Context, tenantID string, input AddMemberInput, inviterUserID shared.ID, actx auditapp.AuditContext) (*tenantdom.Membership, error)
	NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body, severity string)
}

// AddMemberInput mirrors tenant.AddMemberInput (kept here so the port does
// not import the tenant service).
type AddMemberInput struct {
	UserID shared.ID
	Role   string
}

// Service is the onboarding service.
type Service struct {
	invitations Invitations
	members     Members
	tenants     Tenants
	domains     signupdom.DomainPolicySource
	policy      signupdom.PolicySource
	requests    joinrequest.Repository
	audit       *auditapp.AuditService
	key         []byte
	log         *logger.Logger
	now         func() time.Time
}

// NewService creates the service. key signs offer references (derive it
// from a server secret under its own label).
func NewService(inv Invitations, members Members, tenants Tenants, domains signupdom.DomainPolicySource,
	policy signupdom.PolicySource, requests joinrequest.Repository, audit *auditapp.AuditService, key []byte, log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{invitations: inv, members: members, tenants: tenants, domains: domains, policy: policy,
		requests: requests, audit: audit, key: key, log: log.With("service", "onboarding"), now: time.Now}
}

// InvitationOption is a pending invitation offered to the account.
type InvitationOption struct {
	Ref              string    `json:"ref"`
	OrganizationName string    `json:"organization_name"`
	Role             string    `json:"role"`
	InvitedBy        string    `json:"invited_by,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// DomainOption is an organization the account's verified email domain may
// join. Mode is "join" (auto) or "request" (approval). Pending is true when
// the account already waits on it.
type DomainOption struct {
	Ref              string `json:"ref"`
	OrganizationName string `json:"organization_name"`
	Domain           string `json:"domain"`
	Mode             string `json:"mode"`
	Pending          bool   `json:"pending"`
}

// Options is the onboarding fork.
type Options struct {
	EmailVerified   bool               `json:"email_verified"`
	Invitations     []InvitationOption `json:"invitations"`
	Organizations   []DomainOption     `json:"organizations"`
	CanCreate       bool               `json:"can_create_organization"`
	PendingRequests int                `json:"pending_requests"`
}

// Options returns what the account may do. Nothing is offered by domain
// before the address is verified, and an organization that is not
// discoverable is never revealed.
func (s *Service) Options(ctx context.Context, u *userdom.User) (*Options, error) {
	out := &Options{EmailVerified: u.EmailVerified(), Invitations: []InvitationOption{}, Organizations: []DomainOption{}}
	if u.EmailVerified() && s.invitations != nil {
		offers, err := s.invitations.ListInvitationOffersForEmail(ctx, u.Email())
		if err != nil {
			return nil, err
		}
		for _, o := range offers {
			out.Invitations = append(out.Invitations, InvitationOption{
				Ref:              s.sign(u.ID(), kindInvitation, o.TenantID, o.InvitationID),
				OrganizationName: o.TenantName, Role: o.Role, InvitedBy: o.InviterName, ExpiresAt: o.ExpiresAt,
			})
		}
	}
	facts := signupdom.DomainFacts{}
	if s.domains != nil {
		ep, ok, err := s.domains.SignupPolicyForEmail(ctx, u.Email())
		if err != nil {
			return nil, err
		}
		if ok {
			facts.WorkspacesBlocked = ep.Policy.BlockNewWorkspaces
			if opt, offered, err := s.domainOption(ctx, u, ep); err != nil {
				return nil, err
			} else if offered {
				out.Organizations = append(out.Organizations, opt)
			}
		}
	}
	if s.policy != nil {
		out.CanCreate = signupdom.Admit(s.policy.Current(ctx), facts.Apply(signupdom.Identity{Intent: signupdom.IntentOrganization})).Admitted()
	}
	if s.requests != nil {
		own, err := s.requests.ListByUser(ctx, u.ID(), 50)
		if err != nil {
			return nil, err
		}
		for _, r := range own {
			if r.Pending(s.now()) {
				out.PendingRequests++
			}
		}
	}
	return out, nil
}

// domainOption builds the offer of the organization that claims the
// account's domain, when it is offered: verified address, discoverable,
// joinable, and the account is not a member already.
func (s *Service) domainOption(ctx context.Context, u *userdom.User, ep verifieddomain.EmailPolicy) (DomainOption, bool, error) {
	if !u.EmailVerified() || !ep.Policy.Discoverable || !ep.Joinable() {
		return DomainOption{}, false, nil
	}
	if m, err := s.members.GetMembership(ctx, u.ID(), ep.OrganizationID); err == nil && !m.IsOffboarded() {
		return DomainOption{}, false, nil
	} else if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return DomainOption{}, false, err
	}
	t, err := s.members.GetByID(ctx, ep.OrganizationID)
	if err != nil {
		return DomainOption{}, false, err
	}
	mode := "request"
	if ep.Policy.Join == verifieddomain.JoinAuto {
		mode = "join"
	}
	pending := false
	if s.requests != nil {
		own, err := s.requests.ListByUser(ctx, u.ID(), 50)
		if err != nil {
			return DomainOption{}, false, err
		}
		for _, r := range own {
			if r.TenantID.Equals(ep.OrganizationID) && r.Pending(s.now()) {
				pending = true
			}
		}
	}
	return DomainOption{
		Ref:              s.sign(u.ID(), kindDomain, ep.OrganizationID, ep.DomainID),
		OrganizationName: t.Name(), Domain: ep.Domain, Mode: mode, Pending: pending,
	}, true, nil
}

// AcceptResult says what an accepted offer did.
type AcceptResult struct {
	// Status: "joined" (a membership exists now) or "requested" (a join
	// request waits for the organization's administrators).
	Status string `json:"status"`
	// OrganizationName of the offer.
	OrganizationName string `json:"organization_name"`
	// OrganizationID is set when the account joined: the account is a member
	// now, so it may select the organization.
	OrganizationID string `json:"organization_id,omitempty"`
}

// Accept takes an offer: accepts an invitation, joins by domain (auto) or
// asks to join (approval). Every condition is checked again now; a stale or
// foreign reference gets ErrInvalidRef.
func (s *Service) Accept(ctx context.Context, u *userdom.User, ref string, actx auditapp.AuditContext) (*AcceptResult, error) {
	kind, tenantID, targetID, err := s.verify(u.ID(), ref)
	if err != nil {
		return nil, err
	}
	if !u.EmailVerified() {
		return nil, ErrEmailNotVerified
	}
	t, err := s.members.GetByID(ctx, tenantID)
	if err != nil {
		return nil, ErrInvalidRef
	}
	switch kind {
	case kindInvitation:
		if _, err := s.tenants.AcceptInvitationByID(ctx, tenantID, targetID, u.ID(), u.Email(), true, actx); err != nil {
			return nil, err
		}
		return &AcceptResult{Status: "joined", OrganizationName: t.Name(), OrganizationID: t.ID().String()}, nil
	case kindDomain:
		return s.joinByDomain(ctx, u, t, targetID, actx)
	}
	return nil, ErrInvalidRef
}

func (s *Service) joinByDomain(ctx context.Context, u *userdom.User, t *tenantdom.Tenant, domainID shared.ID, actx auditapp.AuditContext) (*AcceptResult, error) {
	ep, ok, err := s.domains.SignupPolicyForEmail(ctx, u.Email())
	if err != nil {
		return nil, err
	}
	// The offer stands only while the same claim still governs the address
	// and still lets it join.
	if !ok || !ep.OrganizationID.Equals(t.ID()) || !ep.DomainID.Equals(domainID) || !ep.Joinable() || !ep.Policy.Discoverable {
		return nil, ErrInvalidRef
	}
	role := ep.Policy.JoinRole
	if !joinrequest.ValidRole(role) {
		role = "viewer"
	}
	actx.TenantID = t.ID().String()
	if ep.Policy.Join == verifieddomain.JoinAuto {
		if _, err := s.tenants.AddMember(ctx, t.ID().String(), AddMemberInput{UserID: u.ID(), Role: role}, shared.ID{}, actx); err != nil {
			return nil, err
		}
		s.record(ctx, actx, audit.ActionMemberJoinedByDomain, t.ID(), u, "Joined by verified email domain "+ep.Domain, role)
		s.tenants.NotifyAdmins(ctx, t.ID(), "A colleague joined by email domain",
			fmt.Sprintf("%s joined as %s through the verified domain %s.", u.Email(), role, ep.Domain), "info")
		return &AcceptResult{Status: "joined", OrganizationName: t.Name(), OrganizationID: t.ID().String()}, nil
	}

	since := s.now().Add(-24 * time.Hour)
	if n, err := s.requests.CountSince(ctx, u.ID(), since); err != nil {
		return nil, err
	} else if n >= joinrequest.MaxPerDay {
		return nil, joinrequest.ErrTooMany
	}
	did := ep.DomainID
	jr, err := joinrequest.New(t.ID(), u.ID(), &did, role, s.now())
	if err != nil {
		return nil, err
	}
	if err := s.requests.Create(ctx, jr); err != nil {
		return nil, err
	}
	s.record(ctx, actx, audit.ActionJoinRequestCreated, t.ID(), u, "Asked to join through the verified domain "+ep.Domain, role)
	s.tenants.NotifyAdmins(ctx, t.ID(), "Request to join your organization",
		fmt.Sprintf("%s asked to join through the verified domain %s. Review it under Members > Requests.", u.Email(), ep.Domain), "info")
	return &AcceptResult{Status: "requested", OrganizationName: t.Name()}, nil
}

// ListRequests lists an organization's waiting requests (its administrators).
func (s *Service) ListRequests(ctx context.Context, tenantID shared.ID) ([]*joinrequest.Request, error) {
	return s.requests.ListPending(ctx, tenantID, s.now(), 200)
}

// Approve approves a waiting request of the organization with role (viewer
// or member: nobody becomes an administrator by request) and creates the
// membership. Tenant-scoped: another organization's request is not found.
func (s *Service) Approve(ctx context.Context, tenantID, requestID, by shared.ID, role string, actx auditapp.AuditContext) error {
	if !joinrequest.ValidRole(role) {
		return joinrequest.ErrInvalidRole
	}
	jr, err := s.requests.GetForTenant(ctx, tenantID, requestID)
	if err != nil {
		return err
	}
	if !jr.Pending(s.now()) {
		return joinrequest.ErrNotPending
	}
	if err := s.requests.Decide(ctx, tenantID, requestID, joinrequest.StatusApproved, role, by, s.now()); err != nil {
		return err
	}
	actx.TenantID = tenantID.String()
	if _, err := s.tenants.AddMember(ctx, tenantID.String(), AddMemberInput{UserID: jr.UserID, Role: role}, by, actx); err != nil {
		return err
	}
	s.recordRequest(ctx, actx, audit.ActionJoinRequestApproved, jr, role)
	return nil
}

// Reject rejects a waiting request of the organization. The requester is
// not told who decided.
func (s *Service) Reject(ctx context.Context, tenantID, requestID, by shared.ID, actx auditapp.AuditContext) error {
	jr, err := s.requests.GetForTenant(ctx, tenantID, requestID)
	if err != nil {
		return err
	}
	if err := s.requests.Decide(ctx, tenantID, requestID, joinrequest.StatusRejected, "", by, s.now()); err != nil {
		return err
	}
	actx.TenantID = tenantID.String()
	s.recordRequest(ctx, actx, audit.ActionJoinRequestRejected, jr, "")
	return nil
}

// Purge removes decided and expired requests after the retention period.
func (s *Service) Purge(ctx context.Context) (int64, error) {
	return s.requests.Purge(ctx, s.now().Add(-joinrequest.Retention))
}

func (s *Service) record(ctx context.Context, actx auditapp.AuditContext, action audit.Action, tenantID shared.ID, u *userdom.User, msg, role string) {
	if s.audit == nil {
		return
	}
	actx.TenantID = tenantID.String()
	ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeMembership, u.ID().String()).
		WithResourceName(u.Email()).WithMessage(msg).WithMetadata("role", role)
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.log.Error("audit onboarding event", "action", string(action), "error", err)
	}
}

func (s *Service) recordRequest(ctx context.Context, actx auditapp.AuditContext, action audit.Action, jr *joinrequest.Request, role string) {
	if s.audit == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeMembership, jr.ID.String()).
		WithResourceName(jr.Email).WithMessage("Join request decided").
		WithMetadata("user_id", jr.UserID.String()).WithMetadata("role", role)
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.log.Error("audit join request", "action", string(action), "error", err)
	}
}

// sign builds an offer reference: kind, organization, target, account and
// expiry under an HMAC. It is opaque to the client and bound to the account.
func (s *Service) sign(userID shared.ID, kind string, tenantID, targetID shared.ID) string {
	exp := strconv.FormatInt(s.now().Add(refTTL).Unix(), 10)
	payload := strings.Join([]string{kind, tenantID.String(), targetID.String(), exp}, "|")
	mac := s.mac(userID, payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac)
}

func (s *Service) mac(userID shared.ID, payload string) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte("onboarding-offer/v1|" + userID.String() + "|" + payload))
	return h.Sum(nil)
}

// verify checks a reference for userID and returns its content.
func (s *Service) verify(userID shared.ID, ref string) (kind string, tenantID, targetID shared.ID, err error) {
	if len(s.key) == 0 {
		return "", shared.ID{}, shared.ID{}, ErrInvalidRef
	}
	p, m, ok := strings.Cut(ref, ".")
	if !ok {
		return "", shared.ID{}, shared.ID{}, ErrInvalidRef
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(p)
	mac, err2 := base64.RawURLEncoding.DecodeString(m)
	if err1 != nil || err2 != nil || !hmac.Equal(mac, s.mac(userID, string(payload))) {
		return "", shared.ID{}, shared.ID{}, ErrInvalidRef
	}
	parts := strings.Split(string(payload), "|")
	if len(parts) != 4 {
		return "", shared.ID{}, shared.ID{}, ErrInvalidRef
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || s.now().Unix() > exp {
		return "", shared.ID{}, shared.ID{}, ErrInvalidRef
	}
	tid, err1 := shared.IDFromString(parts[1])
	xid, err2 := shared.IDFromString(parts[2])
	if err1 != nil || err2 != nil {
		return "", shared.ID{}, shared.ID{}, ErrInvalidRef
	}
	return parts[0], tid, xid, nil
}
