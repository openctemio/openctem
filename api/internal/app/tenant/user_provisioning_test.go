package tenant

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// --- fakes -------------------------------------------------------------------

type provTenantRepo struct {
	tenantdom.Repository
	tenant      *tenantdom.Tenant
	memberships map[string]*tenantdom.Membership // key user id
	others      []tenantdom.UserMembership       // extra memberships reported for the user
	createErr   error
	deleted     []shared.ID
}

func (r *provTenantRepo) GetByID(_ context.Context, id shared.ID) (*tenantdom.Tenant, error) {
	if r.tenant == nil || r.tenant.ID() != id {
		return nil, shared.ErrNotFound
	}
	return r.tenant, nil
}

func (r *provTenantRepo) CreateMembership(_ context.Context, m *tenantdom.Membership) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.memberships[m.UserID().String()] = m
	return nil
}

func (r *provTenantRepo) DeleteMembership(_ context.Context, _ shared.ID, id shared.ID) error {
	r.deleted = append(r.deleted, id)
	for k, m := range r.memberships {
		if m.ID() == id {
			delete(r.memberships, k)
		}
	}
	return nil
}

func (r *provTenantRepo) GetMembership(_ context.Context, userID, _ shared.ID) (*tenantdom.Membership, error) {
	m, ok := r.memberships[userID.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return m, nil
}

func (r *provTenantRepo) GetUserMembershipsWithStatus(_ context.Context, userID shared.ID) (*tenantdom.UserMembershipsByStatus, error) {
	out := &tenantdom.UserMembershipsByStatus{}
	if _, ok := r.memberships[userID.String()]; ok {
		out.Active = append(out.Active, tenantdom.UserMembership{TenantID: r.tenant.ID().String()})
	}
	out.Active = append(out.Active, r.others...)
	return out, nil
}

type provUserRepo struct {
	userdom.Repository
	byEmail map[string]*userdom.User
	byID    map[string]*userdom.User
	deleted []shared.ID
}

func newProvUserRepo() *provUserRepo {
	return &provUserRepo{byEmail: map[string]*userdom.User{}, byID: map[string]*userdom.User{}}
}

func (r *provUserRepo) GetByEmail(_ context.Context, email string) (*userdom.User, error) {
	if u, ok := r.byEmail[email]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}

func (r *provUserRepo) GetByID(_ context.Context, id shared.ID) (*userdom.User, error) {
	if u, ok := r.byID[id.String()]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}

func (r *provUserRepo) Create(_ context.Context, u *userdom.User) error {
	r.byEmail[u.Email()] = u
	r.byID[u.ID().String()] = u
	return nil
}

func (r *provUserRepo) Update(_ context.Context, u *userdom.User) error {
	r.byID[u.ID().String()] = u
	return nil
}

func (r *provUserRepo) Delete(_ context.Context, id shared.ID) error {
	r.deleted = append(r.deleted, id)
	if u, ok := r.byID[id.String()]; ok {
		delete(r.byEmail, u.Email())
		delete(r.byID, id.String())
	}
	return nil
}

type provRoles struct {
	granted map[string][]string // user id -> roles
	err     error
	foreign map[string]bool // role ids that belong to another tenant
	checked int
	authErr error // returned by AuthorizeAccountAction
}

func (g *provRoles) AuthorizeAccountAction(context.Context, string, string, string) error {
	return g.authErr
}

func (g *provRoles) ValidateRolesForTenant(_ context.Context, _ string, roleIDs []string) error {
	g.checked++
	for _, id := range roleIDs {
		if g.foreign[id] {
			return fmt.Errorf("%w: role %s is not available in this organization", shared.ErrValidation, id)
		}
	}
	return nil
}

func (g *provRoles) GrantExactRoles(_ context.Context, _, userID string, roleIDs []string, _ string, _ auditapp.AuditContext) error {
	if g.err != nil {
		return g.err
	}
	if g.granted == nil {
		g.granted = map[string][]string{}
	}
	g.granted[userID] = roleIDs
	return nil
}

type provMailer struct {
	canDeliver bool
	sendErr    error
	sentTo     string
	sentToken  string
}

func (m *provMailer) CanDeliverTo(context.Context, string) bool { return m.canDeliver }
func (m *provMailer) SendAccountSetupEmail(_ context.Context, _, to, _, _, token string, _ time.Duration) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sentTo, m.sentToken = to, token
	return nil
}

func provFixture(t *testing.T, allowedDomains ...string) (*UserProvisioningService, *provTenantRepo, *provUserRepo, *provRoles, *provMailer) {
	t.Helper()
	tn, err := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if len(allowedDomains) > 0 {
		sec := tn.TypedSettings().Security
		sec.AllowedDomains = allowedDomains
		if err := tn.UpdateSecuritySettings(sec); err != nil {
			t.Fatalf("security settings: %v", err)
		}
	}
	tr := &provTenantRepo{tenant: tn, memberships: map[string]*tenantdom.Membership{}}
	ur := newProvUserRepo()
	roles := &provRoles{}
	mailer := &provMailer{}
	svc := NewUserProvisioningService(tr, ur, roles, mailer, nil, logger.NewNop())
	return svc, tr, ur, roles, mailer
}

var viewerOnly = []string{roledom.ViewerRoleID.String()}

// --- CreateUser --------------------------------------------------------------

func TestCreateUser_NoSMTP_ReturnsOneTimeTokenHashedAtRest(t *testing.T) {
	svc, tr, ur, roles, _ := provFixture(t)

	res, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "  New@Corp.com ", Name: "New", RoleIDs: viewerOnly, CreatedBy: shared.NewID(),
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if res.EmailSent || res.SetupToken == "" {
		t.Fatal("without SMTP the token must be returned to the administrator")
	}
	u := ur.byEmail["new@corp.com"]
	if u == nil {
		t.Fatal("email must be normalized")
	}
	if u.PasswordHash() != nil || !u.IsPendingSetup() {
		t.Fatal("the account has no password until the user sets one")
	}
	if got := u.PasswordResetToken(); got == nil || *got != crypto.HashToken(res.SetupToken) || *got == res.SetupToken {
		t.Fatal("only the token hash may be stored")
	}
	if exp := u.PasswordResetExpiresAt(); exp == nil || time.Until(*exp) > AccountSetupTTL+time.Minute || exp.Before(time.Now().Add(AccountSetupTTL-time.Minute)) {
		t.Fatalf("setup link must expire after %s", AccountSetupTTL)
	}
	m := tr.memberships[u.ID().String()]
	if m == nil || m.Role() != tenantdom.RoleViewer {
		t.Fatalf("a viewer-only grant must create a viewer membership, got %+v", m)
	}
	if got := roles.granted[u.ID().String()]; len(got) != 1 || got[0] != roledom.ViewerRoleID.String() {
		t.Fatalf("the user must end up with exactly the granted roles, got %v", got)
	}
}

func TestCreateUser_WithSMTP_EmailsLinkAndNeverReturnsToken(t *testing.T) {
	svc, tr, _, _, mailer := provFixture(t)
	mailer.canDeliver = true

	res, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "new@corp.com", RoleIDs: viewerOnly,
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !res.EmailSent || res.SetupToken != "" {
		t.Fatal("with SMTP the link is emailed and not returned")
	}
	if mailer.sentTo != "new@corp.com" || mailer.sentToken == "" {
		t.Fatal("the raw token goes to the user's mailbox")
	}
}

func TestCreateUser_EmailFailure_FallsBackToAdministrator(t *testing.T) {
	svc, tr, _, _, mailer := provFixture(t)
	mailer.canDeliver = true
	mailer.sendErr = errors.New("smtp down")

	res, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "new@corp.com", RoleIDs: viewerOnly,
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if res.EmailSent || res.SetupToken == "" {
		t.Fatal("a failed email must fall back to returning the link")
	}
}

func TestCreateUser_ExistingAccount_Conflict(t *testing.T) {
	svc, tr, ur, _, _ := provFixture(t)
	existing, _ := userdom.NewProvisionedLocalUser("taken@corp.com", "Taken")
	_ = ur.Create(context.Background(), existing)

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "Taken@corp.com", RoleIDs: viewerOnly,
	}, auditapp.AuditContext{})
	if !errors.Is(err, ErrAccountExists) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("existing account must be a conflict, got %v", err)
	}
	if len(tr.memberships) != 0 {
		t.Fatal("an existing account must not be attached to the organization")
	}
}

func TestCreateUser_AllowedDomainsEnforced(t *testing.T) {
	svc, tr, ur, _, _ := provFixture(t, "corp.com")

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "x@evil.com", RoleIDs: viewerOnly,
	}, auditapp.AuditContext{})
	if !errors.Is(err, ErrEmailDomainNotAllowed) {
		t.Fatalf("domain outside AllowedDomains must be refused, got %v", err)
	}
	if len(ur.byEmail) != 0 {
		t.Fatal("no account may be created")
	}
	if _, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "ok@corp.com", RoleIDs: viewerOnly,
	}, auditapp.AuditContext{}); err != nil {
		t.Fatalf("allowed domain must pass: %v", err)
	}
}

func TestCreateUser_OwnerRoleRefused(t *testing.T) {
	svc, tr, ur, _, _ := provFixture(t)
	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "x@corp.com", RoleIDs: []string{roledom.OwnerRoleID.String()},
	}, auditapp.AuditContext{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("owner role must be refused, got %v", err)
	}
	if len(ur.byEmail) != 0 {
		t.Fatal("no account may be created")
	}
}

// A role of another tenant is refused before any account is created; it used
// to be caught only by the grant, after the account and membership existed.
func TestCreateUser_ForeignRoleRefusedBeforeAccountCreated(t *testing.T) {
	svc, tr, ur, roles, _ := provFixture(t)
	foreign := shared.NewID().String()
	roles.foreign = map[string]bool{foreign: true}

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "x@corp.com", RoleIDs: []string{foreign},
	}, auditapp.AuditContext{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("another tenant's role must be refused, got %v", err)
	}
	if roles.checked != 1 {
		t.Fatalf("role tenancy must be checked once, got %d", roles.checked)
	}
	if len(ur.byEmail) != 0 || len(ur.deleted) != 0 || len(tr.memberships) != 0 {
		t.Fatalf("no account or membership may be created (users=%d deleted=%d memberships=%d)",
			len(ur.byEmail), len(ur.deleted), len(tr.memberships))
	}
}

func TestCreateUser_RoleGrantFailure_RollsBack(t *testing.T) {
	svc, tr, ur, roles, _ := provFixture(t)
	roles.err = errors.New("db down")

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "x@corp.com", RoleIDs: viewerOnly,
	}, auditapp.AuditContext{})
	if err == nil {
		t.Fatal("a role grant failure must fail the creation")
	}
	if len(ur.byEmail) != 0 || len(ur.deleted) != 1 || len(tr.deleted) != 1 {
		t.Fatalf("account and membership must be rolled back (users=%d deletedUsers=%d deletedMemberships=%d)",
			len(ur.byEmail), len(ur.deleted), len(tr.deleted))
	}
}

func TestCreateUser_MemberRoleMakesMemberMembership(t *testing.T) {
	svc, tr, ur, _, _ := provFixture(t)
	if _, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "m@corp.com", RoleIDs: []string{roledom.MemberRoleID.String()},
	}, auditapp.AuditContext{}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if m := tr.memberships[ur.byEmail["m@corp.com"].ID().String()]; m.Role() != tenantdom.RoleMember {
		t.Fatalf("member role must create a member membership, got %s", m.Role())
	}
}

// --- ReissueSetupLink --------------------------------------------------------

func createdUser(t *testing.T, svc *UserProvisioningService, tr *provTenantRepo, ur *provUserRepo) *userdom.User {
	t.Helper()
	if _, err := svc.CreateUser(context.Background(), CreateUserInput{
		TenantID: tr.tenant.ID().String(), Email: "p@corp.com", RoleIDs: viewerOnly,
	}, auditapp.AuditContext{}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return ur.byEmail["p@corp.com"]
}

func TestReissueSetupLink_PendingAccount_ReplacesToken(t *testing.T) {
	svc, tr, ur, _, _ := provFixture(t)
	u := createdUser(t, svc, tr, ur)
	oldHash := *u.PasswordResetToken()

	res, err := svc.ReissueSetupLink(context.Background(), tr.tenant.ID().String(), u.ID().String(), "", auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("ReissueSetupLink: %v", err)
	}
	if res.SetupToken == "" || *u.PasswordResetToken() == oldHash {
		t.Fatal("a fresh token must replace (and so invalidate) the previous one")
	}
}

func TestReissueSetupLink_UsedAccountRefused(t *testing.T) {
	svc, tr, ur, _, _ := provFixture(t)
	u := createdUser(t, svc, tr, ur)
	_ = u.SetPasswordHash("hash")

	if _, err := svc.ReissueSetupLink(context.Background(), tr.tenant.ID().String(), u.ID().String(), "", auditapp.AuditContext{}); !errors.Is(err, ErrNotPendingSetup) {
		t.Fatalf("an account with a password must be refused, got %v", err)
	}
}

func TestReissueSetupLink_AccountInAnotherOrganizationRefused(t *testing.T) {
	svc, tr, ur, _, _ := provFixture(t)
	u := createdUser(t, svc, tr, ur)
	tr.others = []tenantdom.UserMembership{{TenantID: shared.NewID().String()}}

	if _, err := svc.ReissueSetupLink(context.Background(), tr.tenant.ID().String(), u.ID().String(), "", auditapp.AuditContext{}); !errors.Is(err, ErrNotPendingSetup) {
		t.Fatalf("an account that also belongs to another organization must be refused, got %v", err)
	}
}

func TestReissueSetupLink_NonMemberNotFound(t *testing.T) {
	svc, tr, ur, _, _ := provFixture(t)
	stranger, _ := userdom.NewProvisionedLocalUser("s@corp.com", "S")
	_ = ur.Create(context.Background(), stranger)

	if _, err := svc.ReissueSetupLink(context.Background(), tr.tenant.ID().String(), stranger.ID().String(), "", auditapp.AuditContext{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a non-member must be not found, got %v", err)
	}
}

// addMember gives the fixture tenant a member with the given team role.
func addMember(t *testing.T, tr *provTenantRepo, role tenantdom.Role) shared.ID {
	t.Helper()
	uid := shared.NewID()
	m, err := tenantdom.NewMembership(uid, tr.tenant.ID(), role, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.memberships[uid.String()] = m
	return uid
}

// M1: the set-password link takes the pending account over, so an
// administrator may not obtain one for an owner or administrator account.
func TestReissueSetupLink_CallerBoundedByTargetRole(t *testing.T) {
	ctx := context.Background()
	svc, tr, ur, roles, _ := provFixture(t)
	u := createdUser(t, svc, tr, ur)
	tid := tr.tenant.ID().String()
	admin := addMember(t, tr, tenantdom.RoleAdmin).String()
	owner := addMember(t, tr, tenantdom.RoleOwner).String()
	viewer := addMember(t, tr, tenantdom.RoleViewer).String()

	// Pending viewer: an admin may reissue.
	if res, err := svc.ReissueSetupLink(ctx, tid, u.ID().String(), admin, auditapp.AuditContext{}); err != nil || res.SetupToken == "" {
		t.Fatalf("admin -> pending viewer: %v", err)
	}
	// A non-admin caller never may.
	if _, err := svc.ReissueSetupLink(ctx, tid, u.ID().String(), viewer, auditapp.AuditContext{}); !errors.Is(err, ErrSetupLinkForbidden) {
		t.Fatalf("viewer caller: want forbidden, got %v", err)
	}
	// A caller outside the organization never may.
	if _, err := svc.ReissueSetupLink(ctx, tid, u.ID().String(), shared.NewID().String(), auditapp.AuditContext{}); !errors.Is(err, ErrSetupLinkForbidden) {
		t.Fatalf("non-member caller: want forbidden, got %v", err)
	}
	// The role ceiling refuses: no token.
	roles.authErr = fmt.Errorf("%w: carries team:delete", shared.ErrForbidden)
	if res, err := svc.ReissueSetupLink(ctx, tid, u.ID().String(), admin, auditapp.AuditContext{}); !errors.Is(err, ErrSetupLinkForbidden) || res != nil {
		t.Fatalf("role beyond the caller's grants: want forbidden and no result, got %v", err)
	}
	roles.authErr = nil

	// Pending owner / admin targets need an owner.
	for _, role := range []tenantdom.Role{tenantdom.RoleOwner, tenantdom.RoleAdmin} {
		m := tr.memberships[u.ID().String()]
		if err := m.UpdateRole(role); err != nil {
			// UpdateRole refuses owner; rebuild the membership instead.
			nm, nerr := tenantdom.NewMembership(u.ID(), tr.tenant.ID(), role, nil)
			if nerr != nil {
				t.Fatal(nerr)
			}
			tr.memberships[u.ID().String()] = nm
		}
		if res, err := svc.ReissueSetupLink(ctx, tid, u.ID().String(), admin, auditapp.AuditContext{}); !errors.Is(err, ErrSetupLinkForbidden) || res != nil {
			t.Fatalf("admin -> pending %s: want forbidden and no token, got %v", role, err)
		}
		if res, err := svc.ReissueSetupLink(ctx, tid, u.ID().String(), owner, auditapp.AuditContext{}); err != nil || res.SetupToken == "" {
			t.Fatalf("owner -> pending %s: %v", role, err)
		}
		if res, err := svc.ReissueSetupLink(ctx, tid, u.ID().String(), "", auditapp.AuditContext{}); err != nil || res.SetupToken == "" {
			t.Fatalf("platform console -> pending %s: %v", role, err)
		}
	}
}
