package integration

// Onboarding and join requests (RFC-104), end to end on the database: the
// fork offers an organization only to a verified holder of its discoverable,
// joinable domain; offer references are bound to the account; requests are
// listed and decided only by that organization; nobody joins as an
// administrator by request; auto join adds a viewer at once.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	"github.com/openctemio/openctem/api/internal/app/onboarding"
	signupapp "github.com/openctemio/openctem/api/internal/app/signup"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/joinrequest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
)

type onbTenants struct{ *tenantapp.TenantService }

func (t onbTenants) AddMemberApprovingJoinRequest(ctx context.Context, tenantID string, in onboarding.AddMemberInput, approver, requestID shared.ID, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	return t.TenantService.AddMemberApprovingJoinRequest(ctx, tenantID, tenantapp.AddMemberInput{UserID: in.UserID, Role: in.Role}, approver, requestID, actx)
}

func (t onbTenants) AddMember(ctx context.Context, tenantID string, in onboarding.AddMemberInput, inviter shared.ID, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	return t.TenantService.AddMember(ctx, tenantID, tenantapp.AddMemberInput{UserID: in.UserID, Role: in.Role}, inviter, actx)
}

func onbUser(t *testing.T, db *postgres.DB, email string, verified bool) *userdom.User {
	t.Helper()
	hash, err := password.New().Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, 'Onb', $3, 'local', 'active', $4, NOW(), NOW())`, id, email, hash, verified); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, id) })
	u, err := postgres.NewUserRepository(db).GetByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestOnboardingJoinByDomain(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	log := logger.NewNop()
	tenants := postgres.NewTenantRepository(db)
	vdRepo := postgres.NewVerifiedDomainRepository(db)
	domains := domainverify.NewService(vdRepo, nil, log)
	domains.SetSSOReadiness(func(context.Context, shared.ID) (bool, error) { return true, nil })
	tenantSvc := tenantapp.NewTenantService(tenants, log)
	requests := postgres.NewJoinRequestRepository(db)

	orgA := createTestTenant(t, db.DB, "onb-a")
	orgB := createTestTenant(t, db.DB, "onb-b")
	domain := "onb-" + uuid.NewString()[:8] + ".example"
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM organization_join_requests WHERE tenant_id IN ($1, $2)`, orgA.String(), orgB.String())
		_, _ = db.Exec(`DELETE FROM verified_domains WHERE tenant_id IN ($1, $2)`, orgA.String(), orgB.String())
		_, _ = db.Exec(`DELETE FROM tenant_members WHERE tenant_id IN ($1, $2)`, orgA.String(), orgB.String())
		cleanupTestData(db.DB, orgA, orgB)
	})
	vd, _ := verifieddomain.New(shared.NewID(), orgA, domain, "tok")
	vd.WithPurpose(verifieddomain.PurposeSSO)
	if err := vdRepo.Create(ctx, vd); err != nil {
		t.Fatal(err)
	}
	vd.MarkVerified(time.Now())
	if err := vdRepo.Update(ctx, vd); err != nil {
		t.Fatal(err)
	}
	setPolicy := func(p verifieddomain.SignupPolicy) {
		t.Helper()
		if _, _, err := domains.ChangeSignupPolicy(ctx, orgA, vd.ID(), p); err != nil {
			t.Fatal(err)
		}
	}
	setPolicy(verifieddomain.SignupPolicy{Join: verifieddomain.JoinApproval, JoinRole: "viewer", Discoverable: true})

	repo := withStoredSignupPolicy(t, db, signupdom.Policy{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen})
	policy := signupapp.NewService(repo, nil, nil, nil, log)
	policy.SetCeiling(signupdom.CeilingOpen)
	svc := onboarding.NewService(tenants, tenants, onbTenants{tenantSvc}, domains, policy, requests, nil, []byte("test-key-0123456789"), log)
	actx := auditapp.AuditContext{}

	// Unverified: nothing is offered by domain.
	unverified := onbUser(t, db, "new-"+uuid.NewString()[:6]+"@"+domain, false)
	opts, err := svc.Options(ctx, unverified)
	if err != nil || len(opts.Organizations) != 0 || opts.EmailVerified {
		t.Fatalf("an unverified address is offered nothing by domain: %+v %v", opts, err)
	}

	bob := onbUser(t, db, "bob-"+uuid.NewString()[:6]+"@"+domain, true)
	opts, err = svc.Options(ctx, bob)
	if err != nil || len(opts.Organizations) != 1 || opts.Organizations[0].Mode != "request" {
		t.Fatalf("a verified colleague is offered the organization: %+v %v", opts, err)
	}
	ref := opts.Organizations[0].Ref

	// The reference is bound to the account and cannot be altered.
	eve := onbUser(t, db, "eve-"+uuid.NewString()[:6]+"@"+domain, true)
	if _, err := svc.Accept(ctx, eve, ref, actx); !errors.Is(err, onboarding.ErrInvalidRef) {
		t.Fatalf("another account's reference must be refused, got %v", err)
	}
	if _, err := svc.Accept(ctx, bob, ref[:len(ref)-2]+"xx", actx); !errors.Is(err, onboarding.ErrInvalidRef) {
		t.Fatalf("a tampered reference must be refused, got %v", err)
	}

	res, err := svc.Accept(ctx, bob, ref, actx)
	if err != nil || res.Status != "requested" {
		t.Fatalf("approval policy asks: %+v %v", res, err)
	}
	if _, err := svc.Accept(ctx, bob, ref, actx); !errors.Is(err, joinrequest.ErrAlreadyPending) {
		t.Fatalf("one pending request per organization, got %v", err)
	}
	if opts, _ := svc.Options(ctx, bob); !opts.Organizations[0].Pending || opts.PendingRequests != 1 {
		t.Fatalf("options show the pending request: %+v", opts)
	}

	// Only organization A lists and decides it.
	if got, _ := svc.ListRequests(ctx, orgB); len(got) != 0 {
		t.Fatal("another organization must not see the request")
	}
	listed, err := svc.ListRequests(ctx, orgA)
	if err != nil || len(listed) != 1 || listed[0].Email != bob.Email() {
		t.Fatalf("organization A lists the request: %+v %v", listed, err)
	}
	reqID := listed[0].ID
	admin := onbUser(t, db, "admin-"+uuid.NewString()[:6]+"@"+domain, true)
	if err := svc.Approve(ctx, orgB, reqID, admin.ID(), "viewer", actx); !errors.Is(err, joinrequest.ErrNotFound) {
		t.Fatalf("cross-tenant approval must be not found, got %v", err)
	}
	if err := svc.Approve(ctx, orgA, reqID, admin.ID(), "admin", actx); !errors.Is(err, joinrequest.ErrInvalidRole) {
		t.Fatalf("nobody becomes an administrator by request, got %v", err)
	}
	if err := svc.Approve(ctx, orgA, reqID, shared.ID{}, "member", actx); err != nil {
		t.Fatalf("approve: %v", err)
	}
	m, err := tenants.GetMembership(ctx, bob.ID(), orgA)
	if err != nil || m.Role() != tenantdom.RoleMember {
		t.Fatalf("approved request creates the membership: %+v %v", m, err)
	}
	if err := svc.Reject(ctx, orgA, reqID, admin.ID(), actx); !errors.Is(err, joinrequest.ErrNotPending) {
		t.Fatalf("a decided request cannot be decided again, got %v", err)
	}

	// Approval re-checks the domain now: a request made while joining was
	// open is not approved once the owner turned joining off.
	fay := onbUser(t, db, "fay-"+uuid.NewString()[:6]+"@"+domain, true)
	opts, _ = svc.Options(ctx, fay)
	if _, err := svc.Accept(ctx, fay, opts.Organizations[0].Ref, actx); err != nil {
		t.Fatal(err)
	}
	listed, _ = svc.ListRequests(ctx, orgA)
	fayReq := listed[0].ID
	setPolicy(verifieddomain.SignupPolicy{Join: verifieddomain.JoinOff, JoinRole: "viewer", Discoverable: true})
	if err := svc.Approve(ctx, orgA, fayReq, shared.ID{}, "viewer", actx); !errors.Is(err, onboarding.ErrNoLongerJoinable) {
		t.Fatalf("approval after joining was turned off must be refused, got %v", err)
	}
	if _, err := tenants.GetMembership(ctx, fay.ID(), orgA); err == nil {
		t.Fatal("a refused approval adds nobody")
	}
	setPolicy(verifieddomain.SignupPolicy{Join: verifieddomain.JoinApproval, JoinRole: "viewer", Discoverable: true})

	// One transaction: when the membership cannot be created (the person
	// became a platform administrator), the request stays waiting.
	if _, err := db.Exec(`INSERT INTO admin_users (id, email, name, role, is_active, api_key_hash, api_key_prefix, user_id, created_at, updated_at)
		VALUES ($1, $2, 'fay', 'super_admin', FALSE, '!revoked', 'revoked-x', $3, NOW(), NOW())`, uuid.NewString(), fay.Email(), fay.ID().String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM admin_users WHERE user_id = $1`, fay.ID().String()) })
	if err := svc.Approve(ctx, orgA, fayReq, shared.ID{}, "viewer", actx); err == nil {
		t.Fatal("the membership insert must fail for a platform administrator")
	}
	if jr, err := requests.GetForTenant(ctx, orgA, fayReq); err != nil || jr.Status != joinrequest.StatusPending {
		t.Fatalf("the failed approval must roll back the decision: %+v %v", jr, err)
	}

	// Auto: joins at once as the domain's role.
	setPolicy(verifieddomain.SignupPolicy{Join: verifieddomain.JoinAuto, JoinRole: "viewer", Discoverable: true})
	cy := onbUser(t, db, "cy-"+uuid.NewString()[:6]+"@"+domain, true)
	opts, _ = svc.Options(ctx, cy)
	if len(opts.Organizations) != 1 || opts.Organizations[0].Mode != "join" {
		t.Fatalf("auto policy offers join: %+v", opts)
	}
	staleRef := opts.Organizations[0].Ref
	if res, err := svc.Accept(ctx, cy, staleRef, actx); err != nil || res.Status != "joined" {
		t.Fatalf("auto join: %+v %v", res, err)
	}
	if m, err := tenants.GetMembership(ctx, cy.ID(), orgA); err != nil || m.Role() != tenantdom.RoleViewer {
		t.Fatalf("auto join adds a viewer: %+v %v", m, err)
	}

	// An organization that stops being discoverable is not offered, and an
	// earlier reference no longer works.
	dee := onbUser(t, db, "dee-"+uuid.NewString()[:6]+"@"+domain, true)
	opts, _ = svc.Options(ctx, dee)
	oldRef := opts.Organizations[0].Ref
	setPolicy(verifieddomain.SignupPolicy{Join: verifieddomain.JoinAuto, JoinRole: "viewer"})
	if opts, _ := svc.Options(ctx, dee); len(opts.Organizations) != 0 {
		t.Fatal("a non-discoverable organization is never revealed")
	}
	if _, err := svc.Accept(ctx, dee, oldRef, actx); !errors.Is(err, onboarding.ErrInvalidRef) {
		t.Fatalf("an offer that no longer stands must be refused, got %v", err)
	}
	if _, err := tenants.GetMembership(ctx, dee.ID(), orgA); err == nil {
		t.Fatal("a refused offer adds nobody")
	}

	// Pending invitations for the verified address are listed (only to
	// that address), with the organization's name and no token.
	inv, err := tenantdom.NewInvitation(orgB, dee.Email(), tenantdom.RoleMember, admin.ID(), []string{"00000000-0000-0000-0000-000000000003"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tenants.CreateInvitation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	opts, _ = svc.Options(ctx, dee)
	if len(opts.Invitations) != 1 || opts.Invitations[0].OrganizationName != "onb-b" || opts.Invitations[0].Ref == "" {
		t.Fatalf("the invitation is offered: %+v", opts.Invitations)
	}
	if opts, _ := svc.Options(ctx, eve); len(opts.Invitations) != 0 {
		t.Fatal("another address never sees the invitation")
	}
	if _, err := svc.Accept(ctx, eve, opts.Invitations[0].Ref, actx); !errors.Is(err, onboarding.ErrInvalidRef) {
		t.Fatalf("another account cannot take the invitation, got %v", err)
	}

	// Decided requests are purged after the retention period.
	if _, err := db.Exec(`UPDATE organization_join_requests SET decided_at = now() - interval '31 days' WHERE id = $1`, reqID.String()); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.Purge(ctx); err != nil || n < 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := requests.GetForTenant(ctx, orgA, reqID); !errors.Is(err, joinrequest.ErrNotFound) {
		t.Fatal("the purged request is gone")
	}
}
