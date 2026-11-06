package tenant_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Ownership invitations against a real database
// (docs/architecture/organization-ownership-invitations.md).

type oiStepUp struct{ ok bool }

var errOIStepUp = errors.New("step-up required")

func (g *oiStepUp) RequireRecentAuth(context.Context, string) error {
	if g.ok {
		return nil
	}
	return errOIStepUp
}

type oiMailer struct {
	mu       sync.Mutex
	invites  []string // email|org
	canceled []string
}

func (m *oiMailer) SendOwnershipInvitation(_ context.Context, email, _, org string, _ time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites = append(m.invites, email+"|"+org)
}

func (m *oiMailer) NotifyOwnershipTransfer(_ context.Context, email, _, _, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.canceled = append(m.canceled, email)
}

func (m *oiMailer) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.invites), len(m.canceled)
}

type oiEnv struct {
	t       *testing.T
	db      *sql.DB
	svc     *tenantapp.TenantService
	creator *tenantapp.OrganizationCreator
	users   userdom.Repository
	stepUp  *oiStepUp
	mailer  *oiMailer
}

func newOIEnv(t *testing.T) *oiEnv {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	pg := &postgres.DB{DB: raw}
	log := logger.NewNop()
	tenants := postgres.NewTenantRepository(pg)
	users := postgres.NewUserRepository(pg)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(pg), log)
	svc := tenantapp.NewTenantService(tenants, log, tenantapp.WithTenantAuditService(auditSvc))
	svc.SetOwnerInvitationRepository(tenants)
	step := &oiStepUp{ok: true}
	svc.SetStepUpGate(step)
	mailer := &oiMailer{}
	svc.SetOwnerInvitationNotifier(mailer)
	prov := tenantapp.NewUserProvisioningService(tenants, users, nil, nil, auditSvc, log)
	return &oiEnv{t: t, db: raw, svc: svc, creator: tenantapp.NewOrganizationCreator(svc, prov, users, log),
		users: users, stepUp: step, mailer: mailer}
}

func (e *oiEnv) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

func (e *oiEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// account inserts a person account (email verified) and removes it after.
func (e *oiEnv) account(verified bool) *userdom.User {
	e.t.Helper()
	id := uuid.NewString()
	email := "oi-" + id[:8] + "@it.test"
	e.exec(`INSERT INTO users (id, email, name, email_verified) VALUES ($1, $2, 'Invitee', $3)`, id, email, verified)
	e.t.Cleanup(func() {
		_, _ = e.db.Exec(`DELETE FROM users WHERE id = $1`, id)
	})
	u, err := e.users.GetByEmail(context.Background(), email)
	if err != nil {
		e.t.Fatalf("load account: %v", err)
	}
	return u
}

// cleanupOrg removes an organization the test created, and its rows.
func (e *oiEnv) cleanupOrg(id string) {
	e.t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM organization_owner_invitations WHERE tenant_id = $1`,
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
			`DELETE FROM tenant_limits WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = e.db.Exec(q, id)
		}
	})
}

func adminActx() auditapp.AuditContext {
	return auditapp.AuditContext{ActorEmail: "platform-admin:ops@example.com"}
}

// create makes an organization for owner's existing account through the
// console path and returns it with its invitation.
func (e *oiEnv) create(owner *userdom.User) (*tenantapp.CreatedOrganization, *tenantdom.OwnerInvitation) {
	e.t.Helper()
	slug := "oi-" + strings.ReplaceAll(uuid.NewString()[:13], "-", "")
	created, err := e.creator.Create(context.Background(), tenantapp.CreateOrganizationInput{
		Name: "VNDS " + slug, Slug: slug, OwnerEmail: owner.Email(),
		InviteExistingOwner: true, InvitedBy: shared.NewID(),
	}, adminActx())
	if err != nil {
		e.t.Fatalf("create organization: %v", err)
	}
	e.cleanupOrg(created.Tenant.ID().String())
	if created.OwnerInvitation == nil {
		e.t.Fatal("existing account: want an ownership invitation")
	}
	return created, created.OwnerInvitation
}

func (e *oiEnv) members(tenantID shared.ID) int {
	return e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1`, tenantID.String())
}

func (e *oiEnv) status(inv *tenantdom.OwnerInvitation) string {
	e.t.Helper()
	var s string
	if err := e.db.QueryRow(`SELECT status FROM organization_owner_invitations WHERE id = $1`, inv.ID.String()).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func inviteeActx(u *userdom.User) auditapp.AuditContext {
	return auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email()}
}

func TestOwnerInvitation_ExistingAccountGetsPendingOrganization(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	created, inv := e.create(owner)

	if created.OwnerCreated || created.OwnerSetup != nil {
		t.Fatal("no account may be created or set up for an existing owner")
	}
	if n := e.members(created.Tenant.ID()); n != 0 {
		t.Fatalf("pending organization has %d members, want 0 (nobody can enter it)", n)
	}
	if inv.InviteeUserID != owner.ID() || inv.Status != tenantdom.OwnerInvitationPending {
		t.Fatalf("invitation = %+v", inv)
	}
	if d := time.Until(inv.ExpiresAt); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Fatalf("expires in %v, want about 7 days", d)
	}
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'member.owner_invitation_sent'`,
		created.Tenant.ID().String()); n != 1 {
		t.Fatalf("owner_invitation_sent audit rows = %d", n)
	}
	if sent, _ := e.mailer.counts(); sent != 1 {
		t.Fatalf("invitation emails = %d, want 1", sent)
	}
	offers, err := e.svc.ListMyOwnerInvitations(context.Background(), owner.ID())
	if err != nil || len(offers) != 1 || offers[0].TenantID != created.Tenant.ID() {
		t.Fatalf("invitee offers = %+v, %v", offers, err)
	}
	// Another account sees nothing.
	other := e.account(true)
	if offers, _ := e.svc.ListMyOwnerInvitations(context.Background(), other.ID()); len(offers) != 0 {
		t.Fatalf("another account sees %d offers", len(offers))
	}
}

func TestOwnerInvitation_WithoutInviteFlagStillRefused(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	_, err := e.creator.Create(context.Background(), tenantapp.CreateOrganizationInput{
		Name: "Refused", Slug: "oi-refused-" + uuid.NewString()[:8], OwnerEmail: owner.Email(),
	}, adminActx())
	if !errors.Is(err, tenantapp.ErrOwnerAccountExists) {
		t.Fatalf("err = %v, want ErrOwnerAccountExists (consent rule for every other path)", err)
	}
}

func TestOwnerInvitation_AcceptByInviteeWithStepUp(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	created, inv := e.create(owner)
	ctx := context.Background()

	e.stepUp.ok = false
	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner)); !errors.Is(err, errOIStepUp) {
		t.Fatalf("without step-up: err = %v", err)
	}
	if e.members(created.Tenant.ID()) != 0 {
		t.Fatal("refused acceptance created a membership")
	}
	e.stepUp.ok = true
	got, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got.TenantID != created.Tenant.ID() {
		t.Fatal("accepted the wrong organization")
	}
	if n := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND user_id = $2 AND role = 'owner'`,
		created.Tenant.ID().String(), owner.ID().String()); n != 1 {
		t.Fatalf("owner memberships = %d", n)
	}
	if n := e.count(`SELECT count(*) FROM user_roles WHERE tenant_id = $1 AND user_id = $2
		AND role_id = '00000000-0000-0000-0000-000000000001'`, created.Tenant.ID().String(), owner.ID().String()); n != 1 {
		t.Fatalf("owner role rows = %d", n)
	}
	if s := e.status(inv); s != "accepted" {
		t.Fatalf("status = %s", s)
	}
	// Single use.
	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner)); !errors.Is(err, tenantdom.ErrOwnerInvitationNotFound) {
		t.Fatalf("second accept: err = %v", err)
	}
	// Once accepted, the console cannot invite anyone else into it.
	if _, err := e.svc.InviteOwner(ctx, created.Tenant.ID(), e.account(true), shared.ID{}, adminActx()); !errors.Is(err, tenantdom.ErrOwnerInvitationNotAllowed) {
		t.Fatalf("re-invite after acceptance: err = %v", err)
	}
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'member.owner_invitation_accepted' AND actor_id = $2`,
		created.Tenant.ID().String(), owner.ID().String()); n != 1 {
		t.Fatalf("accepted audit rows = %d", n)
	}
}

func TestOwnerInvitation_AnotherAccountCannotRedeem(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	created, inv := e.create(owner)
	other := e.account(true)
	ctx := context.Background()

	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, other, inviteeActx(other)); !errors.Is(err, tenantdom.ErrOwnerInvitationNotFound) {
		t.Fatalf("accept by another account: err = %v", err)
	}
	if err := e.svc.DeclineOwnerInvitation(ctx, inv.ID, other, inviteeActx(other)); !errors.Is(err, tenantdom.ErrOwnerInvitationNotFound) {
		t.Fatalf("decline by another account: err = %v", err)
	}
	if e.members(created.Tenant.ID()) != 0 || e.status(inv) != "pending" {
		t.Fatal("another account changed the invitation")
	}
	// The invitee can still accept.
	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner)); err != nil {
		t.Fatalf("invitee accept: %v", err)
	}
}

func TestOwnerInvitation_UnverifiedEmailCannotAccept(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(false)
	created, inv := e.create(owner)
	if _, err := e.svc.AcceptOwnerInvitation(context.Background(), inv.ID, owner, inviteeActx(owner)); !errors.Is(err, tenantdom.ErrOwnerInviteeEmailUnverified) {
		t.Fatalf("err = %v", err)
	}
	if e.members(created.Tenant.ID()) != 0 {
		t.Fatal("unverified account became a member")
	}
}

func TestOwnerInvitation_ExpiredRefused(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	created, inv := e.create(owner)
	e.exec(`UPDATE organization_owner_invitations SET expires_at = now() - interval '1 minute' WHERE id = $1`, inv.ID.String())
	ctx := context.Background()
	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner)); !errors.Is(err, tenantdom.ErrOwnerInvitationExpired) {
		t.Fatalf("err = %v", err)
	}
	if offers, _ := e.svc.ListMyOwnerInvitations(ctx, owner.ID()); len(offers) != 0 {
		t.Fatal("expired invitation still offered")
	}
	if e.members(created.Tenant.ID()) != 0 {
		t.Fatal("expired invitation created a membership")
	}
	// A resend renews it.
	e.exec(`UPDATE organization_owner_invitations SET last_sent_at = now() - interval '1 hour' WHERE id = $1`, inv.ID.String())
	if _, err := e.svc.ResendOwnerInvitation(ctx, created.Tenant.ID(), adminActx()); err != nil {
		t.Fatalf("resend: %v", err)
	}
	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner)); err != nil {
		t.Fatalf("accept after resend: %v", err)
	}
}

func TestOwnerInvitation_Decline(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	created, inv := e.create(owner)
	ctx := context.Background()
	if err := e.svc.DeclineOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner)); err != nil {
		t.Fatalf("decline: %v", err)
	}
	if s := e.status(inv); s != "declined" {
		t.Fatalf("status = %s", s)
	}
	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner)); !errors.Is(err, tenantdom.ErrOwnerInvitationNotFound) {
		t.Fatalf("accept after decline: err = %v", err)
	}
	// The administrator may invite again: nobody ever entered.
	next := e.account(true)
	if _, err := e.svc.InviteOwner(ctx, created.Tenant.ID(), next, shared.ID{}, adminActx()); err != nil {
		t.Fatalf("invite after decline: %v", err)
	}
}

func TestOwnerInvitation_ResendLimits(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	created, inv := e.create(owner)
	ctx := context.Background()
	if _, err := e.svc.ResendOwnerInvitation(ctx, created.Tenant.ID(), adminActx()); !errors.Is(err, tenantdom.ErrOwnerInvitationResendTooSoon) {
		t.Fatalf("immediate resend: err = %v", err)
	}
	for i := 2; i <= tenantdom.OwnerInvitationMaxSends; i++ {
		e.exec(`UPDATE organization_owner_invitations SET last_sent_at = now() - interval '1 hour' WHERE id = $1`, inv.ID.String())
		got, err := e.svc.ResendOwnerInvitation(ctx, created.Tenant.ID(), adminActx())
		if err != nil {
			t.Fatalf("resend %d: %v", i, err)
		}
		if got.SendCount != i {
			t.Fatalf("send count = %d, want %d", got.SendCount, i)
		}
	}
	e.exec(`UPDATE organization_owner_invitations SET last_sent_at = now() - interval '1 hour' WHERE id = $1`, inv.ID.String())
	if _, err := e.svc.ResendOwnerInvitation(ctx, created.Tenant.ID(), adminActx()); !errors.Is(err, tenantdom.ErrOwnerInvitationResendLimit) {
		t.Fatalf("resend over the cap: err = %v", err)
	}
	if sent, _ := e.mailer.counts(); sent != tenantdom.OwnerInvitationMaxSends {
		t.Fatalf("emails = %d, want %d", sent, tenantdom.OwnerInvitationMaxSends)
	}
}

func TestOwnerInvitation_CancelAndReplace(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	created, inv := e.create(owner)
	ctx := context.Background()

	// Replace: the first invitee's invitation is canceled.
	second := e.account(true)
	inv2, err := e.svc.InviteOwner(ctx, created.Tenant.ID(), second, shared.ID{}, adminActx())
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if s := e.status(inv); s != "canceled" {
		t.Fatalf("replaced invitation status = %s", s)
	}
	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv.ID, owner, inviteeActx(owner)); !errors.Is(err, tenantdom.ErrOwnerInvitationNotFound) {
		t.Fatalf("accept of a replaced invitation: err = %v", err)
	}
	// Cancel.
	if _, err := e.svc.CancelOwnerInvitation(ctx, created.Tenant.ID(), adminActx()); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if s := e.status(inv2); s != "canceled" {
		t.Fatalf("canceled status = %s", s)
	}
	if _, err := e.svc.CancelOwnerInvitation(ctx, created.Tenant.ID(), adminActx()); !errors.Is(err, tenantdom.ErrOwnerInvitationNotFound) {
		t.Fatalf("second cancel: err = %v", err)
	}
	if _, err := e.svc.AcceptOwnerInvitation(ctx, inv2.ID, second, inviteeActx(second)); !errors.Is(err, tenantdom.ErrOwnerInvitationNotFound) {
		t.Fatalf("accept of a canceled invitation: err = %v", err)
	}
	if _, canceled := e.mailer.counts(); canceled != 2 {
		t.Fatalf("withdrawal notices = %d, want 2", canceled)
	}
	if e.members(created.Tenant.ID()) != 0 {
		t.Fatal("membership after cancel")
	}
}

func TestOwnerInvitation_NotForAnOrganizationWithDataOrPeople(t *testing.T) {
	e := newOIEnv(t)
	ctx := context.Background()
	// A plain organization (never created waiting for an owner) with no
	// owner: an existing account is never invited into it.
	id := uuid.NewString()
	e.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Plain', $2)`, id, "oi-plain-"+id[:8])
	e.cleanupOrg(id)
	tid, _ := shared.IDFromString(id)
	if _, err := e.svc.InviteOwner(ctx, tid, e.account(true), shared.ID{}, adminActx()); !errors.Is(err, tenantdom.ErrOwnerInvitationNotAllowed) {
		t.Fatalf("plain organization: err = %v", err)
	}

	// A pending organization someone was put into (by SSO, say): refused too.
	owner := e.account(true)
	created, _ := e.create(owner)
	member := e.account(true)
	e.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'member')`,
		uuid.NewString(), member.ID().String(), created.Tenant.ID().String())
	if _, err := e.svc.InviteOwner(ctx, created.Tenant.ID(), e.account(true), shared.ID{}, adminActx()); !errors.Is(err, tenantdom.ErrOwnerInvitationNotAllowed) {
		t.Fatalf("organization with a member: err = %v", err)
	}
}

func TestOwnerInvitation_RefusedOnceAnOwnerExists(t *testing.T) {
	e := newOIEnv(t)
	owner := e.account(true)
	created, inv := e.create(owner)
	// An owner appears by another path (first-owner bootstrap); it also
	// cancels the pending invitation.
	first := e.account(true)
	m, err := tenantdom.NewOwnerMembership(first.ID(), created.Tenant.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := postgres.NewTenantRepository(&postgres.DB{DB: e.db}).CreateFirstOwnerMembership(context.Background(), m, false); err != nil {
		t.Fatalf("first owner: %v", err)
	}
	if s := e.status(inv); s != "canceled" {
		t.Fatalf("first-owner bootstrap left the invitation %s", s)
	}
	if _, err := e.svc.AcceptOwnerInvitation(context.Background(), inv.ID, owner, inviteeActx(owner)); !errors.Is(err, tenantdom.ErrOwnerInvitationNotFound) {
		t.Fatalf("accept after an owner exists: err = %v", err)
	}
	if n := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND role = 'owner'`, created.Tenant.ID().String()); n != 1 {
		t.Fatalf("owners = %d, want 1", n)
	}
}

func TestOwnerInvitation_InactiveAccountNotInvited(t *testing.T) {
	e := newOIEnv(t)
	// A suspended account cannot be invited.
	owner := e.account(true)
	e.exec(`UPDATE users SET status = 'suspended' WHERE id = $1`, owner.ID().String())
	u, _ := e.users.GetByEmail(context.Background(), owner.Email())
	_, err := e.creator.Create(context.Background(), tenantapp.CreateOrganizationInput{
		Name: "Suspended", Slug: "oi-susp-" + uuid.NewString()[:8], OwnerEmail: u.Email(), InviteExistingOwner: true,
	}, adminActx())
	if !errors.Is(err, tenantdom.ErrOwnerInviteeNotEligible) {
		t.Fatalf("err = %v", err)
	}
	if n := e.count(`SELECT count(*) FROM tenants WHERE name = 'Suspended' AND slug LIKE 'oi-susp-%'`); n != 0 {
		t.Fatal("organization left behind after a refused invitation")
	}
}

func TestOwnerInvitation_NewEmailPathUnchanged(t *testing.T) {
	e := newOIEnv(t)
	email := "oi-new-" + uuid.NewString()[:8] + "@it.test"
	created, err := e.creator.Create(context.Background(), tenantapp.CreateOrganizationInput{
		Name: "New owner", Slug: "oi-new-" + uuid.NewString()[:8], OwnerEmail: email, InviteExistingOwner: true,
	}, adminActx())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	e.cleanupOrg(created.Tenant.ID().String())
	t.Cleanup(func() { _, _ = e.db.Exec(`DELETE FROM users WHERE email = $1`, email) })
	if !created.OwnerCreated || created.OwnerInvitation != nil {
		t.Fatalf("new email: created=%v invitation=%v", created.OwnerCreated, created.OwnerInvitation)
	}
	if n := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND role = 'owner'`, created.Tenant.ID().String()); n != 1 {
		t.Fatalf("owners = %d, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM organization_owner_invitations WHERE tenant_id = $1`, created.Tenant.ID().String()); n != 0 {
		t.Fatal("new email path wrote an invitation")
	}
}
