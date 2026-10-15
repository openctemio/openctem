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
	"github.com/openctemio/openctem/api/pkg/logger"
)

// otStepUp passes or refuses re-authentication for everyone.
type otStepUp struct{ ok bool }

var errOTStepUp = errors.New("step-up required")

func (g otStepUp) RequireRecentAuth(context.Context, string) error {
	if g.ok {
		return nil
	}
	return errOTStepUp
}

// otMailer records the emails sent.
type otMailer struct {
	mu   sync.Mutex
	sent []string // "email|subject"
}

func (m *otMailer) NotifyOwnershipTransfer(_ context.Context, email, _, subject, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, email+"|"+subject)
}

func (m *otMailer) to(email string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.sent {
		if strings.HasPrefix(s, email+"|") {
			n++
		}
	}
	return n
}

type otEnv struct {
	t      *testing.T
	db     *sql.DB
	svc    *tenantapp.TenantService
	mailer *otMailer
	users  []string
}

func newOTEnv(t *testing.T, stepUp bool) *otEnv {
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
	svc := tenantapp.NewTenantService(postgres.NewTenantRepository(pg), log,
		tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(pg), log)))
	svc.SetOwnershipTransferRepository(postgres.NewOwnershipTransferRepository(pg))
	svc.SetStepUpGate(otStepUp{ok: stepUp})
	mailer := &otMailer{}
	svc.SetOwnershipTransferNotifier(mailer)
	svc.SetUserService(tenantapp.NewUserService(postgres.NewUserRepository(pg), log))
	return &otEnv{t: t, db: raw, svc: svc, mailer: mailer}
}

func (e *otEnv) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

func (e *otEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// org creates an organization and removes it, its people and its rows after.
func (e *otEnv) org() string {
	e.t.Helper()
	id := uuid.NewString()
	e.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Ownership IT', $2)`,
		id, "ownership-"+strings.ReplaceAll(id[:13], "-", ""))
	e.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM tenant_ownership_transfers WHERE tenant_id = $1`,
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
		} {
			_, _ = e.db.ExecContext(ctx, q, id)
		}
		for _, u := range e.users {
			_, _ = e.db.ExecContext(ctx, `DELETE FROM user_mfa WHERE user_id = $1
				AND NOT EXISTS (SELECT 1 FROM tenant_members m WHERE m.user_id = $1)`, u)
			_, _ = e.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1
				AND NOT EXISTS (SELECT 1 FROM tenant_members m WHERE m.user_id = $1)`, u)
		}
		_, _ = e.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

type otPerson struct {
	userID, membershipID, email string
}

type personOpt struct {
	mfa     bool
	kind    string // internal (default) or external
	home    string // home tenant id for a managed external
	status  string
	service bool
	expires bool
}

// person adds a member with role to org.
func (e *otEnv) person(org, role string, o personOpt) otPerson {
	e.t.Helper()
	p := otPerson{userID: uuid.NewString(), membershipID: uuid.NewString()}
	p.email = "ot-" + p.userID[:8] + "@it.test"
	e.users = append(e.users, p.userID)
	if o.service {
		e.exec(`INSERT INTO users (id, email, name, kind, service_tenant_id) VALUES ($1, $2, 'Service', 'service', $3)`,
			p.userID, p.email, org)
	} else {
		e.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, p.userID, p.email, "Person "+p.userID[:4])
	}
	if o.mfa {
		e.exec(`INSERT INTO user_mfa (user_id, secret_encrypted, enabled, enabled_at) VALUES ($1, 'x', true, now())`, p.userID)
	}
	kind := o.kind
	if kind == "" {
		kind = "internal"
	}
	status := o.status
	if status == "" {
		status = "active"
	}
	var home any
	if o.home != "" {
		home = o.home
	}
	var expires any
	if o.expires {
		expires = time.Now().Add(30 * 24 * time.Hour)
	}
	e.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role, status, kind, home_tenant_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, p.membershipID, p.userID, org, role, status, kind, home, expires)
	return p
}

func actx(org string, p otPerson) auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: org, ActorID: p.userID}
}

func (e *otEnv) role(org string, p otPerson) string {
	e.t.Helper()
	var r string
	if err := e.db.QueryRow(`SELECT role FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, org, p.userID).Scan(&r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

// checkOneOwner asserts the organization has exactly one owner, owner, by
// membership and by role, and that it holds exactly one system role.
func (e *otEnv) checkOneOwner(org string, owner otPerson) {
	e.t.Helper()
	if n := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND role = 'owner'`, org); n != 1 {
		e.t.Fatalf("owner memberships = %d, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM user_roles WHERE tenant_id = $1 AND role_id = '00000000-0000-0000-0000-000000000001'`, org); n != 1 {
		e.t.Fatalf("owner role rows = %d, want 1", n)
	}
	if r := e.role(org, owner); r != "owner" {
		e.t.Fatalf("owner is %s", r)
	}
	if n := e.count(`SELECT count(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.tenant_id = $1 AND ur.user_id = $2 AND r.is_system AND r.tenant_id IS NULL`, org, owner.userID); n != 1 {
		e.t.Fatalf("new owner holds %d system roles, want 1", n)
	}
}

func TestOwnershipTransfer_HappyPath(t *testing.T) {
	e := newOTEnv(t, true)
	org := e.org()
	owner := e.person(org, "owner", personOpt{mfa: true})
	target := e.person(org, "member", personOpt{mfa: true})
	ctx := context.Background()

	v, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID}, actx(org, owner))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if v.PreviousOwnerRole != "admin" || v.Viewer != "owner" || v.ExpiresAt.Sub(v.CreatedAt) != tenantdom.OwnershipTransferTTL {
		t.Fatalf("view = %+v", v)
	}
	// Nothing changes before acceptance.
	e.checkOneOwner(org, owner)
	if got, err := e.svc.PendingOwnershipTransfer(ctx, actx(org, target)); err != nil || got.Viewer != "new_owner" {
		t.Fatalf("target view = %+v, %v", got, err)
	}
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	e.checkOneOwner(org, target)
	if r := e.role(org, owner); r != "admin" {
		t.Fatalf("previous owner is %s, want admin", r)
	}
	if n := e.count(`SELECT count(*) FROM user_roles WHERE tenant_id = $1 AND user_id = $2 AND role_id = '00000000-0000-0000-0000-000000000002'`, org, owner.userID); n != 1 {
		t.Fatalf("previous owner admin role rows = %d", n)
	}
	// Audited on both sides; both told by email at each step.
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action IN ('member.ownership_transfer_requested','member.ownership_transferred')`, org); n != 2 {
		t.Fatalf("audit rows = %d, want 2", n)
	}
	if e.mailer.to(owner.email) != 2 || e.mailer.to(target.email) != 2 {
		t.Fatalf("emails = %v", e.mailer.sent)
	}
	// The request is closed.
	if _, err := e.svc.PendingOwnershipTransfer(ctx, actx(org, target)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotFound) {
		t.Fatalf("pending after accept: %v", err)
	}
	// The old owner can no longer start a transfer.
	other := e.person(org, "member", personOpt{mfa: true})
	if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: other.membershipID}, actx(org, owner)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotOwner) {
		t.Fatalf("old owner start: %v", err)
	}
}

func TestOwnershipTransfer_PreviousOwnerChosenRole(t *testing.T) {
	e := newOTEnv(t, true)
	org := e.org()
	owner := e.person(org, "owner", personOpt{mfa: true})
	target := e.person(org, "admin", personOpt{mfa: true})
	ctx := context.Background()
	if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID, PreviousOwnerRole: "owner"}, actx(org, owner)); !errors.Is(err, tenantdom.ErrOwnershipPreviousRole) {
		t.Fatalf("previous role owner: %v", err)
	}
	if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID, PreviousOwnerRole: "viewer"}, actx(org, owner)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)); err != nil {
		t.Fatal(err)
	}
	e.checkOneOwner(org, target)
	if r := e.role(org, owner); r != "viewer" {
		t.Fatalf("previous owner is %s, want viewer", r)
	}
}

func TestOwnershipTransfer_Refusals(t *testing.T) {
	e := newOTEnv(t, true)
	org := e.org()
	otherOrg := e.org()
	ctx := context.Background()
	owner := e.person(org, "owner", personOpt{mfa: true})
	admin := e.person(org, "admin", personOpt{mfa: true})
	noMFA := e.person(org, "member", personOpt{})
	suspended := e.person(org, "member", personOpt{mfa: true, status: "suspended"})
	service := e.person(org, "member", personOpt{service: true})
	managed := e.person(org, "member", personOpt{mfa: true, kind: "external", home: otherOrg})
	unmanaged := e.person(org, "member", personOpt{mfa: true, kind: "external"})
	foreign := e.person(otherOrg, "member", personOpt{mfa: true})
	e.person(otherOrg, "owner", personOpt{mfa: true})

	start := func(by otPerson, target string, confirm bool) error {
		_, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target, ConfirmInternal: confirm}, actx(org, by))
		return err
	}
	for _, tc := range []struct {
		name   string
		by     otPerson
		target string
		want   error
	}{
		{"non-owner (administrator)", admin, noMFA.membershipID, tenantdom.ErrOwnershipTransferNotOwner},
		{"no two-factor", owner, noMFA.membershipID, tenantdom.ErrOwnershipTargetNoMFA},
		{"suspended member", owner, suspended.membershipID, tenantdom.ErrOwnershipTargetInactive},
		{"service account", owner, service.membershipID, tenantdom.ErrOwnershipTargetService},
		{"managed by another organization", owner, managed.membershipID, tenantdom.ErrOwnershipTargetManaged},
		{"outsider without confirmation", owner, unmanaged.membershipID, tenantdom.ErrOwnershipTargetNeedsInternal},
		{"cross-tenant member", owner, foreign.membershipID, shared.ErrNotFound},
		{"self", owner, owner.membershipID, tenantdom.ErrOwnershipTargetSelf},
	} {
		if err := start(tc.by, tc.target, false); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if n := e.count(`SELECT count(*) FROM tenant_ownership_transfers WHERE tenant_id = $1`, org); n != 0 {
		t.Fatalf("refused requests stored: %d", n)
	}
	// A caller of another organization cannot see, cancel or accept this
	// organization's request: its token tenant is its own organization.
	if err := start(owner, admin.membershipID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(otherOrg, admin)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotFound) {
		t.Fatalf("accept from another organization: %v", err)
	}
	// Only the person asked can accept or decline; others see nothing.
	if _, err := e.svc.PendingOwnershipTransfer(ctx, actx(org, noMFA)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotFound) {
		t.Fatalf("bystander view: %v", err)
	}
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, noMFA)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotFound) {
		t.Fatalf("bystander accept: %v", err)
	}
	if err := e.svc.DeclineOwnershipTransfer(ctx, actx(org, owner)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotFound) {
		t.Fatalf("owner decline: %v", err)
	}
	if err := e.svc.CancelOwnershipTransfer(ctx, actx(org, admin)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotOwner) {
		t.Fatalf("target cancel: %v", err)
	}
	// One open request at a time.
	if err := start(owner, unmanaged.membershipID, true); !errors.Is(err, tenantdom.ErrOwnershipTransferPending) {
		t.Fatalf("second request: %v", err)
	}
	e.checkOneOwner(org, owner)
}

func TestOwnershipTransfer_StepUpRequiredOnBothSides(t *testing.T) {
	e := newOTEnv(t, false)
	org := e.org()
	owner := e.person(org, "owner", personOpt{mfa: true})
	target := e.person(org, "member", personOpt{mfa: true})
	ctx := context.Background()
	if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID}, actx(org, owner)); !errors.Is(err, errOTStepUp) {
		t.Fatalf("start without step-up: %v", err)
	}
	// Seeded request: acceptance without step-up is refused, nothing changes.
	e.exec(`INSERT INTO tenant_ownership_transfers (tenant_id, from_user_id, to_user_id, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour')`,
		org, owner.userID, target.userID)
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)); !errors.Is(err, errOTStepUp) {
		t.Fatalf("accept without step-up: %v", err)
	}
	e.checkOneOwner(org, owner)
}

func TestOwnershipTransfer_ExpiresAfter72Hours(t *testing.T) {
	e := newOTEnv(t, true)
	org := e.org()
	owner := e.person(org, "owner", personOpt{mfa: true})
	target := e.person(org, "member", personOpt{mfa: true})
	other := e.person(org, "member", personOpt{mfa: true})
	ctx := context.Background()
	if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID}, actx(org, owner)); err != nil {
		t.Fatal(err)
	}
	// 73 hours later.
	e.exec(`UPDATE tenant_ownership_transfers SET created_at = created_at - interval '73 hours', expires_at = expires_at - interval '73 hours' WHERE tenant_id = $1`, org)
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotFound) {
		t.Fatalf("accept after expiry: %v", err)
	}
	e.checkOneOwner(org, owner)
	// Noticing the lapse closes the request and records it.
	if n := e.count(`SELECT count(*) FROM tenant_ownership_transfers WHERE tenant_id = $1 AND status = 'expired'`, org); n != 1 {
		t.Fatalf("expired rows after the lapse was noticed = %d, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'member.ownership_transfer_expired'`, org); n != 1 {
		t.Fatalf("expiry audit rows = %d, want 1", n)
	}
	// The store closes a lapsed request it is asked to accept.
	store := postgres.NewOwnershipTransferRepository(&postgres.DB{DB: e.db})
	var id string
	if err := e.db.QueryRow(`SELECT id FROM tenant_ownership_transfers WHERE tenant_id = $1`, org).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tid, _ := shared.IDFromString(org)
	tr, _ := shared.IDFromString(id)
	uid, _ := shared.IDFromString(target.userID)
	if _, err := store.AcceptOwnershipTransfer(ctx, tid, tr, uid, time.Now()); !errors.Is(err, tenantdom.ErrOwnershipTransferNotFound) {
		t.Fatalf("store accept of an expired request: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM tenant_ownership_transfers WHERE tenant_id = $1 AND status = 'expired'`, org); n != 1 {
		t.Fatalf("expired rows = %d", n)
	}
	// A new request can be made.
	if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: other.membershipID}, actx(org, owner)); err != nil {
		t.Fatalf("new request after expiry: %v", err)
	}
}

func TestOwnershipTransfer_CancelAndDecline(t *testing.T) {
	e := newOTEnv(t, true)
	org := e.org()
	owner := e.person(org, "owner", personOpt{mfa: true})
	target := e.person(org, "member", personOpt{mfa: true})
	ctx := context.Background()
	in := tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID}
	if _, err := e.svc.StartOwnershipTransfer(ctx, in, actx(org, owner)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CancelOwnershipTransfer(ctx, actx(org, owner)); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)); !errors.Is(err, tenantdom.ErrOwnershipTransferNotFound) {
		t.Fatalf("accept after cancel: %v", err)
	}
	if _, err := e.svc.StartOwnershipTransfer(ctx, in, actx(org, owner)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeclineOwnershipTransfer(ctx, actx(org, target)); err != nil {
		t.Fatalf("decline: %v", err)
	}
	e.checkOneOwner(org, owner)
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action IN ('member.ownership_transfer_canceled','member.ownership_transfer_declined')`, org); n != 2 {
		t.Fatalf("audit rows = %d", n)
	}
}

func TestOwnershipTransfer_UnmanagedOutsiderBecomesInternal(t *testing.T) {
	e := newOTEnv(t, true)
	org := e.org()
	owner := e.person(org, "owner", personOpt{mfa: true})
	outsider := e.person(org, "admin", personOpt{mfa: true, kind: "external", expires: true})
	ctx := context.Background()
	if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: outsider.membershipID, ConfirmInternal: true}, actx(org, owner)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, outsider)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	e.checkOneOwner(org, outsider)
	if n := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND user_id = $2 AND kind = 'internal' AND expires_at IS NULL AND home_tenant_id IS NULL`, org, outsider.userID); n != 1 {
		t.Fatal("the new owner is not internal without an end of access")
	}
}

func TestOwnershipTransfer_RecheckedAtAcceptance(t *testing.T) {
	e := newOTEnv(t, true)
	org := e.org()
	owner := e.person(org, "owner", personOpt{mfa: true})
	target := e.person(org, "member", personOpt{mfa: true})
	ctx := context.Background()
	if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID}, actx(org, owner)); err != nil {
		t.Fatal(err)
	}
	// Two-factor turned off after the request: refused, request stays open.
	e.exec(`UPDATE user_mfa SET enabled = false WHERE user_id = $1`, target.userID)
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)); !errors.Is(err, tenantdom.ErrOwnershipTargetNoMFA) {
		t.Fatalf("accept without 2FA: %v", err)
	}
	e.checkOneOwner(org, owner)
	e.exec(`UPDATE user_mfa SET enabled = true WHERE user_id = $1`, target.userID)
	// Suspended after the request: refused.
	e.exec(`UPDATE tenant_members SET status = 'suspended' WHERE tenant_id = $1 AND user_id = $2`, org, target.userID)
	if _, err := e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)); !errors.Is(err, tenantdom.ErrOwnershipTargetInactive) {
		t.Fatalf("accept while suspended: %v", err)
	}
	e.checkOneOwner(org, owner)
}

// TestOwnershipTransfer_ConcurrentRace: concurrent requests leave one open;
// a concurrent accept and cancel have exactly one winner; two accepts change
// the owner once. The one-owner invariant holds after each race.
func TestOwnershipTransfer_ConcurrentRace(t *testing.T) {
	e := newOTEnv(t, true)
	ctx := context.Background()

	t.Run("concurrent requests", func(t *testing.T) {
		org := e.org()
		owner := e.person(org, "owner", personOpt{mfa: true})
		targets := make([]otPerson, 6)
		for i := range targets {
			targets[i] = e.person(org, "member", personOpt{mfa: true})
		}
		var wg sync.WaitGroup
		errs := make([]error, len(targets))
		for i := range targets {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: targets[i].membershipID}, actx(org, owner))
			}(i)
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, tenantdom.ErrOwnershipTransferPending):
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if ok != 1 || e.count(`SELECT count(*) FROM tenant_ownership_transfers WHERE tenant_id = $1 AND status = 'pending'`, org) != 1 {
			t.Fatalf("succeeded = %d, want exactly one open request", ok)
		}
	})

	t.Run("accept races cancel", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			org := e.org()
			owner := e.person(org, "owner", personOpt{mfa: true})
			target := e.person(org, "member", personOpt{mfa: true})
			if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID}, actx(org, owner)); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			var acceptErr, cancelErr error
			wg.Add(2)
			go func() { defer wg.Done(); _, acceptErr = e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)) }()
			go func() { defer wg.Done(); cancelErr = e.svc.CancelOwnershipTransfer(ctx, actx(org, owner)) }()
			wg.Wait()
			switch {
			case acceptErr == nil && cancelErr != nil:
				e.checkOneOwner(org, target)
			case cancelErr == nil && acceptErr != nil:
				e.checkOneOwner(org, owner)
			default:
				t.Fatalf("accept=%v cancel=%v: want exactly one winner", acceptErr, cancelErr)
			}
		}
	})

	t.Run("double accept", func(t *testing.T) {
		org := e.org()
		owner := e.person(org, "owner", personOpt{mfa: true})
		target := e.person(org, "member", personOpt{mfa: true})
		if _, err := e.svc.StartOwnershipTransfer(ctx, tenantapp.StartOwnershipTransferInput{MembershipID: target.membershipID}, actx(org, owner)); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			wg.Add(1)
			go func(i int) { defer wg.Done(); _, errs[i] = e.svc.AcceptOwnershipTransfer(ctx, actx(org, target)) }(i)
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("accepts succeeded = %d (%v), want 1", ok, errs)
		}
		e.checkOneOwner(org, target)
		if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'member.ownership_transferred'`, org); n != 1 {
			t.Fatalf("transfer audited %d times", n)
		}
	})
}

// TestOwnershipTransfer_LastOwnerProtection: the owner still cannot be
// demoted by a role change; the message points to the transfer.
func TestOwnershipTransfer_LastOwnerProtection(t *testing.T) {
	e := newOTEnv(t, true)
	org := e.org()
	owner := e.person(org, "owner", personOpt{mfa: true})
	_, err := e.svc.UpdateMemberRole(context.Background(), owner.membershipID, tenantapp.UpdateMemberRoleInput{Role: "admin"}, actx(org, owner))
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "Transfer ownership") {
		t.Fatalf("demote owner: %v", err)
	}
	e.checkOneOwner(org, owner)
}
