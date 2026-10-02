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
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeSetupMailer stands in for the organization's email: deliverable says
// whether SMTP is configured, fail makes the send fail.
type fakeSetupMailer struct {
	deliverable, fail bool
	sent              int
}

func (m *fakeSetupMailer) CanDeliverTo(context.Context, string) bool { return m.deliverable }
func (m *fakeSetupMailer) SendAccountSetupEmail(context.Context, string, string, string, string, string, time.Duration) error {
	if m.fail {
		return errors.New("smtp down")
	}
	m.sent++
	return nil
}

type firstOwnerEnv struct {
	t   *testing.T
	db  *sql.DB
	pg  *postgres.DB
	log *logger.Logger
}

func newFirstOwnerEnv(t *testing.T) *firstOwnerEnv {
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
	return &firstOwnerEnv{t: t, db: raw, pg: &postgres.DB{DB: raw}, log: logger.NewNop()}
}

func (e *firstOwnerEnv) service(mailer tenantapp.AccountSetupMailer) *tenantapp.UserProvisioningService {
	audit := auditapp.NewAuditService(postgres.NewAuditRepository(e.pg), e.log)
	return tenantapp.NewUserProvisioningService(postgres.NewTenantRepository(e.pg), postgres.NewUserRepository(e.pg),
		nil, mailer, audit, e.log)
}

// org creates an organization with no members and removes it (and every
// account that ended up in it) afterwards.
func (e *firstOwnerEnv) org() string {
	e.t.Helper()
	id := uuid.NewString()
	if _, err := e.db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'First owner IT', $2)`,
		id, "firstowner-"+strings.ReplaceAll(id[:13], "-", "")); err != nil {
		e.t.Fatalf("seed tenant: %v", err)
	}
	e.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = e.db.ExecContext(ctx, `DELETE FROM users WHERE id IN (SELECT user_id FROM tenant_members WHERE tenant_id = $1)`, id)
		for _, q := range []string{
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = e.db.ExecContext(ctx, q, id)
		}
	})
	return id
}

func (e *firstOwnerEnv) email() string {
	addr := "first-owner-" + uuid.NewString()[:8] + "@it.test"
	e.t.Cleanup(func() { _, _ = e.db.Exec(`DELETE FROM users WHERE email = $1`, addr) })
	return addr
}

func (e *firstOwnerEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

var platformAdminActor = auditapp.AuditContext{ActorEmail: "platform-admin:ops@platform.test"}

func TestCreateFirstOwner_NoSMTP_ReturnsLinkOnceAndAudits(t *testing.T) {
	e := newFirstOwnerEnv(t)
	org := e.org()
	email := e.email()

	res, err := e.service(nil).CreateFirstOwner(context.Background(), org, email, "First Owner", platformAdminActor)
	if err != nil {
		t.Fatalf("CreateFirstOwner: %v", err)
	}
	if res.SetupToken == "" || res.EmailSent {
		t.Fatalf("without SMTP the link is returned once: token=%q sent=%v", res.SetupToken, res.EmailSent)
	}
	if res.Membership == nil || !res.Membership.IsOwner() {
		t.Fatalf("membership = %+v, want owner", res.Membership)
	}
	uid := res.User.ID().String()
	if n := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id=$1 AND user_id=$2 AND role='owner'`, org, uid); n != 1 {
		t.Fatalf("owner membership rows = %d", n)
	}
	if n := e.count(`SELECT count(*) FROM user_roles WHERE tenant_id=$1 AND user_id=$2 AND role_id='00000000-0000-0000-0000-000000000001'`, org, uid); n != 1 {
		t.Fatalf("owner role rows = %d", n)
	}
	// No password: the owner's first sign-in is with one they set via the link.
	if n := e.count(`SELECT count(*) FROM users WHERE id=$1 AND password_hash IS NULL AND password_reset_token IS NOT NULL`, uid); n != 1 {
		t.Fatalf("account is not password-less with a pending setup link")
	}
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id=$1 AND action='user.created' AND resource_id=$2
		AND actor_email='platform-admin:ops@platform.test' AND severity='high'`, org, uid); n != 1 {
		t.Fatalf("organization audit rows for the bootstrap = %d, want 1", n)
	}
}

func TestCreateFirstOwner_RefusedWhenOrganizationHasOwner(t *testing.T) {
	e := newFirstOwnerEnv(t)
	org := e.org()
	svc := e.service(nil)
	if _, err := svc.CreateFirstOwner(context.Background(), org, e.email(), "", platformAdminActor); err != nil {
		t.Fatalf("first: %v", err)
	}
	second := e.email()
	_, err := svc.CreateFirstOwner(context.Background(), org, second, "", platformAdminActor)
	if !errors.Is(err, tenantdom.ErrOrganizationHasOwner) {
		t.Fatalf("second owner: err = %v, want ErrOrganizationHasOwner", err)
	}
	if n := e.count(`SELECT count(*) FROM users WHERE email=$1`, second); n != 0 {
		t.Fatalf("a refused bootstrap left an account behind")
	}
}

func TestCreateFirstOwner_SMTPConfigured_NeverReturnsLink(t *testing.T) {
	e := newFirstOwnerEnv(t)

	ok := &fakeSetupMailer{deliverable: true}
	res, err := e.service(ok).CreateFirstOwner(context.Background(), e.org(), e.email(), "", platformAdminActor)
	if err != nil {
		t.Fatalf("CreateFirstOwner: %v", err)
	}
	if !res.EmailSent || res.SetupToken != "" || ok.sent != 1 {
		t.Fatalf("SMTP configured: sent=%v token=%q mails=%d, want emailed and no token", res.EmailSent, res.SetupToken, ok.sent)
	}

	// A failed send does not fall back to handing the link over.
	broken := &fakeSetupMailer{deliverable: true, fail: true}
	res, err = e.service(broken).CreateFirstOwner(context.Background(), e.org(), e.email(), "", platformAdminActor)
	if err != nil {
		t.Fatalf("CreateFirstOwner with failing SMTP: %v", err)
	}
	if res.SetupToken != "" || res.EmailSent || !res.EmailFailed {
		t.Fatalf("failed send: token=%q sent=%v failed=%v, want no token and email_failed", res.SetupToken, res.EmailSent, res.EmailFailed)
	}
}

func TestCreateFirstOwner_ConcurrentRequestsCreateOneOwner(t *testing.T) {
	e := newFirstOwnerEnv(t)
	org := e.org()
	svc := e.service(nil)
	const n = 6
	emails := make([]string, n)
	for i := range emails {
		emails[i] = e.email()
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.CreateFirstOwner(context.Background(), org, emails[i], "", platformAdminActor)
		}(i)
	}
	wg.Wait()
	okCount := 0
	for _, err := range errs {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, tenantdom.ErrOrganizationHasOwner):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if okCount != 1 {
		t.Fatalf("%d concurrent bootstraps succeeded, want exactly 1", okCount)
	}
	if got := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id=$1 AND role='owner'`, org); got != 1 {
		t.Fatalf("owners = %d, want 1", got)
	}
}

// The owner account created together with an organization follows the same
// delivery rule.
func TestIssueFirstOwnerSetupLink_SMTPConfigured_NoToken(t *testing.T) {
	e := newFirstOwnerEnv(t)
	ctx := context.Background()
	mailer := &fakeSetupMailer{deliverable: true}
	svc := e.service(mailer)
	email := e.email()
	u, err := svc.CreateAccount(ctx, email, "Org Owner")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	tenants := tenantapp.NewTenantService(postgres.NewTenantRepository(e.pg), e.log)
	slug := "fo-" + uuid.NewString()[:8]
	org, err := tenants.CreateTenant(ctx, tenantapp.CreateTenantInput{Name: "First owner org", Slug: slug}, u.ID(), platformAdminActor)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM audit_log_chain WHERE tenant_id = $1`, `DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`, `DELETE FROM tenant_members WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
			_, _ = e.db.Exec(q, org.ID().String())
		}
	})
	res, err := svc.IssueFirstOwnerSetupLink(ctx, org, u, platformAdminActor)
	if err != nil {
		t.Fatalf("IssueFirstOwnerSetupLink: %v", err)
	}
	if !res.EmailSent || res.SetupToken != "" {
		t.Fatalf("sent=%v token=%q, want emailed only", res.EmailSent, res.SetupToken)
	}

	svcNoMail := e.service(nil)
	res, err = svcNoMail.IssueFirstOwnerSetupLink(ctx, org, u, platformAdminActor)
	if err != nil {
		t.Fatalf("IssueFirstOwnerSetupLink without SMTP: %v", err)
	}
	if res.SetupToken == "" {
		t.Fatalf("without SMTP the link is returned once")
	}
}
