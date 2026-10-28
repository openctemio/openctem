package supportaccess_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/supportaccess"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	dom "github.com/openctemio/openctem/api/pkg/domain/supportaccess"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type sentMail struct{ to, subject string }

type captureMailer struct {
	mu   sync.Mutex
	sent []sentMail
}

func (m *captureMailer) NotifySupportAccess(_ context.Context, email, _, subject, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{email, subject})
}

func (m *captureMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

type ownersOf struct{ db *sql.DB }

func (o ownersOf) ListActiveOwners(ctx context.Context, tenantID shared.ID) ([]ssochange.OwnerContact, error) {
	rows, err := o.db.QueryContext(ctx, `SELECT u.id, u.email FROM tenant_members m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.role = 'owner'`, tenantID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ssochange.OwnerContact
	for rows.Next() {
		var id, email string
		if err := rows.Scan(&id, &email); err != nil {
			return nil, err
		}
		uid, _ := shared.IDFromString(id)
		out = append(out, ssochange.OwnerContact{UserID: uid, Email: email})
	}
	return out, rows.Err()
}

type names struct{}

func (names) TenantName(context.Context, shared.ID) (string, error) { return "Acme", nil }

type fixture struct {
	db                    *sql.DB
	svc                   *supportaccess.Service
	clock                 *time.Time
	mailer                *captureMailer
	tenant, other         shared.ID
	owner                 shared.ID
	support, otherSupport *admin.AdminUser
	readonly              *admin.AdminUser
	ownFinding            shared.ID
	ownAsset              shared.ID
	foreignFinding        shared.ID
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	f := &fixture{db: raw, mailer: &captureMailer{}}
	f.tenant, f.other, f.owner = shared.NewID(), shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{f.tenant, f.other} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'support it', $2)`, id.String(), "sup-"+id.String())
		tid := id
		t.Cleanup(func() { _, _ = raw.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String()) })
	}
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Owner')`, f.owner.String(), "owner-"+f.owner.String()[:8]+"@example.com")
	t.Cleanup(func() { _, _ = raw.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, f.owner.String()) })
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'owner')`, f.owner.String(), f.tenant.String())

	admins := postgres.NewAdminRepository(&postgres.DB{DB: raw})
	mkAdmin := func(role admin.AdminRole) *admin.AdminUser {
		id := uuid.NewString()
		email := "support-" + id[:8] + "@example.com"
		exec(`INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Support', $3)`, id, email, string(role))
		t.Cleanup(func() { _, _ = raw.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, id) })
		a, err := admins.GetByEmail(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	f.support, f.otherSupport, f.readonly = mkAdmin(admin.AdminRoleOpsAdmin), mkAdmin(admin.AdminRoleSuperAdmin), mkAdmin(admin.AdminRoleReadonly)

	asset := func(tid shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`, id.String(), tid.String(), "a-"+id.String()[:8]+".example")
		return id
	}
	finding := func(tid, aid shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, title, snippet)
			VALUES ($1::uuid, $2, $3, 'secret', 'gitleaks', 'AKIAEXAMPLESECRET', 'high', $1::text, 'new', 'AWS key in config', 'AKIAEXAMPLESECRET')`,
			id.String(), tid.String(), aid.String())
		return id
	}
	f.ownAsset = asset(f.tenant)
	f.ownFinding = finding(f.tenant, f.ownAsset)
	f.foreignFinding = finding(f.other, asset(f.other))

	pdb := &postgres.DB{DB: raw}
	now := time.Now().UTC()
	f.clock = &now
	f.svc = supportaccess.NewService(postgres.NewSupportAccessRepository(pdb), postgres.NewSupportReadRepository(pdb), admins,
		auditapp.NewAuditService(postgres.NewAuditRepository(pdb), logger.NewNop()), postgres.NewAuditLogRepository(pdb),
		ownersOf{db: raw}, names{}, f.mailer, logger.NewNop())
	supportaccess.SetClock(f.svc, func() time.Time { return *f.clock })
	return f
}

var client = supportaccess.Client{IP: "203.0.113.9", UserAgent: "it"}

func (f *fixture) grant(t *testing.T, a *admin.AdminUser, scopes []string, hours int) *dom.Grant {
	t.Helper()
	g, err := f.svc.CreateGrant(context.Background(), supportaccess.CreateGrantInput{
		TenantID: f.tenant, GrantedBy: f.owner, GrantedByEmail: "owner@example.com", AdminEmail: a.Email(),
		Scopes: scopes, DurationHours: hours, Reason: "Customer ticket: P0 ranking question",
	}, client)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	return g
}

func (f *fixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSupportAccessGrantRules_DB(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := func(email string, hours int, reason string) supportaccess.CreateGrantInput {
		return supportaccess.CreateGrantInput{TenantID: f.tenant, GrantedBy: f.owner, GrantedByEmail: "o@example.com",
			AdminEmail: email, DurationHours: hours, Reason: reason}
	}
	for name, c := range map[string]struct {
		in   supportaccess.CreateGrantInput
		want error
	}{
		"unknown administrator":   {in("nobody@example.com", 4, "a valid reason here"), dom.ErrNotSupportAdmin},
		"read-only administrator": {in(f.readonly.Email(), 4, "a valid reason here"), dom.ErrNotSupportAdmin},
		"over 72 hours":           {in(f.support.Email(), 73, "a valid reason here"), dom.ErrInvalidDuration},
		"reason too short":        {in(f.support.Email(), 4, "short"), shared.ErrValidation},
	} {
		if _, err := f.svc.CreateGrant(ctx, c.in, client); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// A user who is not an active owner (demoted after the token was issued).
	notOwner := in(f.support.Email(), 4, "a valid reason here")
	notOwner.GrantedBy = shared.NewID()
	if _, err := f.svc.CreateGrant(ctx, notOwner, client); !errors.Is(err, dom.ErrNotOwner) {
		t.Fatalf("not an owner: %v", err)
	}
	g := f.grant(t, f.support, nil, 0)
	if g.ExpiresAt.Sub(g.StartsAt) != dom.DefaultDuration || len(g.Scopes) != 2 || g.Level != dom.LevelRead {
		t.Fatalf("defaults: %+v", g)
	}
	if _, err := f.svc.CreateGrant(ctx, in(f.support.Email(), 4, "a second valid reason"), client); !errors.Is(err, dom.ErrTooManyActiveGrant) {
		t.Fatalf("second active grant: %v", err)
	}
	if f.mailer.count() != 1 {
		t.Fatalf("owner emails: %d, want 1", f.mailer.count())
	}
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'support.grant_created'`, f.tenant.String()); n != 1 {
		t.Fatalf("tenant audit grant_created: %d", n)
	}
	// The database refuses a window over 72 hours, whatever the caller.
	_, err := f.db.Exec(`INSERT INTO support_grants (tenant_id, admin_id, admin_email, scopes, reason, granted_by, starts_at, expires_at)
		VALUES ($1, $2, 'x@example.com', '{findings}', 'a valid reason here', $3, now(), now() + interval '73 hours')`,
		f.tenant.String(), f.support.ID().String(), f.owner.String())
	if err == nil {
		t.Fatal("the window check must refuse 73 hours")
	}
}

// The negative paths: no grant, another administrator, another console
// session, scope not granted, cross-tenant ids, revoked mid-session and
// expired. Every allowed read is in both audit logs; refusals are in the
// admin log.
func TestSupportAccessSessions_DB(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	console := shared.NewID()

	// No grant: refused, audited on the admin side.
	if _, _, err := f.svc.StartSession(ctx, f.support, console, shared.NewID(), "", client); !errors.Is(err, dom.ErrGrantRequired) {
		t.Fatalf("no grant: %v", err)
	}
	g := f.grant(t, f.support, []string{dom.ScopeFindings}, 2)
	// Another administrator cannot use it.
	if _, _, err := f.svc.StartSession(ctx, f.otherSupport, console, g.ID, "", client); !errors.Is(err, dom.ErrGrantRequired) {
		t.Fatalf("other admin: %v", err)
	}
	// A read-only administrator never can.
	if _, _, err := f.svc.StartSession(ctx, f.readonly, console, g.ID, "", client); !errors.Is(err, dom.ErrGrantRequired) {
		t.Fatalf("readonly: %v", err)
	}
	if mine, err := f.svc.GrantsForAdmin(ctx, f.support); err != nil || len(mine) != 1 || mine[0].TenantName != "support it" {
		t.Fatalf("my grants: %+v %v", mine, err)
	}
	if theirs, _ := f.svc.GrantsForAdmin(ctx, f.otherSupport); len(theirs) != 0 {
		t.Fatalf("another admin sees %d grants", len(theirs))
	}
	sess, _, err := f.svc.StartSession(ctx, f.support, console, g.ID, "looking at P0 ranking", client)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// Opening another session under the same grant supersedes the first.
	first := sess
	sess, _, err = f.svc.StartSession(ctx, f.support, console, g.ID, "", client)
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if _, err := f.svc.Access(ctx, f.support, supportaccess.AccessInput{SessionID: first.ID, ConsoleSessionID: console, Method: "GET", Route: "overview"}, client); !errors.Is(err, dom.ErrNoLiveSession) {
		t.Fatalf("superseded session: %v", err)
	}
	access := func(a *admin.AdminUser, cs shared.ID, scope string) (*dom.LiveSession, error) {
		return f.svc.Access(ctx, a, supportaccess.AccessInput{SessionID: sess.ID, ConsoleSessionID: cs, Scope: scope,
			Method: "GET", Route: "findings"}, client)
	}
	ls, err := access(f.support, console, dom.ScopeFindings)
	if err != nil {
		t.Fatalf("access: %v", err)
	}
	items, total, err := f.svc.ListFindings(ctx, ls, dom.ListQuery{})
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != f.ownFinding.String() {
		t.Fatalf("findings: %d %v %v", total, items, err)
	}
	if items[0].Title != "AWS key in config" {
		t.Fatalf("title: %q", items[0].Title)
	}
	// A findings-only grant never names the asset of a finding, and the
	// overview carries no asset count.
	if items[0].AssetID != "" || items[0].AssetName != "" || items[0].AssetType != "" {
		t.Fatalf("findings-only grant leaked asset columns: %+v", items[0])
	}
	if one, err := f.svc.GetFinding(ctx, ls, f.ownFinding); err != nil || one.AssetID != "" || one.AssetName != "" || one.AssetType != "" {
		t.Fatalf("finding by id leaked asset columns: %+v %v", one, err)
	}
	if ov, err := f.svc.Overview(ctx, ls); err != nil || ov.AssetCount != nil || ov.OpenFindingCount == nil || *ov.OpenFindingCount != 1 {
		t.Fatalf("findings-only overview: %+v %v", ov, err)
	}
	// The secret value (message, snippet) is never selected.
	if raw, _ := json.Marshal(items); strings.Contains(string(raw), "AKIAEXAMPLESECRET") {
		t.Fatalf("a support read leaked the secret: %s", raw)
	}
	// Cross-tenant id: not found inside this organization.
	if _, err := f.svc.GetFinding(ctx, ls, f.foreignFinding); !errors.Is(err, dom.ErrNotFound) {
		t.Fatalf("foreign finding: %v", err)
	}
	// Scope not granted.
	if _, err := access(f.support, console, dom.ScopeAssets); !errors.Is(err, dom.ErrScopeNotGranted) {
		t.Fatalf("assets scope: %v", err)
	}
	// Another console session (a stolen session id used elsewhere), another admin.
	if _, err := access(f.support, shared.NewID(), dom.ScopeFindings); !errors.Is(err, dom.ErrNoLiveSession) {
		t.Fatalf("other console session: %v", err)
	}
	if _, err := access(f.otherSupport, console, dom.ScopeFindings); !errors.Is(err, dom.ErrNoLiveSession) {
		t.Fatalf("other admin on the session: %v", err)
	}

	// Revoked mid-session: the next read is refused.
	if _, err := f.svc.RevokeGrant(ctx, f.tenant, g.ID, f.owner, "owner@example.com", client); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := access(f.support, console, dom.ScopeFindings); !errors.Is(err, dom.ErrNoLiveSession) {
		t.Fatalf("after revoke: %v", err)
	}
	if _, err := f.svc.RevokeGrant(ctx, f.other, g.ID, f.owner, "x", client); !errors.Is(err, dom.ErrGrantNotFound) {
		t.Fatalf("revoke from another tenant: %v", err)
	}

	// Expired: enforced by the server's clock on every request.
	g2 := f.grant(t, f.support, nil, 1)
	sess2, _, err := f.svc.StartSession(ctx, f.support, console, g2.ID, "", client)
	if err != nil {
		t.Fatalf("start 2: %v", err)
	}
	later := f.clock.Add(time.Hour + time.Second)
	f.clock = &later
	if _, err := f.svc.Access(ctx, f.support, supportaccess.AccessInput{SessionID: sess2.ID, ConsoleSessionID: console, Method: "GET", Route: "overview"}, client); !errors.Is(err, dom.ErrNoLiveSession) {
		t.Fatalf("expired: %v", err)
	}
	if _, _, err := f.svc.StartSession(ctx, f.support, console, g2.ID, "", client); !errors.Is(err, dom.ErrGrantRequired) {
		t.Fatalf("start after expiry: %v", err)
	}
	if grants, _ := f.svc.GrantsForAdmin(ctx, f.support); len(grants) != 0 {
		t.Fatalf("expired grants listed: %d", len(grants))
	}

	// Both audit logs: one allowed read, sessions started twice.
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'support.accessed' AND actor_email = $2`,
		f.tenant.String(), "support:"+f.support.Email()); n != 1 {
		t.Fatalf("tenant audit reads: %d, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1 AND action = 'support.accessed'`, f.support.ID().String()); n != 1 {
		t.Fatalf("admin audit reads: %d, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'support.session_started'`, f.tenant.String()); n != 3 {
		t.Fatalf("tenant audit sessions: %d, want 3", n)
	}
	if n := f.count(t, `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1 AND action = 'support.refused'`, f.support.ID().String()); n < 4 {
		t.Fatalf("admin audit refusals: %d, want >= 4", n)
	}
	// No support row ever reaches another organization's log.
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'support.%'`, f.other.String()); n != 0 {
		t.Fatalf("other tenant audit rows: %d", n)
	}
	// Owners were emailed: grant, session start, revoke, grant 2, session 2 start.
	if f.mailer.count() < 5 {
		t.Fatalf("owner emails: %d", f.mailer.count())
	}
}

// A console route that reaches organization data without a grant is never
// blocked, but its use lands in the organization's audit log and the owners
// are emailed; a repeatable read emails once per hour.
func TestConsoleTenantAccessNotice_DB(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := supportaccess.ConsoleAccessInput{TenantID: f.tenant, Route: "user list", Method: "GET", Repeatable: true}
	for range 3 {
		if err := f.svc.NoticeConsoleAccess(ctx, f.support, in, client); err != nil {
			t.Fatalf("notice: %v", err)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'admin_console.tenant_access' AND actor_email = $2`,
		f.tenant.String(), "console:"+f.support.Email()); n != 3 {
		t.Fatalf("tenant audit rows: %d, want 3 (every use)", n)
	}
	if f.mailer.count() != 1 {
		t.Fatalf("owner emails for a repeatable read: %d, want 1", f.mailer.count())
	}
	in = supportaccess.ConsoleAccessInput{TenantID: f.tenant, Route: "owner create or recovery", Method: "POST"}
	for range 2 {
		if err := f.svc.NoticeConsoleAccess(ctx, f.support, in, client); err != nil {
			t.Fatal(err)
		}
	}
	if f.mailer.count() != 3 {
		t.Fatalf("owner emails: %d, want 3 (every write is emailed)", f.mailer.count())
	}
	// Nothing leaks into another organization's log.
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'admin_console.tenant_access'`, f.other.String()); n != 0 {
		t.Fatalf("other organization: %d rows", n)
	}
}

type downAuditor struct{}

func (downAuditor) LogEvent(context.Context, auditapp.AuditContext, auditapp.AuditEvent) error {
	return errors.New("audit store down")
}

// A grant of support access that cannot be audited is revoked at once and the
// owner gets an error, not a grant.
func TestSupportAccessGrant_AuditFailureRevokesIt_DB(t *testing.T) {
	f := setup(t)
	pdb := &postgres.DB{DB: f.db}
	svc := supportaccess.NewService(postgres.NewSupportAccessRepository(pdb), postgres.NewSupportReadRepository(pdb),
		postgres.NewAdminRepository(pdb), downAuditor{}, postgres.NewAuditLogRepository(pdb),
		ownersOf{db: f.db}, names{}, f.mailer, logger.NewNop())
	g, err := svc.CreateGrant(context.Background(), supportaccess.CreateGrantInput{
		TenantID: f.tenant, GrantedBy: f.owner, GrantedByEmail: "owner@example.com", AdminEmail: f.support.Email(),
		DurationHours: 4, Reason: "Customer ticket: P0 ranking question",
	}, client)
	if !errors.Is(err, dom.ErrAuditUnavailable) || g != nil {
		t.Fatalf("grant=%v err=%v, want ErrAuditUnavailable and no grant", g, err)
	}
	if n := f.count(t, `SELECT count(*) FROM support_grants WHERE tenant_id = $1 AND revoked_at IS NULL`, f.tenant.String()); n != 0 {
		t.Fatalf("live grants after a failed audit = %d, want 0", n)
	}
	if f.mailer.count() != 0 {
		t.Fatal("owners were told about a grant that was withdrawn")
	}
}

// A support session lives only as long as the console session that opened it:
// sign-out ends it at once, expiry and idle end it within the sweeper's
// minute, an unused session ends after 30 minutes, and the organization's
// "support is viewing" signal (open_session) never outlives the console
// session. Each end writes both audit rows and emails the owners. Another
// administrator's session, on a live console session, is never touched.
func TestSupportSessionLifecycle_DB(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	console := func(a *admin.AdminUser, lastSeen, expires time.Time) shared.ID {
		id := shared.NewID()
		if _, err := f.db.ExecContext(ctx, `
			INSERT INTO admin_sessions (id, admin_id, token_hash, mfa_verified, created_at, expires_at, last_seen_at)
			VALUES ($1, $2, $3, true, $4, $5, $4)`,
			id.String(), a.ID().String(), "th-"+id.String(), lastSeen, expires); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(ctx, `UPDATE admin_sessions SET last_seen_at = $2 WHERE id = $1`, id.String(), lastSeen); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// The open_session signal compares with the database clock.
	dbNow := time.Now()
	alive := func(a *admin.AdminUser) shared.ID { return console(a, dbNow, dbNow.Add(8*time.Hour)) }
	endReason := func(id shared.ID) (string, bool) {
		var reason sql.NullString
		var ended sql.NullTime
		if err := f.db.QueryRow(`SELECT end_reason, ended_at FROM support_sessions WHERE id = $1`, id.String()).Scan(&reason, &ended); err != nil {
			t.Fatal(err)
		}
		return reason.String, ended.Valid
	}
	openSignal := func() bool {
		t.Helper()
		gs, err := f.svc.ActiveGrants(ctx, f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range gs {
			if g.OpenSession {
				return true
			}
		}
		return false
	}
	start := func(a *admin.AdminUser, cs shared.ID, g *dom.Grant) *dom.Session {
		t.Helper()
		s, _, err := f.svc.StartSession(ctx, a, cs, g.ID, "lifecycle", client)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		return s
	}

	gA := f.grant(t, f.support, nil, 4)
	gB := f.grant(t, f.otherSupport, nil, 4)
	csA, csB := alive(f.support), alive(f.otherSupport)
	sA, sB := start(f.support, csA, gA), start(f.otherSupport, csB, gB)
	if !openSignal() {
		t.Fatal("open_session must be true while a session is open on a live console session")
	}

	// Nothing to end while every console session is alive.
	if n, err := f.svc.EndStaleSessions(ctx); err != nil || n != 0 {
		t.Fatalf("sweep with live consoles: %d %v", n, err)
	}

	// Console expiry without any sweep: the signal drops at once, the row
	// still says open until the sweeper (or sign-out) runs.
	if _, err := f.db.ExecContext(ctx, `UPDATE admin_sessions SET expires_at = now() - interval '1 minute' WHERE id = $1`, csA.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id = $1`, csB.String()); err != nil {
		t.Fatal(err)
	}
	if openSignal() {
		t.Fatal("open_session stayed true after both console sessions were gone")
	}
	before := f.mailer.count()
	if n, err := f.svc.EndStaleSessions(ctx); err != nil || n != 2 {
		t.Fatalf("sweep: %d %v, want 2 ended", n, err)
	}
	for name, id := range map[string]shared.ID{"expired console": sA.ID, "deleted console": sB.ID} {
		if r, ended := endReason(id); !ended || r != dom.EndReasonConsoleSessionGone {
			t.Fatalf("%s: reason %q ended=%v", name, r, ended)
		}
	}
	if got := f.mailer.count() - before; got != 2 {
		t.Fatalf("owner emails for two ended sessions: %d", got)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'support.session_ended'`, f.tenant.String()); n != 2 {
		t.Fatalf("tenant audit session_ended rows: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM admin_audit_logs WHERE admin_id IN ($1, $2) AND action = 'support.session_ended'`,
		f.support.ID().String(), f.otherSupport.ID().String()); n != 2 {
		t.Fatalf("admin audit session_ended rows: %d", n)
	}
	// Sweeping again ends and notifies nothing twice.
	if n, _ := f.svc.EndStaleSessions(ctx); n != 0 {
		t.Fatalf("second sweep ended %d", n)
	}

	// Sign-out ends only the sessions of that console session.
	csA2, csB2 := alive(f.support), alive(f.otherSupport)
	sA2, sB2 := start(f.support, csA2, gA), start(f.otherSupport, csB2, gB)
	before = f.mailer.count()
	f.svc.EndForConsoleSession(ctx, csA2)
	if r, ended := endReason(sA2.ID); !ended || r != dom.EndReasonConsoleSessionGone {
		t.Fatalf("sign-out: reason %q ended=%v", r, ended)
	}
	if _, ended := endReason(sB2.ID); ended {
		t.Fatal("another administrator's session ended with someone else's sign-out")
	}
	if f.mailer.count()-before != 1 {
		t.Fatalf("sign-out owner emails: %d", f.mailer.count()-before)
	}
	// An unrelated or unknown console session ends nothing.
	f.svc.EndForConsoleSession(ctx, shared.NewID())
	if _, ended := endReason(sB2.ID); ended {
		t.Fatal("an unknown console session ended a session")
	}

	// Idle: the console session is alive but the support session was not
	// used for 30 minutes.
	later := f.clock.Add(dom.SessionIdleTimeout + time.Minute)
	f.clock = &later
	if _, err := f.db.ExecContext(ctx, `UPDATE admin_sessions SET last_seen_at = $2, expires_at = $3 WHERE id = $1`,
		csB2.String(), later, later.Add(8*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, err := f.svc.EndStaleSessions(ctx); err != nil || n != 1 {
		t.Fatalf("idle sweep: %d %v", n, err)
	}
	if r, ended := endReason(sB2.ID); !ended || r != dom.EndReasonIdle {
		t.Fatalf("idle: reason %q ended=%v", r, ended)
	}

	// A read keeps a session from idling out.
	csA3 := console(f.support, later, later.Add(8*time.Hour))
	sA3 := start(f.support, csA3, gA)
	if _, err := f.svc.Access(ctx, f.support, supportaccess.AccessInput{SessionID: sA3.ID, ConsoleSessionID: csA3, Method: "GET", Route: "overview"}, client); err != nil {
		t.Fatalf("access: %v", err)
	}
	ahead := later.Add(dom.SessionIdleTimeout - time.Minute)
	f.clock = &ahead
	if _, err := f.db.ExecContext(ctx, `UPDATE admin_sessions SET last_seen_at = $2 WHERE id = $1`, csA3.String(), ahead); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.svc.EndStaleSessions(ctx); n != 0 {
		t.Fatalf("a recently used session ended: %d", n)
	}
}
