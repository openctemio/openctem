package integration

// Break-glass administrators and the platform IdP against a real Postgres
// (RFC-022 revision 4): the roster guard, the IdP binding rules enforced by the
// schema, single-use sign-in states, and the require-IdP invariant.
//
// Requires DATABASE_URL pointing at a database migrated through 000229.

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/adminbootstrap"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func openBreakGlassDB(t *testing.T) *postgres.DB {
	t.Helper()
	db := openConsoleDB(t)
	var ok bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'admin_users' AND column_name = 'is_break_glass')`).Scan(&ok); err != nil || !ok {
		t.Skip("admin_users.is_break_glass missing: run migration 000229")
	}
	// These tests reason about the whole roster: start from an empty one.
	if _, err := db.Exec(`DELETE FROM platform_identity_provider`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM users WHERE id IN (SELECT user_id FROM admin_users)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM admin_users`); err != nil {
		t.Fatal(err)
	}
	return db
}

// seedAdmin inserts a linked administrator.
func seedAdmin(t *testing.T, db *postgres.DB, role admin.AdminRole, breakGlass bool) *admin.AdminUser {
	t.Helper()
	ctx := context.Background()
	email := "rev4-" + uuid.NewString()[:8] + "@example.com"
	uid := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, 'x', 'x', 'local', 'active', true, NOW(), NOW())`, uid, email); err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewAdminRepository(db)
	a, err := admin.NewAdminUser(email, "X", role, nil)
	if err != nil {
		t.Fatal(err)
	}
	if breakGlass {
		_ = a.SetBreakGlass(true)
	}
	if err := repo.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	id, _ := shared.IDFromString(uid)
	if err := repo.LinkUser(ctx, a.ID(), id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, uid) })
	got, err := repo.GetByID(ctx, a.ID())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRosterGuardKeepsALocalSuperAdmin(t *testing.T) {
	db := openBreakGlassDB(t)
	repo := postgres.NewAdminRepository(db)
	ctx := context.Background()

	a := seedAdmin(t, db, admin.AdminRoleSuperAdmin, false)
	b := seedAdmin(t, db, admin.AdminRoleSuperAdmin, true)
	ro := seedAdmin(t, db, admin.AdminRoleReadonly, false)

	// Deleting a readonly admin never matters.
	if err := repo.GuardedDelete(ctx, ro.ID()); err != nil {
		t.Fatalf("delete readonly: %v", err)
	}
	// One of two super admins can go...
	b.Deactivate()
	if err := repo.GuardedUpdate(ctx, b); err != nil {
		t.Fatalf("deactivate one of two: %v", err)
	}
	// ...the last one cannot be deleted, deactivated or demoted.
	if err := repo.GuardedDelete(ctx, a.ID()); !errors.Is(err, admin.ErrLastLocalAdmin) {
		t.Fatalf("delete last: got %v", err)
	}
	a.Deactivate()
	if err := repo.GuardedUpdate(ctx, a); !errors.Is(err, admin.ErrLastLocalAdmin) {
		t.Fatalf("deactivate last: got %v", err)
	}
	a.Activate()
	_ = a.UpdateRole(admin.AdminRoleOpsAdmin)
	if err := repo.GuardedUpdate(ctx, a); !errors.Is(err, admin.ErrLastLocalAdmin) {
		t.Fatalf("demote last: got %v", err)
	}
	if got, _ := repo.GetByID(ctx, a.ID()); got.Role() != admin.AdminRoleSuperAdmin || !got.IsActive() {
		t.Fatal("a refused change must be rolled back")
	}
}

func TestRequireIdPNeedsBreakGlassAndGuardsIt(t *testing.T) {
	db := openBreakGlassDB(t)
	repo := postgres.NewAdminRepository(db)
	idps := postgres.NewPlatformIdPRepository(db)
	ctx := context.Background()

	seedAdmin(t, db, admin.AdminRoleSuperAdmin, false)
	cfg := &admin.PlatformIdP{
		Enabled: true, DisplayName: "SSO", Issuer: "https://idp.example", ClientID: "c",
		ClientSecretEncrypted: "enc", RedirectURI: "https://console.example/cb", Scopes: []string{"openid"},
		AuthorizationEndpoint: "https://idp.example/a", TokenEndpoint: "https://idp.example/t",
		JWKSURI: "https://idp.example/j", TokenEndpointAuthMethod: "client_secret_basic", RequireIdP: true,
	}
	if err := idps.Save(ctx, cfg, false); !errors.Is(err, admin.ErrLastLocalAdmin) {
		t.Fatalf("require IdP without break-glass: got %v", err)
	}
	if _, err := idps.Get(ctx); !errors.Is(err, admin.ErrPlatformIdPNotConfigured) {
		t.Fatal("the refused save must be rolled back")
	}

	bg := seedAdmin(t, db, admin.AdminRoleSuperAdmin, true)
	if err := idps.Save(ctx, cfg, false); err != nil {
		t.Fatalf("require IdP with a break-glass admin: %v", err)
	}
	got, err := idps.Get(ctx)
	if err != nil || !got.Enforced() || got.ClientSecretEncrypted != "enc" || len(got.TrustedACRValues) != 0 {
		t.Fatalf("round trip: %v %+v", err, got)
	}

	// While enforced, the last break-glass super admin is protected.
	if err := repo.GuardedDelete(ctx, bg.ID()); !errors.Is(err, admin.ErrLastLocalAdmin) {
		t.Fatalf("delete last break-glass under require-IdP: got %v", err)
	}
	_ = bg.SetBreakGlass(false)
	if err := repo.GuardedUpdate(ctx, bg); !errors.Is(err, admin.ErrLastLocalAdmin) {
		t.Fatalf("unmark last break-glass under require-IdP: got %v", err)
	}
}

func TestIdPBindingRules(t *testing.T) {
	db := openBreakGlassDB(t)
	repo := postgres.NewAdminRepository(db)
	ctx := context.Background()

	a := seedAdmin(t, db, admin.AdminRoleSuperAdmin, false)
	b := seedAdmin(t, db, admin.AdminRoleOpsAdmin, false)
	bg := seedAdmin(t, db, admin.AdminRoleSuperAdmin, true)
	iss := "https://idp.example"

	if err := repo.BindIdP(ctx, a.ID(), iss, "sub-a"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if got, err := repo.GetByIdPSubject(ctx, iss, "sub-a"); err != nil || got.ID() != a.ID() {
		t.Fatalf("lookup by subject: %v", err)
	}
	if err := repo.BindIdP(ctx, a.ID(), iss, "sub-other"); !errors.Is(err, admin.ErrIdPBindingConflict) {
		t.Fatalf("rebinding a bound admin: got %v", err)
	}
	if err := repo.BindIdP(ctx, b.ID(), iss, "sub-a"); !errors.Is(err, admin.ErrIdPBindingConflict) {
		t.Fatalf("one identity, two admins: got %v", err)
	}
	if err := repo.BindIdP(ctx, bg.ID(), iss, "sub-bg"); !errors.Is(err, admin.ErrIdPBindingConflict) {
		t.Fatalf("binding a break-glass admin: got %v", err)
	}
	// The schema refuses it even if the application tried.
	if _, err := db.Exec(`UPDATE admin_users SET idp_issuer = $2, idp_subject = 'x' WHERE id = $1`, bg.ID().String(), iss); err == nil {
		t.Fatal("CHECK must forbid binding a break-glass row")
	}
	// Marking a bound admin break-glass is refused by the schema too.
	if _, err := db.Exec(`UPDATE admin_users SET is_break_glass = TRUE WHERE id = $1`, a.ID().String()); err == nil {
		t.Fatal("CHECK must forbid a bound break-glass row")
	}
	if err := repo.UnbindIdP(ctx, a.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByIdPSubject(ctx, iss, "sub-a"); !admin.IsAdminNotFound(err) {
		t.Fatal("unbound")
	}
}

func TestIdPLoginStateIsSingleUse(t *testing.T) {
	db := openBreakGlassDB(t)
	idps := postgres.NewPlatformIdPRepository(db)
	ctx := context.Background()
	now := time.Now()
	h := "hash-" + uuid.NewString()
	if err := idps.CreateLoginState(ctx, &admin.IdPLoginState{StateHash: h, Nonce: "n", CodeVerifierEncrypted: "v",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if s, err := idps.ConsumeLoginState(ctx, h, now); err != nil || s.Nonce != "n" {
		t.Fatalf("consume: %v", err)
	}
	if _, err := idps.ConsumeLoginState(ctx, h, now); !errors.Is(err, admin.ErrIdPLoginStateNotFound) {
		t.Fatal("a state can be used once")
	}
	h2 := "hash-" + uuid.NewString()
	_ = idps.CreateLoginState(ctx, &admin.IdPLoginState{StateHash: h2, Nonce: "n", CodeVerifierEncrypted: "v",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if _, err := idps.ConsumeLoginState(ctx, h2, now.Add(2*time.Minute)); !errors.Is(err, admin.ErrIdPLoginStateNotFound) {
		t.Fatal("an expired state is refused")
	}
}

func TestPasswordSessionsEndExceptBreakGlass(t *testing.T) {
	db := openBreakGlassDB(t)
	console := postgres.NewAdminConsoleRepository(db)
	ctx := context.Background()
	a := seedAdmin(t, db, admin.AdminRoleSuperAdmin, false)
	bg := seedAdmin(t, db, admin.AdminRoleSuperAdmin, true)
	now := time.Now()
	mk := func(id shared.ID, method, hash string) {
		if err := console.CreateSession(ctx, &admin.Session{ID: shared.NewID(), AdminID: id, TokenHash: hash,
			MFAVerified: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, AuthMethod: method}); err != nil {
			t.Fatal(err)
		}
	}
	mk(a.ID(), admin.AuthMethodPassword, "a-pw-"+uuid.NewString())
	idpHash := "a-idp-" + uuid.NewString()
	mk(a.ID(), admin.AuthMethodIdP, idpHash)
	bgHash := "bg-pw-" + uuid.NewString()
	mk(bg.ID(), admin.AuthMethodPassword, bgHash)

	n, err := console.DeletePasswordSessionsExceptBreakGlass(ctx)
	if err != nil || n != 1 {
		t.Fatalf("expected exactly the normal admin's password session to end, got %d %v", n, err)
	}
	if s, err := console.GetSessionByTokenHash(ctx, idpHash); err != nil || s.AuthMethod != admin.AuthMethodIdP {
		t.Fatalf("IdP session must survive with its method: %v", err)
	}
	if _, err := console.GetSessionByTokenHash(ctx, bgHash); err != nil {
		t.Fatal("break-glass password session must survive")
	}
}

func TestAuditSeverityRoundTrip(t *testing.T) {
	db := openBreakGlassDB(t)
	audit := postgres.NewAuditLogRepository(db)
	ctx := context.Background()
	entry := admin.NewAuditLogBuilder(nil, "test.rev4."+uuid.NewString()[:8]).High().Build()
	if err := audit.Create(ctx, entry); err != nil {
		t.Fatal(err)
	}
	got, err := audit.GetByID(ctx, entry.ID)
	if err != nil || got.Severity != admin.SeverityHigh {
		t.Fatalf("severity: %v %+v", err, got)
	}
}

// TestBootstrapAdminCreatesPrimaryAndBreakGlass runs the bootstrap-admin core
// twice: the first run creates both administrators (temporary passwords
// printed once, both must change them, the backup is a break-glass super
// admin), the second changes nothing.
func TestBootstrapAdminCreatesPrimaryAndBreakGlass(t *testing.T) {
	db := openBreakGlassDB(t)
	ctx := context.Background()
	if err := adminbootstrap.CheckSchema(ctx, db.DB); err != nil {
		t.Skipf("schema not migrated: %v", err)
	}
	suffix := uuid.NewString()[:8]
	o := adminbootstrap.Options{Email: "primary-" + suffix + "@example.com", BackupEmail: "bg-" + suffix + "@example.com"}
	if err := o.Normalize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users WHERE email IN ($1, $2)`, o.Email, o.BackupEmail)
	})

	var out bytes.Buffer
	if err := adminbootstrap.Run(ctx, db.DB, o, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if n := len(regexp.MustCompile(`Password: \S+`).FindAllString(out.String(), -1)); n != 2 {
		t.Fatalf("expected two temporary passwords printed once each, got %d:\n%s", n, out.String())
	}
	var bg, pw bool
	var role string
	if err := db.QueryRow(`SELECT is_break_glass, password_change_required, role FROM admin_users WHERE email = $1`, o.BackupEmail).
		Scan(&bg, &pw, &role); err != nil {
		t.Fatal(err)
	}
	if !bg || !pw || role != "super_admin" {
		t.Fatalf("backup: break_glass=%v password_change_required=%v role=%s", bg, pw, role)
	}
	if err := db.QueryRow(`SELECT is_break_glass, password_change_required FROM admin_users WHERE email = $1`, o.Email).
		Scan(&bg, &pw); err != nil {
		t.Fatal(err)
	}
	if bg || !pw {
		t.Fatalf("primary: break_glass=%v password_change_required=%v", bg, pw)
	}

	out.Reset()
	if err := adminbootstrap.Run(ctx, db.DB, o, &out); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if strings.Contains(out.String(), "Password:") || strings.Count(out.String(), "already exists") != 2 {
		t.Fatalf("second run must skip both:\n%s", out.String())
	}
}

// TestBootstrapAdminLegacyAdministrator covers an administrator created before
// v0.9.0 (an API key only). Migration 000227 revoked its key and deactivated
// it. Re-running bootstrap-admin with its email must not report it as existing
// (it cannot sign in), and -link must give it an account AND reactivate it;
// otherwise the operator who upgraded from v0.8 is left with no administrator.
func TestBootstrapAdminLegacyAdministrator(t *testing.T) {
	db := openBreakGlassDB(t)
	ctx := context.Background()
	if err := adminbootstrap.CheckSchema(ctx, db.DB); err != nil {
		t.Skipf("schema not migrated: %v", err)
	}
	email := "legacy-" + uuid.NewString()[:8] + "@example.com"
	// The state 000227 leaves a v0.8 administrator in.
	if _, err := db.Exec(`INSERT INTO admin_users (id, email, name, role, is_active, api_key_hash, api_key_prefix, created_at, updated_at)
		VALUES ($1, $2, 'legacy', 'super_admin', FALSE, '!revoked', 'revoked-x', NOW(), NOW())`, uuid.NewString(), email); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE email = $1`, email) })

	o := adminbootstrap.Options{Email: email, NoBackup: true}
	if err := o.Normalize(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := adminbootstrap.Run(ctx, db.DB, o, &out)
	if err == nil || !strings.Contains(err.Error(), "-link") {
		t.Fatalf("a legacy administrator must be refused with a pointer to -link, got err=%v out=%s", err, out.String())
	}

	link := adminbootstrap.Options{Email: email, LinkOnly: true}
	if err := link.Normalize(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := adminbootstrap.Run(ctx, db.DB, link, &out); err != nil {
		t.Fatalf("link: %v", err)
	}
	var active, linked, pwChange bool
	if err := db.QueryRow(`SELECT is_active, user_id IS NOT NULL, password_change_required FROM admin_users WHERE email = $1`, email).
		Scan(&active, &linked, &pwChange); err != nil {
		t.Fatal(err)
	}
	if !active || !linked || !pwChange {
		t.Fatalf("after -link: active=%v linked=%v password_change_required=%v\n%s", active, linked, pwChange, out.String())
	}
	if !strings.Contains(out.String(), "reactivated") || !strings.Contains(out.String(), "Password:") {
		t.Fatalf("-link output must show the reactivation and the temporary password:\n%s", out.String())
	}

	// A second -link must not create another account.
	out.Reset()
	if err := adminbootstrap.Run(ctx, db.DB, link, &out); err == nil {
		t.Fatalf("second -link must be refused, got:\n%s", out.String())
	}
	// And a plain run now reports it as existing.
	out.Reset()
	if err := adminbootstrap.Run(ctx, db.DB, o, &out); err != nil || !strings.Contains(out.String(), "already exists") {
		t.Fatalf("plain run after -link: err=%v\n%s", err, out.String())
	}
}
