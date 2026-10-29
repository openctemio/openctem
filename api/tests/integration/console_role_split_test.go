package integration

// The API's app-pool repositories under the least-privilege roles WITH the
// console role (deploy/postgres/least-privilege-roles.sql, section 8, the
// production model): admin_sessions and the other console identity tables
// are readable and writable only by the console role, admin_users only
// readable by the app role. The default CI run bootstraps the roles without
// the console role, so a statement of the app pool that touches a console
// table passes there and fails with 42501 in production; this test runs those
// statements as the app role on a database bootstrapped the production way.
//
// Needs a superuser DATABASE_ADMIN_URL (or DATABASE_URL) and psql, like
// TestLeastPrivilegeRoles; it skips otherwise.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/supportaccess"
)

const lpRolesScript = "../../deploy/postgres/least-privilege-roles.sql"

type splitRoles struct {
	app, console *sql.DB
}

// bootstrapSplitRoles creates a database for this test, bootstraps the roles
// with a console role, applies every migration as the migrator, re-runs the
// bootstrap (as a deploy does) and returns app and console connections.
func bootstrapSplitRoles(t *testing.T) splitRoles {
	t.Helper()
	base := testdb.AdminURL()
	if base == "" {
		t.Skip("DATABASE_URL not set to a test database")
	}
	psql, err := exec.LookPath("psql")
	if err != nil {
		testdb.Skipf(t, "psql not installed")
	}
	root, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	var super bool
	if err := root.QueryRow(`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&super); err != nil {
		testdb.Skipf(t, "cannot reach the database: %v", err)
	}
	if !super {
		testdb.Skipf(t, "needs a superuser DATABASE_ADMIN_URL to create roles")
	}

	sfx := splitHex(t)
	dbName := "lpsplit_" + sfx + "_test"
	appRole, migRole, admRole := "lps_app_"+sfx, "lps_mig_"+sfx, "lps_adm_"+sfx
	appPass, migPass, admPass := splitHex(t), splitHex(t), splitHex(t)
	if _, err := root.Exec(`CREATE DATABASE ` + dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = root.Exec(`DROP DATABASE IF EXISTS ` + dbName + ` WITH (FORCE)`)
		for _, r := range []string{appRole, admRole, migRole} {
			_, _ = root.Exec(`DROP ROLE IF EXISTS ` + r)
		}
	})
	scratch := splitURL(t, base, dbName, "", "")
	bootstrap := func() {
		t.Helper()
		out, err := exec.Command(psql, scratch, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-f", lpRolesScript,
			"-v", "app_user="+appRole, "-v", "app_password="+appPass,
			"-v", "migrator_user="+migRole, "-v", "migrator_password="+migPass,
			"-v", "admin_user="+admRole, "-v", "admin_password="+admPass).CombinedOutput()
		if err != nil {
			t.Fatalf("bootstrap: %v\n%s", err, out)
		}
	}
	bootstrap()
	mig := splitOpen(t, splitURL(t, base, dbName, migRole, migPass))
	testdb.Migrate(t, mig, "../../migrations", 0, math.MaxInt, false)
	bootstrap()
	return splitRoles{
		app:     splitOpen(t, splitURL(t, base, dbName, appRole, appPass)),
		console: splitOpen(t, splitURL(t, base, dbName, admRole, admPass)),
	}
}

func TestSupportSessions_ConsoleRoleSplit(t *testing.T) {
	db := bootstrapSplitRoles(t)
	ctx := context.Background()
	must := func(c *sql.DB, q string, args ...any) {
		t.Helper()
		if _, err := c.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// The model under test: the app role cannot read or write admin_sessions,
	// nor lock admin_users.
	for _, q := range []string{
		`SELECT count(*) FROM admin_sessions`,
		`UPDATE admin_sessions SET last_seen_at = now()`,
		`SELECT 1 FROM admin_users FOR UPDATE`,
	} {
		var pqErr *pq.Error
		if _, err := db.app.ExecContext(ctx, q); !errors.As(err, &pqErr) || pqErr.Code != "42501" {
			t.Fatalf("app role ran %q: %v (want 42501)", q, err)
		}
	}

	// Console side: one administrator, a live console session and an
	// expired one.
	adminID := uuid.NewString()
	must(db.console, `INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Support', 'ops_admin')`,
		adminID, "support-"+adminID[:8]+"@example.com")
	now := time.Now().UTC()
	consoleSession := func(expires time.Time) string {
		id := uuid.NewString()
		must(db.console, `INSERT INTO admin_sessions (id, admin_id, token_hash, mfa_verified, expires_at, last_seen_at)
			VALUES ($1, $2, $3, true, $4, $5)`, id, adminID, "th-"+id, expires, now)
		return id
	}
	liveCS, deadCS := consoleSession(now.Add(8*time.Hour)), consoleSession(now.Add(-time.Minute))

	// Tenant side, as the app role: one organization, three grants, and one
	// open support session under each:
	//   live:  live console session, used now          -> stays open
	//   gone:  expired console session                  -> console_session_ended
	//   idle:  live console session, unused 31 minutes  -> idle, refused at read time
	tenant := uuid.NewString()
	must(db.app, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'split', $2)`, tenant, "split-"+tenant[:8])
	grant := func() string {
		id := uuid.NewString()
		must(db.app, `INSERT INTO support_grants (id, tenant_id, admin_id, admin_email, scopes, reason, starts_at, expires_at)
			VALUES ($1, $2, $3, 'support@example.com', '{findings}', 'a valid reason here', $4, $5)`,
			id, tenant, adminID, now.Add(-time.Hour), now.Add(4*time.Hour))
		return id
	}
	session := func(grantID, cs string, lastAccess time.Time) string {
		id := uuid.NewString()
		must(db.app, `INSERT INTO support_sessions (id, tenant_id, grant_id, admin_id, console_session_id, reason, started_at, last_access_at)
			VALUES ($1, $2, $3, $4, $5, 'case', $6, $6)`, id, tenant, grantID, adminID, cs, lastAccess)
		return id
	}
	gLive, gGone, gIdle := grant(), grant(), grant()
	sLive := session(gLive, liveCS, now)
	sGone := session(gGone, deadCS, now)
	sIdle := session(gIdle, liveCS, now.Add(-dom.SessionIdleTimeout-time.Minute))

	repo := postgres.NewSupportAccessRepository(&postgres.DB{DB: db.app})
	id := func(s string) shared.ID { v, _ := shared.IDFromString(s); return v }

	// Grant reads carry the open-session signal (it reads the console session
	// through admin_session_live).
	tid := id(tenant)
	grants, err := repo.ListActiveGrants(ctx, tid, now)
	if err != nil {
		t.Fatalf("list active grants as the app role: %v", err)
	}
	open := map[string]bool{}
	for _, g := range grants {
		open[g.ID.String()] = g.OpenSession
	}
	if len(grants) != 3 || !open[gLive] || open[gGone] || open[gIdle] {
		t.Fatalf("open_session: %v (want only the live grant)", open)
	}

	// Read time: the idle session is refused before any sweep ran; the live
	// one resolves.
	if _, err := repo.LiveSession(ctx, id(sIdle), id(adminID), id(liveCS), now); !errors.Is(err, dom.ErrNoLiveSession) {
		t.Fatalf("idle session resolved: %v", err)
	}
	if ls, err := repo.LiveSession(ctx, id(sLive), id(adminID), id(liveCS), now); err != nil || ls.Session.ID.String() != sLive {
		t.Fatalf("live session as the app role: %v", err)
	}

	// The sweep, as the app role.
	ended, err := repo.EndStaleSessions(ctx, now, dom.SessionIdleTimeout, admin.SessionIdleTimeout)
	if err != nil {
		t.Fatalf("sweep as the app role: %v", err)
	}
	why := map[string]string{}
	for _, s := range ended {
		why[s.ID.String()] = s.EndReason
	}
	if len(ended) != 2 || why[sGone] != dom.EndReasonConsoleSessionGone || why[sIdle] != dom.EndReasonIdle {
		t.Fatalf("sweep ended %v, want %s=%s and %s=%s", why, sGone, dom.EndReasonConsoleSessionGone, sIdle, dom.EndReasonIdle)
	}
	if again, err := repo.EndStaleSessions(ctx, now, dom.SessionIdleTimeout, admin.SessionIdleTimeout); err != nil || len(again) != 0 {
		t.Fatalf("second sweep: %d %v", len(again), err)
	}

	// The predicate exposes one boolean and nothing else: the app role still
	// cannot read the table behind it.
	var live bool
	if err := db.app.QueryRowContext(ctx, `SELECT admin_session_live($1, now(), 900)`, liveCS).Scan(&live); err != nil || !live {
		t.Fatalf("admin_session_live(live): %v %v", live, err)
	}
	if err := db.app.QueryRowContext(ctx, `SELECT admin_session_live($1, now(), 900)`, deadCS).Scan(&live); err != nil || live {
		t.Fatalf("admin_session_live(expired): %v %v", live, err)
	}
}

// The console's second factors (passkeys, recovery codes, passkey
// ceremonies) belong to the console role alone: the app role can neither
// plant nor read one, so a tenant-plane SQL injection cannot take over a
// platform administrator. The factor repository runs on the console pool.
func TestAdminFactors_ConsoleRoleSplit(t *testing.T) {
	db := bootstrapSplitRoles(t)
	ctx := context.Background()
	adminID := uuid.NewString()
	if _, err := db.console.ExecContext(ctx, `INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Factor', 'super_admin')`,
		adminID, "factor-"+adminID[:8]+"@example.com"); err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.NewString()
	if _, err := db.console.ExecContext(ctx, `INSERT INTO admin_sessions (id, admin_id, token_hash, mfa_verified, expires_at, last_seen_at)
		VALUES ($1, $2, $3, true, now() + interval '1 hour', now())`, sessionID, adminID, "th-"+sessionID); err != nil {
		t.Fatal(err)
	}

	// The app role: no plant, no change, no read of any factor.
	for _, q := range []string{
		`INSERT INTO admin_webauthn_credentials (id, admin_id, credential_id, public_key, name, created_at)
			VALUES (gen_random_uuid(), '` + adminID + `', 'planted', '\x01', 'planted', now())`,
		`INSERT INTO admin_recovery_codes (admin_id, code_hash, created_at) VALUES ('` + adminID + `', 'known-hash', now())`,
		`INSERT INTO admin_webauthn_ceremonies (session_id, purpose, session_data, expires_at)
			VALUES ('` + sessionID + `', 'login', '\x00', now() + interval '1 minute')`,
		`UPDATE admin_recovery_codes SET used_at = NULL`,
		`UPDATE admin_webauthn_credentials SET sign_count = 0`,
		`DELETE FROM admin_webauthn_credentials`,
		`DELETE FROM admin_recovery_codes`,
		`SELECT count(*) FROM admin_webauthn_credentials`,
		`SELECT count(*) FROM admin_recovery_codes`,
		`SELECT count(*) FROM admin_webauthn_ceremonies`,
	} {
		var pqErr *pq.Error
		if _, err := db.app.ExecContext(ctx, q); !errors.As(err, &pqErr) || pqErr.Code != "42501" {
			t.Fatalf("app role ran %q: %v (want 42501)", q, err)
		}
	}
	appRepo := postgres.NewAdminFactorRepository(&postgres.DB{DB: db.app})
	aid, _ := shared.IDFromString(adminID)
	now := time.Now().UTC().Truncate(time.Microsecond)
	planted := &admin.WebAuthnCredential{ID: shared.NewID(), AdminID: aid, CredentialID: []byte("planted"),
		PublicKey: []byte{1}, AAGUID: make([]byte, 16), Transports: []string{"usb"}, Name: "planted", CreatedAt: now}
	if err := appRepo.CreateWebAuthnCredential(ctx, planted); !isInsufficientPrivilege(err) {
		t.Fatalf("app pool planted a passkey: %v (want 42501)", err)
	}
	if err := appRepo.ReplaceRecoveryCodes(ctx, aid, []string{"known-hash"}, now); !isInsufficientPrivilege(err) {
		t.Fatalf("app pool planted a recovery code: %v (want 42501)", err)
	}

	// The console pool: the whole factor lifecycle.
	repo := postgres.NewAdminFactorRepository(&postgres.DB{DB: db.console})
	creds := make([]*admin.WebAuthnCredential, 0, 2)
	for i := range 2 {
		c := &admin.WebAuthnCredential{ID: shared.NewID(), AdminID: aid, CredentialID: []byte(uuid.NewString()),
			PublicKey: []byte{1, 2, 3}, AAGUID: make([]byte, 16), Transports: []string{"usb"}, Name: "key",
			CreatedAt: now.Add(time.Duration(i) * time.Second)}
		if err := repo.CreateWebAuthnCredential(ctx, c); err != nil {
			t.Fatalf("create as the console role: %v", err)
		}
		creds = append(creds, c)
	}
	if ok, err := repo.RecordWebAuthnUse(ctx, aid, creds[1].ID, 7, false, now); err != nil || !ok {
		t.Fatalf("record use: %v %v", ok, err)
	}
	if err := repo.RenameWebAuthnCredential(ctx, aid, creds[1].ID, "renamed"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := repo.DeleteWebAuthnCredential(ctx, aid, creds[0].ID, 2); !errors.Is(err, admin.ErrLastWebAuthnCredential) {
		t.Fatalf("below the floor: %v", err)
	}
	if err := repo.DeleteWebAuthnCredential(ctx, aid, creds[0].ID, 1); err != nil {
		t.Fatalf("delete as the console role: %v", err)
	}
	if list, err := repo.ListWebAuthnCredentials(ctx, aid); err != nil || len(list) != 1 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	if err := repo.ReplaceRecoveryCodes(ctx, aid, []string{"h1", "h2"}, now); err != nil {
		t.Fatalf("recovery codes as the console role: %v", err)
	}
	if ok, err := repo.UseRecoveryCode(ctx, aid, "h1", now); err != nil || !ok {
		t.Fatalf("use recovery code: %v %v", ok, err)
	}
	if n, err := repo.CountRecoveryCodes(ctx, aid); err != nil || n != 1 {
		t.Fatalf("count recovery codes: %d %v", n, err)
	}
	sid, _ := shared.IDFromString(sessionID)
	if err := repo.SaveCeremony(ctx, sid, "login", []byte("state"), now.Add(time.Minute)); err != nil {
		t.Fatalf("save ceremony: %v", err)
	}
	if data, err := repo.TakeCeremony(ctx, sid, "login", now); err != nil || string(data) != "state" {
		t.Fatalf("take ceremony: %q %v", data, err)
	}
	if err := repo.DeleteFactorsForAdmin(ctx, aid); err != nil {
		t.Fatalf("delete factors: %v", err)
	}
}

func isInsufficientPrivilege(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "42501"
}

func splitHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func splitURL(t *testing.T, base, dbName, user, pass string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil || !strings.HasPrefix(u.Scheme, "postgres") {
		t.Skip("DATABASE_URL is not a postgres:// URL")
	}
	u.Path = "/" + dbName
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u.String()
}

func splitOpen(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return db
}
