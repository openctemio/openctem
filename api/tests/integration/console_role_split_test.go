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

// Deleting an authenticator serializes on the administrator without a row
// lock on admin_users (which needs UPDATE, a privilege the app role lacks).
func TestAdminFactors_ConsoleRoleSplit(t *testing.T) {
	db := bootstrapSplitRoles(t)
	ctx := context.Background()
	adminID := uuid.NewString()
	if _, err := db.console.ExecContext(ctx, `INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Factor', 'super_admin')`,
		adminID, "factor-"+adminID[:8]+"@example.com"); err != nil {
		t.Fatal(err)
	}
	aid, _ := shared.IDFromString(adminID)
	repo := postgres.NewAdminFactorRepository(&postgres.DB{DB: db.app})
	now := time.Now().UTC().Truncate(time.Microsecond)
	creds := make([]*admin.WebAuthnCredential, 0, 2)
	for i := range 2 {
		c := &admin.WebAuthnCredential{ID: shared.NewID(), AdminID: aid, CredentialID: []byte(uuid.NewString()),
			PublicKey: []byte{1, 2, 3}, AAGUID: make([]byte, 16), Transports: []string{"usb"}, Name: "key",
			CreatedAt: now.Add(time.Duration(i) * time.Second)}
		if err := repo.CreateWebAuthnCredential(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}
		creds = append(creds, c)
	}
	if err := repo.DeleteWebAuthnCredential(ctx, aid, creds[0].ID, 2); !errors.Is(err, admin.ErrLastWebAuthnCredential) {
		t.Fatalf("below the floor: %v", err)
	}
	if err := repo.DeleteWebAuthnCredential(ctx, aid, creds[0].ID, 1); err != nil {
		t.Fatalf("delete as the app role: %v", err)
	}
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
