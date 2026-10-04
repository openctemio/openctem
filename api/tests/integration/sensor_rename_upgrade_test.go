package integration

// Upgrade test for the agent → sensor rename (RFC-023 §9.5, migration 000230).
//
// An existing installation upgrades through its normal `migrate up`. This test
// builds a database the way such an installation looks — every migration
// before 000230 plus representative data written in the old vocabulary
// (testdata/sensor_rename_seed.sql) — and then applies the rest of the
// migrations in one go, as an install that skipped several releases would.
// It asserts the converted values, that every role, group, permission set and
// oct_ API key keeps exactly the same effective access, that the upgrade check
// reports nothing left over, and that down → up round-trips.
//
// Needs DATABASE_URL with the right to CREATE DATABASE (CI's Test job has it);
// the test builds and drops its own database and never touches DATABASE_URL's.

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const sensorRenameVersion = "000230"

type migrationFile struct{ version, up, down string }

func loadMigrations(t *testing.T) []migrationFile {
	t.Helper()
	ups, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.up.sql"))
	if err != nil || len(ups) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}
	sort.Strings(ups)
	out := make([]migrationFile, 0, len(ups))
	for _, up := range ups {
		base := filepath.Base(up)
		out = append(out, migrationFile{
			version: base[:strings.Index(base, "_")],
			up:      up,
			down:    strings.TrimSuffix(up, ".up.sql") + ".down.sql",
		})
	}
	return out
}

func execFile(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	sqlText, err := os.ReadFile(path) //nolint:gosec // repo-local migration path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// One Exec per file, exactly as golang-migrate applies it: a multi-
	// statement string runs as one implicit transaction unless the file
	// manages its own (some do).
	if _, err := db.Exec(string(sqlText)); err != nil {
		t.Fatalf("apply %s: %v", filepath.Base(path), err)
	}
}

func scratchDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping the sensor rename upgrade test")
	}
	admin, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if err := admin.Ping(); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	name := "sensor_upgrade_" + strings.ReplaceAll(shared.NewID().String(), "-", "")[:16]
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Skipf("cannot create a scratch database (needs CREATEDB): %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
	})

	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// effectiveAccess is every principal's grant set with agents:* spelled
// sensors:*, so the value must be identical before and after the rename.
func effectiveAccess(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	q := `
		SELECT 'role:' || r.slug, string_agg(p, ',' ORDER BY p)
		FROM role_permissions rp JOIN roles r ON r.id = rp.role_id,
		     LATERAL (SELECT replace(rp.permission_id, 'agents:', 'sensors:') AS p) m
		GROUP BY r.slug
		UNION ALL
		SELECT 'api_key:' || k.name, array_to_string(ARRAY(
			SELECT replace(s, 'agents:', 'sensors:') AS p FROM unnest(k.scopes::text[]) s ORDER BY p), ',')
		FROM api_keys k`
	// Group permission overrides and permission sets exist until migration
	// 000493 removes them (permissions come only from roles); include them
	// while they exist.
	if queryString(t, db, `SELECT coalesce(to_regclass('public.group_permissions')::text, '')`) != "" {
		q += `
		UNION ALL
		SELECT 'group:' || g.slug, string_agg(p, ',' ORDER BY p)
		FROM group_permissions gp JOIN groups g ON g.id = gp.group_id,
		     LATERAL (SELECT replace(gp.permission_id, 'agents:', 'sensors:') AS p) m
		GROUP BY g.slug`
	}
	if queryString(t, db, `SELECT coalesce(to_regclass('public.permission_sets')::text, '')`) != "" {
		q += `
		UNION ALL
		SELECT 'permission_set:' || ps.slug, string_agg(p, ',' ORDER BY p)
		FROM permission_set_items i JOIN permission_sets ps ON ps.id = i.permission_set_id,
		     LATERAL (SELECT replace(i.permission_id, 'agents:', 'sensors:') AS p) m
		GROUP BY ps.slug`
	}
	rows, err := db.Query(q)
	if err != nil {
		t.Fatalf("effective access: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var who, perms string
		if err := rows.Scan(&who, &perms); err != nil {
			t.Fatal(err)
		}
		out[who] = perms
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("effective access: %v", err)
	}
	return out
}

func queryString(t *testing.T, db *sql.DB, q string) string {
	t.Helper()
	var s sql.NullString
	if err := db.QueryRow(q).Scan(&s); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return s.String
}

func TestSensorRenameUpgrade(t *testing.T) {
	db := scratchDatabase(t)
	ctx := context.Background()
	migs := loadMigrations(t)

	// 1. An installation as it is before the upgrade.
	var pending []migrationFile
	for _, m := range migs {
		if m.version < sensorRenameVersion {
			execFile(t, db, m.up)
		} else {
			pending = append(pending, m)
		}
	}
	if len(pending) == 0 || pending[0].version != sensorRenameVersion {
		t.Fatalf("migration %s not found", sensorRenameVersion)
	}
	execFile(t, db, filepath.Join("testdata", "sensor_rename_seed.sql"))
	before := effectiveAccess(t, db)
	known := permissionCatalog(t, db)
	assetsUpdatedAt := queryString(t, db, `SELECT updated_at::text FROM assets WHERE id = '11111111-0000-0000-0000-00000000000f'`)

	// 2. Upgrade: everything from 000230 on, in one go.
	for _, m := range pending {
		execFile(t, db, m.up)
	}
	assertUpgraded(t, db, before, known, assetsUpdatedAt)

	// 3. Re-running the rename on an upgraded database changes nothing. The
	// rename also rewrites group permission overrides and permission sets,
	// which 000493 later drops, so the re-run happens with 000493 rolled back
	// (its down restores the archived rows) and 000493 is applied again after.
	removal := migrationByVersion(t, pending, groupPermissionSetRemovalVersion)
	execFile(t, db, removal.down)
	execFile(t, db, pending[0].up)
	execFile(t, db, removal.up)
	assertUpgraded(t, db, before, known, assetsUpdatedAt)

	items, err := postgres.CheckSensorRename(ctx, db, true)
	if err != nil {
		t.Fatalf("upgrade check: %v", err)
	}
	for _, it := range items {
		if it.Leftover() {
			t.Errorf("upgrade check reports a leftover: %s (%d)", it.What, it.Count)
		}
	}

	// The check notices pre-rename data written after the upgrade (e.g. by an
	// old binary that was not stopped).
	if _, err := db.Exec(`INSERT INTO pipeline_templates (tenant_id, name, settings)
		VALUES ('11111111-0000-0000-0000-000000000001', 'stale', '{"agent_preference":"auto"}')`); err != nil {
		t.Fatal(err)
	}
	items, err = postgres.CheckSensorRename(ctx, db, false)
	if err != nil {
		t.Fatalf("upgrade check: %v", err)
	}
	flagged := false
	for _, it := range items {
		flagged = flagged || (it.Leftover() && strings.Contains(it.What, "pipeline"))
	}
	if !flagged {
		t.Error("upgrade check did not report a pipeline template still using agent_preference")
	}
	if _, err := db.Exec(`DELETE FROM pipeline_templates WHERE name = 'stale'`); err != nil {
		t.Fatal(err)
	}

	// 4. Down restores the old vocabulary with the same access; up again.
	for i := len(pending) - 1; i >= 0; i-- {
		execFile(t, db, pending[i].down)
	}
	if got := effectiveAccess(t, db); fmt.Sprint(got) != fmt.Sprint(before) {
		t.Errorf("effective access changed by down:\nbefore %v\nafter  %v", before, got)
	}
	if n := queryString(t, db, `SELECT count(*)::text FROM role_permissions WHERE permission_id LIKE 'agents:%'`); n == "0" {
		t.Error("down did not restore agents:* grants")
	}
	if queryString(t, db, `SELECT to_regclass('public.agents')::text`) == "" {
		t.Error("down did not restore the agents table")
	}
	for _, m := range pending {
		execFile(t, db, m.up)
	}
	assertUpgraded(t, db, before, known, assetsUpdatedAt)
}

// groupPermissionSetRemovalVersion drops group permission overrides and
// permission sets (permissions come only from roles).
const groupPermissionSetRemovalVersion = "000493"

func migrationByVersion(t *testing.T, migs []migrationFile, version string) migrationFile {
	t.Helper()
	for _, m := range migs {
		if m.version == version {
			return m
		}
	}
	t.Fatalf("migration %s not found", version)
	return migrationFile{}
}

// renamedCatalog is the sensor permission catalog the rename produces.
var renamedCatalog = []string{
	"sensors:read", "sensors:write", "sensors:delete",
	"sensors:commands:read", "sensors:commands:write", "sensors:commands:delete",
}

// permissionCatalog returns the permission ids that exist before the upgrade,
// spelled as the rename spells them (agents:* -> sensors:*).
func permissionCatalog(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT replace(id, 'agents:', 'sensors:') FROM permissions`)
	if err != nil {
		t.Fatalf("permission catalog: %v", err)
	}
	defer rows.Close()
	known := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		known[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("permission catalog: %v", err)
	}
	return known
}

// withoutLaterPermissions drops, from an access map taken after the upgrade,
// every permission that did not exist before it: migrations after 000230 add
// permissions and grant them to the system roles (000231 sensors:zones:*,
// 000232 findings:credentials:reveal), and those grants are not part of the
// rename. Every permission that existed at 000230 is still compared, so a
// grant the rename gained or lost is caught.
func withoutLaterPermissions(access map[string]string, known map[string]bool) map[string]string {
	out := make(map[string]string, len(access))
	for who, perms := range access {
		kept := []string{}
		for _, p := range strings.Split(perms, ",") {
			if known[p] {
				kept = append(kept, p)
			}
		}
		out[who] = strings.Join(kept, ",")
	}
	return out
}

// laterRevocations are system-role grants that a migration after 000230
// removes on purpose (000246: sensors:write, audit:read and
// settings:billing:read are owner/admin only; 000262: scanner templates and
// template sources are written by owners and admins only). They are not part
// of the rename, so they are taken out of the "before" map too; any other
// grant the upgrade lost is still caught.
var laterRevocations = map[string][]string{
	"role:member": {"sensors:write", "audit:read", "settings:billing:read",
		"scans:templates:write", "scans:sources:write"},
	"role:viewer": {"audit:read", "settings:billing:read"},
}

// laterRemovedPermissions are permission ids a migration after 000230
// deletes from the catalog with every grant of them (000492: permission sets
// are gone, so team:permission_sets:* means nothing).
var laterRemovedPermissions = []string{
	"team:permission_sets:read", "team:permission_sets:write", "team:permission_sets:delete",
}

// laterRemovedPrincipals are grant holders a migration after 000230 removes
// (000493: group permission overrides and permission sets; their rows are
// archived and restored by its down migration).
var laterRemovedPrincipals = []string{"group:", "permission_set:"}

func withoutLaterRevocations(access map[string]string) map[string]string {
	out := make(map[string]string, len(access))
	for who, perms := range access {
		if slices.ContainsFunc(laterRemovedPrincipals, func(prefix string) bool { return strings.HasPrefix(who, prefix) }) {
			continue
		}
		kept := []string{}
		for _, p := range strings.Split(perms, ",") {
			if !slices.Contains(laterRevocations[who], p) && !slices.Contains(laterRemovedPermissions, p) {
				kept = append(kept, p)
			}
		}
		out[who] = strings.Join(kept, ",")
	}
	return out
}

func assertUpgraded(t *testing.T, db *sql.DB, before map[string]string, known map[string]bool, assetsUpdatedAt string) {
	t.Helper()
	before = withoutLaterRevocations(before)
	if got := withoutLaterPermissions(effectiveAccess(t, db), known); fmt.Sprint(got) != fmt.Sprint(before) {
		t.Errorf("effective access changed by the upgrade:\nbefore %v\nafter  %v", before, got)
	}
	for _, c := range []struct{ name, q, want string }{
		{"agents table renamed", `SELECT to_regclass('public.sensors')::text`, "sensors"},
		{"old table gone", `SELECT coalesce(to_regclass('public.agents')::text, '')`, ""},
		{"key row kept", `SELECT sensor_id::text FROM sensor_api_keys WHERE id = '11111111-0000-0000-0000-000000000008'`,
			"11111111-0000-0000-0000-000000000007"},
		{"sensor key scopes", `SELECT array_to_string(ARRAY(SELECT unnest(scopes) ORDER BY 1), ',') FROM sensor_api_keys`,
			"ingest:write,sensor:heartbeat,sensor:read"},
		{"command pin", `SELECT sensor_id::text FROM commands WHERE id = '11111111-0000-0000-0000-000000000009'`,
			"11111111-0000-0000-0000-000000000007"},
		{"v1 job payload untouched", `SELECT payload->>'agent_preference' FROM commands WHERE id = '11111111-0000-0000-0000-000000000009'`, "tenant"},
		{"scan preference", `SELECT sensor_preference FROM scans WHERE id = '11111111-0000-0000-0000-00000000000a'`, "tenant"},
		{"module toggle", `SELECT module_id FROM tenant_modules WHERE tenant_id = '11111111-0000-0000-0000-000000000001'`, "sensors"},
		{"webhook events", `SELECT array_to_string(ARRAY(SELECT unnest(event_types) ORDER BY 1), ',') FROM webhooks`,
			"finding.created,sensor.offline"},
		{"notification extension events", `SELECT enabled_event_types::text FROM integration_notification_extensions`,
			`["finding.created", "sensor.error"]`},
		{"muted types", `SELECT muted_types::text FROM notification_preferences`, `["sensor.offline"]`},
		{"pipeline settings", `SELECT settings->>'sensor_preference' FROM pipeline_templates WHERE id = '11111111-0000-0000-0000-00000000000e'`, "platform"},
		{"tenable mode", `SELECT config->>'execution_mode' FROM integrations WHERE id = '11111111-0000-0000-0000-00000000000d'`, "sensor"},
		{"tenable pin", `SELECT config->>'sensor_id' FROM integrations WHERE id = '11111111-0000-0000-0000-00000000000d'`,
			"11111111-0000-0000-0000-000000000007"},
		{"asset provenance", `SELECT source_type || '/' || discovery_source FROM assets WHERE id = '11111111-0000-0000-0000-00000000000f'`, "sensor/sensor"},
		{"asset updated_at untouched", `SELECT updated_at::text FROM assets WHERE id = '11111111-0000-0000-0000-00000000000f'`, assetsUpdatedAt},
		{"append-only state history kept", `SELECT source FROM asset_state_history WHERE asset_id = '11111111-0000-0000-0000-00000000000f'`, "agent"},
		{"hash-chained audit kept", `SELECT action || '/' || resource_type FROM audit_logs WHERE tenant_id = '11111111-0000-0000-0000-000000000001'`, "agent.created/agent"},
		{"permission catalog", `SELECT count(*)::text FROM permissions WHERE id = ANY('{` + strings.Join(renamedCatalog, ",") + `}')`, "6"},
		{"no agents:* permission left", `SELECT count(*)::text FROM permissions WHERE id LIKE 'agents:%'`, "0"},
	} {
		if got := queryString(t, db, c.q); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
