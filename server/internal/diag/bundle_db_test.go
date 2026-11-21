package diag

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/diag/redact"
	"github.com/openctemio/openctem/server/internal/migrate"
	"github.com/openctemio/openctem/server/internal/testdb"
)

const migrationsDir = "../../migrations"

// untar returns the files of a bundle by name (without the top directory).
func untar(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if hdr.Mode != 0o600 {
			t.Errorf("%s has mode %o, want 600", hdr.Name, hdr.Mode)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[strings.TrimPrefix(hdr.Name, "openctem-support/")] = body
	}
	return files
}

// The values seeded into the scratch database, the environment and the log
// input. None may appear anywhere in the archive.
var seeded = struct {
	tenantName, tenantSlug, userEmail, userName, assetName, findingTitle, evidence string
	sensorName, integrationName, dbPassword, encryptionKey, jwtSecret, appURL      string
	liveLiteral, logToken, logIP, logHost                                          string
}{
	tenantName: "Northwind Traders Holding", tenantSlug: "northwind-traders",
	userEmail: "priya.raman@northwind-traders.example", userName: "Priya Raman",
	assetName: "payroll-db-01.northwind-traders.example", findingTitle: "SQL injection in the payroll login form",
	evidence:   "root:x:0:0:root:/root:/bin/bash",
	sensorName: "dmz-scanner-northwind", integrationName: "Northwind Jira",
	dbPassword: "Sup3rS3cretDbPassw0rd!", encryptionKey: "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0",
	jwtSecret: "jwt-signing-secret-of-the-installation", appURL: "https://ctem.northwind-traders.example",
	liveLiteral: "live-statement-literal-northwind", logToken: "oct_Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1H",
	logIP: "203.0.113.77", logHost: "intranet.northwind-traders.example",
}

func seededValues() []string {
	s := seeded
	return []string{
		s.tenantName, s.tenantSlug, s.userEmail, s.userName, s.assetName, s.findingTitle, s.evidence,
		s.sensorName, s.integrationName, s.dbPassword, s.encryptionKey, s.jwtSecret, s.appURL,
		s.liveLiteral, s.logToken, s.logIP, s.logHost,
		// Parts of them, too.
		"northwind", "Northwind", "priya", "Priya", "payroll", "Sup3rS3cret", s.encryptionKey[:16],
	}
}

func seedInstallation(t *testing.T, db *sql.DB) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	const tenant, user, asset, finding = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, tenant, seeded.tenantName, seeded.tenantSlug)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, user, seeded.userEmail, seeded.userName)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
		asset, tenant, seeded.assetName)
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 'seed-tool', $4, 'high', $1::text, 'confirmed')`, finding, tenant, asset, seeded.findingTitle)
	exec(`INSERT INTO finding_evidence (id, tenant_id, finding_id, origin, kind, content, content_sha256)
		VALUES (gen_random_uuid(), $1, $2, 'manual', 'note', jsonb_build_object('text', $3::text), 'sha-seed')`, tenant, finding, seeded.evidence)
	exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, auth_type, status)
		VALUES (gen_random_uuid(), $1, $2, 'ticketing', 'jira', 'token', 'connected')`, tenant, seeded.integrationName)
	exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, max_concurrent_jobs, version)
		VALUES (gen_random_uuid(), $1, $2, 'worker', 'active', 'online', 'daemon', 'hash-seed-1', '', 5, 'v0.0.1'),
		       (gen_random_uuid(), $1, $3, 'worker', 'active', 'offline', 'daemon', 'hash-seed-2', '', 5, 'not-a-version')`,
		tenant, seeded.sensorName, seeded.sensorName+"-2")
}

// recordMigrations writes the migration tracking tables the way a migration
// run leaves them (testdb applies the files without the runner).
func recordMigrations(t *testing.T, db *sql.DB, migs []migrate.Migration) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS schema_migrations_applied (version bigint NOT NULL PRIMARY KEY, name text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`TRUNCATE schema_migrations, schema_migrations_applied`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range migs {
		if _, err := db.ExecContext(context.Background(), `INSERT INTO schema_migrations_applied (version, name) VALUES ($1, $2)`, m.Version, m.Name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO schema_migrations (version, dirty) VALUES ($1, false)`, migrate.Fence); err != nil {
		t.Fatal(err)
	}
}

// TestBundle_SeededInstallationLeaksNothing builds a bundle from a scratch
// database holding an organization, a user, an asset, a finding with
// evidence, an integration and sensors, with secrets in the environment,
// the same values in the log input and one of them in a statement that runs
// while the bundle is made. No seeded value may appear in any file.
func TestBundle_SeededInstallationLeaksNothing(t *testing.T) {
	db := testdb.PrivateDatabase(t, "diag_bundle", migrationsDir)
	seedInstallation(t, db)
	migs, err := migrate.Load(migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	recordMigrations(t, db, migs)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// A statement that is running while the bundle is made, with a seeded
	// value as a literal.
	running := make(chan struct{})
	slowCtx, stopSlow := context.WithCancel(ctx)
	go func() {
		defer close(running)
		_, _ = db.ExecContext(slowCtx, `SELECT pg_sleep(60), '`+seeded.liveLiteral+`' AS marker, 424242`)
	}()
	defer func() { stopSlow(); <-running }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(60)%' AND state = 'active' AND pid <> pg_backend_pid()`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the long statement never showed up in pg_stat_activity")
		}
		time.Sleep(50 * time.Millisecond)
	}

	env := map[string]string{
		"APP_ENV": "production", "APP_URL": seeded.appURL, "DB_PASSWORD": seeded.dbPassword,
		"DB_HOST": "db." + seeded.tenantSlug + ".example", "DB_NAME": "northwind_ctem", "DB_USER": "northwind_owner",
		"APP_ENCRYPTION_KEY": seeded.encryptionKey, "FINGERPRINT_KEY": seeded.encryptionKey, "AUTH_JWT_SECRET": seeded.jwtSecret,
		"SENSOR_KEY_PEPPER": seeded.jwtSecret, "LOG_LEVEL": "info",
	}
	deps := Deps{
		Getenv: envOf(env), DB: db, MigrationsDir: migrationsDir,
		PingRedis: func(context.Context) error {
			return errors.New("dial tcp " + seeded.logIP + ":6379: connect: connection refused")
		},
		SensorLatest: "v0.6.4", SensorMin: "v0.5.0",
		OwnsAuditTables: func(ctx context.Context, q Querier) (bool, error) {
			var owns bool
			err := q.QueryRowContext(ctx, `SELECT pg_has_role(current_user, c.relowner, 'USAGE') FROM pg_class c WHERE c.oid = to_regclass('public.audit_logs')`).Scan(&owns)
			return owns, err
		},
	}
	report := Run(ctx, deps)

	// The doctor on this installation.
	wantStatus := map[string]Status{
		"database.reachable":  StatusPass,
		"database.migrations": StatusPass,
		"database.clock":      StatusPass,
		"database.role":       StatusWarn, // the test connects as the schema owner
		"redis.reachable":     StatusFail,
		"sensors.heartbeat":   StatusPass,
		"sensors.versions":    StatusWarn, // one sensor older than the minimum
		"audit.chain":         StatusInfo,
		"queue.backlog":       StatusPass,
		"config.base_url":     StatusPass,
	}
	for id, want := range wantStatus {
		if c := findCheck(t, report, id); c.Status != want {
			t.Errorf("%s = %s (%s %s), want %s", id, c.Status, c.Summary, c.Detail, want)
		}
	}
	if c := findCheck(t, report, "sensors.heartbeat"); !strings.Contains(c.Summary, "2 active sensors: 1 online, 1 offline") {
		t.Errorf("sensors.heartbeat = %q", c.Summary)
	}
	if c := findCheck(t, report, "sensors.versions"); !strings.Contains(c.Summary, "1 older than supported, 1 of unknown version") {
		t.Errorf("sensors.versions = %q", c.Summary)
	}
	if report.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1 (Redis fails)", report.ExitCode())
	}

	logs := strings.Join([]string{
		`{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","level":"INFO","msg":"http request","method":"GET","path":"/api/v1/assets?search=` + seeded.assetName + `","status":200,"remote_addr":"` + seeded.logIP + `:51123","email":"` + seeded.userEmail + `","tenant_name":"` + seeded.tenantName + `"}`,
		`{"level":"ERROR","msg":"failed to save finding","error":"pq: duplicate key value violates unique constraint \"findings_key\" DETAIL: Key (title)=(` + seeded.findingTitle + `) already exists.","asset_name":"` + seeded.assetName + `","evidence":{"text":"` + seeded.evidence + `"}}`,
		`{"level":"WARN","msg":"login failed for ` + seeded.userEmail + ` from ` + seeded.logIP + `","user_name":"` + seeded.userName + `","authorization":"Bearer ` + seeded.logToken + `","cookie":"session=` + seeded.jwtSecret + `"}`,
		`{"level":"ERROR","msg":"cannot connect","error":"postgres://northwind_owner:` + seeded.dbPassword + `@db.` + seeded.tenantSlug + `.example:5432/northwind_ctem?sslmode=require: dial tcp ` + seeded.logIP + `:5432"}`,
		`gateway-1  | {"level":"info","msg":"handled request","request":{"host":"` + seeded.logHost + `","uri":"/x?token=` + seeded.logToken + `","remote_ip":"` + seeded.logIP + `","headers":{"Cookie":["sid=` + seeded.jwtSecret + `"],"Referer":["` + seeded.appURL + `/findings"]}},"status":200}`,
		`postgres-1  | LOG:  statement: UPDATE users SET name = '` + seeded.userName + `' WHERE email = '` + seeded.userEmail + `'`,
		`plain line: lookup ` + seeded.logHost + ` on 2001:db8::53: no such host, asset "` + seeded.assetName + `" skipped`,
		`time=2026-11-17T10:00:00Z level=WARN msg="scan target unreachable" target=` + seeded.assetName + ` sensor_name=` + seeded.sensorName + ` tenant=` + seeded.tenantSlug,
		`{"level":"INFO","msg":"integration ` + "'" + seeded.integrationName + "'" + ` synced","key":"` + seeded.encryptionKey + `"}`,
	}, "\n") + "\n"

	var archive bytes.Buffer
	manifest, err := WriteBundle(ctx, &archive, BundleInput{
		Report: report, Config: EffectiveConfig(config.Registry(), envOf(env)), DB: db,
		Logs: strings.NewReader(logs), Since: 1000000 * time.Hour, Redactor: redact.NewWithKey([]byte("bundle test")),
		LongQueryAfter: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Notes) != 1 || !strings.HasPrefix(manifest.Notes[0], "logs: 9 lines read") {
		t.Errorf("notes = %v, want only the log summary (every other file present)", manifest.Notes)
	}
	files := untar(t, archive.Bytes())

	// 1. No seeded value anywhere: not in the raw archive bytes, not in any
	// file, in any letter case.
	for name, body := range files {
		lower := strings.ToLower(string(body))
		for _, v := range seededValues() {
			if strings.Contains(lower, strings.ToLower(v)) {
				at := strings.Index(lower, strings.ToLower(v))
				t.Errorf("%s holds the seeded value %q: ...%s...", name, v, string(body[max(0, at-80):min(len(body), at+80)]))
			}
		}
	}

	// 2. The expected files, each listed in the manifest with its hash.
	want := []string{"README.txt", "build.json", "config.json", "doctor.json", "doctor.txt", "queue.json", "logs/server.log",
		"database/server.json", "database/tables.json", "database/indexes.json", "database/activity.json", "database/migrations.json"}
	listed := map[string]File{}
	for _, f := range manifest.Files {
		listed[f.Name] = f
	}
	for _, name := range want {
		body, ok := files[name]
		if !ok {
			t.Errorf("%s missing from the archive", name)
			continue
		}
		sum := sha256.Sum256(body)
		if f := listed[name]; f.SHA256 != hex.EncodeToString(sum[:]) || f.Bytes != int64(len(body)) || f.About == "" {
			t.Errorf("%s: manifest entry %+v does not match the file", name, f)
		}
	}
	if len(files) != len(want)+1 || len(manifest.Files) != len(want) {
		t.Errorf("archive holds %d files, manifest lists %d, want %d and the manifest", len(files), len(manifest.Files), len(want))
	}
	var inArchive Manifest
	if err := json.Unmarshal(files["manifest.json"], &inArchive); err != nil || len(inArchive.Files) != len(want) || len(inArchive.NeverIncluded) == 0 {
		t.Errorf("manifest.json in the archive: %v %+v", err, inArchive)
	}

	// 3. The statistics are there, and they are statistics.
	var tables []map[string]any
	if err := json.Unmarshal(files["database/tables.json"], &tables); err != nil || len(tables) < 100 {
		t.Fatalf("tables.json: %v, %d tables", err, len(tables))
	}
	found := false
	for _, tb := range tables {
		if tb["name"] == "findings" && tb["schema"] == "public" {
			found = true
		}
	}
	if !found {
		t.Error("tables.json does not list public.findings")
	}
	activity := string(files["database/activity.json"])
	if !strings.Contains(activity, "SELECT pg_sleep(?), ? AS marker, ?") {
		t.Errorf("activity.json lacks the long statement's shape:\n%s", activity)
	}
	var migrations struct {
		Applied []struct{ Version int64 } `json:"applied"`
		Dirty   bool                      `json:"dirty"`
	}
	if err := json.Unmarshal(files["database/migrations.json"], &migrations); err != nil || len(migrations.Applied) != len(migs) || migrations.Dirty {
		t.Errorf("migrations.json: %v, %d applied (want %d), dirty %v", err, len(migrations.Applied), len(migs), migrations.Dirty)
	}
	logOut := string(files["logs/server.log"])
	for _, kept := range []string{`"msg":"http request"`, `"status":200`, "failed to save finding", "findings_key", "gateway-1 | ", "no such host", `msg="scan target unreachable"`} {
		if !strings.Contains(logOut, kept) {
			t.Errorf("the masked log lost %q:\n%s", kept, logOut)
		}
	}
	// One value, one mark: the address appears in five lines.
	ipMark := redact.NewWithKey([]byte("bundle test")).Mark(redact.KindIP, seeded.logIP)
	if n := strings.Count(logOut, ipMark); n < 2 {
		t.Errorf("the address's mark %s appears %d times, want it wherever the address was in free text", ipMark, n)
	}
	var cfg []ConfigEntry
	if err := json.Unmarshal(files["config.json"], &cfg); err != nil {
		t.Fatal(err)
	}
	for _, e := range cfg {
		switch e.Name {
		case "DB_PASSWORD", "APP_URL", "APP_ENCRYPTION_KEY", "DB_HOST":
			if !e.Set || e.Value != nil {
				t.Errorf("config %s = %+v, want set without a value", e.Name, e)
			}
		case "LOG_LEVEL":
			if e.Value == nil || *e.Value != "info" {
				t.Errorf("config LOG_LEVEL = %+v, want its value", e)
			}
		}
	}

	// 4. Pending and dirty migrations are failures with a fix.
	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations_applied WHERE version = $1`, migs[len(migs)-1].Version); err != nil {
		t.Fatal(err)
	}
	if c := deps.checkMigrations(ctx); c.Status != StatusFail || !strings.Contains(c.Summary, "1 of its") || c.Fix == "" {
		t.Errorf("one pending migration: %+v", c)
	}
	if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET version = $1, dirty = true`, migs[len(migs)-1].Version); err != nil {
		t.Fatal(err)
	}
	if c := deps.checkMigrations(ctx); c.Status != StatusFail || !strings.Contains(c.Summary, "dirty") {
		t.Errorf("dirty schema: %+v", c)
	}
}

// TestReadOnly_NothingCanBeWritten: the transaction every check and every
// statistic runs in refuses writes and cuts long statements.
func TestReadOnly_NothingCanBeWritten(t *testing.T) {
	db := testdb.EmptyDatabase(t, "diag_ro")
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE probe (n int)`); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO probe VALUES (1)`, `UPDATE probe SET n = 2`, `DELETE FROM probe`, `TRUNCATE probe`,
		`CREATE TABLE other (n int)`, `DROP TABLE probe`, `SET TRANSACTION READ WRITE`, `SET LOCAL transaction_read_only = off`,
	} {
		err := ReadOnly(ctx, db, time.Second, func(q Querier) error {
			var discard any
			err := q.QueryRowContext(ctx, stmt).Scan(&discard)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		})
		if err == nil {
			t.Errorf("%q succeeded in the read-only transaction", stmt)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM probe`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("probe has %d rows (%v), want the empty table untouched", n, err)
	}

	start := time.Now()
	err := ReadOnly(ctx, db, 200*time.Millisecond, func(q Querier) error {
		var x string
		return q.QueryRowContext(ctx, `SELECT pg_sleep(10)::text`).Scan(&x)
	})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("a 10 s statement under a 200 ms limit: err %v after %v", err, time.Since(start))
	}
	if err := ReadOnly(ctx, nil, time.Second, func(Querier) error { return nil }); err == nil {
		t.Error("no database, no error")
	}
}
