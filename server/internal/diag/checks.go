package diag

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/internal/app/systemstatus"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/migrate"
	"github.com/openctemio/openctem/server/pkg/crypto"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
)

// Thresholds of the checks.
const (
	clockWarn = 5 * time.Second
	clockFail = 60 * time.Second

	queueOldestWarn  = time.Hour
	outboxOldestWarn = 15 * time.Minute

	publicCertWarn = 30 * 24 * time.Hour
	publicCertFail = 7 * 24 * time.Hour
)

// The settings below hold keys that existing data depends on. A new value
// does not "rotate" anything: it makes the data written under the old value
// unusable.
var permanentKeys = []struct{ name, loses string }{
	{"APP_ENCRYPTION_KEY", "stored credentials cannot be decrypted"},
	{"FINGERPRINT_KEY", "every known secret finding is reported again as new"},
	{"SENSOR_KEY_PEPPER", "every sensor key stops verifying"},
}

func (d Deps) getenv(name string) (string, bool) {
	if d.Getenv == nil {
		return "", false
	}
	return d.Getenv(name)
}

func (d Deps) production() bool {
	if d.Config != nil {
		return d.Config.IsProduction()
	}
	env, _ := d.getenv("APP_ENV")
	return env == "" || env == "production"
}

func (d Deps) checkConfig() Check {
	c := Check{ID: "config.valid", Name: "Configuration"}
	if d.ConfigErr != nil {
		c.Status, c.Summary = StatusFail, "The configuration does not load, so the server cannot start."
		c.Detail = d.ConfigErr.Error()
		c.Fix = "Correct the setting the detail names in the environment (.env, the kit's variables or the chart's values), then run this command again."
		return c
	}
	if d.Config == nil {
		c.Status, c.Summary = StatusInfo, "The configuration was not checked."
		return c
	}
	warnings := len(d.Config.EnvWarnings) + len(d.Config.WideTrustedProxies())
	if warnings > 0 {
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("The configuration is valid, with %d warnings.", warnings)
		c.Detail = strings.Join(append(append([]string{}, d.Config.EnvWarnings...), d.Config.WideTrustedProxies()...), "; ")
		c.Fix = "Run `server -check-config` to read each warning, and correct the settings it names."
		return c
	}
	c.Status, c.Summary = StatusPass, "The configuration is valid."
	return c
}

func (d Deps) checkBaseURL() Check {
	c := Check{ID: "config.base_url", Name: "Public URL"}
	raw, _ := d.getenv("APP_URL")
	if d.Config != nil {
		raw = d.Config.App.URL
	}
	fix := "Set APP_URL to the exact origin browsers and sensors use, for example https://ctem.example.com (Compose: OPENCTEM_PUBLIC_URL)."
	if raw == "" {
		c.Status, c.Summary, c.Fix = StatusFail, "APP_URL is not set: links in e-mails, sign-in redirects and sensor install commands have no address to use.", fix
		if !d.production() {
			c.Status = StatusWarn
		}
		return c
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https"):
		c.Status, c.Summary, c.Fix = StatusFail, "APP_URL is not an http or https origin.", fix
	case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		c.Status, c.Summary, c.Fix = StatusWarn, "APP_URL carries more than an origin (a path, a query or credentials).", fix
	case u.Scheme == "http" && d.production():
		c.Status, c.Summary = StatusWarn, "APP_URL uses http: sessions and sensor traffic are not encrypted."
		c.Fix = "Serve the platform over https and set APP_URL to the https origin."
	default:
		c.Status, c.Summary = StatusPass, fmt.Sprintf("APP_URL is set and is an %s origin.", u.Scheme)
	}
	return c
}

// checkKeys reports whether the key settings are present and well-formed. It
// reads the values only to measure them; no value, prefix or digest is
// reported.
func (d Deps) checkKeys() []Check {
	enc := Check{ID: "config.encryption_key", Name: "Encryption key"}
	key, set := d.getenv("APP_ENCRYPTION_KEY")
	format, _ := d.getenv("APP_ENCRYPTION_KEY_FORMAT")
	switch {
	case !set || key == "":
		enc.Status, enc.Summary = StatusFail, "APP_ENCRYPTION_KEY is not set: stored credentials cannot be encrypted."
		enc.Fix = "On a NEW installation generate one with `openssl rand -hex 32`. On an existing installation restore the original value from your backup of the settings: a new key cannot read what the old one encrypted."
		if !d.production() {
			enc.Status = StatusWarn
		}
	default:
		if _, err := crypto.ParseKey(key, format); err != nil {
			enc.Status, enc.Summary = StatusFail, "APP_ENCRYPTION_KEY is set but is not a valid key (32 raw, 64 hex or 44 base64 characters)."
			enc.Fix = "Restore the original value from your backup of the settings; check for a truncated line, quotes or trailing spaces."
		} else {
			enc.Status, enc.Summary = StatusPass, "APP_ENCRYPTION_KEY is set and well-formed."
		}
	}

	fp := Check{ID: "config.fingerprint_key", Name: "Fingerprint key"}
	fkey, fset := d.getenv("FINGERPRINT_KEY")
	switch {
	case !fset || fkey == "":
		fp.Status, fp.Summary = StatusFail, "FINGERPRINT_KEY is not set."
		fp.Fix = "On an installation that already stores secret findings set it to the value APP_ENCRYPTION_KEY had when they were stored; on a new installation generate one with `openssl rand -hex 32`."
		if !d.production() {
			fp.Status = StatusWarn
		}
	case len(fkey) < 32:
		fp.Status, fp.Summary = StatusFail, "FINGERPRINT_KEY is set but shorter than 32 characters."
		fp.Fix = "Restore the original value from your backup of the settings."
	default:
		fp.Status, fp.Summary = StatusPass, "FINGERPRINT_KEY is set and well-formed."
	}

	names := make([]string, 0, len(permanentKeys))
	for _, k := range permanentKeys {
		state := "not set"
		if v, ok := d.getenv(k.name); ok && v != "" {
			state = "set"
		}
		names = append(names, fmt.Sprintf("%s (%s; a new value means %s)", k.name, state, k.loses))
	}
	perm := Check{ID: "config.permanent_keys", Name: "Keys to keep", Status: StatusInfo,
		Summary: "Never regenerate these on a running installation: " + strings.Join(names, ", ") + ".",
		Fix:     "Keep a copy of them with every database backup; change one only with the documented rotation (docs/deployment/encryption-key-rotation.md)."}
	return []Check{enc, fp, perm}
}

func (d Deps) checkDatabase(ctx context.Context) Check {
	c := Check{ID: "database.reachable", Name: "Database"}
	fix := "Check that PostgreSQL runs and that DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and DB_SSLMODE match it; the detail carries the driver's reason."
	if d.DB == nil {
		c.Status, c.Summary, c.Fix = StatusFail, "The database connection could not be opened.", fix
		if d.DBErr != nil {
			c.Detail = d.DBErr.Error()
		}
		if d.Config == nil {
			c.Status, c.Summary, c.Fix = StatusInfo, "Not checked: the configuration did not load.", ""
		}
		return c
	}
	start := time.Now()
	var one int
	err := d.readOnly(ctx, func(q Querier) error { return q.QueryRowContext(ctx, `SELECT 1`).Scan(&one) })
	if err != nil {
		c.Status, c.Summary, c.Fix, c.Detail = StatusFail, "The database does not answer.", fix, err.Error()
		return c
	}
	c.Status, c.Summary = StatusPass, fmt.Sprintf("The database answered in %d ms.", time.Since(start).Milliseconds())
	return c
}

func (d Deps) checkRole(ctx context.Context) Check {
	c := Check{ID: "database.role", Name: "Database role"}
	var super, createSchema, readsState bool
	var owns bool
	err := d.readOnly(ctx, func(q Querier) error {
		if err := q.QueryRowContext(ctx, `
			SELECT COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false),
			       has_schema_privilege(current_user, current_schema(), 'CREATE'),
			       COALESCE(has_table_privilege(current_user, to_regclass('schema_migrations_applied'), 'SELECT'), true)`,
		).Scan(&super, &createSchema, &readsState); err != nil {
			return err
		}
		if d.OwnsAuditTables != nil {
			var err error
			owns, err = d.OwnsAuditTables(ctx, q)
			return err
		}
		return nil
	})
	if err != nil {
		c.Status, c.Summary, c.Detail = StatusInfo, "The role's privileges could not be read.", err.Error()
		return c
	}
	var problems []string
	if super {
		problems = append(problems, "it is a superuser")
	}
	if owns {
		problems = append(problems, "it owns the audit tables, so the database cannot stop a holder of the API's credentials from changing audit history")
	}
	if createSchema {
		problems = append(problems, "it may create objects in the schema")
	}
	roleFix := "Run deploy/postgres/least-privilege-roles.sql and connect the API as the app role (docs/deployment/database-roles.md)."
	switch {
	case !readsState:
		c.Status, c.Summary = StatusFail, "The API's role may not read the migration state, so the server refuses to start."
		c.Fix = "Grant it SELECT on schema_migrations and schema_migrations_applied: re-run deploy/postgres/least-privilege-roles.sql."
	case len(problems) > 0:
		c.Status = StatusWarn
		c.Summary = "The API connects with more privileges than the least-privilege setup gives it: " + strings.Join(problems, "; ") + "."
		c.Fix = roleFix
	default:
		c.Status, c.Summary = StatusPass, "The API connects as a least-privilege role that does not own the audit tables."
	}
	return c
}

func (d Deps) checkMigrations(ctx context.Context) Check {
	c := Check{ID: "database.migrations", Name: "Migrations"}
	migs, err := migrate.Load(d.MigrationsDir)
	if err != nil || len(migs) == 0 {
		c.Status, c.Summary = StatusInfo, "The migrations shipped with this build could not be read, so the schema was not compared."
		c.Fix = "Run the command inside the server image, or set MIGRATIONS_DIR to the directory of the *.up.sql files."
		if err != nil {
			c.Detail = err.Error()
		}
		return c
	}
	rels, _ := migrate.LoadReleases(d.MigrationsDir)
	var rep migrate.Report
	var tracked bool
	var inspectErr error
	err = d.readOnly(ctx, func(q Querier) error {
		var err error
		if tracked, err = migrate.Tracked(ctx, q); err != nil || !tracked {
			return err
		}
		rep, inspectErr = migrate.Inspect(ctx, q, migs, migrate.Takeover{Releases: rels})
		return nil
	})
	upFix := "Run the migrations of this release: `docker compose run --rm migrate` (Compose), the kit's upgrade play, or the chart's migration job; then start the server."
	var newer migrate.ErrNewerDatabase
	var dirty migrate.ErrDirty
	switch {
	case migrate.IsPermissionDenied(err) || migrate.IsPermissionDenied(inspectErr):
		c.Status, c.Summary = StatusFail, "The API's role may not read the migration state."
		c.Fix = "Re-run deploy/postgres/least-privilege-roles.sql."
	case err != nil:
		c.Status, c.Summary, c.Detail = StatusInfo, "The migration state could not be read.", err.Error()
	case !tracked:
		c.Status, c.Summary, c.Fix = StatusFail, "No migration has been applied to this database.", upFix
	case rep.Dirty || errors.As(inspectErr, &dirty):
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("Migration %d failed midway and the schema is marked dirty.", rep.Version)
		c.Fix = "Read the migration job's log for the statement that failed, correct its cause, then run the migrations again; do not start the server on a dirty schema."
	case len(rep.Pending) > 0:
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("The schema is behind this build: %d of its %d migrations are not applied (%s).",
			len(rep.Pending), len(migs), migrate.Versions(rep.Pending, 3))
		c.Fix = upFix
	case errors.As(inspectErr, &newer):
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("The schema (version %d) is newer than this build (version %d): a newer release migrated this database.", newer.Applied, newer.Shipped)
		c.Fix = "Run the release that matches the database, unless this is a deliberate rollback."
	case inspectErr != nil:
		c.Status, c.Summary, c.Detail = StatusFail, "The migration state is not one this build can continue from.", inspectErr.Error()
		c.Fix = "Run `openctem-migrate status` for the full explanation."
	default:
		c.Status = StatusPass
		c.Summary = fmt.Sprintf("The schema matches this build: %d migrations applied, version %d, not dirty.", rep.Applied, rep.Version)
	}
	return c
}

func (d Deps) checkClock(ctx context.Context) Check {
	c := Check{ID: "database.clock", Name: "Clock"}
	var dbNow time.Time
	before := time.Now()
	err := d.readOnly(ctx, func(q Querier) error {
		before = time.Now()
		return q.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow)
	})
	after := time.Now()
	if err != nil {
		c.Status, c.Summary, c.Detail = StatusInfo, "The database server's time could not be read.", err.Error()
		return c
	}
	// The database's clock was read somewhere between before and after.
	local := before.Add(after.Sub(before) / 2)
	skew := dbNow.Sub(local)
	abs := time.Duration(math.Abs(float64(skew)))
	fix := "Synchronize both hosts with NTP (chrony or systemd-timesyncd); signed sensor jobs, one-time codes and token expiry all depend on the clock."
	seconds := abs.Seconds()
	switch {
	case abs >= clockFail:
		c.Status, c.Summary, c.Fix = StatusFail, fmt.Sprintf("This host's clock and the database server's clock differ by %.0f seconds.", seconds), fix
	case abs >= clockWarn:
		c.Status, c.Summary, c.Fix = StatusWarn, fmt.Sprintf("This host's clock and the database server's clock differ by %.0f seconds.", seconds), fix
	default:
		c.Status, c.Summary = StatusPass, fmt.Sprintf("This host's clock and the database server's clock agree (within %.1f seconds).", math.Max(seconds, 0.1))
	}
	return c
}

func (d Deps) checkRedis(ctx context.Context) Check {
	c := Check{ID: "redis.reachable", Name: "Redis"}
	fix := "Check that Redis runs and that REDIS_HOST, REDIS_PORT, REDIS_PASSWORD and the REDIS_TLS settings match it."
	switch {
	case d.PingRedis == nil && d.Config == nil:
		c.Status, c.Summary = StatusInfo, "Not checked: the configuration did not load."
	case d.PingRedis == nil:
		c.Status, c.Summary, c.Fix = StatusFail, "The Redis connection could not be opened.", fix
		if d.RedisErr != nil {
			c.Detail = d.RedisErr.Error()
		}
	default:
		start := time.Now()
		pctx, cancel := context.WithTimeout(ctx, d.statementTimeout())
		defer cancel()
		if err := d.PingRedis(pctx); err != nil {
			c.Status, c.Summary, c.Fix, c.Detail = StatusFail, "Redis does not answer.", fix, err.Error()
			return c
		}
		c.Status, c.Summary = StatusPass, fmt.Sprintf("Redis answered in %d ms.", time.Since(start).Milliseconds())
	}
	return c
}

func levelStatus(level int) Status {
	switch level {
	case systemstatus.LevelCritical:
		return StatusFail
	case systemstatus.LevelWarning:
		return StatusWarn
	}
	return StatusPass
}

func worse(a, b Status) Status {
	rank := map[Status]int{StatusInfo: 0, StatusPass: 1, StatusWarn: 2, StatusFail: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func days(seconds int64) int64 { return seconds / 86400 }

// checkCertificates reports the certificate files the operator configured
// (and the sensor CA) and, unless the probe is off, the certificate the
// public URL serves.
func (d Deps) checkCertificates(ctx context.Context, snap *systemstatus.Snapshot) []Check {
	files := Check{ID: "tls.certificate_files", Name: "Certificate files"}
	fix := "Renew the certificate before it expires and restart the service that serves it; add other certificate files to SYSTEM_TLS_CERT_FILES (name=path) so they are checked too."
	switch {
	case snap == nil || len(snap.Certificates) == 0:
		files.Status, files.Summary = StatusInfo, "No certificate file is configured for checking (SYSTEM_TLS_CERT_FILES, the sensor CA)."
	default:
		status := StatusPass
		var soonest int64 = math.MaxInt64
		unreadable := 0
		for _, cert := range snap.Certificates {
			if !cert.OK {
				unreadable++
				status = worse(status, StatusWarn)
				continue
			}
			status = worse(status, levelStatus(cert.Level))
			soonest = min(soonest, cert.ExpiresInSecs)
		}
		files.Status = status
		switch {
		case unreadable == len(snap.Certificates):
			files.Summary = fmt.Sprintf("None of the %d configured certificate files could be read.", unreadable)
			files.Fix = "Check the paths in SYSTEM_TLS_CERT_FILES and that the files are mounted into the server's container."
		case soonest < 0:
			files.Summary = fmt.Sprintf("A certificate expired %d days ago (%d files checked, %d unreadable).", days(-soonest), len(snap.Certificates), unreadable)
			files.Fix = fix
		default:
			files.Summary = fmt.Sprintf("%d certificate files checked, %d unreadable; the first to expire has %d days left.", len(snap.Certificates), unreadable, days(soonest))
			if status != StatusPass {
				files.Fix = fix
			}
		}
	}

	pub := Check{ID: "tls.public_url", Name: "Public certificate"}
	hostPort := d.publicHostPort()
	switch {
	case d.CertExpiry == nil:
		pub.Status, pub.Summary = StatusInfo, "Not checked (--offline)."
	case hostPort == "":
		pub.Status, pub.Summary = StatusInfo, "Not checked: APP_URL is not an https origin."
	default:
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		notAfter, err := d.CertExpiry(pctx, hostPort)
		if err != nil {
			pub.Status = StatusInfo
			pub.Summary = "The public URL could not be reached from here, so its certificate was not checked (normal when the server cannot reach its own public address)."
			pub.Detail = err.Error()
			break
		}
		left := notAfter.Sub(d.now())
		switch {
		case left <= 0:
			pub.Status, pub.Summary = StatusFail, "The certificate the public URL serves has expired."
		case left < publicCertFail:
			pub.Status, pub.Summary = StatusFail, fmt.Sprintf("The certificate the public URL serves expires in %d days.", int64(left.Hours())/24)
		case left < publicCertWarn:
			pub.Status, pub.Summary = StatusWarn, fmt.Sprintf("The certificate the public URL serves expires in %d days.", int64(left.Hours())/24)
		default:
			pub.Status, pub.Summary = StatusPass, fmt.Sprintf("The certificate the public URL serves is valid for %d more days.", int64(left.Hours())/24)
		}
		if pub.Status != StatusPass {
			pub.Fix = "Renew the certificate at the gateway or the load balancer in front of the platform."
		}
	}
	return []Check{files, pub}
}

// publicHostPort is the host:port of APP_URL when it is an https origin.
func (d Deps) publicHostPort() string {
	if d.Config == nil {
		return ""
	}
	u, err := url.Parse(d.Config.App.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func (d Deps) checkStorage(snap *systemstatus.Snapshot) Check {
	c := Check{ID: "storage.free_space", Name: "Disk space"}
	if snap == nil || len(snap.Storage.Volumes) == 0 {
		c.Status, c.Summary = StatusInfo, "No data path is configured for checking (SYSTEM_STORAGE_PATHS)."
		return c
	}
	status := StatusPass
	lowest := 1.0
	lowestName := ""
	unreadable := 0
	for _, v := range snap.Storage.Volumes {
		if !v.OK {
			unreadable++
			status = worse(status, StatusWarn)
			continue
		}
		status = worse(status, levelStatus(v.Level))
		if v.FreeRatio <= lowest {
			lowest, lowestName = v.FreeRatio, v.Name
		}
	}
	c.Status = status
	if lowestName == "" {
		c.Summary = fmt.Sprintf("None of the %d data paths could be measured.", len(snap.Storage.Volumes))
		c.Fix = "Check the paths in SYSTEM_STORAGE_PATHS."
		return c
	}
	c.Summary = fmt.Sprintf("%d data paths measured, %d unreadable; the fullest (%s) has %.0f%% free.",
		len(snap.Storage.Volumes), unreadable, safeName(lowestName), lowest*100)
	if status != StatusPass {
		c.Fix = "Free or add space on that volume before it fills: below 10% free PostgreSQL and uploads start to fail. Old backups and unused images are the usual cause."
	}
	return c
}

func (d Deps) checkBackup(snap *systemstatus.Snapshot) Check {
	c := Check{ID: "backup.recency", Name: "Backup"}
	fix := "Run the backup job and read its output (Compose: ./backup.sh; the kit and the chart schedule their own), then schedule it daily."
	switch {
	case snap == nil || !snap.Backup.Reported:
		c.Status = StatusInfo
		c.Summary = "This installation records no backup status, so the age of the last backup is unknown."
		c.Fix = "Point SYSTEM_BACKUP_STATUS_FILE at the backup job's status file to have it checked (docs/deployment/backup-and-restore.md)."
	case snap.Backup.LastFailed:
		c.Status, c.Summary, c.Fix = StatusFail, fmt.Sprintf("The last backup run failed; the last successful backup is %d hours old.", snap.Backup.AgeSeconds/3600), fix
	case snap.Backup.Level != systemstatus.LevelOK:
		c.Status, c.Summary, c.Fix = levelStatus(snap.Backup.Level), fmt.Sprintf("The last successful backup is %d hours old.", snap.Backup.AgeSeconds/3600), fix
	default:
		c.Status, c.Summary = StatusPass, fmt.Sprintf("The last successful backup is %d hours old.", snap.Backup.AgeSeconds/3600)
	}
	return c
}

// checkServices reports the web and gateway probes when they are configured.
func (d Deps) checkServices(snap *systemstatus.Snapshot) []Check {
	if snap == nil {
		return nil
	}
	var out []Check
	for _, s := range snap.Services {
		if (s.Name != "web" && s.Name != "gateway") || !s.Configured {
			continue
		}
		c := Check{ID: "service." + s.Name, Name: "Service " + s.Name, Status: StatusPass,
			Summary: fmt.Sprintf("The %s answered its health probe in %.0f ms.", s.Name, s.LatencyMS)}
		if !s.OK {
			c.Status = StatusWarn
			c.Summary = fmt.Sprintf("The %s did not answer its health probe (%s).", s.Name, s.Code)
			c.Fix = fmt.Sprintf("Check that the %s container runs and read its log.", s.Name)
		}
		out = append(out, c)
	}
	return out
}

func (d Deps) checkQueue(ctx context.Context) []Check {
	var ops postgres.OpsSnapshot
	err := d.readOnly(ctx, func(q Querier) error {
		var err error
		ops, err = postgres.ReadOpsSnapshot(ctx, q)
		return err
	})
	backlog := Check{ID: "queue.backlog", Name: "Job queue"}
	stuck := Check{ID: "queue.stuck", Name: "Stuck jobs"}
	if err != nil {
		backlog.Status, backlog.Summary, backlog.Detail = StatusInfo, "The queue could not be read.", err.Error()
		return []Check{backlog}
	}
	oldest := time.Duration(ops.CommandOldestPendingSecs) * time.Second
	backlog.Status = StatusPass
	backlog.Summary = fmt.Sprintf("%d commands wait for a sensor and %d run; the oldest has waited %d minutes. %d notifications wait to be sent.",
		ops.CommandsPending, ops.CommandsRunning, int64(oldest.Minutes()), ops.OutboxPending)
	if oldest >= queueOldestWarn {
		backlog.Status = StatusWarn
		backlog.Fix = "No sensor is taking this work: check that a sensor able to run it is online (Sensors page) and not at its job limit."
	}
	if time.Duration(ops.OutboxOldestPendingSec)*time.Second >= outboxOldestWarn {
		backlog.Status = StatusWarn
		backlog.Fix = strings.TrimSpace(backlog.Fix + " Notifications are not being sent: read the server log for the notification worker's errors.")
	}

	stuck.Status = StatusPass
	stuck.Summary = fmt.Sprintf("%d scan runs are open; %d are past their deadline. %d notifications failed for good.",
		ops.ScanRunsOpen, ops.ScanRunsPastDeadline, ops.OutboxDead)
	var fixes []string
	if ops.ScanRunsPastDeadline > 0 {
		stuck.Status = StatusWarn
		fixes = append(fixes, "Runs past their deadline mean the server's background controllers are not running: read the server log from its last start and restart the server.")
	}
	if ops.OutboxDead > 0 {
		stuck.Status = StatusWarn
		fixes = append(fixes, "Check the notification integrations that fail (Settings, Integrations) and re-test them.")
	}
	stuck.Fix = strings.Join(fixes, " ")
	return []Check{backlog, stuck}
}

// checkSensors reports the sensors by heartbeat state and by version, as
// counts only.
func (d Deps) checkSensors(ctx context.Context) []Check {
	hb := Check{ID: "sensors.heartbeat", Name: "Sensor heartbeats"}
	ver := Check{ID: "sensors.versions", Name: "Sensor versions"}
	health := map[string]int64{}
	versions := map[string]int64{}
	err := d.readOnly(ctx, func(q Querier) error {
		rows, err := q.QueryContext(ctx, `
			SELECT COALESCE(health, 'unknown'), COALESCE(version, ''), count(*)
			FROM sensors WHERE status = 'active' GROUP BY 1, 2`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var h, v string
			var n int64
			if err := rows.Scan(&h, &v, &n); err != nil {
				return err
			}
			health[h] += n
			versions[v] += n
		}
		return rows.Err()
	})
	if err != nil {
		hb.Status, hb.Summary, hb.Detail = StatusInfo, "The sensors could not be read.", err.Error()
		return []Check{hb}
	}
	var total int64
	for _, n := range health {
		total += n
	}
	if total == 0 {
		hb.Status, hb.Summary = StatusInfo, "No active sensor is registered."
		return []Check{hb}
	}
	parts := make([]string, 0, len(health))
	for _, h := range []string{"online", "late", "stale", "offline", "error", "unknown"} {
		if n := health[h]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, h))
		}
	}
	hb.Status = StatusPass
	hb.Summary = fmt.Sprintf("%d active sensors: %s.", total, strings.Join(parts, ", "))
	if health["online"] == 0 {
		hb.Status = StatusWarn
		hb.Fix = "No sensor is online, so no scan can run: check the sensors' hosts and their logs, and that they reach the platform's sensor address."
	}

	counts := map[sensor.VersionStatus]int64{}
	for v, n := range versions {
		counts[sensor.ClassifyVersion(v, d.SensorLatest, d.SensorMin)] += n
	}
	ver.Status = StatusPass
	rule := "this build documents no minimum sensor version"
	if d.SensorMin != "" {
		rule = "this build supports sensors from " + safeName(d.SensorMin)
	}
	ver.Summary = fmt.Sprintf("%d on the latest release, %d behind it, %d older than supported, %d of unknown version (%s; latest %s).",
		counts[sensor.VersionLatest], counts[sensor.VersionUpdateAvailable], counts[sensor.VersionUnsupported], counts[sensor.VersionUnknown],
		rule, safeName(d.SensorLatest))
	if counts[sensor.VersionUnsupported] > 0 {
		ver.Status = StatusWarn
		ver.Fix = "Upgrade the sensors older than the supported minimum (Sensors page, filter by version): the platform no longer tests against them."
	}
	return []Check{hb, ver}
}

// checkAuditChain counts the entries of the organizations' audit chains
// whose link to the entry before them does not hold. It reports the count
// and does not judge it: explaining a break is the job of the chain tools
// (docs/architecture/audit-hash-chain.md).
func (d Deps) checkAuditChain(ctx context.Context) Check {
	c := Check{ID: "audit.chain", Name: "Audit chain", Status: StatusInfo}
	var entries, chains, breaks, rebaselines int64
	err := d.readOnly(ctx, func(q Querier) error {
		if err := q.QueryRowContext(ctx, `
			SELECT count(*), count(DISTINCT tenant_id), count(*) FILTER (WHERE before IS NOT NULL AND prev_hash <> before)
			FROM (SELECT tenant_id, prev_hash,
			             lag(hash) OVER (PARTITION BY tenant_id ORDER BY chain_position) AS before
			      FROM audit_log_chain) c`).Scan(&entries, &chains, &breaks); err != nil {
			return err
		}
		return q.QueryRowContext(ctx, `SELECT count(*) FROM audit_chain_rebaselines`).Scan(&rebaselines)
	})
	if err != nil {
		c.Summary = "The audit chain's links were not checked here (the read failed or took longer than the time limit); the server verifies every chain hourly."
		c.Detail = err.Error()
		return c
	}
	c.Summary = fmt.Sprintf("%d entries in %d chains; %d known link breaks; %d rebaselines on record. This is the link check only: the server verifies entry contents hourly.",
		entries, chains, breaks, rebaselines)
	if breaks > 0 {
		c.Fix = "Explain each break with the chain tools before anything else is done to the chain (docs/architecture/audit-hash-chain.md)."
	}
	return c
}

// safeName keeps a short configured name or version made of plain
// characters; anything else is reported as "(name withheld)".
func safeName(s string) string {
	if s == "" {
		return "none"
	}
	if len(s) > 40 {
		return "(name withheld)"
	}
	for _, r := range s {
		ok := r == '-' || r == '_' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return "(name withheld)"
		}
	}
	return s
}
