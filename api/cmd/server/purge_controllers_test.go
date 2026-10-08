package main

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

var purgeControllerNames = []string{"invitation-purge", "admin-session-purge", "sensor-result-quarantine-purge"}

// TestNewWorkers_RegistersPurgeControllers: CleanupExpiredInvitations,
// the admin-session delete and the quarantine PurgeReviewed existed with no
// caller, so expired invitations (email + token hash), dead admin sessions
// (IP, user agent) and reviewed quarantined payloads stayed forever.
func TestNewWorkers_RegistersPurgeControllers(t *testing.T) {
	cfg := &config.Config{}
	cfg.Redis.Host = "127.0.0.1"
	cfg.Redis.Port = 6379

	w, err := NewWorkers(&WorkerDeps{
		Config: cfg,
		Log:    logger.NewNop(),
		Repos: &Repositories{
			AdminConsole: postgres.NewAdminConsoleRepository(nil),
			SensorResult: postgres.NewSensorResultRepository(nil),
		},
		Services: &Services{Tenant: tenant.NewTenantService(nil, logger.NewNop())},
	})
	if err != nil {
		t.Fatalf("NewWorkers: %v", err)
	}
	defer w.JobWorker.Stop()

	names := w.ControllerManager.ControllerNames()
	for _, want := range purgeControllerNames {
		if !slices.Contains(names, want) {
			t.Errorf("controller %q is not registered", want)
		}
	}
}

// TestPurgeControllers_DeleteOnlyWhatExpired runs the registered purges once
// (the manager reconciles every controller on start) against a scratch
// database: each deletes its expired rows and keeps the live ones.
//
// DB-gated: needs DATABASE_URL pointing at a migrated *_test database.
func TestPurgeControllers_DeleteOnlyWhatExpired(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()
	if err := sqlDB.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()
	db := &postgres.DB{DB: sqlDB}

	tenantID, userID, adminID := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Purge test', $2)`, tenantID, "purge-"+tenantID[24:])
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Purge test')`, userID, "purge-"+userID[24:]+"@example.com")
	exec(`INSERT INTO admin_users (id, email, name) VALUES ($1, $2, 'Purge test')`, adminID, "purge-admin-"+adminID[24:]+"@example.com")
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, adminID)
		_, _ = sqlDB.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		_, _ = sqlDB.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})

	invExpired, invLive, invAccepted := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	invite := func(id, expires string, accepted bool) {
		acceptedAt := "NULL"
		if accepted {
			acceptedAt = "now() - interval '9 days'"
		}
		exec(`INSERT INTO tenant_invitations (id, tenant_id, email, token, invited_by, expires_at, accepted_at)
			VALUES ($1, $2, $3, $4, $5, `+expires+`, `+acceptedAt+`)`,
			id, tenantID, "inv-"+id[24:]+"@example.com", "hash-"+id, userID)
	}
	invite(invExpired, "now() - interval '1 day'", false)
	invite(invLive, "now() + interval '6 days'", false)
	invite(invAccepted, "now() - interval '1 day'", true)

	sessExpired, sessLive := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO admin_sessions (id, admin_id, token_hash, expires_at) VALUES ($1, $3, $4, now() - interval '1 minute'),
		($2, $3, $5, now() + interval '1 hour')`, sessExpired, sessLive, adminID, "h-"+sessExpired, "h-"+sessLive)

	qOld, qRecent, qPending := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	quarantine := func(id, status, reviewedAt string) {
		exec(`INSERT INTO sensor_result_quarantine (id, tenant_id, sensor_id, protocol, route, reason, status, reviewed_at)
			VALUES ($1, $2, $3, 'v2', 'results', 'test', $4, `+reviewedAt+`)`, id, tenantID, shared.NewID().String(), status)
	}
	quarantine(qOld, "discarded", "now() - interval '31 days'")
	quarantine(qRecent, "accepted", "now() - interval '1 day'")
	quarantine(qPending, "pending", "NULL")

	cfg := &config.Config{}
	cfg.Worker.QuarantineRetention = 30 * 24 * time.Hour
	m := controller.NewManager(&controller.ManagerConfig{Logger: logger.NewNop()})
	registerPurgeControllers(m, cfg, &Repositories{
		AdminConsole: postgres.NewAdminConsoleRepository(db),
		SensorResult: postgres.NewSensorResultRepository(db),
	}, &Services{Tenant: tenant.NewTenantService(postgres.NewTenantRepository(db), logger.NewNop())}, logger.NewNop())
	if got := m.ControllerNames(); !slices.Equal(got, purgeControllerNames) {
		t.Fatalf("registered %v, want %v", got, purgeControllerNames)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	_ = m.Stop() // each controller reconciles once on start before it sees the stop

	exists := func(table, id string) bool {
		var n int
		if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n == 1
	}
	for _, c := range []struct {
		table, id, what string
		kept            bool
	}{
		{"tenant_invitations", invExpired, "expired pending invitation", false},
		{"tenant_invitations", invLive, "unexpired invitation", true},
		{"tenant_invitations", invAccepted, "accepted invitation", true},
		{"admin_sessions", sessExpired, "expired admin session", false},
		{"admin_sessions", sessLive, "live admin session", true},
		{"sensor_result_quarantine", qOld, "result reviewed 31 days ago", false},
		{"sensor_result_quarantine", qRecent, "result reviewed yesterday", true},
		{"sensor_result_quarantine", qPending, "pending result", true},
	} {
		if got := exists(c.table, c.id); got != c.kept {
			t.Errorf("%s: kept=%v, want kept=%v", c.what, got, c.kept)
		}
	}
}
