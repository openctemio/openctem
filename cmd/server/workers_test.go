package main

import (
	"slices"
	"time"

	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// TestNewJobWorker_BuiltWithoutEmailService pins the fix for the defect where a
// default deployment ran no asynq worker at all.
//
// SMTP_ENABLED defaults to false, so config.SMTPConfig.IsConfigured() is false,
// so Services.InitEmailServices leaves Services.Email nil. NewJobWorker used to
// return (nil, nil) on a nil email service and NewWorkers only called it when
// Email was non-nil — so the whole asynq server was absent. AI-triage, Jira
// status-sync and GitHub status-sync tasks are enqueued regardless of SMTP and
// were left in Redis with no consumer.
//
// The worker must therefore be constructed even with no email service; only the
// email handlers are conditional.
func TestNewJobWorker_BuiltWithoutEmailService(t *testing.T) {
	cfg := &config.Config{}
	cfg.Redis.Host = "127.0.0.1"
	cfg.Redis.Port = 6379

	worker, err := NewJobWorker(cfg, nil /*email*/, nil /*aiTriage*/, nil /*jira*/, nil /*github*/, logger.NewNop())
	if err != nil {
		t.Fatalf("NewJobWorker returned error with nil email service: %v", err)
	}
	if worker == nil {
		t.Fatal("NewJobWorker returned a nil worker when the email service is nil: " +
			"the asynq server would never start, so AI-triage / Jira-sync / GitHub-sync " +
			"tasks would be enqueued with nothing consuming them")
	}
	worker.Stop()
}

// TestNewWorkers_JobWorkerStartedWithoutEmail is the composition-root half of the
// same defect: even with a correct NewJobWorker, NewWorkers used to skip the call
// entirely when Services.Email was nil.
func TestNewWorkers_JobWorkerStartedWithoutEmail(t *testing.T) {
	cfg := &config.Config{}
	cfg.Redis.Host = "127.0.0.1"
	cfg.Redis.Port = 6379

	w, err := NewWorkers(&WorkerDeps{
		Config:   cfg,
		Log:      logger.NewNop(),
		Repos:    &Repositories{},
		Services: &Services{}, // Email is nil, as with SMTP_ENABLED=false
	})
	if err != nil {
		t.Fatalf("NewWorkers: %v", err)
	}
	if w.JobWorker == nil {
		t.Fatal("Workers.JobWorker is nil when Services.Email is nil: " +
			"no asynq consumer runs in a default (SMTP-disabled) deployment")
	}
	w.JobWorker.Stop()

	// Same construction, second time: controller.NewPrometheusMetrics uses
	// promauto and would panic on re-registration if it were not memoised.
	w2, err := NewWorkers(&WorkerDeps{
		Config:   cfg,
		Log:      logger.NewNop(),
		Repos:    &Repositories{},
		Services: &Services{},
	})
	if err != nil {
		t.Fatalf("NewWorkers (second call): %v", err)
	}
	w2.JobWorker.Stop()
}

// TestControllerManager_IsObserved proves the controller manager built by the
// composition root actually has a metrics collector attached, and that the
// collector lands on the registry /metrics serves.
//
// controller.NewPrometheusMetrics had zero call sites, so ManagerConfig.Metrics
// was nil. Manager guards every metrics call with `if m.metrics != nil`, so all
// ~28 background controllers ran unobserved: a reaper erroring on every tick
// exported exactly the same (nothing) as a healthy idle one.
//
// The probe is behavioral: Manager.Register publishes
// openctem_controller_running{controller=...} 0, so after building Workers the
// series must be present on the default gatherer for the controllers that were
// registered.
func TestControllerManager_IsObserved(t *testing.T) {
	cfg := &config.Config{}
	cfg.Redis.Host = "127.0.0.1"
	cfg.Redis.Port = 6379

	w, err := NewWorkers(&WorkerDeps{
		Config:   cfg,
		Log:      logger.NewNop(),
		Repos:    &Repositories{},
		Services: &Services{},
	})
	if err != nil {
		t.Fatalf("NewWorkers: %v", err)
	}
	defer w.JobWorker.Stop()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	observed := map[string]bool{}
	for _, f := range families {
		if f.GetName() != "openctem_controller_running" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "controller" {
					observed[l.GetValue()] = true
				}
			}
		}
	}

	if len(observed) == 0 {
		t.Fatal("no openctem_controller_running samples after building Workers: " +
			"the controller manager has no Metrics collector, so every background " +
			"controller runs unobserved and /metrics exports nothing about them")
	}
	for _, name := range w.ControllerManager.ControllerNames() {
		if !observed[name] {
			t.Errorf("controller %q registered but not observed by Prometheus", name)
		}
	}
}

// TestAdminAuditRetention_DryRunIsConfigurable pins that the admin-audit
// retention controller's destructive switch is an operator setting.
//
// It used to be a literal `DryRun: true` in NewWorkers with no config plumbing
// at all, so admin_audit_logs grew forever and the documented 365-day
// retention policy could never be enforced by any deployment. The default is
// still dry-run — deleting audit history on upgrade would be a compliance
// incident — but ADMIN_AUDIT_RETENTION_DRY_RUN=false must now reach the
// controller.
func TestAdminAuditRetention_DryRunIsConfigurable(t *testing.T) {
	cfg := &config.Config{}
	cfg.AdminAuditRetention = config.AdminAuditRetentionConfig{
		Enabled:       true,
		DryRun:        false, // operator opted in to real deletion
		RetentionDays: 400,
		Interval:      12 * time.Hour,
		BatchSize:     250,
	}

	got := adminAuditRetentionConfig(cfg, logger.NewNop())

	if got.DryRun {
		t.Error("ADMIN_AUDIT_RETENTION_DRY_RUN=false did not reach the controller: " +
			"retention is permanently a dry run and admin_audit_logs grows forever")
	}
	if got.RetentionDays != 400 {
		t.Errorf("RetentionDays = %d, want 400 (ADMIN_AUDIT_RETENTION_DAYS ignored)", got.RetentionDays)
	}
	if got.Interval != 12*time.Hour {
		t.Errorf("Interval = %s, want 12h (ADMIN_AUDIT_RETENTION_INTERVAL ignored)", got.Interval)
	}
	if got.BatchSize != 250 {
		t.Errorf("BatchSize = %d, want 250 (ADMIN_AUDIT_RETENTION_BATCH_SIZE ignored)", got.BatchSize)
	}
}

// TestAdminAuditRetention_DefaultIsDryRun pins the chosen default: a
// deployment that sets nothing keeps reporting rather than deleting, so an
// upgrade never silently destroys audit history.
func TestAdminAuditRetention_DefaultIsDryRun(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if !cfg.AdminAuditRetention.Enabled {
		t.Error("admin audit retention is disabled by default; nothing would report growth")
	}
	if !cfg.AdminAuditRetention.DryRun {
		t.Error("admin audit retention deletes by default; an upgrade would start " +
			"destroying audit history without the operator asking for it")
	}
	if cfg.AdminAuditRetention.RetentionDays != 365 {
		t.Errorf("default retention = %d days, want 365", cfg.AdminAuditRetention.RetentionDays)
	}
}

// TestAdminAuditRetention_RegistrationFollowsConfig proves the switch is
// observable in the composition root, not just in a helper.
func TestAdminAuditRetention_RegistrationFollowsConfig(t *testing.T) {
	const name = "audit-retention"

	build := func(t *testing.T, enabled bool) []string {
		t.Helper()
		cfg := &config.Config{}
		cfg.Redis.Host = "127.0.0.1"
		cfg.Redis.Port = 6379
		cfg.AdminAuditRetention = config.AdminAuditRetentionConfig{
			Enabled:       enabled,
			DryRun:        true,
			RetentionDays: 365,
			Interval:      24 * time.Hour,
			BatchSize:     10000,
		}

		w, err := NewWorkers(&WorkerDeps{
			Config:   cfg,
			Log:      logger.NewNop(),
			Repos:    &Repositories{},
			Services: &Services{},
		})
		if err != nil {
			t.Fatalf("NewWorkers: %v", err)
		}
		defer w.JobWorker.Stop()
		return w.ControllerManager.ControllerNames()
	}

	if !slices.Contains(build(t, true), name) {
		t.Errorf("ADMIN_AUDIT_RETENTION_ENABLED=true but %q was not registered", name)
	}
	if slices.Contains(build(t, false), name) {
		t.Errorf("ADMIN_AUDIT_RETENTION_ENABLED=false but %q was still registered", name)
	}
}

// TestConfig_RejectsDestructiveRetentionWindow pins the guard on the
// irreversible path: enabling real deletion with a tiny (or zero, or negative)
// retention window would move the cutoff to now-or-later and wipe the table.
// The server must refuse to boot instead.
func TestConfig_RejectsDestructiveRetentionWindow(t *testing.T) {
	base := config.AdminAuditRetentionConfig{
		Enabled:       true,
		DryRun:        false,
		RetentionDays: 365,
		Interval:      24 * time.Hour,
		BatchSize:     10000,
	}

	newCfg := func(mut func(*config.AdminAuditRetentionConfig)) *config.Config {
		c := &config.Config{}
		c.App.Env = "development"
		c.Server.Port = 8080
		c.Database.Host = "localhost"
		// "oidc" keeps validateAuth off the local-auth branch, so this test
		// only exercises the retention guard.
		c.Auth.Provider = "oidc"
		c.AdminAuditRetention = base
		mut(&c.AdminAuditRetention)
		return c
	}

	if err := newCfg(func(*config.AdminAuditRetentionConfig) {}).Validate(); err != nil {
		t.Fatalf("a 365-day deleting config must validate, got: %v", err)
	}

	for _, tc := range []struct {
		name string
		mut  func(*config.AdminAuditRetentionConfig)
	}{
		{"zero days", func(r *config.AdminAuditRetentionConfig) { r.RetentionDays = 0 }},
		{"negative days", func(r *config.AdminAuditRetentionConfig) { r.RetentionDays = -30 }},
		{"one day", func(r *config.AdminAuditRetentionConfig) { r.RetentionDays = 1 }},
		{"zero interval", func(r *config.AdminAuditRetentionConfig) { r.Interval = 0 }},
		{"zero batch", func(r *config.AdminAuditRetentionConfig) { r.BatchSize = 0 }},
	} {
		if err := newCfg(tc.mut).Validate(); err == nil {
			t.Errorf("%s: config validated, so the server would boot and delete audit logs", tc.name)
		}
	}

	// The same values are harmless while dry-run: nothing is deleted, so they
	// must not block boot.
	dry := newCfg(func(r *config.AdminAuditRetentionConfig) {
		r.DryRun = true
		r.RetentionDays = 0
	})
	if err := dry.Validate(); err != nil {
		t.Errorf("dry-run config must not fail validation, got: %v", err)
	}
}
