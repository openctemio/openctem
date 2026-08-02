package main

import (
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
