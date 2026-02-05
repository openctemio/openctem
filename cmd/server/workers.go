package main

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/internal/infra/jobs"
	"github.com/openctemio/api/pkg/logger"
)

// Workers holds all background worker instances.
type Workers struct {
	JobWorker                 *jobs.Worker
	AgentHealthChecker        *jobs.AgentHealthChecker
	AITriageRecoveryJob       *jobs.AITriageRecoveryJob
	ScanScheduler             *app.ScanScheduler
	CommandExpirationChecker  *app.CommandExpirationChecker
	NotificationScheduler     *app.NotificationScheduler
	FindingLifecycleScheduler *app.FindingLifecycleScheduler
	ControllerManager         *controller.Manager
}

// WorkerDeps contains dependencies needed to create workers.
type WorkerDeps struct {
	Config   *config.Config
	Log      *logger.Logger
	Repos    *Repositories
	Services *Services
}

// NewWorkers initializes all background workers.
func NewWorkers(deps *WorkerDeps) (*Workers, error) {
	cfg := deps.Config
	log := deps.Log
	repos := deps.Repos
	svc := deps.Services

	w := &Workers{}

	// Initialize job worker if email service is configured
	if svc.Email != nil {
		var err error
		w.JobWorker, err = NewJobWorker(cfg, svc.Email, svc.AITriage, log)
		if err != nil {
			return nil, err
		}
	}

	// Initialize agent health checker if worker is enabled
	if cfg.Worker.Enabled {
		w.AgentHealthChecker = jobs.NewAgentHealthChecker(repos.Agent, &cfg.Worker, log)
		log.Info("agent health checker initialized",
			"heartbeat_timeout", cfg.Worker.HeartbeatTimeout,
			"check_interval", cfg.Worker.HealthCheckInterval,
		)
	}

	// Initialize AI triage recovery job if AI triage service is available
	if svc.AITriage != nil && cfg.AITriage.RecoveryEnabled {
		w.AITriageRecoveryJob = jobs.NewAITriageRecoveryJob(svc.AITriage, &cfg.AITriage, log)
		log.Info("AI triage recovery job initialized",
			"interval", cfg.AITriage.RecoveryInterval,
			"stuck_duration", cfg.AITriage.RecoveryStuckDuration,
			"batch_size", cfg.AITriage.RecoveryBatchSize,
		)
	}

	// Initialize scan scheduler
	w.ScanScheduler = app.NewScanScheduler(
		repos.Scan,
		svc.Scan,
		app.ScanSchedulerConfig{
			CheckInterval: time.Minute,
			BatchSize:     50,
		},
		log,
	)

	// Initialize command expiration checker
	w.CommandExpirationChecker = app.NewCommandExpirationChecker(
		repos.Command,
		svc.Pipeline,
		app.CommandExpirationCheckerConfig{
			CheckInterval: time.Minute,
		},
		log,
	)

	// Initialize notification scheduler
	w.NotificationScheduler = app.NewNotificationScheduler(
		svc.Notification,
		app.DefaultNotificationSchedulerConfig(),
		log,
	)

	// Initialize finding lifecycle scheduler
	// Handles feature branch finding expiry
	w.FindingLifecycleScheduler = app.NewFindingLifecycleScheduler(
		repos.Finding,
		repos.Tenant,
		app.DefaultFindingLifecycleSchedulerConfig(),
		log,
	)

	// Note: Template sync uses lazy sync on scan trigger, no background worker needed.
	// Templates are synced on-demand when a scan uses custom templates.

	// Initialize controller manager for background tasks
	w.ControllerManager = controller.NewManager(&controller.ManagerConfig{
		Logger: log.With("component", "controller-manager"),
	})

	// Register controllers
	w.ControllerManager.Register(controller.NewAgentHealthController(
		repos.Agent,
		&controller.AgentHealthControllerConfig{
			Interval:     30 * time.Second,
			StaleTimeout: 90 * time.Second,
			Logger:       log.With("controller", "agent-health"),
		},
	))

	w.ControllerManager.Register(controller.NewJobRecoveryController(
		repos.Command,
		&controller.JobRecoveryControllerConfig{
			Interval:              60 * time.Second,
			StuckThresholdMinutes: 30,
			MaxRetries:            3,
			MaxQueueMinutes:       60,
			Logger:                log.With("controller", "job-recovery"),
		},
	))

	return w, nil
}

// Start starts all background workers.
func (w *Workers) Start(ctx context.Context, log *logger.Logger) error {
	// Start job worker
	if w.JobWorker != nil {
		go func() {
			log.Info("starting job worker")
			if err := w.JobWorker.Start(); err != nil {
				log.Error("job worker error", "error", err)
			}
		}()
	}

	// Start agent health checker
	if w.AgentHealthChecker != nil {
		w.AgentHealthChecker.Start()
	}

	// Start AI triage recovery job
	if w.AITriageRecoveryJob != nil {
		w.AITriageRecoveryJob.Start()
	}

	// Start scan scheduler
	w.ScanScheduler.Start()

	// Start command expiration checker
	w.CommandExpirationChecker.Start()

	// Start notification scheduler
	w.NotificationScheduler.Start()

	// Start finding lifecycle scheduler
	w.FindingLifecycleScheduler.Start()

	// Start controller manager
	if err := w.ControllerManager.Start(ctx); err != nil {
		return err
	}
	log.Info("controller manager started", "controllers", w.ControllerManager.ControllerNames())

	return nil
}

// Stop stops all background workers gracefully.
func (w *Workers) Stop(log *logger.Logger) {
	// Stop job worker first
	if w.JobWorker != nil {
		log.Info("stopping job worker...")
		w.JobWorker.Shutdown()
		log.Info("job worker stopped")
	}

	// Stop agent health checker
	if w.AgentHealthChecker != nil {
		w.AgentHealthChecker.Stop()
	}

	// Stop AI triage recovery job
	if w.AITriageRecoveryJob != nil {
		w.AITriageRecoveryJob.Stop()
	}

	// Stop scan scheduler
	log.Info("stopping scan scheduler...")
	w.ScanScheduler.Stop()
	log.Info("scan scheduler stopped")

	// Stop command expiration checker
	log.Info("stopping command expiration checker...")
	w.CommandExpirationChecker.Stop()
	log.Info("command expiration checker stopped")

	// Stop notification scheduler
	log.Info("stopping notification scheduler...")
	w.NotificationScheduler.Stop()
	log.Info("notification scheduler stopped")

	// Stop finding lifecycle scheduler
	log.Info("stopping finding lifecycle scheduler...")
	w.FindingLifecycleScheduler.Stop()
	log.Info("finding lifecycle scheduler stopped")

	// Stop controller manager
	log.Info("stopping controller manager...")
	if err := w.ControllerManager.Stop(); err != nil {
		log.Error("controller manager stop error", "error", err)
	}
	log.Info("controller manager stopped")
}
