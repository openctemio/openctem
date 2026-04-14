package main

import (
	"context"
	"database/sql"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/internal/infra/jobs"
	"github.com/openctemio/api/pkg/logger"
)

// Workers holds all background worker instances.
type Workers struct {
	JobWorker                    *jobs.Worker
	AgentHealthChecker           *jobs.AgentHealthChecker
	AITriageRecoveryJob          *jobs.AITriageRecoveryJob
	ScanScheduler                *app.ScanScheduler
	CommandExpirationChecker     *app.CommandExpirationChecker
	OutboxScheduler              *app.OutboxScheduler
	FindingLifecycleScheduler    *app.FindingLifecycleScheduler
	NotificationCleanupTicker    *time.Ticker
	notificationService          *app.NotificationService
	// SessionCleanupTicker periodically deletes expired/revoked
	// sessions and refresh tokens. Without this the tables grow
	// unboundedly because logout marks rows as 'revoked' (not deleted)
	// and refresh-token rotation marks old rows as 'used' (not deleted).
	// SessionService.CleanupExpiredSessions() exists in the codebase
	// but was never wired into a worker until this hookup.
	SessionCleanupTicker *time.Ticker
	sessionService       *app.SessionService
	ControllerManager    *controller.Manager
}

// WorkerDeps contains dependencies needed to create workers.
type WorkerDeps struct {
	Config   *config.Config
	Log      *logger.Logger
	DB       *sql.DB
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
	w.OutboxScheduler = app.NewOutboxScheduler(
		svc.Outbox,
		app.DefaultOutboxSchedulerConfig(),
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

	// Store notification service reference for cleanup worker
	w.notificationService = svc.Notification

	// Store session service reference for the session cleanup worker.
	// Started in Workers.Start() — see comment on SessionCleanupTicker.
	w.sessionService = svc.Session

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

	// Scan timeout controller: enforces per-scan timeout_seconds on running pipeline_runs
	w.ControllerManager.Register(controller.NewScanTimeoutController(
		repos.PipelineRun,
		&controller.ScanTimeoutControllerConfig{
			Interval: 60 * time.Second,
			Logger:   log.With("controller", "scan-timeout"),
		},
	))

	// Scan retry controller: dispatches automatic retries for failed scans
	// with retry budget remaining (uses exponential backoff)
	w.ControllerManager.Register(controller.NewScanRetryController(
		repos.PipelineRun,
		svc.Scan, // scan service implements RetryDispatcher
		&controller.ScanRetryControllerConfig{
			Interval:  60 * time.Second,
			BatchSize: 100,
			Logger:    log.With("controller", "scan-retry"),
		},
	))

	w.ControllerManager.Register(controller.NewDataExpirationController(
		repos.Suppression,
		repos.ScopeExcl,
		repos.Audit,
		&controller.DataExpirationControllerConfig{
			Interval:           1 * time.Hour,
			AuditRetentionDays: 365,
			Logger:             log.With("controller", "data-expiration"),
		},
	))

	w.ControllerManager.Register(controller.NewRoleSyncController(
		deps.DB,
		&controller.RoleSyncControllerConfig{
			Interval: 1 * time.Hour,
			Logger:   log.With("controller", "role-sync"),
		},
	))

	w.ControllerManager.Register(controller.NewApprovalExpirationController(
		repos.FindingApproval,
		repos.Finding,
		&controller.ApprovalExpirationControllerConfig{
			Interval:  1 * time.Hour,
			BatchSize: 100,
			Logger:    log.With("controller", "approval-expiration"),
		},
	))

	w.ControllerManager.Register(controller.NewScopeReconciliationController(
		repos.AccessControl,
		svc.ScopeRule,
		&controller.ScopeReconciliationControllerConfig{
			Interval: 30 * time.Minute,
			Logger:   log.With("controller", "scope-reconciliation"),
		},
	))

	// Threat intel — daily EPSS + KEV refresh (fetches + persists to DB)
	w.ControllerManager.Register(controller.NewThreatIntelRefreshController(
		svc.ThreatIntel,
		log.With("controller", "threat-intel-refresh"),
	))

	// Control test scheduler — daily sweep to mark stale detection coverage as overdue
	w.ControllerManager.Register(controller.NewControlTestSchedulerController(
		repos.ControlTest,
		&controller.ControlTestSchedulerConfig{
			Interval:  24 * time.Hour,
			StaleDays: 30,
			BatchSize: 500,
			Logger:    log.With("controller", "control-test-scheduler"),
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
	w.OutboxScheduler.Start()

	// Start finding lifecycle scheduler
	w.FindingLifecycleScheduler.Start()

	// Start notification cleanup worker (runs daily, 90-day retention)
	if w.notificationService != nil {
		w.NotificationCleanupTicker = time.NewTicker(24 * time.Hour)
		go func() {
			for range w.NotificationCleanupTicker.C {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				deleted, err := w.notificationService.CleanupOld(cleanupCtx, 90)
				if err != nil {
					log.Error("notification cleanup failed", "error", err)
				} else if deleted > 0 {
					log.Info("notification cleanup completed", "deleted", deleted)
				}
				cancel()
			}
		}()
		log.Info("notification cleanup worker started", "interval", "24h", "retention_days", 90)
	}

	// Start session + refresh-token cleanup worker.
	//
	// PURPOSE: delete rows that the regular code paths leave behind.
	// Logout marks sessions as 'revoked' (UPDATE, not DELETE). Refresh
	// token rotation marks the old token as used (UPDATE, not DELETE).
	// Without this worker the sessions and refresh_tokens tables grow
	// unboundedly with every login.
	//
	// SCHEDULE: every hour. Cheap query (single DELETE filtered by
	// expires_at + status), runs against indexed columns. Hourly
	// keeps the tables tight without spamming the DB. We also fire
	// once at startup so a freshly-deployed server reclaims any
	// backlog from when this worker didn't exist.
	if w.sessionService != nil {
		runCleanup := func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			sessionsDeleted, tokensDeleted, err := w.sessionService.CleanupExpiredSessions(cleanupCtx)
			if err != nil {
				log.Error("session cleanup failed", "error", err)
				return
			}
			if sessionsDeleted > 0 || tokensDeleted > 0 {
				log.Info("session cleanup completed",
					"sessions_deleted", sessionsDeleted,
					"refresh_tokens_deleted", tokensDeleted,
				)
			}
		}
		// Initial run on startup to clear historical backlog.
		go runCleanup()
		w.SessionCleanupTicker = time.NewTicker(1 * time.Hour)
		go func() {
			for range w.SessionCleanupTicker.C {
				runCleanup()
			}
		}()
		log.Info("session cleanup worker started", "interval", "1h")
	}

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
	w.OutboxScheduler.Stop()
	log.Info("notification scheduler stopped")

	// Stop finding lifecycle scheduler
	log.Info("stopping finding lifecycle scheduler...")
	w.FindingLifecycleScheduler.Stop()
	log.Info("finding lifecycle scheduler stopped")

	// Stop notification cleanup worker
	if w.NotificationCleanupTicker != nil {
		log.Info("stopping notification cleanup worker...")
		w.NotificationCleanupTicker.Stop()
		log.Info("notification cleanup worker stopped")
	}

	// Stop session cleanup worker
	if w.SessionCleanupTicker != nil {
		log.Info("stopping session cleanup worker...")
		w.SessionCleanupTicker.Stop()
		log.Info("session cleanup worker stopped")
	}

	// Stop controller manager
	log.Info("stopping controller manager...")
	if err := w.ControllerManager.Stop(); err != nil {
		log.Error("controller manager stop error", "error", err)
	}
	log.Info("controller manager stopped")
}
