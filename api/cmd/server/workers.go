package main

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/app/defectdojo"
	easmdnsapp "github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/jobs"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// sensorStaleTimeout is the shortest time from a sensor's heartbeat deadline
// to offline on the heartbeat ladder (sensordom.LadderOfflineFloor; each
// sensor is judged against its own deadline, pkg/domain/sensor/liveness.go).
// The doorbell never advises an interval above half of it
// (heartbeatDoorbellConfig), which is also below half of every sensor's own
// offline distance.
const sensorStaleTimeout = sensordom.LadderOfflineFloor

// ddTenantSyncerAdapter adapts *defectdojo.SyncService (which returns a
// SyncResult) to the scheduler's error-only TenantSyncer, so the controller
// package need not import app/defectdojo.
type ddTenantSyncerAdapter struct{ svc *defectdojo.SyncService }

func (a ddTenantSyncerAdapter) SyncTenant(ctx context.Context, tenantID shared.ID) error {
	_, err := a.svc.SyncTenant(ctx, tenantID)
	return err
}

// controllerMetrics returns the process-wide controller metrics collector.
//
// It is memoised because controller.NewPrometheusMetrics uses promauto, which
// registers on the Prometheus default registerer and panics on a duplicate
// registration. NewWorkers is called once by the server, but a test (or any
// future second composition root) that builds Workers twice would otherwise
// take the process down.
var controllerMetrics = sync.OnceValue(func() controller.Metrics {
	return controller.NewPrometheusMetrics("openctem")
})

// Workers holds all background worker instances.
type Workers struct {
	JobWorker                 *jobs.Worker
	SensorHealthChecker       *jobs.SensorHealthChecker
	AITriageRecoveryJob       *jobs.AITriageRecoveryJob
	ScanScheduler             *scan.ScanScheduler
	CommandExpirationChecker  *command.ExpirationChecker
	OutboxScheduler           *outbox.Scheduler
	FindingLifecycleScheduler *finding.FindingLifecycleScheduler
	NotificationCleanupTicker *time.Ticker
	notificationService       *integration.NotificationService
	// SessionCleanupTicker periodically deletes expired/revoked
	// sessions and refresh tokens. Without this the tables grow
	// unboundedly because logout marks rows as 'revoked' (not deleted)
	// and refresh-token rotation marks old rows as 'used' (not deleted).
	// SessionService.CleanupExpiredSessions() exists in the codebase
	// but was never wired into a worker until this hookup.
	SessionCleanupTicker *time.Ticker
	sessionService       *auth.SessionService
	ControllerManager    *controller.Manager

	// cleanupStopCh signals the ticker-driven cleanup goroutines (notification
	// + session) to exit; cleanupWG lets Stop() join them. time.Ticker.Stop()
	// does not close its channel, so a bare `for range ticker.C` loop would
	// leak the goroutine — these let them shut down cleanly.
	cleanupStopCh chan struct{}
	cleanupWG     sync.WaitGroup

	// AssetLifecycleWorker is exposed so the HTTP layer can invoke
	// the dry-run endpoint against the same worker instance the
	// cron controller uses. Keeps us from double-constructing the
	// worker and, more importantly, means settings changes observed
	// by the cron side are visible to the dry-run side on the next
	// tick.
	AssetLifecycleWorker *assetapp.AssetLifecycleWorker
}

// WorkerDeps contains dependencies needed to create workers.
type WorkerDeps struct {
	Config   *config.Config
	Log      *logger.Logger
	DB       *sql.DB
	Repos    *Repositories
	Services *Services
}

// adminAuditRetentionConfig maps the operator-facing ADMIN_AUDIT_RETENTION_*
// settings onto the controller config.
//
// This used to be a literal with DryRun hardcoded to true, so admin_audit_logs
// grew forever and no environment variable could change that. DryRun still
// DEFAULTS to true (see config.AdminAuditRetentionConfig) — the point is that
// an operator can now turn it off.
func adminAuditRetentionConfig(cfg *config.Config, log *logger.Logger) *controller.AuditRetentionControllerConfig {
	return &controller.AuditRetentionControllerConfig{
		Interval:      cfg.AdminAuditRetention.Interval,
		RetentionDays: cfg.AdminAuditRetention.RetentionDays,
		BatchSize:     cfg.AdminAuditRetention.BatchSize,
		DryRun:        cfg.AdminAuditRetention.DryRun,
		Logger:        log.With("controller", "admin-audit-retention"),
	}
}

// registerPurgeControllers schedules the time-based deletes that had no caller:
// expired invitations, expired platform-admin sessions and reviewed quarantined
// sensor results. Each runs under its controller lease, so one replica at a
// time; a missing dependency leaves that purge unregistered.
func registerPurgeControllers(m *controller.Manager, cfg *config.Config, repos *Repositories, svc *Services, log *logger.Logger) {
	if svc.Tenant != nil {
		m.Register(controller.NewPurgeController("invitation-purge", cfg.Worker.InvitationPurgeInterval,
			svc.Tenant.CleanupExpiredInvitations, log.With("controller", "invitation-purge")))
	}
	if repos.AdminConsole != nil {
		console := repos.AdminConsole
		m.Register(controller.NewPurgeController("admin-session-purge", cfg.Worker.AdminSessionPurgeInterval,
			func(ctx context.Context) (int64, error) { return console.DeleteExpiredSessions(ctx, time.Now()) },
			log.With("controller", "admin-session-purge")))
	}
	if repos.MCPOAuth != nil {
		// Ended MCP OAuth requests, tokens, grants and unused clients (RFC-062).
		mcp := repos.MCPOAuth
		m.Register(controller.NewPurgeController("mcp-oauth-purge", time.Hour,
			func(ctx context.Context) (int64, error) { return mcp.PurgeForPlatform(ctx, time.Now()) },
			log.With("controller", "mcp-oauth-purge")))
	}
	if repos.SensorResult != nil {
		quarantine := repos.SensorResult
		retention := cfg.Worker.QuarantineRetention
		if retention <= 0 {
			retention = 30 * 24 * time.Hour
		}
		m.Register(controller.NewPurgeController("sensor-result-quarantine-purge", cfg.Worker.QuarantinePurgeInterval,
			func(ctx context.Context) (int64, error) {
				n, err := quarantine.PurgeReviewed(ctx, time.Now().Add(-retention))
				return int64(n), err
			},
			log.With("controller", "sensor-result-quarantine-purge")))
	}
}

// NewWorkers initializes all background workers.
func NewWorkers(deps *WorkerDeps) (*Workers, error) {
	cfg := deps.Config
	log := deps.Log
	repos := deps.Repos
	svc := deps.Services

	w := &Workers{}

	// Initialize the job worker. This is unconditional on purpose: the asynq
	// server consumes AI-triage, Jira-sync and GitHub-sync tasks as well as
	// email, and those are enqueued regardless of SMTP. Gating the worker on
	// svc.Email meant a default deployment (SMTP_ENABLED=false) enqueued those
	// tasks and never consumed them. jobs.NewWorker logs which handlers it had
	// to skip.
	var err error
	w.JobWorker, err = NewJobWorker(cfg, svc.Email, svc.AITriage, svc.JiraSync, svc.GitHubTicket, log)
	if err != nil {
		return nil, err
	}

	// Initialize sensor health checker if worker is enabled
	if cfg.Worker.Enabled {
		w.SensorHealthChecker = jobs.NewSensorHealthChecker(repos.Sensor, &cfg.Worker, log)
		log.Info("sensor health checker initialized",
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
	w.ScanScheduler = scan.NewScanScheduler(
		repos.Scan,
		svc.Scan, scan.ScanSchedulerConfig{
			CheckInterval: time.Minute,
			BatchSize:     50,
		}, log,
	)

	// Initialize command expiration checker
	w.CommandExpirationChecker = command.NewExpirationChecker(
		repos.Command,
		svc.ScanRun,
		command.ExpirationCheckerConfig{
			CheckInterval: time.Minute,
			// Owns platform-job queue expiry too, because expiring a job has to
			// tell the owning scan run why. Previously JobRecoveryController's
			// MaxQueueMinutes, where the expiry notified nobody.
			MaxQueueMinutes: 60,
		},
		log,
	)

	// Initialize notification scheduler
	w.OutboxScheduler = outbox.NewScheduler(
		svc.Outbox,
		outbox.DefaultSchedulerConfig(),
		log,
	)

	// Initialize finding lifecycle scheduler
	// Handles feature branch finding expiry
	w.FindingLifecycleScheduler = finding.NewFindingLifecycleScheduler(
		repos.Finding,
		repos.Tenant,
		finding.DefaultFindingLifecycleSchedulerConfig(),
		log,
	)

	// Store notification service reference for cleanup worker
	w.notificationService = svc.Notification

	// Store session service reference for the session cleanup worker.
	// Started in Workers.Start() — see comment on SessionCleanupTicker.
	w.sessionService = svc.Session

	// Note: Template sync uses lazy sync on scan trigger, no background worker needed.
	// Templates are synced on-demand when a scan uses custom templates.

	// Initialize controller manager for background tasks.
	//
	// Metrics is the single seam through which every registered controller is
	// observed — Manager.reconcileOnce records duration/items/errors per
	// controller name, and skips all of it when Metrics is nil. It was nil, so
	// none of the background controllers were observable: a reaper that errors
	// on every tick looked identical to one with nothing to do. The collectors
	// register on the Prometheus default registerer, which is what /metrics
	// serves.
	w.ControllerManager = controller.NewManager(&controller.ManagerConfig{
		Logger:  log.With("component", "controller-manager"),
		Metrics: controllerMetrics(),
		// Exclusive controllers (retention sweeps, threat-intel refresh) run
		// on one replica at a time under a controller lease (RFC-046 P1.8).
		Leases:      postgres.NewControllerLeaseRepository(&postgres.DB{DB: deps.DB}),
		LeaseHolder: postgres.LeaseHolderID(),
	})

	// Register controllers
	sensorHealth := controller.NewSensorHealthController(
		repos.Sensor,
		svc.Audit,
		&controller.SensorHealthControllerConfig{
			Interval:     30 * time.Second,
			StaleTimeout: sensorStaleTimeout,
			Logger:       log.With("controller", "sensor-health"),
		},
	)
	// sensor.offline was a subscribable event type that nothing emitted; the
	// controller is the one place that sees the online -> offline transition.
	if svc.Outbox != nil {
		sensorHealth.SetNotifier(svc.Outbox)
	}
	// The offline transition also goes on the sensor's activity timeline.
	if svc.Sensor != nil {
		sensorHealth.SetEventRecorder(svc.Sensor)
	}
	// No offline conviction while the platform itself is degraded (RFC-035
	// D3): just started, stalled, or slow to handle heartbeats.
	sensorHealth.SetPlatformHealth(svc.SensorPlatformHealth)
	w.ControllerManager.Register(sensorHealth)

	// CI alerts (RFC-051 §10.6): missed schedules, lost coverage, failing
	// default branches and outdated runners, once each while they hold; and
	// findings only a stale CI pipeline reported become not observed.
	if repos.CIRun != nil {
		var notifier cirunapp.Notifier
		if svc.Outbox != nil {
			notifier = svc.Outbox
		}
		var auditor cirunapp.Auditor
		if svc.Audit != nil {
			auditor = svc.Audit
		}
		job := cirunapp.NewAlertJob(repos.CIRun, notifier, auditor, cirun.StatusPolicy{
			LatestVersion: sensordom.NormalizeVersion(deps.Config.SensorConfig.LatestVersion),
			MinVersion:    sensordom.NormalizeVersion(deps.Config.SensorConfig.MinVersion),
		}, log)
		w.ControllerManager.Register(controller.NewCIAlertsController(job, 0))
		// Retention: expired run token hashes, run findings after 90 days,
		// runs after 400 days (each scan workflow keeps its latest runs).
		w.ControllerManager.Register(controller.NewCIRetentionController(cirunapp.NewRetentionJob(repos.CIRun, log), 0))
	}

	jobRecovery := controller.NewJobRecoveryController(
		repos.Command,
		&controller.JobRecoveryControllerConfig{
			Interval:              60 * time.Second,
			StuckThresholdMinutes: 30,
			MaxRetries:            3,
			Logger:                log.With("controller", "job-recovery"),
		},
	)
	// A poison command (dispatch attempts exhausted) fails its workflow step.
	if svc.ScanRun != nil {
		jobRecovery.SetStepFailureNotifier(svc.ScanRun)
	}
	w.ControllerManager.Register(jobRecovery)

	// Automation runs a restart left pending or running end as failed (on
	// start and every 15 minutes), so they stop holding the active-run cap.
	w.ControllerManager.Register(controller.NewAutomationRunReaper(repos.WorkflowRun, 0, log))

	// One-off scans that never ran are archived after 30 days (audited).
	w.ControllerManager.Register(controller.NewOneOffScanArchiveController(svc.Scan, 0, 0))

	// Scan timeout controller: enforces per-scan timeout_seconds on running scan_runs
	scanTimeout := controller.NewScanTimeoutController(
		repos.ScanRun,
		&controller.ScanTimeoutControllerConfig{
			Interval: 60 * time.Second,
			Logger:   log.With("controller", "scan-timeout"),
		},
	)
	// A run the reaper ends fires the run-finished event (automations) like
	// any other (research/62 P0-11).
	if svc.ScanRun != nil {
		scanTimeout.SetReapedRunListener(svc.ScanRun.NotifyRunsReaped)
	}
	w.ControllerManager.Register(scanTimeout)

	// Stalled run repair (research/62 SG-10): a run whose chained step waits
	// for a report that failed or expired, or whose plan was saved without
	// its commands, is advanced again.
	if svc.ScanRun != nil {
		w.ControllerManager.Register(controller.NewStalledRunRepairController(
			svc.ScanRun, time.Minute, log.With("controller", "stalled-run-repair")))
	}

	// Scan retry controller: dispatches automatic retries for failed scans
	// with retry budget remaining (uses exponential backoff)
	w.ControllerManager.Register(controller.NewScanRetryController(
		repos.ScanRun,
		svc.Scan, // scan service implements RetryDispatcher
		&controller.ScanRetryControllerConfig{
			Interval:  60 * time.Second,
			BatchSize: 100,
			Logger:    log.With("controller", "scan-retry"),
		},
	))

	// Coverage scheduler: license-aware rolling coverage (RFC-007), rebuilt on
	// the Tenable.sc sensor connector (RFC-047 §9): each batch is a
	// connector_scan sized against Tenable.sc's own license numbers. Behind
	// the connector switch (integrationdom.TenableConnectorEnabled, D-14).
	if integrationdom.TenableConnectorEnabled && svc.TenableSC != nil {
		w.ControllerManager.Register(controller.NewCoverageScheduler(
			repos.Integration,
			repos.ScanCoverage,
			connectorCoverageDispatcher{svc: svc.TenableSC},
			&controller.CoverageSchedulerConfig{
				Interval: 5 * time.Minute,
				// Each batch passes a scan trigger's target checks (RFC-042 F16).
				Gate:      svc.Scan,
				Connector: svc.TenableSC,
				Logger:    log.With("controller", "coverage-scheduler"),
			},
		))
	}

	// Report scheduler: runs due report_schedules, renders the executive summary,
	// and emails it to recipients. Only registered when email is configured
	// (otherwise every run would fail delivery). This is the controller that was
	// missing — schedules could be created in the UI but never executed.
	if svc.Email != nil && svc.Email.IsConfigured() {
		reportScheduler := controller.NewReportScheduler(
			repos.ReportSchedule,
			repos.Finding,
			svc.Email,
			nil,        // TenantNamer optional; report header falls back to tenant id
			svc.Module, // ModuleGuard: skip tenants without the reports module
			controller.ReportSchedulerConfig{Interval: time.Minute},
			log,
		)
		// Recipients are re-checked at send time: members or allowed domains (D12).
		reportScheduler.SetRecipientPolicy(repos.Tenant)
		// Each report renders under its creator's data scope (D6).
		reportScheduler.SetScopeResolver(svc.DataScope)
		w.ControllerManager.Register(reportScheduler)
	}

	// Continuous retest (RFC-039): settle stale retests and serve due
	// auto-retest ticks. Auto-retest is per tenant and off by default
	// (settings.retest.auto_enabled); each tick is claimed by compare-and-set,
	// so every replica can run this controller without double-firing.
	if svc.Retest != nil {
		w.ControllerManager.Register(controller.NewRetestScheduler(
			svc.Retest, repos.FindingRetest, time.Minute, log,
		))
	}

	w.ControllerManager.Register(controller.NewDataExpirationController(
		repos.Suppression,
		repos.ScopeExcl,
		svc.Audit,
		&controller.DataExpirationControllerConfig{
			Interval:           1 * time.Hour,
			AuditRetentionDays: cfg.AuditRetention.Days,
			AuditArchiveDir:    cfg.AuditRetention.ArchiveDir,
			Logger:             log.With("controller", "data-expiration"),
		},
	).SetScopeTargetExpirer(repos.ScopeTarget))

	w.ControllerManager.Register(controller.NewRoleSyncController(
		deps.DB,
		&controller.RoleSyncControllerConfig{
			Interval: 1 * time.Hour,
			Logger:   log.With("controller", "role-sync"),
		},
	))

	// Access requests: unconfirmed ones go after 24 h, decided ones after 90 days.
	if svc.AccessRequest != nil {
		w.ControllerManager.Register(controller.NewAccessRequestRetentionController(
			svc.AccessRequest, log.With("controller", "access-request-retention")))
	}

	// Domain re-verify sweep (SSO P1): periodically re-checks verified domains;
	// a domain whose TXT record vanished is downgraded to failed (fail-closed),
	// so a lapsed/hijacked domain loses SSO JIT authority.
	if svc.DomainVerify != nil {
		w.ControllerManager.Register(controller.NewDomainReverifyController(
			svc.DomainVerify,
			&controller.DomainReverifyControllerConfig{
				Interval:  12 * time.Hour,
				Staleness: 24 * time.Hour,
				BatchSize: 100,
				Logger:    log.With("controller", "domain-reverify"),
			},
		))
	}

	// External members' access end dates (RFC-058): an expired membership is
	// suspended within a minute.
	if svc.Tenant != nil {
		w.ControllerManager.Register(controller.NewMemberAccessExpiryController(svc.Tenant, time.Minute, 200,
			log.With("controller", "member-access-expiry")))
	}

	// Idle Free workspaces: reminder, read-only, warnings, deletion due.
	if svc.IdleWorkspaces != nil {
		w.ControllerManager.Register(controller.NewIdleWorkspaceController(svc.IdleWorkspaces, 6*time.Hour,
			log.With("controller", "idle-workspaces")))
	}

	registerPurgeControllers(w.ControllerManager, cfg, repos, svc, log)

	w.ControllerManager.Register(controller.NewApprovalExpirationController(
		repos.FindingApproval,
		repos.Finding,
		&controller.ApprovalExpirationControllerConfig{
			Interval:  1 * time.Hour,
			BatchSize: 100,
			Logger:    log.With("controller", "approval-expiration"),
		},
	))

	// Asset identity model: derive identifiers for assets that predate it and
	// queue suspected duplicates for review (never merges).
	w.ControllerManager.Register(controller.NewAssetIdentityBackfillController(
		ingest.NewIdentityBackfill(repos.AssetIdentityBackfill, repos.AssetIdentifier, repos.AssetDedup,
			log.With("controller", "asset-identity-backfill")),
	))

	w.ControllerManager.Register(controller.NewScopeReconciliationController(
		repos.AccessControl,
		svc.ScopeRule,
		&controller.ScopeReconciliationControllerConfig{
			Interval: 30 * time.Minute,
			Logger:   log.With("controller", "scope-reconciliation"),
		},
	))

	// Tenable.sc sensor connector (RFC-047): settle finished connector_sync
	// commands and queue the next sync of each connector integration when due.
	if svc.TenableSC != nil && integrationdom.TenableConnectorEnabled {
		w.ControllerManager.Register(controller.NewTenableSCSyncController(repos.Integration, svc.TenableSC, log))
	}

	// RFC-013 Phase 2c: periodically pull due DefectDojo integrations so the
	// co-existence sync is hands-off (nil-safe when the sync service is absent).
	if svc.DefectDojoSync != nil {
		w.ControllerManager.Register(controller.NewDefectDojoSyncController(
			repos.Integration,
			ddTenantSyncerAdapter{svc: svc.DefectDojoSync},
			log,
		))
	}

	// Threat intel — daily EPSS + KEV refresh + auto-escalate KEV findings
	w.ControllerManager.Register(controller.NewThreatIntelRefreshController(
		svc.ThreatIntel,
		repos.KEVEscalator,
		svc.ReclassifyQueue,
		log.With("controller", "threat-intel-refresh"),
	))

	// CTEM-ID catalog — daily fail-open refresh of the standardized exposure
	// catalog (https://ctem.org/source.json), mirroring the threat-intel refresh.
	w.ControllerManager.Register(controller.NewCTEMIDRefreshController(
		svc.CTEMID,
		log.With("controller", "ctem-id-refresh"),
	))

	// Certificate-Transparency discovery — daily, fail-open, PUBLIC-data
	// external-exposure connector. Per tenant it queries crt.sh for the tenant's
	// domain assets (SSRF-guarded, rate-limited, body-bounded) and emits
	// subdomain_discovered + certificate_expiring ExposureEvents. Inert until a
	// tenant owns domain assets; disable with CERT_MONITOR_ENABLED=false.
	// Names a permanent scope target or seed covers are confirmed: once at
	// start-up (the backfill) and every 6 h (RFC-054 §4.3).
	if svc.ScopeJoin != nil {
		w.ControllerManager.Register(controller.NewScopeJoinController(svc.ScopeJoin, 0))
		// Programs with a scope source are read again every 6 hours (RFC-065 §14).
		if svc.BountyProgram != nil {
			w.ControllerManager.Register(controller.NewProgramSyncController(svc.BountyProgram, 0))
		}
	}

	if cfg.Worker.CertMonitorEnabled && svc.CertMonitor != nil {
		w.ControllerManager.Register(controller.NewCertMonitorController(
			svc.CertMonitor,
			repos.Tenant,
			&controller.CertMonitorControllerConfig{
				Interval:    easmTick(cfg.Worker.CertMonitorInterval),
				Logger:      log.With("controller", "cert-monitor"),
				ModuleGuard: svc.Module, // skip tenants without the attack-surface module
				DNSFollowUp: dnsFollowUp(svc.EASMDNS),
			},
		))
	}

	// EASM DNS-only checks — daily, fail-open, passive (RFC-036 P1): dangling
	// CNAME/NS and email posture of the tenant's own domains. On by default
	// (research/22 E3); disable platform-wide with EASM_DNS_CHECKS_ENABLED=false.
	// The CT controller also runs them for a tenant right after its CT sweep,
	// so names CT just promoted are checked in the same pass.
	if svc.EASMDNS != nil {
		w.ControllerManager.Register(controller.NewEASMDNSController(
			svc.EASMDNS,
			repos.Tenant,
			&controller.EASMDNSControllerConfig{
				Interval:    easmTick(cfg.Worker.EASMDNSInterval),
				Logger:      log.With("controller", "easm-dns-checks"),
				ModuleGuard: svc.Module,
			},
		))
	}

	// Owner resolution — make the member whose email is owner_ref a primary owner (asset_owners)
	w.ControllerManager.Register(controller.NewOwnerResolutionController(
		deps.DB,
		log.With("controller", "owner-resolution"),
	))

	// Scheduled SCM repository/branch sync — disabled unless SCM_SYNC_INTERVAL
	// is set. Imports repos + branches for connected SCM integrations and flips
	// connections to "error" when their tokens expire.
	if cfg.Worker.SCMSyncInterval > 0 && svc.Integration != nil {
		w.ControllerManager.Register(controller.NewSCMSyncController(
			svc.Integration,
			cfg.Worker.SCMSyncInterval,
			log.With("controller", "scm-sync"),
		))
	}

	// B1/B2 priority reclassification sweep — drains the in-memory
	// queue populated by ControlChangePublisher (and future EPSS/KEV/
	// rule producers) and re-runs ClassifyFinding on the scoped set.
	// Nil-safe only against a missing queue/reclassifier — svc itself
	// is a required argument to NewWorkers (an earlier redundant
	// svc != nil check confused staticcheck; the function dereferences
	// svc unconditionally above this point).
	if svc.ReclassifyQueue != nil && svc.Reclassifier != nil {
		w.ControllerManager.Register(controller.NewPriorityReclassifyController(
			svc.ReclassifyQueue,
			svc.Reclassifier,
			&controller.PriorityReclassifyConfig{
				// Drained every minute: an attribution decision reclassifies
				// its assets' findings within two minutes (research/22 P0-9).
				Interval: time.Minute,
				Logger:   log.With("controller", "priority-reclassify"),
			},
		))

		// Periodic *producer* for the same queue: on a low-frequency timer it
		// enqueues one whole-tenant reclassify per active tenant. Without this
		// the consumer above has nothing to drain except discrete producer
		// events (control-change, KEV/EPSS refresh), so never-classified
		// findings (priority_class IS NULL) and slow EPSS drift are never
		// re-swept. Nil-safe on a missing queue/tenant repo.
		if repos.Tenant != nil {
			w.ControllerManager.Register(controller.NewPriorityReclassifySweepController(
				svc.ReclassifyQueue,
				repos.Tenant,
				&controller.PriorityReclassifySweepConfig{
					Interval: 12 * time.Hour,
					Logger:   log.With("controller", "priority-reclassify-sweep"),
				},
			))
		}
	}

	// SLA escalation — marks overdue findings as breached every 15 min (RFC-005 Gap 7).
	// B4: attach outbox publisher so each breach fans out as
	// a notification. Nil-safe when Outbox service isn't configured.
	slaEscalation := controller.NewSLAEscalationController(
		deps.DB,
		log.With("controller", "sla-escalation"),
	)
	if svc != nil && svc.Outbox != nil {
		slaEscalation.SetBreachPublisher(sla.NewBreachOutboxAdapter(svc.Outbox))
		// Also fan out "approaching deadline" warnings (previously the warning
		// pass updated sla_status but notified no one).
		slaEscalation.SetWarningPublisher(sla.NewWarningOutboxAdapter(svc.Outbox))
	}
	w.ControllerManager.Register(slaEscalation)

	// Risk snapshot — computes daily risk/MTTR/SLA metrics per tenant (RFC-005 Gap 4)
	w.ControllerManager.Register(controller.NewRiskSnapshotController(
		deps.DB,
		log.With("controller", "risk-snapshot"),
	))

	// Remediation progress — periodically refresh campaign finding counts and
	// auto-complete campaigns whose findings are all resolved.
	if svc != nil && svc.RemediationCampaign != nil {
		if svc.Module != nil {
			svc.RemediationCampaign.SetModuleGuard(svc.Module) // skip tenants with remediation off
		}
		w.ControllerManager.Register(controller.NewRemediationProgressController(
			svc.RemediationCampaign,
			30*time.Minute,
			log.With("controller", "remediation-progress"),
		))
	}

	// Control test scheduler — daily sweep to mark stale detection coverage as overdue
	w.ControllerManager.Register(controller.NewControlTestSchedulerController(
		repos.ControlTest,
		&controller.ControlTestSchedulerConfig{
			Interval:    24 * time.Hour,
			StaleDays:   30,
			BatchSize:   500,
			Logger:      log.With("controller", "control-test-scheduler"),
			ModuleGuard: svc.Module, // skip tenants without the control-testing module
		},
	))

	// F-13: Priority-class audit log retention. Prevents unbounded growth of
	// priority_class_audit_log — every classification/enrichment writes a row.
	w.ControllerManager.Register(controller.NewPriorityAuditRetentionController(
		repos.PriorityAudit,
		&controller.PriorityAuditRetentionConfig{
			Interval:      24 * time.Hour,
			RetentionDays: 180,
			Logger:        log.With("controller", "priority-audit-retention"),
		},
	))

	// Deleted-asset purge: assets a person deleted (soft delete, no findings)
	// are hard-deleted 30 days later. Findings are never purged with them.
	if repos.Asset != nil {
		w.ControllerManager.Register(controller.NewAssetPurgeController(
			repos.Asset,
			&controller.AssetPurgeConfig{
				Interval:      24 * time.Hour,
				RetentionDays: 30,
				Logger:        log.With("controller", "asset-purge"),
			},
		))
	}

	// Scanner output retention: plugin output of findings closed more than
	// 365 days ago is dropped (research 24 P0-2, owner decision C9).
	if repos.Finding != nil {
		w.ControllerManager.Register(controller.NewScannerOutputRetentionController(
			repos.Finding,
			&controller.ScannerOutputRetentionConfig{
				Logger: log.With("controller", "finding-scanner-output-retention"),
			},
		))
	}

	// Finding evidence retention: encrypted secret values past the tenant's
	// secret retention, evidence past 365 days (finding-evidence.md).
	if svc.Evidence != nil {
		w.ControllerManager.Register(controller.NewEvidenceRetentionController(
			svc.Evidence, time.Hour, log.With("controller", "finding-evidence-retention")))
	}

	// Sensor activity timeline retention: sensor_events past 90 days.
	if repos.SensorEvent != nil {
		w.ControllerManager.Register(controller.NewSensorEventRetentionController(
			repos.SensorEvent,
			&controller.SensorEventRetentionConfig{
				Interval:      6 * time.Hour,
				RetentionDays: 90,
				Logger:        log.With("controller", "sensor-event-retention"),
			},
		))
	}

	// Run timelines: command_events past 30 days (research/62 P0-4).
	if repos.CommandEvent != nil {
		w.ControllerManager.Register(controller.NewCommandEventRetentionController(
			repos.CommandEvent,
			&controller.CommandEventRetentionConfig{
				Interval:      6 * time.Hour,
				RetentionDays: 30,
				Logger:        log.With("controller", "command-event-retention"),
			},
		))
	}

	// Web surface (RFC-056 WS14): unseen 30 days -> gone, gone a year ->
	// deleted, change feed kept 90 days.
	if repos.WebEndpoint != nil {
		w.ControllerManager.Register(controller.NewWebSurfaceRetentionController(
			repos.WebEndpoint, log.With("controller", "web-surface-retention")))
	}

	// Per-task sensor logs (RFC-029 §4.4.1): kept 14 days.
	if repos.CommandLog != nil {
		w.ControllerManager.Register(controller.NewCommandLogRetentionController(
			repos.CommandLog, commandlog.Retention, log.With("controller", "command-log-retention")))
	}

	// Heartbeat history retention: buckets past 48 h (RFC-035, the Control
	// channel sparkline reads 24 h).
	if repos.SensorHeartbeatHistory != nil {
		w.ControllerManager.Register(controller.NewHeartbeatHistoryRetentionController(
			repos.SensorHeartbeatHistory, log.With("controller", "sensor-heartbeat-history-retention")))
	}

	// Platform job queue priority rebalancing. Without this the platform
	// command queue stays strictly FIFO and a noisy tenant can starve
	// quieter ones. Runs every 60 s — cheap SQL update, safe default.
	w.ControllerManager.Register(controller.NewQueuePriorityController(
		repos.Command,
		&controller.QueuePriorityControllerConfig{
			Interval: 60 * time.Second,
			Logger:   log.With("controller", "queue-priority"),
		},
	))

	// Admin-audit-log retention. Complements DataExpirationController
	// (which handles tenant audit_logs) by pruning the platform-level
	// admin_audit_logs table on the same 365-day window.
	//
	// Every knob is operator-configurable (ADMIN_AUDIT_RETENTION_*).
	// DryRun defaults to true so an upgrade never silently starts deleting
	// audit history: the controller reports what it WOULD delete and an
	// operator promotes to ADMIN_AUDIT_RETENTION_DRY_RUN=false once the
	// counts look right. Previously DryRun was hardcoded true with no way
	// to turn it off, so admin_audit_logs grew forever.
	if cfg.AdminAuditRetention.Enabled {
		arCfg := adminAuditRetentionConfig(cfg, log)
		w.ControllerManager.Register(controller.NewAuditRetentionController(repos.AdminAuditLog, arCfg))
		log.Info("admin audit retention controller registered",
			"retention_days", arCfg.RetentionDays,
			"dry_run", arCfg.DryRun,
			"interval", arCfg.Interval,
		)
	}

	// Audit hash-chain integrity verification. The admin endpoint
	// GET /api/v1/audit-logs/verify is pull-based; this controller
	// runs the same VerifyChain on every active tenant once an hour
	// and emits an ERROR-level log (SIEM alert keyword
	// "audit_chain_break") for every break. Closes the MTTD gap for
	// tamper events where the endpoint is never called.
	w.ControllerManager.Register(controller.NewAuditChainVerifyController(
		svc.Audit,
		repos.Tenant,
		&controller.AuditChainVerifyControllerConfig{
			Interval: time.Hour,
			// PerTenantLimit unset: walk every chain in full. A cap here
			// left everything past the first 10,000 entries unverified.
			// Logger: the controller adds its own "controller" attribute.
			Logger: log,
		},
	))

	// Asset lifecycle worker. Demotes assets that no scanner or
	// integration has re-observed within each tenant's configured
	// threshold. Backward compatible by default: a tenant that has
	// not enabled the feature in its settings is skipped entirely
	// inside the worker, so registering this controller is safe for
	// every deployment even before operators opt in.
	lifecycleWorker := assetapp.NewAssetLifecycleWorker(deps.DB, repos.Tenant, log)
	lifecycleWorker.SetAuditService(svc.Audit)
	lifecycleWorker.SetStateHistoryRepository(repos.AssetStateHistory)
	w.ControllerManager.Register(controller.NewAssetLifecycleController(
		lifecycleWorker,
		repos.Tenant,
		&controller.AssetLifecycleControllerConfig{
			Interval: 24 * time.Hour,
			Logger:   log.With("controller", "asset-lifecycle"),
		},
	))
	// Expose the worker to the HTTP layer so the admin dry-run
	// endpoint can call it without a duplicate instance.
	w.AssetLifecycleWorker = lifecycleWorker

	// Asset-graph enrichment. Infers high-confidence Exposes (host→service)
	// and RunsOn (application→host) edges from data scanners already ingest,
	// so the attack-path / exposure-chain / reachability engines have edges
	// beyond DNS to traverse over historical assets. Idempotent (edges use
	// ON CONFLICT DO NOTHING); ambiguous matches are filed as suggestions for
	// operator review rather than auto-applied.
	if svc.RelationshipSuggestion != nil {
		w.ControllerManager.Register(controller.NewGraphEnrichmentController(
			svc.RelationshipSuggestion,
			repos.Tenant,
			&controller.GraphEnrichmentControllerConfig{
				Interval:    time.Hour,
				Logger:      log.With("controller", "graph-enrichment"),
				ModuleGuard: svc.Module, // skip tenants without the attack-surface module
			},
		))
	}

	// Threat-model refresh. Regenerates each tenant's tenant-wide threat model
	// so it reflects the latest exposure chains and asset-graph edges (e.g.
	// edges the graph-enrichment pass above just inferred). Without this,
	// threat_model_threats only changes on manual API-triggered generation,
	// starving the priority-classification threat-model oracle of fresh data.
	// The generator has built-in no-op detection (InputHash), so a slower
	// cadence than graph-enrichment keeps cost down without going stale.
	if svc.ThreatModel != nil {
		w.ControllerManager.Register(controller.NewThreatModelRefreshController(
			svc.ThreatModel,
			repos.Tenant,
			&controller.ThreatModelRefreshControllerConfig{
				Interval:    2 * time.Hour,
				Logger:      log.With("controller", "threat-model-refresh"),
				ModuleGuard: svc.Module, // skip tenants without the threat-model module
			},
		))
	}

	// Async-ingest worker (RFC-005). Drains the ingest_jobs queue through the
	// normal ingest pipeline. Safe to register unconditionally: until the
	// accept path enqueues jobs (async mode), the queue is empty and the
	// worker reconciles to zero. Bounded batch/per-tick caps are the
	// backpressure that protects the DB pool under heavy ingest.
	if svc.Ingest != nil && repos.IngestJob != nil {
		jobs := ingest.NewJobProcessor(svc.Ingest)
		// Protocol v2 results jobs (RFC-026) run on the same queue whatever
		// INGEST_MODE is, whenever v2 results are enabled.
		if cfg.Ingest.V2Results && repos.IngestReport != nil {
			jobs.SetV2(ingest.NewV2JobProcessor(svc.Ingest, repos.IngestReport, repos.IngestJob,
				protov2.DefaultLimits(), ingest.BlindingGuard{
					Ratio: cfg.Ingest.V2BlindingRatio, MinFindings: cfg.Ingest.V2BlindingMinFindings,
				}, log))
		}
		w.ControllerManager.Register(controller.NewIngestWorkerController(
			repos.IngestJob,
			jobs,
			&controller.IngestWorkerControllerConfig{
				Interval:     2 * time.Second,
				BatchSize:    5,
				MaxPerTick:   50,
				LeaseTimeout: 5 * time.Minute,
				Logger:       log.With("controller", "ingest-worker"),
			},
		))
	}

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

	// Start sensor health checker
	if w.SensorHealthChecker != nil {
		w.SensorHealthChecker.Start()
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

	// Shared stop channel for the ticker-driven cleanup goroutines below.
	w.cleanupStopCh = make(chan struct{})

	// Start notification cleanup worker (runs daily, 90-day retention)
	if w.notificationService != nil {
		w.NotificationCleanupTicker = time.NewTicker(24 * time.Hour)
		w.cleanupWG.Add(1)
		go func() {
			defer w.cleanupWG.Done()
			for {
				select {
				case <-w.cleanupStopCh:
					return
				case <-w.NotificationCleanupTicker.C:
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					deleted, err := w.notificationService.CleanupOld(cleanupCtx, 90)
					if err != nil {
						log.Error("notification cleanup failed", "error", err)
					} else if deleted > 0 {
						log.Info("notification cleanup completed", "deleted", deleted)
					}
					cancel()
				}
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
		w.SessionCleanupTicker = time.NewTicker(1 * time.Hour)
		w.cleanupWG.Add(1)
		go func() {
			defer w.cleanupWG.Done()
			// Initial run on startup to clear historical backlog. Done INSIDE the
			// tracked goroutine (not a bare `go runCleanup()`) so graceful shutdown
			// — Workers.Stop() → cleanupWG.Wait() — waits for it to finish before
			// the DB is torn down, instead of leaving it racing a closed pool.
			runCleanup()
			for {
				select {
				case <-w.cleanupStopCh:
					return
				case <-w.SessionCleanupTicker.C:
					runCleanup()
				}
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

	// Stop sensor health checker
	if w.SensorHealthChecker != nil {
		w.SensorHealthChecker.Stop()
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

	// Stop the ticker-driven cleanup workers. Signal them to exit, stop the
	// tickers, then join — time.Ticker.Stop() alone doesn't close the channel,
	// so the goroutines need the stop signal to actually return.
	if w.cleanupStopCh != nil {
		log.Info("stopping cleanup workers...")
		close(w.cleanupStopCh)
		if w.NotificationCleanupTicker != nil {
			w.NotificationCleanupTicker.Stop()
		}
		if w.SessionCleanupTicker != nil {
			w.SessionCleanupTicker.Stop()
		}
		w.cleanupWG.Wait()
		log.Info("cleanup workers stopped")
	}

	// Stop controller manager
	log.Info("stopping controller manager...")
	if err := w.ControllerManager.Stop(); err != nil {
		log.Error("controller manager stop error", "error", err)
	}
	log.Info("controller manager stopped")
}

// connectorCoverageDispatcher dispatches a coverage batch as a connector_scan
// of the batch's Tenable.sc connector (RFC-047 §9).
type connectorCoverageDispatcher struct {
	svc *tenablesc.Service
}

func (d connectorCoverageDispatcher) DispatchTenableScan(ctx context.Context, in scancoverage.DispatchTenableInput) (shared.ID, string, error) {
	if in.IntegrationID == nil {
		return shared.ID{}, "", errors.New("coverage batch names no Tenable.sc connector")
	}
	session := in.SessionID
	if session == "" {
		session = shared.NewID().String()
	}
	id, err := d.svc.DispatchCoverageBatch(ctx, in.TenantID, *in.IntegrationID, in.Targets, session)
	return id, session, err
}

// easmTick is how often the CT and DNS controllers wake up: hourly (or the
// interval, when shorter), so a tenant's own interval (6 h and up, P0-11)
// takes effect; each name is re-queried only once its window has passed.
func easmTick(interval time.Duration) time.Duration {
	return min(interval, time.Hour)
}

// dnsFollowUp returns the DNS checks for the CT controller to run after each
// tenant's CT sweep, or nil when they are off (a typed nil would not be nil).
func dnsFollowUp(s *easmdnsapp.Service) controller.EASMDNSChecker {
	if s == nil {
		return nil
	}
	return s
}
