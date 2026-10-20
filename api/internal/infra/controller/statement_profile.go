package controller

// How each controller's SQL stays inside the app role's statement_timeout
// (deploy/postgres/least-privilege-roles.sql, default 60s). A background job
// whose statement can outlast that limit at scale must raise the limit for its
// own transaction (SET LOCAL statement_timeout, see
// internal/infra/postgres/statement_timeout.go) or work in batches that stay
// under it. TestEveryControllerDeclaresItsStatementProfile fails when a
// controller is added without an entry here. The inventory of the long
// statements is in docs/deployment/database-roles.md.

// SQLProfile says how a controller's statements are bounded.
type SQLProfile string

const (
	// SQLLight: point statements and index-bound reads or updates; none grows
	// with the data set.
	SQLLight SQLProfile = "light"
	// SQLBatched: set-based work in keyset or LIMIT batches; each statement
	// touches a bounded number of rows and finishes under the role limit.
	SQLBatched SQLProfile = "batched"
	// SQLLong: runs statements that can legitimately exceed the role limit
	// (bulk feed upserts, full-table sweeps, merges, dashboard run steps); each
	// sets an explicit bounded SET LOCAL statement_timeout.
	SQLLong SQLProfile = "long"
)

// sqlProfiles is keyed by the controller's Go type name.
var sqlProfiles = map[string]SQLProfile{
	// long: explicit, bounded SET LOCAL in the repository methods they call.
	"ThreatIntelRefreshController":        SQLLong, // EPSS/KEV upserts, catalog propagation, finding EPSS refresh, intel enqueue
	"FindingPriorityController":           SQLLong, // priority queue enqueue and batch writes
	"FindingPriorityReconcileController":  SQLLong, // per-tenant reconcile enqueue over all open findings
	"DashboardFactsController":            SQLLong, // dirty-queue processing
	"DashboardFactReconcileController":    SQLLong, // full run steps, partition upkeep
	"VulnFeedImportController":            SQLLong, // CVE corpus chunks and bundle finish
	"VulnMatchController":                 SQLLong, // software match invalidation and version matching
	"AuditRetentionController":            SQLLong, // chain prefix prune
	"EvidenceRetentionController":         SQLLong, // evidence secret and evidence deletes
	"CIRetentionController":               SQLLong, // run token clearing
	"AttachmentRetentionController":       SQLLong, // orphan marking over all attachments
	"WebEvidenceRetentionController":      SQLLong, // capture deletes
	"IngestWorkerController":              SQLLong, // asset and finding batch upserts, payload clearing
	"EventRetentionController":            SQLLong, // vuln event and sensor result prunes
	"AssetTechnologyBackfillController":   SQLBatched,
	"AssetIdentityBackfillController":     SQLBatched,
	"PriorityAuditRetentionController":    SQLBatched,
	"ScannerOutputRetentionController":    SQLBatched,
	"CommandLogRetentionController":       SQLBatched,
	"HeartbeatHistoryRetentionController": SQLBatched,
	"WebSurfaceRetentionController":       SQLBatched,
	"AccessRequestRetentionController":    SQLBatched,
	"SignupEventRetentionController":      SQLBatched,
	"DataExpirationController":            SQLBatched,
	"PurgeController":                     SQLBatched,
	"AssetPurgeController":                SQLBatched,
	"OneOffScanArchiveController":         SQLBatched,
	"CoverageScheduler":                   SQLBatched, // keyset batches per tenant and capability
	"AssetCoverageController":             SQLBatched,
	"AssetRiskScoreController":            SQLBatched,
	"AssetRiskReconcileController":        SQLBatched,
	"QueuePriorityController":             SQLBatched,
	"RiskSnapshotController":              SQLBatched,
	"AssetLifecycleController":            SQLBatched,
	"AssetEnrichmentController":           SQLBatched,
	"AssetChangeTimelineController":       SQLBatched,
	"GraphEnrichmentController":           SQLBatched,
	"OwnerResolutionController":           SQLBatched,
	"ProgramAssignmentController":         SQLBatched,
	"ProgramFeedController":               SQLBatched,
	"ProgramSyncController":               SQLBatched,
	"ScopeReconciliationController":       SQLBatched,
	"ScopeJoinController":                 SQLBatched,
	"ScopePendingController":              SQLBatched,
	"ScopeAttestationController":          SQLBatched,
	"ReportFileMigrationController":       SQLBatched,
	"RemediationProgressController":       SQLBatched,
	"RemediationSuggestionController":     SQLBatched,
	"RemediationTaskController":           SQLBatched,
	"RemediationTaskQueryController":      SQLBatched,
	"ThreatAlertPlannerController":        SQLBatched,
	"ThreatModelRefreshController":        SQLBatched,
	"SLAEscalationController":             SQLBatched,
	"AuditChainVerifyController":          SQLBatched, // keyset over the chain
	"CISweepController":                   SQLBatched,
	"EASMLookalikeController":             SQLBatched,
	"EASMNetworkSeedController":           SQLBatched,
	"TenableSCSyncController":             SQLBatched,
	"DefectDojoSyncController":            SQLBatched,
	"SCMSyncController":                   SQLBatched,
	"CTEMIDRefreshController":             SQLBatched,

	// light.
	"ApprovalDigestController":         SQLLight,
	"ApprovalExpirationController":     SQLLight,
	"ApprovalMaterialChangeController": SQLLight,
	"AttachmentScanController":         SQLLight,
	"AutomationRunReaper":              SQLLight,
	"CertMonitorController":            SQLLight,
	"CIAlertsController":               SQLLight,
	"CIDecorationController":           SQLLight,
	"ControlTestSchedulerController":   SQLLight,
	"DomainReverifyController":         SQLLight,
	"DurableJobsController":            SQLLight,
	"EASMDNSController":                SQLLight,
	"EASMWeeklyDigestController":       SQLLight,
	"IdleWorkspaceController":          SQLLight,
	"JobRecoveryController":            SQLLight,
	"MemberAccessExpiryController":     SQLLight,
	"ReportScheduler":                  SQLLight,
	"RetestScheduler":                  SQLLight,
	"RoleSyncController":               SQLLight,
	"ScanRetryController":              SQLLight,
	"ScanTimeoutController":            SQLLight,
	"ScanWindowClosingController":      SQLLight,
	"SensorHealthController":           SQLLight,
	"SensorLegacyKeysController":       SQLLight,
	"StalledRunRepairController":       SQLLight,
	"TaskTicketController":             SQLLight,
	"TeamMembershipExpiryController":   SQLLight,
	"VersionCheckController":           SQLLight,
	"VEXRequestNoticeController":       SQLLight,
	"VEXStatementExpiryController":     SQLLight,
}
