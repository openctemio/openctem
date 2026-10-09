package routes

import (
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// commentReactionsPerMinute caps reaction add/remove requests per user.
const commentReactionsPerMinute = 60

// registerExposureRoutes registers exposure event management endpoints.
// Exposures are tenant-scoped attack surface changes.
func registerExposureRoutes(
	router Router,
	h *handler.ExposureHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Build tenant middleware chain from JWT token.
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	// Exposure routes - tenant from JWT token
	router.Group("/api/v1/exposures", func(r Router) {
		// Stats endpoint (must be before /{id} to avoid matching)
		r.GET("/stats", h.GetStats, middleware.RequireAll(permission.FindingsRead, permission.ExposuresRead))

		// Bulk ingest (must be before /{id} to avoid matching)
		r.POST("/ingest", h.BulkIngest, middleware.RequireAll(permission.FindingsWrite, permission.ExposuresWrite))

		// Read operations
		r.GET("/", h.List, middleware.RequireAll(permission.FindingsRead, permission.ExposuresRead))
		r.GET("/{id}", h.Get, middleware.RequireAll(permission.FindingsRead, permission.ExposuresRead))

		// Write operations
		r.POST("/", h.Create, middleware.RequireAll(permission.FindingsWrite, permission.ExposuresWrite))

		// State transitions
		r.POST("/{id}/resolve", h.Resolve, middleware.RequireAll(permission.FindingsWrite, permission.ExposuresTriage))
		// Accepting the risk of, or dismissing, an exposure is the same
		// disposition a finding can only reach through the approval workflow
		// (FindingStatus.RequiresApproval: accepted / false_positive), so it
		// needs the approver permission, not findings:write. Exposures have no
		// request/approve records of their own; the approver sets the state
		// directly, with the reason recorded in the state history.
		r.POST("/{id}/accept", h.Accept, middleware.RequireAll(permission.FindingsApprove, permission.ExposuresTriage))
		r.POST("/{id}/false-positive", h.MarkFalsePositive, middleware.RequireAll(permission.FindingsApprove, permission.ExposuresTriage))
		r.POST("/{id}/reactivate", h.Reactivate, middleware.RequireAll(permission.FindingsWrite, permission.ExposuresTriage))

		// CTEM-ID tag: associate a standardized exposure-catalog id with this
		// exposure (stored on the exposure's details; no schema change).
		r.PUT("/{id}/ctem-id", h.SetCTEMID, middleware.RequireAll(permission.FindingsWrite, permission.ExposuresWrite))

		// History
		r.GET("/{id}/history", h.GetHistory, middleware.RequireAll(permission.FindingsRead, permission.ExposuresRead))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.RequireAll(permission.FindingsDelete, permission.ExposuresDelete))
	}, tenantMiddlewares...)
}

// registerThreatIntelRoutes registers threat intelligence endpoints.
// Threat intel provides global EPSS scores and KEV catalog data.
// Permission model:
// - Read (GET): vulnerabilities:read permission
// - Write (POST, PATCH): admin only
func registerThreatIntelRoutes(
	router Router,
	h *handler.ThreatIntelHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build base middleware chain (no tenant required - global data)
	baseMiddlewares := buildBaseMiddlewares(authMiddleware, userSyncMiddleware)

	// Threat Intel routes - global data accessible to authenticated users
	router.Group("/api/v1/threat-intel", func(r Router) {
		// Unified stats endpoint (combines EPSS, KEV, and sync status)
		r.GET("/stats", h.GetThreatIntelStats, middleware.Require(permission.VulnerabilitiesRead))

		// Sync status and management (admin operations)
		r.GET("/sync", h.GetSyncStatuses, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/sync/{source}", h.GetSyncStatus, middleware.Require(permission.VulnerabilitiesRead))
		// The feed syncs are platform-wide: an organization may neither run
		// nor toggle them, so there is no write route here. Operators use
		// /api/v1/admin/threat-intel.

		// CVE enrichment (combine EPSS + KEV data)
		r.GET("/enrich/{cveId}", h.EnrichCVE, middleware.Require(permission.VulnerabilitiesRead))
		r.POST("/enrich", h.EnrichCVEs, middleware.Require(permission.VulnerabilitiesRead))

		// EPSS scores (must have stats before {cveId} to avoid route conflicts)
		r.GET("/epss/stats", h.GetEPSSStats, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/epss/{cveId}", h.GetEPSSScore, middleware.Require(permission.VulnerabilitiesRead))

		// KEV catalog (must have stats before {cveId} to avoid route conflicts)
		r.GET("/kev/stats", h.GetKEVStats, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/kev/{cveId}", h.GetKEVEntry, middleware.Require(permission.VulnerabilitiesRead))
	}, baseMiddlewares...)
}

// registerCredentialRoutes registers credential leak management endpoints.
// Credentials are tenant-scoped (tenant from JWT token).
func registerCredentialRoutes(
	router Router,
	h *handler.CredentialImportHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Build tenant middleware chain from JWT token, then the module gate.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	// Credential routes - tenant from JWT token (admin interface)
	router.Group("/api/v1/credentials", func(r Router) {
		// List credentials (must be before /{id} to avoid conflicts)
		r.GET("/", h.List, middleware.Require(permission.CredentialsRead))

		// Stats endpoint (must be before other routes to avoid conflicts)
		r.GET("/stats", h.GetStats, middleware.Require(permission.CredentialsRead))

		// Enum values (for UI dropdowns)
		r.GET("/enums", h.GetEnums, middleware.Require(permission.CredentialsRead))

		// Identity-centric view (credentials grouped by username/email)
		r.GET("/identities", h.ListByIdentity, middleware.Require(permission.CredentialsRead))

		// Get exposures for a specific identity (lazy load)
		r.GET("/identities/{identity}/exposures", h.GetExposuresForIdentity, middleware.Require(permission.CredentialsRead))

		// Import endpoints
		r.POST("/import", h.Import, middleware.Require(permission.CredentialsWrite))
		r.POST("/import/csv", h.ImportCSV, middleware.Require(permission.CredentialsWrite))
		r.GET("/import/template", h.GetTemplate, middleware.Require(permission.CredentialsRead))

		// Get single credential by ID
		r.GET("/{id}", h.GetByID, middleware.Require(permission.CredentialsRead))

		// Reveal the plaintext secret. Read returns only a mask and a
		// fingerprint; this needs its own permission and a recent sign-in
		// (step-up), and is audited.
		r.POST("/{id}/reveal", h.RevealSecret, middleware.Require(permission.CredentialsReveal), requireStepUp())

		// Get related credentials (same identity)
		r.GET("/{id}/related", h.GetRelatedCredentials, middleware.Require(permission.CredentialsRead))

		// State change endpoints
		r.POST("/{id}/resolve", h.Resolve, middleware.Require(permission.CredentialsWrite))
		// Accept and false-positive set the same exposure dispositions that
		// /exposures/{id}/accept and /false-positive gate on the approver
		// permission, so they need findings:approve as well as credentials:write.
		r.POST("/{id}/accept", h.Accept, middleware.RequireAll(permission.CredentialsWrite, permission.FindingsApprove))
		r.POST("/{id}/false-positive", h.MarkFalsePositive, middleware.RequireAll(permission.CredentialsWrite, permission.FindingsApprove))
		r.POST("/{id}/reactivate", h.Reactivate, middleware.Require(permission.CredentialsWrite))
	}, tenantMiddlewares...)

}

// registerVulnerabilityRoutes registers vulnerability and finding management endpoints.
// Vulnerabilities are global (CVE database), Findings are tenant-scoped (tenant from JWT token).
func registerVulnerabilityRoutes(
	router Router,
	h *handler.VulnerabilityHandler,
	findingActionsHandler *handler.FindingActionsHandler,
	jiraHandler *handler.JiraWebhookHandler,
	remediationGroupHandler *handler.RemediationGroupHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build base middleware chain
	baseMiddlewares := buildBaseMiddlewares(authMiddleware, userSyncMiddleware)

	// Vulnerability routes - global CVE database (no tenant required for catalog ops).
	// EXCEPTION: /{id}/affected-assets and /cve/{cveId}/affected-assets are
	// blast-radius reverse lookups that JOIN findings × assets — those need
	// tenant context. We apply middleware.RequireTenant() per-route below
	// (chi doesn't allow two Group() blocks on the same mount path).
	router.Group("/api/v1/vulnerabilities", func(r Router) {
		// Read operations
		r.GET("/", h.ListVulnerabilities, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/{id}", h.GetVulnerability, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/cve/{cveId}", h.GetVulnerabilityByCVE, middleware.Require(permission.VulnerabilitiesRead))

		// Blast-radius reverse lookups + Active CVEs (tenant-scoped). Use
		// tenantOverlayMiddlewares() to apply RequireTenant + active-membership
		// + CSRF + rate-limit per-route, since chi forbids mounting a second
		// Group on the same path. See routes.go.
		tenantScopedMW := append(tenantOverlayMiddlewares(),
			middleware.Require(permission.VulnerabilitiesRead))
		// IMPORTANT: register /active/stats BEFORE /active and /{id} so the
		// most-specific literal path wins.
		r.GET("/active/stats", h.GetActiveCVEStats, tenantScopedMW...)
		r.GET("/active", h.ListActiveCVEs, tenantScopedMW...)
		r.GET("/{id}/affected-assets", h.ListAffectedAssets, tenantScopedMW...)
		r.GET("/cve/{cveId}/affected-assets", h.ListAffectedAssetsByCVE, tenantScopedMW...)

		// There are no writes to the shared CVE catalog: one organization must
		// not decide what every other one sees (405 for every tenant role).
		// See docs/architecture/global-catalog-trust.md.
	}, baseMiddlewares...)

	// Build tenant middleware chain from JWT token (used by /findings group below)
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Finding routes - tenant from JWT token
	router.Group("/api/v1/findings", func(r Router) {
		// Read operations
		r.GET("/", h.ListFindings, middleware.Require(permission.FindingsRead))

		// Stats endpoint (must be before /{id} to avoid route conflicts)
		r.GET("/stats", h.GetFindingStats, middleware.Require(permission.FindingsRead))

		// The FilterDocument form of the list (RFC-048): read-only, same
		// permission and scope as GET /findings.
		r.POST("/search", h.SearchFindings, middleware.Require(permission.FindingsRead))

		// Server-side export (RFC-048): the list's filter, scoped, streamed,
		// one per user at a time, audit-logged.
		r.GET("/export", h.ExportFindings, middleware.Require(permission.FindingsExport))
		r.POST("/export", h.ExportFindingsDocument, middleware.Require(permission.FindingsExport))

		// Groups + Related CVEs (must be before /{id})
		if findingActionsHandler != nil {
			r.GET("/groups", findingActionsHandler.ListFindingGroups, middleware.Require(permission.FindingsRead))
			r.GET("/related-cves/{cveId}", findingActionsHandler.GetRelatedCVEs, middleware.Require(permission.FindingsRead))
		}

		// Bulk operations (must be before /{id})
		r.POST("/bulk/status", h.BulkUpdateFindingsStatus, middleware.Require(permission.FindingsBulkUpdate))
		r.POST("/bulk/assign", h.BulkAssignFindings, middleware.Require(permission.FindingsBulkUpdate))

		// Remediation groups (RFC-015): one fix → many findings (must be before /{id}).
		if remediationGroupHandler != nil {
			r.GET("/remediation-groups", remediationGroupHandler.ListGroups, middleware.Require(permission.FindingsRead))
			r.POST("/remediation-groups/{key}/resolve", remediationGroupHandler.ResolveGroup, middleware.Require(permission.FindingsWrite))
		}

		// Actions (must be before /{id})
		if findingActionsHandler != nil {
			r.POST("/actions/fix-applied", findingActionsHandler.FixApplied, middleware.Require(permission.FindingsFixApply))
			r.POST("/actions/verify", findingActionsHandler.Verify, middleware.Require(permission.FindingsVerify))
			r.POST("/actions/reject-fix", findingActionsHandler.RejectFix, middleware.Require(permission.FindingsVerify))
			r.POST("/actions/assign-to-owners", findingActionsHandler.AssignToOwners, middleware.Require(permission.FindingsAssign))
		}

		// Single finding operations
		r.GET("/{id}", h.GetFinding, middleware.Require(permission.FindingsRead))
		// Priority explainability: why does this finding hold its P-class?
		r.GET("/{id}/priority-explanation", h.ExplainPriority, middleware.Require(permission.FindingsRead))

		// Write operations
		r.POST("/", h.CreateFinding, middleware.Require(permission.FindingsWrite))
		r.PATCH("/{id}/status", h.UpdateFindingStatus, middleware.Require(permission.FindingsStatus))

		// Assignment operations
		r.POST("/{id}/assign", h.AssignFinding, middleware.Require(permission.FindingsAssign))
		r.POST("/{id}/unassign", h.UnassignFinding, middleware.Require(permission.FindingsAssign))

		// Classification and severity
		// Re-scoring is its own permission (findings:severity), so the person
		// who fixes a finding need not be able to lower its severity.
		r.PATCH("/{id}/classify", h.ClassifyFinding, middleware.Require(permission.FindingsSeverity))
		r.PATCH("/{id}/severity", h.UpdateFindingSeverity, middleware.Require(permission.FindingsSeverity))

		// Triage and verification
		r.PATCH("/{id}/triage", h.TriageFinding, middleware.Require(permission.FindingsTriage))
		// Mark duplicate (RFC-043 §9): a triage decision that folds the finding
		// in the body into this one; merging with an approval disposition
		// also needs findings:approve (checked in the service).
		r.POST("/{id}/duplicates", h.AddFindingDuplicate, middleware.Require(permission.FindingsTriage))
		// Verification is a segregation-of-duties control: moving a finding to
		// resolved must require FindingsVerify (security/scanner), NOT the
		// broader FindingsWrite that a developer role holds — otherwise a member
		// could self-verify here what the sibling /actions/verify correctly
		// gates on FindingsVerify.
		r.POST("/{id}/verify", h.VerifyFinding, middleware.Require(permission.FindingsVerify))

		// The whole-asset "request verification scan" is retired (RFC-039 D4):
		// Retest now (POST /{id}/retests) re-runs the finding's own check.
		if findingActionsHandler != nil {
			// CTEM Stage-4: dispatch a validation (safe-check) job for this finding.
			r.POST("/{id}/validate", findingActionsHandler.RequestValidation, middleware.Require(permission.FindingsWrite))
		}

		// Tags
		r.PUT("/{id}/tags", h.SetFindingTags, middleware.Require(permission.FindingsWrite))

		// Data flows (attack paths / taint tracking)
		r.GET("/{id}/dataflows", h.GetFindingDataFlows, middleware.Require(permission.FindingsRead))

		// Manual remediation steps (append-preserving) on generic findings.
		// NOTE: manual evidence lives on the /{id}/evidence mount registered by
		// registerValidationRoutes (chi forbids a second mount on that path).
		r.POST("/{id}/remediation/steps", h.AddRemediationStep, middleware.Require(permission.FindingsWrite))

		// CTEM Mobilization guidance: definition of done + acceptable fixes.
		r.PATCH("/{id}/remediation", h.UpdateRemediation, middleware.Require(permission.FindingsWrite))

		// Jira: open a ticket for a finding.
		if jiraHandler != nil {
			r.POST("/{id}/create-ticket", jiraHandler.CreateTicket, middleware.Require(permission.FindingsWrite))
		}

		// Delete operations
		r.DELETE("/{id}", h.DeleteFinding, middleware.Require(permission.FindingsDelete))
	}, tenantMiddlewares...)

	// The findings filter contract (RFC-048): fields, operators, limits.
	router.Group("/api/v1/meta/filters", func(r Router) {
		r.GET("/findings", h.FindingFilterMeta, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)

	// Asset-scoped finding routes
	router.Group("/api/v1/assets/{id}/findings", func(r Router) {
		r.GET("/", h.ListAssetFindings, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)

	// Finding comment routes - tenant from JWT token
	router.Group("/api/v1/findings/{id}/comments", func(r Router) {
		r.GET("/", h.ListComments, middleware.Require(permission.FindingsRead))
		r.POST("/", h.AddComment, middleware.Require(permission.FindingsComment))
		r.PUT("/{comment_id}", h.UpdateComment, middleware.Require(permission.FindingsComment))
		r.DELETE("/{comment_id}", h.DeleteComment, middleware.Require(permission.FindingsComment))
	}, tenantMiddlewares...)

	// Emoji reactions on finding comments. Same permission as posting a
	// comment (findings:comment); the service also requires read access to the comment's finding
	// (data scope, pentest campaign membership). Rate limited per user.
	reactionRL := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled:         true,
		RequestsPerSec:  commentReactionsPerMinute / 60.0,
		Burst:           commentReactionsPerMinute,
		CleanupInterval: 5 * time.Minute,
	}, nil)
	router.Group("/api/v1/comments/{comment_id}/reactions", func(r Router) {
		r.POST("/", h.AddCommentReaction, middleware.Require(permission.FindingsComment), reactionRL.UserMiddleware())
		r.DELETE("/{emoji}", h.RemoveCommentReaction, middleware.Require(permission.FindingsComment), reactionRL.UserMiddleware())
	}, tenantMiddlewares...)

	// Finding approval routes - tenant from JWT token
	router.Group("/api/v1/findings/{id}/approvals", func(r Router) {
		r.GET("/", h.ListFindingApprovals, middleware.Require(permission.FindingsRead))
		r.POST("/", h.RequestApproval, middleware.Require(permission.FindingsWrite))
	}, tenantMiddlewares...)

	// Approval management routes - tenant from JWT token
	router.Group("/api/v1/approvals", func(r Router) {
		r.GET("/", h.ListApprovals, middleware.Require(permission.FindingsRead))
		r.POST("/{id}/approve", h.ApproveApproval, middleware.Require(permission.FindingsApprove))
		r.POST("/{id}/reject", h.RejectApproval, middleware.Require(permission.FindingsApprove))
		r.POST("/{id}/cancel", h.CancelApproval, middleware.Require(permission.FindingsWrite))
	}, tenantMiddlewares...)

}

// registerFindingActivityRoutes registers finding activity endpoints.
// Activities are tenant-scoped (tenant from JWT token) and APPEND-ONLY.
// Rate limiting is applied to prevent enumeration and DoS attacks.
// Real-time updates are delivered via WebSocket (see registerWebSocketRoutes in misc.go).
func registerFindingActivityRoutes(
	router Router,
	h *handler.FindingActivityHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	rateLimiter *middleware.FindingActivityRateLimiter,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add rate limiting middleware if enabled
	if rateLimiter != nil {
		tenantMiddlewares = append(tenantMiddlewares, rateLimiter.ListMiddleware())
	}

	// Finding activity routes - tenant from JWT token
	router.Group("/api/v1/findings/{id}/activities", func(r Router) {
		r.GET("/", h.ListActivities, middleware.Require(permission.FindingsRead))
		// Note: Activities are created automatically via service hooks, not via direct API
		// Real-time updates are delivered via WebSocket channel: finding:{id}
	}, tenantMiddlewares...)
}

// registerAITriageRoutes registers AI triage endpoints.
// AI triage is tenant-scoped (tenant from JWT token).
// Rate limiting is applied to POST endpoints to prevent abuse of expensive LLM calls.
//
// Endpoints:
// - POST /api/v1/findings/{id}/ai-triage - Request AI triage for a finding (rate-limited)
// - POST /api/v1/findings/ai-triage/bulk - Bulk triage multiple findings (rate-limited)
// - GET /api/v1/findings/{id}/ai-triage - Get latest triage result
// - GET /api/v1/findings/{id}/ai-triage/history - Get triage history
// - GET /api/v1/findings/{id}/ai-triage/{triageId} - Get specific triage result
// - GET /api/v1/findings/ai-triage/config - Get AI configuration info
func registerAITriageRoutes(
	router Router,
	h *handler.AITriageHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	rateLimiter *middleware.AITriageRateLimiter,
	moduleGate Middleware,
) {
	// Build tenant middleware chain from JWT token; the ai_triage module gate
	// runs after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	// Add rate limiter to POST endpoints if available
	var postMiddlewares []Middleware
	postMiddlewares = append(postMiddlewares, tenantMiddlewares...)
	if rateLimiter != nil {
		postMiddlewares = append(postMiddlewares, rateLimiter.RequestMiddleware())
	}

	// AI triage routes - tenant from JWT token
	router.Group("/api/v1/findings/{id}/ai-triage", func(r Router) {
		// Get latest triage result (must be before /{triageId} to avoid conflicts)
		r.GET("/", h.GetTriageResult, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))

		// Get triage history (must be before /{triageId} to avoid conflicts)
		r.GET("/history", h.ListTriageHistory, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))

		// Get specific triage result by ID
		r.GET("/{triageId}", h.GetTriageResultByID, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))
	}, tenantMiddlewares...)

	// Trigger AI triage for a finding (rate-limited)
	router.POST("/api/v1/findings/{id}/ai-triage", h.RequestTriage,
		append(postMiddlewares, middleware.RequireAll(permission.FindingsWrite, permission.AITriageTrigger))...)

	// Bulk triage multiple findings (rate-limited; each finding counts toward
	// the limit). Deprecated: nothing in the console or the SDK calls it, and
	// it is documented publicly, so it carries Deprecation/Sunset headers for
	// a release before it is removed; triage one finding at a time.
	bulkTriageDeprecated := middleware.Deprecated(middleware.Deprecation{
		Plane:        "user",
		Route:        "findings_ai_triage_bulk",
		Successor:    "/api/v1/findings/{id}/ai-triage",
		DeprecatedAt: time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC),
		SunsetAt:     time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC),
	})
	router.POST("/api/v1/findings/ai-triage/bulk", h.RequestBulkTriage,
		append(append([]Middleware{bulkTriageDeprecated}, postMiddlewares...),
			middleware.RequireAll(permission.FindingsWrite, permission.AITriageTrigger))...)

	// AI triage config endpoint - returns current AI mode, provider, model
	router.GET("/api/v1/findings/ai-triage/config", h.GetConfig,
		append(tenantMiddlewares, middleware.RequireAll(permission.FindingsRead, permission.AITriageRead))...)
}
