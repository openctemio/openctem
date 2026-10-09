// Package routes registers all HTTP routes for the API.
// Routes are organized by domain for maintainability.
package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/sensortransport"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/keycloak"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Middleware is an alias to the http package's Middleware type.
type Middleware = infrahttp.Middleware

// Router is an alias to the http package's Router interface.
type Router = infrahttp.Router

// Handlers holds all HTTP handlers for route registration.
type Handlers struct {
	Health           *handler.HealthHandler
	ClientErrors     *handler.ClientErrorHandler
	Auth             *handler.AuthHandler             // OIDC auth info handler
	LocalAuth        *handler.LocalAuthHandler        // Local auth handler (nil if OIDC-only)
	OAuth            *handler.OAuthHandler            // OAuth handler for social login (nil if not configured)
	Asset            *handler.AssetHandler            // nil if not initialized (no database)
	Tenant           *handler.TenantHandler           // nil if not initialized (no database)
	User             *handler.UserHandler             // nil if not initialized (no database)
	Component        *handler.ComponentHandler        // nil if not initialized (no database)
	Vulnerability    *handler.VulnerabilityHandler    // nil if not initialized (no database)
	RemediationGroup *handler.RemediationGroupHandler // nil if not initialized (no database)
	MCP              *handler.MCPHandler              // read-only MCP server; nil if not initialized
	// MCPAuth is the tenant-scoped `oct_` API-key auth middleware guarding the
	// MCP endpoint. Set alongside MCP; nil disables the endpoint.
	MCPAuth Middleware
	// MCPDiscovery is the OAuth discovery of the MCP endpoint (Protected
	// Resource Metadata, 401 challenge, Origin guard). nil without a public URL.
	MCPDiscovery *MCPDiscovery
	// MCPOAuth is the authorization server of the MCP endpoint (RFC-062);
	// nil without discovery or a database.
	MCPOAuth *handler.MCPOAuthHandler
	// MCPSettings is the organization MCP policy (RFC-062 §8).
	MCPSettings *handler.MCPSettingsHandler
	// MCPConnections is the connected applications (RFC-062 §12), tenant
	// and platform console; nil without the authorization server.
	MCPConnections *handler.MCPConnectionsHandler
	// APIKeyAuth authenticates `oct_` API keys on the tenant REST routes (the
	// token-tenant chains), read-only. Share the instance behind MCPAuth so a
	// key has one rate-limit budget. nil leaves the REST API JWT-only.
	APIKeyAuth      *middleware.APIKeyAuthMiddleware
	FindingActivity *handler.FindingActivityHandler // nil if not initialized (no database)
	// Note: Real-time updates moved to WebSocket (see WebSocket field below)
	AITriage      *handler.AITriageHandler      // Always initialized - handles nil service gracefully
	Dashboard     *handler.DashboardHandler     // nil if not initialized (no database)
	UserDashboard *handler.UserDashboardHandler // nil if not initialized - per-user customizable dashboards (RFC-021)
	SavedView     *handler.SavedViewHandler     // nil if not initialized - saved list views (D15, RFC-048)
	Audit         *handler.AuditHandler         // nil if not initialized (no database)
	Branch        *handler.BranchHandler        // nil if not initialized (no database)
	SLA           *handler.SLAHandler           // nil if not initialized (no database)
	Integration   *handler.IntegrationHandler   // nil if not initialized (no database)
	DefectDojo    *handler.DefectDojoHandler    // nil if not initialized / no DefectDojo sync
	AssetGroup    *handler.AssetGroupHandler    // nil if not initialized (no database)
	Scope         *handler.ScopeHandler         // nil if not initialized (no database)
	AssetType     *handler.AssetTypeHandler     // nil if not initialized (no database)
	AttackSurface *handler.AttackSurfaceHandler // nil if not initialized (no database)
	EASM          *handler.EASMHandler          // RFC-036 overview; nil if not initialized
	// EASMVerifiedDomain is tenant self-service domain verification
	// (research/22 P0-10); nil if not initialized.
	EASMVerifiedDomain *handler.EASMVerifiedDomainHandler
	// EASMSettings is attack-surface monitoring settings and run-now
	// (research/22 P0-11); nil if not initialized.
	EASMSettings *handler.EASMSettingsHandler
	Docs         *handler.DocsHandler    // API documentation handler
	Command      *handler.CommandHandler // nil if not initialized (no database)
	Ingest       *handler.IngestHandler  // nil if not initialized (no database) - sensor authentication and heartbeat
	// SensorResultsV2 serves sensor protocol v2 results (RFC-026); nil unless
	// SENSOR_PROTOCOL_V2_RESULTS is on, and then /api/v2/sensor is not mounted.
	SensorResultsV2 *handler.SensorResultsV2Handler
	// SensorV3 serves sensor protocol v3 (RFC-059); nil unless
	// SENSOR_TRANSPORT_V3_ENABLED. Register attaches the in-process v2 route
	// group it serves through; the HTTPS binding is mounted by the caller
	// (Server.MountPrefix).
	SensorV3 *sensortransport.Server
	// SensorPairing serves interactive pairing (RFC-052); nil when disabled.
	SensorPairing *handler.SensorPairingHandler
	IOC           *handler.IOCHandler        // nil if not initialized - IOC catalog (feeds B6 correlator)
	Validation    *handler.ValidationHandler // nil if not initialized - CTEM Stage-4 validation evidence
	SCIM          *handler.SCIMHandler       // nil if not initialized - SCIM 2.0 provisioning (RFC-009)
	SCIMToken     *handler.SCIMTokenHandler  // nil if not initialized - SCIM token admin
	SCIMAuth      Middleware                 // SCIM bearer-token auth middleware (nil if SCIM disabled)
	ModuleGate    *middleware.ModuleGate     // per-tenant module route gating (nil-safe: fail-open)
	// DataScope enforces the Layer 2 (group) data scope on every by-id asset
	// and finding route of the token-tenant chain (DataScopeGuard). nil
	// disables the guard (tests with a minimal handler set).
	DataScope     middleware.DataScopeAsserter
	Sensor        *handler.SensorHandler           // nil if not initialized (no database)
	SensorContent *handler.SensorContentHandler    // scanner content policy + refresh (RFC-031); nil without a database
	SensorResults *handler.SensorResultHandler     // unsolicited results policy + quarantine review (RFC-040); nil without a database
	ScanZone      *handler.ScanZoneHandler         // nil if not initialized (no database)
	ScanFreeze    *handler.ScanFreezeWindowHandler // nil if not initialized (no database)
	ScanWorkflow  *handler.ScanWorkflowHandler     // nil if not initialized (no database)
	ScanProfile   *handler.ScanProfileHandler      // nil if not initialized (no database)
	Tool          *handler.ToolHandler             // nil if not initialized (no database)
	ToolCategory  *handler.ToolCategoryHandler     // nil if not initialized (no database)
	Capability    *handler.CapabilityHandler       // nil if not initialized (no database)
	Scan          *handler.ScanHandler             // nil if not initialized (no database)
	CI            *handler.CIHandler               // nil if not initialized (no database) - CI/CD snippet generator
	// CIAdmin and CIRunner serve CI runs, trust and the gate (RFC-051); nil
	// without a database.
	CIAdmin         *handler.CIAdminHandler
	CIRunner        *handler.CIRunnerHandler
	ScannerTemplate *handler.ScannerTemplateHandler // nil if not initialized (no database)
	TemplateSource  *handler.TemplateSourceHandler  // nil if not initialized (no database)
	ContentPack     *handler.ContentPackHandler     // nil if not initialized (no database)
	SecretStore     *handler.SecretStoreHandler     // nil if not initialized (no database)

	Exposure         *handler.ExposureHandler         // nil if not initialized (no database)
	ThreatIntel      *handler.ThreatIntelHandler      // nil if not initialized (no database)
	CTEMID           *handler.CTEMIDHandler           // nil if not initialized (no database)
	CredentialImport *handler.CredentialImportHandler // nil if not initialized (no database)
	Workflow         *handler.WorkflowHandler         // nil if not initialized (no database)
	Suppression      *handler.SuppressionHandler      // nil if not initialized (no database)

	// CTEM Discovery handlers
	AssetService           *handler.AssetServiceHandler           // nil if not initialized (no database)
	WebEndpoint            *handler.WebEndpointHandler            // Web surface (RFC-056); nil without a database
	APISpec                *handler.APISpecHandler                // API descriptions of web origins (RFC-056)
	AssetStateHistory      *handler.AssetStateHistoryHandler      // nil if not initialized (no database)
	AssetIdentifier        *handler.AssetIdentifierHandler        // asset identity model; nil if not initialized
	AssetAttribution       *handler.AssetAttributionHandler       // RFC-036 attribution; nil if not initialized
	AssetRelationship      *handler.AssetRelationshipHandler      // nil if not initialized (no database)
	RelationshipSuggestion *handler.RelationshipSuggestionHandler // nil if not initialized (no database)

	// Access Control handlers
	Group          *handler.GroupHandler          // nil if not initialized (no database)
	Role           *handler.RoleHandler           // nil if not initialized (no database)
	Permission     *handler.PermissionHandler     // nil if not initialized (permission sync handler)
	AssignmentRule *handler.AssignmentRuleHandler // nil if not initialized (no database)
	ScopeRule      *handler.ScopeRuleHandler      // nil if not initialized (no database)
	AssetOwner     *handler.AssetOwnerHandler     // nil if not initialized (no database)

	// Finding Lifecycle (closed-loop: fix_applied → verified → resolved)
	FindingActions *handler.FindingActionsHandler // nil if not initialized (no database)
	// FindingRetest serves Retest now + retest history (RFC-039); nil if not initialized
	FindingRetest *handler.FindingRetestHandler
	// FindingEvidenceItems serves masked finding evidence + reveal; nil if not initialized
	FindingEvidenceItems *handler.FindingEvidenceItemsHandler

	// Jira Bidirectional Sync (link tickets to findings + receive Jira webhooks)
	JiraWebhook   *handler.JiraWebhookHandler   // nil if not initialized (no database)
	GitHubWebhook *handler.GitHubWebhookHandler // nil if not initialized (no database)

	// JiraWebhookSecretResolver resolves the per-tenant Jira inbound-webhook
	// HMAC secrets (stored on each tenant's Jira integration). When non-nil,
	// the incoming-webhook route verifies against the requesting tenant's own
	// secrets (plus the platform fallback), closing the cross-tenant spoofing
	// gap of a single shared secret. nil falls back to the platform secret only.
	JiraWebhookSecretResolver JiraWebhookSecretResolver

	// Pentest Campaign Management handlers
	Pentest                *handler.PentestHandler        // nil if not initialized (no database)
	PentestCampaignRoleQry middleware.CampaignRoleQuerier // Campaign role resolver for RBAC middleware

	// File Attachments (shared across pentest, retest, campaign)
	Attachment *handler.AttachmentHandler // nil if not initialized

	// Compliance Framework Management handlers
	Compliance *handler.ComplianceHandler // nil if not initialized (no database)

	// Attack Simulation & Control Testing
	Simulation *handler.SimulationHandler // nil if not initialized (no database)

	// Threat Actor Intelligence
	ThreatActor *handler.ThreatActorHandler // nil if not initialized (no database)

	// Remediation Campaigns
	RemediationCampaign *handler.RemediationCampaignHandler // nil if not initialized
	ReportSchedule      *handler.ReportScheduleHandler      // nil if not initialized

	// Business Units
	BusinessUnit *handler.BusinessUnitHandler // nil if not initialized

	// Business Services (distinct from Business Units — represent business capabilities)
	BusinessService *handler.BusinessServiceHandler // nil if not initialized

	// CTEM RFC-005 handlers (direct SQL, no DDD repo layer yet)
	CompensatingControl   *handler.CompensatingControlHandler   // nil if not initialized
	AttackerProfile       *handler.AttackerProfileHandler       // nil if not initialized
	CTEMCycle             *handler.CTEMCycleHandler             // nil if not initialized
	VerificationChecklist *handler.VerificationChecklistHandler // nil if not initialized
	PriorityRule          *handler.PriorityRuleHandler          // nil if not initialized
	ThreatModel           *handler.ThreatModelHandler           // nil if not initialized
	Scoping               *handler.ScopingHandler               // nil if not initialized

	// Asset Import (K8s, CSV)
	AssetImport *handler.AssetImportHandler // nil if not initialized

	// Finding import (exports of other tools, VEX documents)
	FindingImport *handler.FindingImportHandler // nil if not initialized

	// Configuration handlers (read-only system config)
	FindingSource *handler.FindingSourceHandler // nil if not initialized (no database)

	// API Keys & Webhooks
	APIKey *handler.APIKeyHandler // nil if not initialized (no database)

	// Notification handlers
	Notification *handler.NotificationHandler // nil if not initialized (no database)
	Outbox       *handler.OutboxHandler       // nil if not initialized (no database)

	// Bootstrap handler (combines multiple endpoints into one)
	Bootstrap *handler.BootstrapHandler // nil if not initialized (no database)

	// Admin Auth handler (API key authentication for Admin UI)
	AdminAuth         *handler.AdminAuthHandler
	AdminOrganization *handler.AdminOrganizationHandler
	AdminOverview     *handler.AdminOverviewHandler
	AdminPlatformUser *handler.AdminPlatformUserHandler
	AdminSession      *handler.AdminSessionHandler
	// AdminSupportRateLimiter caps console support actions per administrator.
	AdminSupportRateLimiter *middleware.AdminMappingRateLimiter
	AdminConsole            *handler.AdminConsoleHandler
	AdminAuditChain         *handler.AdminAuditChainHandler
	// AccessRequest: the request-access queue (public form + console).
	AccessRequest *handler.AccessRequestHandler
	// Plan: plans and limits (console plan defaults, organization plans and
	// overrides, the organization's own usage).
	Plan *handler.PlanHandler
	// IdleWorkspace: an organization's idle lifecycle in the console.
	IdleWorkspace *handler.IdleWorkspaceHandler
	// IdleReadOnly refuses changes to an idle Free organization (read-only
	// after 90 days without a sign-in).
	IdleReadOnly middleware.IdleReadOnlyChecker
	// AdminSignup: Console > System > Sign-up (the sign-up policy).
	AdminSignup *handler.AdminSignupHandler
	// SignupPolicy answers the sign-up policy to the public auth endpoints.
	SignupPolicy        signupdom.PolicySource
	AdminAuthMiddleware *middleware.AdminAuthMiddleware

	// Admin Audit middleware (audit logging for admin operations)
	AdminAuditMiddleware *middleware.AuditMiddleware

	// Admin Mapping rate limiter (10 req/min for write operations)
	AdminMappingRateLimiter *middleware.AdminMappingRateLimiter

	// Admin management handlers (CRUD for admin users, audit logs, target mappings)
	AdminUser          *handler.AdminUserHandler
	AdminAudit         *handler.AdminAuditHandler
	AdminTargetMapping *handler.AdminTargetMappingHandler
	AdminDedup         *handler.AdminDedupHandler // RFC-001: Asset dedup review

	// SSO handler (per-tenant SSO authentication)
	SSO  *handler.SSOHandler  // nil if not initialized
	SAML *handler.SAMLHandler // nil if not initialized - SAML 2.0 SP (RFC-009)
	// SSOChange lists and decides admin-console SSO changes that wait for an
	// owner's approval (RFC-022). nil if SAML/SSO is not initialized.
	SSOChange *handler.SSOChangeHandler

	// VerifiedDomain handler (SSO P1 domain-ownership verification)
	VerifiedDomain *handler.VerifiedDomainHandler // nil if not initialized
	// OrgTrust: trusted organizations (RFC-058); nil if not initialized.
	OrgTrust *handler.OrgTrustHandler

	// Platform Stats handler (tenant-scoped platform sensor stats)
	PlatformScanning *handler.PlatformScanningHandler

	// WebSocket handler for real-time communication
	WebSocket *websocket.Handler

	// F-8: Optional single-use WebSocket ticket redeemer. When non-nil,
	// the /ws route uses ticket auth instead of the JWT chain.

	// AuthRateLimitBackend is the shared store (Redis) the public auth rate
	// limits count in, so every API replica spends one budget. nil keeps them
	// in-memory per process (tests, single-instance dev).
	AuthRateLimitBackend middleware.AuthRateLimitBackend

	// StepUp answers the step-up check on sensitive routes. nil uses the
	// local auth handler's (sessions.step_up_at); route tests that are not
	// about step-up pass a stub. No checker at all refuses those routes.
	StepUp middleware.RecentAuthChecker
}

// AuthConfig holds authentication configuration for route registration.
type AuthConfig struct {
	Provider       config.AuthProvider
	LocalValidator *jwt.Generator
	OIDCValidator  *keycloak.Validator
	// RevokedSessions makes a signed-out session's access tokens fail on the
	// next request (nil = they stay valid until they expire).
	RevokedSessions middleware.RevokedSessionChecker
}

// Register registers all application routes.
// This keeps route definitions in the infrastructure layer, not in main.
//
// Routes are organized across multiple files by domain:
//   - auth.go: Authentication (login, register, OAuth)
//   - tenant.go: Tenant management
//   - assets.go: Assets, components, asset groups, scope
//   - scanning.go: Sensors, commands, scans, scan workflows, tools
//   - exposure.go: Exposures, threat intel, credentials
//   - access_control.go: Groups, roles, permissions
//   - platform.go: Platform sensors and jobs
//   - misc.go: Health, docs, dashboard, audit, SLA, integrations
//
//nolint:cyclop,gocognit // Route registration naturally has many branches
func Register(
	router Router,
	h Handlers,
	cfg *config.Config,
	log *logger.Logger,
	authCfg AuthConfig,
	tenantRepo tenant.Repository,
	userService *tenantapp.UserService,
	// Optional Redis-backed membership reader. When non-nil it is
	// used by RequireMembership and RequireActiveMembershipFromJWT
	// instead of querying the database directly. nil falls back to
	// tenantRepo (the legacy behavior).
	membershipReader middleware.MembershipReader,
	// Permission sync services. When both are non-nil, EnrichPermissions is
	// mounted on every token-tenant chain so revoked permissions / demoted
	// admins are enforced within the token lifetime (real-time sync). nil
	// disables it (legacy embedded-JWT-permission behavior).
	permCache *accesscontrol.PermissionCacheService,
	permVersion *accesscontrol.PermissionVersionService,
) {
	// Pick the membership reader: cache when available, repo otherwise.
	if membershipReader == nil {
		membershipReader = tenantRepo
	}
	// Create unified auth middleware based on provider
	unifiedAuthCfg := middleware.UnifiedAuthConfig{
		Provider:              authCfg.Provider,
		LocalValidator:        authCfg.LocalValidator,
		OIDCValidator:         authCfg.OIDCValidator,
		Logger:                log,
		SessionTimeoutMinutes: cfg.Server.SessionTimeoutMinutes,
		RevokedSessions:       authCfg.RevokedSessions,
		CookieName:            cfg.Auth.AccessTokenCookieName,
	}
	authMiddleware := middleware.UnifiedAuth(unifiedAuthCfg)

	// `oct_` API keys on the tenant REST routes. Only buildTokenTenantMiddlewares
	// uses it, so routes outside those chains (account, auth, admin console,
	// /tenants/{tenant}) stay JWT-only. Reset on every Register so a previous
	// router's setting can't leak into this one.
	authRateLimitBackend = h.AuthRateLimitBackend
	// Step-up re-authentication for sensitive routes. Reset on every Register
	// so a previous router's checker cannot leak into this one.
	stepUpChecker = h.StepUp
	if stepUpChecker == nil && h.LocalAuth != nil {
		stepUpChecker = h.LocalAuth.RecentAuthChecker()
	}
	apiKeyOrJWT = nil
	if h.APIKeyAuth != nil {
		apiKeyOrJWT = h.APIKeyAuth.OrJWT
	}
	// Health routes: /health and /ready are public; /metrics is gated by a
	// bearer token unless METRICS_PUBLIC=true (see MetricsConfig).
	registerHealthRoutes(router, h.Health, middleware.MetricsAuth(cfg.Metrics.Public, cfg.Metrics.Token, log))
	registerClientErrorRoute(router, h.ClientErrors, log)

	// API Documentation routes (public)
	if h.Docs != nil {
		registerDocsRoutes(router, h.Docs)
	}

	// Initialize per-user read endpoint rate limiter to prevent enumeration and scraping.
	// Applied to all GET requests on authenticated tenant-scoped routes via
	// buildTokenTenantMiddlewares (package-level variable).
	if cfg.RateLimit.Enabled {
		rl := middleware.NewReadEndpointRateLimiter(
			middleware.ReadEndpointRateLimitConfigFrom(cfg.RateLimit), log)
		readRateLimitMiddleware = rl.Middleware()
	}

	// Initialize the JWT-tenant membership check. This middleware is
	// appended to every chain returned by buildTokenTenantMiddlewares,
	// so any token-scoped route automatically rejects suspended users.
	// Uses the cache reader when wired, otherwise falls back to the
	// raw tenant repository.
	if membershipReader != nil {
		activeMembershipFromJWTMiddleware = middleware.RequireActiveMembershipFromJWT(membershipReader)
	}

	// CSRF (double-submit cookie). Two layers:
	//
	//   - UnifiedAuth (authMiddleware) rejects a state-changing request
	//     authenticated by the auth_token cookie unless it carries a
	//     matching csrf_token cookie + X-CSRF-Token header. That covers
	//     every user-authenticated route, including the groups mounted
	//     without the tenant chain (/users/me, /tenants/{tenant}, ...).
	//   - CSRFOptional, on the tenant chains below, additionally validates
	//     the pair whenever a csrf_token cookie is sent, and fails closed
	//     for cookie-authenticated requests.
	//
	// Clients that authenticate with a header (Bearer JWT, oct_ API keys,
	// sensor keys) are not ambient-credential requests — a cross-site page
	// cannot set Authorization — and pass without a CSRF token. Sensor
	// (/api/v2/sensor/*) and HMAC-verified webhook routes do not use these
	// chains at all.
	csrfProtectionMiddleware = middleware.CSRFOptional(middleware.NewCSRFConfig(cfg.Auth, log))

	// Real-time permission sync. When the permission cache + version services
	// are wired, EnrichPermissions refreshes each request's permissions from
	// Redis (DB fallback) and rejects state-mutating requests whose JWT
	// permission version is confirmed-stale (e.g. a role was revoked or an
	// admin demoted). Without it, permissions baked into the JWT stay live
	// until the token expires. Fails open on a Redis outage (see GetChecked).
	// A stale token's admin flag and role are re-read from the database
	// (tenantRepo, not the membership cache), so a demoted admin loses the
	// admin bypass on the next request, reads included.
	if permCache != nil {
		tenantPermissionChecker = permCache
	}
	if permCache != nil && permVersion != nil {
		permissionSyncMiddleware = middleware.NewPermissionSyncMiddleware(permCache, permVersion, log).
			WithTeamRoleReader(tenantRepo).EnrichPermissions
	}

	// Layer 2 data scope on by-id asset/finding routes (404 when out of scope).
	if h.DataScope != nil {
		dataScopeGuardMiddleware = middleware.DataScopeGuard(h.DataScope)
	}

	// Per-request SSO enforcement (defense-in-depth). Re-applies the mint-time
	// enforce-SSO decision on every authenticated request using the token's
	// auth_method claim, so a password token minted before a tenant enabled SSO
	// enforcement stops working immediately (bounded by the gate's TTL) instead
	// of at token expiry. Cheap exits for federated sessions and owners avoid any
	// tenant lookup. Appended to buildBaseMiddlewares so it covers both
	// token-tenant and URL-path tenant chains.
	if tenantRepo != nil {
		ssoEnforcementMiddleware = middleware.NewSSOEnforcementGate(
			tenantSSOEnforcedAdapter{repo: tenantRepo}, 60*time.Second, log,
		).Enforce
	}

	// Idle Free organizations are read-only after 90 days without a sign-in
	// (docs/architecture/idle-workspaces.md). Appended to
	// buildBaseMiddlewares; reads always pass.
	if h.IdleReadOnly != nil {
		idleReadOnlyMiddleware = middleware.IdleReadOnly(h.IdleReadOnly)
	}

	// Organization IP allowlist (Security.IPWhitelist) on user sessions.
	// Appended to buildBaseMiddlewares (token-scoped organization)
	// and to the /tenants/{tenant} chain (URL organization). Settings changes
	// invalidate the cached policy through the tenant handler.
	if tenantRepo != nil {
		ipGate := middleware.NewIPAllowlistGate(tenantSecurityPolicyAdapter{repo: tenantRepo}, 30*time.Second, log)
		ipAllowlistMiddleware = ipGate.Enforce
		if h.Tenant != nil {
			h.Tenant.SetSecurityPolicyInvalidator(ipGate.Invalidate)
		}
	}

	// UserSync middleware syncs authenticated users to local database
	// Supports both local auth and OIDC auth
	var userSync Middleware
	if userService != nil {
		userSync = middleware.UserSync(userService, log)
	}

	// Auth routes - based on provider (some protected, some public).
	// Registered AFTER the tenant-chain middlewares above are initialized.
	registerAuthRoutes(router, h, cfg, authCfg, authMiddleware, userSync, log)

	// Build identity for Help > About (any signed-in user).
	registerVersionRoute(router, authMiddleware)

	// User routes (protected with user sync for OIDC)
	if h.User != nil {
		registerUserRoutes(router, h.User, h.LocalAuth, authMiddleware, userSync, authCfg.Provider)
	}

	// Tenant routes (protected with user sync)
	if h.Tenant != nil {
		registerTenantRoutes(router, h.Tenant, authMiddleware, userSync, tenantRepo, membershipReader, h.LocalAuth, h.SSOChange)
		registerOrganizationPlanRoutes(router, h.Plan, authMiddleware, userSync)
	}

	// Asset routes (tenant from JWT token) - only if handler is initialized
	if h.Asset != nil {
		registerAssetRoutes(router, h.Asset, authMiddleware, userSync)
	}
	if h.AssetImport != nil {
		registerAssetImportRoutes(router, h.AssetImport, authMiddleware, userSync)
	}
	if h.FindingImport != nil {
		registerFindingImportRoutes(router, h.FindingImport, authMiddleware, userSync)
	}

	// Asset Owner routes (tenant from JWT token) - nested under assets
	if h.AssetOwner != nil {
		registerAssetOwnerRoutes(router, h.AssetOwner, authMiddleware, userSync)
	}

	// Component routes (tenant from JWT token)
	if h.Component != nil {
		registerComponentRoutes(router, h.Component, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleComponents))
	}

	// Asset Service routes (CTEM Discovery - network services on assets)
	if h.AssetService != nil {
		registerAssetServiceRoutes(router, h.AssetService, authMiddleware, userSync)
	}

	// Web surface: endpoints under their origin asset (RFC-056)
	if h.WebEndpoint != nil {
		registerWebEndpointRoutes(router, h.WebEndpoint, authMiddleware, userSync)
	}
	if h.APISpec != nil {
		registerAPISpecRoutes(router, h.APISpec, authMiddleware, userSync)
	}

	// Asset State History routes (CTEM Discovery - shadow IT detection, audit)
	if h.AssetAttribution != nil {
		registerAssetAttributionRoutes(router, h.AssetAttribution, authMiddleware, userSync)
	}
	if h.AssetIdentifier != nil {
		registerAssetIdentifierRoutes(router, h.AssetIdentifier, authMiddleware, userSync)
	}
	if h.AssetStateHistory != nil {
		registerAssetStateHistoryRoutes(router, h.AssetStateHistory, authMiddleware, userSync)
	}

	// Asset Relationship routes (CTEM Discovery - attack surface topology graph)
	if h.AssetRelationship != nil {
		registerAssetRelationshipRoutes(router, h.AssetRelationship, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleRelationships))
	}

	// Asset Dedup Review routes (RFC-001: merge duplicate assets)
	if h.AdminDedup != nil {
		registerAssetDedupRoutes(router, h.AdminDedup, authMiddleware, userSync)
	}

	// Relationship Suggestion routes (auto-generated relationship recommendations)
	if h.RelationshipSuggestion != nil {
		registerRelationshipSuggestionRoutes(router, h.RelationshipSuggestion, authMiddleware, userSync)
	}

	// Vulnerability routes (global) and Finding routes (tenant from JWT token)
	if h.Vulnerability != nil {
		registerVulnerabilityRoutes(router, h.Vulnerability, h.FindingActions, h.JiraWebhook, h.RemediationGroup, authMiddleware, userSync)
	}

	// Continuous retest (RFC-039): Retest now + a finding's retest history.
	registerFindingRetestRoutes(router, h.FindingRetest, authMiddleware, userSync)
	registerRetestSettingsRoutes(router, h.Tenant, authMiddleware, userSync)
	// Finding evidence: masked proof per detection / retest + audited reveal.
	registerFindingEvidenceItemRoutes(router, h.FindingEvidenceItems, authMiddleware, userSync, log)
	registerEvidenceSettingsRoutes(router, h.Tenant, authMiddleware, userSync)
	registerOrganizationMemberRoutes(router, h.LocalAuth, h.Tenant, authMiddleware, userSync)
	registerOrganizationTrustRoutes(router, h.OrgTrust, authMiddleware, userSync)

	// CTEM Stage-4 validation evidence (sensor ingest + finding evidence list)
	if h.Validation != nil {
		registerValidationRoutes(router, h.Validation, h.Vulnerability, h.Ingest, authMiddleware, userSync)
	}

	// SCIM 2.0 provisioning (RFC-009) — bearer-token provisioning + admin token mgmt
	if h.SCIM != nil || h.SCIMToken != nil {
		registerSCIMRoutes(router, h.SCIM, h.SCIMToken, h.SCIMAuth, authMiddleware, userSync)
	}

	// Incoming Jira webhook — public endpoint (no JWT), HMAC-gated (F-1).
	registerIncomingWebhookRoutes(router, h.JiraWebhook, h.JiraWebhookSecretResolver, cfg.Webhooks.JiraSecret, log)

	// Public GitHub webhook endpoint — verified in the handler via GitHub's
	// X-Hub-Signature-256 scheme (per-tenant secret), so no HMAC middleware.
	if h.GitHubWebhook != nil {
		router.POST("/api/v1/webhooks/incoming/github", h.GitHubWebhook.IncomingGitHubWebhook)
	}

	// Initialize finding activity rate limiter to prevent enumeration and DoS
	var activityRateLimiter *middleware.FindingActivityRateLimiter
	if cfg.RateLimit.Enabled {
		activityRateLimiter = middleware.NewFindingActivityRateLimiter(middleware.DefaultFindingActivityRateLimitConfig(), log)
	}

	// Finding Activity routes (tenant from JWT token)
	// Note: Real-time updates are delivered via WebSocket (channel: finding:{id})
	if h.FindingActivity != nil {
		registerFindingActivityRoutes(router, h.FindingActivity, authMiddleware, userSync, activityRateLimiter)
	}

	// Initialize AI triage rate limiter to prevent abuse of expensive LLM calls
	var aiTriageRateLimiter *middleware.AITriageRateLimiter
	if cfg.RateLimit.Enabled {
		aiTriageRateLimiter = middleware.NewAITriageRateLimiter(middleware.DefaultAITriageRateLimitConfig(), log)
	}

	// AI Triage routes (tenant from JWT token)
	// Always registered - handler handles nil service gracefully (returns 503)
	registerAITriageRoutes(router, h.AITriage, authMiddleware, userSync, aiTriageRateLimiter)

	// Dashboard routes (global and tenant from JWT token)
	if h.Dashboard != nil {
		registerDashboardRoutes(router, h.Dashboard, authMiddleware, userSync)
	}

	// Audit log routes (tenant from JWT token)
	if h.Audit != nil {
		registerAuditRoutes(router, h.Audit, authMiddleware, userSync)
	}

	// Branch routes (asset-scoped, tenant from JWT token)
	if h.Branch != nil {
		registerBranchRoutes(router, h.Branch, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleBranches))
	}

	// SLA Policy routes (tenant from JWT token)
	if h.SLA != nil {
		registerSLARoutes(router, h.SLA, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleSLA))
	}

	// Pentest Campaign Management routes (tenant from JWT token)
	if h.Pentest != nil {
		registerPentestRoutes(router, h.Pentest, authMiddleware, userSync, h.PentestCampaignRoleQry, h.ModuleGate.RequireModule(moduledom.ModulePentest))
	}

	// Attachment routes (file upload/download, shared across pentest/retest/campaign)
	if h.Attachment != nil {
		registerAttachmentRoutes(router, h.Attachment, authMiddleware, userSync)
	}

	// Compliance Framework Management routes (tenant from JWT token)
	if h.Compliance != nil {
		registerComplianceRoutes(router, h.Compliance, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleCompliance))
	}

	// Attack Simulation & Control Testing routes
	if h.Simulation != nil {
		registerSimulationRoutes(router, h.Simulation, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleAttackSimulation), h.ModuleGate.RequireModule(moduledom.ModuleControlTesting))
	}

	// Threat Actor Intelligence routes
	if h.ThreatActor != nil {
		registerThreatActorRoutes(router, h.ThreatActor, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleThreatIntel))
	}

	// Indicators of Compromise (IOC catalogue, feeds B6 correlator)
	if h.IOC != nil {
		registerIOCRoutes(router, h.IOC, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleIOCs))
	}

	// Organization MCP policy (RFC-062 §8).
	if h.MCPSettings != nil {
		registerMCPSettingsRoutes(router, h.MCPSettings, authMiddleware, userSync)
	}
	// Connected AI applications (RFC-062 §12).
	if h.MCPConnections != nil {
		registerMCPConnectionRoutes(router, h.MCPConnections, authMiddleware, userSync)
	}

	// Read-only MCP server — authenticated by tenant-scoped API key, not JWT.
	// Per-IP rate limit runs before auth to throttle junk-token floods; the
	// organization IP allowlist runs after it (mcpMiddlewares).
	if h.MCP != nil && h.MCPAuth != nil {
		registerMCPRoutes(router, h.MCP, middleware.RateLimit(&cfg.RateLimit, log), h.MCPAuth, h.MCPDiscovery)
		if h.MCPOAuth != nil {
			registerMCPOAuthRoutes(router, h.MCPOAuth, middleware.RateLimit(&cfg.RateLimit, log), authMiddleware, userSync)
		}
	}

	// Remediation Campaign routes
	if h.RemediationCampaign != nil {
		registerRemediationCampaignRoutes(router, h.RemediationCampaign, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleRemediation))
	}
	if h.ReportSchedule != nil {
		registerReportScheduleRoutes(router, h.ReportSchedule, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleReports))
	}

	// Business Unit routes
	if h.BusinessUnit != nil {
		registerBusinessUnitRoutes(router, h.BusinessUnit, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleBusinessUnits))
	}

	// Business Service routes (Phase 3 — business capability management)
	if h.BusinessService != nil {
		registerBusinessServiceRoutes(router, h.BusinessService, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleBusinessServices))
	}

	// Compensating Control routes (RFC-005)
	if h.CompensatingControl != nil {
		registerCompensatingControlRoutes(router, h.CompensatingControl, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleCompensatingControls))
	}

	// Attacker Profile routes (RFC-005)
	if h.AttackerProfile != nil {
		registerAttackerProfileRoutes(router, h.AttackerProfile, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleAttackerProfiles))
	}

	// CTEM Cycle routes (RFC-005)
	if h.CTEMCycle != nil {
		registerCTEMCycleRoutes(router, h.CTEMCycle, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleCTEMCycles))
	}

	// Scoping overview (no module gate, like Program Health)
	if h.Scoping != nil {
		registerScopingRoutes(router, h.Scoping, authMiddleware, userSync)
	}

	// Priority Rule routes (RFC-004)
	if h.PriorityRule != nil {
		registerPriorityRuleRoutes(router, h.PriorityRule, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModulePriorityRules))
	}

	// Threat Model routes (continuous threat modeling)
	if h.ThreatModel != nil {
		registerThreatModelRoutes(router, h.ThreatModel, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleThreatModel))
	}

	// Verification Checklist routes (RFC-005) — added to findings group
	if h.VerificationChecklist != nil {
		vcHandler := h.VerificationChecklist
		tenantMW := buildTokenTenantMiddlewares(authMiddleware, userSync)
		router.Group("/api/v1/verification-checklists", func(r Router) {
			r.GET("/{findingId}", vcHandler.Get, middleware.Require(permission.VerificationChecklistsRead))
			r.PUT("/{findingId}", vcHandler.Update, middleware.Require(permission.VerificationChecklistsWrite))
		}, tenantMW...)
	}

	// Integration routes (tenant from JWT token)
	if h.Integration != nil {
		registerIntegrationRoutes(router, h.Integration, h.JiraWebhook, h.DefectDojo, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleIntegrations))
	}

	// Asset Group routes (tenant from JWT token)
	if h.AssetGroup != nil {
		registerAssetGroupRoutes(router, h.AssetGroup, authMiddleware, userSync)
	}

	// Scope Configuration routes (tenant from JWT token)
	if h.Scope != nil {
		registerScopeRoutes(router, h.Scope, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleScopeConfig))
	}

	// Asset Type routes (tenant from JWT token)
	if h.AssetType != nil {
		registerAssetTypeRoutes(router, h.AssetType, authMiddleware, userSync)
	}

	// Finding Source routes (read-only system configuration)
	if h.FindingSource != nil {
		registerFindingSourceRoutes(router, h.FindingSource, authMiddleware, userSync)
	}

	// Attack Surface routes (tenant from JWT token)
	if h.AttackSurface != nil {
		registerAttackSurfaceRoutes(router, h.AttackSurface, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleAttackSurface))
	}
	if h.EASM != nil {
		registerEASMRoutes(router, h.EASM, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleAttackSurface))
	}
	if h.EASMVerifiedDomain != nil {
		registerEASMVerifiedDomainRoutes(router, h.EASMVerifiedDomain, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleAttackSurface))
	}
	if h.EASMSettings != nil {
		registerEASMSettingsRoutes(router, h.EASMSettings, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleAttackSurface))
	}

	// Command routes (tenant from JWT token)
	if h.Command != nil {
		registerCommandRoutes(router, h.Command, authMiddleware, userSync)
	}

	// Per-tenant limiter for the heavy report-ingest endpoints (up to 100k
	// findings / 100MB per request): a low budget, enough for legitimate CI
	// bursts, low enough to bound a runaway loop or compromised sensor key.
	var ingestRateLimiter *middleware.TelemetryRateLimiter
	if cfg.RateLimit.Enabled {
		ingestRateLimiter = middleware.NewTelemetryRateLimiter(20, 40, 10*time.Minute, log)
	}

	// CI runs: OIDC exchange, run-token uploads and the gate, administration
	// (RFC-051).
	if h.CIAdmin != nil || h.CIRunner != nil {
		registerCIRoutes(router, h.CIAdmin, h.CIRunner, authMiddleware, userSync,
			h.ModuleGate.RequireModule(moduledom.ModuleScans), ingestRateLimiter, log)
	}

	// Sensor protocol v2 results (RFC-026): its own route group and
	// authenticator, only when enabled.
	if h.SensorResultsV2 != nil {
		ctl := sensorControlV2Handler(h, log)
		budgets := newSensorV2Budgets(ingestRateLimiter, log)
		mountSensorV2(router, h.SensorResultsV2, ctl, budgets, h.SensorResultsV2.Authenticate)
		if h.SensorV3 != nil && ctl != nil {
			h.SensorV3.Attach(sensorV2InProcess(h.SensorResultsV2, ctl, budgets), ctl, h.SensorResultsV2)
		}
	}

	// Sensor pairing (RFC-052): sensor plane (signed by the key being
	// paired) and user plane.
	if h.SensorPairing != nil {
		registerSensorPairingRoutes(router, h.SensorPairing, authMiddleware, userSync, log)
	}

	// Sensor management routes (tenant from JWT token)
	if h.Sensor != nil {
		registerSensorManagementRoutes(router, h.Sensor, h.SensorContent, h.SensorResults, authMiddleware, userSync)
	}

	// The fleet: sensors (daemon mode) and CI pipelines (runner mode) in one
	// read model (RFC-051).
	registerFleetRoutes(router, h.Sensor, h.CIAdmin, h.ModuleGate, authMiddleware, userSync, log)

	// Scan zone routes (tenant from JWT token)
	if h.ScanZone != nil {
		registerScanZoneRoutes(router, h.ScanZone, authMiddleware, userSync)
	}
	if h.ScanFreeze != nil {
		registerScanFreezeWindowRoutes(router, h.ScanFreeze, authMiddleware, userSync)
	}

	// Initialize trigger rate limiter for scan workflow/scan trigger endpoints
	// This prevents abuse and ensures fair resource usage across tenants
	var triggerRateLimiter *middleware.TriggerRateLimiter
	if cfg.RateLimit.Enabled {
		triggerRateLimiter = middleware.NewTriggerRateLimiter(middleware.DefaultTriggerRateLimitConfig(), log)
	}

	// Scan workflow and scan run routes (tenant from JWT token)
	if h.ScanWorkflow != nil {
		registerScanWorkflowRoutes(router, h.ScanWorkflow, authMiddleware, userSync, h.ModuleGate)
	}

	// Scan Profile routes (tenant from JWT token)
	if h.ScanProfile != nil {
		registerScanProfileRoutes(router, h.ScanProfile, authMiddleware, userSync)
	}

	// Tool Registry routes (tenant from JWT token for tenant tools)
	if h.Tool != nil {
		registerToolRoutes(router, h.Tool, authMiddleware, userSync)
	}

	// Tool Category routes (tenant from JWT token)
	if h.ToolCategory != nil {
		registerToolCategoryRoutes(router, h.ToolCategory, authMiddleware, userSync)
	}

	// Capability routes (tenant from JWT token)
	if h.Capability != nil {
		registerCapabilityRoutes(router, h.Capability, authMiddleware, userSync)
	}

	// Scan routes (tenant from JWT token)
	if h.Scan != nil {
		registerScanRoutes(router, h.Scan, h.CI, authMiddleware, userSync, triggerRateLimiter)
	}

	// Scanner Template routes (tenant from JWT token)
	if h.ScannerTemplate != nil {
		registerScannerTemplateRoutes(router, h.ScannerTemplate, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleScannerTemplates))
	}

	// Template Source routes (tenant from JWT token)
	if h.ContentPack != nil {
		registerContentPackRoutes(router, h.ContentPack, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleScannerTemplates))
	}

	if h.TemplateSource != nil {
		registerTemplateSourceRoutes(router, h.TemplateSource, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleTemplateSources))
	}

	// Secret Store routes (tenant from JWT token)
	if h.SecretStore != nil {
		registerSecretStoreRoutes(router, h.SecretStore, authMiddleware, userSync)
	}

	// Workflow routes (tenant from JWT token)
	if h.Workflow != nil {
		registerWorkflowRoutes(router, h.Workflow, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleWorkflows))
	}

	// Suppression routes (tenant from JWT token)
	if h.Suppression != nil {
		registerSuppressionRoutes(router, h.Suppression, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleSuppressions))
	}

	// Exposure routes (tenant from JWT token)
	if h.Exposure != nil {
		registerExposureRoutes(router, h.Exposure, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleExposures))
	}

	// Threat Intelligence routes (global threat intel data)
	if h.ThreatIntel != nil {
		registerThreatIntelRoutes(router, h.ThreatIntel, authMiddleware, userSync)
	}

	// CTEM-ID catalog routes (global reference data)
	if h.CTEMID != nil {
		registerCTEMIDRoutes(router, h.CTEMID, authMiddleware, userSync)
	}

	// Credential Import routes (tenant from JWT token)
	if h.CredentialImport != nil {
		registerCredentialRoutes(router, h.CredentialImport, authMiddleware, userSync, h.ModuleGate.RequireModule(moduledom.ModuleCredentials))
	}

	// Group routes (Access Control - tenant from JWT token)
	if h.Group != nil {
		registerGroupRoutes(router, h.Group, authMiddleware, userSync)
	}

	// Per-user customizable dashboards (RFC-021) - self-scoped under /me/*.
	if h.UserDashboard != nil {
		registerUserDashboardRoutes(router, h.UserDashboard, authMiddleware, userSync)
	}
	if h.SavedView != nil {
		registerSavedViewRoutes(router, h.SavedView, authMiddleware, userSync)
	}

	// Permission Sync routes (real-time permission sync with ETag support)
	if h.Permission != nil {
		registerPermissionSyncRoutes(router, h.Permission, authMiddleware, userSync)
	}

	// Role routes (Access Control - tenant from JWT token)
	if h.Role != nil {
		registerRoleRoutes(router, h.Role, authMiddleware, userSync)
	}

	// Assignment Rule routes (Access Control - tenant from JWT token)
	if h.AssignmentRule != nil {
		registerAssignmentRuleRoutes(router, h.AssignmentRule, authMiddleware, userSync)
	}

	// Scope Rule routes (nested under groups)
	if h.ScopeRule != nil {
		registerScopeRuleRoutes(router, h.ScopeRule, authMiddleware, userSync)
	}

	// API Key routes (tenant from JWT token)
	if h.APIKey != nil {
		registerAPIKeyRoutes(router, h.APIKey, authMiddleware, userSync)
	}

	// User Notification routes (tenant from JWT token, user-scoped)
	if h.Notification != nil {
		registerNotificationRoutes(router, h.Notification, authMiddleware, userSync)
	}

	// Notification Outbox routes (tenant from JWT token)
	if h.Outbox != nil {
		registerOutboxRoutes(router, h.Outbox, authMiddleware, userSync)
	}

	// Bootstrap route (combines permissions, subscription, modules, dashboard)
	if h.Bootstrap != nil {
		registerBootstrapRoutes(router, h.Bootstrap, authMiddleware, userSync)
	}

	// Platform Stats routes (tenant-scoped platform sensor statistics)
	if h.PlatformScanning != nil {
		registerPlatformScanningRoutes(router, h.PlatformScanning, authMiddleware, userSync)
	}

	// ==========================================================================
	// Platform Admin Routes (separate from tenant routes)
	// ==========================================================================
	// These routes are for OpenCTEM platform administrators only.
	// They manage shared infrastructure that serves all tenants.
	registerAdminRoutes(router, h, middleware.RejectCrossSiteBrowser(cfg.CORS.AllowedOrigins, log))

	// ==========================================================================
	// WebSocket Routes (protected with auth)
	// ==========================================================================
	// WebSocket endpoint for real-time features (activities, scans, notifications)
	if h.WebSocket != nil {
		registerWebSocketRoutes(router, h.WebSocket, authMiddleware, userSync)
	}
}

// =============================================================================
// Middleware Helpers
// =============================================================================

// buildBaseMiddlewares builds a middleware chain with auth and optional user sync.
func buildBaseMiddlewares(authMiddleware, userSyncMiddleware Middleware) []Middleware {
	middlewares := []Middleware{authMiddleware}
	if userSyncMiddleware != nil {
		middlewares = append(middlewares, userSyncMiddleware)
	}
	// Per-request SSO enforcement runs right after auth (needs the JWT claims)
	// and before the per-route authz checks. No-op for federated sessions,
	// owners, non-tenant tokens, and OIDC requests (see Enforce).
	if ssoEnforcementMiddleware != nil {
		middlewares = append(middlewares, ssoEnforcementMiddleware)
	}
	// Organization IP allowlist for user sessions and API keys (no-op for sensors).
	if ipAllowlistMiddleware != nil {
		middlewares = append(middlewares, ipAllowlistMiddleware)
	}
	// Idle Free organization: changes refused until someone signs in.
	if idleReadOnlyMiddleware != nil {
		middlewares = append(middlewares, idleReadOnlyMiddleware)
	}
	return middlewares
}

// csrfProtectionMiddleware is the CSRF double-submit-cookie middleware,
// appended to every tenant route chain via buildTokenTenantMiddlewares.
// CSRFOptional keeps header-authenticated clients (Bearer JWT, API keys)
// unaffected; cookie-authenticated requests must send X-CSRF-Token (also
// enforced, for every route, by UnifiedAuth).
var csrfProtectionMiddleware Middleware //nolint:gochecknoglobals // set once during init

// apiKeyOrJWT wraps the JWT auth middleware so that a request presenting an
// `oct_` API key is authenticated by the key instead (see
// middleware.APIKeyAuthMiddleware.OrJWT). Set during Register when the API-key
// service is wired; nil keeps the token-tenant chains JWT-only.
var apiKeyOrJWT func(func(http.Handler) http.Handler) func(http.Handler) http.Handler //nolint:gochecknoglobals // set once during init

// authRateLimitBackend is the shared store for the auth rate limits, set on
// every Register from Handlers.AuthRateLimitBackend (nil = in-memory).
var authRateLimitBackend middleware.AuthRateLimitBackend //nolint:gochecknoglobals // set once during init

// newAuthRateLimiter builds the auth limiter for one group of routes. scope
// keeps its budgets apart from other groups' in the shared store; the same
// scope on another replica shares them.
func newAuthRateLimiter(scope string) *middleware.AuthRateLimiter {
	return middleware.NewDistributedAuthRateLimiter(middleware.DefaultAuthRateLimitConfig(), nil, authRateLimitBackend, scope)
}

// readRateLimitMiddleware is the per-user read endpoint rate limiter,
// set during Register() if rate limiting is enabled. Applied automatically
// by buildTokenTenantMiddlewares to all tenant-scoped route groups.
var readRateLimitMiddleware Middleware //nolint:gochecknoglobals // set once during init

// activeMembershipFromJWTMiddleware checks that the user holding the
// JWT is still an ACTIVE member of the tenant the JWT claims to be
// scoped to. Set during Register() once tenantRepo is available.
//
// Without this, suspended members with a still-valid access token
// could keep hitting JWT-claim-scoped routes (/api/v1/me/*,
// /api/v1/notifications, /api/v1/api-keys, /api/v1/scans/...) until
// the JWT expires. URL-path tenant routes already enforce this via
// RequireMembership in tenant.go.
var activeMembershipFromJWTMiddleware Middleware //nolint:gochecknoglobals // set once during init

// permissionSyncMiddleware enriches each token-tenant request with fresh
// permissions from Redis and rejects confirmed-stale state-mutating requests.
// Set once during Register; nil leaves the legacy embedded-JWT behavior.
var permissionSyncMiddleware Middleware //nolint:gochecknoglobals // set once during init

// tenantPermissionChecker resolves a caller's permissions in the tenant named
// by a /api/v1/tenants/{tenant}/... path (see tenantPerm).
var tenantPermissionChecker middleware.TenantPermissionChecker //nolint:gochecknoglobals // set once during init

// dataScopeGuardMiddleware enforces the Layer 2 data scope on every by-id
// asset and finding route (see middleware.DataScopeGuard). It runs last on
// the token-tenant chain, after auth, tenant, membership and permission sync
// have settled who the caller is. Set once during Register; nil disables it.
var dataScopeGuardMiddleware Middleware //nolint:gochecknoglobals // set once during init

// ssoEnforcementMiddleware re-applies the per-tenant SSO-enforcement decision on
// every authenticated request (defense-in-depth on top of the token-mint gate):
// a password non-owner session whose token's tenant enforces SSO is rejected,
// closing the window where an already-minted password token keeps access after
// the tenant turns enforcement on. Set once during Register once tenantRepo is
// available; nil leaves only the mint-time gate.
var ssoEnforcementMiddleware Middleware //nolint:gochecknoglobals // set once during init

// idleReadOnlyMiddleware refuses changes to an idle Free organization.
var idleReadOnlyMiddleware Middleware //nolint:gochecknoglobals // set once during init

// ipAllowlistMiddleware enforces each organization's Security.IPWhitelist on
// user sessions. Set once during Register; nil disables it (tests).
var ipAllowlistMiddleware Middleware //nolint:gochecknoglobals // set once during init

// stepUpChecker answers RequireRecentAuth (step-up re-authentication,
// docs/architecture/step-up-reauth.md). Set once during Register from the
// local auth handler; nil makes every step-up route refuse (fail closed).
var stepUpChecker middleware.RecentAuthChecker //nolint:gochecknoglobals // set once during init

// requireStepUp is the middleware for a sensitive route: the caller's session
// must have signed in or stepped up within authapp.StepUpWindow, otherwise
// 403 STEP_UP_REQUIRED. Mount it after the route's permission check.
func requireStepUp() Middleware {
	return middleware.RequireRecentAuth(stepUpChecker, authapp.StepUpWindow)
}

// tenantSecurityPolicyAdapter adapts tenant.Repository to
// middleware.TenantSecurityPolicyProvider (the organization's security
// settings). Cross-tenant by design: it answers a per-organization policy
// question, not a data query.
type tenantSecurityPolicyAdapter struct {
	repo tenant.Repository
}

func (a tenantSecurityPolicyAdapter) SecuritySettings(ctx context.Context, tenantID string) (tenant.SecuritySettings, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return tenant.SecuritySettings{}, err
	}
	t, err := a.repo.GetByID(ctx, id)
	if err != nil {
		return tenant.SecuritySettings{}, err
	}
	// Strict: an unreadable security section is an error (the IP allowlist
	// gate then denies), never the permissive defaults.
	return t.SecuritySettingsStrict()
}

// tenantSSOEnforcedAdapter adapts tenant.Repository to
// middleware.SSOEnforcedProvider, reading the tenant's sso_enforced security
// setting. Cross-tenant by design — it answers a per-tenant-id policy question,
// not a data query.
type tenantSSOEnforcedAdapter struct {
	repo tenant.Repository
}

func (a tenantSSOEnforcedAdapter) IsSSOEnforced(ctx context.Context, tenantID string) (bool, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return false, err
	}
	t, err := a.repo.GetByID(ctx, id)
	if err != nil {
		return false, err
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		return false, err
	}
	return sec.SSOEnforced, nil
}

// HasSSOException reports whether the member has an unexpired SSO exception
// (RFC-058), read fresh from the tenant settings.
func (a tenantSSOEnforcedAdapter) HasSSOException(ctx context.Context, tenantID, userID string) (bool, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return false, err
	}
	t, err := a.repo.GetByID(ctx, id)
	if err != nil {
		return false, err
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		return false, err
	}
	return sec.HasSSOException(userID, time.Now().UTC()), nil
}

// buildTokenTenantMiddlewares builds a middleware chain for token-based tenant routes.
// This uses tenant ID from JWT claims instead of URL path.
// Best practice: tenant-scoped access tokens eliminate IDOR by design.
// Includes per-user read rate limiting when enabled.
func buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware Middleware) []Middleware {
	// These are the routes an `oct_` API key may reach (read-only, its scopes
	// only, never the APIKeyRouteDenied areas). The key request then runs the
	// same chain as a session: the key's user is loaded by UserSync and must
	// still be an active member, and the organization's IP allowlist applies.
	if apiKeyOrJWT != nil {
		authMiddleware = apiKeyOrJWT(authMiddleware)
	}
	middlewares := buildBaseMiddlewares(authMiddleware, userSyncMiddleware)
	middlewares = append(middlewares, middleware.RequireTenant())
	// Membership status check — must run AFTER RequireTenant (which
	// validates the JWT carries a tenant id). Skipped only if Register
	// did not wire tenantRepo, which would only happen in tests with a
	// minimal handler set.
	if activeMembershipFromJWTMiddleware != nil {
		middlewares = append(middlewares, activeMembershipFromJWTMiddleware)
	}
	// Real-time permission sync — runs after membership so user/tenant are in
	// context and before the per-route Require() checks so they see the fresh
	// permissions. Rejects confirmed-stale writes (revoked role / demoted
	// admin); safe methods pass through with fresh perms.
	if permissionSyncMiddleware != nil {
		middlewares = append(middlewares, permissionSyncMiddleware)
	}
	// CSRF enforcement for cookie-bound sessions. Safe methods (GET,
	// HEAD, OPTIONS) are exempt inside the middleware, so read
	// endpoints are unaffected.
	if csrfProtectionMiddleware != nil {
		middlewares = append(middlewares, csrfProtectionMiddleware)
	}
	if readRateLimitMiddleware != nil {
		middlewares = append(middlewares, readRateLimitMiddleware)
	}
	if dataScopeGuardMiddleware != nil {
		middlewares = append(middlewares, dataScopeGuardMiddleware)
	}
	return middlewares
}

// tenantOverlayMiddlewares returns the EXTRA middlewares that
// buildTokenTenantMiddlewares adds on top of buildBaseMiddlewares
// (RequireTenant + active-membership + CSRF + rate-limit).
//
// Use case: a route group is mounted with baseMiddlewares (e.g. global
// vulnerabilities catalog) but a few endpoints inside the group are
// tenant-scoped (e.g. /vulnerabilities/{id}/affected-assets joins
// per-tenant findings). Apply this overlay per-route to upgrade those
// endpoints to the same security posture as a tokenTenant group, without
// having to mount a second chi Group on the same path (chi forbids that).
//
// Order matters: caller MUST spread these BEFORE permission middleware so
// RequireTenant runs first.
func tenantOverlayMiddlewares() []Middleware {
	mws := []Middleware{middleware.RequireTenant()}
	if activeMembershipFromJWTMiddleware != nil {
		mws = append(mws, activeMembershipFromJWTMiddleware)
	}
	if csrfProtectionMiddleware != nil {
		mws = append(mws, csrfProtectionMiddleware)
	}
	if readRateLimitMiddleware != nil {
		mws = append(mws, readRateLimitMiddleware)
	}
	return mws
}

// realtimeMiddlewares is the chain for the WebSocket upgrade,
// GET /api/v1/ws (RFC-045). The socket opens the tenant's real-time stream,
// so the upgrade passes the same tenant gates as any tenant route: the
// session (Authorization header or the auth_token cookie, revoked-session
// check), SSO enforcement and the organization IP allowlist
// (buildBaseMiddlewares), then RequireTenant, active membership and the read
// rate limit (tenantOverlayMiddlewares). It stays session-only: unlike
// buildTokenTenantMiddlewares it does not accept `oct_` API keys.
func realtimeMiddlewares(authMiddleware, userSyncMiddleware Middleware) []Middleware {
	return append(buildBaseMiddlewares(authMiddleware, userSyncMiddleware), tenantOverlayMiddlewares()...)
}

// ChainFunc wraps a handler function with middleware(s).
// Returns the final handler after applying all middleware in order.
func ChainFunc(handler http.HandlerFunc, middlewares ...Middleware) http.Handler {
	return infrahttp.ChainFunc(handler, middlewares...)
}
