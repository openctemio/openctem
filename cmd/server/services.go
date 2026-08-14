package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/app/apikey"
	"github.com/openctemio/api/internal/app/assignment"
	"github.com/openctemio/api/internal/app/command"
	"github.com/openctemio/api/internal/app/defectdojo"
	"github.com/openctemio/api/internal/app/remediation"
	"github.com/openctemio/api/internal/app/scope"
	"github.com/openctemio/api/internal/app/threat"
	"github.com/openctemio/api/internal/app/tool"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/attack"
	"github.com/openctemio/api/internal/app/auth/domainverify"
	"github.com/openctemio/api/internal/app/exposure"
	"github.com/openctemio/api/internal/app/exposurebridge"
	"github.com/openctemio/api/internal/app/ingest"
	iocapp "github.com/openctemio/api/internal/app/ioc"
	"github.com/openctemio/api/internal/app/jira"
	"github.com/openctemio/api/internal/app/outbox"
	"github.com/openctemio/api/internal/app/pipeline"
	"github.com/openctemio/api/internal/app/reclassify"
	"github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/internal/app/scim"
	"github.com/openctemio/api/internal/app/sla"
	"github.com/openctemio/api/internal/app/template"
	"github.com/openctemio/api/internal/app/threatmodel"
	"github.com/openctemio/api/internal/app/ticketing"
	"github.com/openctemio/api/internal/app/validation"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/controller"
	infrajira "github.com/openctemio/api/internal/infra/jira"
	"github.com/openctemio/api/internal/infra/jobs"
	"github.com/openctemio/api/internal/infra/llm"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/internal/infra/storage"
	"github.com/openctemio/api/internal/infra/websocket"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/suppression"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/email"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/logger"
)

// findingMutatorAdapter adapts the postgres FindingRepository (GetByID) to the
// validation.FindingMutator interface (Get) used by the evidence-ingest path.
type findingMutatorAdapter struct {
	repo *postgres.FindingRepository
}

func (a findingMutatorAdapter) Get(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, error) {
	return a.repo.GetByID(ctx, tenantID, findingID)
}

func (a findingMutatorAdapter) Update(ctx context.Context, f *vulnerability.Finding) error {
	return a.repo.Update(ctx, f)
}

// validationAgentAvailability answers "is a validation-capable agent online for
// this tenant?" by reusing the exact capability query scan dispatch uses
// (AgentRepository.FindAvailableWithCapacity). It gates validation.RunService so
// a validate command is only ever queued when a real agent can consume it —
// otherwise the command would sit in the queue forever and a live simulation run
// would be stranded in "running". The gate is self-arming: it opens the moment a
// tenant registers an agent advertising the "validate" capability.
type validationAgentAvailability struct {
	agents *postgres.AgentRepository
}

func (v validationAgentAvailability) HasValidationAgent(ctx context.Context, tenantID shared.ID) (bool, error) {
	agents, err := v.agents.FindAvailableWithCapacity(ctx, tenantID, []string{validation.AgentCapabilityValidate}, "")
	if err != nil {
		return false, err
	}
	return len(agents) > 0, nil
}

// assetOwnerMatcher resolves an asset's owner_ref email to a user id for
// auto-ownership, but ONLY when that user is a member of the tenant — never
// assigning ownership to a user outside the tenant (isolation). A no-match is
// returned as (nil, nil), not an error, so auto-match stays best-effort.
// Wires the previously-dead AssetService.SetUserMatcher.
type assetOwnerMatcher struct {
	users   *postgres.UserRepository
	tenants *postgres.TenantRepository
}

func (m assetOwnerMatcher) FindUserIDByEmail(ctx context.Context, tenantID shared.ID, email string) (*shared.ID, error) {
	u, err := m.users.GetByEmail(ctx, email)
	if err != nil {
		return nil, nil //nolint:nilerr // unknown email → no match, not an error (best-effort auto-match)
	}
	if _, err := m.tenants.GetMembership(ctx, u.ID(), tenantID); err != nil {
		return nil, nil //nolint:nilerr // not a member of this tenant → do not assign
	}
	id := u.ID()
	return &id, nil
}

// campaignFindingResolver adapts the finding bulk-status path + abuse guard to
// exposure.CampaignFindingResolver, so completing/resolving a remediation
// campaign actively closes its open findings (RFC-015 Phase 3). Kept here (not
// in exposure) so exposure needn't import the finding service or the guard.
type campaignFindingResolver struct {
	vuln  *app.VulnerabilityService
	guard *app.BulkGuard
}

// maxCampaignResolve caps how many findings one campaign-resolve touches; the
// abuse guard still enforces the tenant ceiling / hourly budget within this.
const maxCampaignResolve = 2000

func (a campaignFindingResolver) ResolveOpenByFilter(ctx context.Context, tenantID string, filter vulnerability.FindingFilter, in exposure.CampaignResolveInput) (int, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, err
	}
	filter.ExcludeStatuses = vulnerability.ClosedFindingStatuses()
	ids, err := a.vuln.ListFindingIDs(ctx, filter, maxCampaignResolve)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if a.guard != nil {
		if err := a.guard.CheckBulk(ctx, tid, len(ids), in.Approved); err != nil {
			return 0, err
		}
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	status := in.Status
	if status == "" {
		status = string(vulnerability.FindingStatusFixApplied)
	}
	res, err := a.vuln.BulkUpdateFindingsStatus(ctx, tenantID, app.BulkUpdateStatusInput{
		FindingIDs:          idStrs,
		Status:              status,
		Resolution:          in.Resolution,
		ActorID:             in.ActorID,
		HasVerifyPermission: in.HasVerifyPermission,
	})
	if err != nil {
		return 0, err
	}
	return res.Updated, nil
}

// campaignKeyResolver serves campaigns scoped to a remediation-group key (a
// solution family): progress from the side-table rollup, resolution via the
// same guarded group-resolve path as the standalone "resolve group" action.
// Kept here so exposure needn't import the remediation group service or the
// key repository.
type campaignKeyResolver struct {
	keys  *postgres.FindingRemediationKeyRepository
	group *remediation.GroupService
}

func (a campaignKeyResolver) CountByKey(ctx context.Context, tenantID shared.ID, key string) (int64, int64, error) {
	closed := vulnerability.ClosedFindingStatuses()
	closedStrs := make([]string, len(closed))
	for i, s := range closed {
		closedStrs[i] = string(s)
	}
	return a.keys.CountByKey(ctx, tenantID, key, closedStrs)
}

func (a campaignKeyResolver) ResolveGroupByKey(ctx context.Context, tenantID, key string, in exposure.CampaignResolveInput) (int, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, err
	}
	res, err := a.group.ResolveGroup(ctx, tid, remediation.ResolveGroupInput{
		Key:                 key,
		Status:              in.Status,
		Resolution:          in.Resolution,
		ActorID:             in.ActorID,
		HasVerifyPermission: in.HasVerifyPermission,
		OperatorApproved:    in.Approved,
	})
	if err != nil {
		return 0, err
	}
	return res.Updated, nil
}

// moduleBundleStore adapts the tenant repository to module.BundleStore, storing
// a tenant's product-bundle subscription in its settings JSON. Read on the
// module-resolution path (cached by the gate); written on subscribe.
type moduleBundleStore struct {
	tenants tenant.Repository
	db      *sql.DB
}

func (a moduleBundleStore) GetSubscribedBundles(ctx context.Context, tenantID string) ([]string, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, err
	}
	t, err := a.tenants.GetByID(ctx, tid)
	if err != nil {
		return nil, err
	}
	return t.TypedSettings().SubscribedBundles, nil
}

// SetSubscribedBundles writes ONLY the subscribed_bundles key inside the tenant
// settings JSONB — never a read-modify-write of the whole blob. This avoids a
// lost-update clobber: a concurrent write to any other settings field (AI
// config, branding, risk weights, …) can't wipe the subscription, and vice
// versa. Empty selection removes the key entirely (= no subscription = all on).
func (a moduleBundleStore) SetSubscribedBundles(ctx context.Context, tenantID string, bundleIDs []string) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return err
	}

	var result sql.Result
	if len(bundleIDs) == 0 {
		result, err = a.db.ExecContext(ctx,
			`UPDATE tenants
			 SET settings = COALESCE(settings, '{}'::jsonb) - 'subscribed_bundles',
			     updated_at = now()
			 WHERE id = $1`,
			tid.String())
	} else {
		payload, mErr := json.Marshal(bundleIDs)
		if mErr != nil {
			return fmt.Errorf("marshal subscribed bundles: %w", mErr)
		}
		result, err = a.db.ExecContext(ctx,
			`UPDATE tenants
			 SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{subscribed_bundles}', $2::jsonb, true),
			     updated_at = now()
			 WHERE id = $1`,
			tid.String(), payload)
	}
	if err != nil {
		return fmt.Errorf("update subscribed bundles: %w", err)
	}
	if rows, rErr := result.RowsAffected(); rErr == nil && rows == 0 {
		return fmt.Errorf("%w: tenant %s", shared.ErrNotFound, tid.String())
	}
	return nil
}

// apikeyMembershipAdapter adapts the tenant repository to apikey.MembershipChecker
// so a user-scoped API key stops authenticating the moment its owner's membership
// is suspended or removed. Fails closed: a missing membership or lookup error is
// reported as "not active" (the caller rejects the key).
type apikeyMembershipAdapter struct{ tenants tenant.Repository }

func (a apikeyMembershipAdapter) IsActiveMember(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	m, err := a.tenants.GetMembership(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	return m.Status() == tenant.MemberStatusActive, nil
}

// pentestTenantMemberAdapter adapts the tenant repository to
// compliance.TenantMemberChecker so PentestService can reject adding a campaign
// member who does not belong to the tenant (the DB FK only checks users.id, not
// tenant membership — a cross-tenant IDOR without this guard). Fails closed:
// unparseable IDs, a missing membership, or a lookup error all report "not a member".
type pentestTenantMemberAdapter struct{ tenants tenant.Repository }

func (a pentestTenantMemberAdapter) IsTenantMember(ctx context.Context, tenantID, userID string) bool {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return false
	}
	m, err := a.tenants.GetMembership(ctx, uid, tid)
	if err != nil || m == nil {
		return false
	}
	return true
}

// workflowJiraTicketAdapter adapts *jira.SyncService to the workflow ticket
// action's JiraTicketService (primitive params, so the workflow package needn't
// import app/jira — that would cycle through the app shim).
type workflowJiraTicketAdapter struct{ svc *jira.SyncService }

func (a workflowJiraTicketAdapter) CreateTicketFromFinding(ctx context.Context, tenantID, findingID, projectKey, issueType string) (app.TicketRef, error) {
	info, err := a.svc.CreateTicketFromFinding(ctx, jira.CreateTicketInput{
		TenantID: tenantID, FindingID: findingID, ProjectKey: projectKey, IssueType: issueType,
	})
	if err != nil {
		return app.TicketRef{}, err
	}
	return app.TicketRef{Key: info.TicketKey, URL: info.TicketURL}, nil
}

func (a workflowJiraTicketAdapter) SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error {
	return a.svc.SyncFindingStatus(ctx, tenantID, findingID)
}

// workflowGitHubTicketAdapter adapts *ticketing.GitHubTicketService to the
// workflow ticket action's GitHubTicketService.
type workflowGitHubTicketAdapter struct {
	svc *ticketing.GitHubTicketService
}

func (a workflowGitHubTicketAdapter) CreateTicketFromFinding(ctx context.Context, tenantID, findingID, owner, repo string) (app.TicketRef, error) {
	info, err := a.svc.CreateTicketFromFinding(ctx, ticketing.GitHubTicketInput{
		TenantID: tenantID, FindingID: findingID, Owner: owner, Repo: repo,
	})
	if err != nil {
		return app.TicketRef{}, err
	}
	return app.TicketRef{Key: info.TicketKey, URL: info.TicketURL}, nil
}

// wsHubBroadcaster adapts websocket.Hub to app.ActivityBroadcaster and app.TriageBroadcaster interfaces.
type wsHubBroadcaster struct {
	hub *websocket.Hub
}

// wsTicketStore is an adapter exposing only the Get/Set/Del surface that the
// WS ticket service needs — keeps that service decoupled from the full Redis
// client surface. F-8.
type wsTicketStore struct {
	rc *redis.Client
}

func newWSTicketStore(rc *redis.Client) *wsTicketStore {
	return &wsTicketStore{rc: rc}
}

func (s *wsTicketStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.rc.Set(ctx, key, value, ttl)
}

func (s *wsTicketStore) GetDel(ctx context.Context, key string) (string, bool, error) {
	return s.rc.GetDel(ctx, key)
}

func (b *wsHubBroadcaster) BroadcastActivity(channel string, data any, tenantID string) {
	b.hub.BroadcastEvent(channel, data, tenantID)
}

func (b *wsHubBroadcaster) BroadcastTriage(channel string, data any, tenantID string) {
	b.hub.BroadcastEvent(channel, data, tenantID)
}

func (b *wsHubBroadcaster) BroadcastScopeChange(channel string, data any, tenantID string) {
	b.hub.BroadcastEvent(channel, data, tenantID)
}

// Broadcast satisfies module.WSBroadcaster. Used by ModuleService to
// fan out "module.updated" events to clients subscribed to the
// tenant:{id} channel — drives the SWR cache invalidation on the
// Settings → Modules page so admins in other tabs see the new state
// immediately.
//
// The channel string already encodes the tenant (`tenant:{id}`); the
// hub's BroadcastEvent expects a separate tenantID so we extract it
// from the channel prefix.
func (b *wsHubBroadcaster) Broadcast(channel string, data any) {
	tenantID := ""
	if len(channel) > len("tenant:") && channel[:len("tenant:")] == "tenant:" {
		tenantID = channel[len("tenant:"):]
	}
	b.hub.BroadcastEvent(channel, data, tenantID)
}

// Services holds all service instances.
type Services struct {
	// Auth
	Auth    *app.AuthService
	Session *app.SessionService

	// Core
	Audit  *app.AuditService
	User   *app.UserService
	Tenant *app.TenantService

	// Assets
	Asset                  *app.AssetService
	AssetGroup             *app.AssetGroupService
	AssetType              *app.AssetTypeService
	AssetRelationship      *app.AssetRelationshipService
	AssetImport            *app.AssetImportService
	RelationshipSuggestion *app.RelationshipSuggestionService
	Scope                  *scope.Service
	AttackSurface          *attack.SurfaceService
	ThreatModel            *threatmodel.Service

	// Configuration (read-only system config)
	FindingSource      *app.FindingSourceService
	FindingSourceCache *app.FindingSourceCacheService

	// Vulnerabilities & Exposures
	Vulnerability    *app.VulnerabilityService
	FindingActivity  *app.FindingActivityService
	FindingActions   *app.FindingActionsService
	SourceAnalytics  *app.SourceAnalyticsService
	Exposure         *app.ExposureService
	ThreatIntel      *threat.IntelService
	CredentialImport *app.CredentialImportService

	// Components & Branches
	Component      *app.ComponentService
	SBOMImport     *app.SBOMImportService
	ReportSchedule *app.ReportScheduleService
	Branch         *app.BranchService

	// Dashboard
	Dashboard *app.DashboardService

	// Integrations & Notifications
	Integration    *app.IntegrationService
	DefectDojoSync *defectdojo.SyncService
	Outbox         *outbox.Service
	Notification   *app.NotificationService

	// Agents & Commands
	Agent   *app.AgentService
	Command *command.Service
	Ingest  *ingest.Service

	// Scanning & Pipelines
	ScanProfile     *app.ScanProfileService
	ScanSession     *app.ScanSessionService
	Tool            *tool.Service
	ToolCategory    *tool.CategoryService
	Capability      *app.CapabilityService
	Scan            *scan.Service
	Pipeline        *pipeline.Service
	ScannerTemplate *app.ScannerTemplateService
	TemplateSource  *template.SourceService
	SecretStore     *app.SecretStoreService
	TemplateSyncer  *template.Syncer

	// Workflows
	Workflow           *app.WorkflowService
	WorkflowDispatcher *app.WorkflowEventDispatcher

	// Suppressions
	Suppression *suppression.Service

	// Agent Selection
	AgentSelector *app.AgentSelector

	// Access Control
	Group          *app.GroupService
	Permission     *app.PermissionService
	Role           *app.RoleService
	AssignmentRule *assignment.RuleService
	ScopeRule      *scope.RuleService

	// Permission Sync
	PermVersion *app.PermissionVersionService
	PermCache   *app.PermissionCacheService

	// Membership cache (Redis-backed wrapper around tenant.Repository
	// .GetMembership). Read by RequireMembership +
	// RequireActiveMembershipFromJWT middlewares so the membership
	// status check on every tenant-scoped request becomes a Redis GET
	// instead of a DB round trip. Invalidated by TenantService when
	// role / status / membership rows change.
	MembershipCache *app.MembershipCacheService

	// Module Service (OSS - all modules enabled, UI metadata only)
	Module *app.ModuleService

	// SLA
	SLA *sla.Service

	// Priority Classification (RFC-004)
	PriorityClassification *app.PriorityClassificationService

	// B1/B2 reclassification pipeline — memory queue,
	// publisher (called from control CRUD), reclassifier (consumed
	// by the PriorityReclassifyController registered in workers.go).
	ReclassifyQueue  *reclassify.MemoryQueue
	ControlChangePub *controller.ControlChangePublisher
	Reclassifier     *reclassify.Reclassifier

	// B6 runtime loop — indicator catalogue + correlator.
	// Handlers.go hooks the correlator into RuntimeTelemetryHandler so
	// every accepted event is matched against active IOCs.
	IOCRepo       *postgres.IOCRepository
	IOCCorrelator *iocapp.Correlator

	// bulk-action guard (attached to finding bulk handlers).
	BulkGuard *app.BulkGuard

	// Pentest
	Pentest    *app.PentestService
	Attachment *app.AttachmentService

	// Compliance
	Compliance *app.ComplianceService

	// Attack Simulation & Control Testing
	Simulation *app.SimulationService

	// Validation (CTEM Stage-4): proof-of-fix / technique-execution evidence
	// recorded by agents, reconciling finding status from the outcome.
	ValidationEvidence *validation.EvidenceIngestService

	// ValidationRun dispatches validation (safe-check) jobs for findings.
	ValidationRun *validation.RunService

	// Threat Actor Intelligence
	ThreatActor *threat.ActorService

	// Remediation Campaigns
	RemediationCampaign *app.RemediationCampaignService
	RemediationGroup    *remediation.GroupService

	// Business Units
	BusinessUnit *app.BusinessUnitService

	// API Keys & Webhooks
	APIKey  *apikey.Service
	Webhook *app.WebhookService

	// Jira Bidirectional Sync
	JiraSync *jira.SyncService

	// GitHub Issues ticket provider (create-from-finding + link only)
	GitHubTicket *ticketing.GitHubTicketService

	// AI Triage
	AITriage *app.AITriageService

	// WebSocket
	WebSocketHub *websocket.Hub
	// F-8: Single-use ticket service used by WS upgrade auth.
	WSTicket *app.WSTicketService

	// Email
	Email        *app.EmailService
	EmailEnqueue app.EmailJobEnqueuer

	// Encryption
	Encryptor crypto.Encryptor

	// JWT
	JWTGenerator *jwt.Generator

	// SSO
	SSO *app.SSOService

	// Social OAuth login (Google / GitHub / Microsoft). nil when no provider
	// is configured, which keeps the OAuth routes unregistered.
	OAuth *app.OAuthService

	// Domain-ownership verification (SSO P1) — the verified-domain JIT gate.
	DomainVerify *domainverify.Service

	// SAML 2.0 SP (RFC-009 9d/9e)
	SAML *app.SAMLService

	// SCIM 2.0 provisioning (RFC-009)
	SCIMToken        *scim.TokenService
	SCIMProvisioning *scim.ProvisioningService
	SCIMGroups       *scim.GroupService
}

// scimMembershipAdapter adapts TenantService to scim.MembershipManager, injecting
// a system audit context so SCIM-driven membership changes go through the full
// lifecycle (session revoke + permission-cache clear + audit).
type scimMembershipAdapter struct {
	svc *app.TenantService
}

func scimAuditContext(tenantID shared.ID) app.AuditContext {
	return app.AuditContext{TenantID: tenantID.String(), ActorEmail: "scim-provisioning"}
}

func (a scimMembershipAdapter) AddMember(ctx context.Context, tenantID, userID shared.ID, role string) error {
	_, err := a.svc.AddMember(ctx, tenantID.String(), app.AddMemberInput{UserID: userID, Role: role}, shared.ID{}, scimAuditContext(tenantID))
	return err
}

func (a scimMembershipAdapter) SuspendMember(ctx context.Context, tenantID, membershipID shared.ID) error {
	return a.svc.SuspendMember(ctx, membershipID.String(), scimAuditContext(tenantID))
}

func (a scimMembershipAdapter) ReactivateMember(ctx context.Context, tenantID, membershipID shared.ID) error {
	return a.svc.ReactivateMember(ctx, membershipID.String(), scimAuditContext(tenantID))
}

// UpdateMemberRole satisfies scim.RoleManager for SCIM group → role mapping.
func (a scimMembershipAdapter) UpdateMemberRole(ctx context.Context, tenantID, membershipID shared.ID, role string) error {
	_, err := a.svc.UpdateMemberRole(ctx, membershipID.String(), app.UpdateMemberRoleInput{Role: role}, scimAuditContext(tenantID))
	return err
}

// ServiceDeps contains dependencies needed to create services.
type ServiceDeps struct {
	Config          *config.Config
	Log             *logger.Logger
	DB              *sql.DB
	Repos           *Repositories
	RedisClient     *redis.Client
	AgentStateStore *redis.AgentStateStore
}

// NewServices initializes all services.
func NewServices(deps *ServiceDeps) (*Services, error) {
	cfg := deps.Config
	log := deps.Log
	repos := deps.Repos

	s := &Services{}

	// Initialize credentials encryptor
	var err error
	s.Encryptor, err = initEncryptor(cfg, log)
	if err != nil {
		return nil, err
	}

	// Initialize audit service first (used by others)
	s.Audit = app.NewAuditService(repos.Audit, log)

	// Initialize core services
	s.User = app.NewUserService(repos.User, log)
	s.Tenant = app.NewTenantService(repos.Tenant, log,
		app.WithTenantAuditService(s.Audit),
	)

	// Initialize asset services
	s.Asset = app.NewAssetService(repos.Asset, log)
	s.Asset.SetRepositoryExtensionRepository(repos.RepoExt)
	// Wire owner_ref→user auto-resolution (was dead: SetUserMatcher never called,
	// so an email owner_ref never resolved to a real user_id). Membership-checked.
	s.Asset.SetUserMatcher(assetOwnerMatcher{users: repos.User, tenants: repos.Tenant})
	s.Asset.SetAssetGroupRepository(repos.AssetGroup)
	s.Asset.SetAccessControlRepository(repos.AccessControl)
	s.Asset.SetScoringConfigProvider(app.NewTenantScoringConfigProvider(repos.Tenant))
	s.Asset.SetRedisClient(deps.RedisClient)
	// The Postgres asset repository also implements the narrow
	// LifecycleRepository side-interface; wire it so the snooze
	// endpoint can write lifecycle_paused_until without going
	// through the full load-modify-save path.
	s.Asset.SetLifecycleRepository(repos.Asset)
	s.Asset.SetStateHistoryRepository(repos.AssetStateHistory)
	// Business-aligned risk scoring: score an asset's EFFECTIVE criticality —
	// MAX(own, its business unit, the business services it powers) — the SAME
	// floor rule (and the SAME lookup adapter) that finding-priority uses, so
	// risk_score and finding priority stop disagreeing. Batch-first; nil-safe
	// (falls back to own criticality). Raises scores for BU-critical assets only.
	s.Asset.SetBusinessContextLookup(postgres.NewBusinessContextLookupRepo(deps.DB))

	s.AssetGroup = app.NewAssetGroupService(repos.AssetGroup, log)
	s.AssetType = app.NewAssetTypeService(repos.AssetType, repos.AssetTypeCat, log)
	s.Scope = scope.NewService(repos.ScopeTarget, repos.ScopeExcl, repos.ScopeSchedule, repos.Asset, log)
	s.AttackSurface = attack.NewSurfaceService(repos.Asset, repos.AssetRelationship, log)
	// Wire the KEV/critical finding counter for exposure-chain analysis.
	s.AttackSurface.SetFindingRiskCounter(repos.Finding)
	// Continuous threat modeling: composes exposure chains + attacker profiles +
	// ATT&CK catalog + live findings into a per-scope threat model.
	s.ThreatModel = threatmodel.NewService(
		repos.ThreatModel, s.AttackSurface, repos.Asset, repos.AssetRelationship,
		repos.AttackerProfileReader, repos.Finding, log)
	s.AssetRelationship = app.NewAssetRelationshipService(repos.AssetRelationship, repos.Asset, log)
	s.RelationshipSuggestion = app.NewRelationshipSuggestionService(repos.RelationshipSuggestion, repos.Asset, repos.AssetRelationship, log)
	s.AssetImport = app.NewAssetImportService(repos.Asset, log)

	// Initialize finding source service (read-only system configuration)
	s.FindingSource = app.NewFindingSourceService(repos.FindingSource, repos.FindingSourceCat, log)

	// Initialize finding source cache service (global cache, 24h TTL)
	s.FindingSourceCache, err = app.NewFindingSourceCacheService(deps.RedisClient, repos.FindingSource, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding source cache service: %w", err)
	}

	// Initialize component & branch services
	s.Component = app.NewComponentService(repos.Component, repos.Asset, log)
	s.SBOMImport = app.NewSBOMImportService(repos.Component, repos.Asset, log)
	s.ReportSchedule = app.NewReportScheduleService(repos.ReportSchedule, log)
	s.Branch = app.NewBranchService(repos.Branch, log)

	// Initialize vulnerability & exposure services
	s.Vulnerability = app.NewVulnerabilityService(repos.Vulnerability, repos.Finding, log)
	s.Vulnerability.SetCommentRepository(repos.FindingComment)
	s.Vulnerability.SetDataFlowRepository(repos.DataFlow)        // Wire data flow loading
	s.Vulnerability.SetApprovalRepository(repos.FindingApproval) // Wire approval workflow
	s.Vulnerability.SetAccessControlRepository(repos.AccessControl)
	s.FindingActivity = app.NewFindingActivityService(repos.FindingActivity, repos.Finding, log)
	s.FindingActivity.SetUserRepo(repos.User) // Wire user lookup for activity broadcasts
	// Note: WebSocket broadcaster is wired later after WebSocketHub is initialized

	// Wire activity service dependencies
	s.Vulnerability.SetActivityService(s.FindingActivity) // Wire activity tracking
	s.Vulnerability.SetUserRepository(repos.User)         // Wire user lookup for activity records

	// Note: AITriage is wired to VulnerabilityService later after AITriage initialization

	// Initialize finding lifecycle service (closed-loop: fix_applied → verify → resolved)
	s.FindingActions = app.NewFindingActionsService(
		repos.Finding, repos.AccessControl, repos.Group, repos.Asset,
		s.FindingActivity, deps.DB, log,
	)
	// Finding source analytics: Tool Insights + the DefectDojo-dependency ratio
	// (RFC-013's measure-to-phase-out guardrail). repos.Finding provides the
	// SourceBreakdown query.
	s.SourceAnalytics = app.NewSourceAnalyticsService(repos.Finding, log)

	s.Exposure = app.NewExposureService(repos.Exposure, repos.ExposureStateHistory, log)
	s.ThreatIntel = threat.NewIntelService(repos.ThreatIntel, log)
	s.CredentialImport = app.NewCredentialImportService(repos.Exposure, repos.ExposureStateHistory, log)

	// Initialize dashboard service
	s.Dashboard = app.NewDashboardService(repos.Dashboard, log)

	// Initialize SLA service
	s.SLA = sla.NewService(repos.SLA, log)

	// Initialize Priority Classification service (RFC-004)
	epssAdapter := postgres.NewEPSSAdapter(repos.ThreatIntel.EPSS().(*postgres.EPSSRepository))
	kevAdapter := postgres.NewKEVAdapter(repos.ThreatIntel.KEV().(*postgres.KEVRepository))
	s.PriorityClassification = app.NewPriorityClassificationService(
		repos.Finding, repos.Asset,
		epssAdapter, kevAdapter,
		repos.PriorityRule, repos.PriorityAudit, log,
	)
	// Wire compensating controls into priority classification (RFC-005 Gap 6)
	s.PriorityClassification.SetControlLookup(postgres.NewCompensatingControlLookupRepo(deps.DB))

	// Business-aligned prioritization: raise an asset's effective criticality to
	// the MAX of {own, its business unit, the business services it powers} so BU /
	// service criticality actually drives priority. Batch-first; nil-safe.
	s.PriorityClassification.SetBusinessContextLookup(postgres.NewBusinessContextLookupRepo(deps.DB))

	// CTEM ownership rule: a finding on an asset with NO assigned owner cannot be
	// safely deprioritized, so it is floored at P2. Opt-in per tenant via
	// RiskScoring.FloorUnownedAtP2 (default OFF — no silent change for existing
	// tenants). The owner-presence lookup is batch + tenant-scoped and only runs
	// for tenants that enabled the floor.
	s.PriorityClassification.SetAssetOwnerLookup(postgres.NewAssetOwnershipLookupRepo(deps.DB))
	s.PriorityClassification.SetOwnershipFloorPolicy(app.NewTenantOwnershipFloorPolicy(repos.Tenant))

	// anti-flap priority flood guard. Caps per-tenant top-class
	// fan-out at 50/hour — protects Jira/outbox from scanner-induced
	// bursts while keeping the classification itself intact on the
	// dashboard.
	s.PriorityClassification.SetPriorityFloodGuard(app.NewPriorityFloodGuard(app.PriorityFloodConfig{}))

	// Close-the-loop: feed attack-path reachability (from the exposure-chain
	// graph) into prioritization, so an internal asset on a validated
	// internet→KEV/crown-jewel path is treated as reachable. Cached 5m/tenant.
	if s.AttackSurface != nil {
		s.PriorityClassification.SetReachabilityOracle(newReachabilityOracle(s.AttackSurface, 5*time.Minute))
	}

	// Close-the-loop (Part 1): feed the threat-model engine's output into
	// prioritization, so an asset the engine placed on an OPEN, high-score
	// modeled attack chain is treated as reachable. Nil-safe: no threat model /
	// no matching threat → no effect. Cached 5m/tenant.
	if repos.ThreatModel != nil {
		s.PriorityClassification.SetThreatModelOracle(
			newThreatModelOracle(repos.ThreatModel, defaultThreatScoreThreshold, 5*time.Minute))
	}

	// AI-triage de-escalation: feed a high-confidence "likely false positive"
	// verdict into prioritization so it can LOWER a finding by one bounded level
	// (the only signal that reduces priority). Batch-first, tenant-scoped, nil-safe
	// — no verdict / low confidence → no effect, never an escalation.
	s.PriorityClassification.SetAITriageVerdictLookup(postgres.NewAITriagePriorityLookupRepo(deps.DB))

	// B1/B2 reclassification pipeline wiring:
	//   producers → ControlChangePublisher → MemoryQueue
	//   PriorityReclassifyController (workers.go) → Reclassifier → ClassifyFinding
	// The publisher is nil-safe; handlers can call PublishChange even
	// when the queue/controller aren't running (logs a warn and drops).
	s.ReclassifyQueue = reclassify.NewMemoryQueue()
	s.ControlChangePub = controller.NewControlChangePublisher(s.ReclassifyQueue, log)
	s.Reclassifier = reclassify.NewReclassifier(
		repos.Finding, repos.Asset, s.PriorityClassification, log,
	)
	// Recompute the SLA deadline when a sweep escalates a finding's priority
	// (e.g. a CVE newly listed in KEV → P0), so the deadline tightens instead
	// of staying at its laxer pre-escalation value.
	s.Reclassifier.SetSLARecomputer(sla.NewApplier(s.SLA))

	// Manually-created findings (VulnerabilityService.CreateFinding, source=
	// 'manual') must run through the SAME priority/SLA brain as ingested
	// findings — otherwise they land with priority_class/sla_deadline NULL and
	// is_reachable=false, invisible to the P0-P3 dashboards, the priority queue,
	// and SLA. Reuse the exact classifier + SLA-service instances the ingest
	// path uses (see SetPriorityClassifier / SetSLAApplier on s.Ingest below).
	s.Vulnerability.SetAssetRepository(repos.Asset)
	s.Vulnerability.SetPriorityClassifier(s.PriorityClassification)
	if s.SLA != nil {
		s.Vulnerability.SetSLAApplier(sla.NewApplier(s.SLA))
	}

	// B6 runtime loop — IOC catalogue + correlator. The correlator is
	// attached to the runtime telemetry handler in handlers.go so every
	// accepted event is matched against active IOCs. Match side effects:
	//   - ioc_matches row (always, per hit)
	//   - closed finding auto-reopen via reopen_adapter (when IOC links
	//     back to a finding)
	s.IOCRepo = repos.IOC
	iocReopener := iocapp.NewFindingReopener(repos.Finding, s.Audit)
	s.IOCCorrelator = iocapp.NewCorrelator(s.IOCRepo, iocReopener, log)

	// bulk-action safety rail. Defaults: 500 rows/request,
	// 10k rows/tenant/hour. Attached to bulk finding handlers below.
	s.BulkGuard = app.NewBulkGuard(app.BulkGuardConfig{})

	// Initialize Pentest service
	s.Pentest = app.NewPentestService(
		repos.PentestCampaign, repos.PentestFinding,
		repos.PentestRetest, repos.PentestTemplate,
		repos.PentestReport, log,
	)
	// Wire unified finding repository for CTEM integration (pentest findings → findings table)
	s.Pentest.SetUnifiedFindingRepository(repos.Finding)
	s.Pentest.SetCampaignMemberRepository(repos.PentestCampaignMember)
	s.Pentest.SetAuditService(s.Audit)                     // audit logging for team changes + status changes
	s.Pentest.SetFindingActivityService(s.FindingActivity) // finding activity trail
	// Cross-tenant guard: reject adding a campaign member from another tenant.
	// The SetTenantMemberChecker seam was never wired, so the check was dead.
	s.Pentest.SetTenantMemberChecker(pentestTenantMemberAdapter{tenants: repos.Tenant})
	// Note: Pentest notification wiring happens later after NotificationService is initialized

	// Initialize Attachment service (file upload/download).
	// Storage provider selected via STORAGE_PROVIDER env var (default: "local").
	// Local path configurable via STORAGE_LOCAL_PATH (default: ./data/attachments).
	// In Docker: mount a volume at the local path to persist across rebuilds.
	var fileStorage attachment.FileStorage
	switch cfg.Storage.Provider {
	case "local", "":
		storagePath := cfg.Storage.LocalPath
		if storagePath == "" {
			storagePath = "./data/attachments"
		}
		fileStorage = storage.NewLocalStorage(storagePath)
		log.Info("attachment storage: local filesystem", "path", storagePath)
	default:
		// Future: case "s3", "minio", "gcs" → initialize respective provider
		log.Warn("unsupported storage provider, falling back to local", "provider", cfg.Storage.Provider)
		fileStorage = storage.NewLocalStorage("./data/attachments")
	}
	s.Attachment = app.NewAttachmentService(repos.Attachment, fileStorage, log)
	// Wire per-tenant storage resolution (tenants can configure S3/MinIO in settings)
	storageResolver := app.NewSettingsStorageResolver(deps.DB, s.Encryptor, log)
	s.Attachment.SetTenantStorageResolver(storageResolver, func(cfg attachment.StorageConfig) (attachment.FileStorage, error) {
		switch cfg.Provider {
		case "local":
			basePath := cfg.BasePath
			if basePath == "" {
				basePath = "./data/attachments"
			}
			return storage.NewLocalStorage(basePath), nil
		case "s3", "minio":
			return storage.NewS3Storage(cfg.Bucket, cfg.Region, cfg.Endpoint, cfg.AccessKey, cfg.SecretKey)
		default:
			return nil, fmt.Errorf("unsupported tenant storage provider: %s", cfg.Provider)
		}
	})
	// Wire the attachment store as the backing store for manual finding evidence
	// (POST/GET /findings/{id}/evidence). Tenant-scoped; does not touch the
	// pentest campaign gate.
	s.Vulnerability.SetEvidenceStore(s.Attachment)

	// Initialize Compliance service
	s.Simulation = app.NewSimulationService(repos.Simulation, repos.ControlTest, log)
	// Persist simulation runs (previously the run repo was never wired, so every
	// run was computed and discarded — run history was always empty).
	s.Simulation.SetRunRepo(repos.SimulationRun)
	// Validation (CTEM Stage-4): agents POST proof-of-fix / technique evidence,
	// which is persisted (redacted) and reconciled into finding status.
	evidenceStore := validation.NewEvidenceStore(repos.ValidationEvidence)
	// Stage-4's second question: "did our controls react?". Correlates
	// the tenant's runtime telemetry against each validation's execution
	// window. Reports no_telemetry_source (an explicit UNKNOWN) when no
	// telemetry is reaching the platform at all, so a missing EDR/XDR
	// integration is never rendered as a failed control.
	evidenceStore.SetDetectionCorrelator(
		validation.NewDetectionCorrelator(repos.TelemetryProbe),
	)
	s.ValidationEvidence = validation.NewEvidenceIngestService(
		evidenceStore,
		findingMutatorAdapter{repo: repos.Finding},
		nil, // retest notifier: optional; status revert still happens without it
		log,
	)
	// Producer side: dispatch a safe-check validation job for a finding. The
	// agent runs the probe and reports back; the command-completion hook maps
	// the result into evidence via ValidationEvidence above.
	s.ValidationRun = validation.NewRunService(
		repos.Finding,
		repos.Asset,
		validation.NewCommandDispatcher(repos.Command, log),
		validation.DefaultSelector{},
		[]validation.ExecutorKind{validation.KindSafeCheck},
		log,
	)
	// Capability-gate the dispatch on a live per-tenant check for an online
	// validation-capable agent, mirroring scan dispatch. Without this the API
	// would enqueue validate commands (on fix_applied auto-retest and live
	// simulation runs) even when no agent can execute them — the command would
	// sit unconsumed and the simulation run would strand in "running". With it,
	// dispatch is observably skipped until a validation agent is deployed, then
	// self-activates. See validation.ErrNoValidationAgent.
	s.ValidationRun.SetAgentAvailability(validationAgentAvailability{agents: repos.Agent})
	// RFC-012 Phase 1b: real safe-check dispatch. An eligible simulation
	// (network-addressable target + safe-checkable technique) runs for real via
	// the validation dispatcher; the command-completion hook finalizes the run.
	//
	// This MUST come after s.ValidationRun is assigned above. It used to sit 14
	// lines earlier, which stored a nil *validation.RunService in the
	// SafeCheckDispatcher interface — and a nil pointer in a non-nil interface
	// passes `s.safeCheck == nil`, so tryDispatchLive called through it and
	// panicked on the nil receiver instead of falling back to the synthetic
	// path.
	s.Simulation.SetSafeCheckDispatcher(s.ValidationRun)

	s.ThreatActor = threat.NewActorService(repos.ThreatActor, log)
	s.RemediationCampaign = app.NewRemediationCampaignService(repos.RemediationCampaign, log)
	// Wire the finding counter so campaign progress (finding_count/resolved_count/
	// progress) is computed from live finding data instead of staying at zero.
	s.RemediationCampaign.SetFindingCounter(repos.Finding)
	// Phase 3: let a campaign actively resolve its open findings (reuses the
	// finding bulk path + abuse guard).
	s.RemediationCampaign.SetFindingResolver(campaignFindingResolver{vuln: s.Vulnerability, guard: s.BulkGuard})
	s.BusinessUnit = app.NewBusinessUnitService(repos.BusinessUnit, repos.Asset, log)

	s.Compliance = app.NewComplianceService(
		repos.ComplianceFramework, repos.ComplianceControl,
		repos.ComplianceAssessment, repos.ComplianceMapping, log,
	)
	s.Compliance.SetFindingRepository(repos.Finding)

	// Initialize AI Triage service (if configured)
	if cfg.AITriage.IsConfigured() {
		llmFactory := llm.NewFactoryWithEncryption(cfg.AITriage, s.Encryptor)
		s.AITriage = app.NewAITriageService(
			repos.AITriage,
			repos.Finding,
			repos.Tenant,
			s.FindingActivity,
			llmFactory,
			cfg.AITriage,
			log,
		)
		s.AITriage.SetAuditService(s.Audit)
		s.Vulnerability.SetAITriageService(s.AITriage) // Wire auto-triage on finding creation

		// On triage completion, enqueue an asset-scoped reclassify so a
		// high-confidence false-positive verdict de-escalates the finding's
		// priority. Reuses the same MemoryQueue → Reclassifier → ClassifyFinding
		// pipeline the control/rule producers use (wired above).
		s.AITriage.SetReclassifyEnqueuer(aiTriageReclassifyEnqueuer{pub: s.ControlChangePub})

		// RFC-008: per-tenant LLM token budget. Always constructed so
		// Status() works for dashboards even before enforcement.
		// Check()/Record() short-circuit when BudgetEnabled=false —
		// the Phase 1 rollout ships the flag off so there is zero
		// behavior change on this deploy.
		budgetSvc := app.NewAITriageBudgetService(
			repos.AITriageBudget,
			app.AITriageBudgetServiceConfig{
				Enabled:               cfg.AITriage.BudgetEnabled,
				Strict:                cfg.AITriage.BudgetStrict,
				DefaultTokensPerMonth: cfg.AITriage.BudgetDefaultTokensPerMonth,
			},
			log,
		)
		s.AITriage.SetBudgetService(budgetSvc)
		log.Info("AI triage service initialized",
			"budget_enabled", cfg.AITriage.BudgetEnabled,
			"budget_strict", cfg.AITriage.BudgetStrict,
		)
	}

	// Initialize API Key & Webhook services. APP_ENCRYPTION_KEY is
	// reused as the apikey pepper so any new tenant API key created
	// from now on is stored as HMAC(pepper, key) instead of plain
	// SHA-256. See crypto.HashTokenPeppered. Unset key → unpeppered
	// (dev only; production startup already refuses this above).
	s.APIKey = apikey.NewService(repos.APIKey, cfg.Encryption.Key, log)
	// Gate user-scoped keys on active membership so member offboarding revokes
	// them immediately (the key's own status can't reflect member lifecycle).
	s.APIKey.SetMembershipChecker(apikeyMembershipAdapter{tenants: repos.Tenant})
	s.Webhook = app.NewWebhookService(repos.Webhook, s.Encryptor, log)

	// SCIM 2.0 provisioning (RFC-009): per-tenant bearer token + user lifecycle.
	s.SCIMToken = scim.NewTokenService(repos.ScimToken, cfg.Encryption.Key, log)
	s.SCIMProvisioning = scim.NewProvisioningService(
		repos.User, repos.Tenant, scimMembershipAdapter{svc: s.Tenant}, log,
	)
	s.SCIMGroups = scim.NewGroupService(
		repos.ScimGroup, repos.Tenant, scimMembershipAdapter{svc: s.Tenant}, log,
	)
	// Outbound Jira ticketing resolves a client per tenant from that tenant's
	// connected ticketing integration (base URL + decrypted credentials). The
	// static client stays nil; the resolver is the production path (mirrors the
	// per-tenant SMTP resolver). Without this wire, create-ticket is inert.
	s.JiraSync = jira.NewSyncService(repos.Finding, nil, log)
	jiraResolver := infrajira.NewIntegrationClientResolver(repos.Integration, s.Encryptor, log)
	s.JiraSync.SetClientResolver(jiraResolver)
	// Same resolver also surfaces the per-tenant status maps for outbound sync.
	s.JiraSync.SetMappingResolver(jiraResolver)
	// Routing rules can match on a finding's asset scope/criticality — resolve
	// that context from the asset repository.
	s.JiraSync.SetAssetRouteResolver(infrajira.NewAssetRouteResolver(repos.Asset))
	// Wire campaign→Jira-epic: the campaign service owns idempotency + link
	// persistence; JiraSync provides the per-tenant epic create. Both deps set
	// here (JiraSync is created after the campaign service above).
	if s.RemediationCampaign != nil {
		s.RemediationCampaign.SetTicketing(repos.RemediationCampaignTicket, s.JiraSync)
		// Inbound: a Jira webhook moving the campaign's epic to Done completes
		// the campaign (the reverse of the outbound transition above).
		s.JiraSync.SetCampaignSink(s.RemediationCampaign)
	}
	// GitHub Issues as a 2nd finding-ticket provider (selected per create-ticket
	// request); resolves the tenant's GitHub integration credentials on demand.
	s.GitHubTicket = ticketing.NewGitHubTicketService(repos.Finding, repos.Integration, s.Encryptor, log)

	// Initialize integration & notification services
	s.Integration = app.NewIntegrationService(repos.Integration, repos.IntegrationSCMExt, s.Encryptor, log)
	s.Integration.SetTransactionDB(deps.DB)
	s.Integration.SetNotificationExtensionRepository(repos.IntegrationNotificationExt)
	s.Integration.SetOutboxEventRepository(repos.OutboxEvent)
	s.Integration.SetRepoImportRepos(repos.Asset, repos.RepoExt, repos.Branch)

	s.Outbox = outbox.NewService(
		repos.Outbox,
		repos.OutboxEvent,
		repos.IntegrationNotificationExt,
		s.Encryptor.DecryptString,
		log.Logger,
	)

	// Wire outbox notification to vulnerability and exposure services
	s.Vulnerability.SetOutboxService(deps.DB, s.Outbox)
	s.Exposure.SetOutboxService(deps.DB, s.Outbox)

	// Priority-change publisher. PriorityClassificationService emits a
	// PriorityChangeEvent on every class transition and nil-guards the
	// publisher, so leaving this unwired made the whole path — the event, the
	// transition detection and the PriorityFloodGuard that protects its
	// fan-out — inert: a finding escalating to P0 was a silent dashboard
	// update. Wired here rather than next to the other
	// PriorityClassification setters because s.Outbox does not exist yet at
	// that point. The publisher itself filters to escalations only (see its
	// doc comment) so ingest does not double-notify alongside "new_finding".
	s.PriorityClassification.SetChangePublisher(
		app.NewOutboxPriorityChangePublisher(s.Outbox, log),
	)

	// Note: UserNotificationService is wired later after NotificationService is initialized

	// Note: NotificationService is wired later after WebSocketHub is initialized

	// Initialize agent & command services
	s.Agent = app.NewAgentService(repos.Agent, s.Audit, log)
	// Pepper the agent API-key hash with the platform encryption key
	// (or its absence in dev). HMAC-SHA256(pepper, key) stops a DB-only
	// leak from being brute-forced offline. New keys hash with pepper;
	// AuthenticateByAPIKey falls back to the legacy plain-SHA256 lookup
	// for rows written before the pepper was deployed.
	s.Agent.SetPepper(cfg.Encryption.Key)
	// Optional short-lived agent credentials (RFC-014 Phase 1b). Zero =
	// disabled (renewed keys never expire), preserving today's behavior.
	s.Agent.SetKeyTTL(cfg.AgentConfig.KeyTTL)
	// Multi-key store for rotation overlap (RFC-014 Phase 3). Additive: auth
	// still accepts the inline key; renewal under a TTL issues overlapping keys.
	s.Agent.SetAPIKeyRepository(repos.AgentAPIKey)
	// Operator-tunable load-balancing weights (AGENT_LB_*). Applied to the
	// load_score recomputed on every heartbeat.
	s.Agent.SetLoadBalancingWeights(cfg.Worker.LoadBalancing.Weights())
	s.Command = command.NewService(repos.Command, log)

	// Initialize ingest service (unified ingestion engine)
	s.Ingest = ingest.NewService(repos.Asset, repos.Finding, repos.Vulnerability, repos.Component, repos.Agent, repos.Branch, repos.Tenant, repos.Audit, log)
	// DefectDojo co-existence sync (RFC-013): pull a tenant's DefectDojo findings
	// and ingest them as CTIS (one-way; OpenCTEM is the system of record).
	s.DefectDojoSync = defectdojo.NewSyncService(repos.Integration, s.Ingest, s.Encryptor, log)
	s.Ingest.SetDataFlowRepository(repos.DataFlow)                   // Wire data flow persistence
	s.Ingest.SetComponentRepository(repos.Component)                 // Wire component linking for SCA findings
	s.Ingest.SetRepositoryExtensionRepository(repos.RepoExt)         // Wire repository extension for auto web_url
	s.Ingest.SetRelationshipRepository(repos.AssetRelationship)      // Wire subdomain-to-domain relationships
	s.Ingest.SetAssetStateHistoryRepository(repos.AssetStateHistory) // Record appeared/recovered on discovery
	s.Ingest.SetActivityService(s.FindingActivity)                   // Wire activity logging for auto-resolve/reopen
	// Ingest audit events are tenant-scoped, so they must go through the SAME
	// audit service instance as every other tenant-scoped event: LogEvent also
	// extends the per-tenant tamper-evident hash chain, and its chainMu is what
	// serializes concurrent appends. Without this, ingest.completed /
	// ingest.partial_success rows land in audit_logs unchained.
	s.Ingest.SetAuditService(s.Audit)
	// Wire IP correlation for host dedup (RFC-001)
	// System defaults; per-tenant overrides come from tenant settings at ingest time
	s.Ingest.SetCorrelator(ingest.NewAssetCorrelator(repos.Asset, log, ingest.CorrelationConfig{
		StaleAssetDays: 30,
		MaxIPsPerAsset: 20,
	}))
	// Enqueue an admin dedup review when correlation finds multiple existing
	// assets sharing identity (RFC-001) — populates the previously-empty queue.
	s.Ingest.SetDedupEnqueuer(repos.AssetDedup)

	// Initialize scanning services
	s.ScanProfile = app.NewScanProfileService(repos.ScanProfile, log)
	s.ScanSession = app.NewScanSessionService(repos.ScanSession, repos.Agent, log)
	s.ScannerTemplate = app.NewScannerTemplateService(repos.ScannerTemplate, cfg.Encryption.Key, log)
	s.TemplateSource = template.NewSourceService(repos.TemplateSource, log)

	// Initialize credential service for template sources
	// Decode hex key to bytes (64 hex chars -> 32 bytes for AES-256)
	var encryptionKey []byte
	if cfg.Encryption.IsConfigured() {
		encryptionKey, err = hex.DecodeString(cfg.Encryption.Key)
		if err != nil {
			// Fallback to raw bytes if not hex encoded
			encryptionKey = []byte(cfg.Encryption.Key)
		}
	} else {
		// Use a zero key for development (secret store will still work but is not secure)
		log.Warn("APP_ENCRYPTION_KEY not configured - secret store using zero key (development only)")
		encryptionKey = make([]byte, 32)
	}
	s.SecretStore, err = app.NewSecretStoreService(repos.SecretStore, encryptionKey, s.Audit, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secret store service: %w", err)
	}

	// Initialize template syncer for fetching templates from external sources
	s.TemplateSyncer = template.NewSyncer(
		repos.TemplateSource,
		repos.ScannerTemplate,
		s.SecretStore,
		encryptionKey,
		log,
	)

	// Wire up template syncer to source service for force sync API
	s.TemplateSource.SetTemplateSyncer(s.TemplateSyncer)

	s.Tool = tool.NewService(repos.Tool, repos.TenantToolConfig, repos.ToolExecution, log)
	s.Tool.SetAgentRepo(repos.Agent)           // Enable tool availability checking
	s.Tool.SetCategoryRepo(repos.ToolCategory) // Enable category info in responses
	s.ToolCategory = tool.NewCategoryService(repos.ToolCategory, repos.Tool, log)
	s.Capability = app.NewCapabilityService(repos.Capability, s.Audit, log)

	// Initialize agent selector for load balancing
	s.AgentSelector = app.NewAgentSelector(repos.Agent, repos.Command, deps.AgentStateStore, log)
	// Same AGENT_LB_* weights drive job placement, so tuning them changes
	// scheduling and not just the reported score.
	s.AgentSelector.SetLoadBalancingWeights(cfg.Worker.LoadBalancing.Weights())

	// Initialize security validator for pipeline/scan operations
	securityValidator := app.NewSecurityValidator(repos.Tool, log)

	// Create adapters for scan sub-package (clean architecture - each package defines its own interfaces)
	scanAuditAdapter := app.NewScanAuditServiceAdapter(s.Audit)
	scanAgentSelectorAdapter := app.NewScanAgentSelectorAdapter(s.AgentSelector)
	templateScanAdapter := template.NewScanAdapter(s.TemplateSyncer)
	scanSecurityValidatorAdapter := app.NewScanSecurityValidatorAdapter(securityValidator)

	// Initialize scan service with adapters for its interfaces
	s.Scan = scan.NewService(
		repos.Scan,
		repos.PipelineTemplate,
		repos.AssetGroup,
		repos.PipelineRun,
		repos.PipelineStep,
		repos.StepRun,
		repos.Command,
		repos.ScannerTemplate,
		repos.TemplateSource,
		repos.Tool,
		templateScanAdapter,
		scanAgentSelectorAdapter,
		scanSecurityValidatorAdapter,
		log,
		scan.WithAuditService(scanAuditAdapter),
		scan.WithProfileRepo(repos.ScanProfile),
		// Enforce scope EXCLUSIONS at scan target selection (fail-open).
		scan.WithScopeExclusionFilter(s.Scope),
	)

	// Wire verification scan trigger: allows FindingActionsService to launch targeted scans
	// when a finding transitions to fix_applied and the user requests scan-based verification.
	s.FindingActions.SetVerificationScanTrigger(app.NewVerificationScanTriggerAdapter(s.Scan))

	// Closed-loop CTEM: auto-queue a proof-of-fix safe-check re-check when
	// findings transition to fix_applied, so a "fixed" claim is verified rather
	// than trusted. Bounded + best-effort; non-network findings are skipped.
	s.FindingActions.SetAutoValidator(s.ValidationRun)

	// B3 wire: when a Jira "Done" webhook arrives and the
	// finding transitions to fix_applied, automatically trigger a
	// verification scan via FindingActions. Per-finding 24h cooldown
	// prevents scanner thrash from chatty Jira automation rules.
	// Without this wire Jira "Done" would only update status and
	// leave the "did the fix actually work?" question unanswered.
	if s.JiraSync != nil && s.FindingActions != nil && repos.Finding != nil {
		rescanHook := jira.NewRescanHook(s.FindingActions, repos.Finding, log)
		s.JiraSync.SetPostFixAppliedHook(rescanHook.Hook)
	}

	// Create adapters for pipeline sub-package
	pipelineAuditAdapter := app.NewPipelineAuditServiceAdapter(s.Audit)
	pipelineAgentSelectorAdapter := app.NewPipelineAgentSelectorAdapter(s.AgentSelector)
	pipelineSecurityValidatorAdapter := app.NewPipelineSecurityValidatorAdapter(securityValidator)

	// Initialize pipeline service with security validator, audit service, transaction support, and tool repo
	s.Pipeline = pipeline.NewService(
		repos.PipelineTemplate,
		repos.PipelineStep,
		repos.PipelineRun,
		repos.StepRun,
		repos.Agent,
		repos.Command,
		pipelineSecurityValidatorAdapter,
		log,
		pipeline.WithAuditService(pipelineAuditAdapter),
		pipeline.WithDB(deps.DB),
		pipeline.WithAgentSelector(pipelineAgentSelectorAdapter),
		pipeline.WithToolRepo(repos.Tool),
		pipeline.WithQualityGate(repos.ScanProfile, repos.Finding),
		pipeline.WithScanDeactivator(s.Scan),     // Cascade pause scans when pipeline is deactivated
		pipeline.WithScanRunRecorder(repos.Scan), // Record run outcome back onto the scan (last_run_status/counters)
	)

	// Wire up pipeline deactivator to tool service for cascade deactivation
	// When a tool is deactivated/deleted, all active pipelines using it will be deactivated
	s.Tool.SetPipelineDeactivator(s.Pipeline)

	// Initialize workflow executor
	workflowExecutor := app.NewWorkflowExecutor(
		repos.Workflow,
		repos.WorkflowRun,
		repos.WorkflowNodeRun,
		log,
		app.WithExecutorDB(deps.DB),
		app.WithExecutorOutboxService(s.Outbox),
		app.WithExecutorIntegrationService(s.Integration),
		app.WithExecutorAuditService(s.Audit),
	)

	// Register all action handlers for the workflow executor. Use the AI-aware
	// variant so trigger_ai_triage is actually registered (it was coded but the
	// non-AI register never wired it), and pass the Jira/GitHub ticket adapters
	// so create_ticket/update_ticket file real issues instead of returning a
	// false success. Adapters are built only when the underlying service exists
	// so a nil service yields a nil interface (not a non-nil box over nil).
	var wfJira app.WorkflowJiraTicketService
	if s.JiraSync != nil {
		wfJira = workflowJiraTicketAdapter{svc: s.JiraSync}
	}
	var wfGitHub app.WorkflowGitHubTicketService
	if s.GitHubTicket != nil {
		wfGitHub = workflowGitHubTicketAdapter{svc: s.GitHubTicket}
	}
	app.RegisterAllActionHandlersWithAI(
		workflowExecutor,
		s.Vulnerability,
		s.Pipeline,
		s.Scan,
		s.Integration,
		s.AITriage,
		wfJira,
		wfGitHub,
		log,
	)

	// Initialize workflow service with executor
	s.Workflow = app.NewWorkflowService(
		repos.Workflow,
		repos.WorkflowNode,
		repos.WorkflowEdge,
		repos.WorkflowRun,
		repos.WorkflowNodeRun,
		log,
		app.WithWorkflowAuditService(s.Audit),
		app.WithWorkflowExecutor(workflowExecutor),
	)

	// Initialize workflow event dispatcher for automatic workflow triggering
	s.WorkflowDispatcher = app.NewWorkflowEventDispatcher(
		repos.Workflow,
		repos.WorkflowNode,
		s.Workflow,
		log,
	)

	// Wire workflow dispatcher to ingest service for automatic workflow triggering
	// when new findings are created during ingestion
	s.Ingest.SetFindingCreatedCallback(s.WorkflowDispatcher.DispatchFindingsCreated)

	// Wire workflow dispatcher to the vulnerability service so a status change
	// (e.g. a resolve) auto-dispatches a `finding_status_changed` workflow event
	// — closes the resolve→verification automation loop the old inline TODO left
	// open. Best-effort/async inside the dispatcher.
	s.Vulnerability.SetWorkflowStatusDispatch(s.WorkflowDispatcher.DispatchFindingStatusChanged)

	// Wire AI-triage completion/failure into the same workflow dispatcher so
	// automation rules can trigger on triage verdicts. The SetWorkflowDispatcher
	// seam was never called, so AITriage silently emitted no workflow events.
	// s.WorkflowDispatcher is built just above (after the AITriage init block),
	// so the wire lives here rather than where AITriage is constructed.
	if s.AITriage != nil {
		s.AITriage.SetWorkflowDispatcher(s.WorkflowDispatcher)
	}

	// Wire priority classification into ingest (RFC-004)
	s.Ingest.SetPriorityClassifier(s.PriorityClassification)

	// F3 wire: every ingest now computes an SLA deadline using
	// priority class (falls back to severity) right after classification.
	// Without this wire the sla_deadline column stays NULL on new rows
	// and the sla_escalation controller has nothing to breach on.
	if s.SLA != nil {
		s.Ingest.SetSLAApplier(sla.NewApplier(s.SLA))
	}

	// Initialize suppression service (platform-controlled false positive management)
	s.Suppression = suppression.NewService(repos.Suppression, log)

	// Enforce approved suppression rules during ingest: a new finding matching an
	// active (approved, non-expired) rule lands resolved+suppressed (out of the
	// open backlog) and records which rule suppressed it. Loads rules once per
	// batch (tenant-scoped). Without this wire the suppression engine + CRUD +
	// approve/reject UI exist but suppress nothing on the ingest path. Nil-safe.
	s.Ingest.SetSuppressionChecker(s.Suppression)

	// Initialize access control services
	s.Group = app.NewGroupService(repos.Group, log,
		app.WithGroupAuditService(s.Audit),
		app.WithPermissionSetRepository(repos.PermissionSet),
		app.WithAccessControlRepository(repos.AccessControl),
	)

	s.AssignmentRule = assignment.NewRuleService(repos.AccessControl, repos.Group, log)
	s.ScopeRule = scope.NewRuleService(repos.AccessControl, repos.Group, log)
	s.ScopeRule.SetAssetGroupValidator(repos.AccessControl)

	// Wire scope rule hooks for real-time evaluation
	s.Asset.SetScopeRuleEvaluator(s.ScopeRule.EvaluateAsset)
	s.AssetGroup.SetScopeRuleReconciler(s.ScopeRule.ReconcileByAssetGroup)

	// Initialize assignment engine and wire to vulnerability service for auto-routing
	assignmentEngine := assignment.NewEngine(repos.AccessControl, log)
	// Resolve a finding's asset type so rules scoped by AssetTypes can match
	// (without this, such rules never fire).
	assignmentEngine.SetAssetTypeResolver(func(ctx context.Context, tenantID, assetID shared.ID) (string, error) {
		a, err := repos.Asset.GetByID(ctx, tenantID, assetID)
		if err != nil {
			return "", err
		}
		return a.Type().String(), nil
	})
	s.Vulnerability.SetAssignmentEngine(assignmentEngine)

	// Close the auto-assign gap on bulk ingest: route scanner-created findings
	// to groups post-insert, mirroring the single CreateFinding path. Lists
	// rules once per batch (not per finding) and bulk-inserts the assignments.
	s.Ingest.SetAssignmentApplier(assignment.NewBatchAssigner(assignmentEngine, repos.AccessControl, repos.Finding, log))

	// Remediation groups (RFC-015): derive each ingested finding's fix-identity
	// key so a whole "solution family" can be resolved in one action. The service
	// reuses the finding bulk-status path + its abuse guard.
	s.Ingest.SetRemediationKeyApplier(remediation.NewKeyApplier(repos.FindingRemediationKey, log))

	// Continuous leaked-credential discovery: promote secret-scan findings
	// (gitleaks/trufflehog → FindingSourceSecret) into the exposure store so a
	// hardcoded secret shows up in the Credentials/Exposures view without a
	// manual import. Labeled discovery_source=secret_scan so it stays distinct
	// from an external breach import. Reuses the same exposure repo + state
	// history as the credential-import service.
	s.Ingest.SetExposureBridge(exposurebridge.NewBridge(repos.Exposure, repos.ExposureStateHistory, log))
	s.RemediationGroup = remediation.NewGroupService(repos.FindingRemediationKey, s.Vulnerability, s.BulkGuard, log)

	// A remediation campaign can be scoped to a group key (solution family): its
	// progress + resolve then run off the side-table / group-resolve path rather
	// than a generic finding filter. Wired here (not at campaign construction)
	// because it needs the group service built above.
	if s.RemediationCampaign != nil {
		s.RemediationCampaign.SetKeyResolver(campaignKeyResolver{keys: repos.FindingRemediationKey, group: s.RemediationGroup})
	}

	// Wire engine and finding repo to assignment rule service for TestRule
	s.AssignmentRule.SetAssignmentEngine(assignmentEngine)
	s.AssignmentRule.SetFindingRepository(repos.Finding)

	s.Permission = app.NewPermissionService(repos.PermissionSet, log,
		app.WithPermissionAuditService(s.Audit),
		app.WithPermissionAccessControlRepository(repos.AccessControl),
		app.WithPermissionGroupRepository(repos.Group),
	)

	// Initialize permission sync services
	s.PermVersion = app.NewPermissionVersionService(deps.RedisClient, log)
	s.PermCache, err = app.NewPermissionCacheService(deps.RedisClient, repos.Role, s.PermVersion, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize permission cache service: %w", err)
	}

	// Initialize membership cache. Hard error if Redis is unreachable
	// at boot — without this cache the RequireMembership middleware
	// hammers the database on every request.
	s.MembershipCache, err = app.NewMembershipCacheService(deps.RedisClient, repos.Tenant, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize membership cache service: %w", err)
	}

	s.Role = app.NewRoleService(repos.Role, repos.RolePermission, log,
		app.WithRoleAuditService(s.Audit),
		app.WithRolePermissionVersionService(s.PermVersion),
		app.WithRolePermissionCacheService(s.PermCache),
		app.WithRoleMembershipReader(s.MembershipCache),
	)

	// Wire permission services to tenant service
	s.Tenant.SetPermissionServices(s.PermCache, s.PermVersion)

	// Wire membership cache so mutations (suspend / reactivate / role
	// change / member removal) can drop the cached entry immediately.
	s.Tenant.SetMembershipCache(s.MembershipCache)

	// Wire role service so invitation.RoleIDs() are applied on accept.
	// Without this, the RBAC roles attached to an invitation are
	// silently dropped — security audit finding (privilege escalation
	// inverse: legitimate roles never granted).
	s.Tenant.SetRoleService(s.Role)

	// Initialize licensing service (OSS edition - modules from database)
	s.Module = app.NewModuleService(repos.Module, log)
	s.Module.SetTenantModuleRepo(repos.TenantModule)
	s.Module.SetAuditService(s.Audit)
	// Product-bundle subscription: resolves the enabled-module baseline live from
	// the tenant's chosen bundles (empty = every module on, backward-compatible).
	s.Module.SetBundleStore(moduleBundleStore{tenants: repos.Tenant, db: deps.DB})
	// Per-tenant module-config version counter (Redis-backed). Used
	// for ETag generation on module-list endpoints and as the cache-
	// key suffix in any future Redis payload cache. Bumped on every
	// toggle / preset apply / reset via notifyModuleChange.
	s.Module.SetVersionService(app.NewModuleVersionService(deps.RedisClient, log))

	// Initialize WebSocket hub for real-time features
	s.WebSocketHub = websocket.NewHub(log)
	log.Info("websocket hub initialized")

	// Wire WebSocket broadcasters - must be done AFTER WebSocketHub is initialized
	broadcaster := &wsHubBroadcaster{hub: s.WebSocketHub}

	// Wire to FindingActivity for real-time activity updates on finding:* channels
	if s.FindingActivity != nil {
		s.FindingActivity.SetBroadcaster(broadcaster)
		log.Info("FindingActivity broadcaster wired to WebSocket hub")
	}

	// Wire to AI Triage for real-time triage updates on triage:* channels
	if s.AITriage != nil {
		s.AITriage.SetTriageBroadcaster(broadcaster)
		log.Info("AI triage broadcaster wired to WebSocket hub")
	}

	// Wire to ScopeRule for real-time scope rule changes on group:* channels
	if s.ScopeRule != nil {
		s.ScopeRule.SetBroadcaster(broadcaster)
		log.Info("ScopeRule broadcaster wired to WebSocket hub")
	}

	// Initialize user notification service (needs WebSocketHub)
	s.Notification = app.NewNotificationService(
		repos.Notification,
		s.WebSocketHub,
		log,
	)
	log.Info("user notification service initialized")

	// Wire notification service to GroupService for member notifications
	s.Group.SetNotificationService(s.Notification)

	// Wire in-app notification service to vulnerability service for real-time user notifications
	s.Vulnerability.SetUserNotificationService(s.Notification)

	// Wire in-app notification service to pentest service
	s.Pentest.SetUserNotificationService(s.Notification)

	return s, nil
}

// InitAuthServices initializes authentication-related services.
// Should be called only if local auth is supported.
func (s *Services) InitAuthServices(cfg *config.Config, repos *Repositories, log *logger.Logger, redisClient *redis.Client) {
	// Initialize JWT generator
	s.JWTGenerator = jwt.NewGenerator(jwt.TokenConfig{
		Secret:               cfg.Auth.JWTSecret,
		Issuer:               cfg.Auth.JWTIssuer,
		AccessTokenDuration:  cfg.Auth.AccessTokenDuration,
		RefreshTokenDuration: cfg.Auth.RefreshTokenDuration,
	})

	// Initialize session service
	s.Session = app.NewSessionService(repos.Session, repos.RefreshToken, log)

	// Initialize auth service
	s.Auth = app.NewAuthService(repos.User, repos.Session, repos.RefreshToken, repos.Tenant, s.Audit, cfg.Auth, log)
	s.Auth.SetRoleService(s.Role)
	// Stamp the current permission version onto issued access tokens so the
	// permission-sync middleware can reject stale tokens after a role change
	// (AUTHZ-3). Without this the JWT carries pv=0 and the stale check is inert.
	s.Auth.SetPermissionVersionService(s.PermVersion)

	// F-8: single-use WebSocket ticket service, Redis-backed.
	if redisClient != nil {
		s.WSTicket = app.NewWSTicketService(newWSTicketStore(redisClient), 30*time.Second, log)
	}

	// Wire permission services to session service
	tenantMembershipAdapter := app.NewTenantMembershipAdapter(repos.Tenant)
	s.Session.SetPermissionServices(s.PermCache, s.PermVersion, tenantMembershipAdapter)

	// Wire session service to user service for session revocation on suspension
	s.User.SetSessionService(s.Session)

	// Wire session service to tenant service so SuspendMember can revoke
	// all sessions of a suspended user immediately. Without this, the
	// user's existing JWT continues to work on JWT-claim-scoped routes
	// (e.g. /api/v1/me/*, /api/v1/notifications) until it expires.
	s.Tenant.SetSessionService(s.Session)

	// Initialize SSO service for per-tenant identity provider authentication
	s.SSO = app.NewSSOService(
		repos.IdentityProvider,
		repos.Tenant,
		repos.User,
		repos.Session,
		repos.RefreshToken,
		s.Encryptor,
		cfg.Auth,
		log,
	)
	s.SSO.SetTenantMemberRepo(repos.Tenant)

	// SSO P1: DNS-TXT domain-ownership verification. Wired as the PRIMARY JIT
	// auto-provisioning gate — a non-member is auto-joined only when the email
	// domain is DNS-verified for the tenant (see SSOService.jitProvisioningAllowed).
	s.DomainVerify = domainverify.NewService(repos.VerifiedDomain, domainverify.NewNetResolver(), log)
	s.SSO.SetDomainVerifier(s.DomainVerify)

	// Social OAuth (Google / GitHub / Microsoft). Built only when at least one
	// provider actually has credentials, so the login surface the API advertises
	// on /auth/providers matches the routes it registers — see registerAuthRoutes.
	if cfg.OAuth.Enabled && cfg.OAuth.HasAnyProvider() {
		s.OAuth = app.NewOAuthService(
			repos.User,
			repos.Session,
			repos.RefreshToken,
			cfg.OAuth,
			cfg.Auth,
			log,
		)
	}

	// SAML 2.0 SP (RFC-009 9d/9e): reuses SSO's session/provisioning tail.
	s.SAML = app.NewSAMLService(repos.SAMLProvider, repos.Tenant, s.SSO, log)

	// Wire the SSO-path checker so TenantService can refuse enabling sso_enforced
	// when the tenant has no usable SSO login path. main.go rebuilds s.Tenant, so
	// this is re-applied there too.
	s.Tenant.SetSSOPathChecker(s.SSO)
}

// InitEmailServices initializes email-related services.
func (s *Services) InitEmailServices(cfg *config.Config, log *logger.Logger) error {
	if !cfg.SMTP.IsConfigured() {
		log.Warn("email service not configured - email features will be disabled")
		return nil
	}

	emailSender := email.NewSMTPSender(email.Config{
		Host:       cfg.SMTP.Host,
		Port:       cfg.SMTP.Port,
		User:       cfg.SMTP.User,
		Password:   cfg.SMTP.Password,
		From:       cfg.SMTP.From,
		FromName:   cfg.SMTP.FromName,
		TLS:        cfg.SMTP.TLS,
		SkipVerify: cfg.SMTP.SkipVerify,
		Timeout:    cfg.SMTP.Timeout,
	})
	s.Email = app.NewEmailService(emailSender, cfg.SMTP, cfg.App.Name, log)
	log.Info("email service initialized", "host", cfg.SMTP.Host, "from", cfg.SMTP.From)

	return nil
}

// Note: SetEmailEnqueuer was removed. The previous implementation
// rebuilt s.Tenant with `app.NewTenantService(nil, nil, ...)`, which
// dropped the repo and the logger and would panic on any subsequent
// call. The actual wiring of the email enqueuer happens in main.go
// where it can also re-attach the permission and session services
// after the tenant service is reconstructed.

// initEncryptor initializes the credentials encryptor.
func initEncryptor(cfg *config.Config, log *logger.Logger) (crypto.Encryptor, error) {
	if !cfg.Encryption.IsConfigured() {
		// Refuse to start in production without encryption key.
		// Plaintext credentials in production is a CRITICAL security risk.
		if cfg.App.Env == config.EnvProduction {
			return nil, fmt.Errorf("APP_ENCRYPTION_KEY is required in production (APP_ENV=production); refusing to start with plaintext credentials")
		}
		// Even in non-production, require an EXPLICIT opt-in to use
		// plaintext storage. Audit finding: silent fallback meant
		// developers could ship credentials to staging/test environments
		// thinking they were encrypted. Now an env var must be set
		// intentionally — making the security trade-off visible.
		if !cfg.Encryption.AllowPlaintext {
			return nil, fmt.Errorf("APP_ENCRYPTION_KEY is not set; to use plaintext credential storage in non-production set APP_ALLOW_PLAINTEXT_CREDENTIALS=true explicitly (NEVER do this in production)")
		}
		log.Warn("APP_ENCRYPTION_KEY not configured - credentials will be stored in plaintext (DEVELOPMENT ONLY, ALLOW_PLAINTEXT_CREDENTIALS=true)")
		return crypto.NewNoOpEncryptor(), nil
	}

	var encryptor crypto.Encryptor
	var err error

	switch cfg.Encryption.KeyFormat {
	case "hex":
		encryptor, err = crypto.NewCipherFromHex(cfg.Encryption.Key)
	case "base64":
		encryptor, err = crypto.NewCipherFromBase64(cfg.Encryption.Key)
	default:
		encryptor, err = crypto.NewCipher([]byte(cfg.Encryption.Key))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize credentials encryptor: %w", err)
	}

	log.Info("credentials encryption enabled")
	return encryptor, nil
}

// NewJobClient creates a new job client for background processing.
func NewJobClient(cfg *config.Config, log *logger.Logger) (*jobs.Client, error) {
	redisAddr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
	jobClientCfg := jobs.ClientConfig{
		RedisAddr:     redisAddr,
		RedisPassword: cfg.Redis.Password,
		RedisDB:       cfg.Redis.DB,
	}

	client, err := jobs.NewClient(jobClientCfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize job client: %w", err)
	}

	log.Info("job client initialized", "redis_addr", redisAddr)
	return client, nil
}

// NewJobWorker creates a new job worker for processing background jobs.
//
// Every argument except cfg and log is optional; a nil dependency only disables
// its own handler. In particular a nil emailService must NOT stop the worker
// from being built: the AI-triage, Jira sync and GitHub sync handlers live on
// the same asynq server, their tasks are enqueued whether or not SMTP is on,
// and SMTP_ENABLED defaults to false. Returning early here (as this used to)
// left those queues with no consumer in a default deployment.
func NewJobWorker(cfg *config.Config, emailService *app.EmailService, aiTriageService *app.AITriageService, jiraSyncer jobs.JiraStatusSyncer, githubSyncer jobs.GitHubStatusSyncer, log *logger.Logger) (*jobs.Worker, error) {
	redisAddr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
	workerCfg := jobs.WorkerConfig{
		RedisAddr:     redisAddr,
		RedisPassword: cfg.Redis.Password,
		RedisDB:       cfg.Redis.DB,
		Concurrency:   5,
	}

	// Build worker options
	var opts []jobs.WorkerOption
	if aiTriageService != nil {
		opts = append(opts, jobs.WithAITriageProcessor(aiTriageService))
	}
	if jiraSyncer != nil {
		opts = append(opts, jobs.WithJiraStatusSyncer(jiraSyncer))
	}
	if githubSyncer != nil {
		opts = append(opts, jobs.WithGitHubStatusSyncer(githubSyncer))
	}

	worker, err := jobs.NewWorker(workerCfg, emailService, log, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize job worker: %w", err)
	}

	log.Info("job worker initialized")
	return worker, nil
}
