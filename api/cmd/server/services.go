package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/aitriage"
	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/capability"
	"github.com/openctemio/openctem/api/internal/app/compliance"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/app/workflow"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/telemetry"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/app/assignment"
	"github.com/openctemio/openctem/api/internal/app/command"
	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/internal/app/defectdojo"
	"github.com/openctemio/openctem/api/internal/app/remediation"
	savedviewapp "github.com/openctemio/openctem/api/internal/app/savedview"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/internal/app/tool"

	"github.com/openctemio/openctem/api/internal/app"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	accessrequestapp "github.com/openctemio/openctem/api/internal/app/accessrequest"
	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/internal/app/assetdiscovery"
	"github.com/openctemio/openctem/api/internal/app/attack"
	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	certmonitorapp "github.com/openctemio/openctem/api/internal/app/certmonitor"
	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	ctemidapp "github.com/openctemio/openctem/api/internal/app/ctemid"
	easmdnsapp "github.com/openctemio/openctem/api/internal/app/easmdns"
	entitlementapp "github.com/openctemio/openctem/api/internal/app/entitlement"
	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/app/exposurebridge"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/jira"
	lifecycleapp "github.com/openctemio/openctem/api/internal/app/lifecycle"
	orgtrustapp "github.com/openctemio/openctem/api/internal/app/orgtrust"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/internal/app/reclassify"
	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/app/scan"
	scanfreezeapp "github.com/openctemio/openctem/api/internal/app/scanfreeze"
	scanzoneapp "github.com/openctemio/openctem/api/internal/app/scanzone"
	"github.com/openctemio/openctem/api/internal/app/scim"
	signupapp "github.com/openctemio/openctem/api/internal/app/signup"
	"github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/internal/app/template"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/app/threatmodel"
	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	infrajira "github.com/openctemio/openctem/api/internal/infra/jira"
	"github.com/openctemio/openctem/api/internal/infra/jobs"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	contentpackdom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/credential"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/secretstore"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
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

// RecordVerdict implements validation.VerdictRecorder: the durable side-write of
// the confirm-or-downgrade verdict (validation_outcome / downgraded_at) that
// feeds the downgrade % metric.
func (a findingMutatorAdapter) RecordVerdict(ctx context.Context, tenantID, findingID shared.ID, verdict validation.Verdict, downgradedAt *time.Time) error {
	return a.repo.StampValidationVerdict(ctx, tenantID, findingID, string(verdict), downgradedAt)
}

// validationSensorAvailability answers "is a validation-capable sensor online for
// this tenant?" by reusing the exact capability query scan dispatch uses
// (SensorRepository.FindAvailableWithCapacity). It gates validation.RunService so
// a validate command is only ever queued when a real sensor can consume it —
// otherwise the command would sit in the queue forever and a live simulation run
// would be stranded in "running". The gate is self-arming: it opens the moment a
// tenant registers a sensor advertising the "validate" capability.
type validationSensorAvailability struct {
	sensors *postgres.SensorRepository
}

func (v validationSensorAvailability) HasValidationSensor(ctx context.Context, tenantID shared.ID) (bool, error) {
	sensors, err := v.sensors.FindAvailableWithCapacity(ctx, tenantID, []string{validation.SensorCapabilityValidate}, "")
	if err != nil {
		return false, err
	}
	return len(sensors) > 0, nil
}

// HasNucleiValidationSensor gates the deeper KindNuclei re-verify rung (RFC-011.2
// Phase 2b) on a live per-tenant check for a sensor advertising the
// `validate:nuclei` capability. Self-arming exactly like the base gate: routing
// upgrades from safe-check to a real single-template re-run the moment a tenant
// deploys a nuclei-capable validation sensor, and degrades back with no code
// change if it goes offline.
func (v validationSensorAvailability) HasNucleiValidationSensor(ctx context.Context, tenantID shared.ID) (bool, error) {
	sensors, err := v.sensors.FindAvailableWithCapacity(ctx, tenantID, []string{validation.SensorCapabilityValidateNuclei}, "")
	if err != nil {
		return false, err
	}
	return len(sensors) > 0, nil
}

// HasRetestSensor reports whether a sensor of the tenant is online, with
// capacity, whose tool has a retest handler (capability "retest:<tool>"), the
// capability a retest command for that tool requires.
func (v validationSensorAvailability) HasRetestSensor(ctx context.Context, tenantID shared.ID, tool string) (bool, error) {
	if !validation.ValidRetestTool(tool) {
		return false, nil
	}
	sensors, err := v.sensors.FindAvailableWithCapacity(ctx, tenantID, []string{validation.RetestCapability(tool)}, "")
	if err != nil {
		return false, err
	}
	return len(sensors) > 0, nil
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
	vuln  *finding.VulnerabilityService
	guard *finding.BulkGuard
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
	res, err := a.vuln.BulkUpdateFindingsStatus(ctx, tenantID, finding.BulkUpdateStatusInput{
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

func (a campaignKeyResolver) CountByKey(ctx context.Context, tenantID shared.ID, key string, scope *shared.DataScope) (int64, int64, error) {
	closed := vulnerability.ClosedFindingStatuses()
	closedStrs := make([]string, len(closed))
	for i, s := range closed {
		closedStrs[i] = string(s)
	}
	return a.keys.CountByKeyInScope(ctx, tenantID, key, closedStrs, scope)
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

// httpDataScopeCaller reads the acting user and the admin decision from the
// HTTP auth context for the Layer 2 data-scope enforcer.
func httpDataScopeCaller(ctx context.Context) datascope.Caller {
	return datascope.Caller{
		UserID:  middleware.GetUserID(ctx),
		IsAdmin: middleware.IsAdmin(ctx),
		APIKey:  middleware.GetAuthProvider(ctx) == middleware.AuthProviderAPIKey,
	}
}

// membershipAdminLookup decides admin status outside a request (WebSocket
// subscriptions, background jobs); see datascope.MembershipAdminLookup.
func membershipAdminLookup(tenants tenant.Repository) datascope.AdminLookup {
	return datascope.MembershipAdminLookup(tenants)
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

// workflowMemberReader is the automation principal's membership lookup.
type workflowMemberReader struct {
	tenants *postgres.TenantRepository
	access  *postgres.AccessControlRepository
}

func (r workflowMemberReader) GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenant.Membership, error) {
	return r.tenants.GetMembership(ctx, userID, tenantID)
}

func (r workflowMemberReader) IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	return r.access.IsActiveTenantMember(ctx, tenantID, userID)
}

// workflowPermissionReader reads the automation principal's permissions
// from the database (the union of their roles), never from a cache.
type workflowPermissionReader struct{ roles *postgres.RoleRepository }

func (r workflowPermissionReader) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	tid, err := role.ParseID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	uid, err := role.ParseID(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	return r.roles.GetUserPermissions(ctx, tid, uid)
}

// workflowPrincipalContext makes an automation step run as its principal:
// the same auth keys a request carries, so the services the step calls
// (data scope above all) treat it as that member and not as an
// unrestricted internal call.
func workflowPrincipalContext(ctx context.Context, p workflow.Principal) context.Context {
	perms := p.Permissions
	if perms == nil {
		perms = []string{}
	}
	ctx = context.WithValue(ctx, middleware.TenantIDKey, p.TenantID.String())
	ctx = context.WithValue(ctx, middleware.UserIDKey, p.UserID.String())
	ctx = context.WithValue(ctx, middleware.IsAdminKey, p.IsAdmin)
	ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
	return ctx
}

// workflowJiraTicketAdapter adapts *jira.SyncService to the workflow ticket
// action's JiraTicketService (primitive params, so the workflow package needn't
// import app/jira — that would cycle through the app shim).
type workflowJiraTicketAdapter struct{ svc *jira.SyncService }

func (a workflowJiraTicketAdapter) CreateTicketFromFinding(ctx context.Context, tenantID, findingID, projectKey, issueType string) (workflow.TicketRef, error) {
	info, err := a.svc.CreateTicketFromFinding(ctx, jira.CreateTicketInput{
		TenantID: tenantID, FindingID: findingID, ProjectKey: projectKey, IssueType: issueType,
	})
	if err != nil {
		return workflow.TicketRef{}, err
	}
	return workflow.TicketRef{Key: info.TicketKey, URL: info.TicketURL}, nil
}

func (a workflowJiraTicketAdapter) SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error {
	return a.svc.SyncFindingStatus(ctx, tenantID, findingID)
}

// workflowGitHubTicketAdapter adapts *ticketing.GitHubTicketService to the
// workflow ticket action's GitHubTicketService.
type workflowGitHubTicketAdapter struct {
	svc *ticketing.GitHubTicketService
}

func (a workflowGitHubTicketAdapter) CreateTicketFromFinding(ctx context.Context, tenantID, findingID, owner, repo string) (workflow.TicketRef, error) {
	info, err := a.svc.CreateTicketFromFinding(ctx, ticketing.GitHubTicketInput{
		TenantID: tenantID, FindingID: findingID, Owner: owner, Repo: repo,
	})
	if err != nil {
		return workflow.TicketRef{}, err
	}
	return workflow.TicketRef{Key: info.TicketKey, URL: info.TicketURL}, nil
}

// wsChannelAccess adapts the RBAC and group services to
// websocket.ChannelAccessChecker, so the hub can refuse a subscription to a
// finding, triage, scan or group channel the user is not allowed to read.
type wsChannelAccess struct {
	roles  *accesscontrol.RoleService
	groups *postgres.GroupRepository
	scope  *datascope.Enforcer
	runs   runReader // run:{id} channels (CanSeeRun); nil refuses them
}

// CanSeeFinding applies the Layer 2 data scope to finding and triage
// channels: the finding must exist in the tenant and be in the user's scope.
func (a wsChannelAccess) CanSeeFinding(ctx context.Context, tenantID, userID, findingID string) (bool, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false, err
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return false, err
	}
	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return false, err // not a finding id: refuse the subscription
	}
	if a.scope == nil {
		return true, nil
	}
	return a.scope.AssertFindingForUser(ctx, tid, uid, fid) == nil, nil
}

func (a wsChannelAccess) HasPermission(ctx context.Context, tenantID, userID, perm string) (bool, error) {
	return a.roles.HasPermission(ctx, tenantID, userID, perm)
}

func (a wsChannelAccess) IsGroupMember(ctx context.Context, tenantID, groupID, userID string) (bool, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false, err
	}
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return false, err
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return false, err
	}
	// The group must belong to the caller's tenant before membership counts.
	if _, err := a.groups.GetByTenantAndID(ctx, tid, gid); err != nil {
		return false, err
	}
	return a.groups.IsMember(ctx, gid, uid)
}

// wsHubBroadcaster adapts websocket.Hub to app.ActivityBroadcaster and app.TriageBroadcaster interfaces.
type wsHubBroadcaster struct {
	hub *websocket.Hub
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
	Auth    *auth.AuthService
	Session *auth.SessionService

	// Core
	Audit  *audit.AuditService
	User   *tenantapp.UserService
	Tenant *tenantapp.TenantService
	// UserProvisioning creates accounts on behalf of administrators.
	UserProvisioning *tenantapp.UserProvisioningService

	// DataScope enforces the Layer 2 (group) data scope on by-id reads and
	// writes and on indirect lists (asset groups, attack surface, exposures,
	// dashboards, notifications, WebSocket finding channels).
	DataScope *datascope.Enforcer

	// Assets
	Asset                  *asset.AssetService
	AssetGroup             *asset.AssetGroupService
	AssetType              *asset.AssetTypeService
	AssetRelationship      *asset.AssetRelationshipService
	AssetImport            *asset.AssetImportService
	RelationshipSuggestion *asset.RelationshipSuggestionService
	Scope                  *scope.Service
	AttackSurface          *attack.SurfaceService
	ThreatModel            *threatmodel.Service

	// Configuration (read-only system config)
	FindingSource      *finding.FindingSourceService
	FindingSourceCache *finding.FindingSourceCacheService

	// Vulnerabilities & Exposures
	Vulnerability   *finding.VulnerabilityService
	FindingActivity *activity.FindingActivityService
	FindingActions  *finding.FindingActionsService
	Exposure        *exposure.ExposureService
	ThreatIntel     *threat.IntelService
	CTEMID          *ctemidapp.Service
	CertMonitor     *certmonitorapp.Service
	// ActiveGate decides what an active scan may touch (RFC-036 §6.3).
	ActiveGate *easmapp.ActiveGate
	// ScopeJoin confirms discovered names a permanent scope target or seed
	// covers (RFC-054 §4.3).
	ScopeJoin *easmapp.ScopeJoin
	// ScopeGuardrails are the operator's scope guardrails (RFC-054 §8).
	ScopeGuardrails  scopedom.Guardrails
	EASMDNS          *easmdnsapp.Service
	EASMSweep        *easmapp.SweepService
	CredentialImport *integration.CredentialImportService

	// Components & Branches
	Component      *asset.ComponentService
	SBOMImport     *asset.SBOMImportService
	ReportSchedule *module.ReportScheduleService
	Branch         *asset.BranchService

	// Dashboard
	Dashboard *module.DashboardService

	// Per-user customizable dashboards (RFC-021)
	UserDashboard *dashboardapp.Service
	SavedView     *savedviewapp.Service

	// Integrations & Notifications
	Integration    *integration.IntegrationService
	DefectDojoSync *defectdojo.SyncService
	Outbox         *outbox.Service
	Notification   *integration.NotificationService

	// Sensors & Commands
	Sensor *sensorapp.SensorService
	// SensorPairing runs interactive pairing (RFC-052); nil when the
	// installation has no encryption key to derive the pairing key from.
	SensorPairing *sensorpairing.Service
	// SensorGrant manages per-sensor grants (RFC-052 §5).
	SensorGrant *sensorgrant.Service
	ScanZone    *scanzoneapp.Service
	// ScanFreeze manages scan freeze windows.
	ScanFreeze *scanfreezeapp.Service
	Command    *command.Service
	// SensorContent is the scanner content policy and refresh (RFC-031).
	SensorContent *sensorapp.ContentService
	// TenableSC queues and follows Tenable.sc connector syncs (RFC-047).
	TenableSC *tenablesc.Service
	// SensorPlatformHealth is the platform-health guard (RFC-035 D3): the
	// heartbeat handlers feed it their latency, the sensor health controller
	// holds offline convictions while it reports the platform degraded.
	SensorPlatformHealth *sensorapp.PlatformHealth
	Ingest               *ingest.Service

	// Scanning & ScanRuns
	ScanProfile     *scan.ScanProfileService
	Tool            *tool.Service
	ToolCategory    *tool.CategoryService
	Capability      *capability.CapabilityService
	Scan            *scan.Service
	ScanRun         *scanrun.Service
	ScannerTemplate *app.ScannerTemplateService
	TemplateSource  *template.SourceService
	SecretStore     *integration.SecretStoreService
	TemplateSyncer  *template.Syncer

	// TemplateKeys signs custom templates for sensors; nil when no key is
	// configured (see initTemplateKeyring).
	TemplateKeys *scannertemplate.Keyring

	// ContentPacks is the content pack store (RFC-061).
	ContentPacks *contentpackapp.Service

	// Workflows
	Workflow           *workflow.WorkflowService
	WorkflowDispatcher *workflow.WorkflowEventDispatcher

	// AssetDiscoveryNotifier turns newly discovered internet-facing assets into
	// throttled tenant notifications (in-app + new_asset outbox event).
	AssetDiscoveryNotifier *assetdiscovery.Notifier

	// Suppressions
	Suppression *suppression.Service

	// Sensor Selection
	SensorSelector *sensorapp.SensorSelector

	// Access Control
	Group          *accesscontrol.GroupService
	Role           *accesscontrol.RoleService
	AssignmentRule *assignment.RuleService
	ScopeRule      *scope.RuleService

	// Permission Sync
	PermVersion *accesscontrol.PermissionVersionService
	PermCache   *accesscontrol.PermissionCacheService

	// Membership cache (Redis-backed wrapper around tenant.Repository
	// .GetMembership). Read by RequireMembership +
	// RequireActiveMembershipFromJWT middlewares so the membership
	// status check on every tenant-scoped request becomes a Redis GET
	// instead of a DB round trip. Invalidated by TenantService when
	// role / status / membership rows change.
	MembershipCache *accesscontrol.MembershipCacheService

	// Module Service (OSS - all modules enabled, UI metadata only)
	Module *module.ModuleService

	// SLA
	SLA *sla.Service

	// Priority Classification (RFC-004)
	PriorityClassification *finding.PriorityClassificationService

	// B1/B2 reclassification pipeline — memory queue,
	// publisher (called from control CRUD), reclassifier (consumed
	// by the PriorityReclassifyController registered in workers.go).
	ReclassifyQueue  *reclassify.MemoryQueue
	ControlChangePub *controller.ControlChangePublisher
	Reclassifier     *reclassify.Reclassifier

	// IOC catalog.
	IOCRepo *postgres.IOCRepository

	// bulk-action guard (attached to finding bulk handlers).
	BulkGuard *finding.BulkGuard

	// Pentest
	Pentest    *compliance.PentestService
	Attachment *integration.AttachmentService

	// Compliance
	Compliance *compliance.ComplianceService

	// Attack Simulation & Control Testing
	Simulation *compliance.SimulationService

	// Validation (CTEM Stage-4): proof-of-fix / technique-execution evidence
	// recorded by sensors, reconciling finding status from the outcome.
	ValidationEvidence *validation.EvidenceIngestService
	// Retest runs continuous retests (RFC-039): Retest now, settle, auto ticks.
	Retest *retestapp.Service
	// Evidence: masked finding evidence, encrypted secret values, audited reveal.
	Evidence *evidenceapp.Service

	// ValidationRun dispatches validation (safe-check) jobs for findings.
	ValidationRun *validation.RunService

	// Threat Actor Intelligence
	ThreatActor *threat.ActorService

	// Remediation Campaigns
	RemediationCampaign *exposure.RemediationCampaignService
	RemediationGroup    *remediation.GroupService

	// Business Units
	BusinessUnit *asset.BusinessUnitService

	// API Keys & Webhooks
	APIKey *apikey.Service

	// Jira Bidirectional Sync
	JiraSync *jira.SyncService

	// GitHub Issues ticket provider (create-from-finding + link only)
	GitHubTicket *ticketing.GitHubTicketService

	// AI Triage
	AITriage *aitriage.AITriageService

	// WebSocket
	WebSocketHub *websocket.Hub
	// ModuleChangeBus fans module toggles out to every replica's route-gate
	// cache; nil without Redis. Started with the WebSocket bridge.
	ModuleChangeBus *redis.ModuleChangeBus
	// F-8: Single-use ticket service used by WS upgrade auth.
	// SessionRevocations rejects access tokens of signed-out sessions
	// immediately (nil without Redis).
	SessionRevocations *redis.SessionRevocationStore

	// Email
	Email        *auth.EmailService
	EmailEnqueue tenantapp.EmailJobEnqueuer

	// Encryption
	Encryptor crypto.Encryptor
	// CredentialSecrets seals leaked-credential secrets (built on Encryptor).
	CredentialSecrets *credential.SecretProtector

	// JWT
	JWTGenerator *jwt.Generator

	// SSO
	SSO *auth.SSOService

	// Social OAuth login (Google / GitHub / Microsoft). nil when no provider
	// is configured, which keeps the OAuth routes unregistered.
	OAuth *auth.OAuthService

	// Domain-ownership verification (SSO P1) — the verified-domain JIT gate.
	DomainVerify *domainverify.Service
	// AddressClassifier decides whether an invitee is internal or external
	// (RFC-058).
	AddressClassifier *tenantapp.AddressClassifier
	// OrgTrust manages trusted organizations (RFC-058).
	OrgTrust *orgtrustapp.Service

	// The platform sign-up policy (who may create an organization).
	Signup *signupapp.Service
	// The request-access queue (sign-up closed, requests allowed).
	AccessRequest *accessrequestapp.Service
	// Plans and limits.
	Entitlement *entitlementapp.Service
	// Idle Free workspaces (reminder, read-only, warnings, deletion due).
	IdleWorkspaces *lifecycleapp.Service

	// SAML 2.0 SP (RFC-009 9d/9e)
	SAML *auth.SAMLService

	// Admin-console SAML / identity-provider changes wait for an owner of
	// the organization (RFC-022).
	SSOChange *auth.SSOChangeService

	// SCIM 2.0 provisioning (RFC-009)
	SCIMToken        *scim.TokenService
	SCIMProvisioning *scim.ProvisioningService
	SCIMGroups       *scim.GroupService
}

// scimMembershipAdapter adapts TenantService to scim.MembershipManager, injecting
// a system audit context so SCIM-driven membership changes go through the full
// lifecycle (session revoke + permission-cache clear + audit).
type scimMembershipAdapter struct {
	svc *tenantapp.TenantService
}

func scimAuditContext(tenantID shared.ID) audit.AuditContext {
	return audit.AuditContext{TenantID: tenantID.String(), ActorEmail: "scim-provisioning"}
}

func (a scimMembershipAdapter) AddMember(ctx context.Context, tenantID, userID shared.ID, role string) error {
	_, err := a.svc.AddMember(ctx, tenantID.String(), tenantapp.AddMemberInput{UserID: userID, Role: role}, shared.ID{}, scimAuditContext(tenantID))
	return err
}

func (a scimMembershipAdapter) SuspendMember(ctx context.Context, tenantID, membershipID shared.ID) error {
	return a.svc.SuspendMember(ctx, membershipID.String(), scimAuditContext(tenantID))
}

func (a scimMembershipAdapter) ReactivateMember(ctx context.Context, tenantID, membershipID shared.ID) error {
	return a.svc.ReactivateMember(ctx, membershipID.String(), scimAuditContext(tenantID))
}

// OffboardMember is SCIM delete: offboard, or disable when the member owns
// work that an administrator must hand to someone first.
func (a scimMembershipAdapter) OffboardMember(ctx context.Context, tenantID, membershipID shared.ID) error {
	return a.svc.DeprovisionMember(ctx, membershipID.String(), scimAuditContext(tenantID))
}

// UpdateMemberRole satisfies scim.RoleManager for SCIM group → role mapping.
// With an actor (a mapping saved in the console) the change runs as that
// person, so the owner-only rule for changing an administrator applies and
// the audit entry names them. Without one (an identity-provider push) it runs
// as SCIM provisioning and the audit entry carries the SCIM token from the
// request context.
func (a scimMembershipAdapter) UpdateMemberRole(ctx context.Context, tenantID, membershipID shared.ID, role string, actorID *shared.ID) error {
	actx := scimAuditContext(tenantID)
	if actorID != nil {
		actx = audit.AuditContext{TenantID: tenantID.String(), ActorID: actorID.String()}
	}
	_, err := a.svc.UpdateMemberRole(ctx, membershipID.String(), tenantapp.UpdateMemberRoleInput{Role: role}, actx)
	return err
}

// ServiceDeps contains dependencies needed to create services.
type ServiceDeps struct {
	Config           *config.Config
	Log              *logger.Logger
	DB               *sql.DB
	Repos            *Repositories
	RedisClient      *redis.Client
	SensorStateStore *redis.SensorStateStore
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
	s.Audit = audit.NewAuditService(repos.Audit, log)

	// Plans and limits: every creation path checks the organization limits
	// (docs/architecture/plans-and-limits.md). Seats and invitations are
	// checked where the rows are inserted.
	s.Entitlement = entitlementapp.NewService(repos.Plan, repos.AdminAuditLog, repos.Admin, nil, log)
	s.IdleWorkspaces = lifecycleapp.NewService(repos.IdleLifecycle, s.Audit, repos.AdminAuditLog, repos.Admin, nil, log)
	for _, r := range []interface{ SetPlanLimits(plan.Checker) }{
		repos.Tenant, repos.Asset, repos.APIKey, repos.CIRun, repos.Sensor, repos.SensorPairing,
	} {
		r.SetPlanLimits(s.Entitlement)
	}

	// Initialize core services
	s.User = tenantapp.NewUserService(repos.User, log)
	s.Tenant = tenantapp.NewTenantService(repos.Tenant, log,
		tenantapp.WithTenantAuditService(s.Audit),
		tenantapp.WithUserInfoProvider(tenantapp.NewUserDisplayNames(repos.User)),
	)
	// The user service lets AddMember enforce Security.AllowedDomains and lets
	// the suspend/reactivate notifier resolve the recipient.
	s.Tenant.SetUserService(s.User)

	// Initialize asset services
	s.Asset = asset.NewAssetService(repos.Asset, log)
	s.Asset.SetRepositoryExtensionRepository(repos.RepoExt)
	// Wire owner_ref→user auto-resolution (was dead: SetUserMatcher never called,
	// so an email owner_ref never resolved to a real user_id). Membership-checked.
	s.Asset.SetUserMatcher(assetOwnerMatcher{users: repos.User, tenants: repos.Tenant})
	s.Asset.SetAssetGroupRepository(repos.AssetGroup)
	s.Asset.SetAccessControlRepository(repos.AccessControl)
	// One Layer 2 enforcer for every service: the caller comes from the HTTP
	// auth context, so the admin decision is the auth layer's. A member with
	// no scope row sees nothing, in every organization.
	s.DataScope = datascope.New(repos.DataScope, httpDataScopeCaller, log)
	s.DataScope.SetAdminLookup(membershipAdminLookup(repos.Tenant))
	s.Asset.SetDataScope(s.DataScope)
	s.Asset.SetScoringConfigProvider(asset.NewTenantScoringConfigProvider(repos.Tenant))
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

	s.AssetGroup = asset.NewAssetGroupService(repos.AssetGroup, log)
	s.AssetGroup.SetDataScope(s.DataScope)
	s.AssetType = asset.NewAssetTypeService(repos.AssetType, repos.AssetTypeCat, log)
	s.Scope = scope.NewService(repos.ScopeTarget, repos.ScopeExcl, repos.Asset, log)
	// The platform's scope guardrails (RFC-054 §8): public suffixes, the deny
	// list and CIDR caps on every new entry; the deny list and the proof mode
	// at dispatch (the ownership gate below).
	scopeGuardrails, badDeny := scopedom.NewGuardrails(cfg.Scope.MaxPublicCIDRv4, cfg.Scope.MaxPublicCIDRv6, cfg.Scope.DenyExtra)
	if len(badDeny) > 0 {
		return nil, fmt.Errorf("SCOPE_DENY_EXTRA has entries that are neither a domain nor an address range: %v", badDeny)
	}
	s.Scope.SetGuardrails(scopeGuardrails)
	s.ScopeGuardrails = scopeGuardrails
	s.Scope.SetCoverage(postgres.NewScopeCoverageRepository(&postgres.DB{DB: deps.DB}), s.DataScope)
	s.AttackSurface = attack.NewSurfaceService(repos.Asset, repos.AssetRelationship, log)
	// Wire the KEV/critical finding counter for exposure-chain analysis.
	s.AttackSurface.SetFindingRiskCounter(repos.Finding)
	s.AttackSurface.SetDataScope(s.DataScope)
	s.AttackSurface.SetStateHistory(repos.AssetStateHistory) // recent changes: real removals + exposure changes
	if repos.Attribution != nil {
		// recent changes say "Added · needs review" for names not in the inventory (RFC-054 §4.4)
		s.AttackSurface.SetAttributionRecords(repos.Attribution)
	}
	// Continuous threat modeling: composes exposure chains + attacker profiles +
	// ATT&CK catalog + live findings into a per-scope threat model.
	s.ThreatModel = threatmodel.NewService(
		repos.ThreatModel, s.AttackSurface, repos.Asset, repos.AssetRelationship,
		repos.AttackerProfileReader, repos.Finding, log)
	s.ThreatModel.SetDataScope(s.DataScope)
	s.AssetRelationship = asset.NewAssetRelationshipService(repos.AssetRelationship, repos.Asset, log)
	s.AssetRelationship.SetDataScope(s.DataScope)
	s.RelationshipSuggestion = asset.NewRelationshipSuggestionService(repos.RelationshipSuggestion, repos.Asset, repos.AssetRelationship, log)
	s.RelationshipSuggestion.SetDataScope(s.DataScope)
	s.AssetImport = asset.NewAssetImportService(repos.Asset, log)

	// Initialize finding source service (read-only system configuration)
	s.FindingSource = finding.NewFindingSourceService(repos.FindingSource, repos.FindingSourceCat, log)

	// Initialize finding source cache service (global cache, 24h TTL)
	s.FindingSourceCache, err = finding.NewFindingSourceCacheService(deps.RedisClient, repos.FindingSource, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding source cache service: %w", err)
	}

	// Initialize component & branch services
	s.Component = asset.NewComponentService(repos.Component, repos.Asset, log)
	s.Component.SetDataScope(s.DataScope)
	s.SBOMImport = asset.NewSBOMImportService(repos.Component, repos.Asset, log)
	s.SBOMImport.SetDataScope(s.DataScope)
	s.ReportSchedule = module.NewReportScheduleService(repos.ReportSchedule, log)
	s.ReportSchedule.SetRecipientPolicy(repos.Tenant)
	s.UserDashboard = dashboardapp.NewService(repos.UserDashboard, log)
	// Saved list views (D15): one page config per page that has views.
	s.SavedView = savedviewapp.NewService(repos.SavedView, map[string]savedviewapp.PageConfig{
		savedview.PageFindings: {
			Registry:   vulnerability.FindingFields,
			Permission: permission.FindingsRead.String(),
			GroupBy:    vulnerability.FindingGroupDimensions(),
			Extra:      []string{"branch_status"},
		},
	}, log)
	s.SavedView.SetAuditService(s.Audit)
	s.Branch = asset.NewBranchService(repos.Branch, log)

	// Initialize vulnerability & exposure services
	s.Vulnerability = finding.NewVulnerabilityService(repos.Vulnerability, repos.Finding, log)
	s.Vulnerability.SetCommentRepository(repos.FindingComment)
	s.Vulnerability.SetCommentReactionRepository(repos.CommentReaction)
	s.Vulnerability.SetAuditService(s.Audit)                     // audits reaction moderation and duplicate marking
	s.Vulnerability.SetDataFlowRepository(repos.DataFlow)        // Wire data flow loading
	s.Vulnerability.SetApprovalRepository(repos.FindingApproval) // Wire approval workflow
	s.Vulnerability.SetAccessControlRepository(repos.AccessControl)
	s.Vulnerability.SetAssigneeChecker(repos.AccessControl) // an assignee must be an active member of the tenant (21b C2)
	s.Vulnerability.SetDataScope(s.DataScope)
	s.Vulnerability.SetAssetRefChecker(s.DataScope) // POST /findings asset_id: tenant + caller scope
	s.Vulnerability.SetBranchLookup(repos.Branch)   // a finding branch must belong to its asset
	s.FindingActivity = activity.NewFindingActivityService(repos.FindingActivity, repos.Finding, log)
	s.FindingActivity.SetUserRepo(repos.User) // Wire user lookup for activity broadcasts
	// Note: WebSocket broadcaster is wired later after WebSocketHub is initialized

	// Wire activity service dependencies
	s.Vulnerability.SetActivityService(s.FindingActivity) // Wire activity tracking
	s.Vulnerability.SetUserRepository(repos.User)         // Wire user lookup for activity records

	// Note: AITriage is wired to VulnerabilityService later after AITriage initialization

	// Initialize finding lifecycle service (closed-loop: fix_applied → verify → resolved)
	s.FindingActions = finding.NewFindingActionsService(
		repos.Finding, repos.AccessControl, repos.Group, repos.Asset,
		s.FindingActivity, deps.DB, log,
	)
	s.FindingActions.SetDataScope(s.DataScope)
	// Finding source analytics: Tool Insights + the DefectDojo-dependency ratio
	// (RFC-013's measure-to-phase-out guardrail). repos.Finding provides the
	// SourceBreakdown query.

	s.Exposure = exposure.NewExposureService(repos.Exposure, repos.ExposureStateHistory, log)
	s.Exposure.SetDataScope(s.DataScope)
	s.ThreatIntel = threat.NewIntelService(repos.ThreatIntel, log)
	s.CTEMID = ctemidapp.NewService(repos.CTEMID, cfg.Worker.CTEMIDFeedURL, log)
	// EASM producers write exposures through one writer that announces new
	// and reopened rows through the notification outbox in the same
	// transaction (research/22 P0-7, decision E4).
	easmDB := &postgres.DB{DB: deps.DB}
	easmAlerts := postgres.NewEASMAlerter(easmDB)
	easmExposures := postgres.NewEASMExposureWriter(easmDB, easmAlerts)
	repos.EASMDNS.WithAlerts(easmAlerts)
	s.CertMonitor = certmonitorapp.NewService(repos.Asset, easmExposures, cfg.Worker.CertMonitorFeedBaseURL, log)
	s.CertMonitor.SetDomainSources(repos.VerifiedDomain, repos.ScopeTarget)
	// Stored CT exposures follow their host to its own asset (research/22 P0-9).
	s.CertMonitor.SetRelinker(repos.Exposure)
	// Excluded names are neither queried nor discovered (RFC-042 F16).
	s.CertMonitor.SetExclusions(s.Scope)
	s.CertMonitor.SetStateStore(repos.CTMonitorState)
	s.CertMonitor.SetCertSpotterFallback(cfg.Worker.CertMonitorCertSpotterURL)
	// Re-check a little under the sweep interval: the next scheduled run
	// re-queries, an API restart in between does not.
	s.CertMonitor.SetLimits(cfg.Worker.CertMonitorMaxDomainsPerRun, easmRecheck(cfg.Worker.CertMonitorInterval))
	// A tenant may turn CT off (E8 opt-out) or set its own interval (P0-11).
	s.CertMonitor.SetTenantSettings(s.Tenant)
	// DNS-only EASM checks (RFC-036 P1): dangling CNAME/NS, email posture.
	if cfg.Worker.EASMDNSChecksEnabled {
		dnsClient, err := dnsprobe.New(dnsprobe.Config{Server: cfg.Worker.EASMDNSResolver, QPS: cfg.Worker.EASMDNSQPS})
		if err != nil {
			log.Warn("EASM DNS checks disabled: no resolver", "error", err)
		} else {
			s.EASMDNS = easmdnsapp.NewService(dnsClient, repos.EASMDNS, easmExposures, log)
			s.EASMDNS.SetLimits(cfg.Worker.EASMDNSMaxNamesPerRun, easmRecheck(cfg.Worker.EASMDNSInterval))
			s.EASMDNS.SetTenantSettings(s.Tenant)
		}
	}
	// Run-now and seed-triggered sweeps (research/22 P0-11): CT then DNS
	// checks for one tenant, each honoring the tenant's switches.
	var sweepCT easmapp.SweepCT
	if cfg.Worker.CertMonitorEnabled {
		sweepCT = s.CertMonitor
	}
	var sweepDNS easmapp.SweepDNS
	if s.EASMDNS != nil {
		sweepDNS = s.EASMDNS
	}
	s.EASMSweep = easmapp.NewSweepService(sweepCT, sweepDNS, postgres.NewEASMSweepRepository(&postgres.DB{DB: deps.DB}), log)
	s.CredentialImport = integration.NewCredentialImportService(repos.Exposure, repos.ExposureStateHistory, log)
	s.CredentialImport.SetDataScope(s.DataScope)
	// Leaked-credential secrets are sealed with the platform credential key
	// on every write path, and the fingerprint HMAC is keyed from it.
	s.CredentialSecrets = credential.NewSecretProtector(s.Encryptor, []byte(cfg.Encryption.Key))
	s.CredentialImport.SetSecretProtector(s.CredentialSecrets)
	s.Exposure.SetSecretProtector(s.CredentialSecrets)

	// Initialize dashboard service
	s.Dashboard = module.NewDashboardService(repos.Dashboard, log)
	s.Dashboard.SetDataScope(s.DataScope)
	// D6: a restricted viewer holding dashboard:aggregate sees organization
	// totals (k-floor on breakdowns); others see their own scope.
	s.Dashboard.SetAggregateCheck(func(ctx context.Context) bool {
		return middleware.HasPermission(ctx, permission.DashboardAggregate.String())
	})

	// Initialize SLA service
	s.SLA = sla.NewService(repos.SLA, log)

	// Initialize Priority Classification service (RFC-004)
	epssAdapter := postgres.NewEPSSAdapter(repos.ThreatIntel.EPSS().(*postgres.EPSSRepository))
	kevAdapter := postgres.NewKEVAdapter(repos.ThreatIntel.KEV().(*postgres.KEVRepository))
	s.PriorityClassification = finding.NewPriorityClassificationService(
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
	s.PriorityClassification.SetOwnershipFloorPolicy(finding.NewTenantOwnershipFloorPolicy(repos.Tenant))
	// RFC-036 §6.8: findings on assets whose attribution is not confirmed
	// (needs_review, candidate, rejected) are capped at P2.
	if repos.Attribution != nil {
		s.PriorityClassification.SetAttributionLookup(repos.Attribution)
	}

	// anti-flap priority flood guard. Caps per-tenant top-class
	// fan-out at 50/hour — protects Jira/outbox from scanner-induced
	// bursts while keeping the classification itself intact on the
	// dashboard.
	s.PriorityClassification.SetPriorityFloodGuard(finding.NewPriorityFloodGuard(finding.PriorityFloodConfig{}))

	// Close-the-loop: feed attack-path reachability (from the exposure-chain
	// graph) into prioritization, so an internal asset on a validated
	// internet→KEV/crown-jewel path is treated as reachable. Cached 5m/tenant.
	if s.AttackSurface != nil {
		s.PriorityClassification.SetReachabilityOracle(newReachabilityOracle(s.AttackSurface, 5*time.Minute))
	}

	// CTEM Discovery: enrich EXPOSURE events on the read path with the SAME
	// machinery findings use — effective (business-aligned) criticality, asset
	// reachability / internet-exposure, and EPSS/KEV for any exposure carrying a
	// CVE id. Additive and best-effort: nil-safe deps degrade gracefully, and no
	// exposure row is mutated or migrated.
	if s.Exposure != nil {
		exposureEnricher := exposure.NewExposureEnricher(repos.Asset, log)
		exposureEnricher.SetBusinessContextLookup(postgres.NewBusinessContextLookupRepo(deps.DB))
		if s.AttackSurface != nil {
			exposureEnricher.SetReachabilityOracle(newReachabilityOracle(s.AttackSurface, 5*time.Minute))
		}
		exposureEnricher.SetThreatIntel(exposureEPSSShim{epssAdapter}, exposureKEVShim{kevAdapter})
		s.Exposure.SetEnricher(exposureEnricher)
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

	// IOC catalog. Runtime telemetry reached the correlator only through
	// the protocol v1 /telemetry-events route, which is retired.
	s.IOCRepo = repos.IOC

	// bulk-action safety rail. Defaults: 500 rows/request,
	// 10k rows/tenant/hour. Attached to bulk finding handlers below.
	s.BulkGuard = finding.NewBulkGuard(finding.BulkGuardConfig{})

	// Initialize Pentest service
	s.Pentest = compliance.NewPentestService(
		repos.PentestCampaign, repos.PentestFinding,
		repos.PentestRetest, repos.PentestTemplate,
		repos.PentestReport, log,
	)
	// Wire unified finding repository for CTEM integration (pentest findings → findings table)
	s.Pentest.SetUnifiedFindingRepository(repos.Finding)
	s.Pentest.SetAssetRefChecker(s.DataScope)
	s.Pentest.SetCampaignMemberRepository(repos.PentestCampaignMember)
	s.Pentest.SetAuditService(s.Audit)                     // audit logging for team changes + status changes
	s.Pentest.SetFindingActivityService(s.FindingActivity) // finding activity trail
	// Cross-tenant guard: reject adding a campaign member from another tenant.
	// The SetTenantMemberChecker seam was never wired, so the check was dead.
	s.Pentest.SetTenantMemberChecker(pentestTenantMemberAdapter{tenants: repos.Tenant})
	// Note: Pentest notification wiring happens later after NotificationService is initialized

	// Initialize Attachment service (file upload/download).
	// The server-wide storage is operator configuration (STORAGE_PROVIDER):
	//   local (default)  files under STORAGE_LOCAL_PATH (./data/attachments);
	//                    in Docker/Kubernetes mount a volume there.
	//   s3 | minio       an S3-compatible bucket (STORAGE_BUCKET, _REGION,
	//                    _ENDPOINT, _ACCESS_KEY, _SECRET_KEY); needed when more
	//                    than one API replica serves attachments without a
	//                    shared (ReadWriteMany) volume.
	// Attachments record the provider "local" for this server-wide storage, so
	// switching STORAGE_PROVIDER later does not move existing files.
	var fileStorage attachment.FileStorage
	switch cfg.Storage.Provider {
	case "local", "":
		storagePath := cfg.Storage.LocalPath
		if storagePath == "" {
			storagePath = "./data/attachments"
		}
		fileStorage = storage.NewLocalStorage(storagePath)
		log.Info("attachment storage: local filesystem", "path", storagePath)
	case attachment.ProviderS3, attachment.ProviderMinIO:
		s3Store, err := storage.NewOperatorS3Storage(cfg.Storage.Bucket, cfg.Storage.Region,
			cfg.Storage.Endpoint, cfg.Storage.AccessKey, cfg.Storage.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("attachment storage: %w", err)
		}
		fileStorage = s3Store
		log.Info("attachment storage: S3-compatible bucket", "provider", cfg.Storage.Provider,
			"bucket", cfg.Storage.Bucket, "endpoint", cfg.Storage.Endpoint)
	default:
		// Used to fall back to local storage with only a warning, so a typo
		// (or "gcs") silently kept files on an ephemeral container disk.
		return nil, fmt.Errorf("unsupported STORAGE_PROVIDER %q (local, s3 or minio)", cfg.Storage.Provider)
	}
	s.Attachment = integration.NewAttachmentService(repos.Attachment, fileStorage, log)
	// Wire per-tenant storage resolution (tenants can configure S3/MinIO in settings)
	storageResolver := auth.NewSettingsStorageResolver(deps.DB, s.Encryptor, log)
	// "local" is always the operator storage above, never a tenant-chosen
	// path; a tenant's own S3/MinIO bucket goes through the SSRF guard.
	s.Attachment.SetTenantStorageResolver(storageResolver, storage.NewTenantStorageFactory(fileStorage))
	// Wire the attachment store as the backing store for manual finding evidence
	// (POST/GET /findings/{id}/evidence). Tenant-scoped; does not touch the
	// pentest campaign gate.
	s.Vulnerability.SetEvidenceStore(s.Attachment)
	// Organization deletion erases the tenant's stored files (every backend)
	// before its rows, and refuses when it cannot.
	s.Tenant.SetBlobEraser(s.Attachment)

	// Initialize Compliance service
	s.Simulation = compliance.NewSimulationService(repos.Simulation, repos.ControlTest, log)
	// Persist simulation runs (previously the run repo was never wired, so every
	// run was computed and discarded — run history was always empty).
	s.Simulation.SetRunRepo(repos.SimulationRun)
	// Simulation targets follow the scan act-scope rule (RFC-050 W3, 21b H4).
	s.Simulation.SetActScope(actscope.New(s.DataScope, repos.Asset, s.Scope, repos.VerifiedNames), s.DataScope)
	// Validation (CTEM Stage-4): sensors POST proof-of-fix / technique evidence,
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
		findingMutatorAdapter{repo: repos.Finding}, // verdict recorder (validation_outcome / downgraded_at)
		log,
	)
	// Producer side: dispatch a safe-check validation job for a finding. The
	// sensor runs the probe and reports back; the command-completion hook maps
	// the result into evidence via ValidationEvidence above.
	// One dispatcher, the only producer of validate commands, for every
	// re-check, retest and simulation probe. Each job passes the active-probe
	// gate (scope exclusions, private-range policy, attribution, scan zones)
	// of the scan service, set below once it exists; until then it refuses.
	probeGate := &lateTargetGate{}
	validationDispatcher := validation.NewCommandDispatcher(repos.Command, probeGate, log)
	s.ValidationRun = validation.NewRunService(
		repos.Finding,
		repos.Asset,
		validationDispatcher,
		validation.DefaultSelector{},
		[]validation.ExecutorKind{validation.KindSafeCheck},
		log,
	)
	// Capability-gate the dispatch on a live per-tenant check for an online
	// validation-capable sensor, mirroring scan dispatch. Without this the API
	// would enqueue validate commands (on fix_applied auto-retest and live
	// simulation runs) even when no sensor can execute them — the command would
	// sit unconsumed and the simulation run would strand in "running". With it,
	// dispatch is observably skipped until a validation sensor is deployed, then
	// self-activates. See validation.ErrNoValidationSensor.
	s.ValidationRun.SetSensorAvailability(validationSensorAvailability{sensors: repos.Sensor})
	// RFC-011.2 Phase 2b: route the deeper `nuclei` re-verify rung when — and only
	// when — a `validate:nuclei`-capable sensor is online. Inert-safe: with no such
	// sensor this gate returns false and routing is byte-for-byte Phase 2a
	// (safe-check only). Reuses the same sensor-registry capability query.
	s.ValidationRun.SetNucleiAvailability(validationSensorAvailability{sensors: repos.Sensor})
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

	// Continuous retest (RFC-039): re-run a finding's own nuclei template plus a
	// reachability probe through the same validate-command dispatcher, so the
	// same fail-closed active-probe gate applies (exclusions, zones,
	// attribution). Evidence is recorded advisory-only; the retest service
	// settles the finding (fixed / still present / unknown).
	s.Retest = retestapp.NewService(
		repos.FindingRetest,
		repos.Finding,
		repos.Asset,
		repos.Command,
		validationDispatcher,
		validationSensorAvailability{sensors: repos.Sensor},
		log,
	)
	s.Retest.SetAuditLogger(s.Audit)
	// RFC-057 R2: a confirmed fix resolves only when the tenant opted in.
	s.Retest.SetPolicy(retestapp.TenantPolicy{Tenants: repos.Tenant})

	// Finding evidence (docs/architecture/finding-evidence.md): secret values
	// are sealed with the platform key (re-keyed by cmd/rekey).
	s.Evidence = evidenceapp.NewService(repos.FindingEvidence, s.Encryptor, s.Tenant, repos.FindingActivity, s.Audit, log)
	s.Retest.SetEvidenceStore(s.Evidence)

	s.ThreatActor = threat.NewActorService(repos.ThreatActor, log)
	s.RemediationCampaign = exposure.NewRemediationCampaignService(repos.RemediationCampaign, log)
	// Wire the finding counter so campaign progress (finding_count/resolved_count/
	// progress) is computed from live finding data instead of staying at zero.
	s.RemediationCampaign.SetFindingCounter(repos.Finding)
	s.RemediationCampaign.SetFindingLister(repos.Finding)
	// A restricted reader sees progress over their own findings (L-18).
	s.RemediationCampaign.SetDataScope(s.DataScope)
	// Creates, edits, status changes and deletes go to audit_logs.
	s.RemediationCampaign.SetAuditLogger(s.Audit)
	s.RemediationCampaign.SetAssigneeChecker(repos.AccessControl) // a campaign owner must be an active member (21b C2)
	// Phase 3: let a campaign actively resolve its open findings (reuses the
	// finding bulk path + abuse guard).
	s.RemediationCampaign.SetFindingResolver(campaignFindingResolver{vuln: s.Vulnerability, guard: s.BulkGuard})
	s.BusinessUnit = asset.NewBusinessUnitService(repos.BusinessUnit, repos.Asset, log)
	s.BusinessUnit.SetDataScope(s.DataScope)

	s.Compliance = compliance.NewComplianceService(
		repos.ComplianceFramework, repos.ComplianceControl,
		repos.ComplianceAssessment, repos.ComplianceMapping, log,
	)
	s.Compliance.SetFindingRepository(repos.Finding)

	// Initialize AI Triage service (if configured)
	if cfg.AITriage.IsConfigured() {
		llmFactory := llm.NewFactoryWithEncryption(cfg.AITriage, s.Encryptor)
		s.AITriage = aitriage.NewAITriageService(
			repos.AITriage,
			repos.Finding,
			repos.Tenant,
			s.FindingActivity,
			llmFactory,
			cfg.AITriage,
			log,
		)
		s.AITriage.SetAuditService(s.Audit)
		s.AITriage.SetDataScope(s.DataScope)
		s.Vulnerability.SetAITriageService(s.AITriage) // Wire auto-triage on finding creation

		// On triage completion, enqueue an asset-scoped reclassify so a
		// high-confidence false-positive verdict de-escalates the finding's
		// priority. Reuses the same MemoryQueue → Reclassifier → ClassifyFinding
		// scan workflow the control/rule producers use (wired above).
		s.AITriage.SetReclassifyEnqueuer(aiTriageReclassifyEnqueuer{pub: s.ControlChangePub})

		// RFC-008: per-tenant LLM token budget. Always constructed so
		// Status() works for dashboards even before enforcement.
		// Check()/Record() short-circuit when BudgetEnabled=false —
		// the Phase 1 rollout ships the flag off so there is zero
		// behavior change on this deploy.
		budgetSvc := aitriage.NewBudgetService(
			repos.AITriageBudget, aitriage.BudgetServiceConfig{
				Enabled:               cfg.AITriage.BudgetEnabled,
				Strict:                cfg.AITriage.BudgetStrict,
				DefaultTokensPerMonth: cfg.AITriage.BudgetDefaultTokensPerMonth,
			}, log,
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
	// Every key hash the repository writes is stamped with the id of the
	// pepper that made it, so the keys still on a rotated-out pepper can be
	// counted (rekey -status).
	repos.APIKey.SetKeyPepperID(crypto.PepperID(cfg.Encryption.Key))
	s.APIKey = apikey.NewService(repos.APIKey, cfg.Encryption.Key, log)
	// Gate user-scoped keys on active membership so member offboarding revokes
	// them immediately (the key's own status can't reflect member lifecycle).
	// The account must be active too. Fails closed on a lookup error.
	s.APIKey.SetMembershipChecker(apikey.NewMembershipChecker(repos.Tenant, repos.User))
	// Audit oct_ key create / revoke / delete.
	s.APIKey.SetAuditService(s.Audit)
	// During an encryption-key rotation, keys hashed under the old key
	// (APP_ENCRYPTION_KEY_PREVIOUS) keep authenticating.
	s.APIKey.SetLegacyPeppers(cfg.Encryption.PreviousKeys...)

	// SCIM 2.0 provisioning (RFC-009): per-tenant bearer token + user lifecycle.
	repos.ScimToken.SetKeyPepperID(crypto.PepperID(cfg.Encryption.Key))
	s.SCIMToken = scim.NewTokenService(repos.ScimToken, cfg.Encryption.Key, log)
	s.SCIMToken.SetLegacyPeppers(cfg.Encryption.PreviousKeys...)
	s.SCIMProvisioning = scim.NewProvisioningService(
		repos.User, repos.Tenant, scimMembershipAdapter{svc: s.Tenant}, log,
	)
	s.SCIMGroups = scim.NewGroupService(
		repos.ScimGroup, repos.Tenant, scimMembershipAdapter{svc: s.Tenant}, log,
	)
	s.SCIMGroups.SetAuditService(s.Audit)
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
	// Inbound status changes are recorded with the integration as the actor.
	s.JiraSync.SetActivityRecorder(s.FindingActivity)
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
	s.GitHubTicket.SetActivityRecorder(s.FindingActivity)

	// Initialize integration & notification services
	s.Integration = integration.NewIntegrationService(repos.Integration, repos.IntegrationSCMExt, s.Encryptor, log)
	s.Integration.SetTransactionDB(deps.DB)
	s.Integration.SetNotificationExtensionRepository(repos.IntegrationNotificationExt)
	s.Integration.SetOutboxEventRepository(repos.OutboxEvent)
	s.Integration.SetRepoImportRepos(repos.Asset, repos.RepoExt, repos.Branch)
	// Test/sync of a ticketing integration checks its credentials against Jira.
	// Without it a Jira integration never leaves "pending", and jiraResolver
	// only uses connected integrations — ticket creation would stay inert.
	s.Integration.SetTicketingConnectionTester(jiraResolver)

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
		finding.NewOutboxPriorityChangePublisher(s.Outbox, log),
	)

	// Note: UserNotificationService is wired later after NotificationService is initialized

	// Note: NotificationService is wired later after WebSocketHub is initialized

	// Initialize sensor & command services
	s.Sensor = sensorapp.NewSensorService(repos.Sensor, s.Audit, log)
	// Pepper the sensor API-key hash: HMAC-SHA256(pepper, key) stops a
	// DB-only leak from being brute-forced offline. The pepper is
	// SENSOR_KEY_PEPPER, else derived from APP_ENCRYPTION_KEY with HKDF (no
	// key serves two purposes; RFC-032 Phase 0). Keys stored under the
	// previous pepper (APP_ENCRYPTION_KEY itself) and plain-SHA256 rows from
	// before any pepper keep authenticating; new and renewed keys are stored
	// under the current pepper.
	// During an encryption-key rotation the peppers derived from the old key
	// (and the old key itself, the pepper before RFC-032 Phase 0) keep
	// verifying the keys sensors already hold.
	sensorPrevious := append(append([]string(nil), cfg.SensorConfig.KeyPepperPrevious...),
		sensorapp.RotatedEncryptionKeyPeppers(cfg.Encryption.PreviousKeys)...)
	sensorPepper, sensorLegacyPeppers := sensorapp.SensorKeyPeppers(cfg.SensorConfig.KeyPepper, cfg.Encryption.Key, sensorPrevious...)
	s.Sensor.SetPepper(sensorPepper)
	repos.Sensor.SetKeyPepperID(crypto.PepperID(sensorPepper))
	repos.SensorAPIKey.SetKeyPepperID(crypto.PepperID(sensorPepper))
	if len(cfg.Encryption.PreviousKeys) > 0 {
		logTokensOnPreviousPepper(&postgres.DB{DB: deps.DB}, crypto.PepperID(cfg.Encryption.Key), crypto.PepperID(sensorPepper), log)
	}
	s.Sensor.SetLegacyPeppers(sensorLegacyPeppers...)
	// Interactive pairing (RFC-052): the platform pairing key derives from
	// APP_ENCRYPTION_KEY, pairing codes are hashed with the sensor-key pepper.
	if sp, err := sensorpairing.NewService(repos.SensorPairing, repos.Sensor, cfg.Encryption.Key, sensorPepper, log); err != nil {
		log.Warn("sensor pairing disabled", "error", err)
	} else {
		s.SensorPairing = sp
		s.SensorPairing.SetAudit(s.Audit)
		s.SensorPairing.SetEvents(s.Sensor)
	}
	// Per-sensor grants (RFC-052 §5): enforced on poll, claim, results
	// without a job and heartbeat actions; a pairing approval sets the
	// chosen profile in its transaction.
	s.SensorGrant = sensorgrant.NewService(repos.SensorGrant, repos.Sensor, log)
	s.SensorGrant.SetAudit(s.Audit)
	s.SensorGrant.SetZoneChecker(repos.SensorGrant)
	if s.SensorPairing != nil {
		s.SensorPairing.SetApprovalHook(s.SensorGrant)
	}
	// Optional short-lived sensor credentials (RFC-014 Phase 1b). Zero =
	// disabled (renewed keys never expire), preserving today's behavior.
	s.Sensor.SetKeyTTL(cfg.SensorConfig.KeyTTL)
	// A renewal retires the key it was made with (and any other the sensor
	// held) after this grace.
	s.Sensor.SetRenewGrace(cfg.SensorConfig.KeyRenewGrace)
	s.Sensor.SetSlimHeartbeat(cfg.SensorConfig.SlimHeartbeat)
	// Multi-key store for rotation overlap (RFC-014 Phase 3). Additive: auth
	// still accepts the inline key; renewal under a TTL issues overlapping keys.
	s.Sensor.SetAPIKeyRepository(repos.SensorAPIKey)
	// Key-bound sensors (RFC-052): public keys and the shared nonce store
	// of signed requests.
	s.Sensor.SetSigningKeyRepository(repos.SensorSigningKey)
	s.Sensor.SetIdentityPolicyRepository(postgres.NewSensorIdentityPolicyRepository(&postgres.DB{DB: deps.DB}))
	if deps.RedisClient != nil {
		s.Sensor.SetNonceStore(redis.NewSensorNonceStore(deps.RedisClient))
	}
	// Operator-tunable load-balancing weights (SENSOR_LB_*). Applied to the
	// load_score recomputed on every heartbeat.
	s.Sensor.SetLoadBalancingWeights(cfg.Worker.LoadBalancing.Weights())
	// Activity timeline: heartbeat diffs and online/offline transitions are
	// recorded in sensor_events; GET /sensors/{id}/activity reads them merged
	// with the sensor's jobs and audit rows.
	s.Sensor.SetEventRepository(repos.SensorEvent, sensordom.DefaultEventLimits())
	s.Sensor.SetActivityReader(repos.SensorEvent)
	// Heartbeat gaps: the fleet histogram and each tenant sensor's 48 h
	// history (the Control channel sparkline; RFC-035).
	s.Sensor.SetHeartbeatHistory(repos.SensorHeartbeatHistory)
	s.Sensor.SetHeartbeatGapObserver(telemetry.SensorHeartbeatMetrics{})
	// Command leases (RFC-035 D6): a claim holds for SENSOR_COMMAND_LEASE
	// and every heartbeat renews what the sensor holds; job recovery takes
	// back what runs out, fenced against a late completion.
	repos.Command.SetLeaseDuration(cfg.SensorConfig.CommandLease)
	s.Sensor.SetLeaseRenewer(repos.Command)
	s.Sensor.SetCancelFinder(repos.Command)
	// Revoking or disabling a sensor takes back its leased commands at once
	// (RFC-040 §5.2) instead of at lease expiry.
	s.Sensor.SetHolderReleaser(repos.Command)
	// Custom templates leave for sensors signed with the tenant's key
	// (sensors refuse unsigned ones; RFC-038 "Custom template trust").
	s.TemplateKeys = initTemplateKeyring(cfg, log)
	// Content packs are stored in each tenant's namespace of the operator
	// file storage and signed with the tenant's content key.
	s.ContentPacks = contentpackapp.NewService(repos.ContentPack, fileStorage, initContentSigner(cfg, log), s.Audit, log)
	cmdOpts := []command.Option{command.WithSensorLookup(repos.Sensor),
		// RFC-040 §5.7: jobs a sensor refused under its local policy reach its
		// timeline and the audit log (A11); a tenant can keep private targets
		// from sensors without a policy.
		command.WithRefusalObserver(s.Sensor), command.WithPrivateTargetPolicy(s.Tenant),
		// research/25 D3: interactsh and custom templates leave only when the
		// organization enabled them (default off).
		command.WithOptInPolicy(s.Tenant),
		// RFC-052 §5: each sensor's grant, before every other gate.
		command.WithGrants(repos.SensorGrant, s.Sensor),
		// RFC-055 §6.3: the tier is assigned from the tool contract.
		command.WithToolContracts(repos.Sensor),
		// A scan job's targets pass the dispatch gate again when a sensor
		// claims it: scope can change while it waits in the queue. Until
		// the scan service exists the gate refuses (fail closed).
		command.WithScopeRecheck(probeGate)}
	if s.TemplateKeys != nil {
		cmdOpts = append(cmdOpts, command.WithTemplateSigner(template.NewPayloadSigner(s.TemplateKeys, log)))
	}
	s.Command = command.NewService(repos.Command, log, cmdOpts...)
	s.SensorContent = sensorapp.NewContentService(repos.Sensor, s.Sensor, repos.SensorContentPolicy, repos.Command, s.Audit, log)
	// Tenable.sc sensor connector (RFC-047): connector_sync commands pinned to
	// the integration's sensor, followed to keep the sync cursor.
	s.TenableSC = tenablesc.NewService(repos.Integration, repos.Sensor, repos.Command, repos.Finding, s.Audit, log)
	s.TenableSC.SetSyncClaimer(repos.Integration)
	// Tenable integrations can be created only once the connector ships
	// (integrationdom.TenableConnectorEnabled, owner decision D-14): without
	// the validator the integration service refuses them.
	if integrationdom.TenableConnectorEnabled {
		s.Integration.SetTenableConnector(s.TenableSC)
	}
	s.SensorPlatformHealth = sensorapp.NewPlatformHealth(sensorapp.PlatformHealthConfig{
		SlowHeartbeat: cfg.SensorConfig.HealthSlowHeartbeat,
		StartupGrace:  cfg.SensorConfig.HealthStartupGrace,
	})

	// Initialize ingest service (unified ingestion engine)
	s.Ingest = ingest.NewService(repos.Asset, repos.Finding, repos.Vulnerability, repos.Component, repos.Sensor, repos.Branch, repos.Tenant, repos.Audit, log)
	// DefectDojo co-existence sync (RFC-013): pull a tenant's DefectDojo findings
	// and ingest them as CTIS (one-way; OpenCTEM is the system of record).
	s.DefectDojoSync = defectdojo.NewSyncService(repos.Integration, s.Ingest, s.Encryptor, log)
	// Assets reported for a tenant's own scan commands get tenant_scanned
	// attribution evidence (RFC-036 O8).
	if repos.Attribution != nil {
		// Names a permanent scope entry covers are confirmed without review
		// (RFC-054 §4.3); the join also backs the start-up backfill, and the
		// scope service runs it (debounced per tenant) after every committed
		// change that can confirm a waiting name.
		s.ScopeJoin = easmapp.NewScopeJoin(s.Scope, s.Scope, repos.Attribution, repos.Asset, log)
		s.ScopeJoin.SetAudit(s.Audit)
		s.ScopeJoin.SetSettings(s.Tenant)
		s.Scope.SetScopeJoin(easmapp.NewJoinScheduler(s.ScopeJoin, 0, log),
			postgres.NewScopeCoverageRepository(&postgres.DB{DB: deps.DB}))
		stamper := easmapp.NewScanStamper(repos.Attribution, repos.VerifiedNames)
		stamper.SetScopeJoin(s.ScopeJoin)
		s.Ingest.SetScanAttributionStamper(stamper)
	}
	// A nuclei takeover-template match from a tenant scan confirms an open
	// dangling_cname as subdomain_takeover (RFC-036 P1).
	if repos.EASMDNS != nil && repos.Exposure != nil {
		s.Ingest.SetTakeoverConfirmer(easmdnsapp.NewTakeoverConfirmer(repos.EASMDNS, postgres.NewEASMExposureWriter(&postgres.DB{DB: deps.DB}, postgres.NewEASMAlerter(&postgres.DB{DB: deps.DB})), log))
	}
	// CT names become inventory assets through this same ingest path, with
	// attribution evidence (RFC-036 P0). Wired here because the CT monitor is
	// built before ingest.
	if s.CertMonitor != nil {
		s.CertMonitor.SetPromotion(s.Ingest, repos.Asset, repos.Attribution)
		s.CertMonitor.SetTombstones(repos.Attribution)
		if s.ScopeJoin != nil {
			s.CertMonitor.SetScopeJoin(s.ScopeJoin)
		}
	}
	// Open ports a port scan no longer sees are closed (research/22 P0-6).
	s.Ingest.SetEvidenceStore(s.Evidence)
	s.Ingest.SetPortReconciler(postgres.NewEASMPortRepository(&postgres.DB{DB: deps.DB}))
	// A tool ported to the tool contract declares what it produces in its
	// sensor's manifest; that narrows what its reports may carry.
	s.Ingest.SetToolContractSource(repos.Sensor)
	s.Ingest.SetDataFlowRepository(repos.DataFlow)                   // Wire data flow persistence
	s.Ingest.SetComponentRepository(repos.Component)                 // Wire component linking for SCA findings
	s.Ingest.SetWebEndpointRepository(repos.WebEndpoint)             // Web endpoints under their origin asset (RFC-056)
	s.Ingest.SetRepositoryExtensionRepository(repos.RepoExt)         // Wire repository extension for auto web_url
	s.Ingest.SetRelationshipRepository(repos.AssetRelationship)      // Wire subdomain-to-domain relationships
	s.Ingest.SetAssetStateHistoryRepository(repos.AssetStateHistory) // Record appeared/recovered on discovery
	s.Ingest.SetExclusionSource(s.Scope)                             // New assets matching a scope exclusion are not added (RFC-042 F16)
	s.Ingest.SetActivityService(s.FindingActivity)                   // Wire activity logging for auto-resolve/reopen
	// Secret findings: fingerprint keyed by the platform secret (RFC-043).
	s.Ingest.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte(cfg.Encryption.Key)))
	// Coverage-scoped auto-resolve of non-repository findings (default dry_run).
	s.Ingest.SetCoverageAutoResolve(ingest.ParseCoverageAutoResolveMode(cfg.Ingest.CoverageAutoResolve), ingest.BlindingGuard{
		Ratio: cfg.Ingest.V2BlindingRatio, MinFindings: cfg.Ingest.V2BlindingMinFindings,
	})
	// Source-asserted resolve (Tenable.sc mitigated rows, RFC-047; default dry_run).
	s.Ingest.SetSourceResolveMode(ingest.ParseSourceResolveMode(cfg.Ingest.SourceResolve))
	s.Ingest.SetVEXMode(ingest.ParseVEXMode(cfg.Ingest.VEX))
	// Ingest audit events are tenant-scoped, so they must go through the SAME
	// audit service instance as every other tenant-scoped event: LogEvent also
	// extends the per-tenant tamper-evident hash chain, and its chainMu is what
	// serializes concurrent appends. Without this, ingest.completed /
	// ingest.partial_success rows land in audit_logs unchained.
	s.Ingest.SetAuditService(s.Audit)
	// Wire IP correlation for host dedup (RFC-001)
	// System defaults; per-tenant overrides come from tenant settings at ingest time
	s.Ingest.SetCorrelator(ingest.NewAssetCorrelator(repos.Asset, log, ingest.CorrelationConfig{
		StaleAssetDays: ingest.DefaultIPTrustWindowDays,
		MaxIPsPerAsset: ingest.DefaultMaxIPsPerAsset,
	}))
	// Enqueue an admin dedup review when correlation finds multiple existing
	// assets sharing identity (RFC-001) — populates the previously-empty queue.
	s.Ingest.SetDedupEnqueuer(repos.AssetDedup)
	// Match assets on stable identifiers (host ID, cloud ID, BIOS UUID,
	// serial, MAC, SCM repository ID) before name and IP; conflicts go to
	// the same review queue.
	s.Ingest.SetIdentityStore(repos.AssetIdentifier, repos.AssetDedup)
	// Result binding (RFC-040 §5.3): reports name the command they belong
	// to; reports without one are applied with limits, or quarantined per the
	// tenant's policy.
	s.Ingest.SetCommandReader(repos.Command)
	s.Ingest.SetResultQuarantine(repos.SensorResult, sensorresult.DefaultLimits())
	// RFC-052 §5.3: results without a job need push ingest in the sensor's
	// effective grant (off by default, always off while New).
	s.Ingest.SetGrants(repos.SensorGrant, s.Sensor)

	// Initialize scanning services
	s.ScanProfile = scan.NewScanProfileService(repos.ScanProfile, log)
	s.ScannerTemplate = app.NewScannerTemplateService(repos.ScannerTemplate, cfg.Encryption.Key, log)
	s.ScannerTemplate.SetSigningKeys(s.TemplateKeys)
	s.TemplateSource = template.NewSourceService(repos.TemplateSource, log)

	// Initialize credential service for template sources
	// Decode hex key to bytes (64 hex chars -> 32 bytes for AES-256)
	var encryptionKey []byte
	var previousSecretStoreKeys [][]byte
	if cfg.Encryption.IsConfigured() {
		// Hex-decoded, else the raw bytes (secretstore.KeyFromConfig).
		encryptionKey = secretstore.KeyFromConfig(cfg.Encryption.Key)
		for _, prev := range cfg.Encryption.PreviousKeys {
			previousSecretStoreKeys = append(previousSecretStoreKeys, secretstore.KeyFromConfig(prev))
		}
	} else {
		// Use a zero key for development (secret store will still work but is not secure)
		log.Warn("APP_ENCRYPTION_KEY not configured - secret store using zero key (development only)")
		encryptionKey = make([]byte, 32)
	}
	s.SecretStore, err = integration.NewSecretStoreService(repos.SecretStore, encryptionKey, s.Audit, log, previousSecretStoreKeys...)
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
	// Binding a stored credential to a source is restricted to owners/admins
	// and the credential's creator, and audited.
	s.TemplateSource.SetCredentialGuard(s.SecretStore, s.Audit)

	s.Tool = tool.NewService(repos.Tool, repos.TenantToolConfig, log)
	// Tool availability: the catalog joined with the tools the sensors report.
	s.Tool.SetAvailabilitySources(s.Sensor, repos.ScanZone, repos.SensorGrant)
	// RFC-055 §5: trust and the platform-assigned tier per tool.
	s.Tool.SetManifestSource(repos.Sensor)
	s.Tool.SetCategoryRepo(repos.ToolCategory) // Enable category info in responses
	s.ToolCategory = tool.NewCategoryService(repos.ToolCategory, repos.Tool, log)
	s.Capability = capability.NewCapabilityService(repos.Capability, s.Audit, log)

	// Initialize sensor selector for load balancing
	s.SensorSelector = sensorapp.NewSensorSelector(repos.Sensor, repos.Command, deps.SensorStateStore, log)
	// Same SENSOR_LB_* weights drive job placement, so tuning them changes
	// scheduling and not just the reported score.
	s.SensorSelector.SetLoadBalancingWeights(cfg.Worker.LoadBalancing.Weights())

	// Initialize security validator for scan workflow/scan operations
	securityValidator := app.NewSecurityValidator(repos.Tool, log)

	// Create adapters for scan sub-package (clean architecture - each package defines its own interfaces)
	scanAuditAdapter := app.NewScanAuditServiceAdapter(s.Audit)
	scanSensorSelectorAdapter := app.NewScanSensorSelectorAdapter(s.SensorSelector)
	templateScanAdapter := template.NewScanAdapter(s.TemplateSyncer)
	scanSecurityValidatorAdapter := app.NewScanSecurityValidatorAdapter(securityValidator)

	s.ActiveGate = easmapp.NewActiveGate(repos.Attribution, repos.Asset, s.Scope, repos.VerifiedNames).
		WithTakeoverEvidence(repos.EASMDNS).
		WithPlatformPolicy(s.ScopeGuardrails, cfg.Scope.ActiveProof == config.ScopeProofAll)

	// Initialize scan service with adapters for its interfaces
	s.Scan = scan.NewService(
		repos.Scan,
		repos.ScanWorkflow,
		repos.AssetGroup,
		repos.ScanRun,
		repos.ScanWorkflowStep,
		repos.StepRun,
		repos.Command,
		repos.ScannerTemplate,
		repos.TemplateSource,
		repos.Tool,
		templateScanAdapter,
		scanSensorSelectorAdapter,
		scanSecurityValidatorAdapter,
		log,
		scan.WithAuditService(scanAuditAdapter),
		scan.WithProfileRepo(repos.ScanProfile),
		// Enforce scope EXCLUSIONS on every dispatch path; unwired or failing, nothing is dispatched (fail closed).
		scan.WithScopeExclusionFilter(s.Scope),
		// Ownership of every actively scanned target (RFC-036 §6.3): confirmed,
		// or unrecorded inside a scope target / under a seed; never rejected.
		scan.WithAttributionGate(s.ActiveGate),
		// Route targets to scan zones and pin jobs to zone sensors (RFC-023).
		// Hostnames route by the address they resolve to, through
		// SCAN_ZONE_RESOLVER (a public resolver on self-service installs).
		scan.WithScanZones(repos.ScanZone, zoneResolver(cfg.Scope.ZoneResolver)),
		// Freeze windows: a scheduled run is deferred to the window's end,
		// any other trigger refused unless overridden (audited).
		scan.WithFreezeWindows(repos.ScanFreezeWindow),
		// Scan targets limited to the actor: restricted members scan only
		// assets in their data scope; free text must match a scope target
		// (research/15 L-06, decision D9).
		scan.WithActScope(actscope.New(s.DataScope, repos.Asset, s.Scope, repos.VerifiedNames)),
		// Platform sensors and intrusive scans need a verified domain
		// (RFC-054 §8.1, SCOPE_ACTIVE_PROOF).
		scan.WithActiveProof(cfg.Scope.ActiveProof),
		// A tenable_sc scan launches Tenable.sc scans through the connector (RFC-047).
		// Only once the connector ships (D-14): without it a tenable_sc scan is refused.
		scan.WithConnectorScans(connectorScansIfEnabled(s.TenableSC)),
		// An organization's "disabled" switch on a tool stops it at trigger time.
		scan.WithTenantToolConfigs(repos.TenantToolConfig),
		// A batch goes only to a sensor whose reported local policy accepts
		// it; a trigger no sensor would accept is refused (research/25 §3.6).
		scan.WithDispatchPolicy(repos.Sensor, s.Tenant),
		// A tool no online sensor may run refuses the trigger with the
		// reason (docs/architecture/tool-availability.md).
		scan.WithToolAvailability(s.Tool),
		// Workflow readiness: the New Scan picker, the workflow list and
		// the refusal of a workflow no sensor here can run.
		scan.WithReadinessSources(readinessSources(s.Tool, repos.Sensor)),
		// research/25 D3: interactsh and custom templates only when the
		// organization enabled them (default off).
		scan.WithOptInPolicy(s.Tenant),
	)
	// A scheduled run acts as the scan owner: refused without one, paused
	// when the owner is no longer an active member (RFC-050 W2).
	s.Scan.SetOwnerActivity(repos.AccessControl)
	s.ScanZone = scanzoneapp.NewService(repos.ScanZone, s.Audit, log)
	s.ScanFreeze = scanfreezeapp.NewService(repos.ScanFreezeWindow, s.Audit, log)
	// The validate-command dispatcher gates every probe through the scan
	// service from here on.
	probeGate.set(s.Scan)

	// Closed-loop CTEM: auto-queue a proof-of-fix safe-check re-check when
	// findings transition to fix_applied, so a "fixed" claim is verified rather
	// than trusted. Bounded + best-effort; non-network findings are skipped.
	// RFC-039: a nuclei finding gets a proof-of-fix retest (its own template +
	// a reachability probe); any other finding falls back to the validation
	// re-check, whose verdict never resolves on a reachability probe.
	proofOfFix := retestapp.NewProofOfFix(s.Retest, s.ValidationRun)
	s.FindingActions.SetAutoValidator(proofOfFix)

	// B3 wire: when a Jira "Done" webhook arrives and the
	// finding transitions to fix_applied, automatically trigger a
	// verification scan via FindingActions. Per-finding 24h cooldown
	// prevents scanner thrash from chatty Jira automation rules.
	// Without this wire Jira "Done" would only update status and
	// leave the "did the fix actually work?" question unanswered.
	if s.JiraSync != nil && s.FindingActions != nil && repos.Finding != nil {
		rescanHook := jira.NewRescanHook(proofOfFix, repos.Finding, log)
		s.JiraSync.SetPostFixAppliedHook(rescanHook.Hook)
	}

	// RFC-039 Phase 2: a regression (a retest or a scan seeing a finding closed
	// as fixed again) gets a fresh SLA deadline from the reopen (D2), and a fix
	// or regression is announced on the linked ticket (opt-in outbound sync) and
	// as a finding_fixed / finding_reopened notification.
	regressionSLA := sla.NewRegressionRestarter(s.SLA, repos.FindingSLARestart, log)
	var ticketCommenter retestapp.TicketCommenter
	if s.JiraSync != nil {
		ticketCommenter = s.JiraSync
	}
	var notifier retestapp.NotificationEnqueuer
	if s.Outbox != nil {
		notifier = s.Outbox
	}
	changeAnnouncer := retestapp.NewChangeAnnouncer(repos.Finding, ticketCommenter, notifier, log)
	s.Retest.SetRegressionSLA(regressionSLA)
	s.Retest.SetAnnouncer(changeAnnouncer)
	s.Ingest.SetRegressionHandler(retestapp.NewScanRegressions(regressionSLA, changeAnnouncer, log))

	// Create adapters for scanrun package
	pipelineAuditAdapter := app.NewScanWorkflowAuditServiceAdapter(s.Audit)
	scanRunSensorSelectorAdapter := app.NewScanRunSensorSelectorAdapter(s.SensorSelector)
	scanWorkflowSecurityValidatorAdapter := app.NewScanWorkflowSecurityValidatorAdapter(securityValidator)

	// Initialize scan run service with security validator, audit service, transaction support, and tool repo
	// Stage chaining storage (research/27 P0-3): what each step produced and
	// how the next stages were planned from it.
	scanHops := postgres.NewScanHopRepository(&postgres.DB{DB: deps.DB})
	s.ScanRun = scanrun.NewService(
		repos.ScanWorkflow,
		repos.ScanWorkflowStep,
		repos.ScanRun,
		repos.StepRun,
		repos.Sensor,
		repos.Command,
		scanWorkflowSecurityValidatorAdapter,
		log,
		scanrun.WithAuditService(pipelineAuditAdapter),
		scanrun.WithDB(deps.DB),
		scanrun.WithSensorSelector(scanRunSensorSelectorAdapter),
		scanrun.WithToolRepo(repos.Tool),
		// A draft check warns about steps no online sensor can run now.
		scanrun.WithRunnableTools(s.Tool),
		// The builder saves drafts; a publish makes them the steps runs use.
		scanrun.WithDraftStore(repos.ScanWorkflow),
		scanrun.WithQualityGate(repos.ScanProfile, repos.Finding),
		scanrun.WithScanDeactivator(s.Scan),     // Cascade pause scans when scan workflow is deactivated
		scanrun.WithScanRunRecorder(repos.Scan), // Record run outcome back onto the scan (last_run_status/counters)
		// Targets of a directly started run pass a scan trigger's checks:
		// private-range policy, scope exclusions, scan zones (RFC-042 F16).
		scanrun.WithTargetGate(s.Scan),
		// A run's asset_id (copied into every step command) must be a live
		// asset of the tenant in the caller's scope (research doc 21b, C4).
		scanrun.WithAssetRefChecker(s.DataScope),
		// Chained steps take what their predecessors produced, through the
		// per-hop gate (hop_router.go).
		scanrun.WithHopStore(scanHops),
		// A run executes the workflow version it started with (research/62 P0-10).
		scanrun.WithVersionStore(repos.ScanWorkflow),
		// Web steps carry the path exclusions of their hosts (RFC-056).
		scanrun.WithWebScope(s.Scope),
		// Incremental web scanning: new or changed endpoints only (RFC-056).
		scanrun.WithEndpointSelector(repos.WebEndpoint),
	)

	// One step dispatcher (research/27 P0-2): a workflow scan's first steps
	// are queued by the scan run service, like every later step.
	s.Scan.SetStepQueuer(s.ScanRun)
	s.Scan.SetWorkflowVersions(repos.ScanWorkflow)
	// Every retest is a scan run (kind retest): Runs lists it with its tasks and logs.
	if s.Retest != nil {
		s.Retest.SetRunRecorder(s.ScanRun)
	}
	// Every finding validation is a run too (kind validation).
	if s.ValidationRun != nil {
		s.ValidationRun.SetRunRecorder(s.ScanRun)
	}
	// Ingest records what each step's reports wrote and tells the scan run service
	// service when a v2 report of a command finished, so a chained step
	// waiting for it is planned.
	s.Ingest.SetStepOutputRecorder(scanHops)
	s.Ingest.SetCommandIngestedHook(s.ScanRun.OnCommandIngested)

	// Wire up scan workflow deactivator to tool service for cascade deactivation
	// When a tool is deactivated/deleted, all active scan workflows using it will be deactivated
	s.Tool.SetScanWorkflowDeactivator(s.ScanRun)

	// Every automation run acts as one person (a manual run: who started
	// it; an event run: the owner), checked live before each step.
	workflowAuthorizer := workflow.NewPrincipalAuthorizer(
		workflowMemberReader{tenants: repos.Tenant, access: repos.AccessControl},
		workflowPermissionReader{roles: repos.Role},
		s.DataScope,
		workflowPrincipalContext,
	)

	// Initialize workflow executor
	workflowExecutor := workflow.NewWorkflowExecutor(
		repos.Workflow,
		repos.WorkflowRun,
		repos.WorkflowNodeRun,
		log, workflow.WithExecutorDB(deps.DB), workflow.WithExecutorOutboxService(s.Outbox), workflow.WithExecutorIntegrationService(s.Integration), workflow.WithExecutorAuditService(s.Audit),
		workflow.WithExecutorStepAuthorizer(workflowAuthorizer),
	)

	// Register all action handlers for the workflow executor. Use the AI-aware
	// variant so trigger_ai_triage is actually registered (it was coded but the
	// non-AI register never wired it), and pass the Jira/GitHub ticket adapters
	// so create_ticket/update_ticket file real issues instead of returning a
	// false success. Adapters are built only when the underlying service exists
	// so a nil service yields a nil interface (not a non-nil box over nil).
	var wfJira workflow.JiraTicketService
	if s.JiraSync != nil {
		wfJira = workflowJiraTicketAdapter{svc: s.JiraSync}
	}
	var wfGitHub workflow.GitHubTicketService
	if s.GitHubTicket != nil {
		wfGitHub = workflowGitHubTicketAdapter{svc: s.GitHubTicket}
	}
	workflow.RegisterAllActionHandlersWithAI(
		workflowExecutor,
		s.Vulnerability,
		s.ScanRun,
		s.Scan,
		s.Integration,
		s.AITriage,
		wfJira,
		wfGitHub,
		log,
	)

	// Initialize workflow service with executor
	s.Workflow = workflow.NewWorkflowService(
		repos.Workflow,
		repos.WorkflowNode,
		repos.WorkflowEdge,
		repos.WorkflowRun,
		repos.WorkflowNodeRun,
		log, workflow.WithWorkflowAuditService(s.Audit), workflow.WithWorkflowExecutor(workflowExecutor),
		workflow.WithWorkflowStepAuthorizer(workflowAuthorizer),
		workflow.WithWorkflowSubjectReaders(repos.Finding, repos.Asset),
	)

	// Initialize workflow event dispatcher for automatic workflow triggering
	s.WorkflowDispatcher = workflow.NewWorkflowEventDispatcher(
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
	// Four-eyes on approvals (owner decision B16) reads who may approve.
	s.Suppression.SetApproverDirectory(repos.Suppression)
	// An asset-bound rule names an asset of the tenant the requester may see
	// (RFC-050 W8, 21b M-10).
	s.Suppression.SetAssetRefChecker(s.DataScope)

	// Enforce approved suppression rules during ingest: a new finding matching an
	// active (approved, non-expired) rule lands resolved+suppressed (out of the
	// open backlog) and records which rule suppressed it. Loads rules once per
	// batch (tenant-scoped). Without this wire the suppression engine + CRUD +
	// approve/reject UI exist but suppress nothing on the ingest path. Nil-safe.
	s.Ingest.SetSuppressionChecker(s.Suppression)

	// Initialize access control services
	s.Group = accesscontrol.NewGroupService(repos.Group, log,
		accesscontrol.WithGroupAuditService(s.Audit),
		accesscontrol.WithAccessControlRepository(repos.AccessControl),
		accesscontrol.WithGroupDataScope(s.DataScope),
		accesscontrol.WithScopeDelegationCap(s.DataScope),
	)

	s.AssignmentRule = assignment.NewRuleService(repos.AccessControl, repos.Group, log)
	s.ScopeRule = scope.NewRuleService(repos.AccessControl, repos.Group, log)
	s.ScopeRule.SetAssetGroupValidator(repos.AccessControl)
	s.ScopeRule.SetScopeDelegationCap(s.DataScope)

	// Wire scope rule hooks for real-time evaluation
	s.Asset.SetScopeRuleEvaluator(s.ScopeRule.EvaluateAsset)
	s.AssetGroup.SetScopeRuleReconciler(s.ScopeRule.ReconcileByAssetGroup)

	// Initialize assignment engine and wire to vulnerability service for auto-routing
	assignmentEngine := assignment.NewEngine(repos.AccessControl, log)
	// Resolve a finding's asset type so rules scoped by AssetTypes can match
	// (without this, such rules never fire).
	assignmentEngine.SetAssetTypeResolver(func(ctx context.Context, tenantID, assetID shared.ID) (assetdom.TypeRef, error) {
		a, err := repos.Asset.GetByID(ctx, tenantID, assetID)
		if err != nil {
			return assetdom.TypeRef{}, err
		}
		return assetdom.TypeRef{Type: a.Type(), SubType: a.SubType()}, nil
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
	// (betterleaks/trufflehog → FindingSourceSecret) into the exposure store so a
	// hardcoded secret shows up in the Credentials/Exposures view without a
	// manual import. Labeled discovery_source=secret_scan so it stays distinct
	// from an external breach import. Reuses the same exposure repo + state
	// history as the credential-import service.
	s.Ingest.SetExposureBridge(exposurebridge.NewBridge(repos.Exposure, repos.ExposureStateHistory, log))

	// Continuous attack-surface discovery: project recon-discovered assets (open
	// ports, exposed services, weak/expiring TLS certificates) into the Exposure
	// Register so they surface continuously — filling the port_open /
	// service_detected / certificate_* / ssl_issue event types that had no
	// producer. Post-asset-insert, best-effort; reuses the same exposure repo +
	// state history + dedupe/reactivate as the secret/misconfig bridge.
	// Recon exposures (port_open, service_detected, certificate, TLS) are
	// announced through the notification outbox like the other EASM ones
	// (research/22 P0-6 with P0-7).
	reconDB := &postgres.DB{DB: deps.DB}
	s.Ingest.SetAssetExposureProjector(exposurebridge.NewAssetBridge(
		postgres.NewAnnouncingExposureRepository(reconDB, postgres.NewEASMAlerter(reconDB)), repos.ExposureStateHistory, log))
	s.RemediationGroup = remediation.NewGroupService(repos.FindingRemediationKey, s.Vulnerability, s.BulkGuard, log)
	s.RemediationGroup.SetDataScope(s.DataScope)

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

	// Initialize permission sync services
	s.PermVersion = accesscontrol.NewPermissionVersionService(deps.RedisClient, log)
	s.PermCache, err = accesscontrol.NewPermissionCacheService(deps.RedisClient, repos.Role, s.PermVersion, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize permission cache service: %w", err)
	}

	// Initialize membership cache. Hard error if Redis is unreachable
	// at boot — without this cache the RequireMembership middleware
	// hammers the database on every request.
	s.MembershipCache, err = accesscontrol.NewMembershipCacheService(deps.RedisClient, repos.Tenant, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize membership cache service: %w", err)
	}

	s.Role = accesscontrol.NewRoleService(repos.Role, repos.RolePermission, log,
		accesscontrol.WithRoleAuditService(s.Audit),
		accesscontrol.WithRolePermissionVersionService(s.PermVersion),
		accesscontrol.WithRolePermissionCacheService(s.PermCache),
		accesscontrol.WithRoleMembershipReader(s.MembershipCache),
		accesscontrol.WithRoleMembershipCacheInvalidator(s.MembershipCache),
	)

	// Bound every oct_ key by what its user holds now, not at mint time.
	if s.APIKey != nil {
		s.APIKey.SetHolderPermissions(apikey.NewHolderPermissions(repos.Tenant, s.PermCache))
	}

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
	s.Module = module.NewModuleService(repos.Module, log)
	s.Module.SetTenantModuleRepo(repos.TenantModule)
	s.Module.SetAuditService(s.Audit)
	// Product-bundle subscription: resolves the enabled-module baseline live from
	// the tenant's chosen bundles (empty = every module on, backward-compatible).
	s.Module.SetBundleStore(moduleBundleStore{tenants: repos.Tenant, db: deps.DB})
	// Per-tenant module-config version counter (Redis-backed). Used
	// for ETag generation on module-list endpoints and as the cache-
	// key suffix in any future Redis payload cache. Bumped on every
	// toggle / preset apply / reset via notifyModuleChange.
	s.Module.SetVersionService(module.NewVersionService(deps.RedisClient, log))
	// Ingest honors the suppressions module toggle: with the module off (or
	// left out of the tenant's bundles) findings land as reported.
	s.Ingest.SetSuppressionModuleGuard(s.Module)
	// Events start no automation for a tenant with the workflows module off.
	if s.WorkflowDispatcher != nil {
		s.WorkflowDispatcher.SetModuleGuard(s.Module)
	}
	// Auto-triage stops for a tenant with the ai_triage module off.
	if s.AITriage != nil {
		s.AITriage.SetModuleGuard(s.Module)
	}

	// Initialize WebSocket hub for real-time features
	s.WebSocketHub = websocket.NewHub(log)
	s.WebSocketHub.SetChannelAccessChecker(wsChannelAccess{roles: s.Role, groups: repos.Group, scope: s.DataScope, runs: s.ScanRun})
	// The live run map: a run that changes tells its run:{id} watchers,
	// at most once a second per run.
	s.ScanRun.SetRunNotifier(newRunChangeThrottle(s.WebSocketHub, time.Second))
	// A role assigned, removed or redefined, or a membership removed or
	// suspended, closes the user's live sockets in that tenant; the client
	// reconnects through every upgrade gate again (RFC-045).
	if s.PermVersion != nil {
		hub := s.WebSocketHub
		s.PermVersion.SetChangeListener(func(ctx context.Context, tenantID, userID string) {
			hub.RevokeAccess(ctx, tenantID, userID)
		})
	}
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

	// Wire to ModuleService so a module toggle / preset / reset pushes
	// "module.updated" on tenant:{id}. wsHubBroadcaster.Broadcast exists only
	// for this seam; without the call the Settings → Modules page and the
	// sidebar never hear about a change made in another tab or by another
	// admin and stay stale until the SWR dedup window expires.
	s.Module.SetWSBroadcaster(broadcaster)

	// Initialize user notification service (needs WebSocketHub)
	s.Notification = integration.NewNotificationService(
		repos.Notification,
		s.WebSocketHub,
		log,
	)
	s.Notification.SetDataScope(s.DataScope)
	log.Info("user notification service initialized")

	// Wire notification service to GroupService for member notifications
	s.Group.SetNotificationService(s.Notification)

	// Wire in-app notification service to vulnerability service for real-time user notifications
	s.Vulnerability.SetUserNotificationService(s.Notification)

	// Wire in-app notification service to pentest service
	s.Pentest.SetUserNotificationService(s.Notification)

	// Change detection: an asset an ingest newly created (not a re-scan merge,
	// not a manual create) fires the `asset_discovered` workflow trigger and,
	// when it is internet-facing, a throttled tenant notification. Wired here
	// because it needs both the workflow dispatcher and the in-app
	// notification service, which is only built above.
	s.AssetDiscoveryNotifier = assetdiscovery.NewNotifier(s.Outbox, s.Notification, assetdiscovery.DefaultWindow, log)
	s.Ingest.SetAssetsDiscoveredCallback(func(ctx context.Context, tenantID shared.ID, assets []*assetdom.Asset) {
		s.WorkflowDispatcher.DispatchAssetsDiscovered(ctx, tenantID, assets)
		s.AssetDiscoveryNotifier.AssetsDiscovered(ctx, tenantID, assets)
	})
	// An existing asset a re-scan turned internet-facing is newly exposed
	// attack surface too: same throttled notification, no asset_discovered.
	s.Ingest.SetAssetsExposedCallback(s.AssetDiscoveryNotifier.AssetsExposed)

	// A successful scan run fires the `scan_completed` workflow trigger.
	s.ScanRun.SetRunCompletedCallback(s.WorkflowDispatcher.DispatchScanCompleted)

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
	s.Session = auth.NewSessionService(repos.Session, repos.RefreshToken, log)

	// Initialize auth service
	s.Auth = auth.NewAuthService(repos.User, repos.Session, repos.RefreshToken, repos.Tenant, s.Audit, cfg.Auth, log)
	s.Auth.SetRoleService(s.Role)
	// The sign-up policy (Console > System > Sign-up). TENANT_CREATION_MODE
	// seeds it on the first start only; afterwards the console value wins.
	s.Signup = signupapp.NewService(repos.SignupPolicy, repos.AdminAuditLog, repos.Admin, nil, log)
	if err := s.Signup.Seed(context.Background(), cfg.Auth.TenantCreationMode); err != nil {
		log.Error("seed the sign-up policy (admin_only stays in force until it can be read)", "error", err)
	}
	s.Auth.SetSignupPolicy(s.Signup)
	if os.Getenv("AUTH_ALLOW_REGISTRATION") != "" {
		log.Warn("AUTH_ALLOW_REGISTRATION is retired and ignored: who may sign up is the sign-up policy (Console > System > Sign-up)")
	}
	// Plans and limits: self-service organizations are Free.
	s.Auth.SetFreePlan(s.Entitlement)
	// Stamp the current permission version onto issued access tokens so the
	// permission-sync middleware can reject stale tokens after a role change
	// (AUTHZ-3). Without this the JWT carries pv=0 and the stale check is inert.
	s.Auth.SetPermissionVersionService(s.PermVersion)

	// Two-factor authentication (TOTP). Secrets are encrypted with the same
	// AES-GCM key as integration credentials.
	s.Auth.SetMFA(repos.UserMFA, s.Encryptor, cfg.App.Name)
	s.Session.SetMFAChallengeCleanup(repos.UserMFA)

	// Immediate session revocation: signing a session out (logout, "sign out
	// this device", password change, enabling 2FA, suspension) records its id
	// in Redis so the auth middleware rejects its still-unexpired access
	// tokens on the next request. Without Redis they expire naturally.
	var revocationStore auth.SessionRevocationStore
	if redisClient != nil {
		if tokens, err := redis.NewTokenStore(redisClient, log); err != nil {
			log.Warn("session revocation store unavailable", "error", err)
		} else if store, err := redis.NewSessionRevocationStore(tokens); err != nil {
			log.Warn("session revocation store unavailable", "error", err)
		} else {
			s.SessionRevocations = store
			revocationStore = store
		}
	}
	// Every session revocation also closes the session's live WebSocket
	// connections, on every API instance (RFC-045). Wired even without Redis,
	// so a single instance still closes its own sockets on logout.
	sessionRevocations := websocket.SessionRevocationNotifier{Store: revocationStore, Hub: s.WebSocketHub}
	revocationTTL := cfg.Auth.AccessTokenDuration + time.Minute
	s.Auth.SetSessionRevocationStore(sessionRevocations)
	s.Session.SetRevocationStore(sessionRevocations, revocationTTL)

	// Wire permission services to session service
	tenantMembershipAdapter := tenantapp.NewTenantMembershipAdapter(repos.Tenant)
	s.Session.SetPermissionServices(s.PermCache, s.PermVersion, tenantMembershipAdapter)

	// Wire session service to user service for session revocation on suspension
	s.User.SetSessionService(s.Session)

	// Wire session service to tenant service so SuspendMember can revoke
	// all sessions of a suspended user immediately. Without this, the
	// user's existing JWT continues to work on JWT-claim-scoped routes
	// (e.g. /api/v1/me/*, /api/v1/notifications) until it expires.
	s.Tenant.SetSessionService(s.Session)

	// Initialize SSO service for per-tenant identity provider authentication
	s.SSO = auth.NewSSOService(
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
	s.SSO.SetIdentityRepo(repos.UserIdentity)
	s.SSO.SetSessionRevocationStore(sessionRevocations, revocationTTL)

	// SSO P1: DNS-TXT domain-ownership verification. Wired as the PRIMARY JIT
	// auto-provisioning gate — a non-member is auto-joined only when the email
	// domain is DNS-verified for the tenant (see SSOService.jitProvisioningAllowed).
	s.DomainVerify = domainverify.NewService(repos.VerifiedDomain, domainverify.NewNetResolver(), log)
	// Tenant verification checks: 10 per organization per hour across
	// replicas (Redis), the in-process window on a Redis error.
	if redisClient != nil {
		if rl, err := redis.NewRateLimiter(redisClient, "easm_domain_verify", domainverify.MaxEASMVerifyPerHour, time.Hour, log); err == nil {
			s.DomainVerify.SetVerifyLimiter(&redisVerifyLimiter{rl: rl,
				fallback: domainverify.NewWindowLimiter(domainverify.MaxEASMVerifyPerHour, time.Hour)})
		}
	}
	s.SSO.SetDomainVerifier(s.DomainVerify)
	// Email-first sign-in asks which organization holds an email's SSO
	// domain (domainverify.Service.OwnerOfDomain).
	if owners, ok := any(s.DomainVerify).(auth.DomainOwnerLookup); ok {
		s.SSO.SetDomainOwnerLookup(owners)
	} else {
		log.Warn("email-first sign-in discovery is off: no domain owner lookup")
	}
	// SCIM attaches an EXISTING account only on a domain the organization has
	// DNS-verified; anyone else must be invited (their consent).
	s.SCIMProvisioning.SetDomainVerifier(s.DomainVerify)

	// External members (RFC-058): the holder of a verified SSO domain is the
	// home organization of its addresses.
	s.AddressClassifier = tenantapp.NewAddressClassifier(s.DomainVerify, func(ctx context.Context, tenantID shared.ID) (bool, error) {
		return domainverify.OwnsAnySSODomain(ctx, repos.VerifiedDomain, tenantID)
	})
	s.Tenant.SetAddressClassifier(s.AddressClassifier)
	// A domain the home organization stops holding suspends the members it
	// managed elsewhere; proving it again restores them (RFC-058).
	s.DomainVerify.SetClaimListener(s.Tenant)
	s.Auth.SetLapsedDomainChecker(s.DomainVerify)
	s.SSO.SetJITApprovalNotifier(s.Tenant)
	s.Role.SetPrivilegeNotifier(s.Tenant)
	s.Auth.SetInviteeClassifier(s.Tenant)

	// Trusted organizations (RFC-058): home-realm sign-in for external
	// members, the role ceiling, proposed end of access and API keys.
	s.OrgTrust = orgtrustapp.NewService(repos.OrgTrust, s.DomainVerify, s.Tenant, s.Audit, log)
	trustPolicy := orgtrustapp.NewPolicy(repos.OrgTrust, repos.Tenant)
	s.Tenant.SetTrustPolicy(trustPolicy)
	s.Auth.SetHomeRealm(repos.OrgTrust, s.DomainVerify)
	if s.Role != nil {
		s.Role.SetExternalRoleCeiling(func(ctx context.Context, host, home shared.ID) (string, error) {
			r, err := trustPolicy.MaxRoleFor(ctx, host, home)
			return string(r), err
		})
	}
	if s.APIKey != nil {
		s.APIKey.SetExternalKeyPolicy(trustPolicy)
	}

	// Social OAuth (Google / GitHub / Microsoft). Built only when at least one
	// provider actually has credentials, so the login surface the API advertises
	// on /auth/providers matches the routes it registers — see registerAuthRoutes.
	if cfg.OAuth.Enabled && cfg.OAuth.HasAnyProvider() {
		s.OAuth = auth.NewOAuthService(
			repos.User,
			repos.Session,
			repos.RefreshToken,
			cfg.OAuth,
			cfg.Auth,
			log,
		)
		// PKCE verifiers live in Redis keyed by state (TTL = state lifetime,
		// GETDEL = single use) so a login can finish on any replica. Without
		// Redis the service keeps them in process.
		// A social sign-in creates an account only when the sign-up policy
		// admits it (self-service, or a pending invitation for the email).
		if s.Signup != nil {
			s.OAuth.SetSignupPolicy(s.Signup)
		}
		s.OAuth.SetInvitationLookup(repos.Tenant)
		s.OAuth.SetIdentityRepo(repos.UserIdentity)
		if redisClient != nil {
			s.OAuth.SetPKCEStore(redisClient)
		} else {
			log.Warn("oauth: no Redis client; PKCE verifiers kept in process (single-replica only)")
		}
	}

	// SAML 2.0 SP (RFC-009 9d/9e): reuses SSO's session/provisioning tail.
	s.SAML = auth.NewSAMLService(repos.SAMLProvider, repos.Tenant, s.SSO, log)

	// A platform administrator's SAML / identity-provider change waits for an
	// owner of the organization; owners are told in-app (and by email, wired
	// in main once the email service exists).
	s.SSOChange = auth.NewSSOChangeService(repos.SSOChange, s.SAML, s.SSO, repos.Tenant, repos.Tenant, log)
	s.SSOChange.SetNotificationService(s.Notification)
	if s.DomainVerify != nil {
		s.SSOChange.SetDomainJITStore(s.DomainVerify)
	}

	// Wire the SSO-path checker so TenantService can refuse enabling sso_enforced
	// when the tenant has no usable SSO login path. main.go rebuilds s.Tenant, so
	// this is re-applied there too.
	s.Tenant.SetSSOPathChecker(s.SSO)

	// Member lifecycle (RFC-050): disable / re-enable / offboard / erase run
	// in one transaction each; administrators are told in-app when a disable
	// pauses schedules or a deprovisioned member still owns work.
	s.Tenant.SetLifecycleRepository(repos.MemberLifecycle)
	s.Tenant.SetLifecycleNotifier(s.Notification)

	// Sensor pairing approvals need step-up re-authentication and notify
	// every administrator (RFC-052 D-2, D-6).
	if s.SensorPairing != nil {
		s.SensorPairing.SetStepUp(s.Auth)
		s.SensorPairing.SetNotifications(repos.MemberLifecycle, s.Notification)
	}
	// A widened grant notifies every administrator (RFC-052 D-5).
	if s.SensorGrant != nil {
		s.SensorGrant.SetNotifications(repos.MemberLifecycle, s.Notification)
	}

	// Scope entries: settings, the approval count and the widening notice to
	// every administrator (RFC-054 §7).
	if s.Scope != nil {
		s.Scope.SetEntryPolicy(s.Tenant, repos.MemberLifecycle, s.Notification)
	}
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
	s.Email = auth.NewEmailService(emailSender, cfg.SMTP, cfg.App.Name, log)
	log.Info("email service initialized", "host", cfg.SMTP.Host, "from", cfg.SMTP.From)

	return nil
}

// Note: SetEmailEnqueuer was removed. The previous implementation
// rebuilt s.Tenant with `tenant.NewTenantService(nil, nil, ...)`, which
// dropped the repo and the logger and would panic on any subsequent
// call. The actual wiring of the email enqueuer happens in main.go
// where it can also re-attach the permission and session services
// after the tenant service is reconstructed.

// initTemplateKeyring returns the keyring custom templates are signed with
// for sensors: from APP_TEMPLATE_SIGNING_KEY, else derived from
// APP_ENCRYPTION_KEY. nil (no key at all, development only): templates go
// unsigned and every sensor refuses them.
func initTemplateKeyring(cfg *config.Config, log *logger.Logger) *scannertemplate.Keyring {
	if k := cfg.Encryption.TemplateSigningKey; k != "" {
		raw, err := crypto.ParseKey(k, "")
		if err == nil {
			if kr, err := scannertemplate.NewKeyring(raw); err == nil {
				log.Info("custom template signing enabled", "key_source", "APP_TEMPLATE_SIGNING_KEY")
				return kr
			}
		}
		log.Error("APP_TEMPLATE_SIGNING_KEY is invalid; custom templates go unsigned and sensors refuse them")
		return nil
	}
	if cfg.Encryption.IsConfigured() {
		raw, err := crypto.ParseKey(cfg.Encryption.Key, cfg.Encryption.KeyFormat)
		if err == nil {
			if kr, err := scannertemplate.NewKeyringFromEncryptionKey(raw); err == nil {
				log.Info("custom template signing enabled", "key_source", "derived from APP_ENCRYPTION_KEY")
				return kr
			}
		}
	}
	log.Warn("no template signing key (APP_TEMPLATE_SIGNING_KEY / APP_ENCRYPTION_KEY); custom templates go unsigned and sensors refuse them")
	return nil
}

// initContentSigner returns the signer of content packs (RFC-061): from
// APP_CONTENT_SIGNING_KEY, else derived from APP_ENCRYPTION_KEY under the
// content label, a key family separate from template, job and sensor CA
// keys. nil (no key at all, development only): uploads are refused.
func initContentSigner(cfg *config.Config, log *logger.Logger) *contentpackdom.Signer {
	if k := cfg.Encryption.ContentSigningKey; k != "" {
		raw, err := crypto.ParseKey(k, "")
		if err == nil {
			if s, err := contentpackdom.NewSigner(raw); err == nil {
				log.Info("content pack signing enabled", "key_source", "APP_CONTENT_SIGNING_KEY")
				return s
			}
		}
		log.Error("APP_CONTENT_SIGNING_KEY is invalid; content pack uploads are refused")
		return nil
	}
	if cfg.Encryption.IsConfigured() {
		raw, err := crypto.ParseKey(cfg.Encryption.Key, cfg.Encryption.KeyFormat)
		if err == nil {
			if s, err := contentpackdom.NewSignerFromEncryptionKey(raw); err == nil {
				log.Info("content pack signing enabled", "key_source", "derived from APP_ENCRYPTION_KEY")
				return s
			}
		}
	}
	log.Warn("no content signing key (APP_CONTENT_SIGNING_KEY / APP_ENCRYPTION_KEY); content pack uploads are refused")
	return nil
}

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

	current, err := crypto.NewCipherFromKey(cfg.Encryption.Key, cfg.Encryption.KeyFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize credentials encryptor: %w", err)
	}
	if len(cfg.Encryption.PreviousKeys) == 0 {
		log.Info("credentials encryption enabled")
		return current, nil
	}

	// Key rotation in progress: encrypt with the new key, still decrypt
	// values written under the previous ones until cmd/rekey re-encrypts them.
	previous := make([]*crypto.Cipher, 0, len(cfg.Encryption.PreviousKeys))
	for i, k := range cfg.Encryption.PreviousKeys {
		c, perr := crypto.NewCipherFromKey(k, "")
		if perr != nil {
			return nil, fmt.Errorf("APP_ENCRYPTION_KEY_PREVIOUS entry %d: %w", i+1, perr)
		}
		previous = append(previous, c)
	}
	log.Warn("credentials encryption enabled with previous keys (rotation in progress); run cmd/rekey, then remove APP_ENCRYPTION_KEY_PREVIOUS",
		"previous_keys", len(previous))
	return crypto.NewKeyRing(current, previous...), nil
}

// NewJobClient creates a new job client for background processing.
func NewJobClient(cfg *config.Config, log *logger.Logger) (*jobs.Client, error) {
	redisAddr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
	redisTLS, err := redis.TLSConfig(&cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("failed to configure job client redis TLS: %w", err)
	}
	jobClientCfg := jobs.ClientConfig{
		RedisAddr:     redisAddr,
		RedisPassword: cfg.Redis.Password,
		RedisDB:       cfg.Redis.DB,
		RedisTLS:      redisTLS,
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
func NewJobWorker(cfg *config.Config, emailService *auth.EmailService, aiTriageService *aitriage.AITriageService, jiraSyncer jobs.JiraStatusSyncer, githubSyncer jobs.GitHubStatusSyncer, log *logger.Logger) (*jobs.Worker, error) {
	redisAddr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
	redisTLS, err := redis.TLSConfig(&cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("failed to configure job worker redis TLS: %w", err)
	}
	workerCfg := jobs.WorkerConfig{
		RedisAddr:     redisAddr,
		RedisPassword: cfg.Redis.Password,
		RedisDB:       cfg.Redis.DB,
		RedisTLS:      redisTLS,
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

// logTokensOnPreviousPepper reports, at start-up during an encryption-key
// rotation, how many active tokens still verify only through
// APP_ENCRYPTION_KEY_PREVIOUS. They are re-hashed on their next use; the
// previous key can be removed once every count is zero (rekey -status).
func logTokensOnPreviousPepper(db *postgres.DB, keyPepperID, sensorPepperID string, log *logger.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	counts, err := postgres.TokensNotUnderPepper(ctx, db, postgres.TokenPepperIDs{
		APIKey: keyPepperID, SCIM: keyPepperID, Sensor: sensorPepperID,
	})
	if err != nil {
		log.Warn("could not count tokens still on the previous encryption key", "error", err)
		return
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	log.Warn("APP_ENCRYPTION_KEY_PREVIOUS is set; active tokens not yet re-hashed under the current key",
		"total", total, "api_keys", counts["api_keys"], "scim_tokens", counts["scim_tokens"],
		"sensors", counts["sensors"], "sensor_api_keys", counts["sensor_api_keys"])
}

// connectorScansIfEnabled is the Tenable.sc connector as the scan service's
// connector, or nil while integrationdom.TenableConnectorEnabled is off.
func connectorScansIfEnabled(c *tenablesc.Service) scan.ConnectorScans {
	if !integrationdom.TenableConnectorEnabled || c == nil {
		return nil
	}
	return c
}

// redisVerifyLimiter counts tenant domain-verification checks in Redis, and
// in-process when Redis fails (never unlimited).
type redisVerifyLimiter struct {
	rl       *redis.RateLimiter
	fallback *domainverify.WindowLimiter
}

func (l *redisVerifyLimiter) Allow(ctx context.Context, tenantID shared.ID) (bool, error) {
	res, err := l.rl.Allow(ctx, "tenant:"+tenantID.String())
	if err != nil || res == nil {
		return l.fallback.Allow(ctx, tenantID)
	}
	return res.Allowed, nil
}

// easmRecheck is the default re-check window of the EASM sweeps for an
// interval: half an hour short of it, so the hourly controller tick re-queries
// a name once per interval (research/22 P0-11).
func easmRecheck(interval time.Duration) time.Duration {
	if interval <= time.Hour {
		return interval * 5 / 6
	}
	return interval - 30*time.Minute
}

// zoneResolver is the resolver scan-zone routing resolves hostnames with:
// the platform's own for "system", else one that asks only the given
// recursive resolver (host[:port], port 53 by default), so tenants cannot
// resolve names through the platform's internal DNS.
func zoneResolver(spec string) *net.Resolver {
	if spec == "" || spec == config.ScanZoneResolverSystem {
		return net.DefaultResolver
	}
	server := spec
	if _, _, err := net.SplitHostPort(spec); err != nil {
		server = net.JoinHostPort(spec, "53")
	}
	d := &net.Dialer{Timeout: 3 * time.Second}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, server)
		},
	}
}
