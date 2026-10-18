// Package tenant implements the application service for the tenant bounded context — orchestrates pkg/domain/tenant entities and cross-cutting concerns (audit, notifications, RBAC).
package tenant

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/signupevent"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/licensepolicy"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EmailJobEnqueuer defines the interface for enqueueing email jobs.
type EmailJobEnqueuer interface {
	EnqueueTeamInvitation(ctx context.Context, payload TeamInvitationJobPayload) error
}

// MemberStatusEmailNotifier sends transactional emails when a
// membership lifecycle event happens (suspend / reactivate). The
// concrete implementation is *auth.EmailService; we depend on the
// interface here to keep the dependency direction clean.
type MemberStatusEmailNotifier interface {
	SendMemberSuspendedEmail(ctx context.Context, recipientEmail, recipientName, teamName, actorName, tenantID string) error
	SendMemberReactivatedEmail(ctx context.Context, recipientEmail, recipientName, teamName, actorName, tenantID string) error
}

// TeamInvitationJobPayload contains data for team invitation email jobs.
type TeamInvitationJobPayload struct {
	RecipientEmail string
	InviterName    string
	TeamName       string
	Token          string
	ExpiresIn      time.Duration
	InvitationID   string
	TenantID       string
}

// TenantService handles tenant-related business operations.
// Note: Tenants are displayed as "Teams" in the UI.
type TenantService struct {
	// signups reports organizations created to the sign-up feed (optional).
	signups signupevent.Recorder
	repo    tenantdom.Repository
	// scoringVersions stamps the scoring version a risk scoring settings
	// change created on its audit entry (SetScoringVersions; optional).
	scoringVersions scoring.VersionRepository
	// stepUp requires the acting owner's recent re-authentication (SetStepUpGate).
	stepUp shared.RecentAuthGate
	// assetPolicy re-resolves assets after a source precedence change.
	assetPolicy      AssetPolicyListener
	auditService     *auditapp.AuditService
	emailEnqueuer    EmailJobEnqueuer
	userInfoProvider UserInfoProvider // For fetching user names
	// Permission sync services for immediate cache invalidation on member removal
	permCacheSvc   *accesscontrol.PermissionCacheService
	permVersionSvc *accesscontrol.PermissionVersionService
	// Session service for revoking all sessions of a user when their
	// access is paused (suspend) or removed. Without this, an existing
	// browser tab keeps a valid JWT until expiry and the suspension
	// only takes effect on tenant-scoped routes that hit
	// RequireMembership middleware. JWT-claim-scoped routes (e.g.
	// /api/v1/me/*, /api/v1/notifications) would still let the user in.
	sessionService *authapp.SessionService
	// Membership cache used by RequireMembership middleware. We hold a
	// reference here so mutations (suspend / reactivate / role change /
	// remove) can drop the cached entry immediately. nil means caching
	// is disabled (Redis unavailable) and the middleware reads the
	// repository directly — invalidation calls become no-ops.
	membershipCache *accesscontrol.MembershipCacheService
	// Email notifier for membership lifecycle events. Optional — if
	// nil (or if SMTP is not configured) the suspend/reactivate
	// operations succeed without sending an email.
	statusNotifier MemberStatusEmailNotifier
	// User service for fetching user name + email when sending the
	// suspend / reactivate notification email. Optional: when unset,
	// the email is skipped (best-effort).
	userService *UserService
	// Role service for assigning RBAC roles attached to invitations
	// when they are accepted. Optional — without it, invitation
	// role_ids are silently dropped (audit finding). Wire it via
	// WithTenantRoleService at app startup.
	roleService *accesscontrol.RoleService
	// ssoPathChecker reports whether a tenant has a usable SSO login path.
	// Used to REFUSE enabling sso_enforced when it would leave members with no
	// way to sign in. Optional — when nil the guard is skipped (and only a
	// warning is logged): the never-lock-out guarantee still holds because the
	// owner is always break-glass exempt at the enforcement gate.
	ssoPathChecker SSOPathChecker
	// Member lifecycle (disable, offboard, erase): the transactional store
	// and the in-app notice to administrators. Optional.
	lifecycle         tenantdom.LifecycleRepository
	lifecycleNotifier LifecycleInAppNotifier
	// invitationTeams checks and applies the teams of an invitation
	// (invitation_teams.go).
	invitationTeams InvitationTeams
	// Ownership transfer store and its emails (ownership_transfer.go).
	ownershipTransfers tenantdom.OwnershipTransferRepository
	ownershipNotifier  OwnershipTransferNotifier
	// classifier decides whether an invitee is internal or external
	// (external_members.go).
	classifier *AddressClassifier
	// trustPolicy reads the trusts with members' home organizations: role
	// ceiling and proposed end of access (RFC-058). Optional.
	trustPolicy TrustPolicy
	// blobEraser deletes the stored files (attachments, evidence) of a
	// tenant being deleted. Wired at startup; nil only in tests.
	blobEraser TenantBlobEraser
	logger     *logger.Logger
}

// TenantBlobEraser deletes every stored file of one tenant from every storage
// backend it uses (AttachmentService.EraseTenant). Idempotent.
type TenantBlobEraser interface {
	EraseTenant(ctx context.Context, tenantID string) (int, error)
}

// ErrStoredFilesNotErased: the organization was not deleted because its stored
// files could not all be deleted (storage unreachable, or the organization's
// own bucket refused). Nothing about the organization's rows changed; the
// owner retries, and files already deleted stay deleted.
var ErrStoredFilesNotErased = errors.New("the organization's stored files could not be deleted")

// SetBlobEraser wires the stored-file erasure that organization deletion runs.
func (s *TenantService) SetBlobEraser(e TenantBlobEraser) {
	s.blobEraser = e
}

// UserInfoProvider defines methods to fetch user information for emails.
type UserInfoProvider interface {
	GetUserNameByID(ctx context.Context, id shared.ID) (string, error)
}

// SSOPathChecker reports whether a tenant identified by slug has a usable SSO
// login path — an active per-tenant identity provider or the opted-in platform
// env fallback. Implemented by the SSO service (HasUsableSSOPath). Used by
// UpdateSecuritySettings to refuse enabling sso_enforced with no way in.
type SSOPathChecker interface {
	HasUsableSSOPath(ctx context.Context, orgSlug string) (bool, error)
}

// NewTenantService creates a new TenantService.
func NewTenantService(repo tenantdom.Repository, log *logger.Logger, opts ...TenantServiceOption) *TenantService {
	s := &TenantService{
		repo:   repo,
		logger: log.With("service", "tenant"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// TenantServiceOption is a functional option for TenantService.
type TenantServiceOption func(*TenantService)

// WithTenantAuditService sets the audit service for TenantService.
func WithTenantAuditService(auditService *auditapp.AuditService) TenantServiceOption {
	return func(s *TenantService) {
		s.auditService = auditService
	}
}

// WithEmailEnqueuer sets the email job enqueuer for TenantService.
func WithEmailEnqueuer(enqueuer EmailJobEnqueuer) TenantServiceOption {
	return func(s *TenantService) {
		s.emailEnqueuer = enqueuer
	}
}

// SetEmailEnqueuer wires the email job enqueuer (invitation emails). It is a
// setter, not only a constructor option, because the job client is built after
// the services: cmd/server used to construct a second TenantService just to
// pass it, and every collaborator wired on the first instance was lost.
func (s *TenantService) SetEmailEnqueuer(enqueuer EmailJobEnqueuer) {
	s.emailEnqueuer = enqueuer
}

// WithUserInfoProvider sets the user info provider for TenantService.
func WithUserInfoProvider(provider UserInfoProvider) TenantServiceOption {
	return func(s *TenantService) {
		s.userInfoProvider = provider
	}
}

// WithTenantRoleService wires the RBAC role service for invitation
// role assignment. Without it, invitation.RoleIDs() is silently dropped
// on accept — security audit finding.
func WithTenantRoleService(svc *accesscontrol.RoleService) TenantServiceOption {
	return func(s *TenantService) {
		s.roleService = svc
	}
}

// SetRoleService wires the RBAC role service after construction
// (used by services.go bootstrap where TenantService is built before
// RoleService — same pattern as SetMembershipCache).
func (s *TenantService) SetRoleService(svc *accesscontrol.RoleService) {
	s.roleService = svc
}

// SetSSOPathChecker wires the SSO-path checker after construction. TenantService
// is built before the SSO service, so this is called at bootstrap once SSO is
// ready (mirrors SetSessionService / SetRoleService).
func (s *TenantService) SetSSOPathChecker(c SSOPathChecker) {
	s.ssoPathChecker = c
}

// WithTenantPermissionCacheService sets the permission cache service for TenantService.
// This enables immediate cache invalidation when members are removed.
func WithTenantPermissionCacheService(svc *accesscontrol.PermissionCacheService) TenantServiceOption {
	return func(s *TenantService) {
		s.permCacheSvc = svc
	}
}

// WithTenantPermissionVersionService sets the permission version service for TenantService.
// This enables version cleanup when members are removed.
func WithTenantPermissionVersionService(svc *accesscontrol.PermissionVersionService) TenantServiceOption {
	return func(s *TenantService) {
		s.permVersionSvc = svc
	}
}

// SetPermissionServices sets the permission cache and version services.
// This is used when services are initialized after TenantService.
func (s *TenantService) SetPermissionServices(cacheSvc *accesscontrol.PermissionCacheService, versionSvc *accesscontrol.PermissionVersionService) {
	s.permCacheSvc = cacheSvc
	s.permVersionSvc = versionSvc
}

// SetSessionService injects the session service so SuspendMember and
// OffboardMember can end the sessions the organization may end
// (endTenantSessions) and erasure can end all of them.
func (s *TenantService) SetSessionService(sessionService *authapp.SessionService) {
	s.sessionService = sessionService
}

// SetMembershipCache injects the membership cache so mutations
// (suspend / reactivate / role change / member removal) can drop the
// cached entry immediately. With the cache wired up, the middleware
// no longer hits the database on every request — but the same wiring
// is what guarantees a suspended user gets a 403 on their NEXT
// request instead of after the cache TTL expires.
func (s *TenantService) SetMembershipCache(cache *accesscontrol.MembershipCacheService) {
	s.membershipCache = cache
}

// SetMemberStatusEmailNotifier injects the email notifier used by
// SuspendMember and ReactivateMember to tell the affected user what
// happened. Optional: when unset, the operations still succeed but
// the user is not notified.
func (s *TenantService) SetMemberStatusEmailNotifier(n MemberStatusEmailNotifier) {
	s.statusNotifier = n
}

// SetUserService injects the user service so the suspend/reactivate
// notifier can resolve a recipient name + email from the user id on
// the membership row. Optional alongside SetMemberStatusEmailNotifier.
func (s *TenantService) SetUserService(u *UserService) {
	s.userService = u
}

// notifyMemberStatusChange sends an email to the affected user when
// their membership is suspended or reactivated. Best-effort: any
// failure (no notifier wired, user lookup fail, SMTP down) is logged
// at warn level and never returned to the caller, because the audit
// log is the system of record for the lifecycle event.
func (s *TenantService) notifyMemberStatusChange(
	ctx context.Context,
	suspended bool,
	tenantID, userID, actorID string,
) {
	if s.statusNotifier == nil || s.userService == nil {
		return
	}

	// Resolve user name + email.
	users, err := s.userService.GetUsersByIDs(ctx, []string{userID})
	if err != nil || len(users) == 0 {
		s.logger.Warn("status email skipped: user lookup failed",
			"user_id", userID, "error", err)
		return
	}
	u := users[0]
	if u.Email() == "" {
		return
	}

	// Resolve tenant name (best effort).
	teamName := "the team"
	if tid, perr := shared.IDFromString(tenantID); perr == nil {
		if t, terr := s.repo.GetByID(ctx, tid); terr == nil && t != nil {
			teamName = t.Name()
		}
	}

	// Resolve actor name (best effort).
	actorName := ""
	if actorID != "" {
		if actorUsers, aerr := s.userService.GetUsersByIDs(ctx, []string{actorID}); aerr == nil && len(actorUsers) > 0 {
			actorName = actorUsers[0].Name()
		}
	}

	var notifyErr error
	if suspended {
		notifyErr = s.statusNotifier.SendMemberSuspendedEmail(
			ctx, u.Email(), u.Name(), teamName, actorName, tenantID)
	} else {
		notifyErr = s.statusNotifier.SendMemberReactivatedEmail(
			ctx, u.Email(), u.Name(), teamName, actorName, tenantID)
	}
	if notifyErr != nil {
		s.logger.Warn("status email failed",
			"user_id", userID, "tenant_id", tenantID, "error", notifyErr)
	}
}

// invalidateMembershipCache is the convenience helper used by every
// mutation that touches role or status. Safe to call when the cache
// is unset (no-op).
func (s *TenantService) invalidateMembershipCache(ctx context.Context, tenantID, userID string) {
	if s.membershipCache == nil {
		return
	}
	s.membershipCache.Invalidate(ctx, tenantID, userID)
}

// bumpPermissionVersion drops the user's cached permissions and bumps their
// permission version, which makes every token minted before now stale. No-op
// for whichever service is unset.
func (s *TenantService) bumpPermissionVersion(ctx context.Context, tenantID, userID string) {
	if s.permCacheSvc != nil {
		s.permCacheSvc.Invalidate(ctx, tenantID, userID)
	}
	if s.permVersionSvc != nil {
		s.permVersionSvc.Increment(ctx, tenantID, userID)
	}
}

// logAudit logs an audit event if audit service is configured.
func (s *TenantService) logAudit(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}

// LogAuditEvent logs an audit event via the tenant service's audit service.
// This is the public variant of logAudit, intended for use by handlers that
// need to log audit events for operations not managed by the service layer.
func (s *TenantService) LogAuditEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	s.logAudit(ctx, actx, event)
}

// =============================================================================
// Tenant Operations
// =============================================================================

// ProvisionedEntitlements are what a hosted service's control plane writes
// with an organization it provisions (validated by the caller).
type ProvisionedEntitlements struct {
	Limits         limits.Limits
	DeniedFeatures []string
	IdlePolicy     bool
	Reason         string
}

// CreateTenantInput represents the input for creating a tenant.
type CreateTenantInput struct {
	Name        string `json:"name" validate:"required,min=2,max=100"`
	Slug        string `json:"slug" validate:"required,min=3,max=100,slug"`
	Description string `json:"description" validate:"max=500"`
	// InitialLimits are stored with the organization (the instance's
	// self-service defaults for an organization a person creates). Empty:
	// no limits.
	InitialLimits limits.Limits `json:"-"`
	// Provisioned, when set, replaces InitialLimits: what the control plane
	// provisions with the organization (its limits, denies and idle policy).
	Provisioned *ProvisionedEntitlements `json:"-"`
	// SignupSource is the path reported to the console's sign-up feed:
	// empty for an organization a signed-in person creates (self_service);
	// the platform paths name themselves (console, access_request,
	// control_plane).
	SignupSource signupevent.Source `json:"-"`
	// CreatorEmail is the creator's address; only its registrable domain
	// reaches the sign-up feed. Empty: the audit context's actor email.
	CreatorEmail string `json:"-"`
}

// SetSignupRecorder wires the sign-up feed (docs/architecture/signup-activity.md).
func (s *TenantService) SetSignupRecorder(r signupevent.Recorder) { s.signups = r }

// CreateTenant creates a new tenant and adds the creator as owner.
// creatorUserID is the local user ID (from users table).
func (s *TenantService) CreateTenant(ctx context.Context, input CreateTenantInput, creatorUserID shared.ID, actx auditapp.AuditContext) (*tenantdom.Tenant, error) {
	s.logger.Info("creating tenant", "name", input.Name, "slug", input.Slug, "creator", creatorUserID.String())

	// Check if slug already exists
	exists, err := s.repo.ExistsBySlug(ctx, input.Slug)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: this URL is not available; choose another", shared.ErrValidation)
	}

	// Create tenant (createdBy still uses string for now as it's stored separately)
	t, err := tenantdom.NewTenant(input.Name, input.Slug, creatorUserID.String())
	if err != nil {
		return nil, err
	}

	if input.Description != "" {
		t.UpdateDescription(input.Description)
	}
	if p := input.Provisioned; p != nil {
		t.SetInitial(tenantdom.InitialEntitlements{
			Limits:     limits.Rows(t.ID(), limits.OriginControlPlane, p.Reason, p.Limits, t.CreatedAt()),
			Denies:     limits.DenyRows(t.ID(), limits.OriginControlPlane, p.Reason, p.DeniedFeatures, t.CreatedAt()),
			IdlePolicy: p.IdlePolicy, IdleReason: p.Reason,
		})
	} else {
		t.SetInitialLimits(limits.SelfServiceRows(t.ID(), input.InitialLimits, t.CreatedAt()))
	}

	// Build the owner membership before any write so a construction error can't
	// leave a tenant without an owner.
	membership, err := tenantdom.NewOwnerMembership(creatorUserID, t.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to create owner membership: %w", err)
	}

	// Create tenant + owner membership atomically (no orphan tenant on failure).
	if err := s.repo.CreateWithOwner(ctx, t, membership); err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	s.logger.Info("tenant created", "id", t.ID().String(), "name", t.Name(), "owner", creatorUserID.String())

	// Log audit event
	actx.TenantID = t.ID().String()
	event := auditapp.NewSuccessEvent(audit.ActionTenantCreated, audit.ResourceTypeTenant, t.ID().String()).
		WithResourceName(t.Name()).
		WithMessage(fmt.Sprintf("Team '%s' created", t.Name()))
	s.logAudit(ctx, actx, event)

	if s.signups != nil {
		source, email := input.SignupSource, input.CreatorEmail
		if source == "" {
			source = signupevent.SourceSelfService
		}
		if email == "" {
			email = actx.ActorEmail
		}
		s.signups.Record(ctx, signupevent.Event{Kind: signupevent.KindOrganizationCreated, Source: source,
			Email: email, TenantID: t.ID(), UserID: creatorUserID})
	}

	return t, nil
}

// GetTenant retrieves a tenant by ID.
func (s *TenantService) GetTenant(ctx context.Context, tenantID string) (*tenantdom.Tenant, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetTenantBySlug retrieves a tenant by slug.
func (s *TenantService) GetTenantBySlug(ctx context.Context, slug string) (*tenantdom.Tenant, error) {
	return s.repo.GetBySlug(ctx, slug)
}

// UpdateTenantInput represents the input for updating a tenant.
type UpdateTenantInput struct {
	Name        *string `json:"name" validate:"omitempty,min=2,max=100"`
	Slug        *string `json:"slug" validate:"omitempty,min=3,max=100,slug"`
	Description *string `json:"description" validate:"omitempty,max=500"`
	LogoURL     *string `json:"logo_url" validate:"omitempty,url,max=500"`
	// CallerIsOwner is set by the handler from the caller's membership role.
	// Renaming the slug is owner-only (owner decision B13).
	CallerIsOwner bool `json:"-"`
}

// ErrSlugChangeOwnerOnly: only the organization owner may rename the slug.
var ErrSlugChangeOwnerOnly = fmt.Errorf("%w: only the organization owner can change the slug", shared.ErrForbidden)

// ErrSlugChangeWithSSO: SAML/SSO sign-in URLs are keyed by the slug, so it is
// frozen while an identity provider is configured.
var ErrSlugChangeWithSSO = fmt.Errorf("%w: the slug cannot change while single sign-on is configured; the SSO sign-in URLs registered at your identity provider use it", shared.ErrValidation)

// UpdateTenant updates a tenant's information.
func (s *TenantService) UpdateTenant(ctx context.Context, tenantID string, input UpdateTenantInput, actx auditapp.AuditContext) (*tenantdom.Tenant, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	before := profileOf(t)

	if input.Name != nil {
		if err := t.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Slug != nil && *input.Slug != t.Slug() {
		if !input.CallerIsOwner {
			return nil, ErrSlugChangeOwnerOnly
		}
		if s.ssoPathChecker != nil {
			usable, err := s.ssoPathChecker.HasUsableSSOPath(ctx, t.Slug())
			if err != nil {
				return nil, fmt.Errorf("failed to check SSO configuration: %w", err)
			}
			if usable {
				return nil, ErrSlugChangeWithSSO
			}
		}
		// Check if new slug already exists
		exists, err := s.repo.ExistsBySlug(ctx, *input.Slug)
		if err != nil {
			return nil, fmt.Errorf("failed to check slug existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: slug '%s' is already taken", shared.ErrValidation, *input.Slug)
		}
		// The slug is in every sign-in and share link: renaming it needs the
		// owner's recent re-authentication (asked once the rename is valid).
		if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
			return nil, err
		}
		if err := t.UpdateSlug(*input.Slug); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		t.UpdateDescription(*input.Description)
	}

	if input.LogoURL != nil {
		t.UpdateLogoURL(*input.LogoURL)
	}

	if err := s.repo.UpdateProfile(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	s.logger.Info("tenant updated", "id", t.ID().String())

	// The slug keys SAML/SSO sign-in URLs, so renaming it is High.
	after := profileOf(t)
	severity := audit.SeverityLow
	if after.Slug != before.Slug {
		severity = audit.SeverityHigh
	}
	actx.TenantID = tenantID
	event := auditapp.NewChangeEvent(audit.ActionTenantUpdated, audit.ResourceTypeTenant, tenantID, before, after).
		WithResourceName(after.Name).
		WithSeverity(severity).
		WithMessage("Organization profile updated")
	s.logAudit(ctx, actx, event)
	return t, nil
}

// DeleteTenant deletes a tenant. The destructive nature means this
// MUST emit an audit event — without it the hash-chain can't prove
// who triggered the deletion, and operators have no forensic trail
// once the tenant's rows are CASCADE'd away. Tenant name is captured
// BEFORE delete so the audit row can name the victim even though the
// row no longer exists.
func (s *TenantService) DeleteTenant(ctx context.Context, actx auditapp.AuditContext, tenantID string) error {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// Capture the name + slug before the row vanishes so the audit
	// entry is self-describing. Best-effort — if the lookup fails the
	// tenant may already be gone and we still want to log the attempt.
	var tenantName, tenantSlug string
	if t, getErr := s.repo.GetByID(ctx, parsedID); getErr == nil && t != nil {
		tenantName = t.Name()
		tenantSlug = t.Slug()
	}

	// Stored files first, rows second. Files are erased while the tenant row
	// still exists, so if storage is down the deletion is refused and the
	// obligation stays visible (the tenant and its attachment rows remain;
	// the owner retries, erasure is idempotent). Deleting rows first would
	// lose the only record of where the files are, and a tenant's own
	// bucket keys with it.
	filesErased := 0
	if s.blobEraser != nil {
		n, eraseErr := s.blobEraser.EraseTenant(ctx, parsedID.String())
		if eraseErr != nil {
			// The cause can name operator paths or endpoints: log it, keep it
			// out of the response and the tenant's audit log.
			s.logger.Error("organization deletion refused: stored files not erased",
				"tenant_id", tenantID, "files_erased", n, "error", eraseErr)
			failCtx := actx
			failCtx.TenantID = tenantID
			s.logAudit(ctx, failCtx, auditapp.NewFailureEvent(audit.ActionTenantDeleted, audit.ResourceTypeTenant, tenantID, ErrStoredFilesNotErased).
				WithResourceName(tenantName).
				WithSeverity(audit.SeverityHigh).
				WithMessage("Organization deletion refused: its stored files could not be deleted").
				WithMetadata("files_erased", n))
			return ErrStoredFilesNotErased
		}
		filesErased = n
	}

	if err := s.repo.Delete(ctx, parsedID); err != nil {
		return err
	}

	// A file uploaded between the erasure and the row delete has no row left
	// to name it: erase the namespace once more. Uploads after this point
	// fail on the missing tenant and remove their own file.
	if s.blobEraser != nil {
		n, eraseErr := s.blobEraser.EraseTenant(ctx, parsedID.String())
		filesErased += n
		if eraseErr != nil {
			s.logger.Error("files uploaded during organization deletion may remain",
				"tenant_id", tenantID, "error", eraseErr)
		}
	}

	// The tenant row is gone, so the event cannot carry its tenant_id
	// (audit_logs.tenant_id references tenants, and the insert used to fail
	// silently, leaving no durable record of the deletion). Record it on the
	// platform-level system chain instead; resource_id and metadata keep the
	// deleted tenant's identity.
	event := auditapp.NewSuccessEvent(audit.ActionTenantDeleted, audit.ResourceTypeTenant, tenantID).
		WithResourceName(tenantName).
		WithSeverity(audit.SeverityCritical).
		WithMessage(fmt.Sprintf("Tenant %q deleted (all tenant data cascaded)", tenantName)).
		WithMetadata("slug", tenantSlug).
		WithMetadata("deleted_tenant_id", tenantID).
		WithMetadata("files_erased", filesErased)
	platformCtx := actx
	platformCtx.TenantID = ""
	s.logAudit(ctx, platformCtx, event)

	s.logger.Info("tenant deleted", "id", tenantID, "name", tenantName)
	return nil
}

// ListUserTenants lists all tenants a user belongs to.
// userID is the local user ID (from users table).
func (s *TenantService) ListUserTenants(ctx context.Context, userID shared.ID) ([]*tenantdom.TenantWithRole, error) {
	return s.repo.ListTenantsByUser(ctx, userID)
}

// =============================================================================
// Member Operations
// =============================================================================

// AddMemberInput represents the input for adding a member.
type AddMemberInput struct {
	UserID shared.ID `json:"user_id" validate:"required"`
	Role   string    `json:"role" validate:"required,oneof=admin member viewer"`
}

// AddMember adds a user to a tenant.
// inviterUserID is the local user ID of the person inviting.
func (s *TenantService) AddMember(ctx context.Context, tenantID string, input AddMemberInput, inviterUserID shared.ID, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	return s.addMember(ctx, tenantID, input, inviterUserID, actx, s.repo.CreateMembership)
}

// joinRequestMembershipCreator approves a join request and creates the
// membership in one transaction (postgres.TenantRepository).
type joinRequestMembershipCreator interface {
	CreateMembershipApprovingJoinRequest(ctx context.Context, m *tenantdom.Membership, requestID, approver shared.ID, at time.Time) error
}

// AddMemberApprovingJoinRequest adds a member exactly as AddMember does
// (every check applies) and approves the person's waiting join request in
// the same transaction: either both happen or neither (RFC-104).
func (s *TenantService) AddMemberApprovingJoinRequest(ctx context.Context, tenantID string, input AddMemberInput, approver, requestID shared.ID, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	creator, ok := s.repo.(joinRequestMembershipCreator)
	if !ok {
		return nil, fmt.Errorf("%w: join requests are not supported by this repository", shared.ErrInternal)
	}
	return s.addMember(ctx, tenantID, input, approver, actx, func(ctx context.Context, m *tenantdom.Membership) error {
		return creator.CreateMembershipApprovingJoinRequest(ctx, m, requestID, approver, time.Now().UTC())
	})
}

func (s *TenantService) addMember(ctx context.Context, tenantID string, input AddMemberInput, inviterUserID shared.ID, actx auditapp.AuditContext,
	create func(ctx context.Context, m *tenantdom.Membership) error,
) (*tenantdom.Membership, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	role, ok := tenantdom.ParseRole(input.Role)
	if !ok {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}
	if role == tenantdom.RoleAdmin {
		if err := s.authorizeAdminPromotion(ctx, parsedTenantID, actx); err != nil {
			return nil, err
		}
	}

	// Check if user is already a member. A suspended membership blocks
	// re-add: the admin must reactivate the existing row instead of
	// creating a duplicate that loses the suspension audit trail.
	// An offboarded tombstone is not a membership: the person re-joins from
	// zero (CreateMembership re-activates the row with the new role).
	existing, err := s.repo.GetMembership(ctx, input.UserID, parsedTenantID)
	if err == nil && !existing.IsOffboarded() {
		if existing.IsSuspended() {
			return nil, fmt.Errorf(
				"%w: this user has a suspended membership in this tenant — reactivate them via the Members page instead",
				shared.ErrValidation,
			)
		}
		return nil, fmt.Errorf("%w: user is already a member", shared.ErrValidation)
	}
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	// Security.AllowedDomains applies to every way into the organization.
	if s.userService != nil {
		users, uerr := s.userService.GetUsersByIDs(ctx, []string{input.UserID.String()})
		if uerr != nil {
			return nil, fmt.Errorf("failed to look up user: %w", uerr)
		}
		if len(users) == 0 {
			return nil, shared.ErrNotFound
		}
		if err := s.requireAllowedEmailDomain(ctx, parsedTenantID, users[0].Email()); err != nil {
			return nil, err
		}
		// Someone outside the organization joins only by accepting an
		// invitation (their consent), never by being added.
		if class, _, cerr := s.classifyInvitee(ctx, parsedTenantID, users[0].Email(), tenantdom.ExternalAccess{}, time.Now().UTC()); cerr != nil {
			return nil, cerr
		} else if class.Kind == tenantdom.MemberKindExternal {
			return nil, ErrExternalNeedsInvitation
		}
		// A person adding an existing account needs more than "not
		// external": an organization without a verified domain treats every
		// work address as its own, so it could pull anyone whose account id
		// it learns into the organization. Only an address on a domain this
		// organization verified is added without the person's consent.
		// Provisioning by the organization's IdP (no inviter) checks the
		// domain itself.
		if !inviterUserID.IsZero() && s.classifier != nil {
			held, herr := s.classifier.HeldBy(ctx, parsedTenantID, users[0].Email())
			if herr != nil {
				return nil, herr
			}
			if !held {
				return nil, ErrDirectAddNeedsVerifiedDomain
			}
		}
	}

	// A zero inviter (e.g. system/SCIM-driven provisioning, where there is no
	// human inviter) must map to NULL invited_by — writing the all-zeros UUID
	// would violate the invited_by → users(id) foreign key.
	var invitedBy *shared.ID
	if !inviterUserID.IsZero() {
		invitedBy = &inviterUserID
	}

	membership, err := tenantdom.NewMembership(input.UserID, parsedTenantID, role, invitedBy)
	if err != nil {
		return nil, err
	}

	if err := create(ctx, membership); err != nil {
		return nil, fmt.Errorf("failed to add member: %w", err)
	}

	s.logger.Info("member added", "tenant_id", tenantID, "user_id", input.UserID.String(), "role", role)

	// Log audit event
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionMemberAdded, audit.ResourceTypeMembership, membership.ID().String()).
		WithMessage(fmt.Sprintf("Member added with role %s", role)).
		WithMetadata("role", input.Role).
		WithMetadata("user_id", input.UserID.String())
	s.logAudit(ctx, actx, event)

	return membership, nil
}

// UpdateMemberRoleInput represents the input for updating a member's role.
type UpdateMemberRoleInput struct {
	Role string `json:"role" validate:"required,oneof=admin member viewer"`
}

// UpdateMemberRole updates a member's role.
// getOwnMembership fetches a membership and verifies it belongs to the caller's
// tenant (callerTenantID, from the audit context / route tenant). Returns
// ErrNotFound on any mismatch or missing tenant — anti-enumeration — so a
// tenant admin cannot manage members of another tenant via a guessed
// membership ID.
func (s *TenantService) getOwnMembership(ctx context.Context, membershipID, callerTenantID string) (*tenantdom.Membership, error) {
	parsedID, err := shared.IDFromString(membershipID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid membership id format", shared.ErrValidation)
	}
	tid, err := shared.IDFromString(callerTenantID)
	if err != nil || tid.IsZero() {
		return nil, shared.ErrNotFound
	}
	return s.repo.GetMembershipByID(ctx, tid, parsedID)
}

func (s *TenantService) UpdateMemberRole(ctx context.Context, membershipID string, input UpdateMemberRoleInput, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	membership, err := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if err != nil {
		return nil, err
	}

	// Prevent changing owner role. The one exception is an owner role row held
	// without the owner membership (planted before system roles were limited to
	// the membership routes): the real owner may remove it (drift).
	drift := false
	if membership.IsOwner() {
		var derr error
		drift, derr = s.authorizeOwnerDriftRemoval(ctx, membership, actx)
		if derr != nil {
			return nil, derr
		}
		if !drift {
			return nil, fmt.Errorf("%w: the owner's role changes only by a transfer: use Transfer ownership on the Members page", shared.ErrValidation)
		}
	}
	if err := s.authorizeMemberChange(ctx, membership, actx); err != nil {
		return nil, err
	}

	oldRole := membership.Role().String()
	role, ok := tenantdom.ParseRole(input.Role)
	if !ok {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}

	// Someone outside the organization may hold any role but owner, unless an
	// active trust with their home organization caps them (RFC-095 §4.2).
	if membership.IsExternal() {
		if role == tenantdom.RoleOwner {
			return nil, accesscontrol.ErrExternalRoleCeiling
		}
		if membership.HomeTenantID() != nil && s.trustPolicy != nil {
			ceiling, cerr := s.trustPolicy.MaxRoleFor(ctx, membership.TenantID(), *membership.HomeTenantID())
			if cerr != nil {
				return nil, cerr
			}
			if ceiling != "" && role == tenantdom.RoleAdmin {
				return nil, accesscontrol.ErrExternalRoleCeiling
			}
			if ceiling == orgtrust.MaxRoleViewer && role != tenantdom.RoleViewer {
				return nil, accesscontrol.ErrExternalViewerCeiling
			}
		}
		if role == tenantdom.RoleAdmin {
			if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
				return nil, err
			}
		}
	}

	// Prevent promoting to owner
	if role == tenantdom.RoleOwner {
		return nil, fmt.Errorf("%w: nobody is made the owner by a role change: the owner uses Transfer ownership on the Members page", shared.ErrValidation)
	}
	if role == tenantdom.RoleAdmin && membership.Role() != tenantdom.RoleAdmin {
		if err := s.authorizeAdminPromotion(ctx, membership.TenantID(), actx); err != nil {
			return nil, err
		}
	}

	if err := membership.UpdateRole(role); err != nil {
		return nil, err
	}

	// UpdateMembership swaps the member's system role rows (the drifted owner
	// row included) and the label in one transaction.
	if err := s.repo.UpdateMembership(ctx, membership); err != nil {
		return nil, fmt.Errorf("failed to update member role: %w", err)
	}
	if drift {
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionOwnerRoleDriftRemoved, audit.ResourceTypeMembership, membershipID).
			WithChanges(audit.NewChanges().Set("role", oldRole, input.Role)).
			WithSeverity(audit.SeverityCritical).
			WithMetadata("user_id", membership.UserID().String()).
			WithMessage(fmt.Sprintf("Owner role without the owner membership removed; member is now %s", input.Role)))
	}

	// The change swaps the user's system role in user_roles: drop the cached
	// membership and permissions and bump the permission version, so a token
	// minted before the change is stale on its next request (its admin flag
	// and role are then re-read from the database, audit H2).
	s.invalidateMembershipCache(ctx, membership.TenantID().String(), membership.UserID().String())
	s.bumpPermissionVersion(ctx, membership.TenantID().String(), membership.UserID().String())

	s.logger.Info("member role updated", "membership_id", logger.SanitizeValue(membershipID), "new_role", logger.SanitizeValue(string(role)))
	if tenantdom.PrivilegeRank(role) > tenantdom.PrivilegeRank(tenantdom.Role(oldRole)) {
		s.notifyPrivilegeIncrease(ctx, membership.TenantID(), membership.UserID(),
			fmt.Sprintf("membership role raised from %s to %s", oldRole, role))
	}

	// Log audit event
	actx.TenantID = membership.TenantID().String()
	changes := audit.NewChanges().Set("role", oldRole, input.Role)
	event := auditapp.NewSuccessEvent(audit.ActionMemberRoleChanged, audit.ResourceTypeMembership, membershipID).
		WithChanges(changes).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Member role changed from %s to %s", oldRole, input.Role))
	s.logAudit(ctx, actx, event)

	return membership, nil
}

// SuspendMember suspends a member's access to a tenant. The membership
// row stays in the database (preserving audit trail, ownership
// attribution, and compliance evidence), but the user's access is
// immediately revoked: sessions are invalidated, permission cache
// cleared, and JWT exchange should check membership status.
func (s *TenantService) SuspendMember(ctx context.Context, membershipID string, actx auditapp.AuditContext) error {
	membership, err := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if err != nil {
		return err
	}
	if err := s.authorizeMemberChange(ctx, membership, actx); err != nil {
		return err
	}

	// A system-initiated suspension (e.g. SCIM deprovisioning) has no human
	// actor. Treat an empty ActorID as system → a zero suspended_by, which the
	// repo persists as NULL (writing the all-zeros UUID would violate the
	// suspended_by → users(id) FK). A non-empty but malformed ActorID is still
	// rejected.
	var actorID shared.ID
	if actx.ActorID != "" {
		parsed, perr := shared.IDFromString(actx.ActorID)
		if perr != nil {
			return fmt.Errorf("%w: invalid acting user id", shared.ErrValidation)
		}
		actorID = parsed
	}

	if err := membership.Suspend(actorID); err != nil {
		return err
	}

	// With the lifecycle store, one transaction also suspends the member's
	// API keys, pauses the schedules they own and drops their materialized
	// scope (groups, grants and ownership stay frozen for a re-enable).
	var disabled *tenantdom.DisableResult
	if s.lifecycle != nil {
		disabled, err = s.lifecycle.Disable(ctx, membership)
	} else {
		err = s.repo.UpdateMembershipStatus(ctx, membership)
	}
	if err != nil {
		return err
	}

	tenantID := membership.TenantID().String()
	userID := membership.UserID().String()

	// Immediately revoke access — four independent kill switches:
	//
	//   1. Permission cache invalidation: forces a fresh permission
	//      lookup on the next tenant-scoped request, which now sees
	//      the suspended status and 403s.
	//   2. Membership cache invalidation: drops the cached membership
	//      so the RequireMembership middleware re-reads the suspended
	//      status from the DB on the next request instead of waiting
	//      for the cache TTL to expire.
	//   3. Session revocation scoped to this tenant (endTenantSessions):
	//      the sessions this tenant's IdP signed in end; sessions that
	//      also serve the person's other organizations stay (JWT-claim
	//      routes re-check the membership per request). A person with no
	//      other organization loses every session.
	//   4. Pending invitation cleanup: removes any unaccepted invites
	//      so the user can't rejoin via a stale link.
	s.invalidateUserPermissions(ctx, tenantID, userID)
	s.invalidateMembershipCache(ctx, tenantID, userID)
	s.endTenantSessions(ctx, tenantID, userID)
	// The home organization controls the person: their access to other
	// organizations as an external member ends with it (RFC-058).
	if !membership.IsExternal() {
		s.homeAccessEnded(ctx, membership.TenantID(), membership.UserID())
	}

	if deleted, derr := s.repo.DeletePendingInvitationsByUserID(ctx, membership.TenantID(), membership.UserID()); derr != nil {
		s.logger.Warn("failed to clean up invitations on suspend", "error", derr)
	} else if deleted > 0 {
		s.logger.Info("invalidated invitations on suspend", "deleted", deleted)
	}

	// Best-effort: notify the user via email so they know their
	// access was paused (and aren't surprised by a 403 next login).
	s.notifyMemberStatusChange(ctx, true, tenantID, userID, actx.ActorID)

	s.logger.Info("member suspended", "membership_id", membershipID, "user_id", userID)

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionMemberSuspended, audit.ResourceTypeMembership, membershipID).
		WithSeverity(audit.SeverityHigh).
		WithMessage("Member suspended").
		WithMetadata("user_id", userID)
	if disabled != nil {
		event = event.
			WithMetadata("suspended_keys", disabled.SuspendedKeys).
			WithMetadata("paused_schedules", disabled.Paused())
	}
	s.logAudit(ctx, actx, event)

	// Owned schedules never run as a disabled person: they were paused, and
	// the administrators are told so they can hand them over or resume them.
	if disabled.Paused() > 0 {
		s.notifyAdmins(ctx, membership.TenantID(),
			"A disabled member's schedules were paused",
			fmt.Sprintf("A member was disabled. Their %s were paused and will not run until an administrator resumes them or offboards the member and reassigns them.",
				pausedSummary(disabled)),
			notificationdom.SeverityMedium)
	}

	return nil
}

// ReactivateMember restores a suspended member's access.
func (s *TenantService) ReactivateMember(ctx context.Context, membershipID string, actx auditapp.AuditContext) error {
	membership, err := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if err != nil {
		return err
	}
	if err := s.authorizeMemberChange(ctx, membership, actx); err != nil {
		return err
	}
	// An external member whose access ended comes back only with a new end
	// date (ExtendMemberAccess), or the expiry would suspend them again.
	if membership.IsExpired(time.Now().UTC()) || membership.SuspendedReason() == tenantdom.SuspendedReasonExpired {
		return fmt.Errorf("%w: this member's access has ended; set a new end date to re-enable them", shared.ErrValidation)
	}
	// Re-enabling a newcomer SSO held for approval is the approval (RFC-058).
	approval := membership.AwaitsApproval()

	if err := membership.Reactivate(); err != nil {
		return err
	}

	// With the lifecycle store, the keys a disable suspended come back and
	// the scope is recomputed from the frozen groups and grants.
	if s.lifecycle != nil {
		err = s.lifecycle.Reenable(ctx, membership)
	} else {
		err = s.repo.UpdateMembershipStatus(ctx, membership)
	}
	if err != nil {
		return err
	}

	tenantID := membership.TenantID().String()
	userID := membership.UserID().String()

	// Invalidate the permission cache so the user's reactivated state
	// takes effect immediately. Without this the user could see stale
	// "empty permissions" (the result of the suspend invalidation) for
	// up to permCacheTTL (5 minutes). The Increment side-effect also
	// bumps the user's permission version so any in-flight JWT clients
	// know to refetch. The membership cache also has to drop its
	// suspended snapshot so the next RequireMembership check sees
	// status='active' immediately.
	s.invalidateUserPermissions(ctx, tenantID, userID)
	s.invalidateMembershipCache(ctx, tenantID, userID)
	if !membership.IsExternal() {
		s.homeAccessRestored(ctx, membership.TenantID(), membership.UserID())
	}

	// Best-effort: notify the user via email that their access is back.
	s.notifyMemberStatusChange(ctx, false, tenantID, userID, actx.ActorID)

	s.logger.Info("member reactivated", "membership_id", membershipID, "user_id", userID)

	actx.TenantID = tenantID
	msg := "Member reactivated"
	if approval {
		msg = "Access approved for a member SSO admitted"
		s.notifyPrivilegeIncrease(ctx, membership.TenantID(), membership.UserID(),
			"access approved after their first sign-in through SSO")
	}
	event := auditapp.NewSuccessEvent(audit.ActionMemberReactivated, audit.ResourceTypeMembership, membershipID).
		WithSeverity(audit.SeverityHigh).
		WithMessage(msg).
		WithMetadata("user_id", userID).
		WithMetadata("approval", approval)
	s.logAudit(ctx, actx, event)

	return nil
}

// invalidateUserPermissions clears the user's cached permissions and bumps
// their permission version. Called when a user is removed, suspended or
// demoted to revoke access at once. The version is bumped, never deleted:
// cached permission sets are keyed by version, and dropping the key would
// make the user read the "no version" entry again, which may still hold a
// set cached before their first version. Bumping also closes their live
// sockets (change listener).
func (s *TenantService) invalidateUserPermissions(ctx context.Context, tenantID, userID string) {
	s.bumpPermissionVersion(ctx, tenantID, userID)

	s.logger.Debug("user permissions invalidated on member removal",
		"tenant_id", tenantID,
		"user_id", userID,
	)
}

// ListMembers lists all members of a tenant.
func (s *TenantService) ListMembers(ctx context.Context, tenantID string) ([]*tenantdom.Membership, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.ListMembersByTenant(ctx, parsedID)
}

// ListMembersWithUserInfo lists all members of a tenant with user details.
func (s *TenantService) ListMembersWithUserInfo(ctx context.Context, tenantID string) ([]*tenantdom.MemberWithUser, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.ListMembersWithUserInfo(ctx, parsedID)
}

// SearchMembersWithUserInfo searches members with filtering and pagination.
func (s *TenantService) SearchMembersWithUserInfo(ctx context.Context, tenantID string, filters tenantdom.MemberSearchFilters) (*tenantdom.MemberSearchResult, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// Validate offset - must be non-negative and bounded
	if filters.Offset < 0 {
		filters.Offset = 0
	}
	// Cap maximum offset to prevent scanning large result sets
	// 10000 is reasonable for most UI pagination scenarios
	const maxOffset = 10000
	if filters.Offset > maxOffset {
		return nil, fmt.Errorf("%w: offset exceeds maximum of %d", shared.ErrValidation, maxOffset)
	}

	// Apply default limit if not specified
	if filters.Limit <= 0 {
		filters.Limit = 10 // Default limit
	}
	// Cap maximum limit
	if filters.Limit > 100 {
		filters.Limit = 100
	}

	// Validate search string length - return error instead of silent truncation
	const maxSearchLength = 100
	if len(filters.Search) > maxSearchLength {
		return nil, fmt.Errorf("%w: search string exceeds maximum of %d characters", shared.ErrValidation, maxSearchLength)
	}

	// The same statuses the members handler accepts and the repository
	// filters on: empty (active and suspended), one status, or all.
	switch filters.Status {
	case "", string(tenantdom.MemberStatusActive), string(tenantdom.MemberStatusSuspended),
		string(tenantdom.MemberStatusOffboarded), tenantdom.MemberFilterAll:
	default:
		return nil, fmt.Errorf("%w: unknown member status filter", shared.ErrValidation)
	}
	switch filters.Role {
	case "", tenantdom.RoleOwner.String(), tenantdom.RoleAdmin.String(), tenantdom.RoleMember.String(), tenantdom.RoleViewer.String():
	default:
		return nil, fmt.Errorf("%w: unknown member role filter", shared.ErrValidation)
	}

	return s.repo.SearchMembersWithUserInfo(ctx, parsedID, filters)
}

// GetMemberStats retrieves member statistics for a tenant.
func (s *TenantService) GetMemberStats(ctx context.Context, tenantID string) (*tenantdom.MemberStats, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetMemberStats(ctx, parsedID)
}

// GetMembership retrieves a user's membership in a tenant.
// userID is the local user ID (from users table).
func (s *TenantService) GetMembership(ctx context.Context, userID shared.ID, tenantID string) (*tenantdom.Membership, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.GetMembership(ctx, userID, parsedTenantID)
}

// =============================================================================
// Invitation Operations
// =============================================================================

// CreateInvitationInput represents the input for creating an invitation.
// Note: All invited users are "member". Permissions come from RBAC roles (RoleIDs).
type CreateInvitationInput struct {
	Email   string   `json:"email" validate:"required,email,max=254"`
	Role    string   `json:"-"`                                         // Internal use only - always set to "member" by handler
	RoleIDs []string `json:"role_ids" validate:"required,min=1,max=10"` // RBAC roles to assign (required, max 10)
	// Access applies to an invitee outside the organization (RFC-058): when
	// the access ends and why. Required for someone no organization manages
	// (defaults to 90 days); ignored for an internal invitee.
	AccessExpiresAt *time.Time `json:"-"`
	AccessReason    string     `json:"-"`
	// GroupIDs: teams of the organization the invitee joins at acceptance
	// (at most 20), each one the inviter may add a member to.
	GroupIDs []string `json:"-"`
}

// CreateInvitation creates an invitation to join a tenant.
// inviterUserID is the local user ID (from users table) of the person sending the invitation.
func (s *TenantService) CreateInvitation(ctx context.Context, tenantID string, input CreateInvitationInput, inviterUserID shared.ID, actx auditapp.AuditContext) (*tenantdom.Invitation, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// Role ids must be well-formed and never the owner role.
	if err := accesscontrol.ValidateGrantableRoleIDs(input.RoleIDs); err != nil {
		return nil, err
	}
	// Only the owner may invite someone as an administrator (settings
	// decision B2). Acceptance grants the roles as the inviter, which the role
	// service would refuse too; refusing here keeps the invitation from being
	// sent at all.
	for _, raw := range input.RoleIDs {
		if raw == roledom.AdminRoleID.String() {
			if err := s.authorizeAdminPromotion(ctx, parsedID, actx); err != nil {
				return nil, err
			}
			break
		}
	}
	// ...and each must be a system role or one of this tenant's own roles. The
	// handler's anti-escalation check is skipped for administrators, so this is
	// the only place an id from another tenant is refused before it is stored.
	if s.roleService != nil {
		if err := s.roleService.ValidateRolesForTenant(ctx, parsedID.String(), input.RoleIDs); err != nil {
			return nil, err
		}
	}
	// The membership role follows the granted RBAC roles. It used to be a fixed
	// 'member', which the tenant_members -> user_roles trigger turned into the
	// member role on top of e.g. a viewer-only invitation.
	role := accesscontrol.MembershipRoleForRoleIDs(input.RoleIDs)

	// Who may be invited is the organization's policy (RFC-095 §4.1).
	if err := s.requireInvitable(ctx, parsedID, input.Email); err != nil {
		return nil, err
	}

	// Someone outside the organization may get any role but owner; a trust
	// with their home organization may cap it, and a privileged role needs
	// the inviter's step-up (RFC-095 §4.2).
	class, access, err := s.classifyInvitee(ctx, parsedID, input.Email,
		tenantdom.ExternalAccess{ExpiresAt: input.AccessExpiresAt, Reason: input.AccessReason}, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := s.requirePersonalAllowed(ctx, parsedID, class); err != nil {
		return nil, err
	}
	groupIDs, err := normalizeTeamIDs(input.GroupIDs)
	if err != nil {
		return nil, err
	}
	privileged := false
	if class.Kind == tenantdom.MemberKindExternal {
		if err := access.Validate(class, time.Now().UTC()); err != nil {
			return nil, err
		}
		if err := s.requireWithinTrustCeiling(ctx, parsedID, class, input.RoleIDs); err != nil {
			return nil, err
		}
		if privileged, err = s.privilegedRoleSet(ctx, parsedID, input.RoleIDs); err != nil {
			return nil, err
		}
		// A team carrying a role above member counts like the role itself.
		teamsAbove, terr := s.checkInvitationTeams(ctx, parsedID, inviterUserID.String(), groupIDs, true, access.ExpiresAt)
		if terr != nil {
			return nil, terr
		}
		privileged = privileged || teamsAbove
		if privileged {
			if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
				return nil, err
			}
		}
	}

	if class.Kind != tenantdom.MemberKindExternal {
		if _, err := s.checkInvitationTeams(ctx, parsedID, inviterUserID.String(), groupIDs, false, access.ExpiresAt); err != nil {
			return nil, err
		}
	}

	// Check for existing pending invitation
	existingInv, err := s.repo.GetPendingInvitationByEmail(ctx, parsedID, input.Email)
	if err == nil && existingInv != nil {
		return nil, fmt.Errorf("%w: pending invitation already exists for this email", shared.ErrValidation)
	}
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing invitation: %w", err)
	}

	// Check if user is already a member of this tenant. A suspended
	// membership counts as "already a member" — the admin must reactivate
	// them via the Members page rather than sending a new invitation, so
	// the suspend audit trail and any compliance evidence stay intact.
	existingMember, err := s.repo.GetMemberByEmail(ctx, parsedID, input.Email)
	if err == nil && existingMember != nil && existingMember.Status != string(tenantdom.MemberStatusOffboarded) {
		if existingMember.Status == string(tenantdom.MemberStatusSuspended) {
			return nil, fmt.Errorf(
				"%w: this user has a suspended membership in this tenant — reactivate them via the Members page instead of sending a new invitation",
				shared.ErrValidation,
			)
		}
		return nil, fmt.Errorf("%w: user with this email is already a member of this team", shared.ErrValidation)
	}
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing member: %w", err)
	}

	invitation, err := tenantdom.NewInvitation(parsedID, input.Email, role, inviterUserID, input.RoleIDs)
	if err != nil {
		return nil, err
	}
	invitation.SetAccess(access)
	invitation.SetGroupIDs(groupIDs)
	if err := invitation.SetInviteeInfo(tenantdom.InviteeInfo{Kind: class.Kind, Privileged: privileged}); err != nil {
		return nil, err
	}

	// Hash-at-rest: persist only the SHA-256 hash of the token, never the raw
	// value. The raw token is what the invitee receives (email link + the
	// creator's API response); lookups hash the presented token before the
	// WHERE token = $1 query. Mirrors the refresh/reset-token pattern.
	rawToken := invitation.Token()
	invitation.SetToken(crypto.HashToken(rawToken))

	if err := s.repo.CreateInvitation(ctx, invitation); err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	// Restore the raw token on the in-memory entity so the email payload and
	// the creator's API response carry the usable link token (the DB row keeps
	// the hash written above).
	invitation.SetToken(rawToken)

	s.logger.Info("invitation created", "tenant_id", tenantID, "email", input.Email, "role", role, "role_ids", input.RoleIDs)

	// Log audit event
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionInvitationCreated, audit.ResourceTypeInvitation, invitation.ID().String()).
		WithResourceName(input.Email).
		WithMessage(fmt.Sprintf("Invitation sent to %s with role %s", input.Email, role)).
		WithMetadata("email", input.Email).
		WithMetadata("role", role.String()).
		WithMetadata("member_kind", string(class.Kind)).
		WithMetadata("privileged", privileged).
		WithMetadata("mfa_required", privileged).
		WithMetadata("group_ids", groupIDs)
	if privileged {
		// A privileged role for someone outside the organization.
		event = event.WithSeverity(audit.SeverityHigh)
	}
	if access.ExpiresAt != nil {
		event = event.WithMetadata("access_expires_at", access.ExpiresAt.Format(time.RFC3339))
	}
	s.logAudit(ctx, actx, event)

	// Enqueue email job if email enqueuer is configured
	if s.emailEnqueuer != nil {
		// Get inviter name
		inviterName := "A team member"
		if s.userInfoProvider != nil {
			if name, err := s.userInfoProvider.GetUserNameByID(ctx, inviterUserID); err == nil && name != "" {
				inviterName = name
			}
		}

		// Get tenant name
		teamName := "the team"
		if t, err := s.repo.GetByID(ctx, parsedID); err == nil && t != nil {
			teamName = t.Name()
		}

		// Enqueue the email job
		payload := TeamInvitationJobPayload{
			RecipientEmail: input.Email,
			InviterName:    inviterName,
			TeamName:       teamName,
			Token:          invitation.Token(),
			ExpiresIn:      7 * 24 * time.Hour, // 7 days
			InvitationID:   invitation.ID().String(),
			TenantID:       tenantID,
		}
		if err := s.emailEnqueuer.EnqueueTeamInvitation(ctx, payload); err != nil {
			// Log error but don't fail the invitation creation
			s.logger.Error("failed to enqueue invitation email",
				"email", input.Email,
				"invitation_id", invitation.ID().String(),
				"error", err,
			)
		} else {
			s.logger.Info("invitation email queued",
				"email", logger.SanitizeValue(input.Email),
				"invitation_id", invitation.ID().String(),
			)
		}
	}

	return invitation, nil
}

// requireAllowedEmailDomain enforces the organization's Security.AllowedDomains
// (empty = no restriction) for an email about to join it.
func (s *TenantService) requireAllowedEmailDomain(ctx context.Context, tenantID shared.ID, email string) error {
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if !t.TypedSettings().Security.EmailDomainAllowed(email) {
		return ErrEmailDomainNotAllowed
	}
	return nil
}

// applyInvitationRoles makes the invitation's RBAC roles the new member's
// complete role set, replacing the system role the tenant_members trigger
// copied from the membership role. Best-effort: on failure the membership
// keeps that trigger role, which MembershipRoleForRoleIDs keeps no broader
// than the invitation, and an administrator can fix roles from Settings.
func (s *TenantService) applyInvitationRoles(ctx context.Context, invitation *tenantdom.Invitation, userID shared.ID) {
	if s.roleService == nil || len(invitation.RoleIDs()) == 0 {
		return
	}
	invitedByStr := invitation.InvitedBy().String()
	invActx := auditapp.AuditContext{ActorID: invitedByStr, TenantID: invitation.TenantID().String()}
	if err := s.roleService.GrantExactRoles(ctx, invitation.TenantID().String(), userID.String(),
		invitation.RoleIDs(), invitedByStr, invActx); err != nil {
		s.logger.Error("failed to apply invitation roles on accept",
			"invitation_id", invitation.ID().String(),
			"user_id", userID.String(),
			"error", err)
	}
}

// GetInvitationByToken retrieves an invitation by its token.
// Tokens are stored hashed at rest, so the raw token is hashed before lookup.
func (s *TenantService) GetInvitationByToken(ctx context.Context, token string) (*tenantdom.Invitation, error) {
	return s.repo.GetInvitationByToken(ctx, crypto.HashToken(token))
}

// AcceptInvitation accepts an invitation and creates a membership.
// userID is the local user ID (from users table) of the person accepting the invitation.
// userEmail is used to verify the invitation is intended for this user.
func (s *TenantService) AcceptInvitation(ctx context.Context, token string, userID shared.ID, userEmail string, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	// Tokens are stored hashed at rest; hash the presented token before lookup.
	invitation, err := s.repo.GetInvitationByToken(ctx, crypto.HashToken(token))
	if err != nil {
		return nil, err
	}
	return s.acceptInvitation(ctx, invitation, userID, userEmail, actx)
}

// AcceptInvitationByID accepts an invitation the onboarding offered to a
// signed-in account whose email address is verified (docs/rfcs/RFC-104). The
// verified address stands in for the emailed token: it proves the same
// mailbox. The invitation is looked up in its organization only; every check
// of AcceptInvitation applies.
func (s *TenantService) AcceptInvitationByID(ctx context.Context, tenantID, invitationID, userID shared.ID, userEmail string, emailVerified bool, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	if !emailVerified {
		return nil, fmt.Errorf("%w: verify your email address first", shared.ErrValidation)
	}
	invitation, err := s.repo.GetInvitationByID(ctx, tenantID, invitationID)
	if err != nil {
		return nil, err
	}
	return s.acceptInvitation(ctx, invitation, userID, userEmail, actx)
}

// acceptInvitation is the acceptance shared by the token and the onboarding
// paths.
func (s *TenantService) acceptInvitation(ctx context.Context, invitation *tenantdom.Invitation, userID shared.ID, userEmail string, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	// Verify the invitation is for this user's email (case-insensitive)
	if !strings.EqualFold(invitation.Email(), userEmail) {
		return nil, fmt.Errorf("%w: this invitation was sent to a different email address", shared.ErrValidation)
	}

	if !invitation.IsPending() {
		if invitation.IsExpired() {
			return nil, fmt.Errorf("%w: invitation has expired", shared.ErrValidation)
		}
		if invitation.IsAccepted() {
			return nil, fmt.Errorf("%w: invitation has already been accepted", shared.ErrValidation)
		}
	}

	// Check if user is already a member. If they have a suspended
	// membership the admin must reactivate it via the Members page —
	// accepting an invitation cannot bypass an active suspension because
	// that would silently erase the audit trail.
	existingMembership, err := s.repo.GetMembership(ctx, userID, invitation.TenantID())
	if err == nil && !existingMembership.IsOffboarded() {
		if existingMembership.IsSuspended() {
			return nil, fmt.Errorf(
				"%w: your access to this team is suspended — please contact an administrator to be reactivated",
				shared.ErrValidation,
			)
		}
		return nil, fmt.Errorf("%w: you are already a member of this team", shared.ErrValidation)
	}
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	// The organization may have restricted who may be invited after the
	// invitation was sent.
	if err := s.requireInvitable(ctx, invitation.TenantID(), invitation.Email()); err != nil {
		return nil, err
	}
	// An invitation is a deferred grant: the inviter must still be able to
	// grant what it offers (RFC-095 §3.2).
	if err := s.authorizeInvitationGrant(ctx, invitation); err != nil {
		return nil, err
	}

	// Accept the invitation
	if err := invitation.Accept(); err != nil {
		return nil, err
	}

	// Create membership (role derived from the invitation's RBAC roles)
	invitedBy := invitation.InvitedBy()
	membership, err := tenantdom.NewMembership(userID, invitation.TenantID(), accesscontrol.InvitationMembershipRole(invitation), &invitedBy)
	if err != nil {
		return nil, err
	}
	if err := s.ClassifyAcceptedInvitation(ctx, invitation, membership, time.Now().UTC()); err != nil {
		return nil, err
	}
	// The teams are checked for the inviter with the classification just
	// made: someone who became an outsider since the invitation was sent
	// never gets full data access through a team.
	if err := s.reauthorizeInvitationTeams(ctx, invitation, membership.IsExternal()); err != nil {
		return nil, err
	}

	// Use transaction to ensure atomicity - both invitation update and membership creation succeed or fail together
	if err := s.repo.AcceptInvitationTx(ctx, invitation, membership); err != nil {
		return nil, fmt.Errorf("failed to accept invitation: %w", err)
	}

	s.applyInvitationRoles(ctx, invitation, userID)
	if teams := invitation.GroupIDs(); len(teams) > 0 && s.invitationTeams != nil {
		s.invitationTeams.ApplyInvitationTeams(ctx, invitation.TenantID().String(), userID, teams)
	}

	// Never log the token, not even a prefix: it is a bearer credential.
	s.logger.Info("invitation accepted", "invitation_id", invitation.ID().String(), "user_id", userID.String(),
		"role_count", len(invitation.RoleIDs()))

	// Log audit event
	actx.TenantID = invitation.TenantID().String()
	event := auditapp.NewSuccessEvent(audit.ActionInvitationAccepted, audit.ResourceTypeInvitation, invitation.ID().String()).
		WithResourceName(userEmail).
		WithMessage(fmt.Sprintf("Invitation accepted by %s", userEmail)).
		WithMetadata("role", invitation.Role().String()).
		WithMetadata("role_ids_count", len(invitation.RoleIDs())).
		WithMetadata("group_ids", invitation.GroupIDs())
	s.logAudit(ctx, actx, event)

	return membership, nil
}

// ListPendingInvitations lists pending invitations for a tenant.
func (s *TenantService) ListPendingInvitations(ctx context.Context, tenantID string) ([]*tenantdom.Invitation, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.ListPendingInvitationsByTenant(ctx, parsedID)
}

// DeleteInvitation cancels an invitation.
func (s *TenantService) DeleteInvitation(ctx context.Context, tenantID, invitationID string, actx auditapp.AuditContext) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(invitationID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// Tenant scoping: only the owning tenant may delete an invitation (mirrors
	// ResendInvitation). Without this any team-admin could cancel another
	// tenant's pending invitations by guessing IDs. Not-found on mismatch to
	// avoid existence disclosure.
	inv, err := s.repo.GetInvitationByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return err
	}

	if err := s.repo.DeleteInvitation(ctx, parsedTenantID, parsedID); err != nil {
		return err
	}

	s.logger.Info("invitation deleted", "id", invitationID)

	// The actor is empty when the invitee declined through the public link.
	message := fmt.Sprintf("Invitation for %s canceled", inv.Email())
	if actx.ActorID == "" {
		message = fmt.Sprintf("Invitation for %s declined", inv.Email())
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionInvitationDeleted, audit.ResourceTypeInvitation, invitationID).
		WithSeverity(audit.SeverityLow).
		WithMessage(message).
		WithMetadata("email", inv.Email()).
		WithMetadata("role_ids", inv.RoleIDs())
	s.logAudit(ctx, actx, event)
	return nil
}

// CleanupExpiredInvitations removes all expired invitations.
func (s *TenantService) CleanupExpiredInvitations(ctx context.Context) (int64, error) {
	count, err := s.repo.DeleteExpiredInvitations(ctx)
	if err != nil {
		return 0, err
	}

	if count > 0 {
		s.logger.Info("cleaned up expired invitations", "count", count)
	}
	return count, nil
}

// ResendInvitation re-enqueues the invitation email for a pending
// invitation. This lets admins recover from lost/spam-filtered invitation
// emails without having to delete + recreate.
//
// Because tokens are stored hashed at rest, the original raw token can no
// longer be recovered to re-send. Resend therefore ROTATES the token: a fresh
// raw token is generated, its hash is persisted, and the raw value is emailed.
// Any previously-issued link for this invitation stops working. Expiry and all
// other fields are left unchanged.
//
// Returns ErrNotFound if the invitation doesn't exist, and ErrValidation
// if the invitation has already been accepted or has expired.
func (s *TenantService) ResendInvitation(ctx context.Context, tenantID, invitationID string, actx auditapp.AuditContext) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	parsedInvID, err := shared.IDFromString(invitationID)
	if err != nil {
		return fmt.Errorf("%w: invalid invitation id format", shared.ErrValidation)
	}

	inv, err := s.repo.GetInvitationByID(ctx, parsedTenantID, parsedInvID)
	if err != nil {
		return err
	}

	// Tenant isolation — invitation must belong to the requesting tenant
	if inv.TenantID().String() != parsedTenantID.String() {
		return shared.ErrNotFound
	}

	if inv.IsAccepted() {
		return fmt.Errorf("%w: invitation has already been accepted", shared.ErrValidation)
	}
	if inv.IsExpired() {
		return fmt.Errorf("%w: invitation has expired — create a new one", shared.ErrValidation)
	}

	if s.emailEnqueuer == nil {
		return fmt.Errorf("%w: email service is not configured", shared.ErrValidation)
	}
	// At most one send every 10 minutes and five resends per invitation.
	if err := inv.MarkResent(time.Now()); err != nil {
		return err
	}

	// Rotate the token: only the hash is stored, so the raw token cannot be
	// recovered from the existing row. Generate a fresh one, persist its hash,
	// and email the raw value below.
	rawToken, rerr := inv.RotateToken()
	if rerr != nil {
		return fmt.Errorf("failed to rotate invitation token: %w", rerr)
	}
	inv.SetToken(crypto.HashToken(rawToken))
	if err := s.repo.UpdateInvitation(ctx, inv); err != nil {
		return fmt.Errorf("failed to persist rotated invitation token: %w", err)
	}
	inv.SetToken(rawToken) // raw token for the email payload below

	// Look up inviter name + tenant name for the email template
	inviterName := "A team member"
	if s.userInfoProvider != nil {
		if name, nerr := s.userInfoProvider.GetUserNameByID(ctx, inv.InvitedBy()); nerr == nil && name != "" {
			inviterName = name
		}
	}
	teamName := "the team"
	if t, terr := s.repo.GetByID(ctx, parsedTenantID); terr == nil && t != nil {
		teamName = t.Name()
	}

	payload := TeamInvitationJobPayload{
		RecipientEmail: inv.Email(),
		InviterName:    inviterName,
		TeamName:       teamName,
		Token:          inv.Token(),
		ExpiresIn:      time.Until(inv.ExpiresAt()), // remaining TTL, not the original 7 days
		InvitationID:   inv.ID().String(),
		TenantID:       tenantID,
	}
	if err := s.emailEnqueuer.EnqueueTeamInvitation(ctx, payload); err != nil {
		return fmt.Errorf("failed to enqueue invitation email: %w", err)
	}

	s.logger.Info("invitation email resent",
		"email", inv.Email(),
		"invitation_id", invitationID,
		"tenant_id", tenantID,
	)

	// Audit
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionInvitationResent, audit.ResourceTypeInvitation, invitationID).
		WithSeverity(audit.SeverityLow).
		WithMessage(fmt.Sprintf("Invitation email resent to %s", inv.Email())).
		WithMetadata("email", inv.Email())
	s.logAudit(ctx, actx, event)

	return nil
}

// GetUserDisplayName returns the display name for a user by their ID.
// Returns empty string if user not found or no userInfoProvider is configured.
func (s *TenantService) GetUserDisplayName(ctx context.Context, userID shared.ID) string {
	if s.userInfoProvider == nil {
		return ""
	}
	name, err := s.userInfoProvider.GetUserNameByID(ctx, userID)
	if err != nil {
		return ""
	}
	return name
}

// =============================================================================
// Settings Operations
// =============================================================================

// GetTenantSettings retrieves the typed settings for a tenant.
func (s *TenantService) GetTenantSettings(ctx context.Context, tenantID string) (*tenantdom.Settings, error) {
	t, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	settings := t.TypedSettings()
	return &settings, nil
}

// UpdateAssetIdentitySettings replaces the asset-identity (dedup) section.
// Bounds are checked by the handler.
func (s *TenantService) UpdateAssetIdentitySettings(ctx context.Context, tenantID string, ai tenantdom.AssetIdentitySettings, actx auditapp.AuditContext) (*tenantdom.Settings, error) {
	var before tenantdom.AssetIdentitySettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionAssetIdentity, func(t *tenantdom.Tenant) error {
		settings := t.TypedSettings()
		before = settings.AssetIdentity
		settings.AssetIdentity = ai
		return t.UpdateSettings(settings)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("asset identity settings updated", "tenant_id", tenantID)

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().AssetIdentity)).
		WithMessage("Asset identity settings updated").
		WithMetadata("stale_asset_days_before", before.StaleAssetDays).
		WithMetadata("stale_asset_days_after", ai.StaleAssetDays).
		WithMetadata("max_ips_per_asset_before", before.MaxIPsPerAsset).
		WithMetadata("max_ips_per_asset_after", ai.MaxIPsPerAsset)
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdateGeneralSettingsInput represents input for updating general settings.
// UpdateGeneralSettingsInput is a partial-update payload: every field is a
// pointer so that a nil field means "not provided — keep the existing value".
// This prevents a client that PATCHes only {timezone,language} from silently
// wiping industry/website to empty (the fragile full-replace it replaced).
type UpdateGeneralSettingsInput struct {
	Timezone *string `json:"timezone" validate:"omitempty"`
	Language *string `json:"language" validate:"omitempty,oneof=en vi ja ko zh"`
	Industry *string `json:"industry" validate:"omitempty,max=100"`
	// No `url` tag: a non-nil pointer to "" is not skipped by omitempty, so
	// `url` would reject an explicit empty string used to clear the field.
	// GeneralSettings.Validate enforces URL format when non-empty.
	Website *string `json:"website" validate:"omitempty,max=500"`
}

// UpdateGeneralSettings updates only the general settings.
func (s *TenantService) UpdateGeneralSettings(ctx context.Context, tenantID string, input UpdateGeneralSettingsInput, actx auditapp.AuditContext) (*tenantdom.Settings, error) {
	var before tenantdom.GeneralSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionGeneral, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().General
		// Partial merge: start from the persisted section and overlay only the
		// fields the client actually sent (non-nil). Omitted fields are preserved.
		general := t.TypedSettings().General
		if input.Timezone != nil {
			general.Timezone = *input.Timezone
		}
		if input.Language != nil {
			general.Language = *input.Language
		}
		if input.Industry != nil {
			general.Industry = *input.Industry
		}
		if input.Website != nil {
			general.Website = *input.Website
		}
		return t.UpdateGeneralSettings(general)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("general settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().General)).
		WithMessage("General settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdateSecuritySettingsInput is a partial-update payload. Scalar fields are
// pointers (nil == "not provided — keep existing"); slice fields rely on the
// nil-vs-non-nil distinction JSON decoding already gives us (absent key => nil
// slice => keep existing; explicit [] => clear). This stops a client that
// toggles a single flag from wiping the IP whitelist / allowed domains.
type UpdateSecuritySettingsInput struct {
	// SSOEnforced requires members to sign in via SSO (owner exempt). Set only
	// by the platform administrator (RFC-022); the tenant-facing handler refuses
	// it, so an organization cannot turn enforcement on or off for itself.
	SSOEnforced *bool `json:"sso_enforced"`
	MFARequired *bool `json:"mfa_required"`
	// MFARequiredForAdmins: see tenantdom.SecuritySettings.
	MFARequiredForAdmins  *bool    `json:"mfa_required_for_admins"`
	IPWhitelist           []string `json:"ip_whitelist"`
	AllowedDomains        []string `json:"allowed_domains"`
	EmailVerificationMode *string  `json:"email_verification_mode" validate:"omitempty,oneof=auto always never"`
	// RequireSensorLocalPolicyForPrivateTargets: see
	// tenantdom.SecuritySettings.
	RequireSensorLocalPolicyForPrivateTargets *bool `json:"require_sensor_local_policy_for_private_targets"`
	// AllowSensorInteractsh, AllowSensorCustomTemplates: see
	// tenantdom.SecuritySettings (research/25 D3).
	AllowSensorInteractsh      *bool `json:"allow_sensor_interactsh"`
	AllowSensorCustomTemplates *bool `json:"allow_sensor_custom_templates"`
	// ToolHTTPUserAgent, ForbidToolInsecureTLS: see tenantdom.SecuritySettings
	// (RFC-060 §4.1).
	ToolHTTPUserAgent     *string `json:"tool_http_user_agent"`
	ForbidToolInsecureTLS *bool   `json:"forbid_tool_insecure_tls"`
	// PersonalAccounts and SSOExceptions: see tenantdom.SecuritySettings
	// (RFC-058). The route already needs the owner with step-up.
	PersonalAccounts *string                   `json:"personal_accounts"`
	SSOExceptions    *[]tenantdom.SSOException `json:"sso_exceptions"`
	// Invitees and ExternalAccessEndRequired: see tenantdom.SecuritySettings
	// (RFC-095 §4).
	Invitees                  *string `json:"invitees"`
	ExternalAccessEndRequired *bool   `json:"external_access_end_required"`
	// JITRequiresApproval: see tenantdom.SecuritySettings (RFC-058).
	JITRequiresApproval *bool `json:"jit_requires_approval"`
	// RequesterIP is the client IP of the tenant user saving the settings, as
	// the API sees it (trusted-proxy aware). When set, an IP allowlist that
	// would exclude it is refused (lockout guard). Empty for the platform
	// administrator, who is not subject to organization allowlists.
	RequesterIP string `json:"-"`
}

// RequiresLocalPolicyForPrivateTargets reports whether the tenant keeps jobs
// with private targets away from sensors without an enforced local policy
// (RFC-040 §5.7). It implements command.PrivateTargetPolicy.
func (s *TenantService) RequiresLocalPolicyForPrivateTargets(ctx context.Context, tenantID shared.ID) (bool, error) {
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return t.TypedSettings().Security.RequireSensorLocalPolicyForPrivateTargets, nil
}

// SensorOptIns returns the tenant's interactsh and custom-template switches
// for sensor jobs (research/25 D3; both off unless an owner enabled them).
// It implements command.OptInPolicy and scan.OptInPolicy.
func (s *TenantService) SensorOptIns(ctx context.Context, tenantID shared.ID) (sensordom.OptIns, error) {
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return sensordom.OptIns{}, err
	}
	sec := t.TypedSettings().Security
	return sensordom.OptIns{AllowInteractsh: sec.AllowSensorInteractsh, AllowCustomTemplates: sec.AllowSensorCustomTemplates}, nil
}

// ToolHTTPPolicy returns the tenant's tool HTTP layer for sensor jobs
// (RFC-060 §4.1). It implements command.HTTPPolicySource.
func (s *TenantService) ToolHTTPPolicy(ctx context.Context, tenantID shared.ID) (sensordom.ToolHTTPPolicy, error) {
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return sensordom.ToolHTTPPolicy{}, err
	}
	sec := t.TypedSettings().Security
	p := sec.ToolHTTPPolicy()
	return sensordom.ToolHTTPPolicy{UserAgent: p.UserAgent, AllowInsecureTLS: p.AllowInsecureTLS}, nil
}

// ErrIPAllowlistExcludesRequester is returned when saving an IP allowlist that
// does not include the saving administrator's own IP.
var ErrIPAllowlistExcludesRequester = fmt.Errorf("%w: IP allowlist must include your current IP address", shared.ErrValidation)

// UpdateSecuritySettings updates only the security settings.
func (s *TenantService) UpdateSecuritySettings(ctx context.Context, tenantID string, input UpdateSecuritySettingsInput, actx auditapp.AuditContext) (*tenantdom.Settings, error) {
	var before tenantdom.SecuritySettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionSecurity, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Security
		// Partial merge: start from the persisted section and overlay only the
		// fields the client actually sent. Omitted fields are preserved.
		security := t.TypedSettings().Security
		if input.SSOEnforced != nil {
			security.SSOEnforced = *input.SSOEnforced
		}
		if input.MFARequired != nil {
			security.MFARequired = *input.MFARequired
		}
		if input.MFARequiredForAdmins != nil {
			security.MFARequiredForAdmins = *input.MFARequiredForAdmins
		}
		if input.IPWhitelist != nil {
			security.IPWhitelist = input.IPWhitelist
		}
		if input.AllowedDomains != nil {
			security.AllowedDomains = input.AllowedDomains
		}
		if input.JITRequiresApproval != nil {
			security.JITRequiresApproval = *input.JITRequiresApproval
		}
		if input.EmailVerificationMode != nil {
			security.EmailVerificationMode = tenantdom.EmailVerificationMode(*input.EmailVerificationMode)
		}
		if input.RequireSensorLocalPolicyForPrivateTargets != nil {
			security.RequireSensorLocalPolicyForPrivateTargets = *input.RequireSensorLocalPolicyForPrivateTargets
		}
		if input.AllowSensorInteractsh != nil {
			security.AllowSensorInteractsh = *input.AllowSensorInteractsh
		}
		if input.AllowSensorCustomTemplates != nil {
			security.AllowSensorCustomTemplates = *input.AllowSensorCustomTemplates
		}
		if input.ToolHTTPUserAgent != nil {
			security.ToolHTTPUserAgent = strings.TrimSpace(*input.ToolHTTPUserAgent)
		}
		if input.ForbidToolInsecureTLS != nil {
			security.ForbidToolInsecureTLS = *input.ForbidToolInsecureTLS
		}
		if input.PersonalAccounts != nil {
			security.PersonalAccounts = tenantdom.PersonalAccountsPolicy(*input.PersonalAccounts)
		}
		if input.Invitees != nil {
			security.Invitees = tenantdom.InviteesPolicy(*input.Invitees)
		}
		if input.ExternalAccessEndRequired != nil {
			security.ExternalAccessEndRequired = *input.ExternalAccessEndRequired
		}
		if input.SSOExceptions != nil {
			if err := s.validateSSOExceptions(ctx, t.ID(), *input.SSOExceptions); err != nil {
				return err
			}
			security.SSOExceptions = *input.SSOExceptions
		}

		// Can't-enable guard: refuse to turn sso_enforced ON unless the tenant has a
		// usable SSO path (an active identity provider or the opted-in env fallback).
		// Without this a tenant could enforce SSO with no way for members to sign in.
		// Only gate when this request actually asserts enforcement ON. The owner
		// break-glass at the enforcement gate is the ultimate lock-out guarantee, so
		// if the checker is unavailable we log and allow rather than hard-fail.
		if input.SSOEnforced != nil && *input.SSOEnforced {
			if s.ssoPathChecker == nil {
				s.logger.Warn("sso_enforced enabled without an SSO-path checker wired; skipping usable-path guard",
					"tenant_id", tenantID)
			} else {
				usable, perr := s.ssoPathChecker.HasUsableSSOPath(ctx, t.Slug())
				if perr != nil {
					s.logger.Warn("failed to verify usable SSO path", "tenant_id", tenantID, "error", perr)
					return fmt.Errorf("failed to verify SSO configuration: %w", perr)
				}
				if !usable {
					return fmt.Errorf("%w: cannot enforce SSO — configure an active SSO identity provider first", shared.ErrValidation)
				}
			}
		}

		// Lockout guard: an administrator may not save an IP allowlist that would
		// block their own next request. Checked only when this request changes the
		// list and comes from a tenant user (the platform administrator passes no
		// requester IP and is not subject to the allowlist).
		if input.IPWhitelist != nil && input.RequesterIP != "" && !security.IPAllowed(input.RequesterIP) {
			return fmt.Errorf("%w (%s)", ErrIPAllowlistExcludesRequester, input.RequesterIP)
		}

		return t.UpdateSecuritySettings(security)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("security settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Security)).
		WithSeverity(securityChangeSeverity(before, t.TypedSettings().Security)).
		WithMessage("Security settings updated")
	s.logAudit(ctx, actx, event)
	after := t.TypedSettings().Security
	s.auditSensorOptIn(ctx, actx, "allow_sensor_interactsh", before.AllowSensorInteractsh, after.AllowSensorInteractsh)
	s.auditSensorOptIn(ctx, actx, "allow_sensor_custom_templates", before.AllowSensorCustomTemplates, after.AllowSensorCustomTemplates)
	s.notifySecurityLoosened(ctx, tenantID, actx, before, after)

	result := t.TypedSettings()
	return &result, nil
}

// AlertSensorOptInEnabled is the alert name logged when an organization
// turns a sensor opt-in on (research/25 D9).
const AlertSensorOptInEnabled = "sensor_opt_in_enabled"

// auditSensorOptIn records a change of a sensor opt-in switch (research/25
// D9). Turning one on widens what the platform sends to sensors: it is
// audited at critical severity and alerted (a WARN line with alert=…, which
// the log scan workflow forwards). Turning one off is audited at medium.
func (s *TenantService) auditSensorOptIn(ctx context.Context, actx auditapp.AuditContext, key string, from, to bool) {
	if from == to {
		return
	}
	severity, verb := audit.SeverityMedium, "disabled"
	if to {
		severity, verb = audit.SeverityCritical, "enabled"
		s.logger.Warn("organization enabled a sensor opt-in", "alert", AlertSensorOptInEnabled,
			"tenant_id", actx.TenantID, "setting", key, "actor_id", actx.ActorID)
	}
	event := auditapp.NewSuccessEvent(audit.ActionSensorOptInChanged, audit.ResourceTypeTenant, actx.TenantID).
		WithSeverity(severity).
		WithMessage(fmt.Sprintf("Sensor opt-in %s %s", key, verb)).
		WithMetadata("setting", key).
		WithMetadata("from", from).
		WithMetadata("to", to)
	s.logAudit(ctx, actx, event)
}

// UpdateBrandingSettingsInput is a partial-update payload: pointer fields so a
// nil field means "not provided — keep existing". This stops updating just the
// primary color from wiping the logo (and vice-versa).
type UpdateBrandingSettingsInput struct {
	PrimaryColor *string `json:"primary_color" validate:"omitempty"`
	LogoDarkURL  *string `json:"logo_dark_url"`                  // url format checked in domain Validate
	LogoData     *string `json:"logo_data" validate:"omitempty"` // Base64 encoded logo (max 150KB)
}

// UpdateBrandingSettings updates only the branding settings.
func (s *TenantService) UpdateBrandingSettings(ctx context.Context, tenantID string, input UpdateBrandingSettingsInput, actx auditapp.AuditContext) (*tenantdom.Settings, error) {
	var before tenantdom.BrandingSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionBranding, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Branding
		// Partial merge: start from the persisted section and overlay only the
		// fields the client actually sent. Omitted fields are preserved.
		branding := t.TypedSettings().Branding
		if input.PrimaryColor != nil {
			branding.PrimaryColor = *input.PrimaryColor
		}
		if input.LogoDarkURL != nil {
			branding.LogoDarkURL = *input.LogoDarkURL
		}
		if input.LogoData != nil {
			branding.LogoData = *input.LogoData
		}

		return t.UpdateBrandingSettings(branding)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("branding settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Branding)).
		WithMessage("Branding settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// BranchTypeRuleInput represents a single branch type mapping rule.
type BranchTypeRuleInput struct {
	Pattern    string `json:"pattern" validate:"required,max=100"`
	MatchType  string `json:"match_type" validate:"required,oneof=exact prefix"`
	BranchType string `json:"branch_type" validate:"required,oneof=main develop feature release hotfix"`
}

// UpdatePentestSettingsInput represents input for updating pentest settings.
type UpdatePentestSettingsInput struct {
	CampaignTypes []tenantdom.ConfigOption `json:"campaign_types"`
	Methodologies []tenantdom.ConfigOption `json:"methodologies"`
	// RequireAuthorizationBeforeStart: nil = unchanged.
	RequireAuthorizationBeforeStart *bool `json:"require_authorization_before_start"`
}

// UpdatePentestSettings updates only the pentest settings.
func (s *TenantService) UpdatePentestSettings(ctx context.Context, tenantID string, input UpdatePentestSettingsInput, actx auditapp.AuditContext) (*tenantdom.Settings, error) {
	var before tenantdom.PentestSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionPentest, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Pentest
		// Absent (nil) = unchanged; an empty list = cleared on purpose.
		current := before
		ps := tenantdom.PentestSettings{
			CampaignTypes: current.CampaignTypes,
			Methodologies: current.Methodologies,

			RequireAuthorizationBeforeStart: current.RequireAuthorizationBeforeStart,
		}
		if input.RequireAuthorizationBeforeStart != nil {
			ps.RequireAuthorizationBeforeStart = *input.RequireAuthorizationBeforeStart
		}
		if input.CampaignTypes != nil {
			ps.CampaignTypes = input.CampaignTypes
		}
		if input.Methodologies != nil {
			ps.Methodologies = input.Methodologies
		}
		return t.UpdatePentestSettings(ps)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("pentest settings updated", "tenant_id", tenantID)

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Pentest)).
		WithMessage("Pentest settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdateFindingCorrelationSettingsInput: nil = unchanged.
type UpdateFindingCorrelationSettingsInput struct {
	AutoDisabled        *bool
	SuggestionsDisabled *bool
}

// UpdateFindingCorrelationSettings changes the correlation switches.
func (s *TenantService) UpdateFindingCorrelationSettings(ctx context.Context, tenantID string, input UpdateFindingCorrelationSettingsInput, actx auditapp.AuditContext) (*tenantdom.FindingCorrelationSettings, error) {
	var before tenantdom.FindingCorrelationSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionFindingCorrelation, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().FindingCorrelation
		fc := before
		if input.AutoDisabled != nil {
			fc.AutoDisabled = *input.AutoDisabled
		}
		if input.SuggestionsDisabled != nil {
			fc.SuggestionsDisabled = *input.SuggestionsDisabled
		}
		return t.UpdateFindingCorrelationSettings(fc)
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	after := t.TypedSettings().FindingCorrelation
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, after)).
		WithMessage("Finding correlation settings updated"))
	return &after, nil
}

// GetFindingCorrelationSettings returns the correlation switches.
func (s *TenantService) GetFindingCorrelationSettings(ctx context.Context, tenantID string) (*tenantdom.FindingCorrelationSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	fc := t.TypedSettings().FindingCorrelation
	return &fc, nil
}

// GetPentestSettings returns the current pentest settings for a tenant.
// Returns system defaults if the tenant has not customized pentest settings.
func (s *TenantService) GetPentestSettings(ctx context.Context, tenantID string) (*tenantdom.PentestSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	settings := t.TypedSettings()
	ps := settings.Pentest

	// Fall back to system defaults if tenant has not customized
	defaults := tenantdom.DefaultSettings().Pentest
	if len(ps.CampaignTypes) == 0 {
		ps.CampaignTypes = defaults.CampaignTypes
	}
	if len(ps.Methodologies) == 0 {
		ps.Methodologies = defaults.Methodologies
	}

	return &ps, nil
}

// UpdateRiskScoringSettings updates only the risk scoring settings.
func (s *TenantService) UpdateRiskScoringSettings(ctx context.Context, tenantID string, rs tenantdom.RiskScoringSettings, actx auditapp.AuditContext) (*tenantdom.Settings, error) {
	var before tenantdom.RiskScoringSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionRiskScoring, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().RiskScoring
		return t.UpdateRiskScoringSettings(rs)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("risk scoring settings updated", "tenant_id", tenantID, "preset", rs.Preset)

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantRiskScoringUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().RiskScoring)).
		WithMessage("Risk scoring settings updated").
		WithMetadata("preset", rs.Preset)
	// The scoring version the change created (scoring_changes, written by
	// the settings trigger in the same transaction as the save).
	if s.scoringVersions != nil {
		if v, verr := s.scoringVersions.CurrentVersion(ctx, t.ID(), scoring.KindAssetRisk); verr == nil {
			event = event.WithMetadata("scoring_version", v)
		}
	}
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// SetScoringVersions wires the scoring version source recorded on risk
// scoring settings audit entries.
func (s *TenantService) SetScoringVersions(v scoring.VersionRepository) {
	s.scoringVersions = v
}

// UpdateAssetLifecycleSettings updates only the asset-lifecycle
// settings. The first-time-enable rule ("must run dry-run first")
// lives in the domain validator; this service layer is where we
// stamp DryRunCompletedAt after a successful preview run.
//
// Accepts the settings as-submitted and lets
// Tenant.UpdateAssetLifecycleSettings apply the validator before
// persisting. Emits a full before/after audit entry so operators
// have a paper trail when lifecycle config changes.
func (s *TenantService) UpdateAssetLifecycleSettings(
	ctx context.Context,
	tenantID string,
	al tenantdom.AssetLifecycleSettings,
	actx auditapp.AuditContext,
) (*tenantdom.Settings, error) {
	var before tenantdom.AssetLifecycleSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionAssetLifecycle, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().AssetLifecycle

		// SECURITY: DryRunCompletedAt is server-side only. The dry-run
		// endpoint (StampAssetLifecycleDryRunCompleted) is the sole writer.
		// Overriding here prevents a client from bypassing the
		// "must run dry-run before enabling" gate by submitting a
		// fabricated timestamp in the PUT body.
		al.DryRunCompletedAt = before.DryRunCompletedAt

		return t.UpdateAssetLifecycleSettings(al)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("asset lifecycle settings updated",
		"tenant_id", tenantID,
		"enabled", al.Enabled,
		"stale_threshold_days", al.EffectiveStaleThresholdDays(),
	)

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantAssetLifecycleUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().AssetLifecycle)).
		WithMessage("Asset lifecycle settings updated").
		WithMetadata("enabled_before", before.Enabled).
		WithMetadata("enabled_after", al.Enabled).
		WithMetadata("stale_threshold_days_before", before.StaleThresholdDays).
		WithMetadata("stale_threshold_days_after", al.StaleThresholdDays).
		WithMetadata("grace_period_days_before", before.GracePeriodDays).
		WithMetadata("grace_period_days_after", al.GracePeriodDays).
		WithMetadata("excluded_source_types_before", before.ExcludedSourceTypes).
		WithMetadata("excluded_source_types_after", al.ExcludedSourceTypes)
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// GetRetestSettings returns the tenant's auto-retest settings (RFC-039). The
// zero value means auto-retest is off with default bounds.
func (s *TenantService) GetRetestSettings(ctx context.Context, tenantID string) (*tenantdom.RetestSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	rs := t.TypedSettings().Retest
	return &rs, nil
}

// UpdateRetestSettings replaces the tenant's auto-retest settings and audits the
// before/after values.
func (s *TenantService) UpdateRetestSettings(
	ctx context.Context,
	tenantID string,
	rs tenantdom.RetestSettings,
	actx auditapp.AuditContext,
) (*tenantdom.RetestSettings, error) {
	var before tenantdom.RetestSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionRetest, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Retest
		return t.UpdateRetestSettings(rs)
	})
	if err != nil {
		return nil, err
	}

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantRetestUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Retest)).
		WithMessage("Auto-retest settings updated").
		WithMetadata("auto_enabled_before", before.AutoEnabled).
		WithMetadata("auto_enabled_after", rs.AutoEnabled).
		WithMetadata("interval_hours_before", before.IntervalHours).
		WithMetadata("interval_hours_after", rs.IntervalHours).
		WithMetadata("daily_cap_before", before.DailyCap).
		WithMetadata("daily_cap_after", rs.DailyCap).
		WithMetadata("auto_resolve_before", before.AutoResolve).
		WithMetadata("auto_resolve_after", rs.AutoResolve)
	s.logAudit(ctx, actx, event)

	out := t.TypedSettings().Retest
	return &out, nil
}

// GetVulnMatchingSettings returns the organization's vulnerability matching
// policy (RFC-066 §9).
func (s *TenantService) GetVulnMatchingSettings(ctx context.Context, tenantID string) (*tenantdom.VulnMatchingSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	vm := t.TypedSettings().VulnMatching
	return &vm, nil
}

// UpdateVulnMatchingSettings replaces the organization's vulnerability
// matching policy and audits the before/after values.
func (s *TenantService) UpdateVulnMatchingSettings(
	ctx context.Context,
	tenantID string,
	vm tenantdom.VulnMatchingSettings,
	actx auditapp.AuditContext,
) (*tenantdom.VulnMatchingSettings, error) {
	var before tenantdom.VulnMatchingSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionVulnMatching, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().VulnMatching
		return t.UpdateVulnMatchingSettings(vm)
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantVulnMatchingUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().VulnMatching)).
		WithMessage("Vulnerability matching settings updated").
		WithMetadata("enabled_before", before.Enabled).
		WithMetadata("enabled_after", vm.Enabled)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().VulnMatching
	return &out, nil
}

// GetLicensePolicySettings returns the organization's license policy, with
// its defaults filled.
func (s *TenantService) GetLicensePolicySettings(ctx context.Context, tenantID string) (*licensepolicy.Policy, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	p := t.TypedSettings().LicensePolicy
	if err := p.Normalize(); err != nil {
		return nil, fmt.Errorf("%w: %s", tenantdom.ErrSettingsSectionCorrupt, err.Error())
	}
	return &p, nil
}

// UpdateLicensePolicySettings replaces the organization's license policy
// and audits the before/after values. The caller re-evaluates the links.
func (s *TenantService) UpdateLicensePolicySettings(
	ctx context.Context,
	tenantID string,
	p licensepolicy.Policy,
	actx auditapp.AuditContext,
) (*licensepolicy.Policy, error) {
	var before licensepolicy.Policy
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionLicensePolicy, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().LicensePolicy
		return t.UpdateLicensePolicySettings(p)
	})
	if err != nil {
		return nil, err
	}
	after := t.TypedSettings().LicensePolicy
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantLicensePolicyUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, after)).
		WithMessage("License policy updated").
		WithMetadata("enabled_before", before.Enabled).
		WithMetadata("enabled_after", after.Enabled).
		WithMetadata("rules", len(after.Rules))
	s.logAudit(ctx, actx, event)
	return &after, nil
}

// GetCycleSettings returns the organization's CTEM cycle policy. The zero
// value (coverage SLO advisory) is the default.
func (s *TenantService) GetCycleSettings(ctx context.Context, tenantID string) (*tenantdom.CycleSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	cs := t.TypedSettings().Cycles
	return &cs, nil
}

// UpdateCycleSettings replaces the organization's CTEM cycle policy and audits
// the before/after values.
func (s *TenantService) UpdateCycleSettings(
	ctx context.Context,
	tenantID string,
	cs tenantdom.CycleSettings,
	actx auditapp.AuditContext,
) (*tenantdom.CycleSettings, error) {
	var before tenantdom.CycleSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionCycles, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Cycles
		return t.UpdateCycleSettings(cs)
	})
	if err != nil {
		return nil, err
	}

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantCyclePolicyUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Cycles)).
		WithMessage("CTEM cycle policy updated").
		WithMetadata("enforce_coverage_slo", cs.EnforceCoverageSLO)
	s.logAudit(ctx, actx, event)

	out := t.TypedSettings().Cycles
	return &out, nil
}

// GetEvidenceSettings returns the tenant's finding-evidence settings. The
// zero value means the defaults.
func (s *TenantService) GetEvidenceSettings(ctx context.Context, tenantID string) (*tenantdom.EvidenceSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	es := t.TypedSettings().Evidence
	return &es, nil
}

// UpdateEvidenceSettings replaces the tenant's finding-evidence settings and
// audits the before/after values.
func (s *TenantService) UpdateEvidenceSettings(
	ctx context.Context,
	tenantID string,
	es tenantdom.EvidenceSettings,
	actx auditapp.AuditContext,
) (*tenantdom.EvidenceSettings, error) {
	var before tenantdom.EvidenceSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionEvidence, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Evidence
		return t.UpdateEvidenceSettings(es)
	})
	if err != nil {
		return nil, err
	}

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantEvidenceUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Evidence)).
		WithMessage("Evidence settings updated").
		WithMetadata("secret_retention_days_before", before.EffectiveSecretRetentionDays()).
		WithMetadata("secret_retention_days_after", es.EffectiveSecretRetentionDays())
	s.logAudit(ctx, actx, event)

	out := t.TypedSettings().Evidence
	return &out, nil
}

// GetAssetLifecycleSettings returns the tenant's current lifecycle
// settings. An empty (zero-value) payload means the feature has
// never been configured — the UI shows defaults.
func (s *TenantService) GetAssetLifecycleSettings(
	ctx context.Context,
	tenantID string,
) (*tenantdom.AssetLifecycleSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	settings := t.TypedSettings()
	al := settings.AssetLifecycle
	return &al, nil
}

// StampAssetLifecycleDryRunCompleted records that the tenant just
// successfully executed a dry-run, unlocking the ability to toggle
// Enabled=true on the next PUT. Separate from the settings update
// so the API handler can stamp after the worker confirms success
// without the caller having to submit a special payload.
func (s *TenantService) StampAssetLifecycleDryRunCompleted(
	ctx context.Context,
	tenantID string,
) error {
	// Writes only the asset_lifecycle section (compare-and-swap, retried on
	// a concurrent write), so the stamp can no longer revert a security or
	// bundle change saved between its read and its write.
	_, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionAssetLifecycle, func(t *tenantdom.Tenant) error {
		settings := t.TypedSettings()
		now := time.Now().UTC().Unix()
		settings.AssetLifecycle.DryRunCompletedAt = &now
		return t.UpdateSettings(settings)
	})
	return err
}

// GetRiskScoringSettings returns the current risk scoring settings for a tenant.
func (s *TenantService) GetRiskScoringSettings(ctx context.Context, tenantID string) (*tenantdom.RiskScoringSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	settings := t.TypedSettings()
	rs := settings.RiskScoring
	return &rs, nil
}

// GetEASMSettings returns the tenant's attack-surface monitoring settings
// (research/22 P0-11). The zero value is the default: everything on at the
// platform cadence.
func (s *TenantService) GetEASMSettings(ctx context.Context, tenantID string) (*tenantdom.EASMSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	es := t.TypedSettings().EASM
	return &es, nil
}

// GetMCPSettings returns the tenant's MCP policy (RFC-062 §8).
func (s *TenantService) GetMCPSettings(ctx context.Context, tenantID string) (*tenantdom.MCPSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	ms := t.TypedSettings().MCP
	return &ms, nil
}

// UpdateMCPSettings replaces the tenant's MCP policy and audits the change.
// The new policy applies to the next MCP request of every connection.
func (s *TenantService) UpdateMCPSettings(
	ctx context.Context,
	tenantID string,
	ms tenantdom.MCPSettings,
	actx auditapp.AuditContext,
) (*tenantdom.MCPSettings, error) {
	var before tenantdom.MCPSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionMCP, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().MCP
		return t.UpdateMCPSettings(ms)
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionMCPSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().MCP)).
		WithMessage("AI application (MCP) policy updated").
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().MCP
	return &out, nil
}

// AllowMCPClientHost adds a publisher host to the organization's MCP policy
// (the hosts whose client metadata documents count as verified) in one
// settings-section write, and audits the change. A host already listed is
// left as is (no write, no audit). The host is validated like every policy
// host; the 50-host cap applies.
func (s *TenantService) AllowMCPClientHost(ctx context.Context, tenantID, host string, actx auditapp.AuditContext) error {
	var before, after tenantdom.MCPSettings
	changed := false
	_, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionMCP, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().MCP
		if slices.Contains(before.ClientHosts, host) {
			changed = false
			return nil
		}
		ms := before
		ms.ClientHosts = append(slices.Clone(before.ClientHosts), host)
		if err := t.UpdateMCPSettings(ms); err != nil {
			return err
		}
		after, changed = t.TypedSettings().MCP, true
		return nil
	})
	if err != nil || !changed {
		return err
	}
	actx.TenantID = tenantID
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionMCPSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, after)).
		WithMessage("AI application publisher approved: "+host).
		WithMetadata("client_host", host).
		WithSeverity(audit.SeverityHigh))
	return nil
}

// GetScopeSettings returns the tenant's scope settings (RFC-054 §6.3).
func (s *TenantService) GetScopeSettings(ctx context.Context, tenantID string) (*tenantdom.ScopeSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	ss := t.TypedSettings().Scope
	return &ss, nil
}

// UpdateScopeSettings replaces the tenant's scope settings and audits the
// before/after values. The route requires attack_surface:scope:approve and
// step-up; the caller notifies the administrators.
func (s *TenantService) UpdateScopeSettings(
	ctx context.Context,
	tenantID string,
	ss tenantdom.ScopeSettings,
	actx auditapp.AuditContext,
) (*tenantdom.ScopeSettings, error) {
	var before tenantdom.ScopeSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionScope, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Scope
		// The owner-only fields are never changed here.
		return t.UpdateScopeSettings(ss.WithIntrusive(before.Intrusive()))
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionScopeSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Scope)).
		WithMessage("Scope settings updated").
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().Scope
	return &out, nil
}

// UpdateIntrusiveScopeSettings changes the owner-only scope settings (the t2
// maximum duration, RFC-054 §12.4) and audits the change at high severity
// with the reason. The route requires the owner role and step-up; the
// caller notifies the administrators.
func (s *TenantService) UpdateIntrusiveScopeSettings(
	ctx context.Context,
	tenantID string,
	in tenantdom.IntrusiveScopeSettings,
	reason string,
	actx auditapp.AuditContext,
) (*tenantdom.ScopeSettings, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, fmt.Errorf("%w: a reason is required", shared.ErrValidation)
	}
	var before tenantdom.ScopeSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionScope, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Scope
		return t.UpdateScopeSettings(before.WithIntrusive(in))
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionScopeSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Scope)).
		WithMessage("Intrusive (t2) scope settings updated by an owner").
		WithMetadata("reason", reason).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().Scope
	return &out, nil
}

// UpdateEASMSettings replaces the tenant's EASM settings and audits the
// before/after values.
func (s *TenantService) UpdateEASMSettings(
	ctx context.Context,
	tenantID string,
	es tenantdom.EASMSettings,
	actx auditapp.AuditContext,
) (*tenantdom.EASMSettings, error) {
	var before tenantdom.EASMSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionEASM, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().EASM
		return t.UpdateEASMSettings(es)
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionEASMSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().EASM)).
		WithMessage("Attack-surface monitoring settings updated").
		WithMetadata("ct_enabled", !es.CTDisabled).
		WithMetadata("dns_checks_enabled", !es.DNSChecksDisabled).
		WithMetadata("ct_interval_hours", es.CTIntervalHours).
		WithMetadata("dns_interval_hours", es.DNSIntervalHours)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().EASM
	return &out, nil
}
