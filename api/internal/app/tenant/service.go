// Package tenant implements the application service for the tenant bounded context — orchestrates pkg/domain/tenant entities and cross-cutting concerns (audit, notifications, RBAC).
package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/branch"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
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
// concrete implementation is *app.EmailService; we depend on the
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
	repo             tenantdom.Repository
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
	logger         *logger.Logger
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
// RemoveMember can revoke all of the user's sessions immediately.
// Without it, suspended users can still hit JWT-claim-scoped routes
// (e.g. /api/v1/me/*) until their JWT expires.
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

// hasTenantModule checks if a tenant has access to a specific module.
// In OSS edition, all modules are enabled by default.
func (s *TenantService) hasTenantModule(ctx context.Context, tenantID string, moduleID string) (bool, error) {
	// OSS edition: all modules are enabled
	return true, nil
}

// =============================================================================
// Tenant Operations
// =============================================================================

// CreateTenantInput represents the input for creating a tenant.
type CreateTenantInput struct {
	Name        string `json:"name" validate:"required,min=2,max=100"`
	Slug        string `json:"slug" validate:"required,min=3,max=100,slug"`
	Description string `json:"description" validate:"max=500"`
}

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
		return nil, fmt.Errorf("%w: slug '%s' is already taken", shared.ErrValidation, input.Slug)
	}

	// Create tenant (createdBy still uses string for now as it's stored separately)
	t, err := tenantdom.NewTenant(input.Name, input.Slug, creatorUserID.String())
	if err != nil {
		return nil, err
	}

	if input.Description != "" {
		t.UpdateDescription(input.Description)
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
}

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
		// Check if new slug already exists
		exists, err := s.repo.ExistsBySlug(ctx, *input.Slug)
		if err != nil {
			return nil, fmt.Errorf("failed to check slug existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: slug '%s' is already taken", shared.ErrValidation, *input.Slug)
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

	if err := s.repo.Delete(ctx, parsedID); err != nil {
		return err
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
		WithMetadata("deleted_tenant_id", tenantID)
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
	existing, err := s.repo.GetMembership(ctx, input.UserID, parsedTenantID)
	if err == nil {
		if existing.IsSuspended() {
			return nil, fmt.Errorf(
				"%w: this user has a suspended membership in this tenant — reactivate them via the Members page instead",
				shared.ErrValidation,
			)
		}
		return nil, fmt.Errorf("%w: user is already a member", shared.ErrValidation)
	}
	if !errors.Is(err, shared.ErrNotFound) {
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

	if err := s.repo.CreateMembership(ctx, membership); err != nil {
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

	// Prevent changing owner role
	if membership.IsOwner() {
		return nil, fmt.Errorf("%w: cannot change owner role", shared.ErrValidation)
	}
	if err := s.authorizeMemberChange(ctx, membership, actx); err != nil {
		return nil, err
	}

	oldRole := membership.Role().String()
	role, ok := tenantdom.ParseRole(input.Role)
	if !ok {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}

	// Prevent promoting to owner
	if role == tenantdom.RoleOwner {
		return nil, fmt.Errorf("%w: cannot promote to owner", shared.ErrValidation)
	}
	if role == tenantdom.RoleAdmin && membership.Role() != tenantdom.RoleAdmin {
		if err := s.authorizeAdminPromotion(ctx, membership.TenantID(), actx); err != nil {
			return nil, err
		}
	}

	if err := membership.UpdateRole(role); err != nil {
		return nil, err
	}

	if err := s.repo.UpdateMembership(ctx, membership); err != nil {
		return nil, fmt.Errorf("failed to update member role: %w", err)
	}

	// The change swaps the user's system role in user_roles: drop the cached
	// membership and permissions and bump the permission version, so a token
	// minted before the change is stale on its next request (its admin flag
	// and role are then re-read from the database, audit H2).
	s.invalidateMembershipCache(ctx, membership.TenantID().String(), membership.UserID().String())
	s.bumpPermissionVersion(ctx, membership.TenantID().String(), membership.UserID().String())

	s.logger.Info("member role updated", "membership_id", membershipID, "new_role", role)

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

// RemoveMember removes a member from a tenant.
func (s *TenantService) RemoveMember(ctx context.Context, membershipID string, actx auditapp.AuditContext) error {
	membership, err := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if err != nil {
		return err
	}

	// Prevent removing the owner
	if membership.IsOwner() {
		return fmt.Errorf("%w: cannot remove the owner", shared.ErrValidation)
	}
	if err := s.authorizeMemberChange(ctx, membership, actx); err != nil {
		return err
	}

	tenantID := membership.TenantID().String()
	userID := membership.UserID().String()

	if err := s.repo.DeleteMembership(ctx, membership.TenantID(), membership.ID()); err != nil {
		return err
	}

	// Immediately invalidate permission cache, membership cache, and
	// version to prevent stale access. This reduces the window of
	// vulnerability from 5 minutes (cache TTL) to 0.
	s.invalidateUserPermissions(ctx, tenantID, userID)
	s.invalidateMembershipCache(ctx, tenantID, userID)

	// Wipe any pending invitations the user still has in their inbox
	// for this tenant. Without this they could re-accept the original
	// invitation token to rejoin after the admin removed them — a
	// real privilege escalation path. Best-effort: a failure here is
	// logged but doesn't roll back the membership delete (the primary
	// security goal — revoking access — has already succeeded).
	if deleted, derr := s.repo.DeletePendingInvitationsByUserID(ctx, membership.TenantID(), membership.UserID()); derr != nil {
		s.logger.Warn("failed to clean up pending invitations after member removal",
			"tenant_id", tenantID,
			"user_id", userID,
			"error", derr,
		)
	} else if deleted > 0 {
		s.logger.Info("invalidated pending invitations on member removal",
			"tenant_id", tenantID,
			"user_id", userID,
			"deleted", deleted,
		)
	}

	s.logger.Info("member removed", "membership_id", membershipID)

	// Log audit event
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionMemberRemoved, audit.ResourceTypeMembership, membershipID).
		WithSeverity(audit.SeverityHigh).
		WithMessage("Member removed from team").
		WithMetadata("user_id", userID)
	s.logAudit(ctx, actx, event)

	return nil
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

	if err := s.repo.UpdateMembershipStatus(ctx, membership); err != nil {
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
	//   3. Session revocation: kills all of this user's active sessions
	//      and refresh tokens. Without this, JWT-claim-scoped routes
	//      (/api/v1/me/*, /api/v1/notifications) would still let the
	//      user in until their JWT expired (~30 min).
	//   4. Pending invitation cleanup: removes any unaccepted invites
	//      so the user can't rejoin via a stale link.
	s.invalidateUserPermissions(ctx, tenantID, userID)
	s.invalidateMembershipCache(ctx, tenantID, userID)

	if s.sessionService != nil {
		if err := s.sessionService.RevokeAllSessions(ctx, userID, ""); err != nil {
			// Best effort — log but don't fail the suspend. The
			// permission cache invalidation above is the primary
			// kill switch; session revocation is defense in depth.
			s.logger.Warn("failed to revoke sessions on suspend",
				"user_id", userID, "error", err)
		}
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
	s.logAudit(ctx, actx, event)

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

	if err := membership.Reactivate(); err != nil {
		return err
	}

	if err := s.repo.UpdateMembershipStatus(ctx, membership); err != nil {
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

	// Best-effort: notify the user via email that their access is back.
	s.notifyMemberStatusChange(ctx, false, tenantID, userID, actx.ActorID)

	s.logger.Info("member reactivated", "membership_id", membershipID, "user_id", userID)

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionMemberReactivated, audit.ResourceTypeMembership, membershipID).
		WithSeverity(audit.SeverityMedium).
		WithMessage("Member reactivated").
		WithMetadata("user_id", userID)
	s.logAudit(ctx, actx, event)

	return nil
}

// invalidateUserPermissions clears permission cache and version for a user.
// Called when user is removed from tenant to immediately revoke access.
func (s *TenantService) invalidateUserPermissions(ctx context.Context, tenantID, userID string) {
	// Invalidate permission cache
	if s.permCacheSvc != nil {
		s.permCacheSvc.Invalidate(ctx, tenantID, userID)
	}

	// Delete permission version (cleanup stale version data)
	if s.permVersionSvc != nil {
		if err := s.permVersionSvc.Delete(ctx, tenantID, userID); err != nil {
			s.logger.Warn("failed to delete permission version",
				"tenant_id", tenantID,
				"user_id", userID,
				"error", err,
			)
		}
	}

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

	switch filters.Status {
	case "", string(tenantdom.MemberStatusActive), string(tenantdom.MemberStatusSuspended):
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

	if err := s.requireAllowedEmailDomain(ctx, parsedID, input.Email); err != nil {
		return nil, err
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
	if err == nil && existingMember != nil {
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
		WithMetadata("role", role.String())
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
	if err == nil {
		if existingMembership.IsSuspended() {
			return nil, fmt.Errorf(
				"%w: your access to this team is suspended — please contact an administrator to be reactivated",
				shared.ErrValidation,
			)
		}
		return nil, fmt.Errorf("%w: you are already a member of this team", shared.ErrValidation)
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	// The organization may have restricted member email domains after the
	// invitation was sent.
	if err := s.requireAllowedEmailDomain(ctx, invitation.TenantID(), invitation.Email()); err != nil {
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

	// Use transaction to ensure atomicity - both invitation update and membership creation succeed or fail together
	if err := s.repo.AcceptInvitationTx(ctx, invitation, membership); err != nil {
		return nil, fmt.Errorf("failed to accept invitation: %w", err)
	}

	s.applyInvitationRoles(ctx, invitation, userID)

	// Never log the token, not even a prefix: it is a bearer credential.
	s.logger.Info("invitation accepted", "invitation_id", invitation.ID().String(), "user_id", userID.String(),
		"role_count", len(invitation.RoleIDs()))

	// Log audit event
	actx.TenantID = invitation.TenantID().String()
	event := auditapp.NewSuccessEvent(audit.ActionInvitationAccepted, audit.ResourceTypeInvitation, invitation.ID().String()).
		WithResourceName(userEmail).
		WithMessage(fmt.Sprintf("Invitation accepted by %s", userEmail)).
		WithMetadata("role", invitation.Role().String()).
		WithMetadata("role_ids_count", len(invitation.RoleIDs()))
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
	SSOEnforced           *bool    `json:"sso_enforced"`
	MFARequired           *bool    `json:"mfa_required"`
	SessionTimeoutMin     *int     `json:"session_timeout_min" validate:"omitempty,min=15,max=480"`
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
		if input.SessionTimeoutMin != nil {
			security.SessionTimeoutMin = *input.SessionTimeoutMin
		}
		if input.IPWhitelist != nil {
			security.IPWhitelist = input.IPWhitelist
		}
		if input.AllowedDomains != nil {
			security.AllowedDomains = input.AllowedDomains
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

	result := t.TypedSettings()
	return &result, nil
}

// AlertSensorOptInEnabled is the alert name logged when an organization
// turns a sensor opt-in on (research/25 D9).
const AlertSensorOptInEnabled = "sensor_opt_in_enabled"

// auditSensorOptIn records a change of a sensor opt-in switch (research/25
// D9). Turning one on widens what the platform sends to sensors: it is
// audited at critical severity and alerted (a WARN line with alert=…, which
// the log pipeline forwards). Turning one off is audited at medium.
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

// UpdateAPISettingsInput is a partial-update payload. Scalars are pointers
// (nil == keep existing); WebhookEvents uses nil-vs-[] (absent => keep,
// explicit [] => clear). This stops toggling api_key_enabled from wiping the
// webhook URL/secret/events.
type UpdateAPISettingsInput struct {
	APIKeyEnabled *bool    `json:"api_key_enabled"`
	WebhookURL    *string  `json:"webhook_url"` // url format checked in domain Validate
	WebhookSecret *string  `json:"webhook_secret"`
	WebhookEvents []string `json:"webhook_events"`
}

// UpdateAPISettings updates only the API settings.
func (s *TenantService) UpdateAPISettings(ctx context.Context, tenantID string, input UpdateAPISettingsInput, actx auditapp.AuditContext) (*tenantdom.Settings, error) {
	var before tenantdom.APISettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionAPI, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().API
		// Check plan limits for API via licensing service. Only gate when this
		// request explicitly asserts API access enabled.
		if input.APIKeyEnabled != nil && *input.APIKeyEnabled {
			hasAPIModule, err := s.hasTenantModule(ctx, tenantID, "api")
			if err != nil {
				s.logger.Warn("failed to check API module access", "tenant_id", tenantID, "error", err)
			}
			if !hasAPIModule {
				return fmt.Errorf("%w: API access is not available on your plan", shared.ErrValidation)
			}
		}

		// Partial merge: start from the persisted section and overlay only the
		// fields the client actually sent. Omitted fields are preserved.
		api := t.TypedSettings().API
		if input.APIKeyEnabled != nil {
			api.APIKeyEnabled = *input.APIKeyEnabled
		}
		if input.WebhookURL != nil {
			api.WebhookURL = *input.WebhookURL
		}
		if input.WebhookSecret != nil {
			api.WebhookSecret = *input.WebhookSecret
		}
		if input.WebhookEvents != nil {
			webhookEvents := make([]tenantdom.WebhookEvent, len(input.WebhookEvents))
			for i, e := range input.WebhookEvents {
				webhookEvents[i] = tenantdom.WebhookEvent(e)
			}
			api.WebhookEvents = webhookEvents
		}

		return t.UpdateAPISettings(api)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("API settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().API)).
		WithMessage("API settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
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

// UpdateBranchSettingsInput represents input for updating branch naming convention settings.
type UpdateBranchSettingsInput struct {
	TypeRules []BranchTypeRuleInput `json:"type_rules" validate:"dive"`
}

// BranchTypeRuleInput represents a single branch type mapping rule.
type BranchTypeRuleInput struct {
	Pattern    string `json:"pattern" validate:"required,max=100"`
	MatchType  string `json:"match_type" validate:"required,oneof=exact prefix"`
	BranchType string `json:"branch_type" validate:"required,oneof=main develop feature release hotfix"`
}

// UpdateBranchSettings updates only the branch naming convention settings.
func (s *TenantService) UpdateBranchSettings(ctx context.Context, tenantID string, input UpdateBranchSettingsInput, actx auditapp.AuditContext) (*tenantdom.Settings, error) {
	var rules branch.BranchTypeRules
	var before tenantdom.BranchSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionBranch, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Branch
		rules = make(branch.BranchTypeRules, len(input.TypeRules))
		for i, r := range input.TypeRules {
			rules[i] = branch.BranchTypeRule{
				Pattern:    r.Pattern,
				MatchType:  r.MatchType,
				BranchType: branch.Type(r.BranchType),
			}
		}

		bs := tenantdom.BranchSettings{
			TypeRules: rules,
		}

		return t.UpdateBranchSettings(bs)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("branch settings updated", "tenant_id", tenantID, "rules_count", len(rules))

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Branch)).
		WithMessage("Branch naming convention settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdatePentestSettingsInput represents input for updating pentest settings.
type UpdatePentestSettingsInput struct {
	CampaignTypes []tenantdom.ConfigOption `json:"campaign_types"`
	Methodologies []tenantdom.ConfigOption `json:"methodologies"`
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
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdateAssetSourceSettings updates only the asset-source priority
// settings (RFC-003 Phase 1a).
//
// Phase 1a only validates structurally — duplicates, unknown trust
// levels, UUID shape — because TenantService does not yet carry a
// DataSourceRepo. Existence validation (UUIDs must belong to the
// tenant's data_sources) moves into Phase 1b once the ingest
// priority gate naturally joins with the data_sources table. A
// misconfigured UUID in the meantime is harmless: the Phase 1b gate
// treats unknown source IDs as lowest-rank and logs once per batch.
func (s *TenantService) UpdateAssetSourceSettings(
	ctx context.Context,
	tenantID string,
	as tenantdom.AssetSourceSettings,
	actx auditapp.AuditContext,
) (*tenantdom.Settings, error) {
	var before tenantdom.AssetSourceSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionAssetSource, func(t *tenantdom.Tenant) error {
		// Snapshot the pre-change state so the audit event can carry a
		// full before/after diff. Compliance frameworks that ask "who
		// changed this setting and what specifically changed" lean on
		// this — bare counts are not enough.
		before = t.TypedSettings().AssetSource

		return t.UpdateAssetSourceSettings(as)
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("asset source settings updated",
		"tenant_id", tenantID,
		"priority_count", len(as.Priority),
		"trust_levels_count", len(as.TrustLevels),
		"track_attribution", as.TrackFieldAttribution,
	)

	// Build ordered []string of UUIDs for audit metadata. Bounded
	// by MaxAssetSourcePriorityLen so we don't blow up the audit
	// row on an oversize-but-accepted list.
	toStrings := func(ids []shared.ID) []string {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, id.String())
		}
		return out
	}

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantAssetSourceUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().AssetSource)).
		WithMessage("Asset source priority settings updated").
		WithMetadata("priority_before", toStrings(before.Priority)).
		WithMetadata("priority_after", toStrings(as.Priority)).
		WithMetadata("trust_levels_before", before.TrustLevels).
		WithMetadata("trust_levels_after", as.TrustLevels).
		WithMetadata("track_field_attribution_before", before.TrackFieldAttribution).
		WithMetadata("track_field_attribution_after", as.TrackFieldAttribution)
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
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
		WithMetadata("daily_cap_after", rs.DailyCap)
	s.logAudit(ctx, actx, event)

	out := t.TypedSettings().Retest
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

// GetAssetSourceSettings returns the current asset-source settings
// for a tenant. Zero-value (empty priority + no trust levels) means
// the feature is not enabled; ingest will fall back to today's
// last-write-wins merge.
func (s *TenantService) GetAssetSourceSettings(
	ctx context.Context,
	tenantID string,
) (*tenantdom.AssetSourceSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	settings := t.TypedSettings()
	as := settings.AssetSource
	return &as, nil
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
