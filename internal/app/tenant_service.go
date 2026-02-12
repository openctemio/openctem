package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// EmailJobEnqueuer defines the interface for enqueueing email jobs.
type EmailJobEnqueuer interface {
	EnqueueTeamInvitation(ctx context.Context, payload TeamInvitationJobPayload) error
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
	repo             tenant.Repository
	auditService     *AuditService
	emailEnqueuer    EmailJobEnqueuer
	userInfoProvider UserInfoProvider // For fetching user names
	// Permission sync services for immediate cache invalidation on member removal
	permCacheSvc   *PermissionCacheService
	permVersionSvc *PermissionVersionService
	logger         *logger.Logger
}

// UserInfoProvider defines methods to fetch user information for emails.
type UserInfoProvider interface {
	GetUserNameByID(ctx context.Context, id shared.ID) (string, error)
}

// NewTenantService creates a new TenantService.
func NewTenantService(repo tenant.Repository, log *logger.Logger, opts ...TenantServiceOption) *TenantService {
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
func WithTenantAuditService(auditService *AuditService) TenantServiceOption {
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

// WithUserInfoProvider sets the user info provider for TenantService.
func WithUserInfoProvider(provider UserInfoProvider) TenantServiceOption {
	return func(s *TenantService) {
		s.userInfoProvider = provider
	}
}

// WithTenantPermissionCacheService sets the permission cache service for TenantService.
// This enables immediate cache invalidation when members are removed.
func WithTenantPermissionCacheService(svc *PermissionCacheService) TenantServiceOption {
	return func(s *TenantService) {
		s.permCacheSvc = svc
	}
}

// WithTenantPermissionVersionService sets the permission version service for TenantService.
// This enables version cleanup when members are removed.
func WithTenantPermissionVersionService(svc *PermissionVersionService) TenantServiceOption {
	return func(s *TenantService) {
		s.permVersionSvc = svc
	}
}

// SetPermissionServices sets the permission cache and version services.
// This is used when services are initialized after TenantService.
func (s *TenantService) SetPermissionServices(cacheSvc *PermissionCacheService, versionSvc *PermissionVersionService) {
	s.permCacheSvc = cacheSvc
	s.permVersionSvc = versionSvc
}

// logAudit logs an audit event if audit service is configured.
func (s *TenantService) logAudit(ctx context.Context, actx AuditContext, event AuditEvent) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "error", err, "action", event.Action)
	}
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
func (s *TenantService) CreateTenant(ctx context.Context, input CreateTenantInput, creatorUserID shared.ID, actx AuditContext) (*tenant.Tenant, error) {
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
	t, err := tenant.NewTenant(input.Name, input.Slug, creatorUserID.String())
	if err != nil {
		return nil, err
	}

	if input.Description != "" {
		t.UpdateDescription(input.Description)
	}

	// Create tenant in database
	if err := s.repo.Create(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Create owner membership for the creator
	membership, err := tenant.NewOwnerMembership(creatorUserID, t.ID())
	if err != nil {
		// Rollback tenant creation
		_ = s.repo.Delete(ctx, t.ID())
		return nil, fmt.Errorf("failed to create owner membership: %w", err)
	}

	if err := s.repo.CreateMembership(ctx, membership); err != nil {
		// Rollback tenant creation
		_ = s.repo.Delete(ctx, t.ID())
		return nil, fmt.Errorf("failed to create owner membership: %w", err)
	}

	s.logger.Info("tenant created", "id", t.ID().String(), "name", t.Name(), "owner", creatorUserID.String())

	// Log audit event
	actx.TenantID = t.ID().String()
	event := NewSuccessEvent(audit.ActionTenantCreated, audit.ResourceTypeTenant, t.ID().String()).
		WithResourceName(t.Name()).
		WithMessage(fmt.Sprintf("Team '%s' created", t.Name()))
	s.logAudit(ctx, actx, event)

	return t, nil
}

// GetTenant retrieves a tenant by ID.
func (s *TenantService) GetTenant(ctx context.Context, tenantID string) (*tenant.Tenant, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetTenantBySlug retrieves a tenant by slug.
func (s *TenantService) GetTenantBySlug(ctx context.Context, slug string) (*tenant.Tenant, error) {
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
func (s *TenantService) UpdateTenant(ctx context.Context, tenantID string, input UpdateTenantInput) (*tenant.Tenant, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

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

	if err := s.repo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	s.logger.Info("tenant updated", "id", t.ID().String())
	return t, nil
}

// DeleteTenant deletes a tenant.
func (s *TenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	if err := s.repo.Delete(ctx, parsedID); err != nil {
		return err
	}

	s.logger.Info("tenant deleted", "id", tenantID)
	return nil
}

// ListUserTenants lists all tenants a user belongs to.
// userID is the local user ID (from users table).
func (s *TenantService) ListUserTenants(ctx context.Context, userID shared.ID) ([]*tenant.TenantWithRole, error) {
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
func (s *TenantService) AddMember(ctx context.Context, tenantID string, input AddMemberInput, inviterUserID shared.ID, actx AuditContext) (*tenant.Membership, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	role, ok := tenant.ParseRole(input.Role)
	if !ok {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}

	// Check if user is already a member
	_, err = s.repo.GetMembership(ctx, input.UserID, parsedTenantID)
	if err == nil {
		return nil, fmt.Errorf("%w: user is already a member", shared.ErrValidation)
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	membership, err := tenant.NewMembership(input.UserID, parsedTenantID, role, &inviterUserID)
	if err != nil {
		return nil, err
	}

	if err := s.repo.CreateMembership(ctx, membership); err != nil {
		return nil, fmt.Errorf("failed to add member: %w", err)
	}

	s.logger.Info("member added", "tenant_id", tenantID, "user_id", input.UserID.String(), "role", role)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionMemberAdded, audit.ResourceTypeMembership, membership.ID().String()).
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
func (s *TenantService) UpdateMemberRole(ctx context.Context, membershipID string, input UpdateMemberRoleInput, actx AuditContext) (*tenant.Membership, error) {
	parsedID, err := shared.IDFromString(membershipID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid membership id format", shared.ErrValidation)
	}

	membership, err := s.repo.GetMembershipByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Prevent changing owner role
	if membership.IsOwner() {
		return nil, fmt.Errorf("%w: cannot change owner role", shared.ErrValidation)
	}

	oldRole := membership.Role().String()
	role, ok := tenant.ParseRole(input.Role)
	if !ok {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}

	// Prevent promoting to owner
	if role == tenant.RoleOwner {
		return nil, fmt.Errorf("%w: cannot promote to owner", shared.ErrValidation)
	}

	if err := membership.UpdateRole(role); err != nil {
		return nil, err
	}

	if err := s.repo.UpdateMembership(ctx, membership); err != nil {
		return nil, fmt.Errorf("failed to update member role: %w", err)
	}

	s.logger.Info("member role updated", "membership_id", membershipID, "new_role", role)

	// Log audit event
	actx.TenantID = membership.TenantID().String()
	changes := audit.NewChanges().Set("role", oldRole, input.Role)
	event := NewSuccessEvent(audit.ActionMemberRoleChanged, audit.ResourceTypeMembership, membershipID).
		WithChanges(changes).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Member role changed from %s to %s", oldRole, input.Role))
	s.logAudit(ctx, actx, event)

	return membership, nil
}

// RemoveMember removes a member from a tenant.
func (s *TenantService) RemoveMember(ctx context.Context, membershipID string, actx AuditContext) error {
	parsedID, err := shared.IDFromString(membershipID)
	if err != nil {
		return fmt.Errorf("%w: invalid membership id format", shared.ErrValidation)
	}

	membership, err := s.repo.GetMembershipByID(ctx, parsedID)
	if err != nil {
		return err
	}

	// Prevent removing the owner
	if membership.IsOwner() {
		return fmt.Errorf("%w: cannot remove the owner", shared.ErrValidation)
	}

	tenantID := membership.TenantID().String()
	userID := membership.UserID().String()

	if err := s.repo.DeleteMembership(ctx, parsedID); err != nil {
		return err
	}

	// Immediately invalidate permission cache and version to prevent stale access
	// This reduces the window of vulnerability from 5 minutes (cache TTL) to 0
	s.invalidateUserPermissions(ctx, tenantID, userID)

	s.logger.Info("member removed", "membership_id", membershipID)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionMemberRemoved, audit.ResourceTypeMembership, membershipID).
		WithSeverity(audit.SeverityHigh).
		WithMessage("Member removed from team").
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
func (s *TenantService) ListMembers(ctx context.Context, tenantID string) ([]*tenant.Membership, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.ListMembersByTenant(ctx, parsedID)
}

// ListMembersWithUserInfo lists all members of a tenant with user details.
func (s *TenantService) ListMembersWithUserInfo(ctx context.Context, tenantID string) ([]*tenant.MemberWithUser, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.ListMembersWithUserInfo(ctx, parsedID)
}

// SearchMembersWithUserInfo searches members with filtering and pagination.
func (s *TenantService) SearchMembersWithUserInfo(ctx context.Context, tenantID string, filters tenant.MemberSearchFilters) (*tenant.MemberSearchResult, error) {
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

	return s.repo.SearchMembersWithUserInfo(ctx, parsedID, filters)
}

// GetMemberStats retrieves member statistics for a tenant.
func (s *TenantService) GetMemberStats(ctx context.Context, tenantID string) (*tenant.MemberStats, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetMemberStats(ctx, parsedID)
}

// GetMembership retrieves a user's membership in a tenant.
// userID is the local user ID (from users table).
func (s *TenantService) GetMembership(ctx context.Context, userID shared.ID, tenantID string) (*tenant.Membership, error) {
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
	Email   string   `json:"email" validate:"required,email"`
	Role    string   `json:"-"`                                  // Internal use only - always set to "member" by handler
	RoleIDs []string `json:"role_ids" validate:"required,min=1"` // RBAC roles to assign (required)
}

// CreateInvitation creates an invitation to join a tenant.
// inviterUserID is the local user ID (from users table) of the person sending the invitation.
func (s *TenantService) CreateInvitation(ctx context.Context, tenantID string, input CreateInvitationInput, inviterUserID shared.ID, actx AuditContext) (*tenant.Invitation, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	role, ok := tenant.ParseRole(input.Role)
	if !ok {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}

	// Check for existing pending invitation
	existingInv, err := s.repo.GetPendingInvitationByEmail(ctx, parsedID, input.Email)
	if err == nil && existingInv != nil {
		return nil, fmt.Errorf("%w: pending invitation already exists for this email", shared.ErrValidation)
	}
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing invitation: %w", err)
	}

	// Check if user is already a member of this tenant
	existingMember, err := s.repo.GetMemberByEmail(ctx, parsedID, input.Email)
	if err == nil && existingMember != nil {
		return nil, fmt.Errorf("%w: user with this email is already a member of this team", shared.ErrValidation)
	}
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing member: %w", err)
	}

	invitation, err := tenant.NewInvitation(parsedID, input.Email, role, inviterUserID, input.RoleIDs)
	if err != nil {
		return nil, err
	}

	if err := s.repo.CreateInvitation(ctx, invitation); err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	s.logger.Info("invitation created", "tenant_id", tenantID, "email", input.Email, "role", role, "role_ids", input.RoleIDs)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionInvitationCreated, audit.ResourceTypeInvitation, invitation.ID().String()).
		WithResourceName(input.Email).
		WithMessage(fmt.Sprintf("Invitation sent to %s with role %s", input.Email, role)).
		WithMetadata("email", input.Email).
		WithMetadata("role", input.Role)
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
				"email", input.Email,
				"invitation_id", invitation.ID().String(),
			)
		}
	}

	return invitation, nil
}

// GetInvitationByToken retrieves an invitation by its token.
func (s *TenantService) GetInvitationByToken(ctx context.Context, token string) (*tenant.Invitation, error) {
	return s.repo.GetInvitationByToken(ctx, token)
}

// AcceptInvitation accepts an invitation and creates a membership.
// userID is the local user ID (from users table) of the person accepting the invitation.
// userEmail is used to verify the invitation is intended for this user.
func (s *TenantService) AcceptInvitation(ctx context.Context, token string, userID shared.ID, userEmail string, actx AuditContext) (*tenant.Membership, error) {
	invitation, err := s.repo.GetInvitationByToken(ctx, token)
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

	// Check if user is already a member
	_, err = s.repo.GetMembership(ctx, userID, invitation.TenantID())
	if err == nil {
		return nil, fmt.Errorf("%w: you are already a member of this team", shared.ErrValidation)
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	// Accept the invitation
	if err := invitation.Accept(); err != nil {
		return nil, err
	}

	// Create membership
	invitedBy := invitation.InvitedBy()
	membership, err := tenant.NewMembership(userID, invitation.TenantID(), invitation.Role(), &invitedBy)
	if err != nil {
		return nil, err
	}

	// Use transaction to ensure atomicity - both invitation update and membership creation succeed or fail together
	if err := s.repo.AcceptInvitationTx(ctx, invitation, membership); err != nil {
		return nil, fmt.Errorf("failed to accept invitation: %w", err)
	}

	s.logger.Info("invitation accepted", "token", token[:8]+"...", "user_id", userID.String())

	// Log audit event
	actx.TenantID = invitation.TenantID().String()
	event := NewSuccessEvent(audit.ActionInvitationAccepted, audit.ResourceTypeInvitation, invitation.ID().String()).
		WithResourceName(userEmail).
		WithMessage(fmt.Sprintf("Invitation accepted by %s", userEmail)).
		WithMetadata("role", invitation.Role().String())
	s.logAudit(ctx, actx, event)

	return membership, nil
}

// ListPendingInvitations lists pending invitations for a tenant.
func (s *TenantService) ListPendingInvitations(ctx context.Context, tenantID string) ([]*tenant.Invitation, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.ListPendingInvitationsByTenant(ctx, parsedID)
}

// DeleteInvitation cancels an invitation.
func (s *TenantService) DeleteInvitation(ctx context.Context, invitationID string) error {
	parsedID, err := shared.IDFromString(invitationID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	if err := s.repo.DeleteInvitation(ctx, parsedID); err != nil {
		return err
	}

	s.logger.Info("invitation deleted", "id", invitationID)
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
func (s *TenantService) GetTenantSettings(ctx context.Context, tenantID string) (*tenant.Settings, error) {
	t, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	settings := t.TypedSettings()
	return &settings, nil
}

// UpdateTenantSettings updates all tenant settings.
func (s *TenantService) UpdateTenantSettings(ctx context.Context, tenantID string, settings tenant.Settings, actx AuditContext) (*tenant.Settings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	if err := t.UpdateSettings(settings); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to update tenant settings: %w", err)
	}

	s.logger.Info("tenant settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithMessage("Team settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdateGeneralSettingsInput represents input for updating general settings.
type UpdateGeneralSettingsInput struct {
	Timezone string `json:"timezone" validate:"omitempty"`
	Language string `json:"language" validate:"omitempty,oneof=en vi ja ko zh"`
	Industry string `json:"industry" validate:"omitempty,max=100"`
	Website  string `json:"website" validate:"omitempty,url,max=500"`
}

// UpdateGeneralSettings updates only the general settings.
func (s *TenantService) UpdateGeneralSettings(ctx context.Context, tenantID string, input UpdateGeneralSettingsInput, actx AuditContext) (*tenant.Settings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	general := tenant.GeneralSettings{
		Timezone: input.Timezone,
		Language: input.Language,
		Industry: input.Industry,
		Website:  input.Website,
	}

	if err := t.UpdateGeneralSettings(general); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to update general settings: %w", err)
	}

	s.logger.Info("general settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithMessage("General settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdateSecuritySettingsInput represents input for updating security settings.
type UpdateSecuritySettingsInput struct {
	SSOEnabled        bool     `json:"sso_enabled"`
	SSOProvider       string   `json:"sso_provider" validate:"omitempty,oneof=saml oidc"`
	SSOConfigURL      string   `json:"sso_config_url" validate:"omitempty,url"`
	MFARequired       bool     `json:"mfa_required"`
	SessionTimeoutMin int      `json:"session_timeout_min" validate:"omitempty,min=15,max=480"`
	IPWhitelist       []string `json:"ip_whitelist"`
	AllowedDomains    []string `json:"allowed_domains"`
}

// UpdateSecuritySettings updates only the security settings.
func (s *TenantService) UpdateSecuritySettings(ctx context.Context, tenantID string, input UpdateSecuritySettingsInput, actx AuditContext) (*tenant.Settings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Check plan limits for SSO via licensing service
	if input.SSOEnabled {
		hasSSOModule, err := s.hasTenantModule(ctx, tenantID, "sso")
		if err != nil {
			s.logger.Warn("failed to check SSO module access", "tenant_id", tenantID, "error", err)
		}
		if !hasSSOModule {
			return nil, fmt.Errorf("%w: SSO is not available on your plan", shared.ErrValidation)
		}
	}

	security := tenant.SecuritySettings{
		SSOEnabled:        input.SSOEnabled,
		SSOProvider:       input.SSOProvider,
		SSOConfigURL:      input.SSOConfigURL,
		MFARequired:       input.MFARequired,
		SessionTimeoutMin: input.SessionTimeoutMin,
		IPWhitelist:       input.IPWhitelist,
		AllowedDomains:    input.AllowedDomains,
	}

	if err := t.UpdateSecuritySettings(security); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to update security settings: %w", err)
	}

	s.logger.Info("security settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithSeverity(audit.SeverityHigh).
		WithMessage("Security settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdateAPISettingsInput represents input for updating API settings.
type UpdateAPISettingsInput struct {
	APIKeyEnabled bool     `json:"api_key_enabled"`
	WebhookURL    string   `json:"webhook_url" validate:"omitempty,url"`
	WebhookSecret string   `json:"webhook_secret"`
	WebhookEvents []string `json:"webhook_events"`
}

// UpdateAPISettings updates only the API settings.
func (s *TenantService) UpdateAPISettings(ctx context.Context, tenantID string, input UpdateAPISettingsInput, actx AuditContext) (*tenant.Settings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Check plan limits for API via licensing service
	if input.APIKeyEnabled {
		hasAPIModule, err := s.hasTenantModule(ctx, tenantID, "api")
		if err != nil {
			s.logger.Warn("failed to check API module access", "tenant_id", tenantID, "error", err)
		}
		if !hasAPIModule {
			return nil, fmt.Errorf("%w: API access is not available on your plan", shared.ErrValidation)
		}
	}

	// Convert webhook events
	webhookEvents := make([]tenant.WebhookEvent, len(input.WebhookEvents))
	for i, e := range input.WebhookEvents {
		webhookEvents[i] = tenant.WebhookEvent(e)
	}

	api := tenant.APISettings{
		APIKeyEnabled: input.APIKeyEnabled,
		WebhookURL:    input.WebhookURL,
		WebhookSecret: input.WebhookSecret,
		WebhookEvents: webhookEvents,
	}

	if err := t.UpdateAPISettings(api); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to update API settings: %w", err)
	}

	s.logger.Info("API settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithMessage("API settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}

// UpdateBrandingSettingsInput represents input for updating branding settings.
type UpdateBrandingSettingsInput struct {
	PrimaryColor string `json:"primary_color" validate:"omitempty"`
	LogoDarkURL  string `json:"logo_dark_url" validate:"omitempty,url"`
	LogoData     string `json:"logo_data" validate:"omitempty"` // Base64 encoded logo (max 150KB)
}

// UpdateBrandingSettings updates only the branding settings.
func (s *TenantService) UpdateBrandingSettings(ctx context.Context, tenantID string, input UpdateBrandingSettingsInput, actx AuditContext) (*tenant.Settings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	branding := tenant.BrandingSettings{
		PrimaryColor: input.PrimaryColor,
		LogoDarkURL:  input.LogoDarkURL,
		LogoData:     input.LogoData,
	}

	if err := t.UpdateBrandingSettings(branding); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to update branding settings: %w", err)
	}

	s.logger.Info("branding settings updated", "tenant_id", tenantID)

	// Log audit event
	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
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
func (s *TenantService) UpdateBranchSettings(ctx context.Context, tenantID string, input UpdateBranchSettingsInput, actx AuditContext) (*tenant.Settings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	rules := make(branch.BranchTypeRules, len(input.TypeRules))
	for i, r := range input.TypeRules {
		rules[i] = branch.BranchTypeRule{
			Pattern:    r.Pattern,
			MatchType:  r.MatchType,
			BranchType: branch.Type(r.BranchType),
		}
	}

	bs := tenant.BranchSettings{
		TypeRules: rules,
	}

	if err := t.UpdateBranchSettings(bs); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to update branch settings: %w", err)
	}

	s.logger.Info("branch settings updated", "tenant_id", tenantID, "rules_count", len(rules))

	actx.TenantID = tenantID
	event := NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithMessage("Branch naming convention settings updated")
	s.logAudit(ctx, actx, event)

	result := t.TypedSettings()
	return &result, nil
}
