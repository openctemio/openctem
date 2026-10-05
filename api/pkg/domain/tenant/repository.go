package tenant

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Repository defines the interface for tenant persistence.
type Repository interface {
	// Tenant CRUD
	Create(ctx context.Context, t *Tenant) error
	GetByID(ctx context.Context, id shared.ID) (*Tenant, error)
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)
	// UpdateProfile writes the organization profile (name, slug, description,
	// logo URL). It never touches settings.
	UpdateProfile(ctx context.Context, t *Tenant) error
	// UpdateSettingsSection replaces one top-level settings section with
	// next, only if its stored value still equals expected (expectedPresent
	// false = the key is absent). Returns *SettingsConflictError when another
	// write changed the section first, and shared.ErrNotFound when the tenant
	// does not exist. Other sections are never rewritten.
	UpdateSettingsSection(ctx context.Context, id shared.ID, section string, expected any, expectedPresent bool, next any) error
	Delete(ctx context.Context, id shared.ID) error
	ExistsBySlug(ctx context.Context, slug string) (bool, error)

	// ListActiveTenantIDs returns all active tenant IDs.
	// Used by background jobs that need to process data across all tenants.
	// The platform system tenant (SystemTenantID) is not included.
	ListActiveTenantIDs(ctx context.Context) ([]shared.ID, error)

	// CreateWithOwner atomically creates a tenant and its owner membership in a
	// single transaction (all-or-nothing — no orphan tenant if membership fails).
	CreateWithOwner(ctx context.Context, t *Tenant, membership *Membership) error

	// Membership operations
	CreateMembership(ctx context.Context, membership *Membership) error
	GetMembership(ctx context.Context, userID shared.ID, tenantID shared.ID) (*Membership, error)
	// GetMembershipByID returns a membership of tenantID; another tenant's is ErrNotFound.
	GetMembershipByID(ctx context.Context, tenantID, id shared.ID) (*Membership, error)
	UpdateMembership(ctx context.Context, membership *Membership) error
	// UpdateMembershipStatus persists the lifecycle status change
	// (active ↔ suspended). Used by Suspend/Reactivate service methods.
	UpdateMembershipStatus(ctx context.Context, membership *Membership) error
	// DeleteMembership removes a membership of tenantID.
	DeleteMembership(ctx context.Context, tenantID, id shared.ID) error
	ListMembersByTenant(ctx context.Context, tenantID shared.ID) ([]*Membership, error)
	ListMembersWithUserInfo(ctx context.Context, tenantID shared.ID) ([]*MemberWithUser, error)
	SearchMembersWithUserInfo(ctx context.Context, tenantID shared.ID, filters MemberSearchFilters) (*MemberSearchResult, error)
	ListTenantsByUser(ctx context.Context, userID shared.ID) ([]*TenantWithRole, error)
	CountMembersByTenant(ctx context.Context, tenantID shared.ID) (int64, error)
	GetMemberStats(ctx context.Context, tenantID shared.ID) (*MemberStats, error)
	// GetUserMemberships returns lightweight membership data for JWT tokens.
	// Suspended memberships are filtered out — they cannot mint tokens.
	GetUserMemberships(ctx context.Context, userID shared.ID) ([]UserMembership, error)
	// GetUserSuspendedMemberships returns the SUSPENDED memberships for a
	// user. Used by the login flow so the UI can tell a suspended user
	// "your access to {tenant} is suspended" instead of bouncing them to
	// the create-team onboarding screen with no explanation.
	GetUserSuspendedMemberships(ctx context.Context, userID shared.ID) ([]UserMembership, error)
	// GetUserMembershipsWithStatus returns BOTH active and suspended
	// memberships in a single query. The login flow uses this to avoid
	// the two sequential round trips that GetUserMemberships +
	// GetUserSuspendedMemberships would cost.
	GetUserMembershipsWithStatus(ctx context.Context, userID shared.ID) (*UserMembershipsByStatus, error)
	// GetMemberByEmail retrieves a member by email address within a tenant
	GetMemberByEmail(ctx context.Context, tenantID shared.ID, email string) (*MemberWithUser, error)

	// Invitation operations
	CreateInvitation(ctx context.Context, invitation *Invitation) error
	GetInvitationByToken(ctx context.Context, token string) (*Invitation, error)
	// GetInvitationByID returns an invitation of tenantID; another tenant's is ErrNotFound.
	GetInvitationByID(ctx context.Context, tenantID, id shared.ID) (*Invitation, error)
	UpdateInvitation(ctx context.Context, invitation *Invitation) error
	// DeleteInvitation removes an invitation of tenantID.
	DeleteInvitation(ctx context.Context, tenantID, id shared.ID) error
	ListPendingInvitationsByTenant(ctx context.Context, tenantID shared.ID) ([]*Invitation, error)
	GetPendingInvitationByEmail(ctx context.Context, tenantID shared.ID, email string) (*Invitation, error)
	DeleteExpiredInvitations(ctx context.Context) (int64, error)

	// DeletePendingInvitationsByUserID removes every UNACCEPTED
	// invitation matching the user's email in the given tenant.
	// Used when removing a member to ensure they can't rejoin via
	// a stale token still sitting in their inbox. Looks up the
	// user's email via JOIN so the caller doesn't need to fetch it
	// first. Email matching is case-insensitive. Returns the number
	// of rows deleted (0 is not an error).
	DeletePendingInvitationsByUserID(ctx context.Context, tenantID, userID shared.ID) (int64, error)

	// AcceptInvitationTx atomically updates the invitation and creates the membership in a single transaction.
	// This ensures data consistency - either both operations succeed or neither does.
	AcceptInvitationTx(ctx context.Context, invitation *Invitation, membership *Membership) error
}

// TenantWithRole represents a tenant with the user's role in it.
type TenantWithRole struct {
	Tenant   *Tenant
	Role     Role
	JoinedAt time.Time
}

// MemberInfo represents a membership with user info.
// Note: User info should be fetched from the local users table by the service layer.
type MemberInfo struct {
	Membership *Membership
	UserID     shared.ID // Local user ID
	Email      string    // From local users table
	Name       string    // From local users table
	AvatarURL  string    // From local users table
}

// MemberWithUser represents a membership joined with user details.
type MemberWithUser struct {
	// Membership fields
	ID        shared.ID
	UserID    shared.ID
	Role      Role
	InvitedBy *shared.ID
	JoinedAt  time.Time
	// User fields
	Email       string
	Name        string
	AvatarURL   string
	Status      string // active, pending, inactive
	LastLoginAt *time.Time
	// MFAStatus is the user's second-factor state: "enabled", "disabled", or
	// "idp" for accounts that sign in through an identity provider (which
	// owns the second factor). Filled by SearchMembersWithUserInfo only.
	MFAStatus string
	// PendingSetup: an administrator-created local account whose owner has not
	// set a password or signed in yet.
	PendingSetup bool
}

// MemberStats contains statistics about tenant members.
type MemberStats struct {
	TotalMembers  int `json:"total_members"`
	ActiveMembers int `json:"active_members"`
	// SuspendedMembers are disabled members (access cut, reversible).
	SuspendedMembers int `json:"suspended_members"`
	// OffboardedMembers are tombstones of members who left. They are not
	// counted in TotalMembers.
	OffboardedMembers int            `json:"offboarded_members"`
	PendingInvites    int            `json:"pending_invites"`
	RoleCounts        map[string]int `json:"role_counts"`
}

// MemberSearchFilters defines filters for searching members.
type MemberSearchFilters struct {
	Search string // Search by name or email (case-insensitive)
	// SearchNameOnly restricts Search to the member's name. Set for callers
	// who may not see member emails, so a search cannot confirm an address.
	SearchNameOnly bool
	Limit          int // Maximum number of results (0 = no limit)
	Offset         int // Offset for pagination
	// Status filters by membership status: "active", "suspended",
	// "offboarded", or "all". Empty lists active and suspended members (not
	// the offboarded tombstones).
	Status string
}

// Member status filter values for MemberSearchFilters.Status.
const (
	MemberFilterAll = "all"
)

// MemberSearchResult contains the search results and total count.
type MemberSearchResult struct {
	Members []*MemberWithUser
	Total   int // Total matching members (before limit)
}

// UserMembership is a lightweight struct for JWT token generation.
// Contains only the essential data needed for authorization.
type UserMembership struct {
	TenantID   string // Tenant UUID
	TenantSlug string // Tenant slug for URL-friendly access
	TenantName string // Tenant display name
	Role       string // Role in tenant (owner, admin, member, viewer)
}

// UserMembershipsByStatus partitions a user's memberships by lifecycle
// status. Returned by GetUserMembershipsWithStatus so the login flow
// can fetch both lists in a single query.
type UserMembershipsByStatus struct {
	Active    []UserMembership
	Suspended []UserMembership
}

// SystemTenantID is the platform system tenant seeded by migration 000058. It
// owns system scan profiles and pipeline templates; it has no members, assets
// or findings, and it is not a customer tenant. shared.ID treats this all-zero
// UUID as empty, so per-tenant services reject it — background sweeps must
// never iterate it.
const SystemTenantID = "00000000-0000-0000-0000-000000000000"
