package middleware

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// Tenant-related context keys for database-based multi-tenancy.
// These are separate from auth.go's JWT-based tenant keys.
const (
	TeamIDKey     logger.ContextKey = "team_id"    // shared.ID from URL/database
	TeamSlugKey   logger.ContextKey = "team_slug"  // slug string
	TeamRoleKey   logger.ContextKey = "team_role"  // tenant.Role from membership
	MembershipKey logger.ContextKey = "membership" // *tenant.Membership
)

// TenantContext extracts tenant ID from URL path parameter and adds to context.
// It expects the path parameter to be named "tenant" (e.g., /tenants/{tenant}/assets).
// The {tenant} can be either a tenant ID (UUID) or tenant slug.
func TenantContext(tenantRepo tenant.Repository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantParam := r.PathValue("tenant")
			if tenantParam == "" {
				apierror.BadRequest("Tenant ID or slug is required").WriteJSON(w)
				return
			}

			var t *tenant.Tenant
			var err error

			// Try to parse as UUID first
			if tenantID, parseErr := shared.IDFromString(tenantParam); parseErr == nil {
				t, err = tenantRepo.GetByID(r.Context(), tenantID)
			} else {
				// Otherwise, treat as slug
				t, err = tenantRepo.GetBySlug(r.Context(), tenantParam)
			}

			if err != nil {
				if errors.Is(err, shared.ErrNotFound) {
					apierror.NotFound("Tenant not found").WriteJSON(w)
					return
				}
				apierror.InternalError(fmt.Errorf("failed to get tenant")).WriteJSON(w)
				return
			}

			// Add tenant info to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, TeamIDKey, t.ID())
			ctx = context.WithValue(ctx, TeamSlugKey, t.Slug())

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireMembership verifies the authenticated user is a member of the tenant.
// Must be used after KeycloakAuth, UserSync, and TenantContext middleware.
func RequireMembership(tenantRepo tenant.Repository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := GetLocalUserID(r.Context())
			if userID.IsZero() {
				apierror.Unauthorized("Authentication required").WriteJSON(w)
				return
			}

			teamID := GetTeamID(r.Context())
			if teamID.IsZero() {
				apierror.BadRequest("Tenant context required").WriteJSON(w)
				return
			}

			membership, err := tenantRepo.GetMembership(r.Context(), userID, teamID)
			if err != nil {
				if errors.Is(err, shared.ErrNotFound) {
					apierror.Forbidden("You are not a member of this tenant").WriteJSON(w)
					return
				}
				apierror.InternalError(fmt.Errorf("failed to check membership")).WriteJSON(w)
				return
			}

			// Add membership info to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, TeamRoleKey, membership.Role())
			ctx = context.WithValue(ctx, MembershipKey, membership)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireTeamRole checks if the user has one of the required roles in the team.
// Must be used after RequireMembership middleware.
func RequireTeamRole(roles ...tenant.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := GetTeamRole(r.Context())
			if role == "" {
				apierror.Forbidden("Membership required").WriteJSON(w)
				return
			}

			// Convert to string slice for comparison
			roleStrings := make([]string, len(roles))
			for i, r := range roles {
				roleStrings[i] = r.String()
			}

			if !slices.Contains(roleStrings, string(role)) {
				apierror.Forbidden("Insufficient permissions in this tenant").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireTeamAdmin checks if the user has admin permissions in the team.
func RequireTeamAdmin() func(http.Handler) http.Handler {
	return RequireTeamRole(tenant.RoleOwner, tenant.RoleAdmin)
}

// RequireTeamOwner checks if the user is the owner of the team.
func RequireTeamOwner() func(http.Handler) http.Handler {
	return RequireTeamRole(tenant.RoleOwner)
}

// RequireTeamWrite checks if the user has write permissions in the team.
func RequireTeamWrite() func(http.Handler) http.Handler {
	return RequireTeamRole(tenant.RoleOwner, tenant.RoleAdmin, tenant.RoleMember)
}

// RequireMinTeamRole checks if the user has at least the minimum role level.
// Uses role hierarchy: owner > admin > member > viewer.
func RequireMinTeamRole(minRole tenant.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := GetTeamRole(r.Context())
			if role == "" {
				apierror.Forbidden("Membership required").WriteJSON(w)
				return
			}

			if role.Priority() < minRole.Priority() {
				apierror.Forbidden("Insufficient permissions in this tenant").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SetTeamDBContext sets the team context for database RLS.
func SetTeamDBContext(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			teamID := GetTeamID(r.Context())
			if teamID.IsZero() {
				next.ServeHTTP(w, r)
				return
			}

			_, err := db.ExecContext(r.Context(), "SET LOCAL app.current_tenant = $1", teamID.String())
			if err != nil {
				apierror.InternalError(fmt.Errorf("failed to set tenant context")).WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// Context Getters
// =============================================================================

// GetTeamID extracts the team ID (shared.ID) from context.
func GetTeamID(ctx context.Context) shared.ID {
	if id, ok := ctx.Value(TeamIDKey).(shared.ID); ok {
		return id
	}
	return shared.ID{}
}

// GetTeamSlug extracts the team slug from context.
func GetTeamSlug(ctx context.Context) string {
	if slug, ok := ctx.Value(TeamSlugKey).(string); ok {
		return slug
	}
	return ""
}

// GetTeamRole extracts the user's role in the team from context.
func GetTeamRole(ctx context.Context) tenant.Role {
	if role, ok := ctx.Value(TeamRoleKey).(tenant.Role); ok {
		return role
	}
	return ""
}

// GetTeamMembership extracts the membership from context.
func GetTeamMembership(ctx context.Context) *tenant.Membership {
	if m, ok := ctx.Value(MembershipKey).(*tenant.Membership); ok {
		return m
	}
	return nil
}
