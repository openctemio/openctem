package middleware

import (
	"context"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/pentest"
	"github.com/openctemio/api/pkg/logger"
)

// CampaignRoleQuerier resolves a user's campaign role from the database.
type CampaignRoleQuerier interface {
	GetUserRole(ctx context.Context, tenantID, campaignID, userID string) (pentest.CampaignRole, error)
}

// CampaignStatusQuerier resolves a campaign's status. Optional — if nil, status not set in context.
type CampaignStatusQuerier interface {
	GetCampaignStatus(ctx context.Context, tenantID, campaignID string) (pentest.CampaignStatus, error)
}

// CampaignRoleResolver creates a middleware that resolves the user's campaign role
// from the database and stores it in the request context.
// It uses the {id} URL parameter for the campaign ID.
// Admin users bypass the DB query entirely.
func CampaignRoleResolver(roleQuerier CampaignRoleQuerier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			campaignID := chi.URLParam(r, "id")
			if campaignID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Admin bypass: skip DB query, no role needed
			if IsAdmin(r.Context()) {
				ctx := context.WithValue(r.Context(), CampaignIDKey, campaignID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			tenantID := GetTenantID(r.Context())
			userID := GetUserID(r.Context())

			role, _ := roleQuerier.GetUserRole(r.Context(), tenantID, campaignID, userID)
			ctx := context.WithValue(r.Context(), CampaignRoleKey, role)
			ctx = context.WithValue(ctx, CampaignIDKey, campaignID)
			// Share the resolved role via request-scoped cache so service-layer
			// helpers (ResolveCampaignRoleForFinding etc.) don't re-query the DB.
			if role != "" {
				ctx = app.WithCachedCampaignRole(ctx, tenantID, campaignID, userID, role)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Campaign RBAC context keys.
const (
	CampaignRoleKey   logger.ContextKey = "campaign_role"
	CampaignStatusKey logger.ContextKey = "campaign_status"
	CampaignIDKey     logger.ContextKey = "campaign_id"
)

// GetCampaignRole returns the user's campaign role from context.
func GetCampaignRole(ctx context.Context) pentest.CampaignRole {
	role, _ := ctx.Value(CampaignRoleKey).(pentest.CampaignRole)
	return role
}

// GetCampaignStatus returns the campaign status from context.
func GetCampaignStatus(ctx context.Context) pentest.CampaignStatus {
	status, _ := ctx.Value(CampaignStatusKey).(pentest.CampaignStatus)
	return status
}

// GetCampaignID returns the campaign ID from context.
func GetCampaignID(ctx context.Context) string {
	id, _ := ctx.Value(CampaignIDKey).(string)
	return id
}

// RequireCampaignRole creates a middleware that checks the user's campaign role.
// Admin/owner bypasses the check.
// If no campaign role is set (not a member), returns 404 to avoid revealing campaign existence.
func RequireCampaignRole(allowed ...pentest.CampaignRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Admin bypass
			if IsAdmin(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			role := GetCampaignRole(r.Context())
			if role == "" {
				apierror.NotFound("not found").WriteJSON(w)
				return
			}

			if !slices.Contains(allowed, role) {
				apierror.Forbidden("Insufficient campaign permissions").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireCampaignWritable creates a middleware that blocks writes on locked campaigns.
// allowExistingUpdates: if true, on_hold campaigns allow updating existing items.
func RequireCampaignWritable(allowExistingUpdates bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			status := GetCampaignStatus(r.Context())
			if err := pentest.RequireCampaignWritable(status, allowExistingUpdates); err != nil {
				apierror.Forbidden(err.Error()).WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SetCampaignContext returns a context with campaign role, status, and ID set.
func SetCampaignContext(ctx context.Context, role pentest.CampaignRole, status pentest.CampaignStatus, campaignID string) context.Context {
	ctx = context.WithValue(ctx, CampaignRoleKey, role)
	ctx = context.WithValue(ctx, CampaignStatusKey, status)
	ctx = context.WithValue(ctx, CampaignIDKey, campaignID)
	return ctx
}
