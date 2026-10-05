package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// LocalUserKey is the context key for the local user entity.
const LocalUserKey logger.ContextKey = "local_user"

// syncInterval determines how often to update last_login_at
// Only sync if last login was more than this duration ago
const syncInterval = 24 * time.Hour

// UserSync middleware syncs authenticated users to the local database.
// It runs AFTER auth middleware (UnifiedAuth or KeycloakAuth) and creates/updates user records.
// Performance optimization:
// - First request: creates user if not exists
// - Subsequent requests: only updates last_login_at every 24 hours
// This enables:
// - Local user management independent of Keycloak
// - User-specific data (preferences, profile) stored locally
// - Future migration away from Keycloak
// Supports both local auth (LocalClaimsKey) and OIDC auth (ClaimsKey).
//
//nolint:gocognit // pre-existing complexity; only the parameter type changed when the app alias shims were removed
func UserSync(userService *tenant.UserService, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check auth provider and get user ID accordingly
			authProvider := GetAuthProvider(ctx)

			// An API key acts as its user: load that user so the membership
			// gate and handlers see the same principal a session would. The
			// user must still exist and be active; a key never creates one.
			if authProvider == AuthProviderAPIKey {
				userID := GetUserID(ctx)
				if userID == "" {
					next.ServeHTTP(w, r)
					return
				}
				keyUser, err := userService.GetProfile(ctx, userID)
				if err != nil || keyUser == nil || !keyUser.IsActive() {
					log.Debug("api key rejected: key user missing or inactive",
						"user_id", userID, "api_key_id", GetAPIKeyID(ctx))
					apierror.Unauthorized("Invalid credentials").WriteJSON(w)
					return
				}
				ctx = context.WithValue(ctx, LocalUserKey, keyUser)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// For local auth, get or create user from JWT claims
			if authProvider == AuthProviderLocal {
				localClaims := GetLocalClaims(ctx)
				if localClaims == nil {
					next.ServeHTTP(w, r)
					return
				}

				userID := localClaims.UserID
				if userID == "" {
					next.ServeHTTP(w, r)
					return
				}

				// Get user from local JWT claims
				// NOTE: For local auth, we do NOT auto-create users from JWT tokens.
				// Users MUST register through /api/v1/auth/register first.
				localUser, err := userService.GetOrCreateFromLocalToken(ctx, userID, localClaims.Email, localClaims.Name)
				if err != nil {
					// Check if this is a "user not found" error (user hasn't registered)
					if shared.IsNotFound(err) {
						log.Warn("unregistered user attempted access with valid JWT",
							"user_id", userID,
							"email", localClaims.Email,
							"error", err,
						)
						// Return 401 - user must register first
						http.Error(w, "User not registered. Please register at /api/v1/auth/register", http.StatusUnauthorized)
						return
					}

					// Other errors - log and continue
					log.Warn("failed to get local user",
						"error", err,
						"user_id", userID,
						"email", localClaims.Email,
					)
					// Continue without local user - endpoint may still work
					next.ServeHTTP(w, r)
					return
				}

				// A disabled or erased account (users.status other than
				// active) is refused on every request, not only at login: a
				// token minted before the change must not outlive it.
				if !localUser.IsActive() {
					log.Warn("inactive user attempted access", "user_id", localUser.ID().String())
					apierror.Unauthorized("Authentication required").WriteJSON(w)
					return
				}

				// Add local user to context and continue
				ctx = context.WithValue(ctx, LocalUserKey, localUser)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// For OIDC auth, get Keycloak claims from context (set by KeycloakAuth middleware)
			claims := GetClaims(ctx)
			if claims == nil {
				// No authentication - continue without syncing
				next.ServeHTTP(w, r)
				return
			}

			keycloakID := claims.GetUserID()
			if keycloakID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Try to get existing user first (fast path - no write)
			localUser, err := userService.GetByKeycloakID(ctx, keycloakID)
			if err == nil && localUser != nil {
				// User exists - check if we need to update last_login_at
				needsSync := localUser.LastLoginAt() == nil ||
					time.Since(*localUser.LastLoginAt()) > syncInterval

				if needsSync {
					// Only sync periodically to update last_login_at
					localUser, err = userService.SyncFromKeycloak(ctx, claims)
					if err != nil {
						log.Warn("failed to update last login",
							"error", err,
							"user_id", localUser.ID().String(),
						)
						// Continue with existing user data
					}
				}

				if localUser == nil || !localUser.IsActive() {
					log.Warn("inactive user attempted access", "keycloak_id", keycloakID)
					apierror.Unauthorized("Authentication required").WriteJSON(w)
					return
				}

				// Add local user to context and continue
				ctx = context.WithValue(ctx, LocalUserKey, localUser)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// User doesn't exist - create new user (first login)
			localUser, err = userService.SyncFromKeycloak(ctx, claims)
			if err != nil {
				// Log error but don't block the request
				log.Error("failed to create local user",
					"error", err,
					"keycloak_id", keycloakID,
					"email", claims.Email,
				)
				// Continue without local user context
				next.ServeHTTP(w, r)
				return
			}

			log.Info("new user synced from Keycloak",
				"user_id", localUser.ID().String(),
				"email", localUser.Email(),
			)

			// A disabled or erased account is refused here too (fail closed).
			if !localUser.IsActive() {
				log.Warn("inactive user attempted access",
					"user_id", localUser.ID().String(),
					"keycloak_id", keycloakID,
				)
				apierror.Unauthorized("Authentication required").WriteJSON(w)
				return
			}

			// Add local user to context
			ctx = context.WithValue(ctx, LocalUserKey, localUser)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetLocalUser extracts the local user entity from context.
func GetLocalUser(ctx context.Context) *user.User {
	if u, ok := ctx.Value(LocalUserKey).(*user.User); ok {
		return u
	}
	return nil
}

// GetLocalUserID extracts the local user ID from context.
// Returns zero ID if no local user is in context.
func GetLocalUserID(ctx context.Context) shared.ID {
	if u := GetLocalUser(ctx); u != nil {
		return u.ID()
	}
	return shared.ID{}
}

// RequireLocalUser ensures a local user exists in context.
// Use this for endpoints that require user data from the local database.
func RequireLocalUser() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if GetLocalUser(r.Context()) == nil {
				http.Error(w, "User not found in local database", http.StatusInternalServerError)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Note: RequireActiveUser middleware was removed. It was never wired
// into any route, and tenant-scoped routes already enforce access via
// RequireMembership (which checks membership.IsSuspended). Platform-
// level user suspension has no UI in the OSS product.
