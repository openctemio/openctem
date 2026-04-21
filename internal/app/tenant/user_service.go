package tenant

import (
	"context"
	"fmt"
	"html"
	"strings"

	authapp "github.com/openctemio/api/internal/app/auth"

	"github.com/openctemio/api/pkg/domain/shared"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/keycloak"
	"github.com/openctemio/api/pkg/logger"
)

// UserService handles user-related business operations.
type UserService struct {
	repo           userdom.Repository
	sessionService *authapp.SessionService // For revoking sessions on suspend
	logger         *logger.Logger
}

// NewUserService creates a new UserService.
func NewUserService(repo userdom.Repository, log *logger.Logger) *UserService {
	return &UserService{
		repo:   repo,
		logger: log.With("service", "user"),
	}
}

// SetSessionService sets the session service for revoking sessions.
// This enables immediate session revocation when user is suspended.
func (s *UserService) SetSessionService(sessionService *authapp.SessionService) {
	s.sessionService = sessionService
}

// sanitizeString removes potentially dangerous characters and trims whitespace.
// It escapes HTML entities to prevent XSS attacks.
func sanitizeString(s string, maxLen int) string {
	// Trim whitespace
	s = strings.TrimSpace(s)

	// Escape HTML entities to prevent XSS
	s = html.EscapeString(s)

	// Limit length
	if len(s) > maxLen {
		s = s[:maxLen]
	}

	return s
}

// SyncFromKeycloak syncs a user from Keycloak claims.
// This is called by middleware on each authenticated request.
// It creates the user if not exists, or updates their info if exists.
func (s *UserService) SyncFromKeycloak(ctx context.Context, claims *keycloak.Claims) (*userdom.User, error) {
	if claims == nil {
		return nil, fmt.Errorf("%w: claims is nil", shared.ErrValidation)
	}

	keycloakID := claims.GetUserID()
	if keycloakID == "" {
		return nil, fmt.Errorf("%w: keycloak user ID is empty", shared.ErrValidation)
	}

	email := claims.Email
	if email == "" {
		// Use preferred_username as fallback for email
		email = claims.PreferredUsername
		if email == "" {
			email = keycloakID + "@placeholder.local"
		}
	}
	// Sanitize and validate email
	email = strings.TrimSpace(strings.ToLower(email))

	name := claims.Name
	if name == "" {
		// Build name from given_name and family_name
		if claims.GivenName != "" || claims.FamilyName != "" {
			name = claims.GivenName
			if claims.FamilyName != "" {
				if name != "" {
					name += " "
				}
				name += claims.FamilyName
			}
		} else if claims.PreferredUsername != "" {
			name = claims.PreferredUsername
		}
	}
	// Sanitize name to prevent XSS
	name = sanitizeString(name, 255)

	u, err := s.repo.UpsertFromKeycloak(ctx, keycloakID, email, name)
	if err != nil {
		s.logger.Error("failed to sync user from Keycloak", "error", err, "keycloak_id", keycloakID)
		return nil, fmt.Errorf("failed to sync user: %w", err)
	}

	s.logger.Debug("user synced from Keycloak", "user_id", u.ID().String(), "keycloak_id", keycloakID)
	return u, nil
}

// GetProfile retrieves a user's profile by ID.
func (s *UserService) GetProfile(ctx context.Context, userID string) (*userdom.User, error) {
	parsedID, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetOrCreateFromLocalToken gets an existing user by ID from local JWT claims.
// This is used by the UserSync middleware for local auth.
//
// IMPORTANT: For OSS/local auth, we do NOT auto-create users from JWT tokens.
// Users MUST register through the /api/v1/auth/register endpoint first.
// This prevents creating passwordless users that cannot login.
func (s *UserService) GetOrCreateFromLocalToken(ctx context.Context, userID, email, name string) (*userdom.User, error) {
	parsedID, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// Try to get existing user first
	existingUser, err := s.repo.GetByID(ctx, parsedID)
	if err == nil && existingUser != nil {
		s.logger.Debug("user found from local token", "user_id", userID)
		return existingUser, nil
	}

	// User doesn't exist in database
	// For local auth, users MUST register first - we don't auto-create from JWT
	// This is different from OIDC where users are created from provider claims
	s.logger.Warn("user not found for local token - user must register first",
		"user_id", userID,
		"email", email,
	)

	return nil, fmt.Errorf("%w: user not registered - please register first", shared.ErrNotFound)
}

// GetByKeycloakID retrieves a user by their Keycloak ID.
func (s *UserService) GetByKeycloakID(ctx context.Context, keycloakID string) (*userdom.User, error) {
	return s.repo.GetByKeycloakID(ctx, keycloakID)
}

// GetByEmail retrieves a user by their email.
func (s *UserService) GetByEmail(ctx context.Context, email string) (*userdom.User, error) {
	return s.repo.GetByEmail(ctx, email)
}

// UpdateProfileInput represents the input for updating a user profile.
type UpdateProfileInput struct {
	Name      *string `validate:"omitempty,max=255"`
	Phone     *string `validate:"omitempty,max=50"`
	AvatarURL *string `validate:"omitempty,max=500,url"`
}

// UpdateProfile updates a user's profile.
func (s *UserService) UpdateProfile(ctx context.Context, userID string, input UpdateProfileInput) (*userdom.User, error) {
	parsedID, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	u, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Apply updates
	name := u.Name()
	if input.Name != nil {
		name = *input.Name
	}

	phone := u.Phone()
	if input.Phone != nil {
		phone = *input.Phone
	}

	avatarURL := u.AvatarURL()
	if input.AvatarURL != nil {
		avatarURL = *input.AvatarURL
	}

	u.UpdateProfile(name, phone, avatarURL)

	if err := s.repo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("failed to update profile: %w", err)
	}

	s.logger.Info("profile updated", "user_id", userID)
	return u, nil
}

// UpdatePreferences updates a user's preferences.
func (s *UserService) UpdatePreferences(ctx context.Context, userID string, prefs userdom.Preferences) (*userdom.User, error) {
	parsedID, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	u, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	u.UpdatePreferences(prefs)

	if err := s.repo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("failed to update preferences: %w", err)
	}

	s.logger.Info("preferences updated", "user_id", userID)
	return u, nil
}

// Note: SuspendUser / ActivateUser were removed. They were never wired
// into any handler or route, and member access is managed at the
// membership level via TenantService.SuspendMember / ReactivateMember.
// See pkg/domain/user/entity.go for the rationale on keeping the
// status column itself.

// GetUsersByIDs retrieves multiple users by their IDs (string format).
func (s *UserService) GetUsersByIDs(ctx context.Context, userIDs []string) ([]*userdom.User, error) {
	if len(userIDs) == 0 {
		return []*userdom.User{}, nil
	}

	ids := make([]shared.ID, 0, len(userIDs))
	for _, idStr := range userIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}

	return s.repo.GetByIDs(ctx, ids)
}

// GetByIDs retrieves multiple users by their IDs (shared.ID format).
func (s *UserService) GetByIDs(ctx context.Context, ids []shared.ID) ([]*userdom.User, error) {
	if len(ids) == 0 {
		return []*userdom.User{}, nil
	}
	return s.repo.GetByIDs(ctx, ids)
}
