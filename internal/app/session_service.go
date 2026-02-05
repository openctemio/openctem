package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// SessionService handles session management operations.
type SessionService struct {
	sessionRepo      session.Repository
	refreshTokenRepo session.RefreshTokenRepository
	logger           *logger.Logger
	// Permission sync services for cache invalidation on session revocation
	permCacheSvc   *PermissionCacheService
	permVersionSvc *PermissionVersionService
	tenantRepo     TenantMembershipProvider // For getting user's tenants
}

// TenantMembershipProvider provides tenant membership information.
// Used to get all tenants a user belongs to for cache invalidation.
type TenantMembershipProvider interface {
	GetUserTenantIDs(ctx context.Context, userID shared.ID) ([]string, error)
}

// NewSessionService creates a new SessionService.
func NewSessionService(
	sessionRepo session.Repository,
	refreshTokenRepo session.RefreshTokenRepository,
	log *logger.Logger,
) *SessionService {
	return &SessionService{
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		logger:           log.With("service", "session"),
	}
}

// SetPermissionServices sets the permission cache and version services.
// This enables cache invalidation when sessions are revoked.
func (s *SessionService) SetPermissionServices(
	cacheSvc *PermissionCacheService,
	versionSvc *PermissionVersionService,
	tenantRepo TenantMembershipProvider,
) {
	s.permCacheSvc = cacheSvc
	s.permVersionSvc = versionSvc
	s.tenantRepo = tenantRepo
}

// invalidateUserPermissionsAllTenants clears permission cache for a user across all their tenants.
// Called when a session is revoked to ensure immediate access revocation.
func (s *SessionService) invalidateUserPermissionsAllTenants(ctx context.Context, userID shared.ID) {
	if s.permCacheSvc == nil || s.tenantRepo == nil {
		return
	}

	// Get all tenants the user belongs to
	tenantIDs, err := s.tenantRepo.GetUserTenantIDs(ctx, userID)
	if err != nil {
		s.logger.Warn("failed to get user tenants for cache invalidation",
			"user_id", userID.String(),
			"error", err,
		)
		return
	}

	// Invalidate cache for each tenant
	for _, tenantID := range tenantIDs {
		s.permCacheSvc.Invalidate(ctx, tenantID, userID.String())
	}

	if len(tenantIDs) > 0 {
		s.logger.Debug("permission cache invalidated for all tenants on session revoke",
			"user_id", userID.String(),
			"tenant_count", len(tenantIDs),
		)
	}
}

// SessionInfo represents session information returned to the user.
type SessionInfo struct {
	ID             string `json:"id"`
	IPAddress      string `json:"ip_address,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	LastActivityAt string `json:"last_activity_at"`
	CreatedAt      string `json:"created_at"`
	IsCurrent      bool   `json:"is_current"`
}

// ListUserSessions returns all active sessions for a user.
func (s *SessionService) ListUserSessions(ctx context.Context, userID string, currentSessionID string) ([]SessionInfo, error) {
	id, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	sessions, err := s.sessionRepo.GetActiveByUserID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}

	result := make([]SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		info := SessionInfo{
			ID:             sess.ID().String(),
			IPAddress:      sess.IPAddress(),
			UserAgent:      sess.UserAgent(),
			LastActivityAt: sess.LastActivityAt().Format("2006-01-02T15:04:05Z07:00"),
			CreatedAt:      sess.CreatedAt().Format("2006-01-02T15:04:05Z07:00"),
			IsCurrent:      sess.ID().String() == currentSessionID,
		}
		result = append(result, info)
	}

	return result, nil
}

// RevokeSession revokes a specific session for a user.
func (s *SessionService) RevokeSession(ctx context.Context, userID, sessionID string) error {
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}

	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}

	sess, err := s.sessionRepo.GetByID(ctx, sid)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Ensure the session belongs to the user
	if !sess.UserID().Equals(uid) {
		return session.ErrSessionNotFound
	}

	// Revoke session
	if err := sess.Revoke(); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	if err := s.sessionRepo.Update(ctx, sess); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Revoke all refresh tokens for this session
	if err := s.refreshTokenRepo.RevokeBySessionID(ctx, sid); err != nil {
		s.logger.Error("failed to revoke refresh tokens", "error", err)
	}

	// Invalidate permission cache for all tenants
	s.invalidateUserPermissionsAllTenants(ctx, uid)

	s.logger.Info("session revoked", "user_id", userID, "session_id", sessionID)
	return nil
}

// RevokeAllSessions revokes all sessions for a user except the current one.
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID, exceptSessionID string) error {
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}

	var exceptSid shared.ID
	if exceptSessionID != "" {
		exceptSid, err = shared.IDFromString(exceptSessionID)
		if err != nil {
			return fmt.Errorf("invalid session id: %w", err)
		}
	}

	if exceptSid.IsZero() {
		if err := s.sessionRepo.RevokeAllByUserID(ctx, uid); err != nil {
			return fmt.Errorf("failed to revoke sessions: %w", err)
		}
		if err := s.refreshTokenRepo.RevokeByUserID(ctx, uid); err != nil {
			s.logger.Error("failed to revoke refresh tokens", "error", err)
		}
		// Invalidate permission cache when ALL sessions are revoked
		s.invalidateUserPermissionsAllTenants(ctx, uid)
	} else {
		if err := s.sessionRepo.RevokeAllByUserIDExcept(ctx, uid, exceptSid); err != nil {
			return fmt.Errorf("failed to revoke sessions: %w", err)
		}
		// Revoke all refresh tokens except for the current session
		sessions, err := s.sessionRepo.GetActiveByUserID(ctx, uid)
		if err == nil {
			for _, sess := range sessions {
				if !sess.ID().Equals(exceptSid) {
					if err := s.refreshTokenRepo.RevokeBySessionID(ctx, sess.ID()); err != nil {
						s.logger.Error("failed to revoke refresh tokens for session", "error", err)
					}
				}
			}
		}
		// Note: When except session exists, user is keeping one active session
		// so we don't invalidate cache (they're still logged in on that device)
	}

	s.logger.Info("all sessions revoked", "user_id", userID, "except", exceptSessionID)
	return nil
}

// ValidateSession checks if a session is valid.
func (s *SessionService) ValidateSession(ctx context.Context, sessionID string) (*session.Session, error) {
	id, err := shared.IDFromString(sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session id: %w", err)
	}

	sess, err := s.sessionRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if !sess.IsActive() {
		return nil, session.ErrSessionExpired
	}

	return sess, nil
}

// GetSessionByAccessToken retrieves a session by its access token.
func (s *SessionService) GetSessionByAccessToken(ctx context.Context, accessToken string) (*session.Session, error) {
	hash := session.HashToken(accessToken)
	return s.sessionRepo.GetByAccessTokenHash(ctx, hash)
}

// UpdateSessionActivity updates the last activity time for a session.
func (s *SessionService) UpdateSessionActivity(ctx context.Context, sessionID string) error {
	id, err := shared.IDFromString(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}

	sess, err := s.sessionRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	sess.UpdateActivity()
	return s.sessionRepo.Update(ctx, sess)
}

// CleanupExpiredSessions removes expired sessions and tokens.
// This should be called periodically (e.g., by a cron job).
func (s *SessionService) CleanupExpiredSessions(ctx context.Context) (int64, int64, error) {
	sessionsDeleted, err := s.sessionRepo.DeleteExpired(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	tokensDeleted, err := s.refreshTokenRepo.DeleteExpired(ctx)
	if err != nil {
		return sessionsDeleted, 0, fmt.Errorf("failed to delete expired tokens: %w", err)
	}

	if sessionsDeleted > 0 || tokensDeleted > 0 {
		s.logger.Info("cleaned up expired sessions and tokens",
			"sessions_deleted", sessionsDeleted,
			"tokens_deleted", tokensDeleted,
		)
	}

	return sessionsDeleted, tokensDeleted, nil
}

// CountActiveSessions returns the count of active sessions for a user.
func (s *SessionService) CountActiveSessions(ctx context.Context, userID string) (int, error) {
	id, err := shared.IDFromString(userID)
	if err != nil {
		return 0, fmt.Errorf("invalid user id: %w", err)
	}

	return s.sessionRepo.CountActiveByUserID(ctx, id)
}
