package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"

	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SessionService handles session management operations.
type SessionService struct {
	sessionRepo      sessiondom.Repository
	refreshTokenRepo sessiondom.RefreshTokenRepository
	logger           *logger.Logger
	// Permission sync services for cache invalidation on session revocation
	permCacheSvc   *accesscontrol.PermissionCacheService
	permVersionSvc *accesscontrol.PermissionVersionService
	tenantRepo     TenantMembershipProvider // For getting user's tenants

	// revocations records revoked session ids so the auth middleware rejects
	// their still-unexpired access tokens at once; revocationTTL must outlive
	// an access token. nil = access tokens expire naturally.
	revocations   SessionRevocationStore
	revocationTTL time.Duration
	// mfaChallenges, when set, has its expired login challenges removed by
	// CleanupExpiredSessions.
	mfaChallenges mfa.Repository
}

// TenantMembershipProvider provides tenant membership information.
// Used to get all tenants a user belongs to for cache invalidation.
type TenantMembershipProvider interface {
	GetUserTenantIDs(ctx context.Context, userID shared.ID) ([]string, error)
}

// NewSessionService creates a new SessionService.
func NewSessionService(
	sessionRepo sessiondom.Repository,
	refreshTokenRepo sessiondom.RefreshTokenRepository,
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
	cacheSvc *accesscontrol.PermissionCacheService,
	versionSvc *accesscontrol.PermissionVersionService,
	tenantRepo TenantMembershipProvider,
) {
	s.permCacheSvc = cacheSvc
	s.permVersionSvc = versionSvc
	s.tenantRepo = tenantRepo
}

// SetRevocationStore wires immediate access-token revocation. ttl must be at
// least the access-token lifetime.
func (s *SessionService) SetRevocationStore(store SessionRevocationStore, ttl time.Duration) {
	s.revocations = store
	s.revocationTTL = ttl
}

// SetMFAChallengeCleanup makes CleanupExpiredSessions also delete expired 2FA
// login challenges.
func (s *SessionService) SetMFAChallengeCleanup(repo mfa.Repository) {
	s.mfaChallenges = repo
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
		return fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}

	// A malformed session id is a client error (400), not a server error.
	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return fmt.Errorf("%w: invalid session id", shared.ErrValidation)
	}

	sess, err := s.sessionRepo.GetByID(ctx, sid)
	if err != nil {
		// Unknown session id: surface the not-found sentinel (404) rather than
		// a wrapped generic error that the handler maps to 500.
		if errors.Is(err, sessiondom.ErrSessionNotFound) {
			return sessiondom.ErrSessionNotFound
		}
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Ensure the session belongs to the user. A session owned by someone else
	// is reported as not-found, so one user cannot probe another's session ids.
	if !sess.UserID().Equals(uid) {
		return sessiondom.ErrSessionNotFound
	}

	// Revoke session
	if err := sess.Revoke(); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	if err := s.sessionRepo.Update(ctx, sess); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Revoke all refresh tokens for this session.
	// Note: Not in same DB transaction as session revoke above.
	// Race window is <1ms. Even if a refresh token is used in this window,
	// the session check in ExchangeToken will reject it (session is already revoked).
	if err := s.refreshTokenRepo.RevokeBySessionID(ctx, sid); err != nil {
		s.logger.Error("failed to revoke refresh tokens", "error", err)
	}
	// Stop the session's access tokens now, not when they expire.
	markSessionRevoked(ctx, s.revocations, s.revocationTTL, sid.String(), s.logger.Error)

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

	// List the sessions BEFORE revoking them: their ids are needed to revoke
	// their refresh tokens and to stop their access tokens immediately.
	sessions, listErr := s.sessionRepo.GetActiveByUserID(ctx, uid)
	if listErr != nil {
		s.logger.Error("failed to list sessions for revocation", "error", listErr)
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
		for _, sess := range sessions {
			if !sess.ID().Equals(exceptSid) {
				if err := s.refreshTokenRepo.RevokeBySessionID(ctx, sess.ID()); err != nil {
					s.logger.Error("failed to revoke refresh tokens for session", "error", err)
				}
			}
		}
		// Note: When except session exists, user is keeping one active session
		// so we don't invalidate cache (they're still logged in on that device)
	}
	for _, sess := range sessions {
		if !sess.ID().Equals(exceptSid) {
			markSessionRevoked(ctx, s.revocations, s.revocationTTL, sess.ID().String(), s.logger.Error)
		}
	}

	s.logger.Info("all sessions revoked", "user_id", userID, "except", exceptSessionID)
	return nil
}

// RevokeSessionsIssuedBy ends the user's sessions whose sign-in was asserted
// by tenantID's own identity provider (Session.IDPTenantID): that
// organization's assertion was the only proof of identity behind them, so
// they end when the organization removes the person. Every other session
// (password, social login, another organization's IdP) stays: the
// organization's own data is closed to it by the per-request membership
// check, and it is not this organization's to end. Returns how many sessions
// were revoked.
func (s *SessionService) RevokeSessionsIssuedBy(ctx context.Context, userID, tenantID string) (int, error) {
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return 0, fmt.Errorf("invalid user id: %w", err)
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("invalid tenant id: %w", err)
	}
	sessions, err := s.sessionRepo.GetActiveByUserID(ctx, uid)
	if err != nil {
		return 0, fmt.Errorf("list sessions: %w", err)
	}
	revoked := 0
	for _, sess := range sessions {
		if !sess.IDPTenantID().Equals(tid) {
			continue
		}
		if err := s.RevokeSession(ctx, userID, sess.ID().String()); err != nil {
			return revoked, err
		}
		revoked++
	}
	return revoked, nil
}

// ValidateSession checks if a session is valid.
func (s *SessionService) ValidateSession(ctx context.Context, sessionID string) (*sessiondom.Session, error) {
	id, err := shared.IDFromString(sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session id: %w", err)
	}

	sess, err := s.sessionRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if !sess.IsActive() {
		return nil, sessiondom.ErrSessionExpired
	}

	return sess, nil
}

// GetSessionByAccessToken retrieves a session by its access token.
func (s *SessionService) GetSessionByAccessToken(ctx context.Context, accessToken string) (*sessiondom.Session, error) {
	hash := sessiondom.HashToken(accessToken)
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

	if s.mfaChallenges != nil {
		if n, err := s.mfaChallenges.DeleteExpiredChallenges(ctx); err != nil {
			s.logger.Error("failed to delete expired 2FA challenges", "error", err)
		} else if n > 0 {
			s.logger.Info("cleaned up expired 2FA challenges", "deleted", n)
		}
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
