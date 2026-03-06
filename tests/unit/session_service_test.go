package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Session Repository
// =============================================================================

type mockSessionRepo struct {
	sessions map[string]*session.Session

	// Error overrides
	createErr            error
	getByIDErr           error
	getByTokenErr        error
	getActiveErr         error
	updateErr            error
	deleteErr            error
	revokeAllErr         error
	revokeAllExceptErr   error
	countActiveErr       error
	getOldestErr         error
	deleteExpiredErr     error

	// Result overrides
	countActiveResult    int
	deleteExpiredResult  int64

	// Call tracking
	createCalls          int
	getByIDCalls         int
	updateCalls          int
	revokeAllCalls       int
	revokeAllExceptCalls int
	deleteExpiredCalls   int
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{
		sessions: make(map[string]*session.Session),
	}
}

func (m *mockSessionRepo) Create(_ context.Context, s *session.Session) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.sessions[s.ID().String()] = s
	return nil
}

func (m *mockSessionRepo) GetByID(_ context.Context, id shared.ID) (*session.Session, error) {
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	s, ok := m.sessions[id.String()]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	return s, nil
}

func (m *mockSessionRepo) GetByAccessTokenHash(_ context.Context, hash string) (*session.Session, error) {
	if m.getByTokenErr != nil {
		return nil, m.getByTokenErr
	}
	for _, s := range m.sessions {
		if s.AccessTokenHash() == hash {
			return s, nil
		}
	}
	return nil, session.ErrSessionNotFound
}

func (m *mockSessionRepo) GetActiveByUserID(_ context.Context, userID shared.ID) ([]*session.Session, error) {
	if m.getActiveErr != nil {
		return nil, m.getActiveErr
	}
	result := make([]*session.Session, 0)
	for _, s := range m.sessions {
		if s.UserID().Equals(userID) && s.IsActive() {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockSessionRepo) Update(_ context.Context, s *session.Session) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sessions[s.ID().String()] = s
	return nil
}

func (m *mockSessionRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sessions, id.String())
	return nil
}

func (m *mockSessionRepo) RevokeAllByUserID(_ context.Context, _ shared.ID) error {
	m.revokeAllCalls++
	if m.revokeAllErr != nil {
		return m.revokeAllErr
	}
	return nil
}

func (m *mockSessionRepo) RevokeAllByUserIDExcept(_ context.Context, _ shared.ID, _ shared.ID) error {
	m.revokeAllExceptCalls++
	if m.revokeAllExceptErr != nil {
		return m.revokeAllExceptErr
	}
	return nil
}

func (m *mockSessionRepo) CountActiveByUserID(_ context.Context, _ shared.ID) (int, error) {
	if m.countActiveErr != nil {
		return 0, m.countActiveErr
	}
	return m.countActiveResult, nil
}

func (m *mockSessionRepo) GetOldestActiveByUserID(_ context.Context, _ shared.ID) (*session.Session, error) {
	if m.getOldestErr != nil {
		return nil, m.getOldestErr
	}
	return nil, nil
}

func (m *mockSessionRepo) DeleteExpired(_ context.Context) (int64, error) {
	m.deleteExpiredCalls++
	if m.deleteExpiredErr != nil {
		return 0, m.deleteExpiredErr
	}
	return m.deleteExpiredResult, nil
}

// =============================================================================
// Mock Refresh Token Repository
// =============================================================================

type mockRefreshTokenRepo struct {
	tokens map[string]*session.RefreshToken

	// Error overrides
	createErr         error
	getByIDErr        error
	getByTokenHashErr error
	getByFamilyErr    error
	updateErr         error
	deleteErr         error
	revokeByFamilyErr error
	revokeBySessionErr error
	revokeByUserErr   error
	deleteExpiredErr  error

	// Result overrides
	deleteExpiredResult int64

	// Call tracking
	revokeBySessionCalls int
	revokeByUserCalls    int
	deleteExpiredCalls   int
}

func newMockRefreshTokenRepo() *mockRefreshTokenRepo {
	return &mockRefreshTokenRepo{
		tokens: make(map[string]*session.RefreshToken),
	}
}

func (m *mockRefreshTokenRepo) Create(_ context.Context, t *session.RefreshToken) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.tokens[t.ID().String()] = t
	return nil
}

func (m *mockRefreshTokenRepo) GetByID(_ context.Context, id shared.ID) (*session.RefreshToken, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	t, ok := m.tokens[id.String()]
	if !ok {
		return nil, session.ErrRefreshTokenNotFound
	}
	return t, nil
}

func (m *mockRefreshTokenRepo) GetByTokenHash(_ context.Context, _ string) (*session.RefreshToken, error) {
	if m.getByTokenHashErr != nil {
		return nil, m.getByTokenHashErr
	}
	return nil, session.ErrRefreshTokenNotFound
}

func (m *mockRefreshTokenRepo) GetByFamily(_ context.Context, _ shared.ID) ([]*session.RefreshToken, error) {
	if m.getByFamilyErr != nil {
		return nil, m.getByFamilyErr
	}
	return nil, nil
}

func (m *mockRefreshTokenRepo) Update(_ context.Context, _ *session.RefreshToken) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	return nil
}

func (m *mockRefreshTokenRepo) Delete(_ context.Context, _ shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *mockRefreshTokenRepo) RevokeByFamily(_ context.Context, _ shared.ID) error {
	if m.revokeByFamilyErr != nil {
		return m.revokeByFamilyErr
	}
	return nil
}

func (m *mockRefreshTokenRepo) RevokeBySessionID(_ context.Context, _ shared.ID) error {
	m.revokeBySessionCalls++
	if m.revokeBySessionErr != nil {
		return m.revokeBySessionErr
	}
	return nil
}

func (m *mockRefreshTokenRepo) RevokeByUserID(_ context.Context, _ shared.ID) error {
	m.revokeByUserCalls++
	if m.revokeByUserErr != nil {
		return m.revokeByUserErr
	}
	return nil
}

func (m *mockRefreshTokenRepo) DeleteExpired(_ context.Context) (int64, error) {
	m.deleteExpiredCalls++
	if m.deleteExpiredErr != nil {
		return 0, m.deleteExpiredErr
	}
	return m.deleteExpiredResult, nil
}

// =============================================================================
// Helper: create a SessionService for testing
// =============================================================================

func newTestSessionService() (*app.SessionService, *mockSessionRepo, *mockRefreshTokenRepo) {
	sessRepo := newMockSessionRepo()
	rtRepo := newMockRefreshTokenRepo()
	log := logger.NewNop()
	svc := app.NewSessionService(sessRepo, rtRepo, log)
	return svc, sessRepo, rtRepo
}

// Helper: create and store an active session in the mock repo.
func seedActiveSession(repo *mockSessionRepo, userID shared.ID) *session.Session {
	s, _ := session.New(userID, "access-token-"+shared.NewID().String(), "127.0.0.1", "TestBrowser/1.0", 24*time.Hour)
	repo.sessions[s.ID().String()] = s
	return s
}

// Helper: create and store a revoked session in the mock repo.
func seedRevokedSession(repo *mockSessionRepo, userID shared.ID) *session.Session {
	s, _ := session.New(userID, "access-token-"+shared.NewID().String(), "127.0.0.1", "TestBrowser/1.0", 24*time.Hour)
	_ = s.Revoke()
	repo.sessions[s.ID().String()] = s
	return s
}

// Helper: create and store an expired session in the mock repo.
func seedExpiredSession(repo *mockSessionRepo, userID shared.ID) *session.Session {
	now := time.Now()
	s := session.Reconstitute(
		shared.NewID(),
		userID,
		"hash-expired",
		"127.0.0.1",
		"TestBrowser/1.0",
		"",
		now.Add(-1*time.Hour), // expired 1 hour ago
		now.Add(-2*time.Hour),
		session.StatusActive,
		now.Add(-24*time.Hour),
		now.Add(-24*time.Hour),
	)
	repo.sessions[s.ID().String()] = s
	return s
}

// =============================================================================
// ValidateSession Tests (maps to "CreateSession - success, validation" + "GetSession")
// =============================================================================

func TestValidateSession_Success(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()
	sess := seedActiveSession(repo, userID)

	result, err := svc.ValidateSession(context.Background(), sess.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected session, got nil")
	}
	if !result.ID().Equals(sess.ID()) {
		t.Errorf("expected session ID %s, got %s", sess.ID(), result.ID())
	}
}

func TestValidateSession_NotFound(t *testing.T) {
	svc, _, _ := newTestSessionService()

	_, err := svc.ValidateSession(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for session not found")
	}
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestValidateSession_Expired(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()
	sess := seedExpiredSession(repo, userID)

	_, err := svc.ValidateSession(context.Background(), sess.ID().String())
	if err == nil {
		t.Fatal("expected error for expired session")
	}
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestValidateSession_Revoked(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()
	sess := seedRevokedSession(repo, userID)

	_, err := svc.ValidateSession(context.Background(), sess.ID().String())
	if err == nil {
		t.Fatal("expected error for revoked session")
	}
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestValidateSession_InvalidID(t *testing.T) {
	svc, _, _ := newTestSessionService()

	_, err := svc.ValidateSession(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid session ID")
	}
}

// =============================================================================
// RevokeSession Tests
// =============================================================================

func TestRevokeSession_Success(t *testing.T) {
	svc, repo, rtRepo := newTestSessionService()
	userID := shared.NewID()
	sess := seedActiveSession(repo, userID)

	err := svc.RevokeSession(context.Background(), userID.String(), sess.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify session was updated (revoked)
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 update call, got %d", repo.updateCalls)
	}

	// Verify refresh tokens were revoked for this session
	if rtRepo.revokeBySessionCalls != 1 {
		t.Errorf("expected 1 RevokeBySessionID call, got %d", rtRepo.revokeBySessionCalls)
	}
}

func TestRevokeSession_NotFound(t *testing.T) {
	svc, _, _ := newTestSessionService()
	userID := shared.NewID()

	err := svc.RevokeSession(context.Background(), userID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for session not found")
	}
}

func TestRevokeSession_BelongsToDifferentUser(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	ownerUserID := shared.NewID()
	otherUserID := shared.NewID()
	sess := seedActiveSession(repo, ownerUserID)

	err := svc.RevokeSession(context.Background(), otherUserID.String(), sess.ID().String())
	if err == nil {
		t.Fatal("expected error when revoking another user's session")
	}
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestRevokeSession_InvalidUserID(t *testing.T) {
	svc, _, _ := newTestSessionService()

	err := svc.RevokeSession(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
}

func TestRevokeSession_InvalidSessionID(t *testing.T) {
	svc, _, _ := newTestSessionService()

	err := svc.RevokeSession(context.Background(), shared.NewID().String(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid session ID")
	}
}

func TestRevokeSession_UpdateError(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()
	sess := seedActiveSession(repo, userID)
	repo.updateErr = errors.New("db error")

	err := svc.RevokeSession(context.Background(), userID.String(), sess.ID().String())
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// =============================================================================
// RevokeAllSessions Tests
// =============================================================================

func TestRevokeAllSessions_NoExcept(t *testing.T) {
	svc, repo, rtRepo := newTestSessionService()
	userID := shared.NewID()

	err := svc.RevokeAllSessions(context.Background(), userID.String(), "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.revokeAllCalls != 1 {
		t.Errorf("expected 1 RevokeAllByUserID call, got %d", repo.revokeAllCalls)
	}

	if rtRepo.revokeByUserCalls != 1 {
		t.Errorf("expected 1 RevokeByUserID call, got %d", rtRepo.revokeByUserCalls)
	}
}

func TestRevokeAllSessions_WithExcept(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()
	currentSess := seedActiveSession(repo, userID)

	err := svc.RevokeAllSessions(context.Background(), userID.String(), currentSess.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.revokeAllExceptCalls != 1 {
		t.Errorf("expected 1 RevokeAllByUserIDExcept call, got %d", repo.revokeAllExceptCalls)
	}

	// Should NOT call RevokeAllByUserID when except is provided
	if repo.revokeAllCalls != 0 {
		t.Errorf("expected 0 RevokeAllByUserID calls when except is provided, got %d", repo.revokeAllCalls)
	}
}

func TestRevokeAllSessions_InvalidUserID(t *testing.T) {
	svc, _, _ := newTestSessionService()

	err := svc.RevokeAllSessions(context.Background(), "bad", "")
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
}

func TestRevokeAllSessions_RepoError(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	repo.revokeAllErr = errors.New("db error")

	err := svc.RevokeAllSessions(context.Background(), shared.NewID().String(), "")
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestRevokeAllSessions_WithExceptRepoError(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()
	currentSess := seedActiveSession(repo, userID)
	repo.revokeAllExceptErr = errors.New("db error")

	err := svc.RevokeAllSessions(context.Background(), userID.String(), currentSess.ID().String())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// ListUserSessions Tests
// =============================================================================

func TestListUserSessions_ReturnsActiveOnly(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()

	// Seed active sessions
	s1 := seedActiveSession(repo, userID)
	seedActiveSession(repo, userID)

	// Seed a revoked session (should not appear in active list from mock)
	seedRevokedSession(repo, userID)

	// Seed expired session (should not appear via IsActive)
	seedExpiredSession(repo, userID)

	sessions, err := svc.ListUserSessions(context.Background(), userID.String(), s1.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Only 2 active sessions should be returned (revoked and expired are filtered)
	if len(sessions) != 2 {
		t.Errorf("expected 2 active sessions, got %d", len(sessions))
	}

	// Verify IsCurrent flag
	foundCurrent := false
	for _, info := range sessions {
		if info.IsCurrent {
			foundCurrent = true
			if info.ID != s1.ID().String() {
				t.Errorf("expected current session ID %s, got %s", s1.ID(), info.ID)
			}
		}
	}
	if !foundCurrent {
		t.Error("expected one session marked as current")
	}
}

func TestListUserSessions_InvalidUserID(t *testing.T) {
	svc, _, _ := newTestSessionService()

	_, err := svc.ListUserSessions(context.Background(), "bad-id", "")
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
}

func TestListUserSessions_Empty(t *testing.T) {
	svc, _, _ := newTestSessionService()
	userID := shared.NewID()

	sessions, err := svc.ListUserSessions(context.Background(), userID.String(), "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestListUserSessions_RepoError(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	repo.getActiveErr = errors.New("db error")

	_, err := svc.ListUserSessions(context.Background(), shared.NewID().String(), "")
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// GetSessionByAccessToken Tests
// =============================================================================

func TestGetSessionByAccessToken_Success(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()
	accessToken := "my-secret-access-token"
	sess, _ := session.New(userID, accessToken, "10.0.0.1", "Chrome/120", 24*time.Hour)
	repo.sessions[sess.ID().String()] = sess

	found, err := svc.GetSessionByAccessToken(context.Background(), accessToken)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !found.ID().Equals(sess.ID()) {
		t.Errorf("expected session ID %s, got %s", sess.ID(), found.ID())
	}
}

func TestGetSessionByAccessToken_NotFound(t *testing.T) {
	svc, _, _ := newTestSessionService()

	_, err := svc.GetSessionByAccessToken(context.Background(), "unknown-token")
	if err == nil {
		t.Fatal("expected error for unknown access token")
	}
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

// =============================================================================
// UpdateSessionActivity Tests
// =============================================================================

func TestUpdateSessionActivity_Success(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	userID := shared.NewID()
	sess := seedActiveSession(repo, userID)
	originalActivity := sess.LastActivityAt()

	// Small delay to ensure time difference
	time.Sleep(time.Millisecond)

	err := svc.UpdateSessionActivity(context.Background(), sess.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify update was called
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 update call, got %d", repo.updateCalls)
	}

	// Verify activity timestamp was updated
	updated := repo.sessions[sess.ID().String()]
	if !updated.LastActivityAt().After(originalActivity) {
		t.Error("expected LastActivityAt to be updated")
	}
}

func TestUpdateSessionActivity_NotFound(t *testing.T) {
	svc, _, _ := newTestSessionService()

	err := svc.UpdateSessionActivity(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for session not found")
	}
}

func TestUpdateSessionActivity_InvalidID(t *testing.T) {
	svc, _, _ := newTestSessionService()

	err := svc.UpdateSessionActivity(context.Background(), "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid session ID")
	}
}

// =============================================================================
// CleanupExpiredSessions Tests
// =============================================================================

func TestCleanupExpiredSessions_Success(t *testing.T) {
	svc, repo, rtRepo := newTestSessionService()
	repo.deleteExpiredResult = 5
	rtRepo.deleteExpiredResult = 3

	sessDeleted, tokensDeleted, err := svc.CleanupExpiredSessions(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sessDeleted != 5 {
		t.Errorf("expected 5 sessions deleted, got %d", sessDeleted)
	}
	if tokensDeleted != 3 {
		t.Errorf("expected 3 tokens deleted, got %d", tokensDeleted)
	}
	if repo.deleteExpiredCalls != 1 {
		t.Errorf("expected 1 DeleteExpired call on session repo, got %d", repo.deleteExpiredCalls)
	}
	if rtRepo.deleteExpiredCalls != 1 {
		t.Errorf("expected 1 DeleteExpired call on token repo, got %d", rtRepo.deleteExpiredCalls)
	}
}

func TestCleanupExpiredSessions_NoExpired(t *testing.T) {
	svc, repo, rtRepo := newTestSessionService()
	repo.deleteExpiredResult = 0
	rtRepo.deleteExpiredResult = 0

	sessDeleted, tokensDeleted, err := svc.CleanupExpiredSessions(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sessDeleted != 0 {
		t.Errorf("expected 0 sessions deleted, got %d", sessDeleted)
	}
	if tokensDeleted != 0 {
		t.Errorf("expected 0 tokens deleted, got %d", tokensDeleted)
	}
}

func TestCleanupExpiredSessions_SessionRepoError(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	repo.deleteExpiredErr = errors.New("db error")

	_, _, err := svc.CleanupExpiredSessions(context.Background())
	if err == nil {
		t.Fatal("expected error from session repo")
	}
}

func TestCleanupExpiredSessions_TokenRepoError(t *testing.T) {
	svc, repo, rtRepo := newTestSessionService()
	repo.deleteExpiredResult = 2
	rtRepo.deleteExpiredErr = errors.New("db error")

	sessDeleted, _, err := svc.CleanupExpiredSessions(context.Background())
	if err == nil {
		t.Fatal("expected error from token repo")
	}
	// Sessions should still be reported as deleted
	if sessDeleted != 2 {
		t.Errorf("expected 2 sessions deleted before token error, got %d", sessDeleted)
	}
}

// =============================================================================
// CountActiveSessions Tests
// =============================================================================

func TestCountActiveSessions_Success(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	repo.countActiveResult = 3

	count, err := svc.CountActiveSessions(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

func TestCountActiveSessions_InvalidUserID(t *testing.T) {
	svc, _, _ := newTestSessionService()

	_, err := svc.CountActiveSessions(context.Background(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
}

func TestCountActiveSessions_Zero(t *testing.T) {
	svc, repo, _ := newTestSessionService()
	repo.countActiveResult = 0

	count, err := svc.CountActiveSessions(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

// =============================================================================
// Session Entity Tests (additional coverage for domain logic)
// =============================================================================

func TestSessionEntity_New_Success(t *testing.T) {
	userID := shared.NewID()
	s, err := session.New(userID, "my-token", "10.0.0.1", "Firefox/120", 30*time.Minute)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !s.UserID().Equals(userID) {
		t.Errorf("expected user ID %s, got %s", userID, s.UserID())
	}
	if s.IPAddress() != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", s.IPAddress())
	}
	if s.UserAgent() != "Firefox/120" {
		t.Errorf("expected user agent Firefox/120, got %s", s.UserAgent())
	}
	if !s.IsActive() {
		t.Error("new session should be active")
	}
	if s.Status() != session.StatusActive {
		t.Errorf("expected status active, got %s", s.Status())
	}
}

func TestSessionEntity_New_EmptyToken(t *testing.T) {
	_, err := session.New(shared.NewID(), "", "10.0.0.1", "Chrome", 30*time.Minute)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSessionEntity_New_ZeroUserID(t *testing.T) {
	_, err := session.New(shared.ID{}, "token", "10.0.0.1", "Chrome", 30*time.Minute)
	if err == nil {
		t.Fatal("expected error for zero user ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSessionEntity_Revoke(t *testing.T) {
	s, _ := session.New(shared.NewID(), "token", "10.0.0.1", "Chrome", 30*time.Minute)

	err := s.Revoke()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if s.Status() != session.StatusRevoked {
		t.Errorf("expected status revoked, got %s", s.Status())
	}
	if s.IsActive() {
		t.Error("revoked session should not be active")
	}
}

func TestSessionEntity_RevokeAlreadyRevoked(t *testing.T) {
	s, _ := session.New(shared.NewID(), "token", "10.0.0.1", "Chrome", 30*time.Minute)
	_ = s.Revoke()

	err := s.Revoke()
	if err == nil {
		t.Fatal("expected error for already revoked session")
	}
	if !errors.Is(err, session.ErrSessionRevoked) {
		t.Errorf("expected ErrSessionRevoked, got %v", err)
	}
}

func TestSessionEntity_VerifyToken(t *testing.T) {
	token := "my-secret-token"
	s, _ := session.New(shared.NewID(), token, "10.0.0.1", "Chrome", 30*time.Minute)

	if !s.VerifyToken(token) {
		t.Error("expected VerifyToken to return true for correct token")
	}
	if s.VerifyToken("wrong-token") {
		t.Error("expected VerifyToken to return false for wrong token")
	}
}

func TestSessionEntity_UpdateActivity(t *testing.T) {
	s, _ := session.New(shared.NewID(), "token", "10.0.0.1", "Chrome", 30*time.Minute)
	before := s.LastActivityAt()

	time.Sleep(time.Millisecond)
	s.UpdateActivity()

	if !s.LastActivityAt().After(before) {
		t.Error("expected LastActivityAt to be updated")
	}
}

func TestSessionEntity_IsExpired(t *testing.T) {
	now := time.Now()
	// Create an expired session via Reconstitute
	s := session.Reconstitute(
		shared.NewID(),
		shared.NewID(),
		"hash",
		"10.0.0.1",
		"Chrome",
		"",
		now.Add(-1*time.Hour), // already expired
		now.Add(-2*time.Hour),
		session.StatusActive,
		now.Add(-24*time.Hour),
		now.Add(-24*time.Hour),
	)

	if !s.IsExpired() {
		t.Error("session should be expired")
	}
	if s.IsActive() {
		t.Error("expired session should not be active even if status is active")
	}
}
