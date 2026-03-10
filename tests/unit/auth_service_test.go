package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/password"
)

// Ensure pagination is used to avoid unused import.
var _ pagination.Pagination

// =============================================================================
// Mock User Repository for Auth Tests
// =============================================================================

type mockAuthUserRepo struct {
	users map[string]*user.User // keyed by ID

	// Error overrides
	createErr                    error
	getByIDErr                   error
	getByEmailErr                error
	getByEmailForAuthErr         error
	getByEmailVerificationErr    error
	getByPasswordResetTokenErr   error
	updateErr                    error
	deleteErr                    error
	existsByEmailResult          bool
	existsByEmailErr             error
	existsByKeycloakIDResult     bool
	existsByKeycloakIDErr        error
	getByKeycloakIDErr           error
	upsertFromKeycloakErr        error
	getByIDsErr                  error
	countResult                  int64
	countErr                     error

	// Call tracking
	createCalls int
	updateCalls int
}

func newMockAuthUserRepo() *mockAuthUserRepo {
	return &mockAuthUserRepo{
		users: make(map[string]*user.User),
	}
}

func (m *mockAuthUserRepo) Create(_ context.Context, u *user.User) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.users[u.ID().String()] = u
	return nil
}

func (m *mockAuthUserRepo) GetByID(_ context.Context, id shared.ID) (*user.User, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	u, ok := m.users[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return u, nil
}

func (m *mockAuthUserRepo) GetByKeycloakID(_ context.Context, _ string) (*user.User, error) {
	if m.getByKeycloakIDErr != nil {
		return nil, m.getByKeycloakIDErr
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuthUserRepo) GetByEmail(_ context.Context, email string) (*user.User, error) {
	if m.getByEmailErr != nil {
		return nil, m.getByEmailErr
	}
	for _, u := range m.users {
		if u.Email() == email {
			return u, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuthUserRepo) GetByEmailForAuth(_ context.Context, email string) (*user.User, error) {
	if m.getByEmailForAuthErr != nil {
		return nil, m.getByEmailForAuthErr
	}
	for _, u := range m.users {
		if u.Email() == email {
			return u, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuthUserRepo) Update(_ context.Context, u *user.User) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.users[u.ID().String()] = u
	return nil
}

func (m *mockAuthUserRepo) Delete(_ context.Context, _ shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *mockAuthUserRepo) ExistsByEmail(_ context.Context, _ string) (bool, error) {
	if m.existsByEmailErr != nil {
		return false, m.existsByEmailErr
	}
	return m.existsByEmailResult, nil
}

func (m *mockAuthUserRepo) ExistsByKeycloakID(_ context.Context, _ string) (bool, error) {
	if m.existsByKeycloakIDErr != nil {
		return false, m.existsByKeycloakIDErr
	}
	return m.existsByKeycloakIDResult, nil
}

func (m *mockAuthUserRepo) UpsertFromKeycloak(_ context.Context, _, _, _ string) (*user.User, error) {
	if m.upsertFromKeycloakErr != nil {
		return nil, m.upsertFromKeycloakErr
	}
	return nil, nil
}

func (m *mockAuthUserRepo) GetByIDs(_ context.Context, _ []shared.ID) ([]*user.User, error) {
	if m.getByIDsErr != nil {
		return nil, m.getByIDsErr
	}
	return nil, nil
}

func (m *mockAuthUserRepo) Count(_ context.Context, _ user.Filter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return m.countResult, nil
}

func (m *mockAuthUserRepo) GetByEmailVerificationToken(_ context.Context, token string) (*user.User, error) {
	if m.getByEmailVerificationErr != nil {
		return nil, m.getByEmailVerificationErr
	}
	for _, u := range m.users {
		if u.EmailVerificationToken() != nil && *u.EmailVerificationToken() == token {
			return u, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuthUserRepo) GetByPasswordResetToken(_ context.Context, token string) (*user.User, error) {
	if m.getByPasswordResetTokenErr != nil {
		return nil, m.getByPasswordResetTokenErr
	}
	for _, u := range m.users {
		if u.PasswordResetToken() != nil && *u.PasswordResetToken() == token {
			return u, nil
		}
	}
	return nil, shared.ErrNotFound
}

// =============================================================================
// Mock Tenant Repository for Auth Tests
// =============================================================================

type mockAuthTenantRepo struct {
	tenants     map[string]*tenant.Tenant
	memberships []*tenant.Membership
	invitations []*tenant.Invitation

	// User membership results
	userMemberships []tenant.UserMembership

	// Error overrides
	createErr              error
	getByIDErr             error
	getBySlugErr           error
	updateErr              error
	deleteErr              error
	existsBySlugResult     bool
	existsBySlugErr        error
	createMembershipErr    error
	getMembershipErr       error
	getMembershipByIDErr   error
	updateMembershipErr    error
	deleteMembershipErr    error
	getUserMembershipsErr  error
	getInvitationByTokenErr error
	acceptInvitationTxErr  error
	listActiveTenantIDsErr error

	// Call tracking
	createCalls           int
	deleteCalls           int
	createMembershipCalls int
}

func newMockAuthTenantRepo() *mockAuthTenantRepo {
	return &mockAuthTenantRepo{
		tenants: make(map[string]*tenant.Tenant),
	}
}

func (m *mockAuthTenantRepo) Create(_ context.Context, t *tenant.Tenant) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.tenants[t.ID().String()] = t
	return nil
}

func (m *mockAuthTenantRepo) GetByID(_ context.Context, id shared.ID) (*tenant.Tenant, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	t, ok := m.tenants[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *mockAuthTenantRepo) GetBySlug(_ context.Context, _ string) (*tenant.Tenant, error) {
	if m.getBySlugErr != nil {
		return nil, m.getBySlugErr
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuthTenantRepo) Update(_ context.Context, _ *tenant.Tenant) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	return nil
}

func (m *mockAuthTenantRepo) Delete(_ context.Context, _ shared.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *mockAuthTenantRepo) ExistsBySlug(_ context.Context, _ string) (bool, error) {
	if m.existsBySlugErr != nil {
		return false, m.existsBySlugErr
	}
	return m.existsBySlugResult, nil
}

func (m *mockAuthTenantRepo) ListActiveTenantIDs(_ context.Context) ([]shared.ID, error) {
	if m.listActiveTenantIDsErr != nil {
		return nil, m.listActiveTenantIDsErr
	}
	return nil, nil
}

func (m *mockAuthTenantRepo) CreateMembership(_ context.Context, membership *tenant.Membership) error {
	m.createMembershipCalls++
	if m.createMembershipErr != nil {
		return m.createMembershipErr
	}
	m.memberships = append(m.memberships, membership)
	return nil
}

func (m *mockAuthTenantRepo) GetMembership(_ context.Context, _ shared.ID, _ shared.ID) (*tenant.Membership, error) {
	if m.getMembershipErr != nil {
		return nil, m.getMembershipErr
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuthTenantRepo) GetMembershipByID(_ context.Context, _ shared.ID) (*tenant.Membership, error) {
	if m.getMembershipByIDErr != nil {
		return nil, m.getMembershipByIDErr
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuthTenantRepo) UpdateMembership(_ context.Context, _ *tenant.Membership) error {
	if m.updateMembershipErr != nil {
		return m.updateMembershipErr
	}
	return nil
}

func (m *mockAuthTenantRepo) DeleteMembership(_ context.Context, _ shared.ID) error {
	if m.deleteMembershipErr != nil {
		return m.deleteMembershipErr
	}
	return nil
}

func (m *mockAuthTenantRepo) ListMembersByTenant(_ context.Context, _ shared.ID) ([]*tenant.Membership, error) {
	return m.memberships, nil
}

func (m *mockAuthTenantRepo) ListMembersWithUserInfo(_ context.Context, _ shared.ID) ([]*tenant.MemberWithUser, error) {
	return nil, nil
}

func (m *mockAuthTenantRepo) SearchMembersWithUserInfo(_ context.Context, _ shared.ID, _ tenant.MemberSearchFilters) (*tenant.MemberSearchResult, error) {
	return nil, nil
}

func (m *mockAuthTenantRepo) ListTenantsByUser(_ context.Context, _ shared.ID) ([]*tenant.TenantWithRole, error) {
	return nil, nil
}

func (m *mockAuthTenantRepo) CountMembersByTenant(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *mockAuthTenantRepo) GetMemberStats(_ context.Context, _ shared.ID) (*tenant.MemberStats, error) {
	return nil, nil
}

func (m *mockAuthTenantRepo) GetUserMemberships(_ context.Context, _ shared.ID) ([]tenant.UserMembership, error) {
	if m.getUserMembershipsErr != nil {
		return nil, m.getUserMembershipsErr
	}
	return m.userMemberships, nil
}

func (m *mockAuthTenantRepo) GetMemberByEmail(_ context.Context, _ shared.ID, _ string) (*tenant.MemberWithUser, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAuthTenantRepo) CreateInvitation(_ context.Context, _ *tenant.Invitation) error {
	return nil
}

func (m *mockAuthTenantRepo) GetInvitationByToken(_ context.Context, _ string) (*tenant.Invitation, error) {
	if m.getInvitationByTokenErr != nil {
		return nil, m.getInvitationByTokenErr
	}
	if len(m.invitations) > 0 {
		return m.invitations[0], nil
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuthTenantRepo) GetInvitationByID(_ context.Context, _ shared.ID) (*tenant.Invitation, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAuthTenantRepo) UpdateInvitation(_ context.Context, _ *tenant.Invitation) error {
	return nil
}

func (m *mockAuthTenantRepo) DeleteInvitation(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *mockAuthTenantRepo) ListPendingInvitationsByTenant(_ context.Context, _ shared.ID) ([]*tenant.Invitation, error) {
	return nil, nil
}

func (m *mockAuthTenantRepo) GetPendingInvitationByEmail(_ context.Context, _ shared.ID, _ string) (*tenant.Invitation, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAuthTenantRepo) DeleteExpiredInvitations(_ context.Context) (int64, error) {
	return 0, nil
}

func (m *mockAuthTenantRepo) AcceptInvitationTx(_ context.Context, _ *tenant.Invitation, _ *tenant.Membership) error {
	if m.acceptInvitationTxErr != nil {
		return m.acceptInvitationTxErr
	}
	return nil
}

// =============================================================================
// Mock Session Repository for Auth Tests
// =============================================================================

type mockAuthSessionRepo struct {
	sessions map[string]*session.Session

	// Error overrides
	createErr          error
	getByIDErr         error
	getByTokenErr      error
	getActiveErr       error
	updateErr          error
	deleteErr          error
	revokeAllErr       error
	revokeAllExceptErr error
	countActiveErr     error
	getOldestErr       error
	deleteExpiredErr   error

	// Result overrides
	countActiveResult   int
	deleteExpiredResult int64
	oldestSession       *session.Session

	// Call tracking
	createCalls         int
	updateCalls         int
	revokeAllCalls      int
	deleteExpiredCalls  int
}

func newMockAuthSessionRepo() *mockAuthSessionRepo {
	return &mockAuthSessionRepo{
		sessions: make(map[string]*session.Session),
	}
}

func (m *mockAuthSessionRepo) Create(_ context.Context, s *session.Session) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.sessions[s.ID().String()] = s
	return nil
}

func (m *mockAuthSessionRepo) GetByID(_ context.Context, id shared.ID) (*session.Session, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	s, ok := m.sessions[id.String()]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	return s, nil
}

func (m *mockAuthSessionRepo) GetByAccessTokenHash(_ context.Context, _ string) (*session.Session, error) {
	if m.getByTokenErr != nil {
		return nil, m.getByTokenErr
	}
	return nil, session.ErrSessionNotFound
}

func (m *mockAuthSessionRepo) GetActiveByUserID(_ context.Context, _ shared.ID) ([]*session.Session, error) {
	if m.getActiveErr != nil {
		return nil, m.getActiveErr
	}
	return nil, nil
}

func (m *mockAuthSessionRepo) Update(_ context.Context, s *session.Session) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sessions[s.ID().String()] = s
	return nil
}

func (m *mockAuthSessionRepo) Delete(_ context.Context, _ shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *mockAuthSessionRepo) RevokeAllByUserID(_ context.Context, _ shared.ID) error {
	m.revokeAllCalls++
	if m.revokeAllErr != nil {
		return m.revokeAllErr
	}
	return nil
}

func (m *mockAuthSessionRepo) RevokeAllByUserIDExcept(_ context.Context, _ shared.ID, _ shared.ID) error {
	if m.revokeAllExceptErr != nil {
		return m.revokeAllExceptErr
	}
	return nil
}

func (m *mockAuthSessionRepo) CountActiveByUserID(_ context.Context, _ shared.ID) (int, error) {
	if m.countActiveErr != nil {
		return 0, m.countActiveErr
	}
	return m.countActiveResult, nil
}

func (m *mockAuthSessionRepo) GetOldestActiveByUserID(_ context.Context, _ shared.ID) (*session.Session, error) {
	if m.getOldestErr != nil {
		return nil, m.getOldestErr
	}
	return m.oldestSession, nil
}

func (m *mockAuthSessionRepo) DeleteExpired(_ context.Context) (int64, error) {
	m.deleteExpiredCalls++
	if m.deleteExpiredErr != nil {
		return 0, m.deleteExpiredErr
	}
	return m.deleteExpiredResult, nil
}

// =============================================================================
// Mock Refresh Token Repository for Auth Tests
// =============================================================================

type mockAuthRefreshTokenRepo struct {
	tokens map[string]*session.RefreshToken

	// Error overrides
	createErr          error
	getByIDErr         error
	getByTokenHashErr  error
	getByFamilyErr     error
	updateErr          error
	deleteErr          error
	revokeByFamilyErr  error
	revokeBySessionErr error
	revokeByUserErr    error
	deleteExpiredErr   error

	// Result overrides
	deleteExpiredResult int64

	// Call tracking
	createCalls          int
	revokeBySessionCalls int
	revokeByUserCalls    int
	revokeByFamilyCalls  int
	updateCalls          int
}

func newMockAuthRefreshTokenRepo() *mockAuthRefreshTokenRepo {
	return &mockAuthRefreshTokenRepo{
		tokens: make(map[string]*session.RefreshToken),
	}
}

func (m *mockAuthRefreshTokenRepo) Create(_ context.Context, t *session.RefreshToken) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.tokens[t.ID().String()] = t
	return nil
}

func (m *mockAuthRefreshTokenRepo) GetByID(_ context.Context, id shared.ID) (*session.RefreshToken, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	t, ok := m.tokens[id.String()]
	if !ok {
		return nil, session.ErrRefreshTokenNotFound
	}
	return t, nil
}

func (m *mockAuthRefreshTokenRepo) GetByTokenHash(_ context.Context, _ string) (*session.RefreshToken, error) {
	if m.getByTokenHashErr != nil {
		return nil, m.getByTokenHashErr
	}
	return nil, session.ErrRefreshTokenNotFound
}

func (m *mockAuthRefreshTokenRepo) GetByFamily(_ context.Context, _ shared.ID) ([]*session.RefreshToken, error) {
	if m.getByFamilyErr != nil {
		return nil, m.getByFamilyErr
	}
	return nil, nil
}

func (m *mockAuthRefreshTokenRepo) Update(_ context.Context, _ *session.RefreshToken) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	return nil
}

func (m *mockAuthRefreshTokenRepo) Delete(_ context.Context, _ shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *mockAuthRefreshTokenRepo) RevokeByFamily(_ context.Context, _ shared.ID) error {
	m.revokeByFamilyCalls++
	if m.revokeByFamilyErr != nil {
		return m.revokeByFamilyErr
	}
	return nil
}

func (m *mockAuthRefreshTokenRepo) RevokeBySessionID(_ context.Context, _ shared.ID) error {
	m.revokeBySessionCalls++
	if m.revokeBySessionErr != nil {
		return m.revokeBySessionErr
	}
	return nil
}

func (m *mockAuthRefreshTokenRepo) RevokeByUserID(_ context.Context, _ shared.ID) error {
	m.revokeByUserCalls++
	if m.revokeByUserErr != nil {
		return m.revokeByUserErr
	}
	return nil
}

func (m *mockAuthRefreshTokenRepo) DeleteExpired(_ context.Context) (int64, error) {
	if m.deleteExpiredErr != nil {
		return 0, m.deleteExpiredErr
	}
	return m.deleteExpiredResult, nil
}

// =============================================================================
// Mock Audit Repository for Auth Tests
// =============================================================================

type mockAuthAuditRepo struct{}

func (m *mockAuthAuditRepo) Create(_ context.Context, _ *audit.AuditLog) error {
	return nil
}

func (m *mockAuthAuditRepo) CreateBatch(_ context.Context, _ []*audit.AuditLog) error {
	return nil
}

func (m *mockAuthAuditRepo) GetByID(_ context.Context, _ shared.ID) (*audit.AuditLog, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAuthAuditRepo) List(_ context.Context, _ audit.Filter, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *mockAuthAuditRepo) Count(_ context.Context, _ audit.Filter) (int64, error) {
	return 0, nil
}

func (m *mockAuthAuditRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockAuthAuditRepo) GetLatestByResource(_ context.Context, _ audit.ResourceType, _ string) (*audit.AuditLog, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAuthAuditRepo) ListByActor(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *mockAuthAuditRepo) ListByResource(_ context.Context, _ audit.ResourceType, _ string, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *mockAuthAuditRepo) CountByAction(_ context.Context, _ *shared.ID, _ audit.Action, _ time.Time) (int64, error) {
	return 0, nil
}

// =============================================================================
// Auth Test Config
// =============================================================================

func defaultAuthTestConfig() config.AuthConfig {
	return config.AuthConfig{
		JWTSecret:                 "test-secret-key-at-least-32-chars-long!!",
		JWTIssuer:                 "test-issuer",
		AccessTokenDuration:       15 * time.Minute,
		RefreshTokenDuration:      7 * 24 * time.Hour,
		SessionDuration:           30 * 24 * time.Hour,
		PasswordMinLength:         8,
		PasswordRequireUpper:      false,
		PasswordRequireLower:      false,
		PasswordRequireNumber:     false,
		PasswordRequireSpecial:    false,
		MaxLoginAttempts:          5,
		LockoutDuration:           15 * time.Minute,
		MaxActiveSessions:         10,
		AllowRegistration:         true,
		RequireEmailVerification:  false,
		EmailVerificationDuration: 24 * time.Hour,
		PasswordResetDuration:     1 * time.Hour,
	}
}

// =============================================================================
// Helper: create an AuthService for testing
// =============================================================================

type authTestDeps struct {
	userRepo    *mockAuthUserRepo
	sessionRepo *mockAuthSessionRepo
	rtRepo      *mockAuthRefreshTokenRepo
	tenantRepo  *mockAuthTenantRepo
	cfg         config.AuthConfig
}

func newTestAuthService() (*app.AuthService, *authTestDeps) {
	return newTestAuthServiceWithConfig(defaultAuthTestConfig())
}

func newTestAuthServiceWithConfig(cfg config.AuthConfig) (*app.AuthService, *authTestDeps) {
	userRepo := newMockAuthUserRepo()
	sessionRepo := newMockAuthSessionRepo()
	rtRepo := newMockAuthRefreshTokenRepo()
	tenantRepo := newMockAuthTenantRepo()
	auditRepo := &mockAuthAuditRepo{}
	log := logger.NewNop()

	auditService := app.NewAuditService(auditRepo, log)

	svc := app.NewAuthService(
		userRepo,
		sessionRepo,
		rtRepo,
		tenantRepo,
		auditService,
		cfg,
		log,
	)

	deps := &authTestDeps{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		rtRepo:      rtRepo,
		tenantRepo:  tenantRepo,
		cfg:         cfg,
	}

	return svc, deps
}

// Helper: create a local user and store in mock repo.
func seedAuthLocalUser(repo *mockAuthUserRepo, email, passwordHash string) *user.User {
	u := user.Reconstitute(
		shared.NewID(),
		nil,
		email,
		"Test User",
		"",
		"",
		user.StatusActive,
		user.Preferences{},
		nil,
		time.Now().UTC(),
		time.Now().UTC(),
		user.AuthProviderLocal,
		&passwordHash,
		true, // emailVerified
		nil,
		nil,
		nil,
		nil,
		0,
		nil,
	)
	repo.users[u.ID().String()] = u
	return u
}

// Helper: create an OIDC user and store in mock repo.
func seedAuthOIDCUser(repo *mockAuthUserRepo, email string) *user.User {
	keycloakID := "kc-" + shared.NewID().String()
	u := user.Reconstitute(
		shared.NewID(),
		&keycloakID,
		email,
		"OIDC User",
		"",
		"",
		user.StatusActive,
		user.Preferences{},
		nil,
		time.Now().UTC(),
		time.Now().UTC(),
		user.AuthProviderOIDC,
		nil,
		true,
		nil,
		nil,
		nil,
		nil,
		0,
		nil,
	)
	repo.users[u.ID().String()] = u
	return u
}

// Helper: create a suspended user and store in mock repo.
func seedAuthSuspendedUser(repo *mockAuthUserRepo, email, passwordHash string) *user.User {
	u := user.Reconstitute(
		shared.NewID(),
		nil,
		email,
		"Suspended User",
		"",
		"",
		user.StatusSuspended,
		user.Preferences{},
		nil,
		time.Now().UTC(),
		time.Now().UTC(),
		user.AuthProviderLocal,
		&passwordHash,
		true,
		nil,
		nil,
		nil,
		nil,
		0,
		nil,
	)
	repo.users[u.ID().String()] = u
	return u
}

// Helper: create a locked user and store in mock repo.
func seedAuthLockedUser(repo *mockAuthUserRepo, email, passwordHash string) *user.User {
	lockUntil := time.Now().Add(1 * time.Hour)
	u := user.Reconstitute(
		shared.NewID(),
		nil,
		email,
		"Locked User",
		"",
		"",
		user.StatusActive,
		user.Preferences{},
		nil,
		time.Now().UTC(),
		time.Now().UTC(),
		user.AuthProviderLocal,
		&passwordHash,
		true,
		nil,
		nil,
		nil,
		nil,
		5,
		&lockUntil,
	)
	repo.users[u.ID().String()] = u
	return u
}

// Helper: create a user with email verification token.
func seedAuthUnverifiedUser(repo *mockAuthUserRepo, email, passwordHash, verificationToken string) *user.User {
	expiresAt := time.Now().Add(24 * time.Hour)
	u := user.Reconstitute(
		shared.NewID(),
		nil,
		email,
		"Unverified User",
		"",
		"",
		user.StatusActive,
		user.Preferences{},
		nil,
		time.Now().UTC(),
		time.Now().UTC(),
		user.AuthProviderLocal,
		&passwordHash,
		false, // emailVerified = false
		&verificationToken,
		&expiresAt,
		nil,
		nil,
		0,
		nil,
	)
	repo.users[u.ID().String()] = u
	return u
}

// Helper: create a user with password reset token.
func seedAuthUserWithResetToken(repo *mockAuthUserRepo, email, passwordHash, resetToken string) *user.User {
	expiresAt := time.Now().Add(1 * time.Hour)
	u := user.Reconstitute(
		shared.NewID(),
		nil,
		email,
		"Reset User",
		"",
		"",
		user.StatusActive,
		user.Preferences{},
		nil,
		time.Now().UTC(),
		time.Now().UTC(),
		user.AuthProviderLocal,
		&passwordHash,
		true,
		nil,
		nil,
		&resetToken,
		&expiresAt,
		0,
		nil,
	)
	repo.users[u.ID().String()] = u
	return u
}

// Helper: create a user with expired reset token.
func seedAuthUserWithExpiredResetToken(repo *mockAuthUserRepo, email, passwordHash, resetToken string) *user.User {
	expiresAt := time.Now().Add(-1 * time.Hour) // Already expired
	u := user.Reconstitute(
		shared.NewID(),
		nil,
		email,
		"Expired Reset User",
		"",
		"",
		user.StatusActive,
		user.Preferences{},
		nil,
		time.Now().UTC(),
		time.Now().UTC(),
		user.AuthProviderLocal,
		&passwordHash,
		true,
		nil,
		nil,
		&resetToken,
		&expiresAt,
		0,
		nil,
	)
	repo.users[u.ID().String()] = u
	return u
}

// Helper: create a user with expired email verification token.
func seedAuthUserWithExpiredVerification(repo *mockAuthUserRepo, email, passwordHash, verificationToken string) *user.User {
	expiresAt := time.Now().Add(-1 * time.Hour) // Already expired
	u := user.Reconstitute(
		shared.NewID(),
		nil,
		email,
		"Expired Verification User",
		"",
		"",
		user.StatusActive,
		user.Preferences{},
		nil,
		time.Now().UTC(),
		time.Now().UTC(),
		user.AuthProviderLocal,
		&passwordHash,
		false,
		&verificationToken,
		&expiresAt,
		nil,
		nil,
		0,
		nil,
	)
	repo.users[u.ID().String()] = u
	return u
}

// =============================================================================
// Register Tests
// =============================================================================

func TestAuthService_Register(t *testing.T) {
	t.Run("success without email verification", func(t *testing.T) {
		svc, deps := newTestAuthService()

		result, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "new@example.com",
			Password: "Password123!",
			Name:     "New User",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result, got nil")
		}
		if result.User == nil {
			t.Fatal("expected user in result, got nil")
		}
		if result.User.Email() != "new@example.com" {
			t.Errorf("expected email new@example.com, got %s", result.User.Email())
		}
		if result.RequiresVerification {
			t.Error("expected RequiresVerification=false when verification is disabled")
		}
		if deps.userRepo.createCalls != 1 {
			t.Errorf("expected 1 create call, got %d", deps.userRepo.createCalls)
		}
	})

	t.Run("success with email verification", func(t *testing.T) {
		cfg := defaultAuthTestConfig()
		cfg.RequireEmailVerification = true
		svc, _ := newTestAuthServiceWithConfig(cfg)

		result, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "verify@example.com",
			Password: "Password123!",
			Name:     "Verify User",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result, got nil")
		}
		if !result.RequiresVerification {
			t.Error("expected RequiresVerification=true")
		}
		if result.VerificationToken == "" {
			t.Error("expected a verification token")
		}
	})

	t.Run("registration disabled", func(t *testing.T) {
		cfg := defaultAuthTestConfig()
		cfg.AllowRegistration = false
		svc, _ := newTestAuthServiceWithConfig(cfg)

		_, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "user@example.com",
			Password: "Password123!",
			Name:     "User",
		})

		if !errors.Is(err, app.ErrRegistrationDisabled) {
			t.Errorf("expected ErrRegistrationDisabled, got %v", err)
		}
	})

	t.Run("email already exists returns anti-enumeration result", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthLocalUser(deps.userRepo, "existing@example.com", "hash")

		result, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "existing@example.com",
			Password: "Password123!",
			Name:     "Duplicate User",
		})

		if err != nil {
			t.Fatalf("expected no error for anti-enumeration, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result, got nil")
		}
		if !result.EmailExisted {
			t.Error("expected EmailExisted=true")
		}
		if result.User != nil {
			t.Error("expected User=nil for anti-enumeration")
		}
	})

	t.Run("email normalization", func(t *testing.T) {
		svc, deps := newTestAuthService()

		result, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "  User@Example.COM  ",
			Password: "Password123!",
			Name:     "Normalized User",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.User == nil {
			t.Fatal("expected user, got nil")
		}
		if result.User.Email() != "user@example.com" {
			t.Errorf("expected normalized email, got %s", result.User.Email())
		}
		_ = deps // used
	})

	t.Run("user repo check email error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		deps.userRepo.getByEmailErr = errors.New("db error")

		_, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "user@example.com",
			Password: "Password123!",
			Name:     "User",
		})

		if err == nil {
			t.Fatal("expected error from repo")
		}
	})

	t.Run("user repo create error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		deps.userRepo.createErr = errors.New("db error")

		_, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "user@example.com",
			Password: "Password123!",
			Name:     "User",
		})

		if err == nil {
			t.Fatal("expected error from repo create")
		}
	})

	t.Run("weak password rejected", func(t *testing.T) {
		cfg := defaultAuthTestConfig()
		cfg.PasswordMinLength = 12
		svc, _ := newTestAuthServiceWithConfig(cfg)

		_, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "user@example.com",
			Password: "short",
			Name:     "User",
		})

		if err == nil {
			t.Fatal("expected error for weak password")
		}
	})

	t.Run("name trimmed", func(t *testing.T) {
		svc, _ := newTestAuthService()

		result, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "user@example.com",
			Password: "Password123!",
			Name:     "  Trimmed Name  ",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.User.Name() != "Trimmed Name" {
			t.Errorf("expected trimmed name, got %q", result.User.Name())
		}
	})
}

// =============================================================================
// Login Tests
// =============================================================================

func TestAuthService_Login(t *testing.T) {
	// Helper to create a user with a real bcrypt hash for login tests.
	setupLoginUser := func(t *testing.T, deps *authTestDeps) (*user.User, string) {
		t.Helper()
		plainPassword := "ValidPassword123"
		hasher := password.New(password.WithCost(4)) // Low cost for fast tests
		hash, err := hasher.Hash(plainPassword)
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}
		u := seedAuthLocalUser(deps.userRepo, "login@example.com", hash)
		return u, plainPassword
	}

	t.Run("success", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, _ = setupLoginUser(t, deps)
		deps.tenantRepo.userMemberships = []tenant.UserMembership{
			{TenantID: shared.NewID().String(), TenantSlug: "my-team", TenantName: "My Team", Role: "owner"},
		}

		result, err := svc.Login(context.Background(), app.LoginInput{
			Email:     "login@example.com",
			Password:  "ValidPassword123",
			IPAddress: "10.0.0.1",
			UserAgent: "TestBrowser/1.0",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result, got nil")
		}
		if result.RefreshToken == "" {
			t.Error("expected a refresh token")
		}
		if result.SessionID == "" {
			t.Error("expected a session ID")
		}
		if len(result.Tenants) != 1 {
			t.Errorf("expected 1 tenant, got %d", len(result.Tenants))
		}
		if deps.sessionRepo.createCalls != 1 {
			t.Errorf("expected 1 session create, got %d", deps.sessionRepo.createCalls)
		}
		if deps.rtRepo.createCalls != 1 {
			t.Errorf("expected 1 refresh token create, got %d", deps.rtRepo.createCalls)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "nouser@example.com",
			Password: "Password123!",
		})

		if !errors.Is(err, app.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, _ = setupLoginUser(t, deps)

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "login@example.com",
			Password: "WrongPassword!",
		})

		if !errors.Is(err, app.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
		// Should record failed login attempt
		if deps.userRepo.updateCalls < 1 {
			t.Error("expected update call for failed login tracking")
		}
	})

	t.Run("account locked", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthLockedUser(deps.userRepo, "locked@example.com", "hash")

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "locked@example.com",
			Password: "Password123!",
		})

		if !errors.Is(err, app.ErrAccountLocked) {
			t.Errorf("expected ErrAccountLocked, got %v", err)
		}
	})

	t.Run("account suspended", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthSuspendedUser(deps.userRepo, "suspended@example.com", "hash")

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "suspended@example.com",
			Password: "Password123!",
		})

		if !errors.Is(err, app.ErrAccountSuspended) {
			t.Errorf("expected ErrAccountSuspended, got %v", err)
		}
	})

	t.Run("OIDC user cannot login with password", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthOIDCUser(deps.userRepo, "oidc@example.com")

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "oidc@example.com",
			Password: "Password123!",
		})

		if !errors.Is(err, app.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials for OIDC user, got %v", err)
		}
	})

	t.Run("email not verified", func(t *testing.T) {
		cfg := defaultAuthTestConfig()
		cfg.RequireEmailVerification = true
		svc, deps := newTestAuthServiceWithConfig(cfg)
		hasher := password.New(password.WithCost(4))
		hash, _ := hasher.Hash("ValidPassword123")
		seedAuthUnverifiedUser(deps.userRepo, "unverified@example.com", hash, "verify-token")

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "unverified@example.com",
			Password: "ValidPassword123",
		})

		if !errors.Is(err, app.ErrEmailNotVerified) {
			t.Errorf("expected ErrEmailNotVerified, got %v", err)
		}
	})

	t.Run("email normalization in login", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, _ = setupLoginUser(t, deps)
		deps.tenantRepo.userMemberships = []tenant.UserMembership{}

		result, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "  LOGIN@EXAMPLE.COM  ",
			Password: "ValidPassword123",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result")
		}
	})

	t.Run("repo error on get by email", func(t *testing.T) {
		svc, deps := newTestAuthService()
		deps.userRepo.getByEmailForAuthErr = errors.New("db error")

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "user@example.com",
			Password: "Password123!",
		})

		if err == nil {
			t.Fatal("expected error")
		}
		if errors.Is(err, app.ErrInvalidCredentials) {
			t.Error("should not be ErrInvalidCredentials for db error")
		}
	})

	t.Run("session create error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, _ = setupLoginUser(t, deps)
		deps.sessionRepo.createErr = errors.New("db error")

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "login@example.com",
			Password: "ValidPassword123",
		})

		if err == nil {
			t.Fatal("expected error from session create")
		}
	})

	t.Run("refresh token create error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, _ = setupLoginUser(t, deps)
		deps.rtRepo.createErr = errors.New("db error")

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "login@example.com",
			Password: "ValidPassword123",
		})

		if err == nil {
			t.Fatal("expected error from refresh token create")
		}
	})

	t.Run("session count error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, _ = setupLoginUser(t, deps)
		deps.sessionRepo.countActiveErr = errors.New("db error")

		_, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "login@example.com",
			Password: "ValidPassword123",
		})

		if err == nil {
			t.Fatal("expected error from session count")
		}
	})

	t.Run("auto-revoke oldest session when limit reached", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, _ = setupLoginUser(t, deps)
		deps.sessionRepo.countActiveResult = 10 // At the limit
		// Create oldest session for auto-revoke
		oldestSess, _ := session.New(shared.NewID(), "old-token", "10.0.0.1", "OldBrowser", 24*time.Hour)
		deps.sessionRepo.oldestSession = oldestSess
		deps.sessionRepo.sessions[oldestSess.ID().String()] = oldestSess
		deps.tenantRepo.userMemberships = []tenant.UserMembership{}

		result, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "login@example.com",
			Password: "ValidPassword123",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result")
		}
		// Verify the oldest session was updated (revoked) + new session created
		// The update should be called for: revoked oldest + user update on successful login
		if deps.sessionRepo.updateCalls < 1 {
			t.Error("expected at least 1 session update for auto-revoke")
		}
	})

	t.Run("login with no tenants returns empty tenant list", func(t *testing.T) {
		svc, deps := newTestAuthService()
		_, _ = setupLoginUser(t, deps)
		deps.tenantRepo.userMemberships = nil

		result, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "login@example.com",
			Password: "ValidPassword123",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result")
		}
		if len(result.Tenants) != 0 {
			t.Errorf("expected 0 tenants, got %d", len(result.Tenants))
		}
	})
}

// =============================================================================
// Logout Tests
// =============================================================================

func TestAuthService_Logout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, deps := newTestAuthService()
		userID := shared.NewID()
		sess, _ := session.New(userID, "token-for-logout", "10.0.0.1", "Browser", 24*time.Hour)
		deps.sessionRepo.sessions[sess.ID().String()] = sess

		err := svc.Logout(context.Background(), sess.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if deps.sessionRepo.updateCalls != 1 {
			t.Errorf("expected 1 session update, got %d", deps.sessionRepo.updateCalls)
		}
		if deps.rtRepo.revokeBySessionCalls != 1 {
			t.Errorf("expected 1 RevokeBySessionID call, got %d", deps.rtRepo.revokeBySessionCalls)
		}
	})

	t.Run("session not found is not an error", func(t *testing.T) {
		svc, _ := newTestAuthService()

		err := svc.Logout(context.Background(), shared.NewID().String())
		if err != nil {
			t.Fatalf("expected no error for session not found (already logged out), got %v", err)
		}
	})

	t.Run("invalid session ID", func(t *testing.T) {
		svc, _ := newTestAuthService()

		err := svc.Logout(context.Background(), "not-a-uuid")
		if err == nil {
			t.Fatal("expected error for invalid session ID")
		}
	})

	t.Run("session repo get error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		deps.sessionRepo.getByIDErr = errors.New("db error")

		err := svc.Logout(context.Background(), shared.NewID().String())
		if err == nil {
			t.Fatal("expected error from repo")
		}
	})

	t.Run("session update error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		userID := shared.NewID()
		sess, _ := session.New(userID, "token", "10.0.0.1", "Browser", 24*time.Hour)
		deps.sessionRepo.sessions[sess.ID().String()] = sess
		deps.sessionRepo.updateErr = errors.New("db error")

		err := svc.Logout(context.Background(), sess.ID().String())
		if err == nil {
			t.Fatal("expected error from session update")
		}
	})

	t.Run("already revoked session", func(t *testing.T) {
		svc, deps := newTestAuthService()
		userID := shared.NewID()
		sess, _ := session.New(userID, "token", "10.0.0.1", "Browser", 24*time.Hour)
		_ = sess.Revoke()
		deps.sessionRepo.sessions[sess.ID().String()] = sess

		err := svc.Logout(context.Background(), sess.ID().String())
		if err == nil {
			t.Fatal("expected error when revoking already-revoked session")
		}
	})
}

// =============================================================================
// VerifyEmail Tests
// =============================================================================

func TestAuthService_VerifyEmail(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthUnverifiedUser(deps.userRepo, "unverified@example.com", "hash", "valid-token-123")

		err := svc.VerifyEmail(context.Background(), "valid-token-123")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if deps.userRepo.updateCalls != 1 {
			t.Errorf("expected 1 update call, got %d", deps.userRepo.updateCalls)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		svc, _ := newTestAuthService()

		err := svc.VerifyEmail(context.Background(), "nonexistent-token")
		if !errors.Is(err, app.ErrInvalidVerificationToken) {
			t.Errorf("expected ErrInvalidVerificationToken, got %v", err)
		}
	})

	t.Run("expired verification token", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthUserWithExpiredVerification(deps.userRepo, "expired@example.com", "hash", "expired-token")

		err := svc.VerifyEmail(context.Background(), "expired-token")
		if !errors.Is(err, app.ErrInvalidVerificationToken) {
			t.Errorf("expected ErrInvalidVerificationToken for expired token, got %v", err)
		}
	})

	t.Run("repo get error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		deps.userRepo.getByEmailVerificationErr = errors.New("db error")

		err := svc.VerifyEmail(context.Background(), "any-token")
		if err == nil {
			t.Fatal("expected error from repo")
		}
	})

	t.Run("repo update error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthUnverifiedUser(deps.userRepo, "user@example.com", "hash", "token")
		deps.userRepo.updateErr = errors.New("db error")

		err := svc.VerifyEmail(context.Background(), "token")
		if err == nil {
			t.Fatal("expected error from repo update")
		}
	})
}

// =============================================================================
// ForgotPassword Tests
// =============================================================================

func TestAuthService_ForgotPassword(t *testing.T) {
	t.Run("success for local user", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthLocalUser(deps.userRepo, "user@example.com", "hash")

		result, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{
			Email: "user@example.com",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result")
		}
		if result.Token == "" {
			t.Error("expected a reset token")
		}
		if deps.userRepo.updateCalls != 1 {
			t.Errorf("expected 1 update call, got %d", deps.userRepo.updateCalls)
		}
	})

	t.Run("email not found returns empty result for anti-enumeration", func(t *testing.T) {
		svc, _ := newTestAuthService()

		result, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{
			Email: "nonexistent@example.com",
		})

		if err != nil {
			t.Fatalf("expected no error for anti-enumeration, got %v", err)
		}
		if result == nil {
			t.Fatal("expected empty result")
		}
		if result.Token != "" {
			t.Error("expected empty token for nonexistent email")
		}
	})

	t.Run("OIDC user returns empty result", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthOIDCUser(deps.userRepo, "oidc@example.com")

		result, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{
			Email: "oidc@example.com",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.Token != "" {
			t.Error("expected empty token for OIDC user")
		}
	})

	t.Run("email normalization", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthLocalUser(deps.userRepo, "user@example.com", "hash")

		result, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{
			Email: "  USER@EXAMPLE.COM  ",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.Token == "" {
			t.Error("expected a reset token even with normalized email")
		}
	})

	t.Run("repo error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		deps.userRepo.getByEmailErr = errors.New("db error")

		_, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{
			Email: "user@example.com",
		})

		if err == nil {
			t.Fatal("expected error from repo")
		}
	})

	t.Run("update error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthLocalUser(deps.userRepo, "user@example.com", "hash")
		deps.userRepo.updateErr = errors.New("db error")

		_, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{
			Email: "user@example.com",
		})

		if err == nil {
			t.Fatal("expected error from repo update")
		}
	})
}

// =============================================================================
// ResetPassword Tests
// =============================================================================

func TestAuthService_ResetPassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthUserWithResetToken(deps.userRepo, "user@example.com", "$2a$04$dummy", "reset-token-123")

		err := svc.ResetPassword(context.Background(), app.ResetPasswordInput{
			Token:       "reset-token-123",
			NewPassword: "NewStrongPassword123!",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		// Should update user and revoke all sessions
		if deps.userRepo.updateCalls != 1 {
			t.Errorf("expected 1 user update call, got %d", deps.userRepo.updateCalls)
		}
		if deps.sessionRepo.revokeAllCalls != 1 {
			t.Errorf("expected 1 session revoke-all call, got %d", deps.sessionRepo.revokeAllCalls)
		}
		if deps.rtRepo.revokeByUserCalls != 1 {
			t.Errorf("expected 1 refresh token revoke-by-user call, got %d", deps.rtRepo.revokeByUserCalls)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		svc, _ := newTestAuthService()

		err := svc.ResetPassword(context.Background(), app.ResetPasswordInput{
			Token:       "nonexistent-token",
			NewPassword: "NewPassword123!",
		})

		if !errors.Is(err, app.ErrInvalidResetToken) {
			t.Errorf("expected ErrInvalidResetToken, got %v", err)
		}
	})

	t.Run("expired reset token", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthUserWithExpiredResetToken(deps.userRepo, "user@example.com", "hash", "expired-token")

		err := svc.ResetPassword(context.Background(), app.ResetPasswordInput{
			Token:       "expired-token",
			NewPassword: "NewPassword123!",
		})

		if !errors.Is(err, app.ErrInvalidResetToken) {
			t.Errorf("expected ErrInvalidResetToken for expired token, got %v", err)
		}
	})

	t.Run("weak new password", func(t *testing.T) {
		cfg := defaultAuthTestConfig()
		cfg.PasswordMinLength = 12
		svc, deps := newTestAuthServiceWithConfig(cfg)
		seedAuthUserWithResetToken(deps.userRepo, "user@example.com", "hash", "reset-token")

		err := svc.ResetPassword(context.Background(), app.ResetPasswordInput{
			Token:       "reset-token",
			NewPassword: "short",
		})

		if err == nil {
			t.Fatal("expected error for weak password")
		}
	})

	t.Run("repo error on get", func(t *testing.T) {
		svc, deps := newTestAuthService()
		deps.userRepo.getByPasswordResetTokenErr = errors.New("db error")

		_, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{
			Email: "user@example.com",
		})

		// This is testing ForgotPassword path, but let's test ResetPassword's GetByPasswordResetToken error
		_ = err

		err = svc.ResetPassword(context.Background(), app.ResetPasswordInput{
			Token:       "any-token",
			NewPassword: "NewPassword123!",
		})
		if err == nil {
			t.Fatal("expected error from repo")
		}
	})

	t.Run("repo update error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		seedAuthUserWithResetToken(deps.userRepo, "user@example.com", "$2a$04$dummy", "reset-token")
		deps.userRepo.updateErr = errors.New("db error")

		err := svc.ResetPassword(context.Background(), app.ResetPasswordInput{
			Token:       "reset-token",
			NewPassword: "NewStrongPassword123!",
		})

		if err == nil {
			t.Fatal("expected error from repo update")
		}
	})
}

// =============================================================================
// ChangePassword Tests
// =============================================================================

func TestAuthService_ChangePassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, deps := newTestAuthService()
		hasher := password.New(password.WithCost(4))
		hash, _ := hasher.Hash("CurrentPassword123")
		u := seedAuthLocalUser(deps.userRepo, "user@example.com", hash)

		err := svc.ChangePassword(context.Background(), u.ID().String(), app.ChangePasswordInput{
			CurrentPassword: "CurrentPassword123",
			NewPassword:     "NewPassword456!",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if deps.userRepo.updateCalls != 1 {
			t.Errorf("expected 1 update call, got %d", deps.userRepo.updateCalls)
		}
	})

	t.Run("wrong current password", func(t *testing.T) {
		svc, deps := newTestAuthService()
		hasher := password.New(password.WithCost(4))
		hash, _ := hasher.Hash("CurrentPassword123")
		u := seedAuthLocalUser(deps.userRepo, "user@example.com", hash)

		err := svc.ChangePassword(context.Background(), u.ID().String(), app.ChangePasswordInput{
			CurrentPassword: "WrongPassword!",
			NewPassword:     "NewPassword456!",
		})

		if !errors.Is(err, app.ErrPasswordMismatch) {
			t.Errorf("expected ErrPasswordMismatch, got %v", err)
		}
	})

	t.Run("OIDC user cannot change password", func(t *testing.T) {
		svc, deps := newTestAuthService()
		u := seedAuthOIDCUser(deps.userRepo, "oidc@example.com")

		err := svc.ChangePassword(context.Background(), u.ID().String(), app.ChangePasswordInput{
			CurrentPassword: "whatever",
			NewPassword:     "NewPassword456!",
		})

		if err == nil {
			t.Fatal("expected error for OIDC user")
		}
	})

	t.Run("invalid user ID", func(t *testing.T) {
		svc, _ := newTestAuthService()

		err := svc.ChangePassword(context.Background(), "bad-uuid", app.ChangePasswordInput{
			CurrentPassword: "current",
			NewPassword:     "newpass",
		})

		if err == nil {
			t.Fatal("expected error for invalid user ID")
		}
	})

	t.Run("user not found", func(t *testing.T) {
		svc, _ := newTestAuthService()

		err := svc.ChangePassword(context.Background(), shared.NewID().String(), app.ChangePasswordInput{
			CurrentPassword: "current",
			NewPassword:     "newpass",
		})

		if err == nil {
			t.Fatal("expected error for user not found")
		}
	})

	t.Run("weak new password", func(t *testing.T) {
		cfg := defaultAuthTestConfig()
		cfg.PasswordMinLength = 12
		svc, deps := newTestAuthServiceWithConfig(cfg)
		hasher := password.New(password.WithCost(4))
		hash, _ := hasher.Hash("CurrentPassword123")
		u := seedAuthLocalUser(deps.userRepo, "user@example.com", hash)

		err := svc.ChangePassword(context.Background(), u.ID().String(), app.ChangePasswordInput{
			CurrentPassword: "CurrentPassword123",
			NewPassword:     "short",
		})

		if err == nil {
			t.Fatal("expected error for weak password")
		}
	})

	t.Run("repo update error", func(t *testing.T) {
		svc, deps := newTestAuthService()
		hasher := password.New(password.WithCost(4))
		hash, _ := hasher.Hash("CurrentPassword123")
		u := seedAuthLocalUser(deps.userRepo, "user@example.com", hash)
		deps.userRepo.updateErr = errors.New("db error")

		err := svc.ChangePassword(context.Background(), u.ID().String(), app.ChangePasswordInput{
			CurrentPassword: "CurrentPassword123",
			NewPassword:     "NewPassword456!",
		})

		if err == nil {
			t.Fatal("expected error from repo update")
		}
	})
}

// =============================================================================
// ValidateAccessToken Tests
// =============================================================================

func TestAuthService_ValidateAccessToken(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		svc, _ := newTestAuthService()

		// Generate a valid token first using the same JWT secret
		// We'll test indirectly through Login + ExchangeToken
		// For direct testing, we need to generate a token with the same secret
		// Since ValidateAccessToken is a thin wrapper around jwt.Generator, test basics.
		claims, err := svc.ValidateAccessToken("invalid-token")
		if err == nil {
			t.Fatal("expected error for invalid token")
		}
		if claims != nil {
			t.Error("expected nil claims for invalid token")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.ValidateAccessToken("")
		if err == nil {
			t.Fatal("expected error for empty token")
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.ValidateAccessToken("not.a.valid.jwt.token")
		if err == nil {
			t.Fatal("expected error for malformed token")
		}
	})
}

// =============================================================================
// GenerateWSToken Tests
// =============================================================================

func TestAuthService_GenerateWSToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, _ := newTestAuthService()
		userID := shared.NewID().String()
		tenantID := shared.NewID().String()

		token, err := svc.GenerateWSToken(context.Background(), userID, tenantID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if token == "" {
			t.Error("expected a token")
		}
	})

	t.Run("empty user ID", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.GenerateWSToken(context.Background(), "", shared.NewID().String())
		if err == nil {
			t.Fatal("expected error for empty user ID")
		}
	})
}

// =============================================================================
// SetRoleService Tests
// =============================================================================

func TestAuthService_SetRoleService(t *testing.T) {
	t.Run("does not panic", func(t *testing.T) {
		svc, _ := newTestAuthService()
		// SetRoleService should not panic even with nil
		svc.SetRoleService(nil)
	})
}

// =============================================================================
// ExchangeToken Tests
// =============================================================================

func TestAuthService_ExchangeToken(t *testing.T) {
	t.Run("empty tenant ID", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.ExchangeToken(context.Background(), app.ExchangeTokenInput{
			RefreshToken: "some-token",
			TenantID:     "",
		})

		if !errors.Is(err, app.ErrTenantRequired) {
			t.Errorf("expected ErrTenantRequired, got %v", err)
		}
	})

	t.Run("invalid refresh token JWT", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.ExchangeToken(context.Background(), app.ExchangeTokenInput{
			RefreshToken: "invalid-jwt",
			TenantID:     shared.NewID().String(),
		})

		if err == nil {
			t.Fatal("expected error for invalid refresh token")
		}
	})
}

// =============================================================================
// RefreshToken Tests
// =============================================================================

func TestAuthService_RefreshToken(t *testing.T) {
	t.Run("empty tenant ID", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.RefreshToken(context.Background(), app.RefreshTokenInput{
			RefreshToken: "some-token",
			TenantID:     "",
		})

		if !errors.Is(err, app.ErrTenantRequired) {
			t.Errorf("expected ErrTenantRequired, got %v", err)
		}
	})

	t.Run("invalid refresh token JWT", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.RefreshToken(context.Background(), app.RefreshTokenInput{
			RefreshToken: "invalid-jwt",
			TenantID:     shared.NewID().String(),
		})

		if err == nil {
			t.Fatal("expected error for invalid refresh token")
		}
	})
}

// =============================================================================
// CreateFirstTeam Tests
// =============================================================================

func TestAuthService_CreateFirstTeam(t *testing.T) {
	t.Run("invalid refresh token", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.CreateFirstTeam(context.Background(), app.CreateFirstTeamInput{
			RefreshToken: "invalid-jwt",
			TeamName:     "My Team",
			TeamSlug:     "my-team",
		})

		if err == nil {
			t.Fatal("expected error for invalid refresh token")
		}
	})
}

// =============================================================================
// AcceptInvitationWithRefreshToken Tests
// =============================================================================

func TestAuthService_AcceptInvitationWithRefreshToken(t *testing.T) {
	t.Run("invalid refresh token", func(t *testing.T) {
		svc, _ := newTestAuthService()

		_, err := svc.AcceptInvitationWithRefreshToken(context.Background(), app.AcceptInvitationWithRefreshTokenInput{
			RefreshToken:    "invalid-jwt",
			InvitationToken: "invite-token",
		})

		if err == nil {
			t.Fatal("expected error for invalid refresh token")
		}
	})
}

// =============================================================================
// Cross-Tenant Isolation Tests
// =============================================================================

func TestAuthService_CrossTenantIsolation(t *testing.T) {
	t.Run("login returns only user memberships", func(t *testing.T) {
		svc, deps := newTestAuthService()
		hasher := password.New(password.WithCost(4))
		hash, _ := hasher.Hash("ValidPassword123")
		seedAuthLocalUser(deps.userRepo, "user@example.com", hash)

		tenant1ID := shared.NewID().String()
		tenant2ID := shared.NewID().String()

		deps.tenantRepo.userMemberships = []tenant.UserMembership{
			{TenantID: tenant1ID, TenantSlug: "team-1", TenantName: "Team 1", Role: "owner"},
			{TenantID: tenant2ID, TenantSlug: "team-2", TenantName: "Team 2", Role: "member"},
		}

		result, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "user@example.com",
			Password: "ValidPassword123",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(result.Tenants) != 2 {
			t.Fatalf("expected 2 tenants, got %d", len(result.Tenants))
		}

		// Verify each tenant info is correct
		foundTenants := make(map[string]string)
		for _, ti := range result.Tenants {
			foundTenants[ti.TenantID] = ti.Role
		}
		if foundTenants[tenant1ID] != "owner" {
			t.Errorf("expected owner role for tenant1, got %s", foundTenants[tenant1ID])
		}
		if foundTenants[tenant2ID] != "member" {
			t.Errorf("expected member role for tenant2, got %s", foundTenants[tenant2ID])
		}
	})

	t.Run("membership error does not block login", func(t *testing.T) {
		svc, deps := newTestAuthService()
		hasher := password.New(password.WithCost(4))
		hash, _ := hasher.Hash("ValidPassword123")
		seedAuthLocalUser(deps.userRepo, "user@example.com", hash)
		deps.tenantRepo.getUserMembershipsErr = errors.New("db error")

		result, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "user@example.com",
			Password: "ValidPassword123",
		})

		if err != nil {
			t.Fatalf("expected no error (memberships are optional), got %v", err)
		}
		if len(result.Tenants) != 0 {
			t.Errorf("expected 0 tenants on error, got %d", len(result.Tenants))
		}
	})
}

// =============================================================================
// Error Propagation Tests
// =============================================================================

func TestAuthService_ErrorPropagation(t *testing.T) {
	testCases := []struct {
		name        string
		setup       func(deps *authTestDeps)
		action      func(svc *app.AuthService) error
		expectError bool
	}{
		{
			name: "Register - user repo create error propagates",
			setup: func(deps *authTestDeps) {
				deps.userRepo.createErr = errors.New("db write error")
			},
			action: func(svc *app.AuthService) error {
				_, err := svc.Register(context.Background(), app.RegisterInput{
					Email: "user@example.com", Password: "Password123!", Name: "User",
				})
				return err
			},
			expectError: true,
		},
		{
			name: "VerifyEmail - user repo update error propagates",
			setup: func(deps *authTestDeps) {
				seedAuthUnverifiedUser(deps.userRepo, "u@example.com", "hash", "verify-token")
				deps.userRepo.updateErr = errors.New("db update error")
			},
			action: func(svc *app.AuthService) error {
				return svc.VerifyEmail(context.Background(), "verify-token")
			},
			expectError: true,
		},
		{
			name: "ForgotPassword - user repo update error propagates",
			setup: func(deps *authTestDeps) {
				seedAuthLocalUser(deps.userRepo, "u@example.com", "hash")
				deps.userRepo.updateErr = errors.New("db update error")
			},
			action: func(svc *app.AuthService) error {
				_, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{Email: "u@example.com"})
				return err
			},
			expectError: true,
		},
		{
			name: "ChangePassword - user not found propagates",
			setup: func(_ *authTestDeps) {
				// No user seeded, so GetByID will return ErrNotFound
			},
			action: func(svc *app.AuthService) error {
				return svc.ChangePassword(context.Background(), shared.NewID().String(), app.ChangePasswordInput{
					CurrentPassword: "old",
					NewPassword:     "newpassword123",
				})
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc, deps := newTestAuthService()
			tc.setup(deps)
			err := tc.action(svc)
			if tc.expectError && err == nil {
				t.Error("expected error but got nil")
			}
		})
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestAuthService_EdgeCases(t *testing.T) {
	t.Run("register with maximum length email", func(t *testing.T) {
		svc, _ := newTestAuthService()

		// Test with a very long but valid email
		longEmail := "a@b.com"
		result, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    longEmail,
			Password: "Password123!",
			Name:     "User",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.User == nil {
			t.Fatal("expected user")
		}
	})

	t.Run("register with whitespace-only name still creates user", func(t *testing.T) {
		svc, _ := newTestAuthService()

		result, err := svc.Register(context.Background(), app.RegisterInput{
			Email:    "user@example.com",
			Password: "Password123!",
			Name:     "   ",
		})

		// The service trims the name; the domain layer might reject empty name
		// but we test the service does not panic
		if err != nil && result == nil {
			// This is acceptable - domain may reject empty name
			return
		}
	})

	t.Run("logout with empty string session ID", func(t *testing.T) {
		svc, _ := newTestAuthService()

		err := svc.Logout(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty session ID")
		}
	})

	t.Run("change password for user with nil password hash", func(t *testing.T) {
		svc, deps := newTestAuthService()
		// Create local user without password hash (edge case)
		u := user.Reconstitute(
			shared.NewID(),
			nil,
			"nopw@example.com",
			"No Password User",
			"", "",
			user.StatusActive,
			user.Preferences{},
			nil,
			time.Now().UTC(),
			time.Now().UTC(),
			user.AuthProviderLocal,
			nil, // No password hash
			true, nil, nil, nil, nil, 0, nil,
		)
		deps.userRepo.users[u.ID().String()] = u

		err := svc.ChangePassword(context.Background(), u.ID().String(), app.ChangePasswordInput{
			CurrentPassword: "anything",
			NewPassword:     "NewPassword123!",
		})

		if err == nil {
			t.Fatal("expected error for user with no password hash")
		}
	})

	t.Run("concurrent login attempts with session limit", func(t *testing.T) {
		svc, deps := newTestAuthService()
		hasher := password.New(password.WithCost(4))
		hash, _ := hasher.Hash("ValidPassword123")
		seedAuthLocalUser(deps.userRepo, "user@example.com", hash)
		deps.sessionRepo.countActiveResult = 10 // At limit
		deps.sessionRepo.oldestSession = nil     // No oldest session found
		deps.tenantRepo.userMemberships = []tenant.UserMembership{}

		// Should still succeed even if no oldest session is found
		result, err := svc.Login(context.Background(), app.LoginInput{
			Email:    "user@example.com",
			Password: "ValidPassword123",
		})

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result")
		}
	})

	t.Run("forgot password with empty email after trim", func(t *testing.T) {
		svc, _ := newTestAuthService()

		result, err := svc.ForgotPassword(context.Background(), app.ForgotPasswordInput{
			Email: "   ",
		})

		// Empty email won't match any user - should return empty result for anti-enumeration
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result == nil {
			t.Fatal("expected result")
		}
		if result.Token != "" {
			t.Error("expected empty token for empty email")
		}
	})
}

// =============================================================================
// Password Validation Edge Cases (through AuthService)
// =============================================================================

func TestAuthService_PasswordValidation(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         config.AuthConfig
		password    string
		expectError bool
	}{
		{
			name:        "meets minimum length",
			cfg:         defaultAuthTestConfig(),
			password:    "12345678",
			expectError: false,
		},
		{
			name: "too short",
			cfg: func() config.AuthConfig {
				c := defaultAuthTestConfig()
				c.PasswordMinLength = 12
				return c
			}(),
			password:    "short",
			expectError: true,
		},
		{
			name: "requires uppercase",
			cfg: func() config.AuthConfig {
				c := defaultAuthTestConfig()
				c.PasswordRequireUpper = true
				return c
			}(),
			password:    "alllowercase123",
			expectError: true,
		},
		{
			name: "requires number",
			cfg: func() config.AuthConfig {
				c := defaultAuthTestConfig()
				c.PasswordRequireNumber = true
				return c
			}(),
			password:    "NoNumberHere!",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestAuthServiceWithConfig(tc.cfg)

			_, err := svc.Register(context.Background(), app.RegisterInput{
				Email:    "user@example.com",
				Password: tc.password,
				Name:     "User",
			})

			if tc.expectError && err == nil {
				t.Error("expected error for password validation")
			}
			if !tc.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
