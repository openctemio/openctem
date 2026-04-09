package unit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/identityprovider"
	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Identity Provider Repository
// =============================================================================

type ssoMockIPRepo struct {
	providers map[string]*identityprovider.IdentityProvider // keyed by ID

	// Error overrides
	createErr              error
	getByIDErr             error
	getByTenantAndProvErr  error
	updateErr              error
	deleteErr              error
	listByTenantErr        error
	listActiveByTenantErr  error

	// Call tracking
	createCalls int
	updateCalls int
	deleteCalls int
}

func newSSOmockIPRepo() *ssoMockIPRepo {
	return &ssoMockIPRepo{
		providers: make(map[string]*identityprovider.IdentityProvider),
	}
}

func (m *ssoMockIPRepo) Create(_ context.Context, ip *identityprovider.IdentityProvider) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.providers[ip.ID()] = ip
	return nil
}

func (m *ssoMockIPRepo) GetByID(_ context.Context, tenantID, id string) (*identityprovider.IdentityProvider, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	ip, ok := m.providers[id]
	if !ok {
		return nil, identityprovider.ErrNotFound
	}
	if ip.TenantID() != tenantID {
		return nil, identityprovider.ErrNotFound
	}
	return ip, nil
}

func (m *ssoMockIPRepo) GetByTenantAndProvider(_ context.Context, tenantID string, provider identityprovider.Provider) (*identityprovider.IdentityProvider, error) {
	if m.getByTenantAndProvErr != nil {
		return nil, m.getByTenantAndProvErr
	}
	for _, ip := range m.providers {
		if ip.TenantID() == tenantID && ip.Provider() == provider {
			return ip, nil
		}
	}
	return nil, identityprovider.ErrNotFound
}

func (m *ssoMockIPRepo) Update(_ context.Context, ip *identityprovider.IdentityProvider) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.providers[ip.ID()] = ip
	return nil
}

func (m *ssoMockIPRepo) Delete(_ context.Context, tenantID, id string) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	ip, ok := m.providers[id]
	if !ok {
		return identityprovider.ErrNotFound
	}
	if ip.TenantID() != tenantID {
		return identityprovider.ErrNotFound
	}
	delete(m.providers, id)
	return nil
}

func (m *ssoMockIPRepo) ListByTenant(_ context.Context, tenantID string) ([]*identityprovider.IdentityProvider, error) {
	if m.listByTenantErr != nil {
		return nil, m.listByTenantErr
	}
	result := make([]*identityprovider.IdentityProvider, 0)
	for _, ip := range m.providers {
		if ip.TenantID() == tenantID {
			result = append(result, ip)
		}
	}
	return result, nil
}

func (m *ssoMockIPRepo) ListActiveByTenant(_ context.Context, tenantID string) ([]*identityprovider.IdentityProvider, error) {
	if m.listActiveByTenantErr != nil {
		return nil, m.listActiveByTenantErr
	}
	result := make([]*identityprovider.IdentityProvider, 0)
	for _, ip := range m.providers {
		if ip.TenantID() == tenantID && ip.IsActive() {
			result = append(result, ip)
		}
	}
	return result, nil
}

// =============================================================================
// Mock Tenant Repository for SSO Tests
// =============================================================================

type ssoMockTenantRepo struct {
	tenants     map[string]*tenant.Tenant // keyed by ID
	slugIndex   map[string]*tenant.Tenant // keyed by slug
	memberships []*tenant.Membership

	// Error overrides
	createErr             error
	getByIDErr            error
	getBySlugErr          error
	updateErr             error
	deleteErr             error
	existsBySlugResult    bool
	existsBySlugErr       error
	createMembershipErr   error
	getMembershipErr      error
	getMembershipByIDErr  error
	updateMembershipErr   error
	deleteMembershipErr   error
	getUserMembershipsErr error
	listActiveTenantIDsErr error
}

func newSSOmockTenantRepo() *ssoMockTenantRepo {
	return &ssoMockTenantRepo{
		tenants:   make(map[string]*tenant.Tenant),
		slugIndex: make(map[string]*tenant.Tenant),
	}
}

func (m *ssoMockTenantRepo) addTenant(t *tenant.Tenant) {
	m.tenants[t.ID().String()] = t
	m.slugIndex[t.Slug()] = t
}

func (m *ssoMockTenantRepo) Create(_ context.Context, t *tenant.Tenant) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.addTenant(t)
	return nil
}

func (m *ssoMockTenantRepo) GetByID(_ context.Context, id shared.ID) (*tenant.Tenant, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	t, ok := m.tenants[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *ssoMockTenantRepo) GetBySlug(_ context.Context, slug string) (*tenant.Tenant, error) {
	if m.getBySlugErr != nil {
		return nil, m.getBySlugErr
	}
	t, ok := m.slugIndex[slug]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *ssoMockTenantRepo) Update(_ context.Context, _ *tenant.Tenant) error {
	return m.updateErr
}

func (m *ssoMockTenantRepo) Delete(_ context.Context, _ shared.ID) error {
	return m.deleteErr
}

func (m *ssoMockTenantRepo) ExistsBySlug(_ context.Context, _ string) (bool, error) {
	if m.existsBySlugErr != nil {
		return false, m.existsBySlugErr
	}
	return m.existsBySlugResult, nil
}

func (m *ssoMockTenantRepo) ListActiveTenantIDs(_ context.Context) ([]shared.ID, error) {
	if m.listActiveTenantIDsErr != nil {
		return nil, m.listActiveTenantIDsErr
	}
	return nil, nil
}

func (m *ssoMockTenantRepo) CreateMembership(_ context.Context, membership *tenant.Membership) error {
	if m.createMembershipErr != nil {
		return m.createMembershipErr
	}
	m.memberships = append(m.memberships, membership)
	return nil
}

func (m *ssoMockTenantRepo) GetMembership(_ context.Context, _ shared.ID, _ shared.ID) (*tenant.Membership, error) {
	if m.getMembershipErr != nil {
		return nil, m.getMembershipErr
	}
	return nil, shared.ErrNotFound
}

func (m *ssoMockTenantRepo) GetMembershipByID(_ context.Context, _ shared.ID) (*tenant.Membership, error) {
	if m.getMembershipByIDErr != nil {
		return nil, m.getMembershipByIDErr
	}
	return nil, shared.ErrNotFound
}

func (m *ssoMockTenantRepo) UpdateMembership(_ context.Context, _ *tenant.Membership) error {
	return m.updateMembershipErr
}

func (m *ssoMockTenantRepo) DeleteMembership(_ context.Context, _ shared.ID) error {
	return m.deleteMembershipErr
}

func (m *ssoMockTenantRepo) ListMembersByTenant(_ context.Context, _ shared.ID) ([]*tenant.Membership, error) {
	return m.memberships, nil
}

func (m *ssoMockTenantRepo) ListMembersWithUserInfo(_ context.Context, _ shared.ID) ([]*tenant.MemberWithUser, error) {
	return nil, nil
}

func (m *ssoMockTenantRepo) SearchMembersWithUserInfo(_ context.Context, _ shared.ID, _ tenant.MemberSearchFilters) (*tenant.MemberSearchResult, error) {
	return nil, nil
}

func (m *ssoMockTenantRepo) ListTenantsByUser(_ context.Context, _ shared.ID) ([]*tenant.TenantWithRole, error) {
	return nil, nil
}

func (m *ssoMockTenantRepo) CountMembersByTenant(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *ssoMockTenantRepo) GetMemberStats(_ context.Context, _ shared.ID) (*tenant.MemberStats, error) {
	return nil, nil
}

func (m *ssoMockTenantRepo) GetUserMemberships(_ context.Context, _ shared.ID) ([]tenant.UserMembership, error) {
	if m.getUserMembershipsErr != nil {
		return nil, m.getUserMembershipsErr
	}
	return nil, nil
}

func (m *ssoMockTenantRepo) GetMemberByEmail(_ context.Context, _ shared.ID, _ string) (*tenant.MemberWithUser, error) {
	return nil, nil
}

func (m *ssoMockTenantRepo) CreateInvitation(_ context.Context, _ *tenant.Invitation) error {
	return nil
}

func (m *ssoMockTenantRepo) GetInvitationByToken(_ context.Context, _ string) (*tenant.Invitation, error) {
	return nil, shared.ErrNotFound
}

func (m *ssoMockTenantRepo) GetInvitationByID(_ context.Context, _ shared.ID) (*tenant.Invitation, error) {
	return nil, shared.ErrNotFound
}

func (m *ssoMockTenantRepo) UpdateInvitation(_ context.Context, _ *tenant.Invitation) error {
	return nil
}

func (m *ssoMockTenantRepo) DeleteInvitation(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *ssoMockTenantRepo) ListPendingInvitationsByTenant(_ context.Context, _ shared.ID) ([]*tenant.Invitation, error) {
	return nil, nil
}

func (m *ssoMockTenantRepo) GetPendingInvitationByEmail(_ context.Context, _ shared.ID, _ string) (*tenant.Invitation, error) {
	return nil, nil
}

func (m *ssoMockTenantRepo) DeleteExpiredInvitations(_ context.Context) (int64, error) {
	return 0, nil
}

func (m *ssoMockTenantRepo) DeletePendingInvitationsByUserID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *ssoMockTenantRepo) AcceptInvitationTx(_ context.Context, _ *tenant.Invitation, _ *tenant.Membership) error {
	return nil
}

// =============================================================================
// Mock User Repository for SSO Tests
// =============================================================================

type ssoMockUserRepo struct {
	users map[string]*user.User // keyed by ID

	// Error overrides
	createErr              error
	getByIDErr             error
	getByEmailErr          error
	getByEmailForAuthErr   error
	updateErr              error
	deleteErr              error
	existsByEmailResult    bool
	existsByEmailErr       error
	existsByKeycloakIDResult bool
	existsByKeycloakIDErr  error
	getByKeycloakIDErr     error
	upsertFromKeycloakErr  error
	getByIDsErr            error
	countResult            int64
	countErr               error
	getByEmailVerificationErr  error
	getByPasswordResetTokenErr error

	// Call tracking
	createCalls int
	updateCalls int
}

func newSSOmockUserRepo() *ssoMockUserRepo {
	return &ssoMockUserRepo{
		users: make(map[string]*user.User),
	}
}

func (m *ssoMockUserRepo) Create(_ context.Context, u *user.User) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.users[u.ID().String()] = u
	return nil
}

func (m *ssoMockUserRepo) GetByID(_ context.Context, id shared.ID) (*user.User, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	u, ok := m.users[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return u, nil
}

func (m *ssoMockUserRepo) GetByKeycloakID(_ context.Context, _ string) (*user.User, error) {
	if m.getByKeycloakIDErr != nil {
		return nil, m.getByKeycloakIDErr
	}
	return nil, shared.ErrNotFound
}

func (m *ssoMockUserRepo) GetByEmail(_ context.Context, email string) (*user.User, error) {
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

func (m *ssoMockUserRepo) GetByEmailForAuth(_ context.Context, email string) (*user.User, error) {
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

func (m *ssoMockUserRepo) Update(_ context.Context, u *user.User) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.users[u.ID().String()] = u
	return nil
}

func (m *ssoMockUserRepo) Delete(_ context.Context, _ shared.ID) error {
	return m.deleteErr
}

func (m *ssoMockUserRepo) ExistsByEmail(_ context.Context, _ string) (bool, error) {
	if m.existsByEmailErr != nil {
		return false, m.existsByEmailErr
	}
	return m.existsByEmailResult, nil
}

func (m *ssoMockUserRepo) ExistsByKeycloakID(_ context.Context, _ string) (bool, error) {
	if m.existsByKeycloakIDErr != nil {
		return false, m.existsByKeycloakIDErr
	}
	return m.existsByKeycloakIDResult, nil
}

func (m *ssoMockUserRepo) UpsertFromKeycloak(_ context.Context, _, _, _ string) (*user.User, error) {
	if m.upsertFromKeycloakErr != nil {
		return nil, m.upsertFromKeycloakErr
	}
	return nil, nil
}

func (m *ssoMockUserRepo) GetByIDs(_ context.Context, _ []shared.ID) ([]*user.User, error) {
	if m.getByIDsErr != nil {
		return nil, m.getByIDsErr
	}
	return nil, nil
}

func (m *ssoMockUserRepo) Count(_ context.Context, _ user.Filter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return m.countResult, nil
}

func (m *ssoMockUserRepo) GetByEmailVerificationToken(_ context.Context, _ string) (*user.User, error) {
	if m.getByEmailVerificationErr != nil {
		return nil, m.getByEmailVerificationErr
	}
	return nil, shared.ErrNotFound
}

func (m *ssoMockUserRepo) GetByPasswordResetToken(_ context.Context, _ string) (*user.User, error) {
	if m.getByPasswordResetTokenErr != nil {
		return nil, m.getByPasswordResetTokenErr
	}
	return nil, shared.ErrNotFound
}

// =============================================================================
// Mock Session Repository for SSO Tests
// =============================================================================

type ssoMockSessionRepo struct {
	sessions map[string]*session.Session

	// Error overrides
	createErr error

	// Call tracking
	createCalls int
}

func newSSOmockSessionRepo() *ssoMockSessionRepo {
	return &ssoMockSessionRepo{
		sessions: make(map[string]*session.Session),
	}
}

func (m *ssoMockSessionRepo) Create(_ context.Context, s *session.Session) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.sessions[s.ID().String()] = s
	return nil
}

func (m *ssoMockSessionRepo) GetByID(_ context.Context, id shared.ID) (*session.Session, error) {
	s, ok := m.sessions[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *ssoMockSessionRepo) GetByAccessTokenHash(_ context.Context, _ string) (*session.Session, error) {
	return nil, shared.ErrNotFound
}

func (m *ssoMockSessionRepo) GetActiveByUserID(_ context.Context, _ shared.ID) ([]*session.Session, error) {
	return nil, nil
}

func (m *ssoMockSessionRepo) Update(_ context.Context, _ *session.Session) error {
	return nil
}

func (m *ssoMockSessionRepo) Delete(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *ssoMockSessionRepo) RevokeAllByUserID(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *ssoMockSessionRepo) RevokeAllByUserIDExcept(_ context.Context, _ shared.ID, _ shared.ID) error {
	return nil
}

func (m *ssoMockSessionRepo) CountActiveByUserID(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}

func (m *ssoMockSessionRepo) GetOldestActiveByUserID(_ context.Context, _ shared.ID) (*session.Session, error) {
	return nil, nil
}

func (m *ssoMockSessionRepo) DeleteExpired(_ context.Context) (int64, error) {
	return 0, nil
}

// =============================================================================
// Mock Refresh Token Repository for SSO Tests
// =============================================================================

type ssoMockRefreshTokenRepo struct {
	// Error overrides
	createErr error

	// Call tracking
	createCalls int
}

func newSSOmockRefreshTokenRepo() *ssoMockRefreshTokenRepo {
	return &ssoMockRefreshTokenRepo{}
}

func (m *ssoMockRefreshTokenRepo) Create(_ context.Context, _ *session.RefreshToken) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	return nil
}

func (m *ssoMockRefreshTokenRepo) GetByID(_ context.Context, _ shared.ID) (*session.RefreshToken, error) {
	return nil, shared.ErrNotFound
}

func (m *ssoMockRefreshTokenRepo) GetByTokenHash(_ context.Context, _ string) (*session.RefreshToken, error) {
	return nil, shared.ErrNotFound
}

func (m *ssoMockRefreshTokenRepo) GetByFamily(_ context.Context, _ shared.ID) ([]*session.RefreshToken, error) {
	return nil, nil
}

func (m *ssoMockRefreshTokenRepo) Update(_ context.Context, _ *session.RefreshToken) error {
	return nil
}

func (m *ssoMockRefreshTokenRepo) Delete(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *ssoMockRefreshTokenRepo) RevokeByFamily(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *ssoMockRefreshTokenRepo) RevokeBySessionID(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *ssoMockRefreshTokenRepo) RevokeByUserID(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *ssoMockRefreshTokenRepo) DeleteExpired(_ context.Context) (int64, error) {
	return 0, nil
}

// =============================================================================
// Mock Encryptor for SSO Tests
// =============================================================================

type ssoMockEncryptor struct {
	encryptErr error
	decryptErr error
}

func newSSOmockEncryptor() *ssoMockEncryptor {
	return &ssoMockEncryptor{}
}

func (m *ssoMockEncryptor) EncryptString(plaintext string) (string, error) {
	if m.encryptErr != nil {
		return "", m.encryptErr
	}
	return "encrypted:" + plaintext, nil
}

func (m *ssoMockEncryptor) DecryptString(encoded string) (string, error) {
	if m.decryptErr != nil {
		return "", m.decryptErr
	}
	return strings.TrimPrefix(encoded, "encrypted:"), nil
}

// =============================================================================
// Mock Tenant Member Creator for SSO Tests
// =============================================================================

type ssoMockTenantMemberCreator struct {
	createMembershipErr error
	createCalls         int
}

func newSSOmockTenantMemberCreator() *ssoMockTenantMemberCreator {
	return &ssoMockTenantMemberCreator{}
}

func (m *ssoMockTenantMemberCreator) CreateMembership(_ context.Context, _ *tenant.Membership) error {
	m.createCalls++
	if m.createMembershipErr != nil {
		return m.createMembershipErr
	}
	return nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestAuthConfig() config.AuthConfig {
	return config.AuthConfig{
		JWTSecret:            "test-secret-key-for-sso-testing-32ch",
		JWTIssuer:            "test-issuer",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		SessionDuration:      30 * 24 * time.Hour,
	}
}

func newTestSSOService(
	ipRepo identityprovider.Repository,
	tenantRepo tenant.Repository,
	userRepo user.Repository,
	sessionRepo session.Repository,
	refreshTokenRepo session.RefreshTokenRepository,
	encryptor crypto.Encryptor,
) *app.SSOService {
	log := logger.New(logger.Config{Level: "error"})
	authCfg := newTestAuthConfig()
	return app.NewSSOService(
		ipRepo,
		tenantRepo,
		userRepo,
		sessionRepo,
		refreshTokenRepo,
		encryptor,
		authCfg,
		log,
	)
}

func createTestTenant(slug string) *tenant.Tenant {
	t, _ := tenant.NewTenant("Test Tenant", slug, "creator-id")
	return t
}

func createTestProvider(tenantID string, provider identityprovider.Provider, active bool) *identityprovider.IdentityProvider {
	ip := identityprovider.New(
		shared.NewID().String(),
		tenantID,
		provider,
		"Test Provider",
		"client-id-123",
		"encrypted:client-secret",
	)
	if !active {
		ip.SetActive(false)
	}
	return ip
}

// =============================================================================
// Tests: GetProvidersForTenant
// =============================================================================

func TestSSOService_GetProvidersForTenant_Success(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	p1 := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	p2 := createTestProvider(testTenant.ID().String(), identityprovider.ProviderOkta, true)
	ipRepo.providers[p1.ID()] = p1
	ipRepo.providers[p2.ID()] = p2

	providers, err := svc.GetProvidersForTenant(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(providers))
	}
}

func TestSSOService_GetProvidersForTenant_TenantNotFound(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	_, err := svc.GetProvidersForTenant(context.Background(), "nonexistent")
	if !errors.Is(err, app.ErrSSOTenantNotFound) {
		t.Fatalf("expected ErrSSOTenantNotFound, got %v", err)
	}
}

func TestSSOService_GetProvidersForTenant_RepoError(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)
	ipRepo.listActiveByTenantErr = errors.New("db error")

	_, err := svc.GetProvidersForTenant(context.Background(), "test-org")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSSOService_GetProvidersForTenant_OnlyActiveProviders(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	active := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	inactive := createTestProvider(testTenant.ID().String(), identityprovider.ProviderOkta, false)
	ipRepo.providers[active.ID()] = active
	ipRepo.providers[inactive.ID()] = inactive

	providers, err := svc.GetProvidersForTenant(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("expected 1 active provider, got %d", len(providers))
	}
}

func TestSSOService_GetProvidersForTenant_EmptyResult(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	providers, err := svc.GetProvidersForTenant(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(providers) != 0 {
		t.Fatalf("expected 0 providers, got %d", len(providers))
	}
}

// =============================================================================
// Tests: GenerateAuthorizeURL
// =============================================================================

func TestSSOService_GenerateAuthorizeURL_Success_EntraID(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	provider.SetTenantIdentifier("tenant-guid-123")
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.AuthorizationURL == "" {
		t.Fatal("expected authorization URL to be set")
	}
	if result.State == "" {
		t.Fatal("expected state to be set")
	}
	// EntraID should use login.microsoftonline.com
	if !strings.Contains(result.AuthorizationURL, "login.microsoftonline.com") {
		t.Fatalf("expected EntraID URL, got %s", result.AuthorizationURL)
	}
	// EntraID should include response_mode=query
	if !strings.Contains(result.AuthorizationURL, "response_mode=query") {
		t.Fatalf("expected response_mode=query for EntraID, got %s", result.AuthorizationURL)
	}
}

func TestSSOService_GenerateAuthorizeURL_Success_GoogleWorkspace(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderGoogleWorkspace, true)
	provider.SetAllowedDomains([]string{"example.com"})
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderGoogleWorkspace),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Google should use accounts.google.com
	if !strings.Contains(result.AuthorizationURL, "accounts.google.com") {
		t.Fatalf("expected Google URL, got %s", result.AuthorizationURL)
	}
	// Google should include access_type=offline and prompt=select_account
	if !strings.Contains(result.AuthorizationURL, "access_type=offline") {
		t.Fatalf("expected access_type=offline for Google, got %s", result.AuthorizationURL)
	}
	if !strings.Contains(result.AuthorizationURL, "prompt=select_account") {
		t.Fatalf("expected prompt=select_account for Google, got %s", result.AuthorizationURL)
	}
	// Google should restrict to allowed domain via hd parameter
	if !strings.Contains(result.AuthorizationURL, "hd=example.com") {
		t.Fatalf("expected hd=example.com for Google, got %s", result.AuthorizationURL)
	}
}

func TestSSOService_GenerateAuthorizeURL_Success_Okta(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderOkta, true)
	provider.SetTenantIdentifier("https://dev-12345.okta.com")
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderOkta),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(result.AuthorizationURL, "okta.com") {
		t.Fatalf("expected Okta URL, got %s", result.AuthorizationURL)
	}
}

func TestSSOService_GenerateAuthorizeURL_InvalidRedirectURI(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tests := []struct {
		name        string
		redirectURI string
	}{
		{"empty scheme", "://example.com/callback"},
		{"ftp scheme", "ftp://example.com/callback"},
		{"javascript scheme", "javascript:alert(1)"},
		{"missing host", "https:///callback"},
		{"too long", "https://example.com/" + strings.Repeat("a", 2001)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
				OrgSlug:     "test-org",
				Provider:    "entra_id",
				RedirectURI: tt.redirectURI,
			})
			if !errors.Is(err, app.ErrSSOInvalidRedirectURI) {
				t.Fatalf("expected ErrSSOInvalidRedirectURI, got %v", err)
			}
		})
	}
}

func TestSSOService_GenerateAuthorizeURL_ValidRedirectURIs(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	tests := []struct {
		name        string
		redirectURI string
	}{
		{"https", "https://app.example.com/callback"},
		{"http localhost", "http://localhost:3000/callback"},
		{"http with port", "http://127.0.0.1:8080/auth/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
				OrgSlug:     "test-org",
				Provider:    string(identityprovider.ProviderEntraID),
				RedirectURI: tt.redirectURI,
			})
			if err != nil {
				t.Fatalf("expected no error for valid redirect URI %q, got %v", tt.redirectURI, err)
			}
			if result == nil {
				t.Fatal("expected result, got nil")
			}
		})
	}
}

func TestSSOService_GenerateAuthorizeURL_TenantNotFound(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	_, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "nonexistent",
		Provider:    "entra_id",
		RedirectURI: "https://app.example.com/callback",
	})
	if !errors.Is(err, app.ErrSSOTenantNotFound) {
		t.Fatalf("expected ErrSSOTenantNotFound, got %v", err)
	}
}

func TestSSOService_GenerateAuthorizeURL_ProviderNotFound(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	_, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    "entra_id",
		RedirectURI: "https://app.example.com/callback",
	})
	if !errors.Is(err, app.ErrSSOProviderNotFound) {
		t.Fatalf("expected ErrSSOProviderNotFound, got %v", err)
	}
}

func TestSSOService_GenerateAuthorizeURL_ProviderInactive(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, false)
	ipRepo.providers[provider.ID()] = provider

	_, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if !errors.Is(err, app.ErrSSOProviderInactive) {
		t.Fatalf("expected ErrSSOProviderInactive, got %v", err)
	}
}

func TestSSOService_GenerateAuthorizeURL_DecryptionFailed(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	encryptor := newSSOmockEncryptor()
	encryptor.decryptErr = errors.New("decryption failed")
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), encryptor)

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	_, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if !errors.Is(err, app.ErrSSODecryptionFailed) {
		t.Fatalf("expected ErrSSODecryptionFailed, got %v", err)
	}
}

func TestSSOService_GenerateAuthorizeURL_IncludesScopes(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	provider.SetScopes([]string{"openid", "email", "profile"})
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Scopes should be space-separated in the URL
	if !strings.Contains(result.AuthorizationURL, "scope=openid+email+profile") &&
		!strings.Contains(result.AuthorizationURL, "scope=openid%20email%20profile") {
		t.Fatalf("expected scopes in URL, got %s", result.AuthorizationURL)
	}
}

// =============================================================================
// Tests: CreateProvider
// =============================================================================

func TestSSOService_CreateProvider_Success(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:     shared.NewID().String(),
		Provider:     string(identityprovider.ProviderEntraID),
		DisplayName:  "Microsoft SSO",
		ClientID:     "client-123",
		ClientSecret: "super-secret",
		DefaultRole:  "member",
		CreatedBy:    shared.NewID().String(),
	}

	ip, err := svc.CreateProvider(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ip == nil {
		t.Fatal("expected provider, got nil")
	}
	if ip.DisplayName() != "Microsoft SSO" {
		t.Fatalf("expected display name 'Microsoft SSO', got %q", ip.DisplayName())
	}
	if ip.ClientID() != "client-123" {
		t.Fatalf("expected client ID 'client-123', got %q", ip.ClientID())
	}
	if !ip.IsActive() {
		t.Fatal("expected provider to be active")
	}
	if ipRepo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", ipRepo.createCalls)
	}
}

func TestSSOService_CreateProvider_InvalidProvider(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:     shared.NewID().String(),
		Provider:     "invalid_provider",
		DisplayName:  "Bad Provider",
		ClientID:     "client-123",
		ClientSecret: "super-secret",
	}

	_, err := svc.CreateProvider(context.Background(), input)
	if !errors.Is(err, identityprovider.ErrInvalidProvider) {
		t.Fatalf("expected ErrInvalidProvider, got %v", err)
	}
}

func TestSSOService_CreateProvider_OwnerRoleRejected(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:     shared.NewID().String(),
		Provider:     string(identityprovider.ProviderEntraID),
		DisplayName:  "SSO Provider",
		ClientID:     "client-123",
		ClientSecret: "super-secret",
		DefaultRole:  "owner",
	}

	_, err := svc.CreateProvider(context.Background(), input)
	if !errors.Is(err, app.ErrSSOInvalidDefaultRole) {
		t.Fatalf("expected ErrSSOInvalidDefaultRole, got %v", err)
	}
}

func TestSSOService_CreateProvider_ValidDefaultRoles(t *testing.T) {
	validRoles := []string{"admin", "member", "viewer", ""}
	for _, role := range validRoles {
		t.Run("role_"+role, func(t *testing.T) {
			ipRepo := newSSOmockIPRepo()
			svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

			input := app.CreateProviderInput{
				TenantID:     shared.NewID().String(),
				Provider:     string(identityprovider.ProviderEntraID),
				DisplayName:  "SSO Provider",
				ClientID:     "client-123",
				ClientSecret: "super-secret",
				DefaultRole:  role,
			}

			_, err := svc.CreateProvider(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error for role %q, got %v", role, err)
			}
		})
	}
}

func TestSSOService_CreateProvider_InvalidDefaultRole(t *testing.T) {
	invalidRoles := []string{"owner", "superadmin", "root", "god"}
	for _, role := range invalidRoles {
		t.Run("role_"+role, func(t *testing.T) {
			svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

			input := app.CreateProviderInput{
				TenantID:     shared.NewID().String(),
				Provider:     string(identityprovider.ProviderEntraID),
				DisplayName:  "SSO Provider",
				ClientID:     "client-123",
				ClientSecret: "super-secret",
				DefaultRole:  role,
			}

			_, err := svc.CreateProvider(context.Background(), input)
			if !errors.Is(err, app.ErrSSOInvalidDefaultRole) {
				t.Fatalf("expected ErrSSOInvalidDefaultRole for role %q, got %v", role, err)
			}
		})
	}
}

func TestSSOService_CreateProvider_OktaTenantIdentifierValidation(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		wantErr    bool
	}{
		{"valid okta URL", "https://dev-12345.okta.com", false},
		{"valid oktapreview URL", "https://dev-12345.oktapreview.com", false},
		{"http scheme rejected", "http://dev-12345.okta.com", true},
		{"non-okta domain rejected", "https://evil.example.com", true},
		{"empty identifier allowed", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

			input := app.CreateProviderInput{
				TenantID:         shared.NewID().String(),
				Provider:         string(identityprovider.ProviderOkta),
				DisplayName:      "Okta SSO",
				ClientID:         "client-123",
				ClientSecret:     "super-secret",
				TenantIdentifier: tt.identifier,
			}

			_, err := svc.CreateProvider(context.Background(), input)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestSSOService_CreateProvider_EntraIDTenantIdentifierTooLong(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:         shared.NewID().String(),
		Provider:         string(identityprovider.ProviderEntraID),
		DisplayName:      "EntraID SSO",
		ClientID:         "client-123",
		ClientSecret:     "super-secret",
		TenantIdentifier: strings.Repeat("a", 129),
	}

	_, err := svc.CreateProvider(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for too-long tenant identifier, got nil")
	}
	if !errors.Is(err, identityprovider.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestSSOService_CreateProvider_ScopesValidation(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []string
		wantErr bool
	}{
		{"valid scopes", []string{"openid", "email", "profile"}, false},
		{"empty scopes allowed", nil, false},
		{"too many scopes", makeScopesList(21), true},
		{"scope too long", []string{strings.Repeat("a", 129)}, true},
		{"max scopes allowed", makeScopesList(20), false},
		{"max length scope allowed", []string{strings.Repeat("a", 128)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

			input := app.CreateProviderInput{
				TenantID:     shared.NewID().String(),
				Provider:     string(identityprovider.ProviderEntraID),
				DisplayName:  "SSO Provider",
				ClientID:     "client-123",
				ClientSecret: "super-secret",
				Scopes:       tt.scopes,
			}

			_, err := svc.CreateProvider(context.Background(), input)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestSSOService_CreateProvider_AllowedDomainsValidation(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		wantErr bool
	}{
		{"valid domains", []string{"example.com", "corp.example.com"}, false},
		{"empty domains allowed", nil, false},
		{"too many domains", makeDomainsList(101), true},
		{"max domains allowed", makeDomainsList(100), false},
		{"empty domain rejected", []string{""}, true},
		{"domain too long", []string{strings.Repeat("a", 256)}, true},
		{"wildcard rejected", []string{"*.example.com"}, true},
		{"whitespace in domain rejected", []string{"exam ple.com"}, true},
		{"tab in domain rejected", []string{"exam\tple.com"}, true},
		{"newline in domain rejected", []string{"exam\nple.com"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

			input := app.CreateProviderInput{
				TenantID:       shared.NewID().String(),
				Provider:       string(identityprovider.ProviderEntraID),
				DisplayName:    "SSO Provider",
				ClientID:       "client-123",
				ClientSecret:   "super-secret",
				AllowedDomains: tt.domains,
			}

			_, err := svc.CreateProvider(context.Background(), input)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestSSOService_CreateProvider_EncryptionFailed(t *testing.T) {
	encryptor := newSSOmockEncryptor()
	encryptor.encryptErr = errors.New("encryption failed")
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), encryptor)

	input := app.CreateProviderInput{
		TenantID:     shared.NewID().String(),
		Provider:     string(identityprovider.ProviderEntraID),
		DisplayName:  "SSO Provider",
		ClientID:     "client-123",
		ClientSecret: "super-secret",
	}

	_, err := svc.CreateProvider(context.Background(), input)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSSOService_CreateProvider_RepoError(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	ipRepo.createErr = errors.New("db error")
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:     shared.NewID().String(),
		Provider:     string(identityprovider.ProviderEntraID),
		DisplayName:  "SSO Provider",
		ClientID:     "client-123",
		ClientSecret: "super-secret",
	}

	_, err := svc.CreateProvider(context.Background(), input)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSSOService_CreateProvider_SetsOptionalFields(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	createdBy := shared.NewID().String()
	input := app.CreateProviderInput{
		TenantID:         shared.NewID().String(),
		Provider:         string(identityprovider.ProviderEntraID),
		DisplayName:      "EntraID SSO",
		ClientID:         "client-123",
		ClientSecret:     "super-secret",
		IssuerURL:        "https://login.microsoftonline.com/tenant-id",
		TenantIdentifier: "tenant-guid",
		Scopes:           []string{"openid", "email"},
		AllowedDomains:   []string{"example.com"},
		AutoProvision:    true,
		DefaultRole:      "viewer",
		CreatedBy:        createdBy,
	}

	ip, err := svc.CreateProvider(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ip.IssuerURL() != "https://login.microsoftonline.com/tenant-id" {
		t.Fatalf("expected issuer URL to be set, got %q", ip.IssuerURL())
	}
	if ip.TenantIdentifier() != "tenant-guid" {
		t.Fatalf("expected tenant identifier to be set, got %q", ip.TenantIdentifier())
	}
	if len(ip.Scopes()) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(ip.Scopes()))
	}
	if len(ip.AllowedDomains()) != 1 || ip.AllowedDomains()[0] != "example.com" {
		t.Fatalf("expected allowed domain 'example.com', got %v", ip.AllowedDomains())
	}
	if !ip.AutoProvision() {
		t.Fatal("expected auto-provision to be true")
	}
	if ip.DefaultRole() != "viewer" {
		t.Fatalf("expected default role 'viewer', got %q", ip.DefaultRole())
	}
	if ip.CreatedBy() != createdBy {
		t.Fatalf("expected created by %q, got %q", createdBy, ip.CreatedBy())
	}
}

func TestSSOService_CreateProvider_AllProviderTypes(t *testing.T) {
	providers := []identityprovider.Provider{
		identityprovider.ProviderEntraID,
		identityprovider.ProviderOkta,
		identityprovider.ProviderGoogleWorkspace,
	}

	for _, p := range providers {
		t.Run(string(p), func(t *testing.T) {
			ipRepo := newSSOmockIPRepo()
			svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

			input := app.CreateProviderInput{
				TenantID:     shared.NewID().String(),
				Provider:     string(p),
				DisplayName:  "Provider " + string(p),
				ClientID:     "client-123",
				ClientSecret: "super-secret",
			}

			ip, err := svc.CreateProvider(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error for provider %s, got %v", p, err)
			}
			if ip.Provider() != p {
				t.Fatalf("expected provider %s, got %s", p, ip.Provider())
			}
		})
	}
}

// =============================================================================
// Tests: UpdateProvider
// =============================================================================

func TestSSOService_UpdateProvider_Success(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	newName := "Updated Name"
	newClientID := "new-client-id"
	isActive := false

	result, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:          provider.ID(),
		TenantID:    tenantID,
		DisplayName: &newName,
		ClientID:    &newClientID,
		IsActive:    &isActive,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.DisplayName() != "Updated Name" {
		t.Fatalf("expected updated name, got %q", result.DisplayName())
	}
	if result.ClientID() != "new-client-id" {
		t.Fatalf("expected updated client ID, got %q", result.ClientID())
	}
	if result.IsActive() {
		t.Fatal("expected provider to be inactive")
	}
	if ipRepo.updateCalls != 1 {
		t.Fatalf("expected 1 update call, got %d", ipRepo.updateCalls)
	}
}

func TestSSOService_UpdateProvider_NotFound(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	newName := "Updated"

	_, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:          "nonexistent-id",
		TenantID:    tenantID,
		DisplayName: &newName,
	})
	if !errors.Is(err, identityprovider.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSSOService_UpdateProvider_OwnerRoleRejected(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	ownerRole := "owner"
	_, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:          provider.ID(),
		TenantID:    tenantID,
		DefaultRole: &ownerRole,
	})
	if !errors.Is(err, app.ErrSSOInvalidDefaultRole) {
		t.Fatalf("expected ErrSSOInvalidDefaultRole, got %v", err)
	}
}

func TestSSOService_UpdateProvider_UpdateClientSecret(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	newSecret := "new-secret-value"
	result, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:           provider.ID(),
		TenantID:     tenantID,
		ClientSecret: &newSecret,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// The secret should be encrypted (our mock prepends "encrypted:")
	if result.ClientSecretEncrypted() != "encrypted:new-secret-value" {
		t.Fatalf("expected encrypted secret, got %q", result.ClientSecretEncrypted())
	}
}

func TestSSOService_UpdateProvider_EncryptionFailed(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	encryptor := newSSOmockEncryptor()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), encryptor)

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	// Set encryption error after provider is created
	encryptor.encryptErr = errors.New("encryption failed")

	newSecret := "new-secret"
	_, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:           provider.ID(),
		TenantID:     tenantID,
		ClientSecret: &newSecret,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSSOService_UpdateProvider_ValidateTenantIdentifier(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderOkta, true)
	ipRepo.providers[provider.ID()] = provider

	// Non-okta domain should fail for Okta provider
	badIdentifier := "https://evil.example.com"
	_, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:               provider.ID(),
		TenantID:         tenantID,
		TenantIdentifier: &badIdentifier,
	})
	if err == nil {
		t.Fatal("expected error for non-Okta domain, got nil")
	}
}

func TestSSOService_UpdateProvider_ValidateAllowedDomains(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	_, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:             provider.ID(),
		TenantID:       tenantID,
		AllowedDomains: []string{"*.example.com"},
	})
	if err == nil {
		t.Fatal("expected error for wildcard domain, got nil")
	}
}

func TestSSOService_UpdateProvider_ValidateScopes(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	_, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:       provider.ID(),
		TenantID: tenantID,
		Scopes:   makeScopesList(21),
	})
	if err == nil {
		t.Fatal("expected error for too many scopes, got nil")
	}
}

func TestSSOService_UpdateProvider_PartialUpdate(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	originalClientID := provider.ClientID()
	newName := "Updated Name Only"

	result, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:          provider.ID(),
		TenantID:    tenantID,
		DisplayName: &newName,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Display name should be updated
	if result.DisplayName() != "Updated Name Only" {
		t.Fatalf("expected updated name, got %q", result.DisplayName())
	}
	// Client ID should remain unchanged
	if result.ClientID() != originalClientID {
		t.Fatalf("expected client ID to remain %q, got %q", originalClientID, result.ClientID())
	}
}

func TestSSOService_UpdateProvider_AllFields(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	name := "Full Update"
	clientID := "new-client"
	secret := "new-secret"
	issuer := "https://issuer.example.com"
	tid := "new-tenant-id"
	autoProvision := false
	role := "admin"
	active := false

	result, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:               provider.ID(),
		TenantID:         tenantID,
		DisplayName:      &name,
		ClientID:         &clientID,
		ClientSecret:     &secret,
		IssuerURL:        &issuer,
		TenantIdentifier: &tid,
		Scopes:           []string{"openid"},
		AllowedDomains:   []string{"example.com"},
		AutoProvision:    &autoProvision,
		DefaultRole:      &role,
		IsActive:         &active,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.DisplayName() != "Full Update" {
		t.Fatalf("unexpected display name: %q", result.DisplayName())
	}
	if result.ClientID() != "new-client" {
		t.Fatalf("unexpected client ID: %q", result.ClientID())
	}
	if result.IssuerURL() != "https://issuer.example.com" {
		t.Fatalf("unexpected issuer URL: %q", result.IssuerURL())
	}
	if result.TenantIdentifier() != "new-tenant-id" {
		t.Fatalf("unexpected tenant identifier: %q", result.TenantIdentifier())
	}
	if len(result.Scopes()) != 1 || result.Scopes()[0] != "openid" {
		t.Fatalf("unexpected scopes: %v", result.Scopes())
	}
	if len(result.AllowedDomains()) != 1 || result.AllowedDomains()[0] != "example.com" {
		t.Fatalf("unexpected allowed domains: %v", result.AllowedDomains())
	}
	if result.AutoProvision() {
		t.Fatal("expected auto-provision to be false")
	}
	if result.DefaultRole() != "admin" {
		t.Fatalf("unexpected default role: %q", result.DefaultRole())
	}
	if result.IsActive() {
		t.Fatal("expected provider to be inactive")
	}
}

func TestSSOService_UpdateProvider_RepoError(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	ipRepo.updateErr = errors.New("db error")
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	newName := "Updated"
	_, err := svc.UpdateProvider(context.Background(), app.UpdateProviderInput{
		ID:          provider.ID(),
		TenantID:    tenantID,
		DisplayName: &newName,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// =============================================================================
// Tests: GetProvider
// =============================================================================

func TestSSOService_GetProvider_Success(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GetProvider(context.Background(), tenantID, provider.ID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID() != provider.ID() {
		t.Fatalf("expected provider ID %s, got %s", provider.ID(), result.ID())
	}
}

func TestSSOService_GetProvider_NotFound(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	_, err := svc.GetProvider(context.Background(), "tenant-id", "nonexistent-id")
	if !errors.Is(err, identityprovider.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSSOService_GetProvider_WrongTenant(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	// Try to access with a different tenant ID
	_, err := svc.GetProvider(context.Background(), "wrong-tenant-id", provider.ID())
	if !errors.Is(err, identityprovider.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong tenant, got %v", err)
	}
}

// =============================================================================
// Tests: ListProviders
// =============================================================================

func TestSSOService_ListProviders_Success(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	p1 := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	p2 := createTestProvider(tenantID, identityprovider.ProviderOkta, false) // inactive included in list
	ipRepo.providers[p1.ID()] = p1
	ipRepo.providers[p2.ID()] = p2

	result, err := svc.ListProviders(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(result))
	}
}

func TestSSOService_ListProviders_Empty(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	result, err := svc.ListProviders(context.Background(), "nonexistent-tenant")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 providers, got %d", len(result))
	}
}

func TestSSOService_ListProviders_RepoError(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	ipRepo.listByTenantErr = errors.New("db error")
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	_, err := svc.ListProviders(context.Background(), "tenant-id")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSSOService_ListProviders_TenantIsolation(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenant1ID := shared.NewID().String()
	tenant2ID := shared.NewID().String()

	p1 := createTestProvider(tenant1ID, identityprovider.ProviderEntraID, true)
	p2 := createTestProvider(tenant2ID, identityprovider.ProviderOkta, true)
	ipRepo.providers[p1.ID()] = p1
	ipRepo.providers[p2.ID()] = p2

	result, err := svc.ListProviders(context.Background(), tenant1ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 provider for tenant1, got %d", len(result))
	}
	if result[0].TenantID() != tenant1ID {
		t.Fatalf("expected provider to belong to tenant1, got tenant %s", result[0].TenantID())
	}
}

// =============================================================================
// Tests: DeleteProvider
// =============================================================================

func TestSSOService_DeleteProvider_Success(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	err := svc.DeleteProvider(context.Background(), tenantID, provider.ID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ipRepo.deleteCalls != 1 {
		t.Fatalf("expected 1 delete call, got %d", ipRepo.deleteCalls)
	}
	// Verify provider was removed
	if _, ok := ipRepo.providers[provider.ID()]; ok {
		t.Fatal("expected provider to be deleted")
	}
}

func TestSSOService_DeleteProvider_NotFound(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	err := svc.DeleteProvider(context.Background(), "tenant-id", "nonexistent-id")
	if !errors.Is(err, identityprovider.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSSOService_DeleteProvider_WrongTenant(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	err := svc.DeleteProvider(context.Background(), "wrong-tenant-id", provider.ID())
	if !errors.Is(err, identityprovider.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong tenant, got %v", err)
	}
}

func TestSSOService_DeleteProvider_RepoError(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	tenantID := shared.NewID().String()
	provider := createTestProvider(tenantID, identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	ipRepo.deleteErr = errors.New("db error")

	err := svc.DeleteProvider(context.Background(), tenantID, provider.ID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// =============================================================================
// Tests: HandleCallback
// =============================================================================

func TestSSOService_HandleCallback_InvalidState(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	_, err := svc.HandleCallback(context.Background(), app.SSOCallbackInput{
		Provider: "entra_id",
		Code:     "auth-code",
		State:    "invalid-state-token",
	})
	if !errors.Is(err, app.ErrSSOInvalidState) {
		t.Fatalf("expected ErrSSOInvalidState, got %v", err)
	}
}

func TestSSOService_HandleCallback_ProviderMismatch(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	// Generate a valid state for "entra_id"
	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("failed to generate authorize URL: %v", err)
	}

	// Use the state but claim the provider is "okta" - should fail
	_, err = svc.HandleCallback(context.Background(), app.SSOCallbackInput{
		Provider: "okta",
		Code:     "auth-code",
		State:    result.State,
	})
	if !errors.Is(err, app.ErrSSOInvalidState) {
		t.Fatalf("expected ErrSSOInvalidState for provider mismatch, got %v", err)
	}
}

func TestSSOService_HandleCallback_TamperedState(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	// State with tampered signature
	_, err := svc.HandleCallback(context.Background(), app.SSOCallbackInput{
		Provider: "entra_id",
		Code:     "auth-code",
		State:    "dGVzdA==.dGFtcGVyZWQ=",
	})
	if !errors.Is(err, app.ErrSSOInvalidState) {
		t.Fatalf("expected ErrSSOInvalidState for tampered state, got %v", err)
	}
}

// =============================================================================
// Tests: State Token Generation and Validation (via GenerateAuthorizeURL)
// =============================================================================

func TestSSOService_StateToken_RoundTrip(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// The state should contain a dot separating data from signature
	parts := strings.SplitN(result.State, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected state to have data.signature format, got %q", result.State)
	}
	if parts[0] == "" || parts[1] == "" {
		t.Fatal("expected both data and signature parts to be non-empty")
	}
}

func TestSSOService_StateToken_UniquePerRequest(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	input := app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	}

	result1, _ := svc.GenerateAuthorizeURL(context.Background(), input)
	result2, _ := svc.GenerateAuthorizeURL(context.Background(), input)

	if result1.State == result2.State {
		t.Fatal("expected state tokens to be unique per request")
	}
}

// =============================================================================
// Tests: SetTenantMemberRepo
// =============================================================================

func TestSSOService_SetTenantMemberRepo(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	memberCreator := newSSOmockTenantMemberCreator()
	svc.SetTenantMemberRepo(memberCreator)

	// No panic means success - the method is a simple setter
}

// =============================================================================
// Tests: Provider-specific Auth Endpoints (via GenerateAuthorizeURL)
// =============================================================================

func TestSSOService_ProviderEndpoints_EntraID_DefaultTenant(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	// EntraID provider without tenant identifier should use "common"
	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(result.AuthorizationURL, "/common/") {
		t.Fatalf("expected 'common' tenant in EntraID URL, got %s", result.AuthorizationURL)
	}
}

func TestSSOService_ProviderEndpoints_EntraID_CustomTenant(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	provider.SetTenantIdentifier("my-tenant-guid")
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(result.AuthorizationURL, "/my-tenant-guid/") {
		t.Fatalf("expected custom tenant in EntraID URL, got %s", result.AuthorizationURL)
	}
}

func TestSSOService_ProviderEndpoints_GoogleWorkspace_NoDomainRestriction(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderGoogleWorkspace, true)
	// No allowed domains set
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderGoogleWorkspace),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Without allowed domains, no hd parameter should be included
	if strings.Contains(result.AuthorizationURL, "hd=") {
		t.Fatalf("expected no hd parameter without allowed domains, got %s", result.AuthorizationURL)
	}
}

// =============================================================================
// Tests: Validation Functions (tested through CreateProvider)
// =============================================================================

func TestSSOService_ValidateDefaultRole_EmptyIsValid(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:     shared.NewID().String(),
		Provider:     string(identityprovider.ProviderEntraID),
		DisplayName:  "SSO Provider",
		ClientID:     "client-123",
		ClientSecret: "super-secret",
		DefaultRole:  "", // Empty should use entity default ("member")
	}

	ip, err := svc.CreateProvider(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error for empty default role, got %v", err)
	}
	// Entity default should be "member"
	if ip.DefaultRole() != "member" {
		t.Fatalf("expected default role 'member', got %q", ip.DefaultRole())
	}
}

func TestSSOService_ValidateOktaTenantIdentifier_MissingScheme(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:         shared.NewID().String(),
		Provider:         string(identityprovider.ProviderOkta),
		DisplayName:      "Okta SSO",
		ClientID:         "client-123",
		ClientSecret:     "super-secret",
		TenantIdentifier: "dev-12345.okta.com", // Missing https://
	}

	_, err := svc.CreateProvider(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for Okta URL without https scheme, got nil")
	}
}

func TestSSOService_ValidateEntraIDTenantIdentifier_ValidLength(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:         shared.NewID().String(),
		Provider:         string(identityprovider.ProviderEntraID),
		DisplayName:      "EntraID SSO",
		ClientID:         "client-123",
		ClientSecret:     "super-secret",
		TenantIdentifier: strings.Repeat("a", 128), // Exactly at max
	}

	_, err := svc.CreateProvider(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error for max-length EntraID tenant identifier, got %v", err)
	}
}

func TestSSOService_ValidateAllowedDomains_MaxLength(t *testing.T) {
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:       shared.NewID().String(),
		Provider:       string(identityprovider.ProviderEntraID),
		DisplayName:    "SSO Provider",
		ClientID:       "client-123",
		ClientSecret:   "super-secret",
		AllowedDomains: []string{strings.Repeat("a", 255)}, // Exactly at max
	}

	_, err := svc.CreateProvider(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error for max-length domain, got %v", err)
	}
}

// =============================================================================
// Tests: SSOProviderInfo response format
// =============================================================================

func TestSSOService_GetProvidersForTenant_ResponseFormat(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := identityprovider.New(
		"provider-id-123",
		testTenant.ID().String(),
		identityprovider.ProviderEntraID,
		"Microsoft Entra ID",
		"client-id",
		"encrypted-secret",
	)
	ipRepo.providers[provider.ID()] = provider

	providers, err := svc.GetProvidersForTenant(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}

	p := providers[0]
	if p.ID != "provider-id-123" {
		t.Fatalf("expected ID 'provider-id-123', got %q", p.ID)
	}
	if p.Provider != "entra_id" {
		t.Fatalf("expected provider 'entra_id', got %q", p.Provider)
	}
	if p.DisplayName != "Microsoft Entra ID" {
		t.Fatalf("expected display name 'Microsoft Entra ID', got %q", p.DisplayName)
	}
}

// =============================================================================
// Tests: Concurrent/edge cases
// =============================================================================

func TestSSOService_CreateProvider_ClientSecretEncrypted(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	svc := newTestSSOService(ipRepo, newSSOmockTenantRepo(), newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	input := app.CreateProviderInput{
		TenantID:     shared.NewID().String(),
		Provider:     string(identityprovider.ProviderEntraID),
		DisplayName:  "SSO Provider",
		ClientID:     "client-123",
		ClientSecret: "my-secret-value",
	}

	ip, err := svc.CreateProvider(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// The mock encryptor prepends "encrypted:" to the plaintext
	if ip.ClientSecretEncrypted() != "encrypted:my-secret-value" {
		t.Fatalf("expected encrypted secret, got %q", ip.ClientSecretEncrypted())
	}
}

func TestSSOService_GenerateAuthorizeURL_ContainsClientID(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// URL should contain the client ID
	if !strings.Contains(result.AuthorizationURL, "client_id="+provider.ClientID()) {
		t.Fatalf("expected client_id in URL, got %s", result.AuthorizationURL)
	}
	// URL should contain response_type=code
	if !strings.Contains(result.AuthorizationURL, "response_type=code") {
		t.Fatalf("expected response_type=code in URL, got %s", result.AuthorizationURL)
	}
	// URL should contain the redirect URI
	if !strings.Contains(result.AuthorizationURL, "redirect_uri=") {
		t.Fatalf("expected redirect_uri in URL, got %s", result.AuthorizationURL)
	}
}

func TestSSOService_GenerateAuthorizeURL_ContainsState(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())

	testTenant := createTestTenant("test-org")
	tenantRepo.addTenant(testTenant)

	provider := createTestProvider(testTenant.ID().String(), identityprovider.ProviderEntraID, true)
	ipRepo.providers[provider.ID()] = provider

	result, err := svc.GenerateAuthorizeURL(context.Background(), app.SSOAuthorizeInput{
		OrgSlug:     "test-org",
		Provider:    string(identityprovider.ProviderEntraID),
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// The state in the URL should match the returned state
	if !strings.Contains(result.AuthorizationURL, "state=") {
		t.Fatalf("expected state parameter in URL, got %s", result.AuthorizationURL)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func makeScopesList(n int) []string {
	scopes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		scopes = append(scopes, "scope"+strings.Repeat("x", i%10))
	}
	return scopes
}

func makeDomainsList(n int) []string {
	domains := make([]string, 0, n)
	for i := 0; i < n; i++ {
		domains = append(domains, "domain"+strings.Repeat("x", i%10)+".com")
	}
	return domains
}
