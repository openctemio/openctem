package unit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/secretstore"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock SecretStore Repository
// =============================================================================

type secretMockRepo struct {
	mu          sync.Mutex
	credentials map[shared.ID]*secretstore.Credential

	// Error overrides
	createErr           error
	getByTenantAndIDErr error
	getByTenantNameErr  error
	listErr             error
	updateErr           error
	deleteErr           error
	updateLastUsedErr   error
	countErr            error

	// Call tracking
	createCalls         int
	getByTenantAndIDCalls int
	getByTenantNameCalls  int
	listCalls           int
	updateCalls         int
	deleteCalls         int
	updateLastUsedCalls int
	countCalls          int

	// Captured arguments
	lastListInput secretstore.ListInput
}

func newSecretMockRepo() *secretMockRepo {
	return &secretMockRepo{
		credentials: make(map[shared.ID]*secretstore.Credential),
	}
}

func (m *secretMockRepo) Create(_ context.Context, cred *secretstore.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.credentials[cred.ID] = cred
	return nil
}

func (m *secretMockRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*secretstore.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByTenantAndIDCalls++
	if m.getByTenantAndIDErr != nil {
		return nil, m.getByTenantAndIDErr
	}
	cred, ok := m.credentials[id]
	if !ok {
		return nil, errors.New("credential not found")
	}
	if cred.TenantID != tenantID {
		return nil, errors.New("credential not found")
	}
	return cred, nil
}

func (m *secretMockRepo) GetByTenantAndName(_ context.Context, tenantID shared.ID, name string) (*secretstore.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByTenantNameCalls++
	if m.getByTenantNameErr != nil {
		return nil, m.getByTenantNameErr
	}
	for _, cred := range m.credentials {
		if cred.TenantID == tenantID && cred.Name == name {
			return cred, nil
		}
	}
	return nil, errors.New("credential not found")
}

func (m *secretMockRepo) List(_ context.Context, input secretstore.ListInput) (*secretstore.ListOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	m.lastListInput = input
	if m.listErr != nil {
		return nil, m.listErr
	}
	items := make([]*secretstore.Credential, 0, len(m.credentials))
	for _, cred := range m.credentials {
		if cred.TenantID == input.TenantID {
			items = append(items, cred)
		}
	}
	return &secretstore.ListOutput{
		Items:      items,
		TotalCount: len(items),
	}, nil
}

func (m *secretMockRepo) Update(_ context.Context, cred *secretstore.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.credentials[cred.ID] = cred
	return nil
}

func (m *secretMockRepo) DeleteByTenantAndID(_ context.Context, tenantID, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	cred, ok := m.credentials[id]
	if !ok || cred.TenantID != tenantID {
		return errors.New("credential not found")
	}
	delete(m.credentials, id)
	return nil
}

func (m *secretMockRepo) UpdateLastUsedByTenantAndID(_ context.Context, _, _ shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateLastUsedCalls++
	if m.updateLastUsedErr != nil {
		return m.updateLastUsedErr
	}
	return nil
}

func (m *secretMockRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countCalls++
	if m.countErr != nil {
		return 0, m.countErr
	}
	return len(m.credentials), nil
}

// Helper to add a credential directly to the mock store.
func (m *secretMockRepo) addCredential(cred *secretstore.Credential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.credentials[cred.ID] = cred
}

// =============================================================================
// Mock Audit Repository (minimal, for AuditService dependency)
// =============================================================================

type secretMockAuditRepo struct {
	mu   sync.Mutex
	logs []*audit.AuditLog
}

func newSecretMockAuditRepo() *secretMockAuditRepo {
	return &secretMockAuditRepo{
		logs: make([]*audit.AuditLog, 0),
	}
}

func (m *secretMockAuditRepo) Create(_ context.Context, log *audit.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, log)
	return nil
}

func (m *secretMockAuditRepo) CreateBatch(_ context.Context, logs []*audit.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, logs...)
	return nil
}

func (m *secretMockAuditRepo) GetByID(_ context.Context, _ shared.ID) (*audit.AuditLog, error) {
	return nil, errors.New("not implemented")
}

func (m *secretMockAuditRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*audit.AuditLog, error) {
	return nil, nil
}

func (m *secretMockAuditRepo) List(_ context.Context, _ audit.Filter, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *secretMockAuditRepo) Count(_ context.Context, _ audit.Filter) (int64, error) {
	return 0, nil
}

func (m *secretMockAuditRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *secretMockAuditRepo) GetLatestByResource(_ context.Context, _ audit.ResourceType, _ string) (*audit.AuditLog, error) {
	return nil, errors.New("not implemented")
}

func (m *secretMockAuditRepo) ListByActor(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *secretMockAuditRepo) ListByResource(_ context.Context, _ audit.ResourceType, _ string, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *secretMockAuditRepo) CountByAction(_ context.Context, _ *shared.ID, _ audit.Action, _ time.Time) (int64, error) {
	return 0, nil
}

// =============================================================================
// Helper: create service
// =============================================================================

// 32-byte test encryption key.
var secretTestKey = []byte("01234567890123456789012345678901")

func newSecretTestService(t *testing.T) (*app.SecretStoreService, *secretMockRepo, *secretMockAuditRepo) {
	t.Helper()
	repo := newSecretMockRepo()
	auditRepo := newSecretMockAuditRepo()
	log := logger.NewNop()
	auditSvc := app.NewAuditService(auditRepo, log)

	svc, err := app.NewSecretStoreService(repo, secretTestKey, auditSvc, log)
	if err != nil {
		t.Fatalf("failed to create SecretStoreService: %v", err)
	}
	return svc, repo, auditRepo
}

// Helper: create a credential in the mock store using real encryption.
func secretCreateCredential(t *testing.T, repo *secretMockRepo, tenantID shared.ID, name string, credType secretstore.CredentialType, data any) *secretstore.Credential {
	t.Helper()
	enc, err := secretstore.NewEncryptor(secretTestKey)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}
	encrypted, err := enc.EncryptJSON(data)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}
	userID := shared.NewID()
	cred := secretstore.NewCredential(tenantID, name, credType, encrypted, &userID)
	repo.addCredential(cred)
	return cred
}

// =============================================================================
// Tests: NewSecretStoreService
// =============================================================================

func TestSecretNewService_InvalidKey(t *testing.T) {
	repo := newSecretMockRepo()
	auditRepo := newSecretMockAuditRepo()
	log := logger.NewNop()
	auditSvc := app.NewAuditService(auditRepo, log)

	_, err := app.NewSecretStoreService(repo, []byte("short"), auditSvc, log)
	if err == nil {
		t.Fatal("expected error for invalid encryption key")
	}
}

// =============================================================================
// Tests: CreateCredential
// =============================================================================

func TestSecretCreateCredential_APIKey(t *testing.T) {
	svc, repo, auditRepo := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	userID := shared.NewID()

	cred, err := svc.CreateCredential(ctx, app.CreateCredentialInput{
		TenantID:       tenantID,
		UserID:         userID,
		Name:           "My API Key",
		CredentialType: secretstore.CredentialTypeAPIKey,
		Description:    "Test key",
		Data:           &secretstore.APIKeyData{Key: "sk-test-123"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.Name != "My API Key" {
		t.Fatalf("expected name 'My API Key', got '%s'", cred.Name)
	}
	if cred.CredentialType != secretstore.CredentialTypeAPIKey {
		t.Fatalf("expected type api_key, got '%s'", cred.CredentialType)
	}
	if cred.Description != "Test key" {
		t.Fatalf("expected description 'Test key', got '%s'", cred.Description)
	}
	if cred.TenantID != tenantID {
		t.Fatal("expected tenant ID to match")
	}
	if cred.KeyVersion != 1 {
		t.Fatalf("expected key version 1, got %d", cred.KeyVersion)
	}
	if len(cred.EncryptedData) == 0 {
		t.Fatal("expected encrypted data to be non-empty")
	}
	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}
	// Audit log should have been written
	if len(auditRepo.logs) != 1 {
		t.Fatalf("expected 1 audit log, got %d", len(auditRepo.logs))
	}
}

func TestSecretCreateCredential_BasicAuth(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	cred, err := svc.CreateCredential(ctx, app.CreateCredentialInput{
		TenantID:       shared.NewID(),
		UserID:         shared.NewID(),
		Name:           "DB Creds",
		CredentialType: secretstore.CredentialTypeBasicAuth,
		Data:           &secretstore.BasicAuthData{Username: "admin", Password: "secret"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.CredentialType != secretstore.CredentialTypeBasicAuth {
		t.Fatalf("expected type basic_auth, got '%s'", cred.CredentialType)
	}
}

func TestSecretCreateCredential_BearerToken(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	cred, err := svc.CreateCredential(ctx, app.CreateCredentialInput{
		TenantID:       shared.NewID(),
		UserID:         shared.NewID(),
		Name:           "Bearer",
		CredentialType: secretstore.CredentialTypeBearerToken,
		Data:           &secretstore.BearerTokenData{Token: "tok-123"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.CredentialType != secretstore.CredentialTypeBearerToken {
		t.Fatalf("expected type bearer_token, got '%s'", cred.CredentialType)
	}
}

func TestSecretCreateCredential_SSHKey(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	cred, err := svc.CreateCredential(ctx, app.CreateCredentialInput{
		TenantID:       shared.NewID(),
		UserID:         shared.NewID(),
		Name:           "SSH",
		CredentialType: secretstore.CredentialTypeSSHKey,
		Data:           &secretstore.SSHKeyData{PrivateKey: "-----BEGIN RSA KEY-----", Passphrase: "pass"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.CredentialType != secretstore.CredentialTypeSSHKey {
		t.Fatalf("expected type ssh_key, got '%s'", cred.CredentialType)
	}
}

func TestSecretCreateCredential_WithExpiration(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	expires := time.Now().Add(24 * time.Hour)
	cred, err := svc.CreateCredential(ctx, app.CreateCredentialInput{
		TenantID:       shared.NewID(),
		UserID:         shared.NewID(),
		Name:           "Expiring Key",
		CredentialType: secretstore.CredentialTypeAPIKey,
		Data:           &secretstore.APIKeyData{Key: "key-456"},
		ExpiresAt:      &expires,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
}

func TestSecretCreateCredential_InvalidType(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.CreateCredential(ctx, app.CreateCredentialInput{
		TenantID:       shared.NewID(),
		UserID:         shared.NewID(),
		Name:           "Bad Type",
		CredentialType: secretstore.CredentialType("invalid_type"),
		Data:           &secretstore.APIKeyData{Key: "key"},
	})
	if err == nil {
		t.Fatal("expected error for invalid credential type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestSecretCreateCredential_RepoError(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	repo.createErr = errors.New("db error")

	_, err := svc.CreateCredential(ctx, app.CreateCredentialInput{
		TenantID:       shared.NewID(),
		UserID:         shared.NewID(),
		Name:           "Test",
		CredentialType: secretstore.CredentialTypeAPIKey,
		Data:           &secretstore.APIKeyData{Key: "key"},
	})
	if err == nil {
		t.Fatal("expected error from repo Create")
	}
}

// =============================================================================
// Tests: GetCredential
// =============================================================================

func TestSecretGetCredential_Success(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "test-key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})

	result, err := svc.GetCredential(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Name != "test-key" {
		t.Fatalf("expected name 'test-key', got '%s'", result.Name)
	}
	if repo.getByTenantAndIDCalls != 1 {
		t.Fatalf("expected 1 getByTenantAndID call, got %d", repo.getByTenantAndIDCalls)
	}
}

func TestSecretGetCredential_InvalidID(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.GetCredential(ctx, shared.NewID(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestSecretGetCredential_NotFound(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.GetCredential(ctx, shared.NewID(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestSecretGetCredential_WrongTenant(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantA := shared.NewID()
	tenantB := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantA, "key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})

	_, err := svc.GetCredential(ctx, tenantB, cred.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

// =============================================================================
// Tests: ListCredentials
// =============================================================================

func TestSecretListCredentials_Success(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	secretCreateCredential(t, repo, tenantID, "key-1", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k1"})
	secretCreateCredential(t, repo, tenantID, "key-2", secretstore.CredentialTypeBearerToken, &secretstore.BearerTokenData{Token: "t1"})

	result, err := svc.ListCredentials(ctx, app.ListCredentialsInput{
		TenantID: tenantID,
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalCount != 2 {
		t.Fatalf("expected 2 credentials, got %d", result.TotalCount)
	}
	if len(result.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result.Items))
	}
	if repo.listCalls != 1 {
		t.Fatalf("expected 1 list call, got %d", repo.listCalls)
	}
}

func TestSecretListCredentials_WithTypeFilter(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	credType := "api_key"

	_, err := svc.ListCredentials(ctx, app.ListCredentialsInput{
		TenantID:       tenantID,
		CredentialType: &credType,
		Page:           1,
		PageSize:       10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.lastListInput.CredentialType == nil {
		t.Fatal("expected CredentialType filter to be set")
	}
	if *repo.lastListInput.CredentialType != secretstore.CredentialTypeAPIKey {
		t.Fatalf("expected filter type api_key, got '%s'", *repo.lastListInput.CredentialType)
	}
}

func TestSecretListCredentials_WithSort(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.ListCredentials(ctx, app.ListCredentialsInput{
		TenantID:  shared.NewID(),
		Page:      1,
		PageSize:  20,
		SortBy:    "name",
		SortOrder: "asc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.lastListInput.SortBy != "name" {
		t.Fatalf("expected sort by 'name', got '%s'", repo.lastListInput.SortBy)
	}
	if repo.lastListInput.SortOrder != "asc" {
		t.Fatalf("expected sort order 'asc', got '%s'", repo.lastListInput.SortOrder)
	}
}

func TestSecretListCredentials_RepoError(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	repo.listErr = errors.New("db error")

	_, err := svc.ListCredentials(ctx, app.ListCredentialsInput{
		TenantID: shared.NewID(),
		Page:     1,
		PageSize: 20,
	})
	if err == nil {
		t.Fatal("expected error from repo List")
	}
}

func TestSecretListCredentials_EmptyResult(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	result, err := svc.ListCredentials(ctx, app.ListCredentialsInput{
		TenantID: shared.NewID(),
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalCount != 0 {
		t.Fatalf("expected 0 credentials, got %d", result.TotalCount)
	}
}

// =============================================================================
// Tests: UpdateCredential
// =============================================================================

func TestSecretUpdateCredential_Success(t *testing.T) {
	svc, repo, auditRepo := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "old-name", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})

	updated, err := svc.UpdateCredential(ctx, app.UpdateCredentialInput{
		TenantID:     tenantID,
		CredentialID: cred.ID.String(),
		Name:         "new-name",
		Description:  "Updated desc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "new-name" {
		t.Fatalf("expected name 'new-name', got '%s'", updated.Name)
	}
	if updated.Description != "Updated desc" {
		t.Fatalf("expected description 'Updated desc', got '%s'", updated.Description)
	}
	if repo.updateCalls != 1 {
		t.Fatalf("expected 1 update call, got %d", repo.updateCalls)
	}
	// Audit log for update
	if len(auditRepo.logs) < 1 {
		t.Fatal("expected at least 1 audit log for update")
	}
}

func TestSecretUpdateCredential_WithNewData(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "old-key"})
	oldEncrypted := make([]byte, len(cred.EncryptedData))
	copy(oldEncrypted, cred.EncryptedData)

	updated, err := svc.UpdateCredential(ctx, app.UpdateCredentialInput{
		TenantID:     tenantID,
		CredentialID: cred.ID.String(),
		Name:         "key",
		Data:         &secretstore.APIKeyData{Key: "new-key"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Encrypted data should be different
	if string(updated.EncryptedData) == string(oldEncrypted) {
		t.Fatal("expected encrypted data to change after update with new data")
	}
}

func TestSecretUpdateCredential_WithExpiration(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})

	expires := time.Now().Add(48 * time.Hour)
	updated, err := svc.UpdateCredential(ctx, app.UpdateCredentialInput{
		TenantID:     tenantID,
		CredentialID: cred.ID.String(),
		Name:         "key",
		ExpiresAt:    &expires,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
}

func TestSecretUpdateCredential_KeepNameIfEmpty(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "original", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})

	updated, err := svc.UpdateCredential(ctx, app.UpdateCredentialInput{
		TenantID:     tenantID,
		CredentialID: cred.ID.String(),
		Name:         "", // empty name should keep original
		Description:  "new desc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "original" {
		t.Fatalf("expected name to remain 'original', got '%s'", updated.Name)
	}
}

func TestSecretUpdateCredential_InvalidID(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.UpdateCredential(ctx, app.UpdateCredentialInput{
		TenantID:     shared.NewID(),
		CredentialID: "bad",
		Name:         "test",
	})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestSecretUpdateCredential_NotFound(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.UpdateCredential(ctx, app.UpdateCredentialInput{
		TenantID:     shared.NewID(),
		CredentialID: shared.NewID().String(),
		Name:         "test",
	})
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestSecretUpdateCredential_RepoError(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})
	repo.updateErr = errors.New("db error")

	_, err := svc.UpdateCredential(ctx, app.UpdateCredentialInput{
		TenantID:     tenantID,
		CredentialID: cred.ID.String(),
		Name:         "updated",
	})
	if err == nil {
		t.Fatal("expected error from repo Update")
	}
}

// =============================================================================
// Tests: RotateCredential
// =============================================================================

func TestSecretRotateCredential_Success(t *testing.T) {
	svc, repo, auditRepo := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "rotate-key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "old-key"})
	originalVersion := cred.KeyVersion

	rotated, err := svc.RotateCredential(ctx, tenantID, cred.ID.String(), &secretstore.APIKeyData{Key: "new-key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rotated.KeyVersion != originalVersion+1 {
		t.Fatalf("expected key version %d, got %d", originalVersion+1, rotated.KeyVersion)
	}
	if rotated.LastRotatedAt == nil {
		t.Fatal("expected LastRotatedAt to be set")
	}
	if repo.updateCalls != 1 {
		t.Fatalf("expected 1 update call, got %d", repo.updateCalls)
	}
	// Audit log for rotation
	if len(auditRepo.logs) < 1 {
		t.Fatal("expected at least 1 audit log for rotation")
	}
}

func TestSecretRotateCredential_InvalidID(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.RotateCredential(ctx, shared.NewID(), "bad", &secretstore.APIKeyData{Key: "k"})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestSecretRotateCredential_NotFound(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.RotateCredential(ctx, shared.NewID(), shared.NewID().String(), &secretstore.APIKeyData{Key: "k"})
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestSecretRotateCredential_RepoError(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})
	repo.updateErr = errors.New("db error")

	_, err := svc.RotateCredential(ctx, tenantID, cred.ID.String(), &secretstore.APIKeyData{Key: "new"})
	if err == nil {
		t.Fatal("expected error from repo Update")
	}
}

func TestSecretRotateCredential_MultipleRotations(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "v1"})

	// Rotate twice
	rotated1, err := svc.RotateCredential(ctx, tenantID, cred.ID.String(), &secretstore.APIKeyData{Key: "v2"})
	if err != nil {
		t.Fatalf("unexpected error on first rotation: %v", err)
	}
	rotated2, err := svc.RotateCredential(ctx, tenantID, rotated1.ID.String(), &secretstore.APIKeyData{Key: "v3"})
	if err != nil {
		t.Fatalf("unexpected error on second rotation: %v", err)
	}
	if rotated2.KeyVersion != 3 {
		t.Fatalf("expected key version 3 after two rotations, got %d", rotated2.KeyVersion)
	}
}

// =============================================================================
// Tests: DeleteCredential
// =============================================================================

func TestSecretDeleteCredential_Success(t *testing.T) {
	svc, repo, auditRepo := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "delete-me", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})

	err := svc.DeleteCredential(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.deleteCalls != 1 {
		t.Fatalf("expected 1 delete call, got %d", repo.deleteCalls)
	}
	// Audit log for deletion
	if len(auditRepo.logs) < 1 {
		t.Fatal("expected at least 1 audit log for deletion")
	}
}

func TestSecretDeleteCredential_InvalidID(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	err := svc.DeleteCredential(ctx, shared.NewID(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestSecretDeleteCredential_NotFound(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	err := svc.DeleteCredential(ctx, shared.NewID(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestSecretDeleteCredential_WrongTenant(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantA := shared.NewID()
	tenantB := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantA, "key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})

	err := svc.DeleteCredential(ctx, tenantB, cred.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestSecretDeleteCredential_RepoError(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	repo.deleteErr = errors.New("db error")

	err := svc.DeleteCredential(ctx, shared.NewID(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo Delete")
	}
}

// =============================================================================
// Tests: DecryptCredentialData
// =============================================================================

func TestSecretDecryptCredentialData_APIKey(t *testing.T) {
	svc, repo, auditRepo := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "my-key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "secret-key-123"})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	apiKeyData, ok := data.(*secretstore.APIKeyData)
	if !ok {
		t.Fatalf("expected *APIKeyData, got %T", data)
	}
	if apiKeyData.Key != "secret-key-123" {
		t.Fatalf("expected key 'secret-key-123', got '%s'", apiKeyData.Key)
	}
	// Should update last used
	if repo.updateLastUsedCalls != 1 {
		t.Fatalf("expected 1 updateLastUsed call, got %d", repo.updateLastUsedCalls)
	}
	// Should audit access
	if len(auditRepo.logs) < 1 {
		t.Fatal("expected at least 1 audit log for access")
	}
}

func TestSecretDecryptCredentialData_BasicAuth(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "db-creds", secretstore.CredentialTypeBasicAuth, &secretstore.BasicAuthData{Username: "admin", Password: "p@ss"})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	basicAuth, ok := data.(*secretstore.BasicAuthData)
	if !ok {
		t.Fatalf("expected *BasicAuthData, got %T", data)
	}
	if basicAuth.Username != "admin" || basicAuth.Password != "p@ss" {
		t.Fatalf("unexpected basic auth data: %+v", basicAuth)
	}
}

func TestSecretDecryptCredentialData_BearerToken(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "bearer", secretstore.CredentialTypeBearerToken, &secretstore.BearerTokenData{Token: "tok-abc"})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bearer, ok := data.(*secretstore.BearerTokenData)
	if !ok {
		t.Fatalf("expected *BearerTokenData, got %T", data)
	}
	if bearer.Token != "tok-abc" {
		t.Fatalf("expected token 'tok-abc', got '%s'", bearer.Token)
	}
}

func TestSecretDecryptCredentialData_SSHKey(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "ssh", secretstore.CredentialTypeSSHKey, &secretstore.SSHKeyData{PrivateKey: "-----BEGIN KEY-----", Passphrase: "pass"})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sshKey, ok := data.(*secretstore.SSHKeyData)
	if !ok {
		t.Fatalf("expected *SSHKeyData, got %T", data)
	}
	if sshKey.PrivateKey != "-----BEGIN KEY-----" {
		t.Fatalf("unexpected private key: %s", sshKey.PrivateKey)
	}
}

func TestSecretDecryptCredentialData_AWSRole(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "aws", secretstore.CredentialTypeAWSRole, &secretstore.AWSRoleData{RoleARN: "arn:aws:iam::123:role/test", ExternalID: "ext"})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	aws, ok := data.(*secretstore.AWSRoleData)
	if !ok {
		t.Fatalf("expected *AWSRoleData, got %T", data)
	}
	if aws.RoleARN != "arn:aws:iam::123:role/test" {
		t.Fatalf("unexpected role ARN: %s", aws.RoleARN)
	}
}

func TestSecretDecryptCredentialData_GCPServiceAccount(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "gcp", secretstore.CredentialTypeGCPServiceAccount, &secretstore.GCPServiceAccountData{JSONKey: `{"type":"service_account"}`})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gcp, ok := data.(*secretstore.GCPServiceAccountData)
	if !ok {
		t.Fatalf("expected *GCPServiceAccountData, got %T", data)
	}
	if gcp.JSONKey != `{"type":"service_account"}` {
		t.Fatalf("unexpected JSON key: %s", gcp.JSONKey)
	}
}

func TestSecretDecryptCredentialData_AzureServicePrincipal(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "azure", secretstore.CredentialTypeAzureServicePrincipal, &secretstore.AzureServicePrincipalData{
		TenantID: "az-tenant", ClientID: "az-client", ClientSecret: "az-secret",
	})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	azure, ok := data.(*secretstore.AzureServicePrincipalData)
	if !ok {
		t.Fatalf("expected *AzureServicePrincipalData, got %T", data)
	}
	if azure.ClientID != "az-client" {
		t.Fatalf("unexpected client ID: %s", azure.ClientID)
	}
}

func TestSecretDecryptCredentialData_GitHubApp(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "github", secretstore.CredentialTypeGitHubApp, &secretstore.GitHubAppData{
		AppID: "123", InstallationID: "456", PrivateKey: "pkey",
	})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gh, ok := data.(*secretstore.GitHubAppData)
	if !ok {
		t.Fatalf("expected *GitHubAppData, got %T", data)
	}
	if gh.AppID != "123" {
		t.Fatalf("unexpected app ID: %s", gh.AppID)
	}
}

func TestSecretDecryptCredentialData_GitLabToken(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "gitlab", secretstore.CredentialTypeGitLabToken, &secretstore.GitLabTokenData{Token: "glpat-xxx"})

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gl, ok := data.(*secretstore.GitLabTokenData)
	if !ok {
		t.Fatalf("expected *GitLabTokenData, got %T", data)
	}
	if gl.Token != "glpat-xxx" {
		t.Fatalf("unexpected token: %s", gl.Token)
	}
}

func TestSecretDecryptCredentialData_ExpiredCredential(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "expired", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})
	// Set expiration in the past
	past := time.Now().Add(-1 * time.Hour)
	cred.ExpiresAt = &past

	_, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err == nil {
		t.Fatal("expected error for expired credential")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestSecretDecryptCredentialData_InvalidID(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.DecryptCredentialData(ctx, shared.NewID(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestSecretDecryptCredentialData_NotFound(t *testing.T) {
	svc, _, _ := newSecretTestService(t)
	ctx := context.Background()

	_, err := svc.DecryptCredentialData(ctx, shared.NewID(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestSecretDecryptCredentialData_WrongTenant(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantA := shared.NewID()
	tenantB := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantA, "key", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "k"})

	_, err := svc.DecryptCredentialData(ctx, tenantB, cred.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestSecretDecryptCredentialData_NotExpiredYet(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "future", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "future-key"})
	future := time.Now().Add(24 * time.Hour)
	cred.ExpiresAt = &future

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	apiKey, ok := data.(*secretstore.APIKeyData)
	if !ok {
		t.Fatalf("expected *APIKeyData, got %T", data)
	}
	if apiKey.Key != "future-key" {
		t.Fatalf("expected key 'future-key', got '%s'", apiKey.Key)
	}
}

func TestSecretDecryptCredentialData_NoExpiration(t *testing.T) {
	svc, repo, _ := newSecretTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	cred := secretCreateCredential(t, repo, tenantID, "no-expire", secretstore.CredentialTypeAPIKey, &secretstore.APIKeyData{Key: "forever"})
	// ExpiresAt is nil by default

	data, err := svc.DecryptCredentialData(ctx, tenantID, cred.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	apiKey, ok := data.(*secretstore.APIKeyData)
	if !ok {
		t.Fatalf("expected *APIKeyData, got %T", data)
	}
	if apiKey.Key != "forever" {
		t.Fatalf("expected key 'forever', got '%s'", apiKey.Key)
	}
}
