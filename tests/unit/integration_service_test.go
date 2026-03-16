package unit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Integration Repository
// =============================================================================

type mockIntegrationRepo struct {
	integrations map[shared.ID]*integration.Integration

	// Error overrides
	createErr          error
	getByIDErr         error
	getByTenantNameErr error
	updateErr          error
	deleteErr          error
	listErr            error
	countErr           error

	// Call tracking
	createCalls int
	updateCalls int
	deleteCalls int
	listCalls   int
}

func newMockIntegrationRepo() *mockIntegrationRepo {
	return &mockIntegrationRepo{
		integrations: make(map[shared.ID]*integration.Integration),
	}
}

func (m *mockIntegrationRepo) Create(_ context.Context, i *integration.Integration) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.integrations[i.ID()] = i
	return nil
}

func (m *mockIntegrationRepo) GetByID(_ context.Context, id integration.ID) (*integration.Integration, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	intg, ok := m.integrations[id]
	if !ok {
		return nil, integration.ErrIntegrationNotFound
	}
	return intg, nil
}

func (m *mockIntegrationRepo) GetByTenantAndName(_ context.Context, tenantID integration.ID, name string) (*integration.Integration, error) {
	if m.getByTenantNameErr != nil {
		return nil, m.getByTenantNameErr
	}
	for _, intg := range m.integrations {
		if intg.TenantID() == tenantID && intg.Name() == name {
			return intg, nil
		}
	}
	return nil, integration.ErrIntegrationNotFound
}

func (m *mockIntegrationRepo) Update(_ context.Context, i *integration.Integration) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.integrations[i.ID()] = i
	return nil
}

func (m *mockIntegrationRepo) Delete(_ context.Context, id integration.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.integrations[id]; !ok {
		return integration.ErrIntegrationNotFound
	}
	delete(m.integrations, id)
	return nil
}

func (m *mockIntegrationRepo) List(_ context.Context, filter integration.Filter) (integration.ListResult, error) {
	m.listCalls++
	if m.listErr != nil {
		return integration.ListResult{}, m.listErr
	}

	var data []*integration.Integration
	for _, intg := range m.integrations {
		if filter.TenantID != nil && intg.TenantID() != *filter.TenantID {
			continue
		}
		if filter.Category != nil && intg.Category() != *filter.Category {
			continue
		}
		if filter.Provider != nil && intg.Provider() != *filter.Provider {
			continue
		}
		if filter.Status != nil && intg.Status() != *filter.Status {
			continue
		}
		if filter.Search != "" && !strings.Contains(strings.ToLower(intg.Name()), strings.ToLower(filter.Search)) {
			continue
		}
		data = append(data, intg)
	}

	total := int64(len(data))

	// Pagination
	page := filter.Page
	if page < 1 {
		page = 1
	}
	perPage := filter.PerPage
	if perPage < 1 {
		perPage = 20
	}

	start := (page - 1) * perPage
	if start > len(data) {
		start = len(data)
	}
	end := start + perPage
	if end > len(data) {
		end = len(data)
	}

	totalPages := int(total) / perPage
	if int(total)%perPage > 0 {
		totalPages++
	}

	return integration.ListResult{
		Data:       data[start:end],
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

func (m *mockIntegrationRepo) Count(_ context.Context, _ integration.Filter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.integrations)), nil
}

func (m *mockIntegrationRepo) ListByTenant(_ context.Context, tenantID integration.ID) ([]*integration.Integration, error) {
	var result []*integration.Integration
	for _, intg := range m.integrations {
		if intg.TenantID() == tenantID {
			result = append(result, intg)
		}
	}
	return result, nil
}

func (m *mockIntegrationRepo) ListByCategory(_ context.Context, tenantID integration.ID, category integration.Category) ([]*integration.Integration, error) {
	var result []*integration.Integration
	for _, intg := range m.integrations {
		if intg.TenantID() == tenantID && intg.Category() == category {
			result = append(result, intg)
		}
	}
	return result, nil
}

func (m *mockIntegrationRepo) ListByProvider(_ context.Context, tenantID integration.ID, provider integration.Provider) ([]*integration.Integration, error) {
	var result []*integration.Integration
	for _, intg := range m.integrations {
		if intg.TenantID() == tenantID && intg.Provider() == provider {
			result = append(result, intg)
		}
	}
	return result, nil
}

// =============================================================================
// Mock SCM Extension Repository
// =============================================================================

type mockSCMExtRepo struct {
	extensions map[shared.ID]*integration.SCMExtension

	// Error overrides
	createErr error
	getErr    error
	updateErr error
	deleteErr error

	// Call tracking
	createCalls int
	updateCalls int
}

func newMockSCMExtRepo() *mockSCMExtRepo {
	return &mockSCMExtRepo{
		extensions: make(map[shared.ID]*integration.SCMExtension),
	}
}

func (m *mockSCMExtRepo) Create(_ context.Context, ext *integration.SCMExtension) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.extensions[ext.IntegrationID()] = ext
	return nil
}

func (m *mockSCMExtRepo) GetByIntegrationID(_ context.Context, integrationID integration.ID) (*integration.SCMExtension, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	ext, ok := m.extensions[integrationID]
	if !ok {
		return nil, integration.ErrSCMExtensionNotFound
	}
	return ext, nil
}

func (m *mockSCMExtRepo) Update(_ context.Context, ext *integration.SCMExtension) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.extensions[ext.IntegrationID()] = ext
	return nil
}

func (m *mockSCMExtRepo) Delete(_ context.Context, integrationID integration.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.extensions, integrationID)
	return nil
}

func (m *mockSCMExtRepo) GetIntegrationWithSCM(_ context.Context, id integration.ID) (*integration.IntegrationWithSCM, error) {
	return nil, integration.ErrIntegrationNotFound
}

func (m *mockSCMExtRepo) ListIntegrationsWithSCM(_ context.Context, _ integration.ID) ([]*integration.IntegrationWithSCM, error) {
	return nil, nil
}

// =============================================================================
// Mock Notification Extension Repository
// =============================================================================

type mockNotificationExtRepo struct {
	extensions map[shared.ID]*integration.NotificationExtension

	// Error overrides
	createErr error
	getErr    error
	updateErr error
	deleteErr error

	// Linked integration repo (for combined queries)
	integrationRepo *mockIntegrationRepo

	// Call tracking
	createCalls int
	updateCalls int
}

func newMockNotificationExtRepo() *mockNotificationExtRepo {
	return &mockNotificationExtRepo{
		extensions: make(map[shared.ID]*integration.NotificationExtension),
	}
}

func (m *mockNotificationExtRepo) Create(_ context.Context, ext *integration.NotificationExtension) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.extensions[ext.IntegrationID()] = ext
	return nil
}

func (m *mockNotificationExtRepo) GetByIntegrationID(_ context.Context, integrationID integration.ID) (*integration.NotificationExtension, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	ext, ok := m.extensions[integrationID]
	if !ok {
		return nil, integration.ErrNotificationExtensionNotFound
	}
	return ext, nil
}

func (m *mockNotificationExtRepo) Update(_ context.Context, ext *integration.NotificationExtension) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.extensions[ext.IntegrationID()] = ext
	return nil
}

func (m *mockNotificationExtRepo) Delete(_ context.Context, integrationID integration.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.extensions, integrationID)
	return nil
}

func (m *mockNotificationExtRepo) GetIntegrationWithNotification(_ context.Context, id integration.ID) (*integration.IntegrationWithNotification, error) {
	return nil, integration.ErrIntegrationNotFound
}

func (m *mockNotificationExtRepo) ListIntegrationsWithNotification(_ context.Context, tenantID integration.ID) ([]*integration.IntegrationWithNotification, error) {
	if m.integrationRepo == nil {
		return nil, nil
	}

	var result []*integration.IntegrationWithNotification
	for _, intg := range m.integrationRepo.integrations {
		if intg.TenantID() == tenantID && intg.Category() == integration.CategoryNotification {
			ext := m.extensions[intg.ID()]
			result = append(result, integration.NewIntegrationWithNotification(intg, ext))
		}
	}
	return result, nil
}

// =============================================================================
// Mock Encryptor (tracks encrypt/decrypt calls)
// =============================================================================

type mockEncryptor struct {
	// Behavior
	encryptErr error
	decryptErr error

	// Tracking
	encryptCalls int
	decryptCalls int

	// Prefix to add on encrypt (to verify encryption happened)
	prefix string
}

func newMockEncryptor() *mockEncryptor {
	return &mockEncryptor{
		prefix: "encrypted:",
	}
}

func (m *mockEncryptor) EncryptString(plaintext string) (string, error) {
	m.encryptCalls++
	if m.encryptErr != nil {
		return "", m.encryptErr
	}
	return m.prefix + plaintext, nil
}

func (m *mockEncryptor) DecryptString(encoded string) (string, error) {
	m.decryptCalls++
	if m.decryptErr != nil {
		return "", m.decryptErr
	}
	if strings.HasPrefix(encoded, m.prefix) {
		return strings.TrimPrefix(encoded, m.prefix), nil
	}
	// Simulate backward compat: if not encrypted, return as-is with error
	return "", fmt.Errorf("not encrypted")
}

// =============================================================================
// Helper: create IntegrationService for tests
// =============================================================================

func newTestIntegrationService(
	repo *mockIntegrationRepo,
	scmRepo *mockSCMExtRepo,
	encryptor crypto.Encryptor,
) *app.IntegrationService {
	log := logger.NewNop()
	svc := app.NewIntegrationService(repo, scmRepo, encryptor, log)
	return svc
}

func newTestIntegrationServiceWithNotification(
	repo *mockIntegrationRepo,
	scmRepo *mockSCMExtRepo,
	notifRepo *mockNotificationExtRepo,
	encryptor crypto.Encryptor,
) *app.IntegrationService {
	log := logger.NewNop()
	svc := app.NewIntegrationService(repo, scmRepo, encryptor, log)
	svc.SetNotificationExtensionRepository(notifRepo)
	return svc
}

// validCreateInput returns a valid CreateIntegrationInput for a security integration.
func validCreateInput(tenantID string) app.CreateIntegrationInput {
	return app.CreateIntegrationInput{
		TenantID:    tenantID,
		Name:        "My Snyk Integration",
		Description: "Snyk scanning integration",
		Category:    "security",
		Provider:    "snyk",
		AuthType:    "api_key",
		BaseURL:     "https://api.snyk.io",
		Credentials: "snyk-api-key-12345",
	}
}

// =============================================================================
// CreateIntegration Tests
// =============================================================================

func TestCreateIntegration_Success(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	enc := newMockEncryptor()
	svc := newTestIntegrationService(repo, scmRepo, enc)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)

	result, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name() != input.Name {
		t.Errorf("expected name %q, got %q", input.Name, result.Name())
	}
	if result.Description() != input.Description {
		t.Errorf("expected description %q, got %q", input.Description, result.Description())
	}
	if result.Category() != integration.CategorySecurity {
		t.Errorf("expected category %q, got %q", integration.CategorySecurity, result.Category())
	}
	if result.Provider() != integration.ProviderSnyk {
		t.Errorf("expected provider %q, got %q", integration.ProviderSnyk, result.Provider())
	}
	if result.Status() != integration.StatusPending {
		t.Errorf("expected status %q, got %q", integration.StatusPending, result.Status())
	}
	if result.BaseURL() != input.BaseURL {
		t.Errorf("expected base URL %q, got %q", input.BaseURL, result.BaseURL())
	}

	// Verify the integration was saved to the repo
	if repo.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", repo.createCalls)
	}
	if len(repo.integrations) != 1 {
		t.Errorf("expected 1 integration in repo, got %d", len(repo.integrations))
	}
}

func TestCreateIntegration_EmptyName(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	input.Name = ""

	// The service creates the integration with an empty name;
	// name validation may happen at a higher level or in the entity.
	// We verify the service does not crash with empty name.
	result, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		// If there is a validation error for empty name, that is acceptable.
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected validation error or success, got %v", err)
		}
		return
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
}

func TestCreateIntegration_InvalidProvider(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	input.Provider = "invalid_provider"

	_, err := svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid provider")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateIntegration_InvalidCategory(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	input.Category = "nonexistent"

	_, err := svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid category")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateIntegration_InvalidAuthType(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	input.AuthType = "invalid_auth"

	_, err := svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid auth type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateIntegration_ProviderCategoryMismatch(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	// github is SCM, but we set category to security
	input.Category = "scm"
	input.Provider = "snyk" // snyk is security, not scm

	_, err := svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for provider/category mismatch")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateIntegration_InvalidTenantID(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	input := validCreateInput("not-a-uuid")

	_, err := svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateIntegration_DuplicateName(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)

	// Create the first integration
	_, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	// Try to create another with the same name
	_, err = svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Errorf("expected conflict error, got %v", err)
	}
}

func TestCreateIntegration_RepoCreateError(t *testing.T) {
	repo := newMockIntegrationRepo()
	repo.createErr = errors.New("db connection failed")
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)

	_, err := svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when repo Create fails")
	}
}

// =============================================================================
// CreateIntegration SCM Extension Tests
// =============================================================================

func TestCreateIntegration_SCM_CreatesSCMExtension(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	enc := newMockEncryptor()
	svc := newTestIntegrationService(repo, scmRepo, enc)

	tenantID := shared.NewID().String()
	input := app.CreateIntegrationInput{
		TenantID:        tenantID,
		Name:            "My GitHub",
		Category:        "scm",
		Provider:        "github",
		AuthType:        "token",
		Credentials:     "ghp_test123",
		SCMOrganization: "my-org",
	}

	result, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// SCM extension should have been created
	if scmRepo.createCalls != 1 {
		t.Errorf("expected 1 SCM extension create call, got %d", scmRepo.createCalls)
	}

	// SCM extension should have the organization set
	if result.SCM == nil {
		t.Fatal("expected SCM extension, got nil")
	}
	if result.SCM.SCMOrganization() != "my-org" {
		t.Errorf("expected SCM organization %q, got %q", "my-org", result.SCM.SCMOrganization())
	}
}

func TestCreateIntegration_NonSCM_NoSCMExtension(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID) // security integration

	result, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// No SCM extension should be created for non-SCM integrations
	if scmRepo.createCalls != 0 {
		t.Errorf("expected 0 SCM extension create calls for security integration, got %d", scmRepo.createCalls)
	}
	if result.SCM != nil {
		t.Error("expected nil SCM extension for security integration")
	}
}

func TestCreateIntegration_SCM_ExtensionCreateFails_RollsBack(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	scmRepo.createErr = errors.New("extension create failed")
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := app.CreateIntegrationInput{
		TenantID: tenantID,
		Name:     "My GitHub",
		Category: "scm",
		Provider: "github",
		AuthType: "token",
	}

	_, err := svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when SCM extension create fails")
	}

	// Integration should be rolled back (deleted)
	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 delete call for rollback, got %d", repo.deleteCalls)
	}
	if len(repo.integrations) != 0 {
		t.Errorf("expected 0 integrations after rollback, got %d", len(repo.integrations))
	}
}

// =============================================================================
// GetIntegration Tests
// =============================================================================

func TestGetIntegration_Success(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	got, err := svc.GetIntegration(context.Background(), created.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.ID() != created.ID() {
		t.Errorf("expected ID %s, got %s", created.ID(), got.ID())
	}
	if got.Name() != input.Name {
		t.Errorf("expected name %q, got %q", input.Name, got.Name())
	}
}

func TestGetIntegration_NotFound(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	nonExistentID := shared.NewID().String()
	_, err := svc.GetIntegration(context.Background(), nonExistentID)
	if err == nil {
		t.Fatal("expected error for non-existent integration")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestGetIntegration_InvalidID(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	_, err := svc.GetIntegration(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// =============================================================================
// UpdateIntegration Tests
// =============================================================================

func TestUpdateIntegration_Success(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	enc := newMockEncryptor()
	svc := newTestIntegrationService(repo, scmRepo, enc)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	newName := "Updated Name"
	newDesc := "Updated Description"
	updateInput := app.UpdateIntegrationInput{
		Name:        &newName,
		Description: &newDesc,
	}

	updated, err := svc.UpdateIntegration(context.Background(), created.ID().String(), tenantID, updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name() != newName {
		t.Errorf("expected name %q, got %q", newName, updated.Name())
	}
	if updated.Description() != newDesc {
		t.Errorf("expected description %q, got %q", newDesc, updated.Description())
	}
}

func TestUpdateIntegration_PartialUpdate_NameOnly(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	newName := "Only Name Changed"
	updateInput := app.UpdateIntegrationInput{
		Name: &newName,
		// Description and other fields are nil (not updated)
	}

	updated, err := svc.UpdateIntegration(context.Background(), created.ID().String(), tenantID, updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name() != newName {
		t.Errorf("expected name %q, got %q", newName, updated.Name())
	}
	// Original description should be preserved
	if updated.Description() != input.Description {
		t.Errorf("expected description preserved as %q, got %q", input.Description, updated.Description())
	}
}

func TestUpdateIntegration_NotFound(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	newName := "Updated"
	updateInput := app.UpdateIntegrationInput{Name: &newName}

	_, err := svc.UpdateIntegration(context.Background(), shared.NewID().String(), tenantID, updateInput)
	if err == nil {
		t.Fatal("expected error for non-existent integration")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestUpdateIntegration_WrongTenant(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	otherTenantID := shared.NewID().String()
	newName := "Hacked"
	updateInput := app.UpdateIntegrationInput{Name: &newName}

	_, err = svc.UpdateIntegration(context.Background(), created.ID().String(), otherTenantID, updateInput)
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error for tenant isolation, got %v", err)
	}
}

func TestUpdateIntegration_UpdateCredentials(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	enc := newMockEncryptor()
	svc := newTestIntegrationService(repo, scmRepo, enc)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	encryptCallsBefore := enc.encryptCalls
	newCreds := "new-api-key-67890"
	updateInput := app.UpdateIntegrationInput{
		Credentials: &newCreds,
	}

	updated, err := svc.UpdateIntegration(context.Background(), created.ID().String(), tenantID, updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify encryption was called for the new credentials
	if enc.encryptCalls <= encryptCallsBefore {
		t.Error("expected EncryptString to be called for credential update")
	}

	// Verify credentials were encrypted
	expectedEncrypted := "encrypted:" + newCreds
	if updated.CredentialsEncrypted() != expectedEncrypted {
		t.Errorf("expected encrypted credentials %q, got %q", expectedEncrypted, updated.CredentialsEncrypted())
	}
}

func TestUpdateIntegration_SCM_UpdateOrganization(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := app.CreateIntegrationInput{
		TenantID:        tenantID,
		Name:            "My GitHub",
		Category:        "scm",
		Provider:        "github",
		AuthType:        "token",
		SCMOrganization: "original-org",
	}

	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	newOrg := "new-org"
	updateInput := app.UpdateIntegrationInput{
		SCMOrganization: &newOrg,
	}

	updated, err := svc.UpdateIntegration(context.Background(), created.ID().String(), tenantID, updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// SCM extension should have been updated
	if updated.SCM == nil {
		t.Fatal("expected SCM extension, got nil")
	}
	if updated.SCM.SCMOrganization() != newOrg {
		t.Errorf("expected SCM organization %q, got %q", newOrg, updated.SCM.SCMOrganization())
	}
	if scmRepo.updateCalls != 1 {
		t.Errorf("expected 1 SCM extension update call, got %d", scmRepo.updateCalls)
	}
}

// =============================================================================
// DeleteIntegration Tests
// =============================================================================

func TestDeleteIntegration_Success(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	err = svc.DeleteIntegration(context.Background(), created.ID().String(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify it was deleted
	_, err = svc.GetIntegration(context.Background(), created.ID().String())
	if err == nil {
		t.Fatal("expected not found after delete")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestDeleteIntegration_NotFound(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	err := svc.DeleteIntegration(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent integration")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestDeleteIntegration_WrongTenant(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	otherTenantID := shared.NewID().String()
	err = svc.DeleteIntegration(context.Background(), created.ID().String(), otherTenantID)
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error for tenant isolation, got %v", err)
	}

	// Integration should still exist
	got, err := svc.GetIntegration(context.Background(), created.ID().String())
	if err != nil {
		t.Fatalf("integration should still exist: %v", err)
	}
	if got == nil {
		t.Fatal("expected integration to still exist after failed delete")
	}
}

func TestDeleteIntegration_InvalidID(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	err := svc.DeleteIntegration(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// =============================================================================
// ListIntegrations Tests
// =============================================================================

func TestListIntegrations_Success(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()

	// Create several integrations
	for i, name := range []string{"Snyk", "Wiz", "GitHub"} {
		input := validCreateInput(tenantID)
		input.Name = name
		if i == 2 {
			input.Category = "scm"
			input.Provider = "github"
			input.AuthType = "token"
		}
		_, err := svc.CreateIntegration(context.Background(), input)
		if err != nil {
			t.Fatalf("setup create %s failed: %v", name, err)
		}
	}

	result, err := svc.ListIntegrations(context.Background(), app.ListIntegrationsInput{
		TenantID: tenantID,
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected total 3, got %d", result.Total)
	}
	if len(result.Data) != 3 {
		t.Errorf("expected 3 items, got %d", len(result.Data))
	}
}

func TestListIntegrations_WithCategoryFilter(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()

	// Create security integration
	secInput := validCreateInput(tenantID)
	secInput.Name = "Snyk"
	_, err := svc.CreateIntegration(context.Background(), secInput)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Create SCM integration
	scmInput := app.CreateIntegrationInput{
		TenantID: tenantID,
		Name:     "GitHub",
		Category: "scm",
		Provider: "github",
		AuthType: "token",
	}
	_, err = svc.CreateIntegration(context.Background(), scmInput)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Filter by security only
	result, err := svc.ListIntegrations(context.Background(), app.ListIntegrationsInput{
		TenantID: tenantID,
		Category: "security",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 security integration, got %d", result.Total)
	}
	if len(result.Data) > 0 && result.Data[0].Name() != "Snyk" {
		t.Errorf("expected Snyk, got %q", result.Data[0].Name())
	}
}

func TestListIntegrations_Pagination(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()

	// Create 5 integrations
	providers := []struct {
		name     string
		provider string
	}{
		{"Snyk-1", "snyk"},
		{"Wiz-1", "wiz"},
		{"Tenable-1", "tenable"},
		{"CrowdStrike-1", "crowdstrike"},
		{"Snyk-2", "snyk"},
	}
	for _, p := range providers {
		input := validCreateInput(tenantID)
		input.Name = p.name
		input.Provider = p.provider
		_, err := svc.CreateIntegration(context.Background(), input)
		if err != nil {
			t.Fatalf("setup create %s failed: %v", p.name, err)
		}
	}

	// Page 1 with PerPage=2
	result, err := svc.ListIntegrations(context.Background(), app.ListIntegrationsInput{
		TenantID: tenantID,
		Page:     1,
		PerPage:  2,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 5 {
		t.Errorf("expected total 5, got %d", result.Total)
	}
	if len(result.Data) != 2 {
		t.Errorf("expected 2 items on page 1, got %d", len(result.Data))
	}
	if result.TotalPages != 3 {
		t.Errorf("expected 3 total pages, got %d", result.TotalPages)
	}
}

func TestListIntegrations_SearchFilter(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()

	for _, name := range []string{"Production Snyk", "Staging Wiz", "Production Tenable"} {
		input := validCreateInput(tenantID)
		input.Name = name
		if strings.Contains(name, "Wiz") {
			input.Provider = "wiz"
		}
		if strings.Contains(name, "Tenable") {
			input.Provider = "tenable"
		}
		_, err := svc.CreateIntegration(context.Background(), input)
		if err != nil {
			t.Fatalf("setup create %s failed: %v", name, err)
		}
	}

	result, err := svc.ListIntegrations(context.Background(), app.ListIntegrationsInput{
		TenantID: tenantID,
		Search:   "Production",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 results for 'Production' search, got %d", result.Total)
	}
}

func TestListIntegrations_InvalidTenantID(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	_, err := svc.ListIntegrations(context.Background(), app.ListIntegrationsInput{
		TenantID: "invalid",
		Page:     1,
		PerPage:  10,
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestListIntegrations_TenantIsolation(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenant1 := shared.NewID().String()
	tenant2 := shared.NewID().String()

	// Create integration for tenant1
	input1 := validCreateInput(tenant1)
	input1.Name = "Tenant1 Snyk"
	_, err := svc.CreateIntegration(context.Background(), input1)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Create integration for tenant2
	input2 := validCreateInput(tenant2)
	input2.Name = "Tenant2 Snyk"
	_, err = svc.CreateIntegration(context.Background(), input2)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// List for tenant1 should only see tenant1's integration
	result, err := svc.ListIntegrations(context.Background(), app.ListIntegrationsInput{
		TenantID: tenant1,
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 integration for tenant1, got %d", result.Total)
	}
}

// =============================================================================
// Credential Encryption/Decryption Tests
// =============================================================================

func TestCreateIntegration_EncryptsCredentials(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	enc := newMockEncryptor()
	svc := newTestIntegrationService(repo, scmRepo, enc)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	input.Credentials = "my-secret-api-key"

	result, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify encrypt was called
	if enc.encryptCalls == 0 {
		t.Error("expected EncryptString to be called")
	}

	// Verify stored credentials are encrypted (prefixed by mock encryptor)
	if !strings.HasPrefix(result.CredentialsEncrypted(), "encrypted:") {
		t.Errorf("expected encrypted credentials to have prefix, got %q", result.CredentialsEncrypted())
	}

	// The original plaintext should not be stored directly
	if result.CredentialsEncrypted() == input.Credentials {
		t.Error("credentials should be encrypted, not stored as plaintext")
	}
}

func TestCreateIntegration_NoCredentials_NoEncryption(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	enc := newMockEncryptor()
	svc := newTestIntegrationService(repo, scmRepo, enc)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	input.Credentials = "" // No credentials

	_, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Encrypt should not be called when there are no credentials
	if enc.encryptCalls != 0 {
		t.Errorf("expected 0 encrypt calls for empty credentials, got %d", enc.encryptCalls)
	}
}

func TestCreateIntegration_EncryptionFailure(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	enc := newMockEncryptor()
	enc.encryptErr = errors.New("encryption key not configured")
	svc := newTestIntegrationService(repo, scmRepo, enc)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)

	_, err := svc.CreateIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when encryption fails")
	}
}

func TestCreateIntegration_NilEncryptor_UsesNoOp(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	// Pass nil encryptor - service should use NoOp
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	input.Credentials = "plaintext-key"

	result, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error with nil encryptor, got %v", err)
	}

	// With NoOp encryptor, credentials are stored as-is
	if result.CredentialsEncrypted() != "plaintext-key" {
		t.Errorf("expected plaintext with NoOp encryptor, got %q", result.CredentialsEncrypted())
	}
}

func TestDecryptCredentials_RealEncryption(t *testing.T) {
	// Use real AES-256-GCM cipher to test round-trip
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, cipher)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	input.Credentials = "super-secret-token"

	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	// Credentials should be encrypted (base64 encoded, not plaintext)
	if created.CredentialsEncrypted() == "super-secret-token" {
		t.Error("credentials should be encrypted, not plaintext")
	}

	// Verify credentials can be decrypted
	decrypted, err := cipher.DecryptString(created.CredentialsEncrypted())
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if decrypted != "super-secret-token" {
		t.Errorf("expected decrypted %q, got %q", "super-secret-token", decrypted)
	}
}

// =============================================================================
// TestNotification Rate Limiting Tests
// =============================================================================

func TestCheckTestRateLimit_FirstRequest_Allowed(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID()
	id := shared.NewID()
	// Seed a notification integration in the repo
	intg := integration.NewIntegration(id, tenantID, "test-slack", integration.CategoryNotification, integration.ProviderSlack, integration.AuthTypeToken)
	intg.SetCredentials("https://hooks.slack.com/test")
	repo.integrations[id] = intg

	// TestNotificationIntegration will call checkTestRateLimit internally.
	// The first call should succeed (rate limit-wise), though the external
	// notification client will fail since there's no real webhook.
	// We just verify no rate limit error.
	result, err := svc.TestNotificationIntegration(context.Background(), id.String(), tenantID.String())
	// The call may fail at the notification client level, but should not fail
	// due to rate limiting on the first call.
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
			t.Fatal("first test notification should not be rate limited")
		}
		// Other errors (e.g., from notification client) are acceptable
	}
	_ = result
}

func TestCheckTestRateLimit_RapidRequests_RateLimited(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID()
	id := shared.NewID()
	intg := integration.NewIntegration(id, tenantID, "test-slack", integration.CategoryNotification, integration.ProviderSlack, integration.AuthTypeToken)
	intg.SetCredentials("https://hooks.slack.com/test")
	repo.integrations[id] = intg

	// First call
	_, _ = svc.TestNotificationIntegration(context.Background(), id.String(), tenantID.String())

	// Second call immediately should be rate limited
	_, err := svc.TestNotificationIntegration(context.Background(), id.String(), tenantID.String())
	if err == nil {
		t.Fatal("expected rate limit error on rapid second test")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error for rate limit, got %v", err)
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("expected 'rate limit' in error message, got %v", err)
	}
}

func TestCheckTestRateLimit_DifferentIntegrations_IndependentLimits(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID()

	// Create two different integrations
	id1 := shared.NewID()
	intg1 := integration.NewIntegration(id1, tenantID, "slack-1", integration.CategoryNotification, integration.ProviderSlack, integration.AuthTypeToken)
	intg1.SetCredentials("https://hooks.slack.com/test1")
	repo.integrations[id1] = intg1

	id2 := shared.NewID()
	intg2 := integration.NewIntegration(id2, tenantID, "slack-2", integration.CategoryNotification, integration.ProviderSlack, integration.AuthTypeToken)
	intg2.SetCredentials("https://hooks.slack.com/test2")
	repo.integrations[id2] = intg2

	// Call test on integration 1
	_, _ = svc.TestNotificationIntegration(context.Background(), id1.String(), tenantID.String())

	// Call test on integration 2 should not be rate limited (different integration)
	_, err := svc.TestNotificationIntegration(context.Background(), id2.String(), tenantID.String())
	if err != nil && strings.Contains(err.Error(), "rate limit") {
		t.Fatal("different integrations should have independent rate limits")
	}
}

func TestTestNotificationIntegration_NotANotificationIntegration(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID()
	id := shared.NewID()
	// Create a security integration (not notification)
	intg := integration.NewIntegration(id, tenantID, "my-snyk", integration.CategorySecurity, integration.ProviderSnyk, integration.AuthTypeAPIKey)
	repo.integrations[id] = intg

	_, err := svc.TestNotificationIntegration(context.Background(), id.String(), tenantID.String())
	if err == nil {
		t.Fatal("expected error for non-notification integration")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// =============================================================================
// Notification Extension Tests
// =============================================================================

func TestCreateNotificationIntegration_WithConfig(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	notifRepo.integrationRepo = repo
	enc := newMockEncryptor()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, enc)

	tenantID := shared.NewID().String()
	input := app.CreateNotificationIntegrationInput{
		TenantID:    tenantID,
		Name:        "My Slack Channel",
		Description: "Alert channel",
		Provider:    "slack",
		AuthType:    "token",
		Credentials: "https://hooks.slack.com/services/xxx",
		ChannelName: "#alerts",
		EnabledSeverities: []string{
			"critical",
			"high",
			"medium",
		},
		EnabledEventTypes: []string{
			"security_alert",
			"new_finding",
		},
		IncludeDetails:     true,
		MinIntervalMinutes: 10,
	}

	result, err := svc.CreateNotificationIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Verify base integration
	if result.Name() != input.Name {
		t.Errorf("expected name %q, got %q", input.Name, result.Name())
	}
	if result.Category() != integration.CategoryNotification {
		t.Errorf("expected notification category, got %q", result.Category())
	}
	if result.Provider() != integration.ProviderSlack {
		t.Errorf("expected slack provider, got %q", result.Provider())
	}

	// Verify repo was called
	if repo.createCalls != 1 {
		t.Errorf("expected 1 repo create call, got %d", repo.createCalls)
	}
	if notifRepo.createCalls != 1 {
		t.Errorf("expected 1 notification extension create call, got %d", notifRepo.createCalls)
	}

	// Verify notification extension was created
	if result.Notification == nil {
		t.Fatal("expected notification extension, got nil")
	}

	// Verify severity configuration
	notifExt := result.Notification
	if !notifExt.IsSeverityEnabled(integration.SeverityCritical) {
		t.Error("expected critical severity to be enabled")
	}
	if !notifExt.IsSeverityEnabled(integration.SeverityHigh) {
		t.Error("expected high severity to be enabled")
	}
	if !notifExt.IsSeverityEnabled(integration.SeverityMedium) {
		t.Error("expected medium severity to be enabled")
	}
	if notifExt.IsSeverityEnabled(integration.SeverityLow) {
		t.Error("expected low severity to be disabled")
	}

	// Verify event type configuration
	if !notifExt.IsEventTypeEnabled(integration.EventTypeSecurityAlert) {
		t.Error("expected security_alert event type to be enabled")
	}
	if !notifExt.IsEventTypeEnabled(integration.EventTypeNewFinding) {
		t.Error("expected new_finding event type to be enabled")
	}
	if notifExt.IsEventTypeEnabled(integration.EventTypeScanCompleted) {
		t.Error("expected scan_completed event type to be disabled")
	}

	// Verify credentials were encrypted
	if enc.encryptCalls == 0 {
		t.Error("expected credentials to be encrypted")
	}
}

func TestCreateNotificationIntegration_DefaultSeverities(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID().String()
	input := app.CreateNotificationIntegrationInput{
		TenantID:    tenantID,
		Name:        "Slack Default",
		Provider:    "slack",
		AuthType:    "token",
		Credentials: "https://hooks.slack.com/xxx",
		// No EnabledSeverities or EnabledEventTypes specified
	}

	result, err := svc.CreateNotificationIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Notification == nil {
		t.Fatal("expected notification extension")
	}

	// Default severities should be critical and high
	notifExt := result.Notification
	if !notifExt.IsSeverityEnabled(integration.SeverityCritical) {
		t.Error("expected critical severity enabled by default")
	}
	if !notifExt.IsSeverityEnabled(integration.SeverityHigh) {
		t.Error("expected high severity enabled by default")
	}
	if notifExt.IsSeverityEnabled(integration.SeverityMedium) {
		t.Error("expected medium severity disabled by default")
	}
	if notifExt.IsSeverityEnabled(integration.SeverityLow) {
		t.Error("expected low severity disabled by default")
	}
}

func TestCreateNotificationIntegration_DuplicateName(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID().String()
	input := app.CreateNotificationIntegrationInput{
		TenantID:    tenantID,
		Name:        "Duplicate Slack",
		Provider:    "slack",
		AuthType:    "token",
		Credentials: "https://hooks.slack.com/xxx",
	}

	_, err := svc.CreateNotificationIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	_, err = svc.CreateNotificationIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Errorf("expected conflict error, got %v", err)
	}
}

func TestCreateNotificationIntegration_InvalidProvider(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID().String()
	input := app.CreateNotificationIntegrationInput{
		TenantID: tenantID,
		Name:     "Bad Provider",
		Provider: "github", // github is SCM, not notification
		AuthType: "token",
	}

	_, err := svc.CreateNotificationIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for non-notification provider")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateNotificationIntegration_ExtensionCreateFails_RollsBack(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	notifRepo.createErr = errors.New("extension table locked")
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID().String()
	input := app.CreateNotificationIntegrationInput{
		TenantID:    tenantID,
		Name:        "Failing Extension",
		Provider:    "slack",
		AuthType:    "token",
		Credentials: "https://hooks.slack.com/xxx",
	}

	_, err := svc.CreateNotificationIntegration(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when extension creation fails")
	}

	// Integration should be rolled back
	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 delete call for rollback, got %d", repo.deleteCalls)
	}
}

// =============================================================================
// Notification Extension Severity Filtering Tests
// =============================================================================

func TestNotificationExtension_SeverityFiltering(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())
	ext.SetEnabledSeverities([]integration.Severity{
		integration.SeverityCritical,
		integration.SeverityHigh,
	})

	tests := []struct {
		severity string
		expected bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", false},
		{"low", false},
		{"info", false},
		{"none", false},
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			if got := ext.ShouldNotify(tc.severity); got != tc.expected {
				t.Errorf("ShouldNotify(%q) = %v, want %v", tc.severity, got, tc.expected)
			}
		})
	}
}

func TestNotificationExtension_EmptySeverities_UsesDefaults(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())
	ext.SetEnabledSeverities(nil) // empty

	// Empty list means defaults (critical, high)
	if !ext.IsSeverityEnabled(integration.SeverityCritical) {
		t.Error("expected critical enabled for empty severities (default)")
	}
	if !ext.IsSeverityEnabled(integration.SeverityHigh) {
		t.Error("expected high enabled for empty severities (default)")
	}
	if ext.IsSeverityEnabled(integration.SeverityMedium) {
		t.Error("expected medium disabled for empty severities")
	}
}

// =============================================================================
// Notification Extension Event Type Filtering Tests
// =============================================================================

func TestNotificationExtension_EventTypeFiltering(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())
	ext.SetEnabledEventTypes([]integration.EventType{
		integration.EventTypeNewFinding,
		integration.EventTypeSecurityAlert,
	})

	tests := []struct {
		eventType integration.EventType
		expected  bool
	}{
		{integration.EventTypeNewFinding, true},
		{integration.EventTypeSecurityAlert, true},
		{integration.EventTypeScanCompleted, false},
		{integration.EventTypeNewAsset, false},
		{integration.EventTypeNewExposure, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.eventType), func(t *testing.T) {
			if got := ext.ShouldNotifyEventType(tc.eventType); got != tc.expected {
				t.Errorf("ShouldNotifyEventType(%q) = %v, want %v", tc.eventType, got, tc.expected)
			}
		})
	}
}

func TestNotificationExtension_EmptyEventTypes_AllEnabled(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())
	ext.SetEnabledEventTypes(nil) // empty

	// Empty list means all events are enabled (backward compatibility)
	if !ext.ShouldNotifyEventType(integration.EventTypeNewFinding) {
		t.Error("expected all event types enabled when empty")
	}
	if !ext.ShouldNotifyEventType(integration.EventTypeScanCompleted) {
		t.Error("expected all event types enabled when empty")
	}
	if !ext.ShouldNotifyEventType(integration.EventTypeNewAsset) {
		t.Error("expected all event types enabled when empty")
	}
}

func TestNotificationExtension_LegacyEventTypeMapping(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())
	ext.SetEnabledEventTypes([]integration.EventType{
		integration.EventTypeNewFinding,
	})

	// Legacy "findings" should map to "new_finding"
	if !ext.ShouldNotifyEventType(integration.EventTypeFindings) {
		t.Error("legacy 'findings' should map to 'new_finding'")
	}
}

// =============================================================================
// Notification Extension Backward Compatibility Tests
// =============================================================================

func TestNotificationExtension_BooleanSeverityGetters(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())
	ext.SetEnabledSeverities([]integration.Severity{
		integration.SeverityCritical,
		integration.SeverityMedium,
	})

	if !ext.NotifyOnCritical() {
		t.Error("expected NotifyOnCritical() = true")
	}
	if ext.NotifyOnHigh() {
		t.Error("expected NotifyOnHigh() = false")
	}
	if !ext.NotifyOnMedium() {
		t.Error("expected NotifyOnMedium() = true")
	}
	if ext.NotifyOnLow() {
		t.Error("expected NotifyOnLow() = false")
	}
}

func TestNotificationExtension_BooleanSeveritySetters(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())
	ext.SetEnabledSeverities([]integration.Severity{integration.SeverityCritical})

	// Add high via boolean setter
	ext.SetNotifyOnHigh(true)
	if !ext.IsSeverityEnabled(integration.SeverityHigh) {
		t.Error("expected high enabled after SetNotifyOnHigh(true)")
	}

	// Remove critical via boolean setter
	ext.SetNotifyOnCritical(false)
	if ext.IsSeverityEnabled(integration.SeverityCritical) {
		t.Error("expected critical disabled after SetNotifyOnCritical(false)")
	}

	// Idempotent add
	ext.SetNotifyOnHigh(true)
	count := 0
	for _, s := range ext.EnabledSeverities() {
		if s == integration.SeverityHigh {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 high severity entry, got %d", count)
	}
}

func TestReconstructNotificationExtensionFromBooleans(t *testing.T) {
	ext := integration.ReconstructNotificationExtensionFromBooleans(
		shared.NewID(),
		"", // channelID - deprecated
		"", // channelName - deprecated
		true,  // notifyOnCritical
		true,  // notifyOnHigh
		false, // notifyOnMedium
		true,  // notifyOnLow
		nil,   // enabledEventTypes
		"",    // messageTemplate
		true,  // includeDetails
		10,    // minIntervalMinutes
	)

	if !ext.IsSeverityEnabled(integration.SeverityCritical) {
		t.Error("expected critical enabled")
	}
	if !ext.IsSeverityEnabled(integration.SeverityHigh) {
		t.Error("expected high enabled")
	}
	if ext.IsSeverityEnabled(integration.SeverityMedium) {
		t.Error("expected medium disabled")
	}
	if !ext.IsSeverityEnabled(integration.SeverityLow) {
		t.Error("expected low enabled")
	}
}

// =============================================================================
// SCM Extension Tests
// =============================================================================

func TestSCMExtension_Defaults(t *testing.T) {
	ext := integration.NewSCMExtension(shared.NewID())

	if ext.DefaultBranchPattern() != "main,master" {
		t.Errorf("expected default branch pattern %q, got %q", "main,master", ext.DefaultBranchPattern())
	}
	if ext.AutoImportRepos() {
		t.Error("expected auto import repos to be false by default")
	}
	if !ext.ImportPrivateRepos() {
		t.Error("expected import private repos to be true by default")
	}
	if ext.ImportArchivedRepos() {
		t.Error("expected import archived repos to be false by default")
	}
	if len(ext.IncludePatterns()) != 0 {
		t.Errorf("expected empty include patterns, got %v", ext.IncludePatterns())
	}
	if len(ext.ExcludePatterns()) != 0 {
		t.Errorf("expected empty exclude patterns, got %v", ext.ExcludePatterns())
	}
}

func TestSCMExtension_Setters(t *testing.T) {
	ext := integration.NewSCMExtension(shared.NewID())

	ext.SetSCMOrganization("my-org")
	if ext.SCMOrganization() != "my-org" {
		t.Errorf("expected organization %q, got %q", "my-org", ext.SCMOrganization())
	}

	ext.SetRepositoryCount(42)
	if ext.RepositoryCount() != 42 {
		t.Errorf("expected repo count 42, got %d", ext.RepositoryCount())
	}

	ext.SetDefaultBranchPattern("develop")
	if ext.DefaultBranchPattern() != "develop" {
		t.Errorf("expected branch pattern %q, got %q", "develop", ext.DefaultBranchPattern())
	}

	ext.SetAutoImportRepos(true)
	if !ext.AutoImportRepos() {
		t.Error("expected auto import repos to be true")
	}

	ext.SetIncludePatterns([]string{"src/*", "lib/*"})
	if len(ext.IncludePatterns()) != 2 {
		t.Errorf("expected 2 include patterns, got %d", len(ext.IncludePatterns()))
	}

	ext.SetExcludePatterns([]string{"vendor/*"})
	if len(ext.ExcludePatterns()) != 1 {
		t.Errorf("expected 1 exclude pattern, got %d", len(ext.ExcludePatterns()))
	}
}

func TestSCMExtension_Reconstruct(t *testing.T) {
	now := time.Now()
	id := shared.NewID()
	ext := integration.ReconstructSCMExtension(
		id,
		"my-org",
		100,
		"wh-123",
		"secret",
		"https://example.com/hook",
		"main",
		true,
		false,
		true,
		[]string{"src/*"},
		[]string{"test/*"},
		&now,
	)

	if ext.IntegrationID() != id {
		t.Errorf("expected integration ID %s, got %s", id, ext.IntegrationID())
	}
	if ext.SCMOrganization() != "my-org" {
		t.Errorf("expected organization %q, got %q", "my-org", ext.SCMOrganization())
	}
	if ext.RepositoryCount() != 100 {
		t.Errorf("expected repo count 100, got %d", ext.RepositoryCount())
	}
	if ext.WebhookID() != "wh-123" {
		t.Errorf("expected webhook ID %q, got %q", "wh-123", ext.WebhookID())
	}
	if ext.WebhookSecret() != "secret" {
		t.Errorf("expected webhook secret %q, got %q", "secret", ext.WebhookSecret())
	}
	if ext.AutoImportRepos() != true {
		t.Error("expected auto import repos to be true")
	}
	if ext.ImportPrivateRepos() != false {
		t.Error("expected import private repos to be false")
	}
	if ext.ImportArchivedRepos() != true {
		t.Error("expected import archived repos to be true")
	}
}

// =============================================================================
// Disable/Enable Integration Tests
// =============================================================================

func TestDisableIntegration_Success(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	disabled, err := svc.DisableIntegration(context.Background(), created.ID().String(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if disabled.Status() != integration.StatusDisabled {
		t.Errorf("expected status disabled, got %q", disabled.Status())
	}
}

func TestDisableIntegration_WrongTenant(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	svc := newTestIntegrationService(repo, scmRepo, nil)

	tenantID := shared.NewID().String()
	input := validCreateInput(tenantID)
	created, err := svc.CreateIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	otherTenant := shared.NewID().String()
	_, err = svc.DisableIntegration(context.Background(), created.ID().String(), otherTenant)
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

// =============================================================================
// GetNotificationIntegration Tests
// =============================================================================

func TestGetNotificationIntegration_Success(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID()
	id := shared.NewID()

	intg := integration.NewIntegration(id, tenantID, "My Slack", integration.CategoryNotification, integration.ProviderSlack, integration.AuthTypeToken)
	repo.integrations[id] = intg

	notifExt := integration.NewNotificationExtension(id)
	notifExt.SetEnabledSeverities([]integration.Severity{integration.SeverityCritical})
	notifRepo.extensions[id] = notifExt

	result, err := svc.GetNotificationIntegration(context.Background(), id.String(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Name() != "My Slack" {
		t.Errorf("expected name %q, got %q", "My Slack", result.Name())
	}
	if result.Notification == nil {
		t.Fatal("expected notification extension")
	}
	if !result.Notification.IsSeverityEnabled(integration.SeverityCritical) {
		t.Error("expected critical severity enabled")
	}
}

func TestGetNotificationIntegration_NotANotification(t *testing.T) {
	repo := newMockIntegrationRepo()
	scmRepo := newMockSCMExtRepo()
	notifRepo := newMockNotificationExtRepo()
	svc := newTestIntegrationServiceWithNotification(repo, scmRepo, notifRepo, nil)

	tenantID := shared.NewID()
	id := shared.NewID()

	// Create a security integration
	intg := integration.NewIntegration(id, tenantID, "Snyk", integration.CategorySecurity, integration.ProviderSnyk, integration.AuthTypeAPIKey)
	repo.integrations[id] = intg

	_, err := svc.GetNotificationIntegration(context.Background(), id.String(), tenantID.String())
	if err == nil {
		t.Fatal("expected error for non-notification integration")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// =============================================================================
// Event Type Validation Tests
// =============================================================================

func TestValidateEventTypes_AllValid(t *testing.T) {
	enabledModules := []string{"assets", "scans", "findings"}
	eventTypes := []integration.EventType{
		integration.EventTypeNewFinding,
		integration.EventTypeScanCompleted,
		integration.EventTypeNewAsset,
	}

	valid, invalidTypes := integration.ValidateEventTypes(eventTypes, enabledModules)
	if !valid {
		t.Errorf("expected all valid, got invalid types: %v", invalidTypes)
	}
}

func TestValidateEventTypes_ModuleNotEnabled(t *testing.T) {
	enabledModules := []string{"assets"} // only assets, no findings

	eventTypes := []integration.EventType{
		integration.EventTypeNewFinding, // requires findings module
	}

	valid, invalidTypes := integration.ValidateEventTypes(eventTypes, enabledModules)
	if valid {
		t.Error("expected invalid when findings module is not enabled")
	}
	if len(invalidTypes) != 1 {
		t.Errorf("expected 1 invalid type, got %d", len(invalidTypes))
	}
}

func TestValidateEventTypes_SystemEventsAlwaysValid(t *testing.T) {
	// No modules enabled at all
	enabledModules := []string{}

	eventTypes := []integration.EventType{
		integration.EventTypeSecurityAlert, // system event, always valid
		integration.EventTypeSystemError,   // system event, always valid
	}

	valid, invalidTypes := integration.ValidateEventTypes(eventTypes, enabledModules)
	if !valid {
		t.Errorf("system events should always be valid, got invalid: %v", invalidTypes)
	}
}

// =============================================================================
// Integration Entity Tests
// =============================================================================

func TestIntegration_NewIntegration(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	intg := integration.NewIntegration(id, tenantID, "Test", integration.CategorySCM, integration.ProviderGitHub, integration.AuthTypeToken)

	if intg.ID() != id {
		t.Errorf("expected ID %s, got %s", id, intg.ID())
	}
	if intg.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, intg.TenantID())
	}
	if intg.Status() != integration.StatusPending {
		t.Errorf("expected pending status, got %q", intg.Status())
	}
	if intg.SyncIntervalMinutes() != 60 {
		t.Errorf("expected default sync interval 60, got %d", intg.SyncIntervalMinutes())
	}
	if !intg.IsSCM() {
		t.Error("expected IsSCM() = true for SCM integration")
	}
}

func TestIntegration_StatusTransitions(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	intg := integration.NewIntegration(id, tenantID, "Test", integration.CategorySCM, integration.ProviderGitHub, integration.AuthTypeToken)

	// Pending -> Connected
	intg.SetConnected()
	if intg.Status() != integration.StatusConnected {
		t.Errorf("expected connected, got %q", intg.Status())
	}
	if !intg.IsConnected() {
		t.Error("expected IsConnected() = true")
	}
	if intg.LastSyncAt() == nil {
		t.Error("expected LastSyncAt to be set after SetConnected")
	}

	// Connected -> Error
	intg.SetError("connection refused")
	if intg.Status() != integration.StatusError {
		t.Errorf("expected error status, got %q", intg.Status())
	}
	if intg.SyncError() != "connection refused" {
		t.Errorf("expected sync error %q, got %q", "connection refused", intg.SyncError())
	}

	// Error -> Disconnected
	intg.SetDisconnected()
	if intg.Status() != integration.StatusDisconnected {
		t.Errorf("expected disconnected, got %q", intg.Status())
	}
}

func TestIntegration_ProviderCategoryValidation(t *testing.T) {
	tests := []struct {
		provider integration.Provider
		expected integration.Category
	}{
		{integration.ProviderGitHub, integration.CategorySCM},
		{integration.ProviderGitLab, integration.CategorySCM},
		{integration.ProviderSnyk, integration.CategorySecurity},
		{integration.ProviderWiz, integration.CategorySecurity},
		{integration.ProviderAWS, integration.CategoryCloud},
		{integration.ProviderJira, integration.CategoryTicketing},
		{integration.ProviderSlack, integration.CategoryNotification},
		{integration.ProviderTeams, integration.CategoryNotification},
		{integration.ProviderTelegram, integration.CategoryNotification},
		{integration.ProviderEmail, integration.CategoryNotification},
		{integration.ProviderWebhook, integration.CategoryNotification},
	}

	for _, tc := range tests {
		t.Run(string(tc.provider), func(t *testing.T) {
			if tc.provider.Category() != tc.expected {
				t.Errorf("provider %q: expected category %q, got %q", tc.provider, tc.expected, tc.provider.Category())
			}
		})
	}
}

func TestIntegration_InvalidProviderAndCategory(t *testing.T) {
	invalidProvider := integration.Provider("nonexistent")
	if invalidProvider.IsValid() {
		t.Error("expected invalid provider to return false")
	}

	invalidCategory := integration.Category("nonexistent")
	if invalidCategory.IsValid() {
		t.Error("expected invalid category to return false")
	}

	invalidAuthType := integration.AuthType("nonexistent")
	if invalidAuthType.IsValid() {
		t.Error("expected invalid auth type to return false")
	}

	invalidStatus := integration.Status("nonexistent")
	if invalidStatus.IsValid() {
		t.Error("expected invalid status to return false")
	}
}

// =============================================================================
// Notification Extension MinInterval Tests
// =============================================================================

func TestNotificationExtension_MinIntervalDefaults(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())
	if ext.MinIntervalMinutes() != 5 {
		t.Errorf("expected default min interval 5, got %d", ext.MinIntervalMinutes())
	}

	// Setting to 0 should default to 5
	ext.SetMinIntervalMinutes(0)
	if ext.MinIntervalMinutes() != 5 {
		t.Errorf("expected min interval 5 after setting 0, got %d", ext.MinIntervalMinutes())
	}

	// Setting to negative should default to 5
	ext.SetMinIntervalMinutes(-1)
	if ext.MinIntervalMinutes() != 5 {
		t.Errorf("expected min interval 5 after setting -1, got %d", ext.MinIntervalMinutes())
	}

	// Setting to valid value
	ext.SetMinIntervalMinutes(15)
	if ext.MinIntervalMinutes() != 15 {
		t.Errorf("expected min interval 15, got %d", ext.MinIntervalMinutes())
	}
}

// =============================================================================
// Reconstruct Tests (Notification Extension)
// =============================================================================

func TestReconstructNotificationExtension_EmptySeverities_UsesDefaults(t *testing.T) {
	ext := integration.ReconstructNotificationExtension(
		shared.NewID(),
		"", // channelID - deprecated
		"", // channelName - deprecated
		nil,   // empty severities -> defaults
		nil,   // empty event types -> defaults
		"",    // messageTemplate
		true,  // includeDetails
		0,     // minIntervalMinutes (0 -> default 5)
	)

	if !ext.IsSeverityEnabled(integration.SeverityCritical) {
		t.Error("expected default critical enabled")
	}
	if !ext.IsSeverityEnabled(integration.SeverityHigh) {
		t.Error("expected default high enabled")
	}
	if ext.MinIntervalMinutes() != 5 {
		t.Errorf("expected default min interval 5, got %d", ext.MinIntervalMinutes())
	}
}

func TestReconstructNotificationExtension_CustomSeverities(t *testing.T) {
	ext := integration.ReconstructNotificationExtension(
		shared.NewID(),
		"", "",
		[]integration.Severity{integration.SeverityLow, integration.SeverityInfo},
		[]integration.EventType{integration.EventTypeScanCompleted},
		"custom template",
		false,
		30,
	)

	if ext.IsSeverityEnabled(integration.SeverityCritical) {
		t.Error("expected critical disabled")
	}
	if !ext.IsSeverityEnabled(integration.SeverityLow) {
		t.Error("expected low enabled")
	}
	if !ext.IsSeverityEnabled(integration.SeverityInfo) {
		t.Error("expected info enabled")
	}
	if ext.MessageTemplate() != "custom template" {
		t.Errorf("expected message template %q, got %q", "custom template", ext.MessageTemplate())
	}
	if ext.IncludeDetails() {
		t.Error("expected include details false")
	}
	if ext.MinIntervalMinutes() != 30 {
		t.Errorf("expected min interval 30, got %d", ext.MinIntervalMinutes())
	}
}
