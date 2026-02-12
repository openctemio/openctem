package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/api/internal/infra/notification"
	"github.com/openctemio/api/internal/infra/scm"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/integration"
	notificationdomain "github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// testNotificationRateLimit defines the minimum interval between test notifications per integration.
const testNotificationRateLimit = 30 * time.Second

// IntegrationService provides integration operations.
type IntegrationService struct {
	repo                  integration.Repository
	scmExtRepo            integration.SCMExtensionRepository
	notificationExtRepo   integration.NotificationExtensionRepository
	notificationEventRepo notificationdomain.EventRepository
	scmFactory            *scm.ClientFactory
	notificationFactory   *notification.ClientFactory
	encryptor             crypto.Encryptor
	logger                *logger.Logger

	// Rate limiting for test notifications
	testRateLimitMu  sync.RWMutex
	testRateLimitMap map[string]time.Time // integration ID -> last test time
}

// NewIntegrationService creates a new IntegrationService.
// The encryptor is used to encrypt/decrypt integration credentials.
// If encryptor is nil, a no-op encryptor is used (credentials stored in plaintext).
func NewIntegrationService(
	repo integration.Repository,
	scmExtRepo integration.SCMExtensionRepository,
	encryptor crypto.Encryptor,
	log *logger.Logger,
) *IntegrationService {
	if encryptor == nil {
		encryptor = crypto.NewNoOpEncryptor()
	}
	return &IntegrationService{
		repo:                repo,
		scmExtRepo:          scmExtRepo,
		scmFactory:          scm.NewClientFactory(),
		notificationFactory: notification.NewClientFactory(),
		encryptor:           encryptor,
		logger:              log.With("service", "integration"),
		testRateLimitMap:    make(map[string]time.Time),
	}
}

// SetNotificationExtensionRepository sets the notification extension repository.
func (s *IntegrationService) SetNotificationExtensionRepository(repo integration.NotificationExtensionRepository) {
	s.notificationExtRepo = repo
}

// SetNotificationEventRepository sets the notification event repository.
func (s *IntegrationService) SetNotificationEventRepository(repo notificationdomain.EventRepository) {
	s.notificationEventRepo = repo
}

// checkTestRateLimit checks if enough time has passed since the last test notification.
// Returns an error if the rate limit is exceeded.
func (s *IntegrationService) checkTestRateLimit(integrationID string) error {
	s.testRateLimitMu.RLock()
	lastTest, exists := s.testRateLimitMap[integrationID]
	s.testRateLimitMu.RUnlock()

	if exists && time.Since(lastTest) < testNotificationRateLimit {
		remaining := testNotificationRateLimit - time.Since(lastTest)
		return fmt.Errorf("%w: rate limit exceeded, please wait %d seconds before testing again",
			shared.ErrValidation, int(remaining.Seconds()))
	}

	// Update the last test time
	s.testRateLimitMu.Lock()
	s.testRateLimitMap[integrationID] = time.Now()
	s.testRateLimitMu.Unlock()

	return nil
}

// CreateIntegrationInput represents the input for creating an integration.
type CreateIntegrationInput struct {
	TenantID    string
	Name        string
	Description string
	Category    string
	Provider    string
	AuthType    string
	BaseURL     string
	Credentials string // Access token, API key, etc.

	// SCM-specific fields
	SCMOrganization string
}

// CreateIntegration creates a new integration.
func (s *IntegrationService) CreateIntegration(ctx context.Context, input CreateIntegrationInput) (*integration.IntegrationWithSCM, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Validate category
	category := integration.Category(input.Category)
	if !category.IsValid() {
		return nil, integration.ErrInvalidCategory
	}

	// Validate provider
	provider := integration.Provider(input.Provider)
	if !provider.IsValid() {
		return nil, integration.ErrInvalidProvider
	}

	// Validate provider matches category
	if provider.Category() != category {
		return nil, integration.ErrProviderCategoryMismatch
	}

	// Validate auth type
	authType := integration.AuthType(input.AuthType)
	if !authType.IsValid() {
		return nil, integration.ErrInvalidAuthType
	}

	// Check for duplicate integration name within tenant
	existing, err := s.repo.GetByTenantAndName(ctx, tenantID, input.Name)
	if err != nil && !errors.Is(err, integration.ErrIntegrationNotFound) {
		return nil, fmt.Errorf("check duplicate integration: %w", err)
	}
	if existing != nil {
		return nil, integration.ErrIntegrationNameExists
	}

	// Create new integration
	id := shared.NewID()
	intg := integration.NewIntegration(
		id,
		tenantID,
		input.Name,
		category,
		provider,
		authType,
	)

	if input.Description != "" {
		intg.SetDescription(input.Description)
	}
	if input.BaseURL != "" {
		intg.SetBaseURL(input.BaseURL)
	}
	if input.Credentials != "" {
		encrypted, err := s.encryptor.EncryptString(input.Credentials)
		if err != nil {
			return nil, fmt.Errorf("encrypt credentials: %w", err)
		}
		intg.SetCredentials(encrypted)
	}

	// Save integration to repository
	if err := s.repo.Create(ctx, intg); err != nil {
		return nil, fmt.Errorf("create integration: %w", err)
	}

	// Create SCM extension if this is an SCM integration
	var scmExt *integration.SCMExtension
	if category == integration.CategorySCM {
		scmExt = integration.NewSCMExtension(id)
		if input.SCMOrganization != "" {
			scmExt.SetSCMOrganization(input.SCMOrganization)
		}
		if err := s.scmExtRepo.Create(ctx, scmExt); err != nil {
			// Rollback integration creation
			_ = s.repo.Delete(ctx, id)
			return nil, fmt.Errorf("create scm extension: %w", err)
		}
	}

	s.logger.Info("integration created",
		"id", intg.ID().String(),
		"tenant_id", intg.TenantID().String(),
		"category", intg.Category().String(),
		"provider", intg.Provider().String(),
	)

	result := integration.NewIntegrationWithSCM(intg, scmExt)

	// Auto-test the connection after creation for SCM integrations
	if category == integration.CategorySCM {
		testedResult, testErr := s.TestIntegration(ctx, intg.ID().String(), input.TenantID)
		if testErr != nil {
			s.logger.Warn("auto-test after creation failed", "error", testErr)
			return result, nil
		}
		return testedResult, nil
	}

	return result, nil
}

// GetIntegration retrieves an integration by ID.
func (s *IntegrationService) GetIntegration(ctx context.Context, id string) (*integration.Integration, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, intgID)
}

// GetIntegrationWithSCM retrieves an SCM integration with its extension.
func (s *IntegrationService) GetIntegrationWithSCM(ctx context.Context, id string) (*integration.IntegrationWithSCM, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	return s.scmExtRepo.GetIntegrationWithSCM(ctx, intgID)
}

// UpdateIntegrationInput represents the input for updating an integration.
type UpdateIntegrationInput struct {
	Name        *string
	Description *string
	Credentials *string
	BaseURL     *string

	// SCM-specific fields
	SCMOrganization *string
}

// UpdateIntegration updates an existing integration.
func (s *IntegrationService) UpdateIntegration(ctx context.Context, id string, tenantID string, input UpdateIntegrationInput) (*integration.IntegrationWithSCM, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if intg.TenantID().String() != tenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Apply updates to integration
	if input.Name != nil {
		intg.SetName(*input.Name)
	}
	if input.Description != nil {
		intg.SetDescription(*input.Description)
	}
	if input.Credentials != nil {
		encrypted, err := s.encryptor.EncryptString(*input.Credentials)
		if err != nil {
			return nil, fmt.Errorf("encrypt credentials: %w", err)
		}
		intg.SetCredentials(encrypted)
	}
	if input.BaseURL != nil {
		intg.SetBaseURL(*input.BaseURL)
	}

	// Save integration
	if err := s.repo.Update(ctx, intg); err != nil {
		return nil, fmt.Errorf("update integration: %w", err)
	}

	// Update SCM extension if this is an SCM integration
	var scmExt *integration.SCMExtension
	if intg.IsSCM() && input.SCMOrganization != nil {
		scmExt, err = s.scmExtRepo.GetByIntegrationID(ctx, intgID)
		if err != nil && !errors.Is(err, integration.ErrSCMExtensionNotFound) {
			return nil, fmt.Errorf("get scm extension: %w", err)
		}
		if scmExt != nil {
			scmExt.SetSCMOrganization(*input.SCMOrganization)
			if err := s.scmExtRepo.Update(ctx, scmExt); err != nil {
				return nil, fmt.Errorf("update scm extension: %w", err)
			}
		}
	}

	s.logger.Info("integration updated", "id", intg.ID().String())

	return integration.NewIntegrationWithSCM(intg, scmExt), nil
}

// DeleteIntegration deletes an integration.
func (s *IntegrationService) DeleteIntegration(ctx context.Context, id string, tenantID string) error {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	// Verify ownership
	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return err
	}

	if intg.TenantID().String() != tenantID {
		return integration.ErrIntegrationNotFound
	}

	// Delete integration (extension tables cascade delete)
	if err := s.repo.Delete(ctx, intgID); err != nil {
		return fmt.Errorf("delete integration: %w", err)
	}

	s.logger.Info("integration deleted", "id", id)

	return nil
}

// ListIntegrationsInput represents the input for listing integrations.
type ListIntegrationsInput struct {
	TenantID  string
	Category  string
	Provider  string
	Status    string
	Search    string
	Page      int
	PerPage   int
	SortBy    string
	SortOrder string
}

// ListIntegrations lists integrations with filtering and pagination.
func (s *IntegrationService) ListIntegrations(ctx context.Context, input ListIntegrationsInput) (integration.ListResult, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return integration.ListResult{}, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	filter := integration.NewFilter()
	filter.TenantID = &tenantID
	filter.Search = input.Search
	filter.Page = input.Page
	filter.PerPage = input.PerPage
	filter.SortBy = input.SortBy
	filter.SortOrder = input.SortOrder

	if input.Category != "" {
		cat := integration.Category(input.Category)
		filter.Category = &cat
	}
	if input.Provider != "" {
		prov := integration.Provider(input.Provider)
		filter.Provider = &prov
	}
	if input.Status != "" {
		stat := integration.Status(input.Status)
		filter.Status = &stat
	}

	return s.repo.List(ctx, filter)
}

// ListSCMIntegrations lists all SCM integrations with their extensions.
func (s *IntegrationService) ListSCMIntegrations(ctx context.Context, tenantID string) ([]*integration.IntegrationWithSCM, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	return s.scmExtRepo.ListIntegrationsWithSCM(ctx, tid)
}

// TestIntegration tests the connection for an integration.
func (s *IntegrationService) TestIntegration(ctx context.Context, id string, tenantID string) (*integration.IntegrationWithSCM, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if intg.TenantID().String() != tenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Only SCM integrations support testing for now
	if !intg.IsSCM() {
		return nil, fmt.Errorf("%w: only SCM integrations support connection testing", shared.ErrValidation)
	}

	// Get SCM extension
	scmExt, _ := s.scmExtRepo.GetByIntegrationID(ctx, intgID)

	// Determine base URL
	baseURL := intg.BaseURL()
	if baseURL == "" {
		baseURL = s.getDefaultBaseURL(intg.Provider())
	}

	// Get SCM organization
	scmOrg := ""
	if scmExt != nil {
		scmOrg = scmExt.SCMOrganization()
	}

	// Decrypt credentials (falls back to plaintext for backward compatibility)
	credentials := s.decryptCredentials(intg)

	// Create SCM client and test connection
	client, err := s.scmFactory.CreateClient(scm.Config{
		Provider:     scm.Provider(intg.Provider()),
		BaseURL:      baseURL,
		AccessToken:  credentials,
		Organization: scmOrg,
		AuthType:     scm.AuthType(intg.AuthType()),
	})
	if err != nil {
		intg.SetError(fmt.Sprintf("Failed to create client: %v", err))
		if updateErr := s.repo.Update(ctx, intg); updateErr != nil {
			s.logger.Error("Failed to update integration after client error", "error", updateErr)
		}
		return integration.NewIntegrationWithSCM(intg, scmExt), nil
	}

	// Test the connection
	result, err := client.TestConnection(ctx)
	if err != nil {
		intg.SetError(fmt.Sprintf("Connection test failed: %v", err))
		if updateErr := s.repo.Update(ctx, intg); updateErr != nil {
			s.logger.Error("Failed to update integration after test error", "error", updateErr)
		}
		return integration.NewIntegrationWithSCM(intg, scmExt), nil
	}

	// Update integration based on result
	if result.Success {
		intg.SetConnected()

		// Update SCM extension with repo count
		if scmExt != nil && result.RepoCount > 0 {
			scmExt.SetRepositoryCount(result.RepoCount)
			scmExt.UpdateLastRepoSync()
			if updateErr := s.scmExtRepo.Update(ctx, scmExt); updateErr != nil {
				s.logger.Warn("Failed to update SCM extension", "error", updateErr)
			}
		}

		// Update stats
		stats := intg.Stats()
		stats.TotalRepositories = result.RepoCount
		intg.SetStats(stats)
	} else {
		intg.SetError(result.Message)
	}

	if err := s.repo.Update(ctx, intg); err != nil {
		return nil, fmt.Errorf("update integration: %w", err)
	}

	return integration.NewIntegrationWithSCM(intg, scmExt), nil
}

// TestCredentialsInput represents the input for testing credentials without creating.
type TestIntegrationCredentialsInput struct {
	Category        string
	Provider        string
	BaseURL         string
	AuthType        string
	Credentials     string
	SCMOrganization string
}

// TestIntegrationCredentialsResult represents the result of testing credentials.
type TestIntegrationCredentialsResult struct {
	Success      bool
	Message      string
	RepoCount    int
	Organization string
	Username     string
}

// TestIntegrationCredentials tests credentials without persisting an integration.
func (s *IntegrationService) TestIntegrationCredentials(ctx context.Context, input TestIntegrationCredentialsInput) (*TestIntegrationCredentialsResult, error) {
	// Validate category
	category := integration.Category(input.Category)
	if !category.IsValid() {
		return nil, integration.ErrInvalidCategory
	}

	// Only SCM integrations support testing for now
	if category != integration.CategorySCM {
		return nil, fmt.Errorf("%w: only SCM integrations support credential testing", shared.ErrValidation)
	}

	// Validate provider
	provider := integration.Provider(input.Provider)
	if !provider.IsValid() {
		return nil, integration.ErrInvalidProvider
	}

	// Determine base URL
	baseURL := input.BaseURL
	if baseURL == "" {
		baseURL = s.getDefaultBaseURL(provider)
	}

	// Create SCM client
	client, err := s.scmFactory.CreateClient(scm.Config{
		Provider:     scm.Provider(provider),
		BaseURL:      baseURL,
		AccessToken:  input.Credentials,
		Organization: input.SCMOrganization,
		AuthType:     scm.AuthType(input.AuthType),
	})
	if err != nil {
		return &TestIntegrationCredentialsResult{
			Success: false,
			Message: fmt.Sprintf("Failed to create SCM client: %v", err),
		}, nil
	}

	// Test the connection
	result, err := client.TestConnection(ctx)
	if err != nil {
		return &TestIntegrationCredentialsResult{
			Success: false,
			Message: fmt.Sprintf("Connection test failed: %v", err),
		}, nil
	}

	// Extract organization name and username from result
	orgName := ""
	if result.Organization != nil {
		orgName = result.Organization.Name
	}
	username := ""
	if result.User != nil {
		username = result.User.Username
	}

	return &TestIntegrationCredentialsResult{
		Success:      result.Success,
		Message:      result.Message,
		RepoCount:    result.RepoCount,
		Organization: orgName,
		Username:     username,
	}, nil
}

// IntegrationListReposInput represents the input for listing repositories from an SCM integration.
type IntegrationListReposInput struct {
	IntegrationID string
	TenantID      string
	Search        string
	Page          int
	PerPage       int
}

// IntegrationListReposResult represents the result of listing repositories.
type IntegrationListReposResult struct {
	Repositories []scm.Repository
	Total        int
	HasMore      bool
	NextPage     int
}

// ListSCMRepositories lists repositories from an SCM integration.
func (s *IntegrationService) ListSCMRepositories(ctx context.Context, input IntegrationListReposInput) (*IntegrationListReposResult, error) {
	intgID, err := shared.IDFromString(input.IntegrationID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid integration ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if intg.TenantID().String() != input.TenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Verify this is an SCM integration
	if !intg.IsSCM() {
		return nil, fmt.Errorf("%w: not an SCM integration", shared.ErrValidation)
	}

	// Get SCM extension for organization
	scmExt, _ := s.scmExtRepo.GetByIntegrationID(ctx, intgID)
	scmOrg := ""
	if scmExt != nil {
		scmOrg = scmExt.SCMOrganization()
	}

	// Determine base URL
	baseURL := intg.BaseURL()
	if baseURL == "" {
		baseURL = s.getDefaultBaseURL(intg.Provider())
	}

	// Decrypt credentials (falls back to plaintext for backward compatibility)
	credentials := s.decryptCredentials(intg)

	// Create SCM client
	client, err := s.scmFactory.CreateClient(scm.Config{
		Provider:     scm.Provider(intg.Provider()),
		BaseURL:      baseURL,
		AccessToken:  credentials,
		Organization: scmOrg,
		AuthType:     scm.AuthType(intg.AuthType()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SCM client: %w", err)
	}

	// Set defaults
	perPage := input.PerPage
	if perPage <= 0 || perPage > 100 {
		perPage = 30
	}
	page := input.Page
	if page <= 0 {
		page = 1
	}

	// List repositories
	result, err := client.ListRepositories(ctx, scm.ListOptions{
		Page:    page,
		PerPage: perPage,
		Search:  input.Search,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	// Update repository count if this is the first page and no search filter
	if page == 1 && input.Search == "" && result.Total > 0 && scmExt != nil {
		if scmExt.RepositoryCount() != result.Total {
			scmExt.SetRepositoryCount(result.Total)
			scmExt.UpdateLastRepoSync()
			if updateErr := s.scmExtRepo.Update(ctx, scmExt); updateErr != nil {
				s.logger.Warn("Failed to update repository count", "error", updateErr)
			}

			// Also update integration stats
			stats := intg.Stats()
			stats.TotalRepositories = result.Total
			intg.SetStats(stats)
			intg.UpdateLastSync()
			if updateErr := s.repo.Update(ctx, intg); updateErr != nil {
				s.logger.Warn("Failed to update integration stats", "error", updateErr)
			}
		}
	}

	return &IntegrationListReposResult{
		Repositories: result.Repositories,
		Total:        result.Total,
		HasMore:      result.HasMore,
		NextPage:     result.NextPage,
	}, nil
}

// decryptCredentials decrypts the stored credentials from an integration.
// If decryption fails (e.g., credentials stored in plaintext), returns the original value.
// This provides backward compatibility with existing unencrypted credentials.
func (s *IntegrationService) decryptCredentials(intg *integration.Integration) string {
	encrypted := intg.CredentialsEncrypted()
	if encrypted == "" {
		return ""
	}
	decrypted, err := s.encryptor.DecryptString(encrypted)
	if err != nil {
		// Decryption failed - assume plaintext (backward compatibility)
		s.logger.Debug("credentials not encrypted, using plaintext",
			"integration_id", intg.ID().String(),
		)
		return encrypted
	}
	return decrypted
}

// EmailCredentials represents the JSON structure for email SMTP credentials (full input from frontend).
type EmailCredentials struct {
	SMTPHost    string   `json:"smtp_host"`
	SMTPPort    int      `json:"smtp_port"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	FromEmail   string   `json:"from_email"`
	FromName    string   `json:"from_name"`
	ToEmails    []string `json:"to_emails"`
	UseTLS      bool     `json:"use_tls"`
	UseSTARTTLS bool     `json:"use_starttls"`
	SkipVerify  bool     `json:"skip_verify"`
	ReplyTo     string   `json:"reply_to,omitempty"`
}

// EmailMetadata represents non-sensitive email config stored in integration.metadata.
// This allows the frontend to display current config when editing without exposing secrets.
type EmailMetadata struct {
	SMTPHost    string   `json:"smtp_host"`
	SMTPPort    int      `json:"smtp_port"`
	FromEmail   string   `json:"from_email"`
	FromName    string   `json:"from_name"`
	ToEmails    []string `json:"to_emails"`
	UseTLS      bool     `json:"use_tls"`
	UseSTARTTLS bool     `json:"use_starttls"`
	SkipVerify  bool     `json:"skip_verify"`
	ReplyTo     string   `json:"reply_to,omitempty"`
}

// EmailSensitiveCredentials represents sensitive email credentials stored encrypted.
type EmailSensitiveCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// splitEmailCredentials splits full email credentials into metadata (non-sensitive) and sensitive parts.
func splitEmailCredentials(creds *EmailCredentials) (*EmailMetadata, *EmailSensitiveCredentials) {
	metadata := &EmailMetadata{
		SMTPHost:    creds.SMTPHost,
		SMTPPort:    creds.SMTPPort,
		FromEmail:   creds.FromEmail,
		FromName:    creds.FromName,
		ToEmails:    creds.ToEmails,
		UseTLS:      creds.UseTLS,
		UseSTARTTLS: creds.UseSTARTTLS,
		SkipVerify:  creds.SkipVerify,
		ReplyTo:     creds.ReplyTo,
	}
	sensitive := &EmailSensitiveCredentials{
		Username: creds.Username,
		Password: creds.Password,
	}
	return metadata, sensitive
}

// mergeEmailConfig merges email metadata and sensitive credentials into a full EmailConfig.
func mergeEmailConfig(metadata *EmailMetadata, sensitive *EmailSensitiveCredentials) *notification.EmailConfig {
	config := &notification.EmailConfig{
		SMTPHost:    metadata.SMTPHost,
		SMTPPort:    metadata.SMTPPort,
		FromEmail:   metadata.FromEmail,
		FromName:    metadata.FromName,
		ToEmails:    metadata.ToEmails,
		UseTLS:      metadata.UseTLS,
		UseSTARTTLS: metadata.UseSTARTTLS,
		SkipVerify:  metadata.SkipVerify,
		ReplyTo:     metadata.ReplyTo,
	}
	if sensitive != nil {
		config.Username = sensitive.Username
		config.Password = sensitive.Password
	}
	return config
}

// parseEmailCredentials parses JSON email credentials and returns an EmailConfig.
func (s *IntegrationService) parseEmailCredentials(credentials string) (*notification.EmailConfig, error) {
	var emailCreds EmailCredentials
	if err := json.Unmarshal([]byte(credentials), &emailCreds); err != nil {
		return nil, fmt.Errorf("parse email credentials: %w", err)
	}

	// Validate required fields
	if emailCreds.SMTPHost == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if emailCreds.SMTPPort == 0 {
		return nil, fmt.Errorf("SMTP port is required")
	}
	if emailCreds.FromEmail == "" {
		return nil, fmt.Errorf("sender email is required")
	}
	if len(emailCreds.ToEmails) == 0 {
		return nil, fmt.Errorf("at least one recipient email is required")
	}

	return &notification.EmailConfig{
		SMTPHost:    emailCreds.SMTPHost,
		SMTPPort:    emailCreds.SMTPPort,
		Username:    emailCreds.Username,
		Password:    emailCreds.Password,
		FromEmail:   emailCreds.FromEmail,
		FromName:    emailCreds.FromName,
		ToEmails:    emailCreds.ToEmails,
		UseTLS:      emailCreds.UseTLS,
		UseSTARTTLS: emailCreds.UseSTARTTLS,
		SkipVerify:  emailCreds.SkipVerify,
		ReplyTo:     emailCreds.ReplyTo,
	}, nil
}

// buildNotificationConfig builds a notification client config based on the provider and credentials.
func (s *IntegrationService) buildNotificationConfig(intg *integration.Integration, notifExt *integration.NotificationExtension) (notification.Config, error) {
	// Populate metadata from credentials for backward compatibility (existing integrations)
	s.populateMetadataFromCredentials(intg)

	credentials := s.decryptCredentials(intg)
	provider := intg.Provider()

	config := notification.Config{
		Provider: notification.Provider(provider.String()),
	}

	switch provider {
	case integration.ProviderSlack, integration.ProviderTeams, integration.ProviderWebhook:
		config.WebhookURL = credentials
	case integration.ProviderTelegram:
		config.BotToken = credentials
		// Read chat_id from metadata (new format) or notification extension (legacy)
		metadata := intg.Metadata()
		if chatID, ok := metadata["chat_id"].(string); ok && chatID != "" {
			config.ChatID = chatID
		} else if notifExt != nil && notifExt.ChannelID() != "" {
			// Fallback to notification extension for backward compatibility
			config.ChatID = notifExt.ChannelID()
		}
	case integration.ProviderEmail:
		emailConfig, err := s.buildEmailConfig(intg, credentials)
		if err != nil {
			return config, err
		}
		config.Email = emailConfig
	}

	return config, nil
}

// buildEmailConfig builds email config by merging metadata (non-sensitive) and credentials (sensitive).
// This supports both new format (split storage) and legacy format (all in credentials).
func (s *IntegrationService) buildEmailConfig(intg *integration.Integration, decryptedCredentials string) (*notification.EmailConfig, error) {
	metadata := intg.Metadata()

	// Check if we have email config in metadata (new format)
	if smtpHost, ok := metadata["smtp_host"].(string); ok && smtpHost != "" {
		// New format: read non-sensitive from metadata, sensitive from credentials
		emailMetadata := &EmailMetadata{
			SMTPHost:    smtpHost,
			FromEmail:   getStringFromMap(metadata, "from_email"),
			FromName:    getStringFromMap(metadata, "from_name"),
			UseTLS:      getBoolFromMap(metadata, "use_tls"),
			UseSTARTTLS: getBoolFromMap(metadata, "use_starttls"),
			SkipVerify:  getBoolFromMap(metadata, "skip_verify"),
			ReplyTo:     getStringFromMap(metadata, "reply_to"),
		}

		// Get smtp_port (can be float64 from JSON)
		if port, ok := metadata["smtp_port"].(float64); ok {
			emailMetadata.SMTPPort = int(port)
		} else if port, ok := metadata["smtp_port"].(int); ok {
			emailMetadata.SMTPPort = port
		}

		// Get to_emails array
		if toEmails, ok := metadata["to_emails"].([]any); ok {
			emailMetadata.ToEmails = make([]string, 0, len(toEmails))
			for _, e := range toEmails {
				if email, ok := e.(string); ok {
					emailMetadata.ToEmails = append(emailMetadata.ToEmails, email)
				}
			}
		}

		// Parse sensitive credentials
		var sensitive *EmailSensitiveCredentials
		if decryptedCredentials != "" {
			var creds EmailSensitiveCredentials
			if err := json.Unmarshal([]byte(decryptedCredentials), &creds); err == nil {
				sensitive = &creds
			}
		}

		return mergeEmailConfig(emailMetadata, sensitive), nil
	}

	// Legacy format: all config in credentials (backward compatibility)
	return s.parseEmailCredentials(decryptedCredentials)
}

// Helper functions to safely get values from map[string]any
func getStringFromMap(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBoolFromMap(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

// setEmailCredentials parses email credentials JSON and splits into metadata and encrypted credentials.
// Non-sensitive config (smtp_host, port, from_email, etc.) goes to metadata.
// Sensitive data (username, password) goes to encrypted credentials.
func (s *IntegrationService) setEmailCredentials(intg *integration.Integration, credentialsJSON string) error {
	var emailCreds EmailCredentials
	if err := json.Unmarshal([]byte(credentialsJSON), &emailCreds); err != nil {
		return fmt.Errorf("parse email credentials: %w", err)
	}

	// Validate required fields
	if emailCreds.SMTPHost == "" {
		return fmt.Errorf("%w: SMTP host is required", shared.ErrValidation)
	}
	if emailCreds.SMTPPort == 0 {
		return fmt.Errorf("%w: SMTP port is required", shared.ErrValidation)
	}
	if emailCreds.FromEmail == "" {
		return fmt.Errorf("%w: sender email is required", shared.ErrValidation)
	}
	if len(emailCreds.ToEmails) == 0 {
		return fmt.Errorf("%w: at least one recipient email is required", shared.ErrValidation)
	}

	// Split into metadata and sensitive
	metadata, sensitive := splitEmailCredentials(&emailCreds)

	// Store non-sensitive config in metadata
	intg.SetMetadata(map[string]any{
		"smtp_host":    metadata.SMTPHost,
		"smtp_port":    metadata.SMTPPort,
		"from_email":   metadata.FromEmail,
		"from_name":    metadata.FromName,
		"to_emails":    metadata.ToEmails,
		"use_tls":      metadata.UseTLS,
		"use_starttls": metadata.UseSTARTTLS,
		"skip_verify":  metadata.SkipVerify,
		"reply_to":     metadata.ReplyTo,
	})

	// Encrypt and store sensitive credentials
	sensitiveJSON, err := json.Marshal(sensitive)
	if err != nil {
		return fmt.Errorf("marshal sensitive credentials: %w", err)
	}
	encrypted, err := s.encryptor.EncryptString(string(sensitiveJSON))
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}
	intg.SetCredentials(encrypted)

	return nil
}

// updateEmailCredentials updates email credentials, merging with existing metadata if partial update.
func (s *IntegrationService) updateEmailCredentials(intg *integration.Integration, credentialsJSON string) error {
	var emailCreds EmailCredentials
	if err := json.Unmarshal([]byte(credentialsJSON), &emailCreds); err != nil {
		return fmt.Errorf("parse email credentials: %w", err)
	}

	// Get existing metadata to merge
	existingMetadata := intg.Metadata()

	// Use new values if provided, otherwise keep existing
	newMetadata := make(map[string]any)

	// SMTP Host
	if emailCreds.SMTPHost != "" {
		newMetadata["smtp_host"] = emailCreds.SMTPHost
	} else if v, ok := existingMetadata["smtp_host"].(string); ok {
		newMetadata["smtp_host"] = v
	}

	// SMTP Port
	if emailCreds.SMTPPort != 0 {
		newMetadata["smtp_port"] = emailCreds.SMTPPort
	} else if v, ok := existingMetadata["smtp_port"].(float64); ok {
		newMetadata["smtp_port"] = int(v)
	} else if v, ok := existingMetadata["smtp_port"].(int); ok {
		newMetadata["smtp_port"] = v
	}

	// From Email
	if emailCreds.FromEmail != "" {
		newMetadata["from_email"] = emailCreds.FromEmail
	} else if v, ok := existingMetadata["from_email"].(string); ok {
		newMetadata["from_email"] = v
	}

	// From Name
	if emailCreds.FromName != "" {
		newMetadata["from_name"] = emailCreds.FromName
	} else if v, ok := existingMetadata["from_name"].(string); ok {
		newMetadata["from_name"] = v
	}

	// To Emails
	if len(emailCreds.ToEmails) > 0 {
		newMetadata["to_emails"] = emailCreds.ToEmails
	} else if v, ok := existingMetadata["to_emails"].([]any); ok {
		newMetadata["to_emails"] = v
	}

	// Boolean flags - use from input (these have default values, so always set)
	newMetadata["use_tls"] = emailCreds.UseTLS
	newMetadata["use_starttls"] = emailCreds.UseSTARTTLS
	newMetadata["skip_verify"] = emailCreds.SkipVerify

	// Reply To
	if emailCreds.ReplyTo != "" {
		newMetadata["reply_to"] = emailCreds.ReplyTo
	} else if v, ok := existingMetadata["reply_to"].(string); ok {
		newMetadata["reply_to"] = v
	}

	// Validate required fields after merge
	smtpHost, _ := newMetadata["smtp_host"].(string)
	if smtpHost == "" {
		return fmt.Errorf("%w: SMTP host is required", shared.ErrValidation)
	}

	smtpPort, _ := newMetadata["smtp_port"].(int)
	if smtpPort == 0 {
		return fmt.Errorf("%w: SMTP port is required", shared.ErrValidation)
	}

	fromEmail, _ := newMetadata["from_email"].(string)
	if fromEmail == "" {
		return fmt.Errorf("%w: sender email is required", shared.ErrValidation)
	}

	// Check to_emails
	hasToEmails := false
	if toEmails, ok := newMetadata["to_emails"].([]string); ok && len(toEmails) > 0 {
		hasToEmails = true
	} else if toEmails, ok := newMetadata["to_emails"].([]any); ok && len(toEmails) > 0 {
		hasToEmails = true
	}
	if !hasToEmails {
		return fmt.Errorf("%w: at least one recipient email is required", shared.ErrValidation)
	}

	intg.SetMetadata(newMetadata)

	// Handle sensitive credentials - only update if provided
	if emailCreds.Username != "" || emailCreds.Password != "" {
		sensitive := &EmailSensitiveCredentials{
			Username: emailCreds.Username,
			Password: emailCreds.Password,
		}
		sensitiveJSON, err := json.Marshal(sensitive)
		if err != nil {
			return fmt.Errorf("marshal sensitive credentials: %w", err)
		}
		encrypted, err := s.encryptor.EncryptString(string(sensitiveJSON))
		if err != nil {
			return fmt.Errorf("encrypt credentials: %w", err)
		}
		intg.SetCredentials(encrypted)
	}

	return nil
}

// TelegramCredentials represents the JSON structure for Telegram credentials (full input from frontend).
type TelegramCredentials struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

// setTelegramCredentials parses Telegram credentials JSON and splits into metadata and encrypted credentials.
// Non-sensitive config (chat_id) goes to metadata.
// Sensitive data (bot_token) goes to encrypted credentials.
func (s *IntegrationService) setTelegramCredentials(intg *integration.Integration, botToken string, chatID string) error {
	// Store chat_id in metadata
	intg.SetMetadata(map[string]any{
		"chat_id": chatID,
	})

	// Encrypt and store bot_token
	if botToken != "" {
		encrypted, err := s.encryptor.EncryptString(botToken)
		if err != nil {
			return fmt.Errorf("encrypt bot token: %w", err)
		}
		intg.SetCredentials(encrypted)
	}

	return nil
}

// updateTelegramCredentials updates Telegram credentials, merging with existing metadata if partial update.
func (s *IntegrationService) updateTelegramCredentials(intg *integration.Integration, botToken string, chatID string) error {
	// Get existing metadata to merge
	existingMetadata := intg.Metadata()
	newMetadata := make(map[string]any)

	// Copy existing metadata
	for k, v := range existingMetadata {
		newMetadata[k] = v
	}

	// Update chat_id if provided
	if chatID != "" {
		newMetadata["chat_id"] = chatID
	}

	intg.SetMetadata(newMetadata)

	// Update bot_token if provided
	if botToken != "" {
		encrypted, err := s.encryptor.EncryptString(botToken)
		if err != nil {
			return fmt.Errorf("encrypt bot token: %w", err)
		}
		intg.SetCredentials(encrypted)
	}

	return nil
}

// populateMetadataFromCredentials extracts non-sensitive config from credentials
// and populates the integration's metadata for backward compatibility.
// This is used when loading existing integrations that have all config in credentials_encrypted.
// Note: This does NOT persist to database - it only populates in-memory for API responses.
func (s *IntegrationService) populateMetadataFromCredentials(intg *integration.Integration) {
	if intg == nil || intg.Category() != integration.CategoryNotification {
		return
	}

	metadata := intg.Metadata()
	provider := intg.Provider()

	switch provider {
	case integration.ProviderEmail:
		// Check if metadata already has email config (new format)
		if _, ok := metadata["smtp_host"].(string); ok {
			return // Already has metadata, no need to populate
		}

		// Try to extract from credentials (legacy format: all config in credentials_encrypted)
		credentials := s.decryptCredentials(intg)
		if credentials == "" {
			return
		}

		var emailCreds EmailCredentials
		if err := json.Unmarshal([]byte(credentials), &emailCreds); err != nil {
			return // Not valid JSON or not email config
		}

		// Only populate if we have valid email config
		if emailCreds.SMTPHost == "" {
			return
		}

		// Create metadata from credentials (non-sensitive fields only)
		newMetadata := make(map[string]any)
		for k, v := range metadata {
			newMetadata[k] = v
		}
		newMetadata["smtp_host"] = emailCreds.SMTPHost
		newMetadata["smtp_port"] = emailCreds.SMTPPort
		newMetadata["from_email"] = emailCreds.FromEmail
		newMetadata["from_name"] = emailCreds.FromName
		newMetadata["to_emails"] = emailCreds.ToEmails
		newMetadata["use_tls"] = emailCreds.UseTLS
		newMetadata["use_starttls"] = emailCreds.UseSTARTTLS
		newMetadata["skip_verify"] = emailCreds.SkipVerify
		if emailCreds.ReplyTo != "" {
			newMetadata["reply_to"] = emailCreds.ReplyTo
		}

		intg.SetMetadata(newMetadata)

	case integration.ProviderTelegram:
		// Check if metadata already has chat_id
		if chatID, ok := metadata["chat_id"].(string); ok && chatID != "" {
			return // Already has metadata
		}

		// For Telegram, chat_id might be stored in notification extension (legacy)
		// We don't handle that here - the notification extension is separate

	case integration.ProviderSlack, integration.ProviderTeams:
		// Check if metadata already has channel_name
		if channelName, ok := metadata["channel_name"].(string); ok && channelName != "" {
			return // Already has metadata
		}

		// For Slack/Teams, channel_name might be stored in notification extension (legacy)
		// We don't handle that here - the notification extension is separate
	}
}

// getDefaultBaseURL returns the default base URL for a provider.
func (s *IntegrationService) getDefaultBaseURL(provider integration.Provider) string {
	switch provider {
	case integration.ProviderGitHub:
		return "https://github.com"
	case integration.ProviderGitLab:
		return "https://gitlab.com"
	case integration.ProviderBitbucket:
		return "https://bitbucket.org"
	case integration.ProviderAzureDevOps:
		return "https://dev.azure.com"
	default:
		return ""
	}
}

// SyncIntegration triggers a sync for an integration (updates stats, repo count, etc.)
func (s *IntegrationService) SyncIntegration(ctx context.Context, id string, tenantID string) (*integration.IntegrationWithSCM, error) {
	// For now, sync is the same as test - it verifies connection and updates stats
	return s.TestIntegration(ctx, id, tenantID)
}

// DisableIntegration disables an integration.
func (s *IntegrationService) DisableIntegration(ctx context.Context, id string, tenantID string) (*integration.Integration, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	if intg.TenantID().String() != tenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	intg.SetStatus(integration.StatusDisabled)
	intg.SetStatusMessage("Disabled by user at " + time.Now().Format(time.RFC3339))

	if err := s.repo.Update(ctx, intg); err != nil {
		return nil, fmt.Errorf("update integration: %w", err)
	}

	s.logger.Info("integration disabled", "id", id)

	return intg, nil
}

// EnableIntegration enables an integration.
func (s *IntegrationService) EnableIntegration(ctx context.Context, id string, tenantID string) (*integration.IntegrationWithSCM, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	if intg.TenantID().String() != tenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Reset to pending and test
	intg.SetStatus(integration.StatusPending)
	intg.SetStatusMessage("")

	if err := s.repo.Update(ctx, intg); err != nil {
		return nil, fmt.Errorf("update integration: %w", err)
	}

	// Test the connection to update status
	return s.TestIntegration(ctx, id, tenantID)
}

// GetSCMRepositoryInput represents the input for getting a single repository from SCM.
type GetSCMRepositoryInput struct {
	IntegrationID string
	TenantID      string
	FullName      string // owner/repo format
}

// GetSCMRepository gets a single repository from an SCM integration (includes languages).
func (s *IntegrationService) GetSCMRepository(ctx context.Context, input GetSCMRepositoryInput) (*scm.Repository, error) {
	intgID, err := shared.IDFromString(input.IntegrationID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid integration ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if intg.TenantID().String() != input.TenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Verify this is an SCM integration
	if !intg.IsSCM() {
		return nil, fmt.Errorf("%w: not an SCM integration", shared.ErrValidation)
	}

	// Get SCM extension for organization
	scmExt, _ := s.scmExtRepo.GetByIntegrationID(ctx, intgID)
	scmOrg := ""
	if scmExt != nil {
		scmOrg = scmExt.SCMOrganization()
	}

	// Determine base URL
	baseURL := intg.BaseURL()
	if baseURL == "" {
		baseURL = s.getDefaultBaseURL(intg.Provider())
	}

	// Decrypt credentials (falls back to plaintext for backward compatibility)
	credentials := s.decryptCredentials(intg)

	// Create SCM client
	client, err := s.scmFactory.CreateClient(scm.Config{
		Provider:     scm.Provider(intg.Provider()),
		BaseURL:      baseURL,
		AccessToken:  credentials,
		Organization: scmOrg,
		AuthType:     scm.AuthType(intg.AuthType()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SCM client: %w", err)
	}

	// Get the repository (this will also fetch languages)
	repo, err := client.GetRepository(ctx, input.FullName)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}

	return repo, nil
}

// FindSCMIntegrationInput represents the input for finding a matching SCM integration.
type FindSCMIntegrationInput struct {
	TenantID string
	Provider string
	SCMOrg   string
}

// FindSCMIntegration finds a matching SCM integration by provider and organization.
// Returns the first connected integration that matches.
func (s *IntegrationService) FindSCMIntegration(ctx context.Context, input FindSCMIntegrationInput) (*integration.IntegrationWithSCM, error) {
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Get all SCM integrations for tenant
	integrations, err := s.scmExtRepo.ListIntegrationsWithSCM(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("list scm integrations: %w", err)
	}

	// Find matching integration
	for _, iws := range integrations {
		// iws embeds Integration and has SCM field for extension
		// Check provider matches
		if input.Provider != "" && iws.Provider().String() != input.Provider {
			continue
		}

		// Check organization matches (if specified)
		if input.SCMOrg != "" && iws.SCM != nil && iws.SCM.SCMOrganization() != input.SCMOrg {
			continue
		}

		// Check status is connected
		if iws.Status() != integration.StatusConnected {
			continue
		}

		return iws, nil
	}

	return nil, integration.ErrIntegrationNotFound
}

// ============================================
// NOTIFICATION INTEGRATION METHODS
// ============================================

// ListNotificationIntegrations lists all notification integrations with their extensions.
func (s *IntegrationService) ListNotificationIntegrations(ctx context.Context, tenantID string) ([]*integration.IntegrationWithNotification, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	if s.notificationExtRepo == nil {
		return nil, fmt.Errorf("%w: notification extension repository not configured", shared.ErrValidation)
	}

	result, err := s.notificationExtRepo.ListIntegrationsWithNotification(ctx, tid)
	if err != nil {
		return nil, err
	}

	// Populate metadata from credentials for backward compatibility (existing integrations)
	for _, iwn := range result {
		s.populateMetadataFromCredentials(iwn.Integration)
	}

	return result, nil
}

// GetNotificationIntegration retrieves a notification integration with its extension.
func (s *IntegrationService) GetNotificationIntegration(ctx context.Context, id string, tenantID string) (*integration.IntegrationWithNotification, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if intg.TenantID().String() != tenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Verify this is a notification integration
	if intg.Category() != integration.CategoryNotification {
		return nil, fmt.Errorf("%w: not a notification integration", shared.ErrValidation)
	}

	// Populate metadata from credentials for backward compatibility (existing integrations)
	s.populateMetadataFromCredentials(intg)

	// Get notification extension
	var notifExt *integration.NotificationExtension
	if s.notificationExtRepo != nil {
		notifExt, _ = s.notificationExtRepo.GetByIntegrationID(ctx, intgID)
	}

	return integration.NewIntegrationWithNotification(intg, notifExt), nil
}

// CreateNotificationIntegrationInput represents the input for creating a notification integration.
type CreateNotificationIntegrationInput struct {
	TenantID    string
	Name        string
	Description string
	Provider    string
	AuthType    string
	Credentials string // Webhook URL, Bot Token, etc.

	// Notification-specific fields
	ChannelID          string
	ChannelName        string
	EnabledSeverities  []string // Severity levels to notify on (critical, high, medium, low, info, none)
	EnabledEventTypes  []string // Event types to receive notifications for (security_alert, new_finding, etc.)
	MessageTemplate    string
	IncludeDetails     bool
	MinIntervalMinutes int
}

// CreateNotificationIntegration creates a new notification integration.
//
//nolint:cyclop // Complex validation logic for multiple providers
func (s *IntegrationService) CreateNotificationIntegration(ctx context.Context, input CreateNotificationIntegrationInput) (*integration.IntegrationWithNotification, error) {
	// Parse tenant ID
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Validate provider
	provider := integration.Provider(input.Provider)
	if !provider.IsValid() || provider.Category() != integration.CategoryNotification {
		return nil, fmt.Errorf("%w: invalid notification provider", shared.ErrValidation)
	}

	// Validate auth type
	authType := integration.AuthType(input.AuthType)
	if !authType.IsValid() {
		return nil, integration.ErrInvalidAuthType
	}

	// Check for duplicate
	existing, err := s.repo.GetByTenantAndName(ctx, tenantID, input.Name)
	if err != nil && !errors.Is(err, integration.ErrIntegrationNotFound) {
		return nil, fmt.Errorf("check duplicate: %w", err)
	}
	if existing != nil {
		return nil, integration.ErrIntegrationNameExists
	}

	// Create integration
	id := shared.NewID()
	intg := integration.NewIntegration(
		id,
		tenantID,
		input.Name,
		integration.CategoryNotification,
		provider,
		authType,
	)

	if input.Description != "" {
		intg.SetDescription(input.Description)
	}

	// Handle credentials and metadata based on provider
	switch provider {
	case integration.ProviderEmail:
		// For email: split into metadata (non-sensitive) and credentials (sensitive)
		if input.Credentials != "" {
			if err := s.setEmailCredentials(intg, input.Credentials); err != nil {
				return nil, err
			}
		}
	case integration.ProviderTelegram:
		// For Telegram: store chat_id in metadata, bot_token in credentials
		if err := s.setTelegramCredentials(intg, input.Credentials, input.ChannelID); err != nil {
			return nil, err
		}
	case integration.ProviderSlack, integration.ProviderTeams:
		// For Slack/Teams: store channel_name in metadata, webhook_url in credentials
		if input.ChannelName != "" {
			intg.SetMetadata(map[string]any{
				"channel_name": input.ChannelName,
			})
		}
		if input.Credentials != "" {
			encrypted, err := s.encryptor.EncryptString(input.Credentials)
			if err != nil {
				return nil, fmt.Errorf("encrypt credentials: %w", err)
			}
			intg.SetCredentials(encrypted)
		}
	default:
		// For other providers (webhook): encrypt and store credentials as-is
		if input.Credentials != "" {
			encrypted, err := s.encryptor.EncryptString(input.Credentials)
			if err != nil {
				return nil, fmt.Errorf("encrypt credentials: %w", err)
			}
			intg.SetCredentials(encrypted)
		}
	}

	// Save integration
	if err := s.repo.Create(ctx, intg); err != nil {
		return nil, fmt.Errorf("create integration: %w", err)
	}

	// Create notification extension
	var notifExt *integration.NotificationExtension
	if s.notificationExtRepo != nil {
		notifExt = integration.NewNotificationExtension(id)
		// Note: channel_id and channel_name are now stored in integrations.metadata
		// Set enabled severities
		if len(input.EnabledSeverities) > 0 {
			severities := make([]integration.Severity, 0, len(input.EnabledSeverities))
			for _, s := range input.EnabledSeverities {
				severities = append(severities, integration.Severity(s))
			}
			notifExt.SetEnabledSeverities(severities)
		}
		// Set enabled event types
		if len(input.EnabledEventTypes) > 0 {
			eventTypes := make([]integration.EventType, 0, len(input.EnabledEventTypes))
			for _, et := range input.EnabledEventTypes {
				eventTypes = append(eventTypes, integration.EventType(et))
			}
			notifExt.SetEnabledEventTypes(eventTypes)
		}
		if input.MessageTemplate != "" {
			notifExt.SetMessageTemplate(input.MessageTemplate)
		}
		notifExt.SetIncludeDetails(input.IncludeDetails)
		if input.MinIntervalMinutes > 0 {
			notifExt.SetMinIntervalMinutes(input.MinIntervalMinutes)
		}

		if err := s.notificationExtRepo.Create(ctx, notifExt); err != nil {
			// Rollback integration creation
			_ = s.repo.Delete(ctx, id)
			return nil, fmt.Errorf("create notification extension: %w", err)
		}
	}

	s.logger.Info("notification integration created",
		"id", intg.ID().String(),
		"provider", intg.Provider().String(),
	)

	result := integration.NewIntegrationWithNotification(intg, notifExt)

	// Auto-test the connection
	testedResult, testErr := s.TestNotificationIntegration(ctx, intg.ID().String(), input.TenantID)
	if testErr != nil {
		s.logger.Warn("auto-test after creation failed", "error", testErr)
		return result, nil
	}

	return testedResult, nil
}

// UpdateNotificationIntegrationInput represents the input for updating a notification integration.
type UpdateNotificationIntegrationInput struct {
	Name        *string
	Description *string
	Credentials *string // Webhook URL, Bot Token, etc.

	// Notification-specific fields
	ChannelID          *string
	ChannelName        *string
	EnabledSeverities  []string // Severity levels to notify on (nil = no change)
	EnabledEventTypes  []string // Event types to receive notifications for (nil = no change)
	MessageTemplate    *string
	IncludeDetails     *bool
	MinIntervalMinutes *int
}

// applyNotificationExtensionUpdates applies updates to a notification extension.
// Note: channel_id and channel_name are now stored in integrations.metadata, not in extension.
func applyNotificationExtensionUpdates(ext *integration.NotificationExtension, input UpdateNotificationIntegrationInput) {
	if input.EnabledSeverities != nil {
		severities := make([]integration.Severity, 0, len(input.EnabledSeverities))
		for _, s := range input.EnabledSeverities {
			severities = append(severities, integration.Severity(s))
		}
		ext.SetEnabledSeverities(severities)
	}
	if input.EnabledEventTypes != nil {
		eventTypes := make([]integration.EventType, 0, len(input.EnabledEventTypes))
		for _, et := range input.EnabledEventTypes {
			eventTypes = append(eventTypes, integration.EventType(et))
		}
		ext.SetEnabledEventTypes(eventTypes)
	}
	if input.MessageTemplate != nil {
		ext.SetMessageTemplate(*input.MessageTemplate)
	}
	if input.IncludeDetails != nil {
		ext.SetIncludeDetails(*input.IncludeDetails)
	}
	if input.MinIntervalMinutes != nil {
		ext.SetMinIntervalMinutes(*input.MinIntervalMinutes)
	}
}

// UpdateNotificationIntegration updates an existing notification integration.
//
//nolint:cyclop // Complex validation logic for multiple providers
func (s *IntegrationService) UpdateNotificationIntegration(ctx context.Context, id string, tenantID string, input UpdateNotificationIntegrationInput) (*integration.IntegrationWithNotification, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership and category
	if intg.TenantID().String() != tenantID {
		return nil, integration.ErrIntegrationNotFound
	}
	if intg.Category() != integration.CategoryNotification {
		return nil, fmt.Errorf("%w: not a notification integration", shared.ErrValidation)
	}

	// Apply updates to base integration (name, description)
	if input.Name != nil {
		intg.SetName(*input.Name)
	}
	if input.Description != nil {
		intg.SetDescription(*input.Description)
	}

	// Handle credentials and metadata based on provider
	provider := intg.Provider()
	switch provider {
	case integration.ProviderEmail:
		// For email: split into metadata (non-sensitive) and credentials (sensitive)
		if input.Credentials != nil && *input.Credentials != "" {
			if err := s.updateEmailCredentials(intg, *input.Credentials); err != nil {
				return nil, err
			}
		}
	case integration.ProviderTelegram:
		// For Telegram: update chat_id in metadata, bot_token in credentials
		chatID := ""
		if input.ChannelID != nil {
			chatID = *input.ChannelID
		}
		botToken := ""
		if input.Credentials != nil {
			botToken = *input.Credentials
		}
		if chatID != "" || botToken != "" {
			if err := s.updateTelegramCredentials(intg, botToken, chatID); err != nil {
				return nil, err
			}
		}
	case integration.ProviderSlack, integration.ProviderTeams:
		// For Slack/Teams: update channel_name in metadata, webhook_url in credentials
		if input.ChannelName != nil && *input.ChannelName != "" {
			existingMetadata := intg.Metadata()
			newMetadata := make(map[string]any)
			for k, v := range existingMetadata {
				newMetadata[k] = v
			}
			newMetadata["channel_name"] = *input.ChannelName
			intg.SetMetadata(newMetadata)
		}
		if input.Credentials != nil && *input.Credentials != "" {
			encrypted, err := s.encryptor.EncryptString(*input.Credentials)
			if err != nil {
				return nil, fmt.Errorf("encrypt credentials: %w", err)
			}
			intg.SetCredentials(encrypted)
		}
	default:
		// For other providers (webhook): encrypt and store credentials as-is
		if input.Credentials != nil && *input.Credentials != "" {
			encrypted, err := s.encryptor.EncryptString(*input.Credentials)
			if err != nil {
				return nil, fmt.Errorf("encrypt credentials: %w", err)
			}
			intg.SetCredentials(encrypted)
		}
	}

	if err := s.repo.Update(ctx, intg); err != nil {
		return nil, fmt.Errorf("update integration: %w", err)
	}

	// Update notification extension
	notifExt, err := s.updateNotificationExtension(ctx, intgID, input)
	if err != nil {
		return nil, err
	}

	s.logger.Info("notification integration updated", "id", intg.ID().String())

	result := integration.NewIntegrationWithNotification(intg, notifExt)

	// Auto-test the connection after update
	testedResult, testErr := s.TestNotificationIntegration(ctx, intg.ID().String(), tenantID)
	if testErr != nil {
		s.logger.Warn("auto-test after update failed", "error", testErr)
		return result, nil
	}

	return testedResult, nil
}

// updateNotificationExtension updates the notification extension for an integration.
func (s *IntegrationService) updateNotificationExtension(ctx context.Context, intgID integration.ID, input UpdateNotificationIntegrationInput) (*integration.NotificationExtension, error) {
	if s.notificationExtRepo == nil {
		return nil, nil
	}

	notifExt, err := s.notificationExtRepo.GetByIntegrationID(ctx, intgID)
	if err != nil {
		if errors.Is(err, integration.ErrNotificationExtensionNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get notification extension: %w", err)
	}

	applyNotificationExtensionUpdates(notifExt, input)

	if err := s.notificationExtRepo.Update(ctx, notifExt); err != nil {
		return nil, fmt.Errorf("update notification extension: %w", err)
	}

	return notifExt, nil
}

// TestNotificationIntegration tests the connection for a notification integration.
func (s *IntegrationService) TestNotificationIntegration(ctx context.Context, id string, tenantID string) (*integration.IntegrationWithNotification, error) {
	intgID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if intg.TenantID().String() != tenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Verify this is a notification integration
	if intg.Category() != integration.CategoryNotification {
		return nil, fmt.Errorf("%w: not a notification integration", shared.ErrValidation)
	}

	// Rate limit check for test notifications (prevents spam)
	if err := s.checkTestRateLimit(id); err != nil {
		return nil, err
	}

	// Get notification extension
	var notifExt *integration.NotificationExtension
	if s.notificationExtRepo != nil {
		notifExt, _ = s.notificationExtRepo.GetByIntegrationID(ctx, intgID)
	}

	// Build notification client config
	config, err := s.buildNotificationConfig(intg, notifExt)
	if err != nil {
		intg.SetError(fmt.Sprintf("Failed to build config: %v", err))
		if updateErr := s.repo.Update(ctx, intg); updateErr != nil {
			s.logger.Error("Failed to update integration after config error", "error", updateErr)
		}
		return integration.NewIntegrationWithNotification(intg, notifExt), nil
	}

	// Create notification client
	client, err := s.notificationFactory.CreateClient(config)
	if err != nil {
		intg.SetError(fmt.Sprintf("Failed to create client: %v", err))
		if updateErr := s.repo.Update(ctx, intg); updateErr != nil {
			s.logger.Error("Failed to update integration after client error", "error", updateErr)
		}
		return integration.NewIntegrationWithNotification(intg, notifExt), nil
	}

	// Test the connection
	// Note: Test notifications are NOT recorded in notification_events (audit trail).
	// They are only for verifying the connection works.
	result, err := client.TestConnection(ctx)
	if err != nil {
		intg.SetError(fmt.Sprintf("Connection test failed: %v", err))
		if updateErr := s.repo.Update(ctx, intg); updateErr != nil {
			s.logger.Error("Failed to update integration after test error", "error", updateErr)
		}
		return integration.NewIntegrationWithNotification(intg, notifExt), nil
	}

	// Update integration based on result
	if result.Success {
		intg.SetConnected()
	} else {
		intg.SetError(result.Error)
	}

	if err := s.repo.Update(ctx, intg); err != nil {
		return nil, fmt.Errorf("update integration: %w", err)
	}

	return integration.NewIntegrationWithNotification(intg, notifExt), nil
}

// SendNotificationInput represents the input for sending a notification.
type SendNotificationInput struct {
	IntegrationID string
	TenantID      string
	Title         string
	Body          string
	Severity      string // critical, high, medium, low
	URL           string
	Fields        map[string]string
}

// SendNotificationResult represents the result of sending a notification.
type SendNotificationResult struct {
	Success   bool
	MessageID string
	Error     string
}

// SendNotification sends a notification through a specific integration.
func (s *IntegrationService) SendNotification(ctx context.Context, input SendNotificationInput) (*SendNotificationResult, error) {
	intgID, err := shared.IDFromString(input.IntegrationID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid integration ID", shared.ErrValidation)
	}

	// Validate tenant ID format
	if _, err := shared.IDFromString(input.TenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if intg.TenantID().String() != input.TenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Verify this is a notification integration
	if intg.Category() != integration.CategoryNotification {
		return nil, fmt.Errorf("%w: not a notification integration", shared.ErrValidation)
	}

	// Verify integration is connected
	if intg.Status() != integration.StatusConnected {
		return &SendNotificationResult{
			Success: false,
			Error:   fmt.Sprintf("integration is not connected (status: %s)", intg.Status()),
		}, nil
	}

	// Get notification extension to check severity settings
	var notifExt *integration.NotificationExtension
	if s.notificationExtRepo != nil {
		notifExt, _ = s.notificationExtRepo.GetByIntegrationID(ctx, intgID)
	}

	// Check if we should notify for this severity
	if notifExt != nil && !notifExt.ShouldNotify(input.Severity) {
		return &SendNotificationResult{
			Success: false,
			Error:   fmt.Sprintf("notifications disabled for severity: %s", input.Severity),
		}, nil
	}

	// Build notification client config
	config, err := s.buildNotificationConfig(intg, notifExt)
	if err != nil {
		return &SendNotificationResult{
			Success: false,
			Error:   fmt.Sprintf("failed to build config: %v", err),
		}, nil
	}

	// Create notification client
	client, err := s.notificationFactory.CreateClient(config)
	if err != nil {
		return &SendNotificationResult{
			Success: false,
			Error:   fmt.Sprintf("failed to create client: %v", err),
		}, nil
	}

	// Build message
	msg := notification.Message{
		Title:      input.Title,
		Body:       input.Body,
		Severity:   input.Severity,
		URL:        input.URL,
		Fields:     input.Fields,
		FooterText: "Sent via OpenCTEM.io",
	}

	// Send notification
	// Note: notification_history is DEPRECATED. Audit trail is now in notification_events
	// via the transactional outbox pattern. This SendNotification method is for
	// legacy/direct API calls and does NOT record to notification_events.
	result, err := client.Send(ctx, msg)
	if err != nil {
		return &SendNotificationResult{
			Success: false,
			Error:   fmt.Sprintf("send failed: %v", err),
		}, nil
	}

	s.logger.Info("notification sent",
		"integration_id", input.IntegrationID,
		"provider", intg.Provider().String(),
		"success", result.Success,
	)

	return &SendNotificationResult{
		Success:   result.Success,
		MessageID: result.MessageID,
		Error:     result.Error,
	}, nil
}

// BroadcastNotificationInput represents the input for broadcasting a notification to all connected integrations.
type BroadcastNotificationInput struct {
	TenantID  string
	EventType integration.EventType // Type of event (findings, exposures, scans, alerts)
	Title     string
	Body      string
	Severity  string
	URL       string
	Fields    map[string]string
}

// BroadcastNotification sends a notification to all connected notification integrations.
func (s *IntegrationService) BroadcastNotification(ctx context.Context, input BroadcastNotificationInput) ([]SendNotificationResult, error) {
	// Get all notification integrations
	integrations, err := s.ListNotificationIntegrations(ctx, input.TenantID)
	if err != nil {
		return nil, err
	}

	results := make([]SendNotificationResult, 0, len(integrations))

	for _, iwn := range integrations {
		// Skip non-connected integrations
		if iwn.Status() != integration.StatusConnected {
			continue
		}

		if iwn.Notification != nil {
			// Check if this integration should receive notifications for this severity
			if !iwn.Notification.ShouldNotify(input.Severity) {
				continue
			}

			// Check if this integration should receive notifications for this event type
			if input.EventType != "" && !iwn.Notification.ShouldNotifyEventType(input.EventType) {
				continue
			}
		}

		result, err := s.SendNotification(ctx, SendNotificationInput{
			IntegrationID: iwn.ID().String(),
			TenantID:      input.TenantID,
			Title:         input.Title,
			Body:          input.Body,
			Severity:      input.Severity,
			URL:           input.URL,
			Fields:        input.Fields,
		})
		if err != nil {
			results = append(results, SendNotificationResult{
				Success: false,
				Error:   err.Error(),
			})
			continue
		}
		results = append(results, *result)
	}

	return results, nil
}

// NotifyNewFinding sends a notification for a new finding to all connected notification integrations.
// This implements the FindingNotifier interface and is designed to be called asynchronously.
// Any errors are logged but not returned since this is a fire-and-forget operation.
func (s *IntegrationService) NotifyNewFinding(tenantID, title, body, severity, url string) {
	// Create background context for async operation
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s.logger.Debug("broadcasting new finding notification",
		"tenant_id", tenantID,
		"severity", severity,
	)

	results, err := s.BroadcastNotification(ctx, BroadcastNotificationInput{
		TenantID: tenantID,
		Title:    title,
		Body:     body,
		Severity: severity,
		URL:      url,
	})
	if err != nil {
		s.logger.Error("failed to broadcast finding notification",
			"tenant_id", tenantID,
			"error", err,
		)
		return
	}

	// Log results
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	if len(results) > 0 {
		s.logger.Info("finding notification broadcasted",
			"tenant_id", tenantID,
			"severity", severity,
			"total_channels", len(results),
			"success_count", successCount,
		)
	}
}

// =============================================================================
// Notification Events (audit trail)
// =============================================================================

// GetNotificationEventsInput represents the input for getting notification events.
type GetNotificationEventsInput struct {
	IntegrationID string
	TenantID      string
	Limit         int
	Offset        int
}

// GetNotificationEventsResult represents the result of getting notification events.
type GetNotificationEventsResult struct {
	Data   []NotificationEventEntry `json:"data"`
	Total  int64                    `json:"total"`
	Limit  int                      `json:"limit"`
	Offset int                      `json:"offset"`
}

// NotificationEventEntry represents a notification event entry in API responses.
type NotificationEventEntry struct {
	ID                    string                        `json:"id"`
	EventType             string                        `json:"event_type"`
	AggregateType         string                        `json:"aggregate_type,omitempty"`
	AggregateID           string                        `json:"aggregate_id,omitempty"`
	Title                 string                        `json:"title"`
	Body                  string                        `json:"body,omitempty"`
	Severity              string                        `json:"severity"`
	URL                   string                        `json:"url,omitempty"`
	Status                string                        `json:"status"`
	IntegrationsTotal     int                           `json:"integrations_total"`
	IntegrationsMatched   int                           `json:"integrations_matched"`
	IntegrationsSucceeded int                           `json:"integrations_succeeded"`
	IntegrationsFailed    int                           `json:"integrations_failed"`
	SendResults           []NotificationEventSendResult `json:"send_results"`
	LastError             string                        `json:"last_error,omitempty"`
	RetryCount            int                           `json:"retry_count"`
	CreatedAt             time.Time                     `json:"created_at"`
	ProcessedAt           time.Time                     `json:"processed_at"`
}

// NotificationEventSendResult represents a single send result to an integration.
type NotificationEventSendResult struct {
	IntegrationID   string    `json:"integration_id"`
	IntegrationName string    `json:"name"`
	Provider        string    `json:"provider"`
	Status          string    `json:"status"`
	MessageID       string    `json:"message_id,omitempty"`
	Error           string    `json:"error,omitempty"`
	SentAt          time.Time `json:"sent_at"`
}

// GetNotificationEvents retrieves notification events for a specific integration.
// This returns events from the new notification_events audit trail.
func (s *IntegrationService) GetNotificationEvents(ctx context.Context, input GetNotificationEventsInput) (*GetNotificationEventsResult, error) {
	if s.notificationEventRepo == nil {
		return &GetNotificationEventsResult{
			Data:   []NotificationEventEntry{},
			Total:  0,
			Limit:  input.Limit,
			Offset: input.Offset,
		}, nil
	}

	// Validate input
	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	offset := input.Offset
	if offset < 0 {
		offset = 0
	}

	// Verify integration exists and belongs to tenant
	integrationID, err := integration.ParseID(input.IntegrationID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid integration id format", shared.ErrValidation)
	}

	intg, err := s.repo.GetByID(ctx, integrationID)
	if err != nil {
		if errors.Is(err, integration.ErrIntegrationNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("get integration: %w", err)
	}

	if intg.TenantID().String() != input.TenantID {
		return nil, integration.ErrIntegrationNotFound
	}

	// Query events that include this integration in send_results
	events, total, err := s.notificationEventRepo.ListByIntegration(ctx, input.IntegrationID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list notification events: %w", err)
	}

	// Convert to API response format
	data := make([]NotificationEventEntry, 0, len(events))
	for _, event := range events {
		entry := NotificationEventEntry{
			ID:                    event.ID().String(),
			EventType:             event.EventType(),
			AggregateType:         event.AggregateType(),
			Title:                 event.Title(),
			Body:                  event.Body(),
			Severity:              event.Severity().String(),
			URL:                   event.URL(),
			Status:                event.Status().String(),
			IntegrationsTotal:     event.IntegrationsTotal(),
			IntegrationsMatched:   event.IntegrationsMatched(),
			IntegrationsSucceeded: event.IntegrationsSucceeded(),
			IntegrationsFailed:    event.IntegrationsFailed(),
			LastError:             event.LastError(),
			RetryCount:            event.RetryCount(),
			CreatedAt:             event.CreatedAt(),
			ProcessedAt:           event.ProcessedAt(),
		}

		if event.AggregateID() != nil {
			entry.AggregateID = event.AggregateID().String()
		}

		// Convert send results, filtering for this integration only
		sendResults := make([]NotificationEventSendResult, 0)
		for _, sr := range event.SendResults() {
			if sr.IntegrationID == input.IntegrationID {
				sendResults = append(sendResults, NotificationEventSendResult{
					IntegrationID:   sr.IntegrationID,
					IntegrationName: sr.IntegrationName,
					Provider:        sr.Provider,
					Status:          sr.Status,
					MessageID:       sr.MessageID,
					Error:           sr.Error,
					SentAt:          sr.SentAt,
				})
			}
		}
		entry.SendResults = sendResults

		data = append(data, entry)
	}

	return &GetNotificationEventsResult{
		Data:   data,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}
